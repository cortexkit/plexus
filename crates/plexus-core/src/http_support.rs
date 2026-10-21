//! Building blocks shared by the blocking HTTP vendor transports (MCP
//! streamable-HTTP in `mcp_remote` and REST in `rest_api`).
//!
//! Everything here runs on `reqwest::blocking`, which owns an internal runtime.
//! Callers executing these transports from an async context must move off the
//! async worker for the duration (see `blocking_section` in plexus-module):
//! dropping the blocking client's runtime on an async worker panics and kills
//! the module mid-request.

use std::io::Read;
use std::time::{Duration, Instant, SystemTime};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION, RETRY_AFTER};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::credentials::ResolvedCredential;
use crate::manifest::CredentialBinding;
use crate::transport::{Retryability, TransmissionState, TransportResponse};

/// Connect phase budget shared by the HTTP vendor transports.
pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Whole-request budget shared by the HTTP vendor transports.
pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle lifetime before a transport's pooled CONNECTION ENTRY (one per Plexus
/// connection id: its HTTP client and, for MCP, its initialized session) may
/// be swept by `sweep_idle`.
///
/// Not to be confused with `POOLED_CONNECTION_IDLE_LIMIT`, which governs the
/// TCP keep-alive connections inside each entry's HTTP client. Evicting an
/// entry drops a whole MCP session; expiring a keep-alive connection only
/// means the next request opens a new socket.
pub(crate) const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long an idle keep-alive TCP connection may sit in an HTTP client's pool
/// before it is dropped instead of reused. Every reqwest client that carries
/// vendor traffic sets this as its `pool_idle_timeout`.
///
/// Kept below the shortest keep-alive common among vendor servers, so Plexus
/// never sends a request on a connection the server may be closing. DeepWiki's
/// server (uvicorn behind a proxy), for example, drops idle connections at
/// about 60 seconds, and AWS load balancers default to 60 seconds as well. The
/// health probe and catalog refresh run every 60 seconds and reqwest's own
/// default keeps idle connections for 90, so without this limit every probe
/// would reuse a connection right at the server's cutoff and some would lose
/// the race: the request is written just as the server closes, fails with
/// "connection closed before message completed", and its outcome is unknown.
///
/// The cost: a caller polling more slowly than this pays one fresh connect and
/// handshake per poll. Retrying instead would not be equivalent, because a
/// request lost this way may already have reached the vendor.
///
/// Not to be confused with `DEFAULT_IDLE_TIMEOUT`, which evicts a transport's
/// pooled connection entries (and with them MCP sessions), not sockets.
pub(crate) const POOLED_CONNECTION_IDLE_LIMIT: Duration = Duration::from_secs(30);

/// Product identifier sent on every outbound vendor request.
///
/// NOT COSMETIC. GitHub's REST API REFUSES a request carrying no `User-Agent`,
/// and `reqwest` sends none unless one is configured. The refusal is a 403 whose
/// status is indistinguishable from a permissions failure, and whose body is the
/// only thing that names the cause: "Request forbidden by administrative rules.
/// Please make sure your request has a User-Agent header".
///
/// A governed write to `POST /repos/{owner}/{repo}/issues/{n}/reactions`
/// fails this way even while the App holds every permission the endpoint
/// documents, and it is hard to diagnose, because a bare 403 supports every
/// permission hypothesis equally.
///
/// Set on BOTH HTTP transports rather than only the one that failed. The MCP
/// endpoint does not enforce this today, so a missing header on the REST side
/// goes unnoticed while trigger polling against the same vendor keeps working.
pub(crate) const USER_AGENT: &str = concat!("ck-plexus/", env!("CARGO_PKG_VERSION"));

/// A reviewed credential binding could not be rendered as an HTTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialHeaderError {
    /// The binding names a header name or value the HTTP layer rejects.
    InvalidBinding,
}

/// Build the credential headers declared by the reviewed manifest bindings.
///
/// Shared verbatim by both HTTP transports so a credential is placed on the
/// wire by exactly one code path. The intermediate assembly buffer is wiped;
/// the returned header and the HTTP stack still own unwiped copies until drop.
pub(crate) fn build_headers(
    bindings: &[CredentialBinding],
    credential: &ResolvedCredential,
) -> Result<HeaderMap, CredentialHeaderError> {
    let mut headers = HeaderMap::new();
    // An anonymous credential (auth.mode = none) has an empty payload. Emitting
    // the binding anyway would send a header containing only its prefix, which
    // a vendor reads as a malformed credential rather than an absent one.
    if credential.payload().is_empty() {
        return Ok(headers);
    }
    for binding in bindings {
        if !binding.placement.eq_ignore_ascii_case("header") {
            return Err(CredentialHeaderError::InvalidBinding);
        }
        let name = HeaderName::from_bytes(binding.key.as_bytes())
            .map_err(|_| CredentialHeaderError::InvalidBinding)?;
        let mut value = Zeroizing::new(binding.prefix.as_bytes().to_vec());
        value.extend_from_slice(credential.payload());
        let mut header = HeaderValue::from_bytes(value.as_slice())
            .map_err(|_| CredentialHeaderError::InvalidBinding)?;
        // Marks the value as secret for the HTTP stack: its Debug output prints
        // `Sensitive` instead of the bytes, and HTTP/2 header compression never
        // adds it to the shared table, where a later request could probe it.
        header.set_sensitive(true);
        headers.insert(name, header);
    }
    Ok(headers)
}

/// Where a failed HTTP attempt failed, which determines write safety and the
/// diagnostic returned to an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpAttemptFailure {
    /// The request timed out. A timeout can occur after the request was written
    /// to the wire, so the outcome is unknown and must never be reported as
    /// not-sent.
    Timeout,
    /// The connection failed before any request was written (refused,
    /// unreachable): definitively not sent.
    Connect,
    /// Reqwest could not turn the configured endpoint and request data into a
    /// request.
    Build,
    /// Reqwest rejected the redirect chain or a redirect target.
    Redirect,
    /// Sending the request failed for a reason other than connect or timeout.
    Request,
    /// A streaming request or response body failed.
    Body,
    /// Decoding a response body failed.
    Decode,
    /// `Response::error_for_status` converted a status into an error.
    Status,
    /// Upgrading the HTTP connection failed.
    Upgrade,
    /// A future reqwest error category that has no public predicate yet.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpFailureDiagnostic {
    pub code: &'static str,
    pub message: &'static str,
}

impl HttpAttemptFailure {
    pub(crate) fn outcome_unknown_diagnostic(self) -> Option<HttpFailureDiagnostic> {
        let diagnostic = match self {
            Self::Timeout | Self::Connect => return None,
            Self::Build => HttpFailureDiagnostic {
                code: "http_request_invalid",
                message: "HTTP request was invalid; inspect the configured endpoint or redirect target",
            },
            Self::Redirect => HttpFailureDiagnostic {
                code: "http_redirect_failed",
                message: "HTTP redirect failed; inspect the endpoint redirect chain",
            },
            Self::Request | Self::Body => HttpFailureDiagnostic {
                code: "http_request_failed",
                message: "HTTP request failed after connection; retry reads or reconcile writes before retrying",
            },
            Self::Decode => HttpFailureDiagnostic {
                code: "http_response_decode_failed",
                message: "HTTP response decoding failed; inspect the vendor response format",
            },
            Self::Status => HttpFailureDiagnostic {
                code: "http_status_failed",
                message: "HTTP status was converted to an error; inspect the vendor response status",
            },
            Self::Upgrade => HttpFailureDiagnostic {
                code: "http_upgrade_failed",
                message: "HTTP protocol upgrade failed; inspect vendor and proxy upgrade support",
            },
            Self::Unknown => HttpFailureDiagnostic {
                code: "outcome_unknown",
                message: "vendor response was not definitive",
            },
        };
        Some(diagnostic)
    }

    pub(crate) fn outcome_unknown_response(self) -> Option<TransportResponse> {
        self.outcome_unknown_diagnostic().map(|diagnostic| {
            let mut response =
                TransportResponse::unknown_with_error(diagnostic.code, diagnostic.message);
            if self == Self::Build {
                response.transmission = TransmissionState::NotSent;
            }
            response
        })
    }
}

/// Classify a reqwest transport error for the transmission-state mapping.
///
/// Timeout is checked before connect on purpose: a connect-phase timeout sets
/// both flags, and reporting that as outcome-unknown is the conservative
/// direction (it may prompt a reconciliation read-back, whereas claiming
/// not-sent for a request that might have been written would be unsafe). A
/// definitive connect failure such as connection-refused is not a timeout and
/// still lands on `Connect`.
pub(crate) fn classify_reqwest_error(error: &reqwest::Error) -> HttpAttemptFailure {
    if error.is_timeout() {
        HttpAttemptFailure::Timeout
    } else if error.is_connect() {
        HttpAttemptFailure::Connect
    } else if error.is_builder() {
        HttpAttemptFailure::Build
    } else if error.is_redirect() {
        HttpAttemptFailure::Redirect
    } else if error.is_request() {
        HttpAttemptFailure::Request
    } else if error.is_body() {
        HttpAttemptFailure::Body
    } else if error.is_decode() {
        HttpAttemptFailure::Decode
    } else if error.is_status() {
        HttpAttemptFailure::Status
    } else if error.is_upgrade() {
        HttpAttemptFailure::Upgrade
    } else {
        HttpAttemptFailure::Unknown
    }
}

/// Longest cause text one operator log line carries. A source chain is normally
/// a few short phrases; the cap only stops a pathological one from flooding the
/// log.
const ERROR_CAUSE_LIMIT: usize = 500;

/// Render why a reqwest transport attempt failed, for the operator log only.
///
/// The category from `classify_reqwest_error` says which phase broke; this says
/// what actually happened underneath (for example hyper's "connection closed
/// before message completed", a TLS close, or a reset), which is what an
/// operator needs to tell a flaky vendor from a local fault. The error is
/// stripped of its URL first: reqwest's own message embeds the full request
/// URL, and vendors sometimes take credentials as query parameters. Never put
/// this text in anything an agent or caller sees.
pub(crate) fn reqwest_error_cause(error: reqwest::Error) -> String {
    error_chain_text(&error.without_url())
}

/// Join an error and each `source()` beneath it with `: `, bounded to
/// `ERROR_CAUSE_LIMIT` characters (a cut chain ends with `…`).
fn error_chain_text(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        if text.chars().count() > ERROR_CAUSE_LIMIT {
            break;
        }
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    match text.char_indices().nth(ERROR_CAUSE_LIMIT) {
        Some((cut, _)) => {
            text.truncate(cut);
            text.push('…');
            text
        }
        None => text,
    }
}

/// Longest `Retry-After` a transport records, however long the vendor asks for.
///
/// The header is vendor-controlled and unbounded: any u64 of seconds parses,
/// and adding `u64::MAX` seconds to `Instant::now()` panics. That panic happened
/// while the per-connection lock was held, poisoning the entry so the
/// connection stayed dead until restart. An hour is long enough to respect any
/// real quota window between retries, and short enough that a mistaken value
/// heals without a restart.
pub(crate) const MAX_RECORDED_THROTTLE: Duration = Duration::from_secs(60 * 60);

/// Longest a request waits, holding its connection's lock, for an earlier
/// vendor throttle to lapse before it is sent.
///
/// The wait blocks a thread and every later request on the same connection, so
/// only a short throttle is waited out. A longer one makes the request refuse
/// locally (not sent, retryable after `retry_after_ms`), which hands the delay
/// to the caller instead of parking a blocking thread for up to an hour.
pub(crate) const MAX_THROTTLE_WAIT: Duration = Duration::from_secs(5);

/// Parse a `Retry-After` header given either as delay-seconds or as an HTTP
/// date, for the throttle discipline the MCP and REST transports share. The
/// result never exceeds `MAX_RECORDED_THROTTLE`.
pub(crate) fn parse_retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds).min(MAX_RECORDED_THROTTLE));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    date.duration_since(SystemTime::now())
        .ok()
        .map(|delay| delay.min(MAX_RECORDED_THROTTLE))
}

/// When a vendor throttle of `delay` ends, if it needs recording at all.
///
/// Checked addition and the clamp together make this total: no delay, however
/// it was obtained, can panic here.
pub(crate) fn throttle_deadline(now: Instant, delay: Duration) -> Option<Instant> {
    if delay.is_zero() {
        return None;
    }
    now.checked_add(delay.min(MAX_RECORDED_THROTTLE))
}

/// What a request must do about a throttle recorded by an earlier response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThrottleGate {
    /// Send now: no throttle, or it has lapsed.
    Clear,
    /// Sleep this long first; it is within `MAX_THROTTLE_WAIT`.
    Wait(Duration),
    /// Do not send; the throttle still has this long to run.
    Refuse(Duration),
}

/// Decide how a request treats the recorded throttle, clearing the record once
/// the request is allowed to go (immediately or after a short wait). A refused
/// request leaves the record in place so the next request refuses too.
pub(crate) fn throttle_gate(throttle_until: &mut Option<Instant>, now: Instant) -> ThrottleGate {
    let Some(until) = *throttle_until else {
        return ThrottleGate::Clear;
    };
    let remaining = until.saturating_duration_since(now);
    if remaining > MAX_THROTTLE_WAIT {
        return ThrottleGate::Refuse(remaining);
    }
    *throttle_until = None;
    if remaining.is_zero() {
        ThrottleGate::Clear
    } else {
        ThrottleGate::Wait(remaining)
    }
}

/// A duration as whole milliseconds for `TransportResponse::retry_after_ms`,
/// rounded up so a caller that waits exactly this long is never early.
pub(crate) fn duration_ms(delay: Duration) -> u64 {
    let millis = delay.as_millis() + u128::from(!delay.subsec_nanos().is_multiple_of(1_000_000));
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// The local refusal for a request sent while a long vendor throttle is still
/// running: nothing was sent, and the caller may retry after `remaining`.
pub(crate) fn throttle_refusal(transport: &str, remaining: Duration) -> TransportResponse {
    TransportResponse {
        transmission: TransmissionState::NotSent,
        retryability: Retryability::Throttle,
        response: None,
        error_code: Some("throttled".to_string()),
        error_message: Some(format!(
            "{transport} vendor throttle still in effect; not sent, retry after {}ms",
            duration_ms(remaining)
        )),
        vendor_request_id: None,
        served_from: None,
        observed_at_ms: None,
        retry_after_ms: Some(duration_ms(remaining)),
        error_signal: None,
    }
}

/// Read a `Retry-After` duration off a response header set.
pub(crate) fn retry_after_from_headers(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after)
}

/// A quota reply without a usable delay must still back off rather than spin.
pub(crate) const DEFAULT_THROTTLE_DELAY: Duration = Duration::from_secs(60);

pub(crate) fn response_throttle(status: u16, headers: &HeaderMap) -> Option<Duration> {
    let retry_after = retry_after_from_headers(headers);
    let github_quota = status == 403
        && (retry_after.is_some()
            || headers
                .get("x-ratelimit-remaining")
                .is_some_and(|value| value == "0"));
    if status == 429 || github_quota || (status == 503 && retry_after.is_some()) {
        Some(
            retry_after
                .filter(|delay| !delay.is_zero())
                .unwrap_or(DEFAULT_THROTTLE_DELAY),
        )
    } else {
        None
    }
}

pub(crate) fn throttled_response(transport: &str, delay: Duration) -> TransportResponse {
    TransportResponse {
        transmission: TransmissionState::Sent,
        retryability: Retryability::Throttle,
        response: None,
        error_code: Some("throttled".into()),
        error_message: Some(format!(
            "{transport} vendor throttled the request; retry after {}ms",
            duration_ms(delay)
        )),
        vendor_request_id: None,
        served_from: None,
        observed_at_ms: None,
        retry_after_ms: Some(duration_ms(delay)),
        error_signal: None,
    }
}

/// Unlike the blocking client's per-read timeout, a request-level timeout is
/// carried into reqwest's async request and bounds headers and the entire body.
/// Keep both: an idle read can fail sooner, but progress cannot extend the total
/// deadline. No extra worker thread or connection lock outlives the request.
pub(crate) fn with_request_deadline(
    builder: reqwest::blocking::RequestBuilder,
    deadline: Instant,
) -> reqwest::blocking::RequestBuilder {
    builder.timeout(deadline.saturating_duration_since(Instant::now()))
}

/// Redact userinfo and any query string off an endpoint URL for Debug
/// projections and logs: the host and path are manifest-reviewed and not
/// secret, but a URL can carry a username and password before its host, and
/// vendors sometimes take credentials as query parameters.
pub(crate) fn redacted_endpoint(endpoint: &str) -> String {
    let (before_query, had_query) = match endpoint.find('?') {
        Some(query_start) => (&endpoint[..query_start], true),
        None => (endpoint, false),
    };
    let mut redacted = without_userinfo(before_query);
    if had_query {
        redacted.push_str("?[redacted]");
    }
    redacted
}

/// Replace the `user:password@` part of a URL's authority, if any, with
/// `[redacted]@`. The authority ends at the first `/` or `#` after `://`, and
/// the LAST `@` inside it ends the userinfo, since a password may itself
/// contain `@`.
fn without_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '#'])
        .map_or(url.len(), |offset| authority_start + offset);
    match url[authority_start..authority_end].rfind('@') {
        Some(at) => format!(
            "{}[redacted]@{}",
            &url[..authority_start],
            &url[authority_start + at + 1..]
        ),
        None => url.to_string(),
    }
}

/// Largest response body either HTTP transport reads into memory.
///
/// Reading a body without a limit lets one vendor response (or anything on the
/// path to it) exhaust the daemon's memory. 16 MiB is far above any tool
/// result or REST page an agent can use, so the limit only stops runaway
/// bodies.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// A response body read under `MAX_RESPONSE_BODY_BYTES`.
pub(crate) struct BoundedBody {
    /// The body as text (invalid UTF-8 replaced), cut at the limit if it was
    /// longer.
    pub text: String,
    /// The body was longer than the limit, so `text` is only its beginning.
    pub truncated: bool,
}

/// A body read that ended early: the classified reason, and the cause text for
/// the operator log (never for a caller).
pub(crate) struct BodyReadFailure {
    pub failure: HttpAttemptFailure,
    pub cause: String,
}

/// Read a response body, stopping at `limit` bytes.
///
/// A body that ends early fails with the classified reason, so a caller can
/// tell a timeout from a reset or a decode failure instead of reporting every
/// one of them as a timeout.
pub(crate) fn read_body_bounded(
    response: reqwest::blocking::Response,
    limit: usize,
) -> Result<BoundedBody, BodyReadFailure> {
    let mut bytes = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    if let Err(error) = response.take(cap).read_to_end(&mut bytes) {
        return Err(BodyReadFailure {
            failure: classify_body_io_error(&error),
            cause: body_io_error_cause(error),
        });
    }
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok(BoundedBody {
        text: String::from_utf8(bytes)
            .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
        truncated,
    })
}

/// Classify a failed body read. The blocking client reports body failures as
/// I/O errors that usually wrap its own error type; that inner error carries
/// the precise category, and the I/O kind is the fallback.
pub(crate) fn classify_body_io_error(error: &std::io::Error) -> HttpAttemptFailure {
    if let Some(inner) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
    {
        return classify_reqwest_error(inner);
    }
    if error.kind() == std::io::ErrorKind::TimedOut {
        HttpAttemptFailure::Timeout
    } else {
        HttpAttemptFailure::Body
    }
}

/// The operator-log rendering of a failed body read. An inner client error is
/// stripped of its URL first, for the same reason as `reqwest_error_cause`.
pub(crate) fn body_io_error_cause(error: std::io::Error) -> String {
    let kind = error.kind();
    match error.into_inner() {
        Some(inner) => match inner.downcast::<reqwest::Error>() {
            Ok(client_error) => reqwest_error_cause(*client_error),
            Err(other) => error_chain_text(&*other),
        },
        None => kind.to_string(),
    }
}

/// Most redirects a credentialed request follows before the redirect itself is
/// returned as the answer.
pub(crate) const MAX_REDIRECT_HOPS: usize = 3;

/// The redirect policy for clients that carry a connection's credential.
///
/// A redirect is followed only to the same scheme, host and port as the
/// original request (the parser lowercases the host and fills in the default
/// port, so `HTTPS://API.example.com` and `https://api.example.com:443` are the
/// same origin), for at most `MAX_REDIRECT_HOPS` hops. Two reasons:
///
/// - The HTTP client strips only `Authorization` and `Cookie` when a redirect
///   changes host. Credentials bound to other headers, such as `x-api-key`,
///   would be sent to whatever host the redirect names.
/// - On 301, 302 and 303 the client turns any method other than GET and HEAD
///   into a body-less GET. A write that met one would silently become a read
///   and could be reported as a success.
///
/// So `follow_method_changing` must be true only for a client that sends
/// nothing but GET: everything else follows only 307 and 308, which keep the
/// method and body. A redirect that is not followed is returned as the
/// response, and the transport reports its status.
pub(crate) fn credentialed_redirect_policy(
    follow_method_changing: bool,
) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let keeps_method = matches!(attempt.status().as_u16(), 307 | 308);
        let same_origin = attempt
            .previous()
            .first()
            .is_some_and(|original| original.origin() == attempt.url().origin());
        if attempt.previous().len() > MAX_REDIRECT_HOPS
            || !same_origin
            || !(keeps_method || follow_method_changing)
        {
            attempt.stop()
        } else {
            attempt.follow()
        }
    })
}

/// The `Location` of a redirect that was not followed, for the operator log
/// only, with any query string removed because it may carry a credential.
pub(crate) fn redirect_location_for_log(headers: &HeaderMap) -> String {
    headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| "<none>".to_string(), redacted_endpoint)
}

/// Redact secret-keyed values for a DIAGNOSTIC PROJECTION — a `Debug` render,
/// a log line, an audit summary — replacing them with a fingerprint so presence
/// stays provable without retaining the material.
///
/// Never apply this to data being DELIVERED to a caller. The key list is a
/// substring guess over field names we do not control, so on a vendor response
/// it is wrong in both directions at once: it cannot catch a credential a
/// vendor returns under a name like `value`, and it reliably destroys ordinary
/// vendor data whose field name happens to contain a matched word. Unreliable
/// protection paired with reliable damage is the worst combination available,
/// and it is what made this a data-loss primitive when it sat on the transport
/// response path (see `dispatch`). Redaction is a property of a PROJECTION,
/// not of the value.
pub(crate) fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    if is_secret_key(key) {
                        (
                            key.clone(),
                            Value::String(crate::fingerprint::fingerprint(
                                serde_json::to_string(value).unwrap_or_default().as_bytes(),
                            )),
                        )
                    } else {
                        (key.clone(), redact_value(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_value).collect()),
        other => other.clone(),
    }
}

/// The one key screen for diagnostic redaction, shared by `redact_value` here
/// and the mock transport's request projection. A case-insensitive substring
/// match on: token, secret, password, handle, payload, credential, api_key,
/// authorization.
///
/// Deliberately separate from `secret_input`, which decides whether to REFUSE
/// an input: a false positive there blocks a legitimate call, while a false
/// positive here only fingerprints a value in a log line.
pub(crate) fn is_secret_key(key: &str) -> bool {
    if crate::secret_input::is_secret_key(key) {
        return true;
    }
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("secret")
        || key.contains("password")
        || key.contains("handle")
        || key.contains("payload")
        || key.contains("credential")
        || key.contains("api_key")
        || key.contains("authorization")
}

pub(crate) fn truncate_utf8(text: &str, limit: usize) -> &str {
    let mut end = limit.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub(crate) fn bounded_text_for_log(text: &str, limit: usize) -> std::borrow::Cow<'_, str> {
    if text.len() <= limit {
        return std::borrow::Cow::Borrowed(text);
    }
    let suffix = " [truncated]";
    let mut output = truncate_utf8(text, limit.saturating_sub(suffix.len())).to_owned();
    output.push_str(truncate_utf8(suffix, limit.saturating_sub(output.len())));
    std::borrow::Cow::Owned(output)
}

pub(crate) fn bounded_json_for_log(value: &serde_json::Value, limit: usize) -> String {
    struct LimitedWriter {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for LimitedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let take = bytes.len().min(self.limit.saturating_sub(self.bytes.len()));
            self.bytes.extend_from_slice(&bytes[..take]);
            if take < bytes.len() {
                return Err(std::io::Error::other("diagnostic limit reached"));
            }
            Ok(take)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = LimitedWriter {
        bytes: Vec::with_capacity(limit),
        limit,
    };
    let truncated = serde_json::to_writer(&mut writer, value).is_err();
    let end = std::str::from_utf8(&writer.bytes)
        .map_or_else(|error| error.valid_up_to(), |text| text.len());
    let text = String::from_utf8_lossy(&writer.bytes[..end]);
    if truncated {
        let suffix = " [truncated]";
        let mut output = truncate_utf8(&text, limit.saturating_sub(suffix.len())).to_owned();
        output.push_str(truncate_utf8(suffix, limit.saturating_sub(output.len())));
        output
    } else {
        text.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_secret_screen_includes_every_input_secret_alias() {
        for key in [
            "apiKey",
            "x-api-key",
            "cookie",
            "private_key",
            "passwd",
            "passphrase",
        ] {
            assert!(is_secret_key(key), "diagnostic screen must cover {key}");
            let redacted = redact_value(&serde_json::json!({key:"CANARY"}));
            assert_ne!(redacted[key], "CANARY");
        }
    }

    #[test]
    fn bounded_json_diagnostic_is_utf8_safe_and_does_not_serialize_the_full_body() {
        let value = serde_json::json!({"text":"界".repeat(100_000)});
        let diagnostic = bounded_json_for_log(&value, 4096);
        assert!(diagnostic.len() <= 4096);
        assert!(diagnostic.ends_with(" [truncated]"));
        assert_eq!(
            bounded_json_for_log(&serde_json::json!({"ok":true}), 4096),
            r#"{"ok":true}"#
        );
    }
    use crate::transport::TransmissionState;

    fn start_failure_server(
        requests: usize,
        response: &'static str,
    ) -> (String, crate::test_http::FixedRequestServer) {
        let (base, server) = crate::test_http::FixedRequestServer::start(
            requests,
            "failure classifier",
            move |_, _| response.to_string(),
        );
        (format!("{base}/loop"), server)
    }

    /// The production keep-alive limit stays below the shortest common vendor
    /// keep-alive, and both HTTP transports default to it.
    ///
    /// The transport tests prove a limit below the idle gap prevents reuse, but
    /// they inject a short limit to stay fast; this is what holds the value
    /// production actually uses. 60 seconds is DeepWiki's idle cutoff and the
    /// AWS load balancer default; reqwest's own default of 90 seconds
    /// is what let probes on a 60-second cadence lose the race.
    #[test]
    fn the_pooled_connection_limit_stays_below_common_vendor_keep_alives() {
        assert!(
            POOLED_CONNECTION_IDLE_LIMIT < Duration::from_secs(60),
            "a pooled connection kept idle for {POOLED_CONNECTION_IDLE_LIMIT:?} can be \
             reused just as a 60-second vendor keep-alive closes it"
        );
        assert_eq!(
            crate::mcp_remote::McpRemoteConfig::new("http://vendor.invalid/mcp")
                .pooled_connection_idle_limit,
            POOLED_CONNECTION_IDLE_LIMIT
        );
        assert_eq!(
            crate::rest_api::RestConfig::new("http://vendor.invalid").pooled_connection_idle_limit,
            POOLED_CONNECTION_IDLE_LIMIT
        );
    }

    #[test]
    fn reachable_reqwest_failures_have_distinct_codes_and_safe_transmission() {
        let build_error = reqwest::blocking::Client::new()
            .get("not a valid URL")
            .send()
            .expect_err("invalid URL must fail request construction");

        let redirect_response = concat!(
            "HTTP/1.1 302 Found\r\n",
            "Location: /loop\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n\r\n"
        );
        let (redirect_endpoint, redirect_task) = start_failure_server(11, redirect_response);
        let redirect_error = reqwest::blocking::Client::new()
            .get(redirect_endpoint)
            .send()
            .expect_err("default redirect limit must reject the loop");
        redirect_task.join().expect("redirect server exits");

        let (request_endpoint, request_task) = start_failure_server(1, "");
        let request_error = reqwest::blocking::Client::new()
            .get(request_endpoint)
            .send()
            .expect_err("closing after request receipt must fail the send");
        request_task.join().expect("request failure server exits");

        let cases = [
            (
                "build",
                build_error,
                HttpAttemptFailure::Build,
                "http_request_invalid",
            ),
            (
                "redirect",
                redirect_error,
                HttpAttemptFailure::Redirect,
                "http_redirect_failed",
            ),
            (
                "request",
                request_error,
                HttpAttemptFailure::Request,
                "http_request_failed",
            ),
        ];
        for (case, error, expected_failure, expected_code) in cases {
            let failure = classify_reqwest_error(&error);
            assert_eq!(failure, expected_failure, "wrong reqwest class for {case}");
            let response = failure
                .outcome_unknown_response()
                .expect("reachable non-connect failures have diagnostics");
            assert_eq!(
                (response.transmission, response.error_code.as_deref(),),
                (
                    if expected_failure == HttpAttemptFailure::Build {
                        TransmissionState::NotSent
                    } else {
                        TransmissionState::OutcomeUnknown
                    },
                    Some(expected_code)
                ),
                "{case} must retain the safe transmission state and its distinct code"
            );
        }
    }

    /// An error whose source is itself, so its chain never ends.
    #[derive(Debug)]
    struct EndlessChain(String);

    impl std::fmt::Display for EndlessChain {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.0)
        }
    }

    impl std::error::Error for EndlessChain {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    #[test]
    fn error_chain_text_joins_sources_and_stays_bounded() {
        let chain = EndlessChain("connection reset".to_string());
        let text = error_chain_text(&chain);
        assert!(
            text.starts_with("connection reset: connection reset: connection reset"),
            "{text}"
        );
        assert_eq!(text.chars().count(), ERROR_CAUSE_LIMIT + 1, "{text}");
        assert!(text.ends_with('…'), "{text}");

        let huge = EndlessChain("é".repeat(ERROR_CAUSE_LIMIT * 4));
        let text = error_chain_text(&huge);
        assert_eq!(text.chars().count(), ERROR_CAUSE_LIMIT + 1);
    }

    #[test]
    fn retry_after_supports_seconds() {
        assert_eq!(parse_retry_after("2"), Some(Duration::from_secs(2)));
    }

    /// A vendor-supplied `Retry-After` can be any u64, and the deadline is
    /// computed while the per-connection lock is held, where a panic would
    /// poison the entry. The parse clamps, and the deadline arithmetic is
    /// total even for a delay that bypassed the parse.
    #[test]
    fn retry_after_is_clamped_and_its_deadline_cannot_overflow() {
        assert_eq!(
            parse_retry_after("18446744073709551615"),
            Some(MAX_RECORDED_THROTTLE)
        );
        assert_eq!(
            parse_retry_after("86400"),
            Some(MAX_RECORDED_THROTTLE),
            "a day-long throttle is recorded as the cap"
        );
        let now = Instant::now();
        let deadline = throttle_deadline(now, Duration::MAX).expect("a deadline is recorded");
        assert!(deadline <= now + MAX_RECORDED_THROTTLE);
        assert_eq!(throttle_deadline(now, Duration::ZERO), None);
    }

    /// A short throttle is waited out and cleared; a long one refuses and
    /// stays recorded, so the next request refuses as well.
    #[test]
    fn the_throttle_gate_waits_only_for_short_throttles() {
        let now = Instant::now();
        let mut none = None;
        assert_eq!(throttle_gate(&mut none, now), ThrottleGate::Clear);

        let mut short = Some(now + Duration::from_secs(1));
        assert_eq!(
            throttle_gate(&mut short, now),
            ThrottleGate::Wait(Duration::from_secs(1))
        );
        assert_eq!(short, None, "a throttle about to be waited out is cleared");

        let mut lapsed = Some(now);
        assert_eq!(throttle_gate(&mut lapsed, now), ThrottleGate::Clear);

        let long = now + MAX_THROTTLE_WAIT + Duration::from_secs(1);
        let mut recorded = Some(long);
        assert_eq!(
            throttle_gate(&mut recorded, now),
            ThrottleGate::Refuse(MAX_THROTTLE_WAIT + Duration::from_secs(1))
        );
        assert_eq!(recorded, Some(long), "a refusing throttle stays recorded");
    }

    /// Debug and log projections of an endpoint never carry its userinfo or
    /// its query, both of which can hold credentials.
    #[test]
    fn redacted_endpoint_hides_userinfo_and_query() {
        assert_eq!(
            redacted_endpoint("https://user:p@ss@vendor.example/mcp?key=SECRET"),
            "https://[redacted]@vendor.example/mcp?[redacted]"
        );
        assert_eq!(
            redacted_endpoint("https://user@vendor.example"),
            "https://[redacted]@vendor.example"
        );
        assert_eq!(
            redacted_endpoint("https://vendor.example/a@b"),
            "https://vendor.example/a@b",
            "an @ in the path is not userinfo"
        );
        assert_eq!(
            redacted_endpoint("https://vendor.example/mcp"),
            "https://vendor.example/mcp"
        );
    }

    /// Credential header values are marked sensitive, so the HTTP stack never
    /// prints them in Debug output or indexes them in HTTP/2 header
    /// compression.
    #[test]
    fn credential_headers_are_marked_sensitive() {
        let bindings = vec![CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "x-api-key".to_string(),
            prefix: String::new(),
            required: true,
        }];
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let headers = build_headers(&bindings, &credential).expect("credential headers");
        assert!(headers["x-api-key"].is_sensitive());
        assert!(!format!("{headers:?}").contains("CANARY"));
    }

    #[test]
    fn anonymous_credential_emits_no_headers() {
        let bindings = vec![CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "authorization".to_string(),
            prefix: "Bearer ".to_string(),
            required: true,
        }];
        let headers =
            build_headers(&bindings, &ResolvedCredential::anonymous()).expect("anonymous headers");
        assert!(headers.is_empty());
    }

    #[test]
    fn credential_payload_is_placed_with_binding_prefix() {
        let bindings = vec![CredentialBinding {
            ref_role: "credential".to_string(),
            placement: "header".to_string(),
            key: "authorization".to_string(),
            prefix: "Bearer ".to_string(),
            required: true,
        }];
        let credential = ResolvedCredential::new(b"CANARY".to_vec(), None, 1);
        let headers = build_headers(&bindings, &credential).expect("credential headers");
        assert_eq!(headers["authorization"], "Bearer CANARY");
    }
}

#[cfg(test)]
#[path = "transport_bounds_tests.rs"]
mod transport_bounds_tests;

#[cfg(test)]
mod binding_tests {
    use super::*;
    #[test]
    fn unsupported_credential_placement_is_not_silently_omitted() {
        let binding = CredentialBinding {
            ref_role: "credential".into(),
            placement: "query".into(),
            key: "key".into(),
            prefix: String::new(),
            required: true,
        };
        assert!(
            matches!(
                build_headers(
                    &[binding],
                    &ResolvedCredential::new(b"secret".to_vec(), None, 1)
                ),
                Err(CredentialHeaderError::InvalidBinding)
            ),
            "unsupported placement must fail closed"
        );
    }
}
