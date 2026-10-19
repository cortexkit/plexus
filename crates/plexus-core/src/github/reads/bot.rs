//! Repository-bound GitHub reads served through an agent's own GitHub App bot.
//!
//! These reads exist for agents' `gh` usage: a head's or worker's read goes out
//! with the installation token of the bot bound to the agent, never a personal
//! token, and only for repositories bound to that bot. Every read is still a
//! governed action on the bot's handle connection, so the calling module needs
//! its module grant there, and every HTTP request is charged to the handle's
//! read budget before it is sent (see `store/github_bot_reads.rs`).
//!
//! The policy checks a caller's request against are kept here, beside the
//! transport-side copy of the same checks in `rest_api/read_envelope.rs`, so
//! a path or media type plexus would refuse is refused again where the URL is
//! built.

use super::*;
use crate::scope::{BotReadIdentity, CallScope};
use crate::storage::github_bot_reads_store::{BotRateLimit, BotReadAdmission};

/// The `github_read` actions that always read with the calling agent's own
/// bot. A ranged CI job log read, `github.actions.job_log` with `offset` and
/// `length`, also reads with the bot (see [`job_log`]), but that action is not
/// listed here. The same action name also has an older form, a bounded tail
/// of the log read through the operator's GitHub Actions connection, and the
/// module decides per call which form applies. So the name stays in the CI
/// group of `reads::ACTIONS`.
pub const ACTIONS: &[&str] = &[
    "github.repo.get",
    "github.search.code",
    "github.search.issues",
];

/// The catalog action the bot form of a job log read checks the job with.
pub(crate) const JOB_GET_ACTION: &str = "github.actions.job.get";
pub(crate) const JOB_LOG_ACTION: &str = "github.actions.job_log";

/// The media types `github.repo.get` may ask for, the first being the default.
pub const ACCEPTED_MEDIA_TYPES: &[&str] = &[
    "application/vnd.github+json",
    "application/vnd.github.raw+json",
    "application/vnd.github.diff",
    "application/vnd.github.patch",
];

/// A bot read reply body larger than this is refused, never truncated: a
/// truncated file or diff would read as the whole thing.
pub const MAX_BOT_READ_BODY_BYTES: usize = 1024 * 1024;
/// The default and largest `length` a job log range read returns.
pub const MAX_JOB_LOG_RANGE_BYTES: u64 = 1_048_576;
/// GitHub's own page-size ceiling for search.
const MAX_SEARCH_PER_PAGE: u64 = 100;

/// How the transport sends and answers a bot read action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnvelopeShape {
    /// The action takes a caller `path` below `/repos/{owner}/{repo}`.
    pub relative_path: bool,
}

/// The bot read actions whose reply carries the HTTP status, the next page and
/// GitHub's rate-limit headers alongside the body. Keyed by action name, which
/// only the reviewed `github_rest` catalog declares.
pub(crate) fn envelope_shape(action: &str) -> Option<EnvelopeShape> {
    match action {
        "github.repo.get" => Some(EnvelopeShape {
            relative_path: true,
        }),
        "github.search.code" | "github.search.issues" | JOB_GET_ACTION => Some(EnvelopeShape {
            relative_path: false,
        }),
        _ => None,
    }
}

/// The media type to send, or `None` when the caller asked for one that is
/// not allowed.
pub(crate) fn accepted_media_type(accept: Option<&Value>) -> Option<&'static str> {
    match accept {
        None => Some(ACCEPTED_MEDIA_TYPES[0]),
        Some(Value::String(asked)) => ACCEPTED_MEDIA_TYPES
            .iter()
            .copied()
            .find(|allowed| *allowed == asked),
        Some(_) => None,
    }
}

/// Whether a reply in this media type is JSON plexus parses, rather than raw
/// file content, a diff or a patch it returns as a string.
pub(crate) fn media_type_is_json(media_type: &str) -> bool {
    media_type == ACCEPTED_MEDIA_TYPES[0]
}

/// Validate a caller's path below `/repos/{owner}/{name}/` and return it
/// encoded for the URL, with its leading `/`, or `""` for the repository
/// itself. Refused: an absolute URL, a leading `/` (a lone `/` included), an
/// empty segment (`//`), a `.` or `..` segment in any spelling, a
/// percent-encoded `/` or `\`, a backslash, a query or fragment marker, and
/// control characters. Characters a path segment may carry pass unchanged;
/// anything else is percent-encoded, so the path cannot change the URL's
/// structure.
pub(crate) fn relative_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some(String::new());
    }
    if path.starts_with('/')
        || path.contains("//")
        || path.contains("://")
        || path.contains(['\\', '?', '#'])
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let mut encoded = String::with_capacity(path.len() + 1);
    for (index, segment) in path.split('/').enumerate() {
        // `scheme:rest` in the first segment would read as an absolute URL.
        if index == 0 && segment.contains(':') {
            return None;
        }
        if !segment_is_plain(segment) {
            return None;
        }
        encoded.push('/');
        encode_segment(segment, &mut encoded);
    }
    Some(encoded)
}

/// A segment that cannot decode, however many times, into `.`, `..`, or
/// anything containing a separator.
fn segment_is_plain(segment: &str) -> bool {
    let mut decoded = segment.to_ascii_lowercase();
    for _ in 0..8 {
        if decoded.contains(['/', '\\']) || decoded == "." || decoded == ".." {
            return false;
        }
        let next = decoded
            .replace("%25", "%")
            .replace("%2f", "/")
            .replace("%5c", "\\")
            .replace("%2e", ".");
        if next == decoded {
            return true;
        }
        decoded = next;
    }
    false
}

fn encode_segment(segment: &str, out: &mut String) {
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let escape = byte == b'%'
            && bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit);
        if escape || byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
        index += 1;
    }
}

/// The page number of GitHub's `Link` header `rel="next"` target.
pub(crate) fn next_page(link: Option<&str>) -> Option<u64> {
    link?.split(',').find_map(|part| {
        let (target, params) = part.trim().split_once(';')?;
        if !params
            .split(';')
            .any(|param| param.trim() == "rel=\"next\"")
        {
            return None;
        }
        let target = target.trim().strip_prefix('<')?.strip_suffix('>')?;
        let (_, query) = target.split_once('?')?;
        query.split('&').find_map(|pair| {
            pair.strip_prefix("page=")
                .and_then(|page| page.parse::<u64>().ok())
        })
    })
}

/// Why a bot read was refused or failed.
#[derive(Debug, Clone, PartialEq)]
pub enum BotReadError {
    /// The route's stamp names no agent a bot read can use.
    AgentIdentityRequired,
    /// The repository is not bound to the agent's enabled bot.
    RepositoryNotVisible,
    /// The named argument asks for something these reads do not serve.
    EndpointNotAllowed {
        field: String,
    },
    /// The handle's read budget has no room; nothing was sent.
    BudgetExhausted {
        retry_after_ms: i64,
    },
    /// GitHub answered with a body over [`MAX_BOT_READ_BODY_BYTES`].
    ResponseTooLarge,
    /// GitHub answered with this non-2xx status.
    Vendor {
        status: u16,
    },
    /// A job log was asked for before its job completed.
    JobNotFinished,
    /// A job log download failed after GitHub was asked, with this code.
    JobLog(&'static str),
    Denied(Denial),
    Dispatch(TransportOutcome),
    InvalidResponse,
}

fn not_allowed(field: &str) -> BotReadError {
    BotReadError::EndpointNotAllowed {
        field: field.to_owned(),
    }
}

fn arguments<'a>(
    args: &'a Value,
    allowed: &[&str],
) -> Result<&'a Map<String, Value>, BotReadError> {
    let fields = args.as_object().ok_or_else(|| not_allowed("args"))?;
    if let Some(field) = fields.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(not_allowed(field));
    }
    Ok(fields)
}

fn positive(
    fields: &Map<String, Value>,
    field: &str,
    max: u64,
) -> Result<Option<u64>, BotReadError> {
    match fields.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|value| (1..=max).contains(value))
            .map(Some)
            .ok_or_else(|| not_allowed(field)),
    }
}

/// Build the vendor arguments for a bot read, refusing any argument these
/// reads do not serve. `owner` and `repo` come from the bound repository,
/// never from the caller.
fn vendor_args(
    action: &str,
    owner: &str,
    repo: &str,
    args: &Value,
) -> Result<Map<String, Value>, BotReadError> {
    let mut vendor = Map::from_iter([("owner".into(), json!(owner)), ("repo".into(), json!(repo))]);
    match action {
        "github.repo.get" => {
            let fields = arguments(args, &["path", "query", "accept"])?;
            let path = fields
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| not_allowed("path"))?;
            relative_path(path).ok_or_else(|| not_allowed("path"))?;
            vendor.insert("path".into(), json!(path));
            if let Some(query) = fields.get("query") {
                let flat = query.as_object().filter(|query| {
                    query
                        .iter()
                        .all(|(key, value)| !key.is_empty() && value.is_string())
                });
                vendor.insert(
                    "query".into(),
                    Value::Object(flat.ok_or_else(|| not_allowed("query"))?.clone()),
                );
            }
            let accept =
                accepted_media_type(fields.get("accept")).ok_or_else(|| not_allowed("accept"))?;
            vendor.insert("accept".into(), json!(accept));
        }
        "github.search.code" | "github.search.issues" => {
            let fields = arguments(args, &["q", "page", "per_page"])?;
            let q = fields
                .get("q")
                .and_then(Value::as_str)
                .ok_or_else(|| not_allowed("q"))?;
            // The search is fenced to the bound repository by the qualifier
            // plexus appends; a caller qualifier naming any other scope would
            // widen it, so any spelling of one is refused.
            let lower = q.to_ascii_lowercase();
            if ["repo:", "org:", "user:"]
                .iter()
                .any(|qualifier| lower.contains(qualifier))
            {
                return Err(not_allowed("q"));
            }
            vendor.insert("q".into(), json!(format!("{q} repo:{owner}/{repo}")));
            if let Some(page) = positive(fields, "page", u64::from(u32::MAX))? {
                vendor.insert("page".into(), json!(page));
            }
            if let Some(per_page) = positive(fields, "per_page", MAX_SEARCH_PER_PAGE)? {
                vendor.insert("per_page".into(), json!(per_page));
            }
        }
        _ => {
            return Err(BotReadError::Denied(Denial::Catalog(
                CatalogDenial::NotFound,
            )))
        }
    }
    Ok(vendor)
}

/// The bot that serves `identity`'s reads of `repository`, which must be bound
/// to that agent's enabled handle.
fn visible_handle(
    store: &PlexusStore,
    identity: &BotReadIdentity,
    repository: &str,
) -> Result<GithubHandle, BotReadError> {
    store
        .github_handle_for_repo(repository)
        .map_err(|_| BotReadError::Denied(Denial::StoreFailure))?
        .filter(|handle| handle.agent_id == identity.agent() && handle.status == "enabled")
        .ok_or(BotReadError::RepositoryNotVisible)
}

struct BotCall<'a, C: CredentialSource + ?Sized, T: Transport + ?Sized> {
    engine: &'a GovernanceEngine<C, T>,
    principal: &'a str,
    repository: String,
    identity: BotReadIdentity,
    scope: Option<&'a CallScope>,
    handle: GithubHandle,
}

impl<C: CredentialSource + ?Sized, T: Transport + ?Sized> BotCall<'_, C, T> {
    /// Authorize, charge `units` requests to the handle's read budget, and
    /// send one governed action on the bot's handle connection.
    fn dispatch(
        &self,
        action: &str,
        args: Map<String, Value>,
        units: i64,
    ) -> Result<Value, BotReadError> {
        let store = self.engine.store();
        let mut request = AuthorizationRequest::new(
            self.principal,
            &self.handle.connection_id,
            action,
            Value::Object(args),
        )
        .with_diagnostic_tool("github")
        .with_resolved_repository(self.repository.clone());
        if let Some(scope) = self.scope {
            // Reads use the calling module's grants. The stamp's agent is
            // recorded and chooses the bot, but no agent grant applies.
            request = request.with_scope_attribution_only(scope.clone());
        }
        request = match &self.identity {
            BotReadIdentity::Head(agent) => request.with_attributed_agent(agent.as_str()),
            BotReadIdentity::OnBehalfOf(agent) => request.with_on_behalf_of_agent(agent.as_str()),
        };
        let reservation = self
            .engine
            .authorize(request)
            .map_err(BotReadError::Denied)?;
        // The binding can move while authorization runs, and the budget is
        // charged only for a read that is about to be sent.
        let now = crate::storage::now_ms();
        let admitted = visible_handle(store, &self.identity, &self.repository).and_then(|handle| {
            if handle.app_handle_id != self.handle.app_handle_id {
                return Err(BotReadError::RepositoryNotVisible);
            }
            match store
                .reserve_github_bot_read(&self.handle.app_handle_id, units, now)
                .map_err(|_| BotReadError::Denied(Denial::StoreFailure))?
            {
                BotReadAdmission::Reserved => Ok(()),
                BotReadAdmission::Exhausted { retry_after_ms } => {
                    Err(BotReadError::BudgetExhausted { retry_after_ms })
                }
            }
        });
        if let Err(error) = admitted {
            store
                .abandon_reservation(&reservation.principal, &reservation.reservation_id)
                .map_err(|_| BotReadError::Denied(Denial::StoreFailure))?;
            return Err(error);
        }
        let outcome = self.engine.revalidate_and_dispatch(&reservation).outcome;
        match outcome {
            TransportOutcome::Completed {
                response: Some(response),
            } => {
                self.record_rate_limit(response.get("rate_limit"));
                Ok(response)
            }
            TransportOutcome::VendorFailed { code, message } => {
                let projection = serde_json::from_str::<Value>(&message).ok();
                self.record_rate_limit(
                    projection
                        .as_ref()
                        .and_then(|value| value.get("rate_limit")),
                );
                Err(vendor_failure(&code, projection.as_ref()))
            }
            other => Err(BotReadError::Dispatch(other)),
        }
    }

    fn record_rate_limit(&self, limit: Option<&Value>) {
        let Some(limit) = limit else { return };
        let (Some(remaining), Some(reset_at_ms)) = (
            limit.get("remaining").and_then(Value::as_i64),
            limit.get("reset_at_ms").and_then(Value::as_i64),
        ) else {
            return;
        };
        let now = crate::storage::now_ms();
        if let Err(error) = self.engine.store().record_github_bot_rate_limit(
            &self.handle.app_handle_id,
            BotRateLimit {
                remaining,
                reset_at_ms,
            },
            now,
        ) {
            eprintln!(warn governance: "recording a GitHub bot rate limit failed: {error}");
        }
    }
}

/// Map a GitHub failure the transport reported: a status for a non-2xx
/// answer (in the code or the projection it attached), a size refusal, or a
/// job log download failure.
fn vendor_failure(code: &str, projection: Option<&Value>) -> BotReadError {
    if code == "response_too_large" {
        return BotReadError::ResponseTooLarge;
    }
    // Governance renames a 401 on a bot handle once it has told the vault the
    // installation token was rejected.
    if code == "handle_credential_rejected" {
        return BotReadError::Vendor { status: 401 };
    }
    let status = code
        .strip_prefix("http_")
        .and_then(|status| status.parse::<u16>().ok())
        .or_else(|| {
            projection
                .and_then(|value| value.get("status"))
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
        });
    if let Some(status) = status {
        return BotReadError::Vendor { status };
    }
    match code {
        "job_log_unavailable" => BotReadError::JobLog("job_log_unavailable"),
        "job_log_redirect_refused" => BotReadError::JobLog("job_log_redirect_refused"),
        "job_log_read_limit" => BotReadError::JobLog("job_log_read_limit"),
        _ => BotReadError::JobLog("job_log_download_failed"),
    }
}

fn prepare<'a, C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &'a GovernanceEngine<C, T>,
    principal: &'a str,
    repository: &Value,
    scope: Option<&'a CallScope>,
    on_behalf_of_agent: Option<&str>,
) -> Result<BotCall<'a, C, T>, BotReadError> {
    let identity = crate::scope::bot_read_identity(scope, on_behalf_of_agent)
        .ok_or(BotReadError::AgentIdentityRequired)?;
    let repository = repository
        .as_str()
        .map(crate::github::canonical_repository)
        .filter(|name| resolver::split_repository(name).is_ok())
        .ok_or(BotReadError::RepositoryNotVisible)?;
    let handle = visible_handle(engine.store(), &identity, &repository)?;
    Ok(BotCall {
        engine,
        principal,
        repository,
        identity,
        scope,
        handle,
    })
}

/// Serve one of [`ACTIONS`] with the GitHub bot of the agent the call is for.
/// That agent is the head's `agent_id` in `scope`, or `on_behalf_of_agent` for
/// a worker; the bot is the one bound to the repository in `repository`, and
/// it must belong to that agent.
pub fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    action: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&CallScope>,
    on_behalf_of_agent: Option<&str>,
) -> Result<Value, BotReadError> {
    let call = prepare(engine, principal, repository, scope, on_behalf_of_agent)?;
    let (owner, repo) = resolver::split_repository(&call.repository)
        .map_err(|_| BotReadError::RepositoryNotVisible)?;
    let vendor = vendor_args(action, owner, repo, args)?;
    let response = call.dispatch(action, vendor, 1)?;
    let next_page = response.get("next_page").cloned().unwrap_or(Value::Null);
    let body = response.get("body").cloned().unwrap_or(Value::Null);
    if action == "github.repo.get" {
        return Ok(json!({"status": response["status"], "body": body, "next_page": next_page}));
    }
    let (Some(total_count), Some(incomplete_results), Some(items)) = (
        body.get("total_count").filter(|value| value.is_u64()),
        body.get("incomplete_results")
            .filter(|value| value.is_boolean()),
        body.get("items").filter(|value| value.is_array()),
    ) else {
        return Err(BotReadError::InvalidResponse);
    };
    Ok(json!({
        "total_count": total_count,
        "incomplete_results": incomplete_results,
        "items": items,
        "next_page": next_page,
    }))
}

/// The bot form of `github.actions.job_log`: a byte range of a finished job's
/// log, read with the bot's installation token. The job is checked first (one
/// request); the log read is two, GitHub's redirect answer and the storage
/// download it points to, which carries no credential.
pub fn job_log<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&CallScope>,
    on_behalf_of_agent: Option<&str>,
) -> Result<Value, BotReadError> {
    let call = prepare(engine, principal, repository, scope, on_behalf_of_agent)?;
    let fields = arguments(args, &["job_id", "offset", "length"])?;
    let job_id = fields
        .get("job_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| not_allowed("job_id"))?;
    let offset = match fields.get("offset") {
        None => 0,
        Some(value) => value.as_u64().ok_or_else(|| not_allowed("offset"))?,
    };
    let length =
        positive(fields, "length", MAX_JOB_LOG_RANGE_BYTES)?.unwrap_or(MAX_JOB_LOG_RANGE_BYTES);
    let (owner, repo) = resolver::split_repository(&call.repository)
        .map_err(|_| BotReadError::RepositoryNotVisible)?;
    let job = call.dispatch(
        JOB_GET_ACTION,
        Map::from_iter([
            ("owner".into(), json!(owner)),
            ("repo".into(), json!(repo)),
            ("job_id".into(), json!(job_id)),
        ]),
        1,
    )?;
    if job["body"].get("status").and_then(Value::as_str) != Some("completed") {
        return Err(BotReadError::JobNotFinished);
    }
    let log = call.dispatch(
        JOB_LOG_ACTION,
        Map::from_iter([
            ("owner".into(), json!(owner)),
            ("repo".into(), json!(repo)),
            ("job_id".into(), json!(job_id)),
            ("offset".into(), json!(offset)),
            ("length".into(), json!(length)),
        ]),
        2,
    )?;
    let (Some(body), Some(offset), Some(length), Some(total_bytes)) = (
        log.get("body").filter(|value| value.is_string()),
        log.get("offset").filter(|value| value.is_u64()),
        log.get("length").filter(|value| value.is_u64()),
        log.get("total_bytes").filter(|value| value.is_u64()),
    ) else {
        return Err(BotReadError::InvalidResponse);
    };
    Ok(json!({"body": body, "offset": offset, "length": length, "total_bytes": total_bytes}))
}

#[cfg(test)]
#[path = "bot_tests.rs"]
mod tests;
