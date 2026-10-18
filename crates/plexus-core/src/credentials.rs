//! Credential custody seam used by governance and the in-process harness.
//!
//! The trait resolves bearer handles or vault references into a zeroizing payload. The
//! stub keys responses by a fingerprint, so its configuration and diagnostics
//! never need to retain the raw handle.

#[cfg(any(test, feature = "test-support"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;
use std::sync::Mutex;

use zeroize::{Zeroize, Zeroizing};

use crate::fingerprint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermanentCredentialError {
    NotFound,
    RefreshUnsupported,
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransientCredentialError {
    RefreshFailed,
    VaultLocked,
    ContextOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    Permanent(PermanentCredentialError),
    AuthRequired,
    Transient(TransientCredentialError),
}

impl CredentialError {
    pub fn class(&self) -> &'static str {
        match self {
            Self::Permanent(_) => "permanent",
            Self::AuthRequired => "auth_required",
            Self::Transient(_) => "transient",
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permanent(reason) => write!(formatter, "permanent credential error: {reason:?}"),
            Self::AuthRequired => formatter.write_str("credential authentication required"),
            Self::Transient(reason) => write!(formatter, "transient credential error: {reason:?}"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// A resolved credential whose payload is zeroized when dropped.
#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-support"), derive(PartialEq, Eq))]
pub struct ResolvedCredential {
    payload: Zeroizing<Vec<u8>>,
    pub expires_at_ms: Option<i64>,
    pub record_version: u64,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedCredential")
            .field("payload_present", &!self.payload.is_empty())
            .field("payload_len", &self.payload.len())
            .field("expires_at_ms", &self.expires_at_ms)
            .field("record_version", &self.record_version)
            .finish()
    }
}

impl ResolvedCredential {
    /// The credential for a vendor whose reviewed manifest declares
    /// `auth.mode = none`: an empty payload that never leaves the process,
    /// because such a vendor has nothing to present. Header binding skips
    /// empty payloads, so an anonymous credential cannot produce a header
    /// carrying only a prefix (an `Authorization: Bearer ` with no token would
    /// look like a malformed credential to the vendor rather than an absent
    /// one).
    pub fn anonymous() -> Self {
        Self {
            payload: Zeroizing::new(Vec::new()),
            expires_at_ms: None,
            record_version: 0,
        }
    }

    pub fn new(payload: Vec<u8>, expires_at_ms: Option<i64>, record_version: u64) -> Self {
        Self {
            payload: Zeroizing::new(payload),
            expires_at_ms,
            record_version,
        }
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }
}

/// The credential source is deliberately narrower than the claustrum vault's wire API.
pub trait CredentialSource: Send + Sync {
    fn get_by_id(&self, _credential_id: &str) -> Result<ResolvedCredential, CredentialError> {
        Err(CredentialError::Permanent(
            PermanentCredentialError::NotFound,
        ))
    }

    fn report_id_auth_failure(&self, _credential_id: &str, _provider_status: u16) {}
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, PartialEq, Eq)]
pub enum StubCredentialResponse {
    Success {
        payload: Vec<u8>,
        expires_at_ms: Option<i64>,
        record_version: u64,
    },
    Error(CredentialError),
}

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Debug for StubCredentialResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success {
                payload,
                expires_at_ms,
                record_version,
            } => formatter
                .debug_struct("Success")
                .field("payload_len", &payload.len())
                .field("expires_at_ms", expires_at_ms)
                .field("record_version", record_version)
                .finish(),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
        }
    }
}

/// Configurable in-process source for governance tests. It never exposes raw
/// credential names in its map keys or error messages.
#[derive(Clone, Default)]
#[cfg(any(test, feature = "test-support"))]
pub struct StubCredentialSource {
    responses: Arc<Mutex<HashMap<String, StubCredentialResponse>>>,
    default_response: Arc<Mutex<Option<StubCredentialResponse>>>,
    /// Auth failures reported back to the vault, as (fingerprint, status,
    /// record_version).
    ///
    /// Recorded because the trait's default implementation of
    /// `report_id_auth_failure` is an empty body, so a stub that does not override
    /// it cannot distinguish a caller that reports from one that never does.
    /// The fingerprint is stored rather than the credential name.
    auth_failure_reports: Arc<Mutex<Vec<(String, u16, u64)>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl StubCredentialSource {
    pub fn with_default_success(payload: Vec<u8>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(HashMap::new())),
            default_response: Arc::new(Mutex::new(Some(StubCredentialResponse::Success {
                payload,
                expires_at_ms: None,
                record_version: 1,
            }))),
            auth_failure_reports: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_default_response(&self, response: StubCredentialResponse) {
        if let Ok(mut current) = self.default_response.lock() {
            *current = Some(response);
        }
    }

    pub fn set_response(&self, handle: &[u8], response: StubCredentialResponse) {
        if let Ok(mut responses) = self.responses.lock() {
            responses.insert(fingerprint(handle), response);
        }
    }

    pub fn set_success(
        &self,
        handle: &[u8],
        payload: Vec<u8>,
        expires_at_ms: Option<i64>,
        record_version: u64,
    ) {
        self.set_response(
            handle,
            StubCredentialResponse::Success {
                payload,
                expires_at_ms,
                record_version,
            },
        );
    }

    pub fn set_error(&self, handle: &[u8], error: CredentialError) {
        self.set_response(handle, StubCredentialResponse::Error(error));
    }

    /// Auth failures this source was told about, in order.
    pub fn auth_failure_reports(&self) -> Vec<(String, u16, u64)> {
        self.auth_failure_reports
            .lock()
            .map(|reports| reports.clone())
            .unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CredentialSource for StubCredentialSource {
    fn report_id_auth_failure(&self, id: &str, status: u16) {
        if let Ok(mut reports) = self.auth_failure_reports.lock() {
            reports.push((fingerprint(id.as_bytes()), status, 0));
        }
    }

    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        let key = fingerprint(id.as_bytes());
        let response = self
            .responses
            .lock()
            .map_err(|_| CredentialError::Transient(TransientCredentialError::VaultLocked))?
            .get(&key)
            .cloned()
            .or_else(|| {
                self.default_response
                    .lock()
                    .ok()
                    .and_then(|value| value.clone())
            })
            .ok_or(CredentialError::Permanent(
                PermanentCredentialError::NotFound,
            ))?;
        match response {
            StubCredentialResponse::Success {
                payload,
                expires_at_ms,
                record_version,
            } => Ok(ResolvedCredential::new(
                payload,
                expires_at_ms,
                record_version,
            )),
            StubCredentialResponse::Error(error) => Err(error),
        }
    }
}

/// Production fail-closed source used when the module is configured for the
/// real vault but the vault's credential route is missing or unreachable. It never falls
/// back to a stub payload.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedCredentialSource;

impl CredentialSource for FailClosedCredentialSource {
    fn get_by_id(&self, _credential_id: &str) -> Result<ResolvedCredential, CredentialError> {
        Err(CredentialError::Transient(
            TransientCredentialError::VaultLocked,
        ))
    }
}

/// Stored authority, not the resolved vendor secret. Debug exposes only the kind.
pub enum ConnectionCredentialBinding {
    Reference(String),
}

impl std::fmt::Debug for ConnectionCredentialBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl ConnectionCredentialBinding {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Reference(_) => "reference",
        }
    }

    pub(crate) fn fingerprint(&self) -> String {
        match self {
            Self::Reference(id) => fingerprint(format!("vault-reference:{id}").as_bytes()),
        }
    }

    pub fn resolve<C: CredentialSource + ?Sized>(
        &self,
        source: &C,
    ) -> Result<ResolvedCredential, CredentialError> {
        match self {
            Self::Reference(id) => source.get_by_id(id),
        }
    }

    pub(crate) fn report_auth_failure<C: CredentialSource + ?Sized>(&self, source: &C) {
        match self {
            Self::Reference(id) => source.report_id_auth_failure(id, 401),
        }
    }
}

/// IDs have one namespace separator and nonempty, printable ASCII components.
/// Reject whitespace and control characters before ids reach wire or operator output.
pub fn valid_credential_id(id: &str) -> bool {
    let Some((namespace, name)) = id.split_once(':') else {
        return false;
    };
    !namespace.is_empty()
        && !name.is_empty()
        && id.len() <= 512
        && namespace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_id_lookup_is_transient_vault_locked() {
        assert_eq!(
            FailClosedCredentialSource
                .get_by_id("ckcred:fixture")
                .unwrap_err(),
            CredentialError::Transient(TransientCredentialError::VaultLocked)
        );
    }

    #[test]
    fn stub_response_debug_never_prints_payload_bytes() {
        let response = StubCredentialResponse::Success {
            payload: b"CANARY-STUB-SECRET".to_vec(),
            expires_at_ms: None,
            record_version: 1,
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("CANARY"));
        assert!(
            !debug.contains("67, 65, 78"),
            "Debug must not render raw secret bytes"
        );
    }

    #[test]
    fn stub_supports_each_ckcred_error_class_by_name() {
        let source = StubCredentialSource::default();
        let handle = b"canary-credential";
        source.set_error(
            handle,
            CredentialError::Permanent(PermanentCredentialError::Corrupt),
        );
        assert_eq!(
            source.get_by_id(std::str::from_utf8(handle).unwrap()),
            Err(CredentialError::Permanent(
                PermanentCredentialError::Corrupt
            ))
        );
        source.set_error(handle, CredentialError::AuthRequired);
        assert_eq!(
            source.get_by_id(std::str::from_utf8(handle).unwrap()),
            Err(CredentialError::AuthRequired)
        );
        source.set_error(
            handle,
            CredentialError::Transient(TransientCredentialError::VaultLocked),
        );
        assert_eq!(
            source.get_by_id(std::str::from_utf8(handle).unwrap()),
            Err(CredentialError::Transient(
                TransientCredentialError::VaultLocked
            ))
        );
    }

    #[test]
    fn resolved_payload_is_only_available_by_borrowing() {
        let value = ResolvedCredential::new(b"secret".to_vec(), None, 1);
        assert_eq!(value.payload(), b"secret");
    }

    #[test]
    fn resolved_credential_debug_omits_payload_bytes_in_all_renderings() {
        let credential = ResolvedCredential::new(b"AAAA".to_vec(), Some(1_700_000_000_000), 7);
        let rendered = format!("{credential:?}");

        assert!(
            !rendered.contains("AAAA"),
            "debug projection exposed credential payload as text"
        );
        assert!(
            !rendered.contains("65, 65, 65, 65"),
            "debug projection exposed credential payload as decimal bytes"
        );
        assert!(
            rendered
                == "ResolvedCredential { payload_present: true, payload_len: 4, expires_at_ms: Some(1700000000000), record_version: 7 }",
            "debug projection shape changed from its four non-secret fields"
        );
    }

    #[test]
    fn resolved_credential_debug_includes_non_secret_diagnostics() {
        let credential = ResolvedCredential::new(b"AAAA".to_vec(), Some(1_700_000_000_000), 7);
        let rendered = format!("{credential:?}");

        assert!(
            rendered.contains("payload_present: true"),
            "debug projection omitted payload presence"
        );
        assert!(
            rendered.contains("payload_len: 4"),
            "debug projection omitted payload length"
        );
        assert!(
            rendered.contains("expires_at_ms: Some(1700000000000)"),
            "debug projection omitted credential expiry"
        );
        assert!(
            rendered.contains("record_version: 7"),
            "debug projection omitted record version"
        );
    }

    #[test]
    fn anonymous_credential_debug_is_distinguishable_without_claiming_payload() {
        let anonymous = format!("{:?}", ResolvedCredential::anonymous());
        let populated = format!("{:?}", ResolvedCredential::new(b"AAAA".to_vec(), None, 0));

        assert!(
            anonymous.contains("payload_present: false"),
            "anonymous credential projection claimed a payload"
        );
        assert!(
            anonymous.contains("payload_len: 0"),
            "anonymous credential projection omitted its empty length"
        );
        assert!(
            anonymous != populated,
            "anonymous and populated credential projections were indistinguishable"
        );
    }
}

/// Errors raised while carrying a vault credential request over the subc route. The
/// route peer deliberately exposes no response body in its error type because
/// credential-module payloads are not safe diagnostic material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkcredRouteError {
    NotSent,
    OutcomeUnknown,
    Transport,
}

/// Narrow route seam used by the vault credential adapter. Production code can implement
/// it with a subc route client; tests use a route-peer mock rather than mocking
/// the credential source itself.
pub trait CkcredRoutePeer: Send + Sync {
    fn call(
        &self,
        operation: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, CkcredRouteError>;
}

/// Claustrum vault credential source speaking the shipped `credential.get` and
/// `credential.report_auth_failure` operations over a route peer.
pub struct CkcredCredentialSource<P> {
    peer: std::sync::Arc<P>,
    /// The queue feeding the one thread that sends auth-failure reports,
    /// started by the first report and shared by every clone of this source.
    reports: std::sync::Arc<Mutex<Option<std::sync::mpsc::SyncSender<WipingValue>>>>,
}

/// Queue ownership includes wiping reports that are dropped before delivery.
struct WipingValue(serde_json::Value);
impl Drop for WipingValue {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

/// How many auth-failure reports may wait for the vault at once. A report is
/// best effort, so once this many are waiting a new one is dropped (and
/// logged) instead of queueing without limit or blocking the caller.
const AUTH_FAILURE_REPORT_QUEUE: usize = 64;

impl<P> Clone for CkcredCredentialSource<P> {
    fn clone(&self) -> Self {
        Self {
            peer: std::sync::Arc::clone(&self.peer),
            reports: std::sync::Arc::clone(&self.reports),
        }
    }
}

impl<P> CkcredCredentialSource<P> {
    pub fn new(peer: std::sync::Arc<P>) -> Self {
        Self {
            peer,
            reports: std::sync::Arc::new(Mutex::new(None)),
        }
    }
}

impl<P: CkcredRoutePeer + 'static> CredentialSource for CkcredCredentialSource<P> {
    fn get_by_id(&self, credential_id: &str) -> Result<ResolvedCredential, CredentialError> {
        let scoped = self.get_scoped(credential_id)?;
        if scoped.credential_id != credential_id {
            return Err(CredentialError::Permanent(
                PermanentCredentialError::Corrupt,
            ));
        }
        Ok(scoped.credential)
    }

    fn report_id_auth_failure(&self, credential_id: &str, provider_status: u16) {
        if provider_status == 401 {
            self.report_scoped_auth_failure(credential_id, provider_status);
        }
    }
}

impl<P: CkcredRoutePeer + 'static> CkcredCredentialSource<P> {
    /// Hand one report to the reporting thread without waiting for the vault.
    /// The provider call has already reached its outcome, so a report that
    /// cannot be queued is dropped rather than delaying the caller.
    fn queue_auth_failure_report(&self, params: serde_json::Value) {
        let params = WipingValue(params);
        let mut reports = self
            .reports
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if reports.is_none() {
            let (sender, receiver) =
                std::sync::mpsc::sync_channel::<WipingValue>(AUTH_FAILURE_REPORT_QUEUE);
            let peer = std::sync::Arc::clone(&self.peer);
            // The thread ends once every clone of this source is gone, because
            // that drops the last sender.
            let spawned = std::thread::Builder::new()
                .name("ckcred-auth-failure-report".into())
                .spawn(move || {
                    for mut params in receiver {
                        if let Err(error) = peer.call("credential.report_auth_failure", params.0.take()) {
                            eprintln!(warn transport: "credential auth-failure report failed: {error:?}");
                        }
                    }
                });
            match spawned {
                Ok(_) => *reports = Some(sender),
                Err(error) => {
                    eprintln!(warn transport: "credential auth-failure report dropped: reporting thread could not start: {error}");
                    return;
                }
            }
        }
        let Some(sender) = reports.as_ref() else {
            return;
        };
        match sender.try_send(params) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                eprintln!(warn transport: "credential auth-failure report dropped: queue full");
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                // The reporting thread died; the next report starts another.
                *reports = None;
                eprintln!(warn transport: "credential auth-failure report dropped: reporting thread gone");
            }
        }
    }
}

impl<P: CkcredRoutePeer + 'static> CkcredCredentialSource<P> {
    /// Report a rejected scoped credential to the vault without exposing the token.
    pub fn report_scoped_auth_failure(&self, credential_id: &str, status: u16) {
        if status != 401 {
            return;
        }
        self.queue_auth_failure_report(serde_json::json!({
            "credential_id": credential_id, "provider_status": status
        }));
    }
}

impl<P: CkcredRoutePeer> CkcredCredentialSource<P> {
    /// Read a minted installation token by vault id, never an App private key.
    /// The daemon's subc client authenticates the module on this route.
    ///
    /// The vault answers `get_scoped` with the same body as `credential.get`:
    /// the token as a JSON array of byte integers plus `expires_at_ms` and
    /// `record_version`, with the `credential_id` it actually resolved beside
    /// them. The token bytes are opaque. GitHub's installation token format is
    /// GitHub's choice, and a vault can serve one that is neither `ghs_`
    /// prefixed nor 40 characters, so nothing here inspects its shape.
    pub fn get_scoped(&self, credential_id: &str) -> Result<ScopedCredential, CredentialError> {
        let response = self
            .peer
            .call(
                "credential.get_scoped",
                serde_json::json!({ "credential_id": credential_id }),
            )
            .map_err(route_error_to_credential_error)?;
        let resolved_id = response
            .get("result")
            .and_then(|result| result.get("credential_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let credential = parse_credential_get_response(response)?;
        let resolved_id = resolved_id.ok_or(CredentialError::Permanent(
            PermanentCredentialError::Corrupt,
        ))?;
        Ok(ScopedCredential {
            credential_id: resolved_id,
            credential,
        })
    }
}

/// Vault response keeps the resolved id alongside the installation token so
/// the handle owner can reject a route that resolved a different App.
#[derive(Debug)]
pub struct ScopedCredential {
    pub credential_id: String,
    pub credential: ResolvedCredential,
}

fn route_error_to_credential_error(error: CkcredRouteError) -> CredentialError {
    match error {
        CkcredRouteError::NotSent
        | CkcredRouteError::OutcomeUnknown
        | CkcredRouteError::Transport => {
            CredentialError::Transient(TransientCredentialError::RefreshFailed)
        }
    }
}

fn parse_credential_get_response(
    mut response: serde_json::Value,
) -> Result<ResolvedCredential, CredentialError> {
    take_credential(&mut response)
}

/// Read the credential out of a `credential.get` style response and then
/// overwrite the token in the response itself. The response carries the token
/// as JSON numbers; they are overwritten whether or not the body parsed, so
/// no copy of the token outlives this call in the response.
fn take_credential(
    response: &mut serde_json::Value,
) -> Result<ResolvedCredential, CredentialError> {
    let parsed = read_credential_body(response);
    wipe_credential_payload(response);
    parsed
}

/// Overwrite every token byte a `credential.get` style response carries, in
/// place. Each array element is replaced by the number 0 (the same JSON number
/// shape, so the old value's memory is written over) and a string payload, the
/// shape an older vault used, is zeroized.
fn wipe_credential_payload(response: &mut serde_json::Value) {
    let Some(payload) = response.pointer_mut("/result/payload") else {
        return;
    };
    match payload {
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                *item = serde_json::Value::from(0_u64);
            }
        }
        serde_json::Value::String(text) => text.zeroize(),
        _ => {}
    }
}

fn read_credential_body(
    response: &serde_json::Value,
) -> Result<ResolvedCredential, CredentialError> {
    let result = response
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or(CredentialError::Permanent(
            PermanentCredentialError::Corrupt,
        ))?;
    if let Some(error) = result.get("error") {
        return Err(map_ckcred_error(error));
    }

    let payload = result
        .get("payload")
        .and_then(serde_json::Value::as_array)
        .ok_or(CredentialError::Permanent(
            PermanentCredentialError::Corrupt,
        ))?;
    // Zeroizing from the first byte: a malformed element or a missing
    // record_version below returns early, and the bytes read so far must be
    // wiped on that path as well.
    let mut bytes = Zeroizing::new(Vec::with_capacity(payload.len()));
    for value in payload {
        let byte = value
            .as_u64()
            .filter(|value| *value <= u8::MAX as u64)
            .map(|value| value as u8)
            .ok_or(CredentialError::Permanent(
                PermanentCredentialError::Corrupt,
            ))?;
        bytes.push(byte);
    }
    let record_version = result
        .get("record_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(CredentialError::Permanent(
            PermanentCredentialError::Corrupt,
        ))?;
    let expires_at_ms = result
        .get("expires_at_ms")
        .and_then(serde_json::Value::as_i64);
    // Moving the buffer out leaves an empty one behind, so the token has one
    // owner, the zeroizing credential.
    Ok(ResolvedCredential::new(
        std::mem::take(&mut *bytes),
        expires_at_ms,
        record_version,
    ))
}

fn map_ckcred_error(error: &serde_json::Value) -> CredentialError {
    let code = error
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let class = error
        .get("class")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("transient");
    match class {
        "permanent" => CredentialError::Permanent(match code {
            "refresh_unsupported" => PermanentCredentialError::RefreshUnsupported,
            "corrupt" => PermanentCredentialError::Corrupt,
            _ => PermanentCredentialError::NotFound,
        }),
        "auth_required" => CredentialError::AuthRequired,
        // MIS-SHAPED ARM, KNOWN AND DELIBERATELY DEFERRED: the vault's
        // context_overflow class carries fixed-cap refusals (get_many item cap,
        // signing payload cap, unsatisfiable min_ttl_ms demand). Their contract
        // is reduce-the-request-then-retry; an identical retry fails identically
        // forever, and for the TTL code each retry buys another upstream token
        // mint. Filing them Transient gives them wait-and-retry semantics
        // (bounded poller backoff, retry advice on dispatch), which is the wrong
        // remedy. This stands only because the class is unreachable from this
        // module BY OPERATION SET: every code under it requires get_many, sign,
        // or a min_ttl_ms demand, and plexus invokes none of those. If you are
        // adding the first such call, re-file this arm as a request-bounds
        // family whose holders surface demand-vs-ceiling and correct the
        // request, without marking the credential, handle, or connection.
        "context_overflow" => CredentialError::Transient(TransientCredentialError::ContextOverflow),
        "transient" => CredentialError::Transient(match code {
            "vault_locked" => TransientCredentialError::VaultLocked,
            _ => TransientCredentialError::RefreshFailed,
        }),
        _ => CredentialError::Transient(TransientCredentialError::RefreshFailed),
    }
}

/// Production route peer backed by the shared subc Rust client. A dedicated
/// runtime keeps the connection's background I/O alive. The synchronous
/// credential seam waits for tasks there without retaining credential bytes.
pub struct SubcCkcredRoutePeer {
    consumer: std::sync::Arc<subc_client_rs::SubcConsumer>,
    target: subc_protocol::RouteTarget,
    identity: subc_protocol::BindIdentity,
    /// Dedicated long-lived runtime that OWNS the consumer's background I/O
    /// tasks. The consumer must execute on the same runtime it was created on:
    /// a per-call throwaway runtime would destroy those tasks the moment the
    /// creating call returned, leaving a dead connection that fails every
    /// subsequent call as NotSent after the route retry deadline.
    ///
    /// Calls run as tasks on this runtime's worker (see `run_on`) while the
    /// caller waits on a bounded channel. The synchronous seam can therefore
    /// run inside an async handler without nesting Tokio runtimes.
    ///
    /// Held in an Option so `Drop` can take it: dropping a Runtime while inside
    /// an async context panics ("cannot drop a runtime in a context where
    /// blocking is not allowed") and would kill the module mid-request, since
    /// this peer is owned by the module's credential source and released on an
    /// async worker.
    runtime: Option<std::sync::Arc<tokio::runtime::Runtime>>,
}

impl Drop for SubcCkcredRoutePeer {
    fn drop(&mut self) {
        // Blocking shutdown is illegal on an async worker, so hand the runtime
        // its own background shutdown instead of letting the drop glue block.
        if let Some(runtime) = self.runtime.take() {
            if let Some(owned) = std::sync::Arc::into_inner(runtime) {
                owned.shutdown_background();
            }
        }
    }
}

impl SubcCkcredRoutePeer {
    pub fn connect(
        connection_file: &std::path::Path,
        module_id: impl Into<String>,
        identity: subc_protocol::BindIdentity,
    ) -> Result<Self, CkcredRouteError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map(std::sync::Arc::new)
            .map_err(|_| CkcredRouteError::Transport)?;
        let connection_file = connection_file.to_path_buf();
        let connected = run_on(&runtime, async move {
            subc_client_rs::SubcConsumer::connect(
                &connection_file,
                subc_client_rs::ConsumerOptions::default(),
            )
            .await
            .map_err(|_| CkcredRouteError::NotSent)
        });
        let consumer = match connected {
            Ok(consumer) => consumer,
            Err(error) => {
                // Same hazard as Drop: this early return would otherwise drop a
                // live Runtime on whatever context called connect.
                if let Some(owned) = std::sync::Arc::into_inner(runtime) {
                    owned.shutdown_background();
                }
                return Err(error);
            }
        };
        Ok(Self {
            runtime: Some(runtime),
            consumer: std::sync::Arc::new(consumer),
            // The vault registers ManagementSurface only: a ToolProvider target
            // is refused by the daemon at route.open (verified live: the
            // role-match check rejects before any body is sent).
            target: subc_protocol::RouteTarget::ManagementSurface {
                module_id: module_id.into(),
            },
            identity,
        })
    }
}

impl CkcredRoutePeer for SubcCkcredRoutePeer {
    fn call(
        &self,
        operation: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, CkcredRouteError> {
        // ReadRequest on the module side keys the operation as `method`
        // (credentials-module main.rs read dispatch), not `op`.
        let params = WipingValue(params);
        #[derive(serde::Serialize)]
        struct Request<'a> {
            method: &'a str,
            params: &'a serde_json::Value,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Request {
                method: operation,
                params: &params.0,
            })
            .map_err(|_| CkcredRouteError::Transport)?,
        );
        let consumer = std::sync::Arc::clone(&self.consumer);
        let target = self.target.clone();
        let identity = self.identity.clone();
        // Execute on the connection-owning runtime (see the `runtime` field).
        let Some(runtime) = self.runtime.as_ref() else {
            return Err(CkcredRouteError::Transport);
        };
        let bytes = Zeroizing::new(run_on(runtime, async move {
            consumer
                .call(
                    target,
                    identity,
                    // The route client takes ownership of an ordinary Vec; its
                    // internal wire buffers cannot be wiped through this API.
                    body.to_vec(),
                    subc_client_rs::CallOptions::default(),
                )
                .await
                .map_err(|error| match error {
                    subc_client_rs::CallError::NotSent(_) => CkcredRouteError::NotSent,
                    _ => CkcredRouteError::OutcomeUnknown,
                })
        })?);
        // The reply body can carry a token; `bytes` is zeroized when dropped.
        serde_json::from_slice(&bytes).map_err(|_| CkcredRouteError::Transport)
    }
}

/// Zeroize every string in a JSON value, in place, at any depth.
fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(zeroize_json_strings),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(zeroize_json_strings),
        _ => {}
    }
}

/// Run `future` on the peer's long-lived runtime and block the caller until
/// it completes. Waiting on the result channel avoids nesting Tokio runtimes.
fn run_on<F, T>(
    runtime: &std::sync::Arc<tokio::runtime::Runtime>,
    future: F,
) -> Result<T, CkcredRouteError>
where
    F: std::future::Future<Output = Result<T, CkcredRouteError>> + Send + 'static,
    T: Send + 'static,
{
    crate::transport::wait_on_runtime(runtime, future)
        .map_err(|_| CkcredRouteError::OutcomeUnknown)?
}

#[cfg(test)]
mod ckcred_wire_tests {
    use super::*;
    use crate::test_scratch::Scratch;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct MockRoutePeer {
        responses: Mutex<VecDeque<Result<serde_json::Value, CkcredRouteError>>>,
        calls: Mutex<Vec<(String, serde_json::Value)>>,
    }

    impl MockRoutePeer {
        fn push(&self, response: serde_json::Value) {
            self.responses
                .lock()
                .expect("response queue lock")
                .push_back(Ok(response));
        }

        fn push_error(&self, error: CkcredRouteError) {
            self.responses
                .lock()
                .expect("response queue lock")
                .push_back(Err(error));
        }
    }

    impl CkcredRoutePeer for MockRoutePeer {
        fn call(
            &self,
            operation: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, CkcredRouteError> {
            self.calls
                .lock()
                .expect("call log lock")
                .push((operation.to_string(), params));
            self.responses
                .lock()
                .expect("response queue lock")
                .pop_front()
                .unwrap_or(Err(CkcredRouteError::Transport))
        }
    }

    fn source() -> (CkcredCredentialSource<MockRoutePeer>, Arc<MockRoutePeer>) {
        let peer = Arc::new(MockRoutePeer::default());
        (CkcredCredentialSource::new(Arc::clone(&peer)), peer)
    }

    #[test]
    fn credential_payload_is_an_integer_array_and_base64_drift_is_rejected() {
        let (source, peer) = source();
        peer.push(serde_json::json!({
            "result": {"credential_id":"credential", "payload": [67, 65, 78, 65, 82, 89], "record_version": 7}
        }));
        let resolved = source
            .get_by_id("credential")
            .expect("integer array payload");
        assert_eq!(resolved.payload(), b"CANARY");
        assert_eq!(resolved.record_version, 7);

        peer.push(serde_json::json!({
            "result": {"credential_id":"credential", "payload": "Q0FOQVJZ", "record_version": 8}
        }));
        assert_eq!(
            source.get_by_id("credential"),
            Err(CredentialError::Permanent(
                PermanentCredentialError::Corrupt
            ))
        );
    }

    #[test]
    fn stale_auth_failure_report_error_leaves_connection_active() {
        use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

        // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            "{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = Scratch::database("ckcred-report");
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("ckcred-report-test-{unique}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let store = crate::PlexusStore::open(&descriptor).expect("report test store");
        store
            .insert_connection(
                "direct",
                "connection",
                "mock",
                "pending",
                &serde_json::json!({"required": [], "write_enabling": []}),
            )
            .expect("connection");
        let handle = b"test:stale-report-handle";
        let ticket = store
            .create_binding_ticket("direct", "connection", handle)
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume binding ticket")
            .expect("active connection");

        let (source, peer) = source();
        peer.push(serde_json::json!({
            "result": {"credential_id":"test:stale-report-handle", "payload": [67, 65, 78, 65, 82, 89], "record_version": 9}
        }));
        peer.push_error(CkcredRouteError::Transport);
        let credential = source
            .get_by_id(std::str::from_utf8(handle).unwrap())
            .expect("credential get");
        assert_eq!(credential.record_version, 9);
        source.report_id_auth_failure(std::str::from_utf8(handle).unwrap(), 401);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if peer.calls.lock().expect("call log lock").len() >= 2 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "report should be dispatched"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read connection")
                .expect("connection row")
                .status,
            "active"
        );
        let _ = std::fs::remove_file(path);
    }

    /// Reading a credential out of a vault reply overwrites the token the reply
    /// carried, both when it parses and when it is refused as corrupt partway
    /// through.
    #[test]
    fn reading_a_credential_wipes_the_token_from_the_reply() {
        let mut served = serde_json::json!({
            "result": {"credential_id":"credential", "payload": [67, 65, 78, 65, 82, 89], "record_version": 7}
        });
        let credential = take_credential(&mut served).expect("credential");
        assert_eq!(credential.payload(), b"CANARY");
        assert_eq!(
            served["result"]["payload"],
            serde_json::json!([0, 0, 0, 0, 0, 0]),
            "the reply still carries the token"
        );

        let mut corrupt = serde_json::json!({
            "result": {"payload": [67, 65, 300, 65], "record_version": 7}
        });
        assert_eq!(
            take_credential(&mut corrupt),
            Err(CredentialError::Permanent(
                PermanentCredentialError::Corrupt
            ))
        );
        assert_eq!(
            corrupt["result"]["payload"],
            serde_json::json!([0, 0, 0, 0]),
            "the reply still carries the token"
        );

        let mut drifted = serde_json::json!({
            "result": {"payload": "Q0FOQVJZ", "record_version": 7}
        });
        assert!(take_credential(&mut drifted).is_err());
        assert_eq!(drifted["result"]["payload"], "");
    }

    #[test]
    fn zeroizing_json_strings_reaches_every_depth() {
        let mut params = serde_json::json!({
            "handle": "ckh_secret",
            "nested": {"list": ["ckh_other", 7]},
            "provider_status": 401,
        });
        zeroize_json_strings(&mut params);
        assert_eq!(
            params,
            serde_json::json!({"handle": "", "nested": {"list": ["", 7]}, "provider_status": 401})
        );
    }

    /// A peer whose report calls record the thread they ran on and, while
    /// `held` is set, wait until it is cleared.
    #[derive(Default)]
    struct ReportPeer {
        threads: Mutex<Vec<std::thread::ThreadId>>,
        held: Mutex<bool>,
        released: std::sync::Condvar,
    }

    #[test]
    fn scoped_auth_failure_report_does_not_block_on_the_vault() {
        let peer = Arc::new(ReportPeer::default());
        *peer.held.lock().unwrap() = true;
        let source = CkcredCredentialSource::new(Arc::clone(&peer));
        let (done, finished) = std::sync::mpsc::channel();
        let reporter = std::thread::spawn(move || {
            source.report_scoped_auth_failure("ckcred:fixture", 401);
            done.send(()).unwrap();
        });
        let returned = finished.recv_timeout(std::time::Duration::from_millis(250));
        *peer.held.lock().unwrap() = false;
        peer.released.notify_all();
        reporter.join().unwrap();
        assert!(
            returned.is_ok(),
            "scoped reporting must not block the caller"
        );
        wait_for_reports(&peer, 1);
    }

    impl CkcredRoutePeer for ReportPeer {
        fn call(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<serde_json::Value, CkcredRouteError> {
            let mut held = self.held.lock().expect("held lock");
            while *held {
                held = self.released.wait(held).expect("held lock");
            }
            drop(held);
            self.threads
                .lock()
                .expect("thread log lock")
                .push(std::thread::current().id());
            Ok(serde_json::json!({"result": {}}))
        }
    }

    fn wait_for_reports(peer: &ReportPeer, count: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while peer.threads.lock().expect("thread log lock").len() < count {
            assert!(
                std::time::Instant::now() < deadline,
                "reports were not dispatched"
            );
            std::thread::yield_now();
        }
    }

    /// Auth-failure reports are sent off the caller's thread, and all of them,
    /// however many are made, go through a single reporting thread.
    #[test]
    fn auth_failure_reports_share_one_reporting_thread() {
        let peer = Arc::new(ReportPeer::default());
        let source = CkcredCredentialSource::new(Arc::clone(&peer));
        for _ in 0..20 {
            source.report_id_auth_failure("credential", 401);
        }
        wait_for_reports(&peer, 20);
        let threads = peer.threads.lock().expect("thread log lock");
        let distinct: std::collections::HashSet<_> = threads.iter().collect();
        assert_eq!(distinct.len(), 1, "one reporting thread");
        assert!(!distinct.contains(&std::thread::current().id()));
    }

    /// While the vault is slow, reports beyond the queue bound are dropped
    /// instead of blocking the caller or piling up.
    #[test]
    fn a_full_report_queue_drops_reports_instead_of_blocking() {
        let peer = Arc::new(ReportPeer::default());
        *peer.held.lock().expect("held lock") = true;
        let source = CkcredCredentialSource::new(Arc::clone(&peer));
        let (done, finished) = std::sync::mpsc::channel();
        let reporter = source.clone();
        std::thread::spawn(move || {
            for _ in 0..AUTH_FAILURE_REPORT_QUEUE * 2 {
                reporter.report_id_auth_failure("credential", 401);
            }
            let _ = done.send(());
        });
        let returned = finished.recv_timeout(std::time::Duration::from_secs(5));
        *peer.held.lock().expect("held lock") = false;
        peer.released.notify_all();
        assert!(returned.is_ok(), "reporting blocked the caller");
        // While the peer was held, one report could be in flight and at most
        // AUTH_FAILURE_REPORT_QUEUE more could wait in the queue; every other
        // report was dropped.
        wait_for_reports(&peer, 1);
        drop(source);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while Arc::strong_count(&peer) > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "reporting thread did not end"
            );
            std::thread::yield_now();
        }
        let sent = peer.threads.lock().expect("thread log lock").len();
        assert!(sent <= AUTH_FAILURE_REPORT_QUEUE + 1, "{sent} reports sent");
    }

    #[test]
    fn unknown_error_class_fails_closed_as_recoverable_transient() {
        let (source, peer) = source();
        peer.push(serde_json::json!({
            "result": {"error": {"code": "new_code", "class": "future_class"}}
        }));
        assert_eq!(
            source.get_by_id("credential"),
            Err(CredentialError::Transient(
                TransientCredentialError::RefreshFailed
            ))
        );
    }
}

#[cfg(test)]
mod report_diagnostic_tests {
    use super::*;
    #[allow(dead_code)]
    mod logging {
        include!("../tests/support/logging.rs");
    }

    #[test]
    fn vault_report_failures_are_logged_without_credential_material() {
        const TEST: &str = "credentials::report_diagnostic_tests::vault_report_failures_are_logged_without_credential_material";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            logging::init_child();
            struct Peer {
                calls: std::sync::atomic::AtomicUsize,
                reached_second: std::sync::mpsc::Sender<()>,
            }
            impl CkcredRoutePeer for Peer {
                fn call(
                    &self,
                    operation: &str,
                    params: serde_json::Value,
                ) -> Result<serde_json::Value, CkcredRouteError> {
                    assert_eq!(operation, "credential.report_auth_failure");
                    assert_eq!(
                        params["provider_status"], 401,
                        "403 must never report a credential bad"
                    );
                    if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                        self.reached_second.send(()).unwrap();
                    }
                    Err(CkcredRouteError::Transport)
                }
            }
            let (tx, rx) = std::sync::mpsc::channel();
            let source = CkcredCredentialSource::new(std::sync::Arc::new(Peer {
                calls: std::sync::atomic::AtomicUsize::new(0),
                reached_second: tx,
            }));
            source.report_id_auth_failure("PRIVATE-CREDENTIAL-NAME", 403);
            source.report_id_auth_failure("PRIVATE-CREDENTIAL-NAME", 401);
            source.report_id_auth_failure("PRIVATE-CREDENTIAL-NAME", 401);
            rx.recv_timeout(std::time::Duration::from_secs(3))
                .expect("second report proves the first reporting-loop iteration finished");
            return;
        }
        let output = crate::test_http::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            std::time::Duration::from_secs(10),
            "vault report diagnostic",
        )
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(
            stderr.contains("credential auth-failure report failed: Transport"),
            "vault report failure must be observable: {stderr}"
        );
        assert!(
            !stderr.contains("PRIVATE-CREDENTIAL-NAME"),
            "credential material must stay out of diagnostics: {stderr}"
        );
    }
}
