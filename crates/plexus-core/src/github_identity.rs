//! Shared client for calls to prefrontal over subc, plus test-support for the
//! retired identity flow. Production bot identity is selected from Plexus's
//! stored agent-to-GitHub-App bindings, not from remote identity replies.

#[cfg(any(test, feature = "test-support"))]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Mutex;

use serde_json::Value;

#[cfg(any(test, feature = "test-support"))]
use crate::{AuditRecord, PlexusStore};

/// The read-only prefrontal management operation used to resolve an agent's
/// configured GitHub identity.
#[cfg(any(test, feature = "test-support"))]
pub const AGENT_GITHUB_IDENTITY_OPERATION: &str = "agent.github_identity";

/// The kind-specific, non-secret portion of an agent's GitHub identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
pub enum GithubIdentity {
    App {
        app_id: String,
        app_slug: String,
        installation_id: String,
    },
    UserToken {
        login: String,
    },
}

#[cfg(any(test, feature = "test-support"))]
impl GithubIdentity {
    fn response_class(&self) -> &'static str {
        match self {
            Self::App { .. } => "github_app",
            Self::UserToken { .. } => "github_user_token",
        }
    }
}

/// An identity accepted for the asserted agent and the subscription's project.
///
/// `credential_ref` is carried forward untouched for the later credential-swap
/// slice. This resolution seam deliberately does not resolve or dispatch with
/// that credential.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
pub struct ResolvedGithubIdentity {
    pub agent_id: String,
    pub identity: GithubIdentity,
    pub credential_ref: String,
}

/// Why an asserted agent identity could not be accepted for a subscription.
/// Every variant has a stable, operator-facing lower-snake-case reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
pub enum GithubIdentityRefusal {
    IdentityAbsent,
    ProjectUnbound,
    ProjectMismatch {
        expected_project_id: String,
        actual_project_id: String,
    },
    AgentIdMismatch {
        expected_agent_id: String,
        actual_agent_id: String,
    },
    IdentityServiceUnavailable,
    MalformedIdentityReply,
    AuditUnavailable,
}

#[cfg(any(test, feature = "test-support"))]
impl GithubIdentityRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::IdentityAbsent => "github_identity_absent",
            Self::ProjectUnbound => "github_identity_project_unbound",
            Self::ProjectMismatch { .. } => "github_identity_project_mismatch",
            Self::AgentIdMismatch { .. } => "github_identity_agent_mismatch",
            Self::IdentityServiceUnavailable => "github_identity_unavailable",
            Self::MalformedIdentityReply => "github_identity_malformed",
            Self::AuditUnavailable => "github_identity_audit_unavailable",
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Display for GithubIdentityRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityAbsent => formatter.write_str("agent has no GitHub identity"),
            Self::ProjectUnbound => formatter.write_str("agent is not bound to a project"),
            Self::ProjectMismatch { .. } => {
                formatter.write_str("agent identity belongs to a different project")
            }
            Self::AgentIdMismatch { .. } => {
                formatter.write_str("identity reply did not match the asserted agent")
            }
            Self::IdentityServiceUnavailable => {
                formatter.write_str("prefrontal identity service is unavailable")
            }
            Self::MalformedIdentityReply => {
                formatter.write_str("prefrontal identity reply was malformed")
            }
            Self::AuditUnavailable => formatter
                .write_str("identity resolution could not be recorded in the audit journal"),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl std::error::Error for GithubIdentityRefusal {}

/// Failure to obtain a reply from the identity authority. This is deliberately
/// distinct from a valid reply declaring that an agent has no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
pub enum GithubIdentitySourceError {
    Unavailable,
}

/// Read-only source of the raw `agent.github_identity` reply.
///
/// The resolver parses the raw value itself so malformed replies fail closed
/// alongside source failures instead of becoming a fallback identity.
#[cfg(any(test, feature = "test-support"))]
pub trait GithubIdentitySource: Send + Sync {
    fn github_identity(&self, agent_id: &str) -> Result<Value, GithubIdentitySourceError>;
}

/// Test-only configurable response for [`StubGithubIdentitySource`].
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "test-support"))]
pub enum StubGithubIdentityResponse {
    Reply(Value),
    Error(GithubIdentitySourceError),
}

/// In-memory identity authority used by resolver tests. It is explicit rather
/// than a production fallback: an absent production route must refuse.
#[cfg(any(test, feature = "test-support"))]
pub struct StubGithubIdentitySource {
    default_response: Mutex<StubGithubIdentityResponse>,
    responses: Mutex<HashMap<String, StubGithubIdentityResponse>>,
    requests: Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for StubGithubIdentitySource {
    fn default() -> Self {
        Self {
            default_response: Mutex::new(StubGithubIdentityResponse::Error(
                GithubIdentitySourceError::Unavailable,
            )),
            responses: Mutex::new(HashMap::new()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl StubGithubIdentitySource {
    pub fn with_default_response(response: StubGithubIdentityResponse) -> Self {
        Self {
            default_response: Mutex::new(response),
            ..Self::default()
        }
    }

    pub fn set_default_response(&self, response: StubGithubIdentityResponse) {
        *self
            .default_response
            .lock()
            .expect("identity source default response lock") = response;
    }

    pub fn set_response(&self, agent_id: impl Into<String>, response: StubGithubIdentityResponse) {
        self.responses
            .lock()
            .expect("identity source responses lock")
            .insert(agent_id.into(), response);
    }

    /// Agent ids requested from this stub, in call order.
    pub fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("identity source requests lock")
            .clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl GithubIdentitySource for StubGithubIdentitySource {
    fn github_identity(&self, agent_id: &str) -> Result<Value, GithubIdentitySourceError> {
        self.requests
            .lock()
            .expect("identity source requests lock")
            .push(agent_id.to_string());
        let response = self
            .responses
            .lock()
            .expect("identity source responses lock")
            .get(agent_id)
            .cloned()
            .unwrap_or_else(|| {
                self.default_response
                    .lock()
                    .expect("identity source default response lock")
                    .clone()
            });
        match response {
            StubGithubIdentityResponse::Reply(reply) => Ok(reply),
            StubGithubIdentityResponse::Error(error) => Err(error),
        }
    }
}

/// Fail-closed source for tests of the retired identity flow.
#[cfg(any(test, feature = "test-support"))]
pub struct FailClosedGithubIdentitySource;

#[cfg(any(test, feature = "test-support"))]
impl GithubIdentitySource for FailClosedGithubIdentitySource {
    fn github_identity(&self, _agent_id: &str) -> Result<Value, GithubIdentitySourceError> {
        Err(GithubIdentitySourceError::Unavailable)
    }
}

/// Errors raised while carrying a prefrontal request over the subc route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefrontalRouteError {
    NotSent,
    Refused,
    OutcomeUnknown,
    Transport,
}

/// Narrow route seam used by the prefrontal adapter. Production code supplies
/// the subc peer; tests can exercise the operation shape without a daemon.
pub trait PrefrontalRoutePeer: Send + Sync {
    fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError>;
}

/// [`GithubIdentitySource`] adapter for prefrontal's management surface.
#[cfg(any(test, feature = "test-support"))]
pub struct PrefrontalGithubIdentitySource<P> {
    peer: Arc<P>,
}

#[cfg(any(test, feature = "test-support"))]
impl<P> Clone for PrefrontalGithubIdentitySource<P> {
    fn clone(&self) -> Self {
        Self {
            peer: Arc::clone(&self.peer),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<P> PrefrontalGithubIdentitySource<P> {
    pub fn new(peer: Arc<P>) -> Self {
        Self { peer }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<P: PrefrontalRoutePeer + 'static> GithubIdentitySource for PrefrontalGithubIdentitySource<P> {
    fn github_identity(&self, agent_id: &str) -> Result<Value, GithubIdentitySourceError> {
        self.peer
            .call(
                AGENT_GITHUB_IDENTITY_OPERATION,
                serde_json::json!({ "agentId": agent_id }),
            )
            .map_err(|_| GithubIdentitySourceError::Unavailable)
    }
}

/// Production route peer backed by the shared subc Rust client. Its long-lived
/// runtime owns the consumer's background I/O; calls hop through a helper
/// thread so this synchronous seam is safe from async module handlers.
pub struct SubcPrefrontalRoutePeer {
    consumer: Arc<subc_client_rs::SubcConsumer>,
    target: subc_protocol::RouteTarget,
    identity: subc_protocol::BindIdentity,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    /// The deadline for one whole call; the subc client's default when unset.
    call_timeout: Option<std::time::Duration>,
    call_options: Option<subc_client_rs::CallOptions>,
}

/// How one call over [`SubcPrefrontalRoutePeer`] failed.
enum RouteCallFailure {
    NotSent,
    OutcomeUnknown,
    Transport,
    /// Prefrontal answered with an error frame carrying a code.
    Module {
        code: String,
        message: String,
        detail: Option<Value>,
    },
}

impl Drop for SubcPrefrontalRoutePeer {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            if let Some(owned) = Arc::into_inner(runtime) {
                // Runtime shutdown can block, which is illegal if this source is
                // released by an async handler.
                owned.shutdown_background();
            }
        }
    }
}

impl SubcPrefrontalRoutePeer {
    /// Connect to prefrontal's management surface. `module_id` is supplied by
    /// Plexus configuration so a prefrontal rename does not require this crate
    /// to hardcode or release a replacement identifier.
    pub fn connect(
        connection_file: &std::path::Path,
        module_id: impl Into<String>,
        identity: subc_protocol::BindIdentity,
    ) -> Result<Self, PrefrontalRouteError> {
        Self::connect_target(
            connection_file,
            subc_protocol::RouteTarget::ManagementSurface {
                module_id: module_id.into(),
            },
            identity,
        )
    }

    /// Connect to an explicit route target, including an internal service.
    pub fn connect_target(
        connection_file: &std::path::Path,
        target: subc_protocol::RouteTarget,
        identity: subc_protocol::BindIdentity,
    ) -> Result<Self, PrefrontalRouteError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map(Arc::new)
            .map_err(|_| PrefrontalRouteError::Transport)?;
        let connection_file = connection_file.to_path_buf();
        let connected = run_on(&runtime, async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                subc_client_rs::SubcConsumer::connect(
                    &connection_file,
                    subc_client_rs::ConsumerOptions::default(),
                ),
            )
            .await
            .map_err(|_| PrefrontalRouteError::NotSent)?
            .map_err(|_| PrefrontalRouteError::NotSent)
        });
        let consumer = match connected {
            Ok(consumer) => consumer,
            Err(error) => {
                if let Some(owned) = Arc::into_inner(runtime) {
                    owned.shutdown_background();
                }
                return Err(error);
            }
        };
        Ok(Self {
            runtime: Some(runtime),
            consumer: Arc::new(consumer),
            target,
            identity,
            call_timeout: None,
            call_options: None,
        })
    }

    /// Bound every call on this peer by `timeout` instead of the subc
    /// client's default.
    pub fn with_call_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.call_timeout = Some(timeout);
        self
    }

    /// Override the subc client's call options, including explicit module
    /// credentials. The daemon still checks which module is calling against
    /// the launch code it handed that module at start, so these options can't
    /// claim another module's identity.
    pub fn with_call_options(mut self, options: subc_client_rs::CallOptions) -> Self {
        self.call_options = Some(options);
        self
    }

    /// Preserve service refusal codes and details rather than flattening them to transport errors.
    pub fn call_service(
        &self,
        operation: &str,
        params: Value,
    ) -> Result<Value, subc_protocol::ErrorBody> {
        self.call_value(operation, params)
            .map_err(|failure| match failure {
                RouteCallFailure::Module {
                    code,
                    message,
                    detail,
                } => subc_protocol::ErrorBody {
                    code,
                    message,
                    detail,
                },
                _ => subc_protocol::ErrorBody {
                    code: "unavailable".into(),
                    message: "route unavailable or timed out".into(),
                    detail: None,
                },
            })
    }

    fn call_value(&self, operation: &str, params: Value) -> Result<Value, RouteCallFailure> {
        self.call_value_scoped(operation, params, None, self.call_timeout)
    }

    fn call_value_scoped(
        &self,
        operation: &str,
        params: Value,
        scope: Option<subc_protocol::scope::ScopeSelector>,
        timeout: Option<std::time::Duration>,
    ) -> Result<Value, RouteCallFailure> {
        // Prefrontal's management surface follows the same route envelope as
        // claustrum: management operation under `method`, arguments under
        // `params`.
        let body = serde_json::to_vec(&serde_json::json!({
            "method": operation,
            "params": params,
        }))
        .map_err(|_| RouteCallFailure::Transport)?;
        let consumer = Arc::clone(&self.consumer);
        let target = self.target.clone();
        let identity = self.identity.clone();
        let mut options = self.call_options.clone().unwrap_or_default();
        if let Some(timeout) = timeout {
            options.timeout = timeout;
        }
        let Some(runtime) = self.runtime.as_ref() else {
            return Err(RouteCallFailure::Transport);
        };

        // A route call waits on a helper thread and can release transport-owned
        // runtime state. Move that blocking wait off a Tokio worker whenever the
        // source is invoked by a module handler.
        blocking_route_call(|| {
            let bytes = run_on(runtime, async move {
                let answer = match scope {
                    Some(scope) => {
                        let deadline = tokio::time::Instant::now() + options.timeout;
                        let route = consumer
                            .open_route_scoped(target, identity, scope, options.clone())
                            .await;
                        match route {
                            Ok(route) => {
                                options.timeout =
                                    deadline.saturating_duration_since(tokio::time::Instant::now());
                                consumer.request(&route, body, options).await
                            }
                            Err(error) => Err(error),
                        }
                    }
                    None => consumer.call(target, identity, body, options).await,
                };
                Ok(answer.map_err(|error| {
                    if let Some(body) = error.route_open_refusal() {
                        return RouteCallFailure::Module {
                            code: body.code.clone(),
                            message: body.message.clone(),
                            detail: body.detail.clone(),
                        };
                    }
                    match error {
                        subc_client_rs::CallError::NotSent(_) => RouteCallFailure::NotSent,
                        subc_client_rs::CallError::Module(body) => RouteCallFailure::Module {
                            code: body.code,
                            message: body.message,
                            detail: body.detail,
                        },
                        _ => RouteCallFailure::OutcomeUnknown,
                    }
                }))
            })
            .map_err(|_| RouteCallFailure::OutcomeUnknown)??;
            serde_json::from_slice(&bytes).map_err(|_| RouteCallFailure::Transport)
        })
    }
}

fn route_error(failure: RouteCallFailure) -> PrefrontalRouteError {
    match failure {
        RouteCallFailure::NotSent => PrefrontalRouteError::NotSent,
        RouteCallFailure::Transport => PrefrontalRouteError::Transport,
        RouteCallFailure::OutcomeUnknown => PrefrontalRouteError::OutcomeUnknown,
        RouteCallFailure::Module { .. } => PrefrontalRouteError::Refused,
    }
}

impl PrefrontalRoutePeer for SubcPrefrontalRoutePeer {
    fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError> {
        self.call_value(operation, params).map_err(route_error)
    }
}

/// Elicitation operations over the same route. Prefrontal core answers a
/// success as `{"result": value}` and a refusal as an error frame with an
/// `elicitation_*` code, which is kept so the caller can log and branch on it.
impl crate::consent_card::ElicitationRoute for SubcPrefrontalRoutePeer {
    fn call_scoped(
        &self,
        scope: &crate::scope::CallScope,
        operation: &str,
        params: Value,
        timeout: std::time::Duration,
    ) -> Result<Value, crate::consent_card::ElicitationCallError> {
        use crate::consent_card::ElicitationCallError;
        let owner =
            crate::scope::parse_scope_owner(&scope.owner).ok_or(ElicitationCallError::NotSent)?;
        let selector = subc_protocol::scope::ScopeSelector::new(
            owner,
            scope.scope_ref.clone(),
            Some(scope.scope_epoch),
        );
        match self.call_value_scoped(operation, params, Some(selector), Some(timeout)) {
            Ok(mut reply) => Ok(reply.get_mut("result").map(Value::take).unwrap_or(reply)),
            Err(RouteCallFailure::Module { code, message, .. }) => {
                Err(ElicitationCallError::Refused { code, message })
            }
            Err(RouteCallFailure::NotSent) => Err(ElicitationCallError::NotSent),
            Err(RouteCallFailure::OutcomeUnknown) => Err(ElicitationCallError::OutcomeUnknown),
            Err(RouteCallFailure::Transport) => Err(ElicitationCallError::Transport),
        }
    }
}

/// Run a blocking route wait from whatever context the caller is in. On a
/// multi-thread Tokio worker the wait moves off the worker with
/// `block_in_place`. That call panics on a current-thread runtime, which has
/// no other worker to hand its tasks to, so there the wait simply blocks the
/// calling thread: the route future itself runs on the peer's own runtime
/// (see `run_on`), so nothing it needs is stuck behind this thread.
fn blocking_route_call<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

/// Run a route future on its connection-owning runtime without calling
/// `Runtime::block_on` from an async worker. The consumer's background tasks
/// stay on the runtime that created them; a bounded channel carries the result
/// back to the synchronous caller without creating another OS thread.
fn run_on<F, T>(
    runtime: &Arc<tokio::runtime::Runtime>,
    future: F,
) -> Result<T, PrefrontalRouteError>
where
    F: std::future::Future<Output = Result<T, PrefrontalRouteError>> + Send + 'static,
    T: Send + 'static,
{
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _ = send.send(future.await);
    });
    receive
        .recv()
        .map_err(|_| PrefrontalRouteError::OutcomeUnknown)?
}

/// Interpret prefrontal's reply without performing I/O or writing audit state.
/// This pure cross-check is intentionally reusable by tests and by the audited
/// resolver below.
#[cfg(any(test, feature = "test-support"))]
pub fn resolve_github_identity_reply(
    asserted_agent_id: &str,
    subscription_project_id: &str,
    reply: &Value,
) -> Result<ResolvedGithubIdentity, GithubIdentityRefusal> {
    let reply = reply.get("result").unwrap_or(reply);
    let reply_agent_id = required_string(reply, "agentId")?;
    if reply_agent_id != asserted_agent_id {
        return Err(GithubIdentityRefusal::AgentIdMismatch {
            expected_agent_id: asserted_agent_id.to_string(),
            actual_agent_id: reply_agent_id,
        });
    }

    let identity = match reply.get("identity") {
        None | Some(Value::Null) => return Err(GithubIdentityRefusal::IdentityAbsent),
        Some(identity) => identity,
    };

    let project_id = match reply.get("projectId") {
        None => return Err(GithubIdentityRefusal::ProjectUnbound),
        Some(Value::String(value)) if !value.trim().is_empty() => value,
        Some(_) => return Err(GithubIdentityRefusal::MalformedIdentityReply),
    };
    if project_id != subscription_project_id {
        return Err(GithubIdentityRefusal::ProjectMismatch {
            expected_project_id: subscription_project_id.to_string(),
            actual_project_id: project_id.to_string(),
        });
    }

    let (identity, credential_ref) = parse_identity(identity)?;
    Ok(ResolvedGithubIdentity {
        agent_id: reply_agent_id,
        identity,
        credential_ref,
    })
}

#[cfg(any(test, feature = "test-support"))]
fn required_string(value: &Value, key: &str) -> Result<String, GithubIdentityRefusal> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or(GithubIdentityRefusal::MalformedIdentityReply)
}

#[cfg(any(test, feature = "test-support"))]
fn required_identifier(value: &Value, key: &str) -> Result<String, GithubIdentityRefusal> {
    match value.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.to_string()),
        Some(Value::Number(value)) if value.as_u64().is_some() => Ok(value.to_string()),
        _ => Err(GithubIdentityRefusal::MalformedIdentityReply),
    }
}

#[cfg(any(test, feature = "test-support"))]
fn parse_identity(identity: &Value) -> Result<(GithubIdentity, String), GithubIdentityRefusal> {
    let credential_ref = required_string(identity, "credentialRef")?;
    match required_string(identity, "kind")?.as_str() {
        "app" => Ok((
            GithubIdentity::App {
                app_id: required_identifier(identity, "appId")?,
                app_slug: required_string(identity, "appSlug")?,
                installation_id: required_identifier(identity, "installationId")?,
            },
            credential_ref,
        )),
        "user_token" => Ok((
            GithubIdentity::UserToken {
                login: required_string(identity, "login")?,
            },
            credential_ref,
        )),
        _ => Err(GithubIdentityRefusal::MalformedIdentityReply),
    }
}

/// Audited resolver for a subscription's asserted agent identity.
#[cfg(any(test, feature = "test-support"))]
pub struct GithubIdentityResolver<S: GithubIdentitySource + ?Sized> {
    store: Arc<PlexusStore>,
    source: Arc<S>,
}

#[cfg(any(test, feature = "test-support"))]
impl<S: GithubIdentitySource + ?Sized> Clone for GithubIdentityResolver<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            source: Arc::clone(&self.source),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<S: GithubIdentitySource + ?Sized> GithubIdentityResolver<S> {
    pub fn new(store: Arc<PlexusStore>, source: Arc<S>) -> Self {
        Self { store, source }
    }

    pub fn source(&self) -> &Arc<S> {
        &self.source
    }

    /// Resolve and journal an identity assertion for a project-bound
    /// subscription. Audit failure is itself fail-closed because this operation
    /// must never make an unreconstructable attribution claim.
    pub fn resolve(
        &self,
        asserted_agent_id: &str,
        subscription_project_id: &str,
    ) -> Result<ResolvedGithubIdentity, GithubIdentityRefusal> {
        let outcome = match self.source.github_identity(asserted_agent_id) {
            Ok(reply) => {
                resolve_github_identity_reply(asserted_agent_id, subscription_project_id, &reply)
            }
            Err(_) => Err(GithubIdentityRefusal::IdentityServiceUnavailable),
        };

        // Prefrontal can establish which identity is configured, but Plexus
        // cannot prove the asserted agent actually acknowledged a GitHub item.
        // This append-only record makes that attribution reconstructable after
        // the fact without pretending the request-time check proves it.
        let (decision, reason_code, outcome_label, response_class) = match &outcome {
            Ok(identity) => (
                "allow",
                "github_identity_resolved",
                "resolved",
                Some(identity.identity.response_class().to_string()),
            ),
            Err(refusal) => ("deny", refusal.code(), "refused", None),
        };
        let record = AuditRecord {
            principal: subscription_project_id.to_string(),
            actor: "plexus".to_string(),
            acting_principal: asserted_agent_id.to_string(),
            agent_id: None,
            app_handle_id: None,
            agent_handle: None,
            connection_id: None,
            app_key: Some("github".to_string()),
            action: Some(AGENT_GITHUB_IDENTITY_OPERATION.to_string()),
            risk: None,
            severity: None,
            decision: decision.to_string(),
            reason_code: reason_code.to_string(),
            gate: Some("github_identity_resolution".to_string()),
            args_redaction_summary: Some(format!("asserted_agent_id:{asserted_agent_id}")),
            outcome: Some(outcome_label.to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: Some(1),
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class,
            reconciliation_of: None,
        };
        if self.store.append_audit(&record).is_err() {
            return Err(GithubIdentityRefusal::AuditUnavailable);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "manual route-call scheduling measurement"]
    fn measure_route_hop() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let start = std::time::Instant::now();
        for _ in 0..200 {
            run_on(&runtime, async { Ok(()) }).unwrap();
        }
        println!("200 real run_on hops: {:?}", start.elapsed());
        let start = std::time::Instant::now();
        for _ in 0..200 {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            runtime.spawn(async move {
                tx.send(()).unwrap();
            });
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        }
        println!("200 runtime task/channel hops: {:?}", start.elapsed());
    }

    #[test]
    fn module_route_refusal_is_not_an_unknown_outcome() {
        let error = route_error(RouteCallFailure::Module {
            code: "denied".into(),
            message: "refused".into(),
            detail: None,
        });
        assert_eq!(
            format!("{error:?}"),
            "Refused",
            "a definite module refusal must not be reported as outcome unknown"
        );
    }

    use super::*;
    use crate::test_scratch::Scratch;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    // The `Scratch` comes back with the store because it is what removes the
    // store's directory: dropping it here would unlink the database this
    // function just opened.
    fn store() -> (Arc<PlexusStore>, Scratch) {
        // A pid+wall-clock nonce alone collides: the macOS system clock ticks in
        // microseconds, so two parallel test threads can observe the same
        // timestamp, mint the same storage namespace, and fail on the store's
        // single-writer lease. The process-wide counter makes every call
        // distinct regardless of clock granularity.
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
        let path = Scratch::database("github-identity");
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("github-identity-test-{unique}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        (
            Arc::new(PlexusStore::open(&descriptor).expect("identity test store")),
            path,
        )
    }

    fn user_identity_reply(project_id: &str) -> Value {
        serde_json::json!({
            "agentId": "agent-1",
            "identity": {
                "kind": "user_token",
                "login": "octocat",
                "credentialRef": "credential-user-1"
            },
            "projectId": project_id,
        })
    }

    fn resolver(
        response: StubGithubIdentityResponse,
    ) -> (
        GithubIdentityResolver<StubGithubIdentitySource>,
        Arc<StubGithubIdentitySource>,
        Arc<PlexusStore>,
        Scratch,
    ) {
        let (store, scratch) = store();
        let source = Arc::new(StubGithubIdentitySource::with_default_response(response));
        (
            GithubIdentityResolver::new(Arc::clone(&store), Arc::clone(&source)),
            source,
            store,
            scratch,
        )
    }

    fn assert_journal(
        store: &PlexusStore,
        expected_decision: &str,
        expected_reason: &str,
        expected_outcome: &str,
    ) {
        let rows = store.list_audit("project-1").expect("read audit");
        assert_eq!(rows.len(), 1);
        let row = rows.first().expect("identity audit row");
        assert_eq!(row.acting_principal, "agent-1");
        assert_eq!(row.decision, expected_decision);
        assert_eq!(row.reason_code, expected_reason);
        assert_eq!(row.outcome.as_deref(), Some(expected_outcome));
        assert_eq!(
            row.args_redaction_summary.as_deref(),
            Some("asserted_agent_id:agent-1")
        );
    }

    #[test]
    fn resolves_a_user_token_identity_and_journals_the_assertion() {
        let (resolver, source, store, _scratch) = resolver(StubGithubIdentityResponse::Reply(
            user_identity_reply("project-1"),
        ));

        let resolved = resolver
            .resolve("agent-1", "project-1")
            .expect("matching user identity resolves");

        assert_eq!(source.requests(), vec!["agent-1"]);
        assert_eq!(
            resolved,
            ResolvedGithubIdentity {
                agent_id: "agent-1".to_string(),
                identity: GithubIdentity::UserToken {
                    login: "octocat".to_string(),
                },
                credential_ref: "credential-user-1".to_string(),
            }
        );
        assert_journal(&store, "allow", "github_identity_resolved", "resolved");
    }

    #[test]
    fn resolves_an_app_identity_with_numeric_ids() {
        let (resolver, _, store, _scratch) =
            resolver(StubGithubIdentityResponse::Reply(serde_json::json!({
                "agentId": "agent-1",
                "identity": {
                    "kind": "app",
                    "appId": 42,
                    "appSlug": "plexus-app",
                    "installationId": 99,
                    "credentialRef": "credential-app-1"
                },
                "projectId": "project-1",
            })));

        let resolved = resolver
            .resolve("agent-1", "project-1")
            .expect("matching app identity resolves");

        assert_eq!(
            resolved.identity,
            GithubIdentity::App {
                app_id: "42".to_string(),
                app_slug: "plexus-app".to_string(),
                installation_id: "99".to_string(),
            }
        );
        assert_eq!(resolved.credential_ref, "credential-app-1");
        assert_journal(&store, "allow", "github_identity_resolved", "resolved");
    }

    #[test]
    fn refuses_a_null_identity_without_substituting_a_fallback() {
        let (resolver, _, store, _scratch) =
            resolver(StubGithubIdentityResponse::Reply(serde_json::json!({
                "agentId": "agent-1",
                "identity": null,
                "projectId": "project-1",
            })));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::IdentityAbsent)
        );
        assert_journal(&store, "deny", "github_identity_absent", "refused");
    }

    #[test]
    fn refuses_an_absent_identity_without_substituting_a_fallback() {
        let (resolver, _, store, _scratch) =
            resolver(StubGithubIdentityResponse::Reply(serde_json::json!({
                "agentId": "agent-1",
                "projectId": "project-1",
            })));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::IdentityAbsent)
        );
        assert_journal(&store, "deny", "github_identity_absent", "refused");
    }

    #[test]
    fn refuses_an_unbound_agent_identity() {
        let (resolver, _, store, _scratch) =
            resolver(StubGithubIdentityResponse::Reply(serde_json::json!({
                "agentId": "agent-1",
                "identity": {
                    "kind": "user_token",
                    "login": "octocat",
                    "credentialRef": "credential-user-1"
                },
            })));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::ProjectUnbound)
        );
        assert_journal(&store, "deny", "github_identity_project_unbound", "refused");
    }

    #[test]
    fn refuses_a_resolvable_identity_from_a_different_project() {
        let (resolver, _, store, _scratch) = resolver(StubGithubIdentityResponse::Reply(
            user_identity_reply("project-2"),
        ));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::ProjectMismatch {
                expected_project_id: "project-1".to_string(),
                actual_project_id: "project-2".to_string(),
            })
        );
        assert_journal(
            &store,
            "deny",
            "github_identity_project_mismatch",
            "refused",
        );
    }

    #[test]
    fn refuses_when_prefrontal_is_unreachable_instead_of_claiming_no_identity() {
        let (resolver, _, store, _scratch) = resolver(StubGithubIdentityResponse::Error(
            GithubIdentitySourceError::Unavailable,
        ));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::IdentityServiceUnavailable)
        );
        assert_journal(&store, "deny", "github_identity_unavailable", "refused");
    }

    #[test]
    fn refuses_a_malformed_prefrontal_reply() {
        let (resolver, _, store, _scratch) =
            resolver(StubGithubIdentityResponse::Reply(serde_json::json!({
                "agentId": "agent-1",
                "identity": {
                    "kind": "user_token",
                    "credentialRef": "credential-user-1"
                },
                "projectId": "project-1",
            })));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::MalformedIdentityReply)
        );
        assert_journal(&store, "deny", "github_identity_malformed", "refused");
    }

    #[test]
    fn refuses_a_reply_for_a_different_agent() {
        let (resolver, _, store, _scratch) =
            resolver(StubGithubIdentityResponse::Reply(serde_json::json!({
                "agentId": "agent-2",
                "identity": {
                    "kind": "user_token",
                    "login": "octocat",
                    "credentialRef": "credential-user-1"
                },
                "projectId": "project-1",
            })));

        assert_eq!(
            resolver.resolve("agent-1", "project-1"),
            Err(GithubIdentityRefusal::AgentIdMismatch {
                expected_agent_id: "agent-1".to_string(),
                actual_agent_id: "agent-2".to_string(),
            })
        );
        assert_journal(&store, "deny", "github_identity_agent_mismatch", "refused");
    }

    #[derive(Default)]
    struct MockRoutePeer {
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl PrefrontalRoutePeer for MockRoutePeer {
        fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError> {
            self.calls
                .lock()
                .expect("route calls lock")
                .push((operation.to_string(), params));
            Ok(user_identity_reply("project-1"))
        }
    }

    #[test]
    fn route_source_uses_the_read_only_prefrontal_management_operation() {
        let peer = Arc::new(MockRoutePeer::default());
        let source = PrefrontalGithubIdentitySource::new(Arc::clone(&peer));

        let reply = source.github_identity("agent-1").expect("route reply");

        assert_eq!(reply, user_identity_reply("project-1"));
        assert_eq!(
            peer.calls.lock().expect("route calls lock").as_slice(),
            &[(
                AGENT_GITHUB_IDENTITY_OPERATION.to_string(),
                serde_json::json!({"agentId": "agent-1"}),
            )]
        );
    }

    /// A route wait may be reached from a plain thread, a multi-thread Tokio
    /// worker or a current-thread runtime; it completes in each and never
    /// panics.
    #[test]
    fn a_blocking_route_wait_completes_on_every_runtime_flavor() {
        assert_eq!(blocking_route_call(|| 1), 1);
        let multi = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .expect("multi-thread runtime");
        // Spawned, so the wait runs on one of the runtime's worker threads.
        let on_worker = multi.block_on(async {
            tokio::spawn(async { blocking_route_call(|| 2) })
                .await
                .expect("worker task")
        });
        assert_eq!(on_worker, 2);
        let current = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");
        assert_eq!(current.block_on(async { blocking_route_call(|| 3) }), 3);
    }
}
