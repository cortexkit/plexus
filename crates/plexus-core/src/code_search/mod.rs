//! Public code search authorized by the caller's module grant.
//! Agent identities are recorded for audit attribution, not used to grant access.

pub mod query;
pub mod reply;

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::credentials::CredentialSource;
use crate::governance::{
    connection_denial, scoped_grant, scoped_grant_refusal, AuthorizationRequest, Denial,
    GovernanceEngine, TransportOutcome, AUTHORITY_INVOKE,
};
use crate::scope::{resolve_call_agent, CallScope};
use crate::storage::{AuditRecord, CatalogAction, ConnectionRecord, PlexusStore, RelayOrigin};
use crate::transport::Transport;
use crate::web_search::limiter::{default_limits, CallerKey, RateLimiter};

pub use query::CodeSearchQuery;
pub use reply::CodeSearchResponse;

pub const BACKEND: &str = "grep_app";
pub const ACTION: &str = "searchGitHub";
const DEFAULT_VENDOR_RETRY_AFTER_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalCode {
    NotGranted,
    RateLimited,
    InvalidQuery,
    ConsentUnavailable,
    AskFirst,
    BackendUnavailable,
    BackendAmbiguous,
    BackendQuarantined,
}

impl RefusalCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotGranted => "code_search_not_granted",
            Self::RateLimited => "rate_limited",
            Self::InvalidQuery => "invalid_query",
            Self::ConsentUnavailable => "consent_unavailable",
            Self::AskFirst => "policy_ask_first",
            Self::BackendUnavailable => "backend_unavailable",
            Self::BackendAmbiguous => "backend_ambiguous",
            Self::BackendQuarantined => "backend_quarantined",
        }
    }
}

impl PartialEq<&str> for RefusalCode {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct CodeSearchRefusal {
    code: RefusalCode,
    field: Option<String>,
    retry_after_ms: Option<u64>,
}

impl CodeSearchRefusal {
    fn new(code: RefusalCode) -> Self {
        Self {
            code,
            field: None,
            retry_after_ms: None,
        }
    }
    pub fn invalid(field: &str) -> Self {
        Self {
            field: Some(field.to_string()),
            ..Self::new(RefusalCode::InvalidQuery)
        }
    }
    pub fn to_wire(&self) -> Value {
        let message = match self.code {
            RefusalCode::NotGranted => "no code search backend is granted to this caller",
            RefusalCode::RateLimited => {
                "code search rate limit reached; retry after retry_after_ms"
            }
            RefusalCode::InvalidQuery => "a code search argument is invalid; see field",
            RefusalCode::BackendAmbiguous => {
                "more than one connection could serve this code search; an operator must leave one"
            }
            RefusalCode::BackendQuarantined => {
                "the code search backend action is quarantined pending operator review"
            }
            RefusalCode::ConsentUnavailable => "flows cannot request consent for this action",
            RefusalCode::AskFirst => {
                "Searches cannot be approved per call; set the search policy to allow or block."
            }
            RefusalCode::BackendUnavailable => crate::transport::OPERATOR_DIAGNOSTIC_MESSAGE,
        };
        let mut error = json!({"code": self.code.as_str(), "message": message});
        if let Some(field) = &self.field {
            error["field"] = json!(field);
        }
        if let Some(delay) = self.retry_after_ms {
            error["retry_after_ms"] = json!(delay);
        }
        if self.code == "consent_unavailable" {
            error["action"] = json!(ACTION);
            error["transmission"] = json!("not_sent");
        }
        json!({"error":error})
    }
}

pub struct CodeSearchService {
    limiter: RateLimiter,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Default for CodeSearchService {
    fn default() -> Self {
        Self::with_clock(Arc::new(crate::storage::now_ms))
    }
}

impl CodeSearchService {
    pub fn with_clock(clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            limiter: RateLimiter::default(),
            clock,
        }
    }

    pub fn search_scoped<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        caller: &str,
        arguments: &Map<String, Value>,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<CodeSearchResponse, CodeSearchRefusal> {
        let mut audit = AuditRecord {
            principal: caller.to_string(),
            actor: caller.to_string(),
            acting_principal: caller.to_string(),
            agent_id: scope.and_then(|s| s.agent_id.clone()),
            app_handle_id: None,
            agent_handle: None,
            connection_id: None,
            app_key: Some(BACKEND.to_string()),
            action: Some(ACTION.to_string()),
            risk: None,
            severity: None,
            decision: "deny".into(),
            reason_code: "invalid_query".into(),
            gate: Some("code_search".into()),
            args_redaction_summary: Some(
                "code_search query recorded in query_text; other arguments omitted".into(),
            ),
            outcome: Some("not_sent".into()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        };
        let mut query_text = None;
        let outcome = (|| {
            let query = CodeSearchQuery::parse(arguments)?;
            query_text = Some(query.query.clone());
            let agent = resolve_call_agent(scope);
            let now = (self.clock)();
            // Find the granted connection first: the rate buckets are shared
            // (the global grep.app bucket serves every caller), so a caller
            // with no grant must be refused before it can spend from them.
            let (connection, action) = backing_connection(engine.store(), caller, now)?;
            audit.principal = connection.principal.clone();
            audit.connection_id = Some(connection.connection_id.clone());
            audit.risk = Some(action.risk.clone());
            audit.severity = Some(action.severity.clone());
            let policy = engine
                .store()
                .matching_policy(
                    &connection.principal,
                    &connection.connection_id,
                    ACTION,
                    now,
                )
                .map_err(store_failure)?;
            let effect = crate::governance::catalog_policy_effect(
                &action,
                policy.as_ref().map(|row| row.effect.as_str()),
                None,
            );
            if crate::governance::per_call_approval_unsupported(effect, false) {
                return Err(CodeSearchRefusal::new(RefusalCode::AskFirst));
            }
            if effect != "allow" {
                return Err(CodeSearchRefusal::new(RefusalCode::NotGranted));
            }
            // Limits are stored by backend in web_search_limits. Charge the caller's
            // module bucket and the global grep.app bucket, irrespective of agent identity.
            let limits = engine
                .store()
                .web_search_limits(BACKEND)
                .map_err(store_failure)?
                .unwrap_or_else(default_limits);
            self.limiter
                .try_acquire(
                    BACKEND,
                    &CallerKey {
                        principal: caller.to_string(),
                        agent_id: None,
                    },
                    limits,
                    now,
                )
                .map_err(|retry_after_ms| CodeSearchRefusal {
                    retry_after_ms: Some(retry_after_ms),
                    ..CodeSearchRefusal::new(RefusalCode::RateLimited)
                })?;
            let mut request = AuthorizationRequest::new(
                caller,
                &connection.connection_id,
                ACTION,
                query.vendor_args(),
            )
            .without_per_call_approval();
            if let Some(agent_id) = &agent.attributed {
                request = request.with_attributed_agent(agent_id);
            }
            // Record the daemon's scope for attribution without requiring the
            // stamped agent to hold its own invoke grant.
            if let Some(scope) = scope {
                request = request.with_scope_attribution_only(scope.clone());
            }
            if let Some(origin) = relay_origin {
                request = request.with_relay_origin(origin.clone());
            }
            let reservation = engine.authorize(request).map_err(refusal_for_denial)?;
            let dispatched = engine.revalidate_and_dispatch(&reservation);
            audit.outcome = Some("failed".into());
            let retry_after_ms = dispatched.retry_after_ms;
            let body = match dispatched.outcome {
                TransportOutcome::Completed {
                    response: Some(body),
                } => body,
                TransportOutcome::VendorFailed { code, .. }
                | TransportOutcome::NotSent { code, .. }
                    if code == "throttled" =>
                {
                    let retry_after_ms = retry_after_ms.unwrap_or(DEFAULT_VENDOR_RETRY_AFTER_MS);
                    return Err(CodeSearchRefusal {
                        retry_after_ms: Some(retry_after_ms),
                        ..CodeSearchRefusal::new(RefusalCode::RateLimited)
                    });
                }
                _ => return Err(unavailable()),
            };
            reply::parse_reply(&body).map_err(|error| {
                eprintln!(warn governance: "code_search reply unreadable: {error}");
                unavailable()
            })
        })();
        let result_count = match &outcome {
            Ok(response) => {
                audit.decision = "allow".into();
                audit.reason_code = "code_search_dispatched".into();
                audit.outcome = Some("completed".into());
                audit.response_class = Some("vendor".into());
                Some(response.matches.len() as i64)
            }
            Err(refusal) => {
                audit.reason_code = refusal.code.to_string();
                None
            }
        };
        // Code search queries are retained as text so usage can be analysed, like web search.
        // Journal retention defaults to 30 days (PLEXUS_AUDIT_RETENTION_DAYS).
        // Credentials are omitted; agent identity comes only from the daemon's route scope.
        if let Err(error) = engine.store().append_web_search_audit(
            &audit,
            query_text.as_deref(),
            result_count,
            scope,
            relay_origin,
        ) {
            eprintln!(error governance: "code_search audit append failed: {error}");
        }
        outcome
    }
}

fn unavailable() -> CodeSearchRefusal {
    CodeSearchRefusal::new(RefusalCode::BackendUnavailable)
}

fn store_failure(error: cortexkit_store::StoreError) -> CodeSearchRefusal {
    eprintln!(error governance: "code_search store lookup failed: {error}");
    unavailable()
}

fn refusal_for_denial(denial: Denial) -> CodeSearchRefusal {
    match denial {
        Denial::Policy(crate::governance::PolicyDenial::AskFirst) => {
            CodeSearchRefusal::new(RefusalCode::AskFirst)
        }
        Denial::Grant(_)
        | Denial::GrantRefusal(_)
        | Denial::Policy(_)
        | Denial::ActionRequestCreated { .. } => CodeSearchRefusal::new(RefusalCode::NotGranted),
        Denial::ConsentUnavailable { .. } => {
            CodeSearchRefusal::new(RefusalCode::ConsentUnavailable)
        }
        _ => unavailable(),
    }
}

fn backing_connection(
    store: &PlexusStore,
    caller: &str,
    now: i64,
) -> Result<(ConnectionRecord, CatalogAction), CodeSearchRefusal> {
    let mut eligible = Vec::new();
    for id in store
        .web_search_candidate_connection_ids(caller, BACKEND)
        .map_err(store_failure)?
    {
        let Some(connection) = store
            .connection_for_invoke(caller, &id)
            .map_err(store_failure)?
        else {
            continue;
        };
        let Some(action) = store
            .catalog_action(&connection.principal, &id, ACTION)
            .map_err(store_failure)?
        else {
            continue;
        };
        let rows = store
            .scoped_invoke_grant_rows(&connection, caller, None)
            .map_err(store_failure)?;
        let grant = scoped_grant(
            &rows,
            &connection,
            caller,
            None,
            AUTHORITY_INVOKE,
            ACTION,
            now,
            Some(&action.risk),
        );
        if scoped_grant_refusal(grant.as_ref(), ACTION, &action.risk, now).is_some() {
            continue;
        }
        eligible.push((connection, action));
    }
    if eligible.is_empty() {
        return Err(CodeSearchRefusal::new(RefusalCode::NotGranted));
    }
    if eligible.len() != 1 {
        eprintln!(warn governance: "code_search for {caller} is ambiguous across connections {:?}", eligible.iter().map(|(connection, _)| &connection.connection_id).collect::<Vec<_>>());
        return Err(CodeSearchRefusal::new(RefusalCode::BackendAmbiguous));
    }
    let (connection, action) = eligible.remove(0);
    if action.status == "quarantined" {
        eprintln!(warn governance: "code_search action quarantined on {}", connection.connection_id);
        return Err(CodeSearchRefusal::new(RefusalCode::BackendQuarantined));
    }
    if action.status != "active" || connection_denial(&connection).is_some() {
        return Err(unavailable());
    }
    Ok((connection, action))
}

#[cfg(test)]
mod tests;
