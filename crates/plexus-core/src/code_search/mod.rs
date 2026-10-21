//! Public code search authorized by the caller's module grant.
//! Agent identities are recorded for audit attribution, not used to grant access.

pub mod query;
pub mod reply;

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::credentials::CredentialSource;
use crate::governance::{AuthorizationRequest, GovernanceEngine};
use crate::grant_refusal::{GrantRefusal, GrantTarget, Layer};
use crate::scope::{resolve_call_agent, CallScope};
use crate::storage::RelayOrigin;
use crate::transport::Transport;
use crate::web_search::facade::{self, SearchDenial, SearchTarget, SearchTool};
use crate::web_search::limiter::{default_limits, CallerKey, RateLimiter};

pub use query::CodeSearchQuery;
pub use reply::CodeSearchResponse;

pub const BACKEND: &str = "grep_app";
pub const ACTION: &str = "searchGitHub";

const TARGET: SearchTarget = SearchTarget {
    tool: SearchTool::Code,
    app_key: BACKEND,
    action: ACTION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalCode {
    NotGranted,
    /// A flow's typed grant refusal at the named layer.
    GrantAbsent(Layer),
    PolicyBlocked,
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
            Self::GrantAbsent(Layer::Module) => "module_grant_absent",
            Self::GrantAbsent(Layer::Agent) => "agent_grant_absent",
            Self::PolicyBlocked => "policy_blocked",
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
    /// Boxed: the typed refusal is large and rarely present.
    grant: Option<Box<GrantRefusal>>,
}

impl CodeSearchRefusal {
    fn new(code: RefusalCode) -> Self {
        Self {
            code,
            field: None,
            retry_after_ms: None,
            grant: None,
        }
    }
    fn grant(refusal: GrantRefusal) -> Self {
        Self {
            grant: Some(Box::new(refusal.clone())),
            ..Self::new(RefusalCode::GrantAbsent(refusal.detail().layer))
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
            RefusalCode::NotGranted | RefusalCode::GrantAbsent(_) => {
                "no code search backend is granted to this caller"
            }
            RefusalCode::PolicyBlocked => {
                "a policy blocks code search on the granted backend; an operator must change that policy"
            }
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
        if let Some(grant) = &self.grant {
            error["detail"] = json!(grant.detail());
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
        let mut audit = facade::SearchAudit::new(
            SearchTool::Code,
            caller,
            scope.and_then(|s| s.agent_id.clone()),
            scope,
            relay_origin,
        );
        let outcome = (|| {
            let query = CodeSearchQuery::parse(arguments)?;
            audit.query_text = Some(query.query.clone());
            let agent = resolve_call_agent(scope);
            let now = (self.clock)();
            let is_flow = scope.is_some_and(|scope| scope.flow_id.is_some());
            // Find the granted connection first: the rate buckets are shared
            // (the global grep.app bucket serves every caller), so a caller
            // with no grant must be refused before it can spend from them.
            let (connection, action) = facade::resolve_connection(
                engine.store(),
                caller,
                now,
                is_flow,
                TARGET,
                grant_target(caller),
            )
            .map_err(refusal_from)?;
            audit.resolved(&connection, &action);
            facade::standing_checks(engine.store(), SearchTool::Code, &connection, &action, now)
                .map_err(refusal_from)?;
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
            let reservation = engine.authorize(request).map_err(|denial| {
                refusal_from(facade::denial_for(&denial, grant_target(caller)))
            })?;
            let dispatched = engine.revalidate_and_dispatch(&reservation);
            audit.dispatched = true;
            let body = facade::vendor_body(
                SearchTool::Code,
                BACKEND,
                &connection.connection_id,
                &dispatched,
            )
            .map_err(refusal_from)?;
            reply::parse_reply(&body).map_err(|error| {
                eprintln!(warn governance: "code_search reply unreadable: {error}");
                unavailable()
            })
        })();
        let row = match &outcome {
            Ok(response) => facade::RowOutcome {
                decision: "allow",
                reason_code: "code_search_dispatched".to_string(),
                outcome: "completed",
                response_class: Some("vendor"),
                result_count: Some(response.matches.len() as i64),
            },
            Err(refusal) => audit.refused(refusal.code.as_str()),
        };
        // Code search queries are retained as text so usage can be analysed, like web search.
        // Journal retention defaults to 30 days (PLEXUS_AUDIT_RETENTION_DAYS).
        // Credentials are omitted; agent identity comes only from the daemon's route scope.
        let _ = audit.append(
            engine.store(),
            Some(BACKEND.to_string()),
            Some(ACTION.to_string()),
            "code_search query recorded in query_text; other arguments omitted".to_string(),
            row,
        );
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

/// The grant a flow is told to restore when no code search connection admits
/// it: the calling module's grant for grep.app's search action.
fn grant_target(caller: &str) -> GrantTarget {
    GrantTarget::new(Layer::Module, caller, "code_search", Some(BACKEND), ACTION)
}

/// Name a shared search denial in code_search's refusal set.
fn refusal_from(denial: SearchDenial) -> CodeSearchRefusal {
    match denial {
        SearchDenial::NotGranted => CodeSearchRefusal::new(RefusalCode::NotGranted),
        SearchDenial::Blocked => CodeSearchRefusal::new(RefusalCode::PolicyBlocked),
        SearchDenial::Grant(refusal) => CodeSearchRefusal::grant(refusal),
        SearchDenial::Ambiguous => CodeSearchRefusal::new(RefusalCode::BackendAmbiguous),
        SearchDenial::AskFirst => CodeSearchRefusal::new(RefusalCode::AskFirst),
        SearchDenial::Quarantined => CodeSearchRefusal::new(RefusalCode::BackendQuarantined),
        SearchDenial::Throttled { retry_after_ms } => CodeSearchRefusal {
            retry_after_ms: Some(retry_after_ms),
            ..CodeSearchRefusal::new(RefusalCode::RateLimited)
        },
        SearchDenial::ConsentUnavailable { .. } => {
            CodeSearchRefusal::new(RefusalCode::ConsentUnavailable)
        }
        SearchDenial::ConnectionUnusable | SearchDenial::Unavailable => unavailable(),
    }
}

/// The connection that backs a code search for a caller outside a flow.
#[cfg(test)]
fn backing_connection(
    store: &crate::storage::PlexusStore,
    caller: &str,
    now: i64,
) -> Result<
    (
        crate::storage::ConnectionRecord,
        crate::storage::CatalogAction,
    ),
    CodeSearchRefusal,
> {
    facade::resolve_connection(store, caller, now, false, TARGET, grant_target(caller))
        .map_err(refusal_from)
}

#[cfg(test)]
mod tests;
