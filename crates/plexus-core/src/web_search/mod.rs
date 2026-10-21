//! `web_search`: a vendor-neutral, governed web search tool.
//!
//! The module's handler only unpacks the wire frame; everything that decides
//! whether a search runs lives here. With no stored provider order, the checks
//! retain the Exa compatibility contract:
//!
//! 1. validate the closed argument schema;
//! 2. attribute the agent only from the daemon scope stamp;
//! 3. refuse source-code lookups without spending rate-limit budget;
//! 4. find the one granted backend connection and require a usable action;
//! 5. charge the caller's and the backend's rate limits;
//! 6. serve from the cache only under current policy, or authorize and
//!    dispatch through governance. The stamped agent never adds an agent
//!    grant requirement to a search.
//!
//! With a stored order, `chain` first tries the cache, whose entry records the
//! provider that served it and is used only if this caller could be served by
//! that provider now. On a miss it prepares each provider's capability, resolves
//! the caller's grant, then checks policy, action status, connection health and
//! cooldown and the chain deadline, then reserves any monthly allowance, before
//! charging rate limits and authorizing a governed dispatch.
//! Argument validation and source-code refusal run once before either path.
//!
//! Every call writes one `web_search` audit row. A dispatched call also leaves
//! the engine's own authorization and dispatch rows.

pub mod backend;
pub mod cache;
pub mod capability;
mod chain;
mod code_lookup;
pub mod limiter;
pub mod providers;
pub mod query;

use std::sync::Arc;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::credentials::CredentialSource;
use crate::governance::{
    connection_denial, scoped_grant, scoped_grant_refusal, AuthorizationRequest, CatalogDenial,
    Denial, GovernanceEngine, TransportOutcome, AUTHORITY_INVOKE,
};
use crate::scope::{resolve_call_agent, CallScope};
use crate::storage::{AuditRecord, CatalogAction, ConnectionRecord, PlexusStore, RelayOrigin};
use crate::transport::Transport;

pub use backend::{
    BraveRestBackend, DeepSeekRestBackend, ExaRestBackend, FirecrawlRestBackend, JinaRestBackend,
    KagiRestBackend, KimiRestBackend, OllamaRestBackend, ParallelRestBackend,
    PerplexityRestBackend, SearxngRestBackend, SyntheticRestBackend, TavilyRestBackend,
    TinyFishRestBackend, WebSearchBackend, WebSearchResult, ZaiMcpBackend, EXCERPT_MAX_CHARS,
};
pub use cache::{CacheKey, ResultCache, CACHE_CAPACITY, CACHE_TTL_MS};
pub use chain::{ProviderSkip, SkipReason, WEB_SEARCH_ATTEMPT_BOUND, WEB_SEARCH_CHAIN_DEADLINE};
pub use limiter::{
    default_limits, CallerKey, RateLimiter, DEFAULT_PER_BACKEND_PER_MINUTE,
    DEFAULT_PER_CALLER_PER_MINUTE,
};
pub use query::{Recency, WebSearchQuery};

/// Every way a `web_search` call is refused. Each has a stable wire code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSearchRefusal {
    /// No live connection of the backend's app carries an invoke grant for
    /// the search action to this caller.
    NotGranted,
    Grant(crate::grant_refusal::GrantRefusal),
    RateLimited {
        retry_after_ms: u64,
    },
    /// The vendor or the transport failed, or the connection cannot serve.
    /// Vendor diagnostics stay in the log.
    BackendUnavailable {
        backend: String,
    },
    /// The provider rejected this request; trying another account cannot repair it.
    RequestRejected {
        backend: String,
    },
    /// The backing catalog action is quarantined.
    BackendQuarantined {
        backend: String,
    },
    /// More than one connection could serve the caller, and choosing one
    /// silently would pick whose credential and quota pays for the search.
    BackendAmbiguous,
    /// No configured provider could serve. Details contain only public names
    /// and closed reasons, never transport or vendor diagnostics.
    WebSearchUnavailable {
        providers: Vec<ProviderSkip>,
    },
    InvalidQuery {
        field: String,
    },
    /// Source-code targets belong to code search, local dependency source, or git.
    CodeLookup,
    PerCallApprovalUnsupported,
    ConsentUnavailable {
        action: String,
    },
}

impl WebSearchRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotGranted => "web_search_not_granted",
            Self::Grant(refusal) => refusal.code(),
            Self::RateLimited { .. } => "rate_limited",
            Self::BackendUnavailable { .. } => "backend_unavailable",
            Self::RequestRejected { .. } => "web_search_request_rejected",
            Self::BackendQuarantined { .. } => "backend_quarantined",
            Self::BackendAmbiguous => "backend_ambiguous",
            Self::WebSearchUnavailable { .. } => "web_search_unavailable",
            Self::InvalidQuery { .. } => "invalid_query",
            Self::CodeLookup => "web_search_code_lookup",
            Self::PerCallApprovalUnsupported => "policy_ask_first",
            Self::ConsentUnavailable { .. } => "consent_unavailable",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::NotGranted | Self::Grant(_) => "no web search backend is granted to this caller",
            Self::RateLimited { .. } => "web search rate limit reached; retry after retry_after_ms",
            Self::BackendUnavailable { .. } => crate::transport::OPERATOR_DIAGNOSTIC_MESSAGE,
            Self::RequestRejected { .. } => "the web search provider rejected the request",
            Self::WebSearchUnavailable { .. } => crate::transport::OPERATOR_DIAGNOSTIC_MESSAGE,
            Self::BackendQuarantined { .. } => {
                "the web search backend action is quarantined pending operator review"
            }
            Self::BackendAmbiguous => {
                "more than one connection could serve this web search; an operator must leave one"
            }
            Self::InvalidQuery { .. } => "a web search argument is invalid; see field",
            Self::CodeLookup => "web_search doesn't look up source code. For public repositories use code_search. For a dependency, read its source on disk (for Rust, ~/.cargo/registry/src). For a commit, use git.",
            Self::ConsentUnavailable { .. } => "flows cannot request consent for this action",
            Self::PerCallApprovalUnsupported => "Searches cannot be approved per call; set the search policy to allow or block.",
        }
    }

    /// The refusal as the tool's error body.
    pub fn to_wire(&self) -> Value {
        let mut error = json!({"code": self.code(), "message": self.message()});
        match self {
            Self::Grant(refusal) => error["detail"] = json!(refusal.detail()),
            Self::RateLimited { retry_after_ms } => error["retry_after_ms"] = json!(retry_after_ms),
            Self::ConsentUnavailable { action } => {
                error["action"] = json!(action);
                error["transmission"] = json!("not_sent");
            }
            Self::BackendUnavailable { backend }
            | Self::BackendQuarantined { backend }
            | Self::RequestRejected { backend } => error["backend"] = json!(backend),
            Self::InvalidQuery { field } => error["field"] = json!(field),
            Self::WebSearchUnavailable { providers } => error["detail"] = json!(providers),
            Self::NotGranted
            | Self::BackendAmbiguous
            | Self::CodeLookup
            | Self::PerCallApprovalUnsupported => {}
        }
        json!({"error": error})
    }
}

/// The backend implementing one provider in the name table, or `None` while
/// that provider has no backend yet. This is the one place a provider's
/// backend is registered: [`WebSearchService::production`] builds the module's
/// service from it, so the module needs no change when a provider is added.
/// A registered backend's `name`, `app_key` and `action` must equal its row.
pub fn registered_backend(provider: &providers::ProviderName) -> Option<Arc<dyn WebSearchBackend>> {
    match provider.name {
        "exa" => Some(Arc::new(ExaRestBackend)),
        "tavily" => Some(Arc::new(TavilyRestBackend)),
        "brave" => Some(Arc::new(BraveRestBackend)),
        "deepseek" => Some(Arc::new(DeepSeekRestBackend)),
        "firecrawl" => Some(Arc::new(FirecrawlRestBackend)),
        "jina" => Some(Arc::new(JinaRestBackend)),
        "kagi" => Some(Arc::new(KagiRestBackend)),
        "kimi" => Some(Arc::new(KimiRestBackend)),
        "ollama" => Some(Arc::new(OllamaRestBackend)),
        "parallel" => Some(Arc::new(ParallelRestBackend)),
        "perplexity" => Some(Arc::new(PerplexityRestBackend)),
        "synthetic" => Some(Arc::new(SyntheticRestBackend)),
        "tinyfish" => Some(Arc::new(TinyFishRestBackend)),
        "searxng" => Some(Arc::new(SearxngRestBackend)),
        "zai" => Some(Arc::new(ZaiMcpBackend::default())),
        _ => None,
    }
}

/// Whether a connection with this status can serve a web search. A pending
/// connection was never activated, and a disabled or revoked one was stopped
/// by an operator; every other status (active, degraded, auth-required) stays
/// a candidate, so governance can name a recoverable health condition.
/// Search resolution and the health report's `connection_present` both use
/// this, so the two cannot disagree about which connections exist.
pub fn connection_status_can_search(status: &str) -> bool {
    !matches!(status, "pending" | "disabled" | "revoked")
}

/// A successful search as the tool returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebSearchResponse {
    pub results: Vec<WebSearchResult>,
    pub backend: String,
    pub cached: bool,
}

/// The long-lived web search state: compatibility backend, chain backends,
/// rate limiter and result cache. One instance serves every caller of the module.
pub struct WebSearchService {
    backend: Arc<dyn WebSearchBackend>,
    limiter: RateLimiter,
    cache: ResultCache,
    /// Epoch milliseconds for rate limiting, cache age and recency windows.
    /// `fetched_at` always reads the real clock, since it reports an event.
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    chain_backends: std::collections::BTreeMap<&'static str, Arc<dyn WebSearchBackend>>,
    chain_cooldowns: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

/// What the one `web_search` audit row of a call records, filled in as the
/// call learns more about itself.
struct CallAudit {
    caller: String,
    /// The connection owner once resolved; the caller until then.
    principal: String,
    connection_id: Option<String>,
    risk: Option<String>,
    severity: Option<String>,
    agent_id: Option<String>,
    gate: &'static str,
    query_text: Option<String>,
    dispatched: bool,
    /// The daemon scope the caller's route was bound under, if any.
    scope: Option<CallScope>,
    /// The call from which this search was relayed, if the relay stated one.
    relay_origin: Option<RelayOrigin>,
    chain: Option<chain::ChainAudit>,
}

impl WebSearchService {
    pub fn new(backend: Arc<dyn WebSearchBackend>) -> Self {
        Self::with_clock(backend, Arc::new(crate::storage::now_ms))
    }

    /// A service reading time from `clock`, so a test can hold a minute still
    /// while it spends a rate limit.
    pub fn with_clock(
        backend: Arc<dyn WebSearchBackend>,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            chain_backends: [(backend.name(), backend.clone())].into(),
            chain_cooldowns: Default::default(),
            backend,
            limiter: RateLimiter::default(),
            cache: ResultCache::default(),
            clock,
        }
    }

    /// Exa over REST. A stored provider order can dispatch to Exa only; use
    /// [`Self::production`] for every implemented provider.
    pub fn exa() -> Self {
        Self::new(Arc::new(ExaRestBackend))
    }

    /// The service the module runs: Exa over REST for searches with no stored
    /// order, plus every backend [`registered_backend`] implements for ordered
    /// searches. With no order stored it behaves exactly as [`Self::exa`].
    pub fn production() -> Self {
        providers::PROVIDER_NAMES
            .iter()
            .filter_map(registered_backend)
            .fold(Self::exa(), Self::with_chain_backend)
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// The names of the providers a stored order can dispatch to, in name order.
    pub fn chain_backend_names(&self) -> Vec<&'static str> {
        self.chain_backends.keys().copied().collect()
    }

    /// The service's clock in epoch milliseconds: the time it counts monthly
    /// allowances and cooldowns against.
    pub fn now_ms(&self) -> i64 {
        (self.clock)()
    }

    /// How long ordered searches still skip `connection_id` after a failure
    /// cooled it down, in milliseconds; 0 when it is not cooling. Cooldowns
    /// live only in this process, so a restarted module reports 0.
    pub fn cooldown_remaining_ms(&self, connection_id: &str) -> u64 {
        let until = self
            .chain_cooldowns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(connection_id)
            .copied();
        until.map_or(0, |until| {
            u64::try_from(until.saturating_sub((self.clock)())).unwrap_or(0)
        })
    }

    /// Run one search for `caller` with the tool's closed argument schema.
    pub fn search<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        caller: &str,
        arguments: &Map<String, Value>,
    ) -> Result<WebSearchResponse, WebSearchRefusal> {
        self.search_scoped(engine, caller, arguments, None, None)
    }

    /// [`Self::search`] for a caller whose route was bound under a daemon
    /// scope. The scope's agent is attribution and part of the rate key only:
    /// search is not an action taken as the agent, so a delegating scope adds
    /// no agent-grant requirement.
    ///
    /// `relay_origin` is the call a relayed search came from. It is written on
    /// every audit row the search makes, for attribution only.
    #[allow(clippy::too_many_arguments)]
    pub fn search_scoped<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        caller: &str,
        arguments: &Map<String, Value>,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Result<WebSearchResponse, WebSearchRefusal> {
        let now_ms = (self.clock)();
        let mut audit = CallAudit {
            caller: caller.to_string(),
            principal: caller.to_string(),
            connection_id: None,
            risk: None,
            severity: None,
            agent_id: None,
            gate: "web_search",
            query_text: None,
            dispatched: false,
            scope: scope.cloned(),
            relay_origin: relay_origin.cloned(),
            chain: None,
        };
        let outcome = self.run(engine, arguments, now_ms, &mut audit);
        self.write_audit(engine.store(), &audit, &outcome);
        outcome
    }

    fn run<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        arguments: &Map<String, Value>,
        now_ms: i64,
        audit: &mut CallAudit,
    ) -> Result<WebSearchResponse, WebSearchRefusal> {
        let store = engine.store();
        let backend = self.backend.as_ref();
        let caller = audit.caller.clone();
        let query = WebSearchQuery::parse(arguments)?;
        audit.query_text = Some(query.query.clone());

        let agent = resolve_call_agent(audit.scope.as_ref());
        audit.agent_id = agent.attributed.clone();

        // Refuse before charging quota or reading old cached source-search results.
        if code_lookup::classify(&query).is_some() {
            return Err(WebSearchRefusal::CodeLookup);
        }

        let order = store.web_search_order().map_err(|error| {
            eprintln!(error web_search: "web_search order unreadable: {error}");
            self.unavailable()
        })?;
        if let Some(order) = order {
            return self.run_chain(engine, &order, &query, now_ms, audit);
        }

        let limits = match store.web_search_limits(backend.name()) {
            Ok(limits) => limits.unwrap_or_else(default_limits),
            Err(error) => {
                eprintln!(error web_search: "web_search limits unreadable for {}: {error}", backend.name());
                return Err(self.unavailable());
            }
        };
        let caller_key = CallerKey {
            principal: caller.clone(),
            agent_id: agent.attributed.clone(),
        };

        let is_flow = audit
            .scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some());
        let (connection, action) = self.backing_connection(store, &caller, now_ms, is_flow)?;
        audit.principal = connection.principal.clone();
        audit.connection_id = Some(connection.connection_id.clone());
        audit.risk = Some(action.risk.clone());
        audit.severity = Some(action.severity.clone());
        let effect = self.policy_effect(store, &connection, &action, now_ms)?;
        if crate::governance::per_call_approval_unsupported(effect, false) {
            return Err(WebSearchRefusal::PerCallApprovalUnsupported);
        }
        match action.status.as_str() {
            "active" => {}
            "quarantined" => {
                return Err(WebSearchRefusal::BackendQuarantined {
                    backend: backend.name().to_string(),
                })
            }
            _ => return Err(self.unavailable()),
        }
        if let Some(reason) = connection_denial(&connection) {
            eprintln!(warn web_search:
                "web_search connection {} cannot serve: {reason:?}",
                connection.connection_id
            );
            return Err(self.unavailable());
        }
        if effect != "allow" {
            return Err(WebSearchRefusal::NotGranted);
        }
        // Charge the rate buckets only once the caller is known to hold a grant
        // on a usable connection. The backend bucket is shared by every caller,
        // so charging earlier would let an ungranted caller drain it for all.
        self.limiter
            .try_acquire(backend.name(), &caller_key, limits, now_ms)
            .map_err(|retry_after_ms| WebSearchRefusal::RateLimited { retry_after_ms })?;

        // Search is authorized by the carrier's module grant. The stamped agent
        // supplies attribution and a rate-limit key, not a second grant layer.
        // Only after that grant and the rate limit are checked may the shared
        // cache answer, and only if policy would let the engine dispatch this
        // search. The cache saves the vendor call; it does not bypass policy.
        let key = CacheKey::new(backend.name(), &query);
        if let Some(results) = self.cache.get(&key, now_ms) {
            self.cached_read_policy(store, &connection, &action, now_ms, is_flow)?;
            return Ok(WebSearchResponse {
                results,
                backend: backend.name().to_string(),
                cached: true,
            });
        }

        let mut request = AuthorizationRequest::new(
            &caller,
            &connection.connection_id,
            backend.action(),
            backend.vendor_args(&query, now_ms),
        )
        .without_per_call_approval();
        if let Some(agent_id) = &agent.attributed {
            request = request.with_attributed_agent(agent_id);
        }
        // The scope goes on the audit rows only: it never makes the engine
        // require the agent's own grant for a search.
        if let Some(scope) = &audit.scope {
            request = request.with_scope_attribution_only(scope.clone());
        }
        if let Some(relay_origin) = &audit.relay_origin {
            request = request.with_relay_origin(relay_origin.clone());
        }
        let reservation = engine.authorize(request).map_err(|denial| {
            eprintln!(warn web_search:
                "web_search authorization refused on {} ({})",
                connection.connection_id,
                denial.reason_code()
            );
            self.refusal_for_denial(&caller, &denial)
        })?;
        let dispatched = engine.revalidate_and_dispatch(&reservation);
        let fetched_at_ms = crate::storage::now_ms();
        audit.dispatched = true;
        let body = match dispatched.outcome {
            TransportOutcome::Completed {
                response: Some(body),
            } => body,
            other => {
                // The transport has already logged the vendor's own body;
                // this line ties that failure to the web_search call.
                eprintln!(warn web_search:
                    "web_search backend {} failed on {}: {other:?}",
                    backend.name(),
                    connection.connection_id
                );
                return Err(self.unavailable());
            }
        };
        let results = backend
            .map_reply(&body, usize::from(query.max_results), fetched_at_ms)
            .map(backend::sanitize_results)
            .map_err(|error| {
                eprintln!(warn web_search:
                    "web_search backend {} reply unreadable: {}",
                    backend.name(),
                    error.0
                );
                self.unavailable()
            })?;
        self.cache.put(key, results.clone(), now_ms);
        Ok(WebSearchResponse {
            results,
            backend: backend.name().to_string(),
            cached: false,
        })
    }

    /// The one connection that backs a search for `caller`, with its search
    /// action. Candidates are resolved through `connection_for_invoke`, the
    /// same owner resolution the governance engine applies, so the connection
    /// checked here is the one `authorize` will load. A candidate counts only
    /// if the caller's module grant on it admits the action.
    fn backing_connection(
        &self,
        store: &PlexusStore,
        caller: &str,
        now_ms: i64,
        is_flow: bool,
    ) -> Result<(ConnectionRecord, CatalogAction), WebSearchRefusal> {
        let backend = self.backend.as_ref();
        self.backing_connection_for(
            store,
            caller,
            now_ms,
            is_flow,
            chain::BackendIdentity::of(backend),
            Self::grant_target(caller),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn backing_connection_for(
        &self,
        store: &PlexusStore,
        caller: &str,
        now_ms: i64,
        is_flow: bool,
        backend: chain::BackendIdentity,
        target: crate::grant_refusal::GrantTarget,
    ) -> Result<(ConnectionRecord, CatalogAction), WebSearchRefusal> {
        let store_failure = |error: cortexkit_store::StoreError| {
            eprintln!(error web_search: "web_search connection lookup failed: {error}");
            self.unavailable()
        };
        let mut eligible = Vec::new();
        let mut cause = crate::grant_refusal::Cause::Missing;
        for connection_id in store
            .web_search_candidate_connection_ids(caller, backend.app_key, now_ms)
            .map_err(store_failure)?
        {
            let Some(connection) = store
                .connection_for_invoke(caller, &connection_id)
                .map_err(store_failure)?
            else {
                continue;
            };
            // Reload after candidate selection: a connection may have changed
            // owner, backend or status between the two store reads.
            if connection.app_key != backend.app_key
                || !connection_status_can_search(&connection.status)
            {
                continue;
            }
            let Some(action) = store
                .catalog_action(
                    &connection.principal,
                    &connection.connection_id,
                    backend.action,
                )
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
                backend.action,
                now_ms,
                Some(&action.risk),
            );
            match scoped_grant_refusal(grant.as_ref(), backend.action, &action.risk, now_ms) {
                None => eligible.push((connection, action)),
                Some(reason) => {
                    cause = match reason {
                        crate::governance::GrantDenial::Expired => {
                            crate::grant_refusal::Cause::Expired
                        }
                        crate::governance::GrantDenial::ActionSelector => {
                            crate::grant_refusal::Cause::ActionSelector
                        }
                        crate::governance::GrantDenial::RiskCeiling => {
                            crate::grant_refusal::Cause::RiskCeiling
                        }
                        _ => crate::grant_refusal::Cause::Missing,
                    }
                }
            }
        }
        match eligible.len() {
            0 if is_flow => Err(WebSearchRefusal::Grant(
                crate::grant_refusal::GrantRefusal::new(target, cause),
            )),
            0 => Err(WebSearchRefusal::NotGranted),
            1 => Ok(eligible.remove(0)),
            _ => {
                eprintln!(warn web_search:
                    "web_search for {caller} is ambiguous across connections {:?}",
                    eligible
                        .iter()
                        .map(|(connection, _)| connection.connection_id.as_str())
                        .collect::<Vec<_>>()
                );
                Err(WebSearchRefusal::BackendAmbiguous)
            }
        }
    }

    /// Apply the policy the engine would apply before dispatching `action`.
    /// It uses the same governing-policy selection and the same default (the
    /// action's ask-first flag when no policy matches). Only `allow` admits a
    /// cached read. `block` refuses, and so does `ask_first`, because a cache hit
    /// never parks an approval request. Unknown effects count as `block`.
    fn cached_read_policy(
        &self,
        store: &PlexusStore,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        now_ms: i64,
        _is_flow: bool,
    ) -> Result<(), WebSearchRefusal> {
        let effect = self.policy_effect(store, connection, action, now_ms)?;
        if effect == "allow" {
            return Ok(());
        }
        if crate::governance::per_call_approval_unsupported(effect, false) {
            return Err(WebSearchRefusal::PerCallApprovalUnsupported);
        }
        eprintln!(warn web_search:
            "web_search cache hit refused by policy ({effect}) on {}",
            connection.connection_id
        );
        Err(WebSearchRefusal::NotGranted)
    }

    pub fn grant_target(caller: &str) -> crate::grant_refusal::GrantTarget {
        crate::grant_refusal::GrantTarget::new(
            crate::grant_refusal::Layer::Module,
            caller,
            "web_search",
            None,
            "search",
        )
    }

    /// Read the same candidate and policy as a search, without rate charging,
    /// cache mutation, reservations, approval requests or vendor contact.
    pub fn would_ask(
        &self,
        store: &PlexusStore,
        caller: &str,
    ) -> Result<&'static str, WebSearchRefusal> {
        let now = (self.clock)();
        let (connection, action) = self.backing_connection(store, caller, now, true)?;
        self.policy_effect(store, &connection, &action, now)
    }

    fn policy_effect(
        &self,
        store: &PlexusStore,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        now: i64,
    ) -> Result<&'static str, WebSearchRefusal> {
        let policy = store
            .matching_policy(
                &connection.principal,
                &connection.connection_id,
                &action.name,
                now,
            )
            .map_err(|error| {
                eprintln!(error web_search: "web_search policy lookup failed: {error}");
                self.unavailable()
            })?;
        Ok(crate::governance::catalog_policy_effect(
            action,
            policy.as_ref().map(|p| p.effect.as_str()),
            None,
        ))
    }

    fn unavailable(&self) -> WebSearchRefusal {
        WebSearchRefusal::BackendUnavailable {
            backend: self.backend.name().to_string(),
        }
    }

    /// Map a governance denial met after the checks above onto the tool's
    /// closed refusal set. Per-call approval is refused explicitly; other
    /// grant and policy denials read as not granted;
    /// everything else (credential, transport, health, store) as unavailable.
    /// A grant refusal names `caller` as the grantee, the same target the
    /// pre-flight grant check reports, so the operator is told to grant the
    /// module that actually asked.
    fn refusal_for_denial(&self, caller: &str, denial: &Denial) -> WebSearchRefusal {
        match denial {
            Denial::Policy(crate::governance::PolicyDenial::AskFirst) => {
                WebSearchRefusal::PerCallApprovalUnsupported
            }
            Denial::GrantRefusal(refusal) => {
                WebSearchRefusal::Grant(crate::grant_refusal::GrantRefusal::new(
                    Self::grant_target(caller),
                    refusal.detail().cause,
                ))
            }
            Denial::ConsentUnavailable { action } => WebSearchRefusal::ConsentUnavailable {
                action: action.clone(),
            },
            Denial::Catalog(CatalogDenial::Quarantined) => WebSearchRefusal::BackendQuarantined {
                backend: self.backend.name().to_string(),
            },
            Denial::Grant(_) | Denial::Policy(_) | Denial::ActionRequestCreated { .. } => {
                WebSearchRefusal::NotGranted
            }
            _ => self.unavailable(),
        }
    }

    fn write_audit(
        &self,
        store: &PlexusStore,
        audit: &CallAudit,
        outcome: &Result<WebSearchResponse, WebSearchRefusal>,
    ) {
        let (decision, reason_code, row_outcome, response_class, result_count) = match outcome {
            Ok(response) if response.cached => (
                "allow",
                "web_search_cache_hit".to_string(),
                "cached",
                Some("cached"),
                Some(response.results.len() as i64),
            ),
            Ok(response) => (
                "allow",
                "web_search_dispatched".to_string(),
                "completed",
                Some("vendor"),
                Some(response.results.len() as i64),
            ),
            Err(refusal) => (
                "deny",
                refusal.code().to_string(),
                if audit.dispatched {
                    "failed"
                } else {
                    "not_sent"
                },
                None,
                None,
            ),
        };
        let record = AuditRecord {
            principal: audit.principal.clone(),
            actor: audit.caller.clone(),
            acting_principal: audit.caller.clone(),
            agent_id: audit.agent_id.clone(),
            app_handle_id: None,
            agent_handle: None,
            connection_id: audit.connection_id.clone(),
            app_key: audit.chain.as_ref().map_or_else(
                || Some(self.backend.app_key().to_string()),
                |chain| chain.attempted.map(|backend| backend.app_key.to_string()),
            ),
            action: audit.chain.as_ref().map_or_else(
                || Some(self.backend.action().to_string()),
                |chain| chain.attempted.map(|backend| backend.action.to_string()),
            ),
            risk: audit.risk.clone(),
            severity: audit.severity.clone(),
            decision: decision.to_string(),
            reason_code,
            gate: Some(audit.gate.to_string()),
            args_redaction_summary: Some(audit.chain.as_ref().map_or_else(
                || {
                    "web_search query recorded in query_text; assertion and other arguments omitted"
                        .to_string()
                },
                |chain| json!({"served_by": chain.served_by, "skipped": chain.skipped}).to_string(),
            )),
            outcome: Some(row_outcome.to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: response_class.map(str::to_string),
            reconciliation_of: None,
        };
        // DELIBERATE EXCEPTION to the hash-only argument policy: every other
        // audit row records arguments only as hashes, but a web search is
        // unreviewable without the words searched for, and search terms are
        // not credentials. The query is kept as text for the journal's normal
        // retention window (30 days by default) and ages out with the row.
        // Nothing credential-derived is written here.
        if let Err(error) = store.append_web_search_audit(
            &record,
            audit.query_text.as_deref(),
            result_count,
            audit.scope.as_ref(),
            audit.relay_origin.as_ref(),
        ) {
            eprintln!(error governance:
                "audit append failed: web_search reason={:?} principal={:?} actor={:?} connection_id={:?}: {error}",
                record.reason_code, record.principal, record.actor, record.connection_id
            );
        }
    }
}

#[cfg(test)]
mod tests;
