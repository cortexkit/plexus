//! Provider admission for every web search: plexus finds the providers that
//! could serve, routing chooses one, and plexus dispatches it.

use super::routing::{self, RouteRef, RoutingPeer};
use super::*;
use crate::storage::web_search_store::{
    WebSearchAllowanceAdmission, WebSearchAllowanceReservation,
};
use crate::transport::TransmissionState;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::time::Duration;

mod outcome;

/// Admission budget measured from entry into the ordered provider walk.
pub const WEB_SEARCH_CHAIN_DEADLINE: Duration = Duration::from_secs(120);
/// One vault read (30 s), vendor request (30 s), and maximum throttle wait (5 s).
pub const WEB_SEARCH_ATTEMPT_BOUND: Duration = Duration::from_secs(65);

/// The closed vocabulary shared by chain refusals and skip auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Capability,
    NotGranted,
    Ambiguous,
    Policy,
    Quarantined,
    ConnectionUnusable,
    Cooldown,
    Allowance,
    RateLimited,
    Deadline,
    Quota,
    Throttled,
    Credential,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderSkip {
    pub provider: String,
    pub reason: SkipReason,
}

#[derive(Clone, Copy)]
pub(super) struct BackendIdentity {
    pub app_key: &'static str,
    pub action: &'static str,
}

/// One provider's reserved monthly allowance count while its attempt is in
/// progress. Dropping it hands the count back, so every early exit between
/// reservation and transmission (a rate-limit refusal, an authorize denial, an
/// unreadable limits row) releases it without a separate call at each exit.
/// `keep` settles a request that may have reached the vendor. The count was
/// committed by the reserving transaction, so a process that dies before
/// settling keeps it.
struct AllowanceHold<'a> {
    store: &'a PlexusStore,
    reservation: Option<WebSearchAllowanceReservation>,
}

impl AllowanceHold<'_> {
    /// Settle the count as spent: the request was sent, or may have been.
    fn keep(mut self) {
        self.reservation = None;
    }
}

impl Drop for AllowanceHold<'_> {
    fn drop(&mut self) {
        // A panic may have unwound out of a dispatch whose request already
        // left, so an unknown attempt keeps its count, as a crash would.
        if std::thread::panicking() {
            return;
        }
        if let Some(reservation) = self.reservation.take() {
            if let Err(error) = self.store.release_web_search_allowance(reservation) {
                eprintln!(error web_search: "web_search allowance release failed: {error}");
            }
        }
    }
}

/// What a chain cache entry records about the instance a connection searches:
/// the SHA-256 hex digest of its normalized instance address, or `None` for a
/// provider with one fixed vendor endpoint. Normalizing (the URL parser's
/// lower-cased scheme and host, default port dropped, no fragment, no
/// trailing slash) lets two spellings of one instance share entries.
///
/// `Err` means the connection's results must be neither stored nor served
/// from the cache: the address does not parse, or a SearXNG connection has
/// none, so its instance cannot be told apart from any other.
fn instance_digest(
    provider: &str,
    backend: &dyn WebSearchBackend,
    connection: &ConnectionRecord,
) -> Result<Option<String>, ()> {
    match backend.instance_url(connection) {
        Some(address) => {
            let mut url = reqwest::Url::parse(&address).map_err(|_| ())?;
            url.set_fragment(None);
            let normalized = url.as_str().trim_end_matches('/');
            Ok(Some(crate::jcs::sha256_hex(normalized.as_bytes())))
        }
        None if provider == "searxng" => Err(()),
        None => Ok(None),
    }
}

#[derive(Default)]
pub(super) struct ChainAudit {
    pub attempted: Option<BackendIdentity>,
    pub served_by: Option<String>,
    pub skipped: Vec<ProviderSkip>,
}

impl SkipReason {
    fn for_refusal(refusal: &WebSearchRefusal) -> Self {
        match refusal {
            WebSearchRefusal::NotGranted | WebSearchRefusal::Grant(_) => Self::NotGranted,
            WebSearchRefusal::BackendAmbiguous => Self::Ambiguous,
            WebSearchRefusal::PerCallApprovalUnsupported | WebSearchRefusal::PolicyBlocked => {
                Self::Policy
            }
            WebSearchRefusal::BackendQuarantined { .. } => Self::Quarantined,
            _ => Self::Unavailable,
        }
    }
}

impl WebSearchService {
    /// Register an implemented backend for ordered searches, leaving the
    /// compatibility backend unchanged. A name alone never enables dispatch.
    pub fn with_chain_backend(mut self, backend: Arc<dyn WebSearchBackend>) -> Self {
        self.chain_backends.insert(backend.name(), backend);
        self
    }

    fn chain_checks(
        &self,
        store: &PlexusStore,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        now_ms: i64,
    ) -> Result<(), SkipReason> {
        self.standing_checks(store, connection, action, now_ms)?;
        // Cooldown is connection-local. A provider's other account stays usable.
        if self
            .chain_cooldowns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&connection.connection_id)
            .is_some_and(|until| *until > now_ms)
        {
            return Err(SkipReason::Cooldown);
        }
        Ok(())
    }

    /// Checks 3-5: connection health, action status, then policy and per-call
    /// approval, in the order governance itself checks them. A cache hit must
    /// pass these too; cooldown, the monthly allowance and the deadline only
    /// govern contacting the vendor, so they are kept apart. (The rate limiter
    /// is separate: an eligible cache hit is still charged against it.)
    fn standing_checks(
        &self,
        store: &PlexusStore,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        now_ms: i64,
    ) -> Result<(), SkipReason> {
        // These durable refusals precede transient admission: a durable
        // refusal must not be hidden by cooldown or quota exhaustion.
        facade::standing_checks(store, facade::SearchTool::Web, connection, action, now_ms).map_err(
            |denial| match denial {
                facade::SearchDenial::ConnectionUnusable => SkipReason::ConnectionUnusable,
                facade::SearchDenial::Quarantined => SkipReason::Quarantined,
                facade::SearchDenial::AskFirst | facade::SearchDenial::Blocked => {
                    SkipReason::Policy
                }
                _ => SkipReason::Unavailable,
            },
        )
    }

    /// Serve a search from the cache, or return `None` for a miss. Cache hits
    /// need no routing: they are tried before any select, send no select and
    /// no report, and still answer while routing is unreachable.
    ///
    /// The entry was served by one provider, and a hit is used only if this
    /// caller could be served by that same provider now: it is still a search
    /// candidate, the caller resolves exactly one connection for it, that
    /// connection passes policy, action status and health and the cached-read
    /// policy, and for a per-connection instance the instance matches.
    /// Cooldown and allowance limit vendor contact, not cached reads, so they
    /// do not block a hit, and a hit counts no allowance.
    ///
    /// The provider's rate buckets are charged last, only once every other
    /// condition passed. A failed condition or a rate refusal is a miss, and
    /// the walk that follows charges each provider at most once, so a miss
    /// costs no more than if the cache had held nothing.
    #[allow(clippy::too_many_arguments)]
    fn chain_cache_hit(
        &self,
        store: &PlexusStore,
        candidates: &[String],
        key: &CacheKey,
        caller_key: &CallerKey,
        is_flow: bool,
        now_ms: i64,
        audit: &mut CallAudit,
    ) -> Option<WebSearchResponse> {
        let entry = self.cache.get_served(key, now_ms)?;
        let name = entry.served.provider.as_str();
        if !candidates.iter().any(|candidate| candidate == name) {
            return None;
        }
        let provider = providers::provider_named(name)?;
        let backend = self.chain_backends.get(provider.name)?;
        let identity = BackendIdentity {
            app_key: provider.app_key,
            action: provider.action,
        };
        let (connection, action) = self
            .resolve_provider(
                store,
                &audit.search.caller,
                now_ms,
                is_flow,
                false,
                provider,
            )
            .ok()?;
        // Policy must allow the search outright: a cache hit never parks an
        // approval request, so ask_first refuses here like block does.
        self.standing_checks(store, &connection, &action, now_ms)
            .ok()?;
        let instance = instance_digest(provider.name, backend.as_ref(), &connection).ok()?;
        if instance != entry.served.instance_digest {
            return None;
        }
        // Every other hit condition has passed: only now spend the caller's
        // and the provider's rate tokens. A refusal takes no tokens.
        let limits = store
            .web_search_limits(name)
            .ok()?
            .unwrap_or_else(default_limits);
        self.limiter
            .try_acquire(name, caller_key, limits, now_ms)
            .ok()?;
        audit.search.resolved(&connection, &action);
        let chain = audit.chain.get_or_insert_with(ChainAudit::default);
        chain.attempted = Some(identity);
        chain.served_by = Some(name.to_string());
        Some(WebSearchResponse {
            results: entry.results,
            backend: name.to_string(),
            cached: true,
        })
    }

    /// The routing facts for this search: a cached `role.describe` answer, or
    /// a fresh one. `Err` carries an operator-log reason.
    fn routing_facts(
        &self,
        peer: &dyn RoutingPeer,
        timeout: Duration,
    ) -> Result<routing::DescribeFacts, String> {
        let now = (self.clock)();
        let mut cached = self
            .routing_describe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((until, facts)) = *cached {
            if until > now {
                return Ok(facts);
            }
        }
        let facts =
            routing::read_describe_reply(peer.call("role.describe", json!({}), None, timeout))?;
        *cached = Some((now.saturating_add(routing::DESCRIBE_TTL_MS), facts));
        Ok(facts)
    }

    fn forget_routing_facts(&self) {
        *self
            .routing_describe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Tell routing how one attempt that reached (or may have reached) the
    /// vendor ended. A failed report is logged and changes nothing here.
    fn report_attempt(
        &self,
        peer: &dyn RoutingPeer,
        decision_id: &str,
        status: routing::AttemptStatus,
        facts: routing::DescribeFacts,
        scope: Option<&crate::scope::CallScope>,
    ) {
        if let Err(error) = peer.call(
            "route.report",
            routing::report_params(decision_id, status, facts.attempt_outcomes),
            scope,
            routing::ROUTING_REPORT_TIMEOUT,
        ) {
            eprintln!(warn web_search: "web_search route.report for {decision_id} failed: {error:?}");
        }
    }

    /// A search that needs a vendor: work out which providers could serve it
    /// now, let routing choose among them, dispatch the chosen provider and
    /// report how the attempt ended. A failed attempt is followed by a new
    /// select without that route, at most once per eligible route.
    pub(super) fn run_chain<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        query: &WebSearchQuery,
        now_ms: i64,
        audit: &mut CallAudit,
    ) -> Result<WebSearchResponse, WebSearchRefusal> {
        audit.chain = Some(ChainAudit::default());
        let is_flow = audit
            .search
            .scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some());
        let caller_key = if let Some(authority) = &audit.federated {
            authority
                .caller_key()
                .map_err(|denial| WebSearchRefusal::Governance(Box::new(denial)))?
        } else {
            CallerKey {
                principal: audit.search.caller.clone(),
                agent_id: audit.search.agent_id.clone(),
            }
        };
        let candidates = self.search_candidates(engine.store());
        let cache_key = CacheKey::new(cache::CHAIN_CACHE_BACKEND, query);
        if let Some(hit) = audit
            .federated
            .is_none()
            .then(|| {
                self.chain_cache_hit(
                    engine.store(),
                    &candidates,
                    &cache_key,
                    &caller_key,
                    is_flow,
                    now_ms,
                    audit,
                )
            })
            .flatten()
        {
            return Ok(hit);
        }
        let mut deadline_at_ms =
            (self.clock)().saturating_add(WEB_SEARCH_CHAIN_DEADLINE.as_millis() as i64);
        // Owned, so the walk can update the audit record while it holds the name.
        let caller = &audit.search.caller.clone();
        let mut all_not_granted = true;
        let mut first_grant_refusal = None;
        let mut retry_after = None::<u64>;
        let mut request_rejected = false;
        let mut federated_gate_refusal = None;
        let mut federated_consent_refusal = None;

        // Which providers could serve this search right now, using only checks
        // that contact nobody: capability, the caller's grant, connection and
        // action status, policy, this process's cooldowns and any monthly
        // allowance the operator set. Only these are offered to routing.
        let mut eligible = Vec::<Candidate>::new();
        for (position, name) in candidates.iter().enumerate() {
            let Some(provider) = providers::provider_named(name) else {
                // Every candidate is a provider-table name; fail closed if a
                // damaged store ever supplies another.
                all_not_granted = false;
                audit.chain.as_mut().unwrap().skipped.push(ProviderSkip {
                    provider: name.clone(),
                    reason: SkipReason::Unavailable,
                });
                continue;
            };
            let identity = BackendIdentity {
                app_key: provider.app_key,
                action: provider.action,
            };
            let backend = self.chain_backends.get(provider.name);
            // Prepare capability first, but always resolve the caller's grant too.
            // A query that cannot fit a provider still contributes its grant
            // result when deciding whether every provider lacks permission.
            let prepared = backend.map(|backend| backend.prepare(query, now_ms));
            let resolved = self.resolve_provider(
                engine.store(),
                caller,
                now_ms,
                is_flow,
                audit.federated.is_some(),
                provider,
            );
            let not_granted = matches!(
                &resolved,
                Err(WebSearchRefusal::NotGranted | WebSearchRefusal::Grant(_))
            );
            all_not_granted &= not_granted;
            if position == 0 && not_granted {
                first_grant_refusal = resolved.as_ref().err().cloned();
            }
            let checked = (|| {
                let prepared = match prepared {
                    Some(Ok(prepared)) => Some(prepared),
                    Some(Err(_)) => return Err(SkipReason::Capability),
                    None => None,
                };
                let (connection, action) =
                    resolved.map_err(|refusal| SkipReason::for_refusal(&refusal))?;
                // Active catalog rows carry the approved pin; refresh quarantines
                // schema drift. Quarantined observations must never steer adapters.
                let prepared = if action.status == "active" {
                    match (backend, prepared) {
                        (Some(backend), Some(prepared)) => Some(
                            backend
                                .prepare_reviewed(
                                    prepared,
                                    Some(&action.schema),
                                    &connection.connection_id,
                                )
                                .map_err(|_| SkipReason::Capability)?,
                        ),
                        (_, prepared) => prepared,
                    }
                } else {
                    prepared
                };
                // A federated search meets its dispatch gates and consent
                // first, and the standing checks and cooldown after them, once
                // routing chose the provider, so a gate's own refusal or
                // consent request is what the caller sees.
                if audit.federated.is_none() {
                    self.chain_checks(engine.store(), &connection, &action, now_ms)?;
                }
                let (Some(backend), Some(prepared), Some(route)) =
                    (backend, prepared, self.route_of(name))
                else {
                    return Err(SkipReason::Unavailable);
                };
                // A provider with an operator-set allowance is offered only
                // while that allowance has searches left this month, so
                // routing can never pick a provider plexus would have to pay
                // past its allowance. The count itself is still reserved at
                // dispatch, in the same transaction as before.
                let allowance_left = match engine.store().web_search_allowance(name) {
                    Ok(None) => false,
                    Ok(Some(allowance)) => {
                        let used = engine
                            .store()
                            .web_search_allowance_used(
                                name,
                                &connection.principal,
                                (self.clock)(),
                            )
                            .map_err(|error| {
                                eprintln!(error web_search: "web_search allowance unreadable for {name}: {error}");
                                SkipReason::Unavailable
                            })?;
                        if used >= allowance {
                            return Err(SkipReason::Allowance);
                        }
                        true
                    }
                    Err(error) => {
                        eprintln!(error web_search: "web_search allowance unreadable for {name}: {error}");
                        return Err(SkipReason::Unavailable);
                    }
                };
                Ok(Candidate {
                    name: name.clone(),
                    provider,
                    identity,
                    route,
                    backend: Arc::clone(backend),
                    connection,
                    action,
                    prepared,
                    allowance_left,
                })
            })();
            match checked {
                Ok(candidate) => eligible.push(candidate),
                Err(reason) => audit.chain.as_mut().unwrap().skipped.push(ProviderSkip {
                    provider: name.clone(),
                    reason,
                }),
            }
        }
        if all_not_granted {
            return Err(Self::module_grant_refusal(
                first_grant_refusal.unwrap_or(WebSearchRefusal::NotGranted),
                caller,
            ));
        }

        let peer = if eligible.is_empty() {
            None
        } else {
            match self.routing_peer(&candidates) {
                Some(peer) => Some(peer),
                None => {
                    eprintln!(warn web_search: "web_search has no routing provider to choose a search provider");
                    return Err(WebSearchRefusal::RoutingUnavailable);
                }
            }
        };
        // Selects and reports go out under the search's own scope stamp.
        let route_scope = audit.search.scope.clone();
        let selects = eligible.len();
        for _ in 0..selects {
            let Some(peer) = peer.as_deref() else { break };
            if eligible.is_empty() {
                break;
            }
            // Check before selecting, so neither a select nor an attempt starts
            // without the time a whole attempt may take.
            let remaining = deadline_at_ms.saturating_sub((self.clock)());
            if remaining < WEB_SEARCH_ATTEMPT_BOUND.as_millis() as i64 {
                for candidate in eligible.drain(..) {
                    audit.chain.as_mut().unwrap().skipped.push(ProviderSkip {
                        provider: candidate.name,
                        reason: SkipReason::Deadline,
                    });
                }
                break;
            }
            let timeout = routing::ROUTING_CALL_TIMEOUT
                .min(Duration::from_millis(u64::try_from(remaining).unwrap_or(0)));
            let facts = match self.routing_facts(peer, timeout) {
                Ok(facts) => facts,
                Err(why) => {
                    eprintln!(warn web_search: "web_search routing cannot serve search: {why}");
                    return Err(WebSearchRefusal::RoutingUnavailable);
                }
            };
            let routes = eligible
                .iter()
                .map(|candidate| candidate.route.clone())
                .collect::<Vec<_>>();
            let allowance_left = eligible
                .iter()
                .filter(|candidate| candidate.allowance_left)
                .map(|candidate| candidate.route.clone())
                .collect::<Vec<_>>();
            let selection = match routing::read_select_reply(peer.call(
                "route.select",
                routing::select_params(&routes, &allowance_left),
                route_scope.as_ref(),
                timeout,
            )) {
                routing::SelectOutcome::Selected(selection) => selection,
                routing::SelectOutcome::NoRoute { reason } => {
                    let added_at = self.routes_added_at_ms.load(AtomicOrdering::Acquire);
                    if (self.clock)().saturating_sub(added_at) < routing::DECLARATION_GRACE_MS {
                        // Routing may not have read a route plexus just
                        // declared, so this is not yet "nothing can serve".
                        eprintln!(warn web_search: "web_search routing found no route ({reason:?}) inside the redeclaration window");
                        return Err(WebSearchRefusal::RoutingUnavailable);
                    }
                    eprintln!(info web_search: "web_search routing found no adequate route: {reason:?}");
                    break;
                }
                routing::SelectOutcome::Unavailable(why) => {
                    self.forget_routing_facts();
                    eprintln!(warn web_search: "web_search route.select failed: {why}");
                    return Err(WebSearchRefusal::RoutingUnavailable);
                }
            };
            let Some(index) = eligible
                .iter()
                .position(|candidate| candidate.route == selection.route)
            else {
                eprintln!(warn web_search:
                    "web_search routing answered route {}/{}, which plexus did not offer",
                    selection.route.provider, selection.route.model
                );
                return Err(WebSearchRefusal::RoutingUnavailable);
            };
            let Candidate {
                name,
                provider,
                identity,
                route: _,
                backend,
                connection,
                action,
                prepared,
                allowance_left: _,
            } = eligible.remove(index);
            let name = &name;
            let mut report = None::<routing::AttemptStatus>;
            let attempt = (|| {
                let federated_request = audit.federated.as_ref().map(|authority| {
                    let mut request = authority.bind(
                        AuthorizationRequest::new(
                            caller,
                            &connection.connection_id,
                            provider.action,
                            prepared.vendor_args.clone(),
                        )
                        .without_per_call_approval(),
                    );
                    if let Some(scope) = &audit.search.scope {
                        request = request.with_scope_attribution_only(scope.clone());
                    }
                    if let Some(origin) = &audit.search.relay_origin {
                        request = request.with_relay_origin(origin.clone());
                    }
                    request
                });
                if let Some(request) = &federated_request {
                    engine
                        .preflight_federated_search(request.clone())
                        .map_err(|denial| {
                            federated_gate_refusal =
                                Some(WebSearchRefusal::Governance(Box::new(denial)));
                            SkipReason::Unavailable
                        })?;
                }
                if audit.federated.is_some() {
                    self.standing_checks(engine.store(), &connection, &action, now_ms)?;
                }
                if let (Some(request), Some(authority)) =
                    (&federated_request, audit.federated.as_mut())
                {
                    engine
                        .apply_federated_search(request, authority)
                        .map_err(|denial| {
                            federated_consent_refusal =
                                Some(WebSearchRefusal::Governance(Box::new(denial)));
                            SkipReason::Unavailable
                        })?;
                    if authority.answer.is_some() {
                        // Human approval time is not provider-attempt time.
                        deadline_at_ms = (self.clock)()
                            .saturating_add(WEB_SEARCH_CHAIN_DEADLINE.as_millis() as i64);
                        engine
                            .preflight_federated_search(request.clone())
                            .map_err(|denial| {
                                federated_gate_refusal =
                                    Some(WebSearchRefusal::Governance(Box::new(denial)));
                                SkipReason::Unavailable
                            })?;
                        self.standing_checks(engine.store(), &connection, &action, now_ms)?;
                    }
                    // Unlike the local cache-first path, a federated cache lookup
                    // follows every backing-connection gate and the search row.
                    let limits = engine
                        .store()
                        .web_search_limits(name)
                        .map_err(|_| SkipReason::Unavailable)?
                        .unwrap_or_else(default_limits);
                    self.limiter
                        .try_acquire(name, &caller_key, limits, now_ms)
                        .map_err(|retry| {
                            retry_after = Some(retry_after.map_or(retry, |old| old.min(retry)));
                            SkipReason::RateLimited
                        })?;
                    engine
                        .consume_federated_search(authority)
                        .map_err(|denial| {
                            federated_consent_refusal =
                                Some(WebSearchRefusal::Governance(Box::new(denial)));
                            SkipReason::Unavailable
                        })?;
                    if let Some(entry) = self.cache.get_served(&cache_key, now_ms) {
                        if entry.served.provider == *name
                            && instance_digest(name, backend.as_ref(), &connection)
                                .is_ok_and(|instance| instance == entry.served.instance_digest)
                        {
                            audit.search.resolved(&connection, &action);
                            return Ok((
                                WebSearchResponse {
                                    results: entry.results,
                                    backend: name.clone(),
                                    cached: true,
                                },
                                instance_digest(name, backend.as_ref(), &connection),
                            ));
                        }
                    }
                    self.chain_checks(engine.store(), &connection, &action, now_ms)?;
                }

                // Check after policy/approval and cooldown, immediately before
                // allowance admission. This budgets attempt starts, not time
                // queued on the transport's per-connection send lock.
                if deadline_at_ms.saturating_sub((self.clock)())
                    < WEB_SEARCH_ATTEMPT_BOUND.as_millis() as i64
                {
                    return Err(SkipReason::Deadline);
                }
                // Check 7. The store decides eligibility and reserves the count
                // in one transaction, so concurrent searches cannot both take
                // the last unit. Only a provider with an allowance set is
                // counted, and the month is the UTC month of this reservation.
                let hold = AllowanceHold {
                    store: engine.store(),
                    reservation: match engine.store().reserve_web_search_allowance(
                        name,
                        &connection.principal,
                        (self.clock)(),
                    ) {
                        Ok(WebSearchAllowanceAdmission::Unlimited) => None,
                        Ok(WebSearchAllowanceAdmission::Reserved(reservation)) => Some(reservation),
                        Ok(WebSearchAllowanceAdmission::Exhausted) => {
                            return Err(SkipReason::Allowance)
                        }
                        Err(error) => {
                            eprintln!(error web_search: "web_search allowance unreadable for {name}: {error}");
                            return Err(SkipReason::Unavailable);
                        }
                    },
                };
                // Every return from here until the dispatch outcome drops
                // `hold` unsent, which releases the count.
                let limits = engine
                    .store()
                    .web_search_limits(name)
                    .map_err(|_| SkipReason::Unavailable)?
                    .unwrap_or_else(default_limits);
                if audit.federated.is_none() {
                    self.limiter
                        .try_acquire(name, &caller_key, limits, now_ms)
                        .map_err(|retry| {
                            retry_after = Some(retry_after.map_or(retry, |old| old.min(retry)));
                            SkipReason::RateLimited
                        })?;
                }

                let mut request = AuthorizationRequest::new(
                    caller,
                    &connection.connection_id,
                    provider.action,
                    prepared.vendor_args,
                )
                .without_per_call_approval();
                if let Some(agent_id) = &audit.search.agent_id {
                    request = request.with_attributed_agent(agent_id);
                }
                if let Some(scope) = &audit.search.scope {
                    request = request.with_scope_attribution_only(scope.clone());
                }
                if let Some(origin) = &audit.search.relay_origin {
                    request = request.with_relay_origin(origin.clone());
                }
                audit.search.resolved(&connection, &action);
                audit.search.new_attempt();
                audit.chain.as_mut().unwrap().attempted = Some(identity);
                // Local searches check connector-home ownership only here;
                // federated searches already checked it before rate and cache.
                let request = if let Some(authority) = &audit.federated {
                    authority.bind(federated_request.unwrap_or(request))
                } else {
                    request
                };
                let reservation = engine.authorize(request).map_err(|denial| {
                    if audit.federated.is_some() { federated_gate_refusal = Some(WebSearchRefusal::Governance(Box::new(denial.clone()))); }
                    eprintln!(warn web_search: "web_search chain authorization refused on {} ({})", connection.connection_id, denial.reason_code());
                    SkipReason::for_refusal(&self.refusal_for_denial(caller, &denial))
                })?;
                audit.search.request_id = Some(reservation.request_id.clone());
                let dispatched = engine.revalidate_and_dispatch(&reservation);
                // Revalidation refusals also report NotSent. Sent and
                // OutcomeUnknown may have reached the vendor, so they keep it.
                let reached_vendor = dispatched.transmission != TransmissionState::NotSent;
                if reached_vendor {
                    hold.keep();
                } else {
                    drop(hold);
                }
                audit.search.transmission = Some(dispatched.transmission);
                let classified = outcome::classify(
                    backend.as_ref(),
                    &dispatched,
                    usize::from(prepared.query.max_results),
                    crate::storage::now_ms(),
                );
                // Routing hears only about attempts that reached, or may have
                // reached, the vendor; one stopped before sending says nothing
                // about the route.
                if reached_vendor {
                    report = Some(outcome::attempt_status(&classified, &dispatched));
                }
                let results = match classified {
                    outcome::Classified::Serve(results) => results,
                    outcome::Classified::Reject => {
                        eprintln!(warn web_search: "web_search request rejected by {}", name);
                        request_rejected = true;
                        return Err(SkipReason::Unavailable);
                    }
                    outcome::Classified::MoveOn {
                        reason,
                        cooldown_ms,
                    } => {
                        let until = (self.clock)().saturating_add(cooldown_ms as i64);
                        self.chain_cooldowns
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .entry(connection.connection_id.clone())
                            .and_modify(|old| *old = (*old).max(until))
                            .or_insert(until);
                        return Err(reason);
                    }
                };
                Ok((
                    WebSearchResponse {
                        results,
                        backend: name.clone(),
                        cached: false,
                    },
                    instance_digest(name, backend.as_ref(), &connection),
                ))
            })();
            if let Some(status) = report {
                self.report_attempt(
                    peer,
                    &selection.decision_id,
                    status,
                    facts,
                    route_scope.as_ref(),
                );
            }
            if let Some(refusal) = federated_consent_refusal.take() {
                return Err(refusal);
            }
            if request_rejected {
                return Err(WebSearchRefusal::RequestRejected {
                    backend: name.clone(),
                });
            }
            match attempt {
                Ok((response, instance)) => {
                    audit.chain.as_mut().unwrap().served_by = Some(name.clone());
                    // An instance address that cannot be told apart from
                    // another instance's is served but never cached.
                    if let Ok(instance_digest) = instance {
                        self.cache.put_served(
                            cache_key,
                            response.results.clone(),
                            cache::ServedBy {
                                provider: name.clone(),
                                instance_digest,
                            },
                            now_ms,
                        );
                    }
                    return Ok(response);
                }
                Err(reason) => audit.chain.as_mut().unwrap().skipped.push(ProviderSkip {
                    provider: name.clone(),
                    reason,
                }),
            }
        }
        let skipped = &audit.chain.as_ref().unwrap().skipped;
        if !skipped.is_empty()
            && skipped
                .iter()
                .all(|skip| skip.reason == SkipReason::RateLimited)
        {
            return Err(WebSearchRefusal::RateLimited {
                retry_after_ms: retry_after.unwrap(),
            });
        }
        if let Some(refusal) = federated_gate_refusal {
            return Err(refusal);
        }
        Err(WebSearchRefusal::WebSearchUnavailable {
            providers: skipped.clone(),
        })
    }

    /// The one connection that would serve `provider` for `caller`, with its
    /// search action: the caller's granted connection for a local search, the
    /// directly owned one for a federated search. Searches, cache hits and
    /// [`WebSearchService::would_ask`] all resolve through here.
    pub(super) fn resolve_provider(
        &self,
        store: &PlexusStore,
        caller: &str,
        now_ms: i64,
        is_flow: bool,
        federated: bool,
        provider: &providers::ProviderName,
    ) -> Result<(ConnectionRecord, CatalogAction), WebSearchRefusal> {
        let identity = BackendIdentity {
            app_key: provider.app_key,
            action: provider.action,
        };
        if federated {
            return facade::resolve_federated_connection(
                store,
                now_ms,
                facade::SearchTarget {
                    tool: facade::SearchTool::Web,
                    app_key: identity.app_key,
                    action: identity.action,
                },
            )
            .map_err(|denial| self.refusal_from(denial));
        }
        self.backing_connection_for(
            store,
            caller,
            now_ms,
            is_flow,
            identity,
            crate::grant_refusal::GrantTarget::new(
                crate::grant_refusal::Layer::Module,
                caller,
                "web_search",
                Some(provider.name),
                provider.action,
            ),
        )
    }

    /// A refusal for a caller no provider is granted to. Web search is
    /// granted per module, not per provider, so a grant refusal names the
    /// module-wide web search target; `grants.would_ask` reads that same
    /// target back.
    pub(super) fn module_grant_refusal(
        refusal: WebSearchRefusal,
        caller: &str,
    ) -> WebSearchRefusal {
        match refusal {
            WebSearchRefusal::Grant(refusal) => {
                WebSearchRefusal::Grant(crate::grant_refusal::GrantRefusal::new(
                    Self::grant_target(caller),
                    refusal.detail().cause,
                ))
            }
            other => other,
        }
    }

    /// The providers a search may use, in the order their skips are recorded:
    /// every provider-table name with a routing route and a registered backend.
    pub(super) fn search_candidates(&self, store: &PlexusStore) -> Vec<String> {
        // Test services may take their candidates from a stored order.
        #[cfg(any(test, feature = "test-support"))]
        if self.stored_order_router {
            if let Ok(Some(order)) = store.web_search_order() {
                return order;
            }
        }
        let _ = store;
        providers::SEARCH_ROUTES
            .iter()
            .map(|(name, _, _)| *name)
            .filter(|name| self.chain_backends.contains_key(name))
            .map(str::to_owned)
            .collect()
    }

    /// The routing route that names provider `name`.
    fn route_of(&self, name: &str) -> Option<RouteRef> {
        if let Some((provider, model)) = providers::search_route(name) {
            return Some(RouteRef::new(provider, model));
        }
        // Test services may search providers that have no catalog row yet.
        #[cfg(any(test, feature = "test-support"))]
        if self.stored_order_router && providers::provider_named(name).is_some() {
            return Some(RouteRef::new(name, "search"));
        }
        None
    }

    /// The route plexus asks to choose a provider over.
    fn routing_peer(&self, candidates: &[String]) -> Option<Arc<dyn RoutingPeer>> {
        if let Some(router) = &self.router {
            return Some(Arc::clone(router));
        }
        // Test services without a router rank their candidates in order.
        #[cfg(any(test, feature = "test-support"))]
        if self.stored_order_router {
            return Some(Arc::new(routing::fake::FakeRouter::ranked(
                candidates
                    .iter()
                    .filter_map(|name| self.route_of(name))
                    .collect(),
            )));
        }
        let _ = candidates;
        None
    }
}

/// One provider that passed every check that contacts nobody, with what its
/// attempt will need if routing chooses it.
struct Candidate {
    name: String,
    provider: &'static providers::ProviderName,
    identity: BackendIdentity,
    route: RouteRef,
    backend: Arc<dyn WebSearchBackend>,
    connection: ConnectionRecord,
    action: CatalogAction,
    prepared: capability::PreparedSearch,
    allowance_left: bool,
}

#[cfg(test)]
mod tests;
