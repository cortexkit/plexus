//! Ordered provider admission. Compatibility searches never enter this walk.

use super::*;
use crate::storage::web_search_store::{
    WebSearchAllowanceAdmission, WebSearchAllowanceReservation,
};
use crate::transport::TransmissionState;
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

impl BackendIdentity {
    pub fn of(backend: &dyn WebSearchBackend) -> Self {
        Self {
            app_key: backend.app_key(),
            action: backend.action(),
        }
    }
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
    use sha2::{Digest, Sha256};
    match backend.instance_url(connection) {
        Some(address) => {
            let mut url = reqwest::Url::parse(&address).map_err(|_| ())?;
            url.set_fragment(None);
            let normalized = url.as_str().trim_end_matches('/');
            Ok(Some(hex::encode(Sha256::digest(normalized.as_bytes()))))
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
            WebSearchRefusal::PerCallApprovalUnsupported => Self::Policy,
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

    /// Checks 3-5: policy and per-call approval, action status and connection
    /// health. A cache hit must pass these too; cooldown, allowance and the
    /// deadline only govern contacting the vendor, so they are kept apart.
    fn standing_checks(
        &self,
        store: &PlexusStore,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        now_ms: i64,
    ) -> Result<(), SkipReason> {
        // Policy, action status and connection health precede transient admission:
        // a durable refusal must not be hidden by cooldown or quota exhaustion.
        let effect = self
            .policy_effect(store, connection, action, now_ms)
            .map_err(|refusal| SkipReason::for_refusal(&refusal))?;
        if effect != "allow" {
            return Err(SkipReason::Policy);
        }
        match action.status.as_str() {
            "active" => {}
            "quarantined" => return Err(SkipReason::Quarantined),
            _ => return Err(SkipReason::Unavailable),
        }
        if connection_denial(connection).is_some() {
            return Err(SkipReason::ConnectionUnusable);
        }
        Ok(())
    }

    /// Serve a chain search from the cache, or return `None` for a miss.
    ///
    /// The entry was served by one provider, and a hit is used only if this
    /// caller could be served by that same provider now: it is still in the
    /// order, the caller resolves exactly one connection for it, that
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
        order: &[String],
        key: &CacheKey,
        caller_key: &CallerKey,
        is_flow: bool,
        now_ms: i64,
        audit: &mut CallAudit,
    ) -> Option<WebSearchResponse> {
        let entry = self.cache.get_served(key, now_ms)?;
        let name = entry.served.provider.as_str();
        if !order.iter().any(|ordered| ordered == name) {
            return None;
        }
        let provider = providers::provider_named(name)?;
        let backend = self.chain_backends.get(provider.name)?;
        let identity = BackendIdentity {
            app_key: provider.app_key,
            action: provider.action,
        };
        let target = crate::grant_refusal::GrantTarget::new(
            crate::grant_refusal::Layer::Module,
            &audit.caller,
            "web_search",
            Some(provider.name),
            provider.action,
        );
        let (connection, action) = self
            .backing_connection_for(store, &audit.caller, now_ms, is_flow, identity, target)
            .ok()?;
        self.cached_read_policy(store, &connection, &action, now_ms, is_flow)
            .ok()?;
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
        audit.principal = connection.principal.clone();
        audit.connection_id = Some(connection.connection_id.clone());
        audit.risk = Some(action.risk.clone());
        audit.severity = Some(action.severity.clone());
        let chain = audit.chain.get_or_insert_with(ChainAudit::default);
        chain.attempted = Some(identity);
        chain.served_by = Some(name.to_string());
        Some(WebSearchResponse {
            results: entry.results,
            backend: name.to_string(),
            cached: true,
        })
    }

    pub(super) fn run_chain<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        order: &[String],
        query: &WebSearchQuery,
        now_ms: i64,
        audit: &mut CallAudit,
    ) -> Result<WebSearchResponse, WebSearchRefusal> {
        audit.chain = Some(ChainAudit::default());
        let is_flow = audit
            .scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some());
        let caller_key = CallerKey {
            principal: audit.caller.clone(),
            agent_id: audit.agent_id.clone(),
        };
        let cache_key = CacheKey::new(cache::CHAIN_CACHE_BACKEND, query);
        if let Some(hit) = self.chain_cache_hit(
            engine.store(),
            order,
            &cache_key,
            &caller_key,
            is_flow,
            now_ms,
            audit,
        ) {
            return Ok(hit);
        }
        let deadline_at_ms =
            (self.clock)().saturating_add(WEB_SEARCH_CHAIN_DEADLINE.as_millis() as i64);
        let mut deadline_stopped = false;
        let caller = &audit.caller;
        let mut all_not_granted = true;
        let mut first_grant_refusal = None;
        let mut retry_after = None::<u64>;
        let mut request_rejected = false;

        for (position, name) in order.iter().enumerate() {
            let Some(provider) = providers::provider_named(name) else {
                // Persisted orders are validated on write. Fail closed if an
                // imported or damaged store contains an unrecognized name.
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
            let target = crate::grant_refusal::GrantTarget::new(
                crate::grant_refusal::Layer::Module,
                caller,
                "web_search",
                Some(provider.name),
                provider.action,
            );
            let resolved = self.backing_connection_for(
                engine.store(),
                caller,
                now_ms,
                is_flow,
                identity,
                target,
            );
            let not_granted = matches!(
                &resolved,
                Err(WebSearchRefusal::NotGranted | WebSearchRefusal::Grant(_))
            );
            all_not_granted &= not_granted;
            if position == 0 && not_granted {
                first_grant_refusal = resolved.as_ref().err().cloned();
            }
            let attempt = (|| {
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
                // Once admission closes, retain capability and grant reasons but
                // never enter another policy or per-call approval check.
                if deadline_stopped {
                    return Err(SkipReason::Deadline);
                }
                self.chain_checks(engine.store(), &connection, &action, now_ms)?;
                let (Some(backend), Some(prepared)) = (backend, prepared) else {
                    return Err(SkipReason::Unavailable);
                };

                // Check after policy/approval and cooldown, immediately before
                // allowance admission. This budgets attempt starts, not time
                // queued on the transport's per-connection send lock.
                if deadline_at_ms.saturating_sub((self.clock)())
                    < WEB_SEARCH_ATTEMPT_BOUND.as_millis() as i64
                {
                    deadline_stopped = true;
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
                self.limiter
                    .try_acquire(name, &caller_key, limits, now_ms)
                    .map_err(|retry| {
                        retry_after = Some(retry_after.map_or(retry, |old| old.min(retry)));
                        SkipReason::RateLimited
                    })?;

                let mut request = AuthorizationRequest::new(
                    caller,
                    &connection.connection_id,
                    provider.action,
                    prepared.vendor_args,
                )
                .without_per_call_approval();
                if let Some(agent_id) = &audit.agent_id {
                    request = request.with_attributed_agent(agent_id);
                }
                if let Some(scope) = &audit.scope {
                    request = request.with_scope_attribution_only(scope.clone());
                }
                if let Some(origin) = &audit.relay_origin {
                    request = request.with_relay_origin(origin.clone());
                }
                audit.principal = connection.principal.clone();
                audit.connection_id = Some(connection.connection_id.clone());
                audit.risk = Some(action.risk.clone());
                audit.severity = Some(action.severity.clone());
                audit.chain.as_mut().unwrap().attempted = Some(identity);
                // Connector-home ownership is mediated only by authorize, not
                // preflight, so its denial is this provider's unavailable reason.
                let reservation = engine.authorize(request).map_err(|denial| {
                    eprintln!(warn web_search: "web_search chain authorization refused on {} ({})", connection.connection_id, denial.reason_code());
                    SkipReason::for_refusal(&self.refusal_for_denial(caller, &denial))
                })?;
                let dispatched = engine.revalidate_and_dispatch(&reservation);
                // Revalidation refusals also report NotSent. Sent and
                // OutcomeUnknown may have reached the vendor, so they keep it.
                if dispatched.transmission != TransmissionState::NotSent {
                    hold.keep();
                } else {
                    drop(hold);
                }
                audit.dispatched = true;
                let results = match outcome::classify(
                    backend.as_ref(),
                    &dispatched,
                    outcome::QuotaSignal::Absent,
                    usize::from(prepared.query.max_results),
                    crate::storage::now_ms(),
                ) {
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
        if all_not_granted {
            return Err(first_grant_refusal.unwrap_or(WebSearchRefusal::NotGranted));
        }
        if !skipped.is_empty()
            && skipped
                .iter()
                .all(|skip| skip.reason == SkipReason::RateLimited)
        {
            return Err(WebSearchRefusal::RateLimited {
                retry_after_ms: retry_after.unwrap(),
            });
        }
        Err(WebSearchRefusal::WebSearchUnavailable {
            providers: skipped.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
