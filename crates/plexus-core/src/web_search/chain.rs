//! Ordered provider admission. Compatibility searches never enter this walk.

use super::*;

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

    pub(super) fn run_chain<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
        &self,
        engine: &GovernanceEngine<C, T>,
        order: &[String],
        query: &WebSearchQuery,
        now_ms: i64,
        audit: &mut CallAudit,
    ) -> Result<WebSearchResponse, WebSearchRefusal> {
        audit.chain = Some(ChainAudit::default());
        let caller = &audit.caller;
        let is_flow = audit
            .scope
            .as_ref()
            .is_some_and(|scope| scope.flow_id.is_some());
        let caller_key = CallerKey {
            principal: caller.clone(),
            agent_id: audit.agent_id.clone(),
        };
        let mut all_not_granted = true;
        let mut first_grant_refusal = None;
        let mut retry_after = None::<u64>;

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
                self.chain_checks(engine.store(), &connection, &action, now_ms)?;
                let (Some(backend), Some(prepared)) = (backend, prepared) else {
                    return Err(SkipReason::Unavailable);
                };

                // The chain deadline gate (6a), then allowance reservation (7),
                // are inserted here before limiter.try_acquire: an inadmissible
                // attempt must not spend the caller's or provider's rate budget.
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
                audit.dispatched = true;
                let body = match dispatched.outcome {
                    TransportOutcome::Completed {
                        response: Some(body),
                    } => body,
                    _ => return Err(SkipReason::Unavailable),
                };
                let results = backend
                    .map_reply(
                        &body,
                        usize::from(prepared.query.max_results),
                        crate::storage::now_ms(),
                    )
                    .map_err(|_| SkipReason::Unavailable)?;
                Ok(WebSearchResponse {
                    results,
                    backend: name.clone(),
                    cached: false,
                })
            })();
            match attempt {
                Ok(response) => {
                    audit.chain.as_mut().unwrap().served_by = Some(name.clone());
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
