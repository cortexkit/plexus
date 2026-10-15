//! CI reads restrict agent-stamped Basal flows to repositories
//! bound to that agent's enabled bot, and authorize every API request independently.
use super::*;

/// Reserve the entire read before its first dispatch, without refunding unused
/// legs. Only authenticated GitHub API requests consume the token's quota;
/// credentialless storage HEAD/GET requests do not use the operator token.
pub(super) struct ReadQuota {
    requests: u16,
    reserved: bool,
}

impl ReadQuota {
    pub(super) fn new(requests: u16) -> Self {
        Self {
            requests,
            reserved: false,
        }
    }

    fn reserve(&mut self, store: &PlexusStore) -> Result<(), ReadError> {
        self.reserve_at(store, crate::storage::now_ms())
    }

    fn reserve_at(&mut self, store: &PlexusStore, now: i64) -> Result<(), ReadError> {
        if !self.reserved {
            match store
                .reserve_github_actions_flow_read_quota(self.requests, now)
                .map_err(|_| ReadError::Denied(Denial::StoreFailure))?
            {
                crate::QuotaAdmission::Reserved { .. } => self.reserved = true,
                crate::QuotaAdmission::Deferred { retry_at_ms } => {
                    return Err(ReadError::QuotaExhausted {
                        retry_after_ms: retry_at_ms.saturating_sub(now),
                    });
                }
                crate::QuotaAdmission::Inactive => {
                    return Err(ReadError::Denied(Denial::StoreFailure))
                }
            }
        }
        Ok(())
    }
}

pub(super) fn repository(value: &Value, invalid: &'static str) -> Result<String, ReadError> {
    let name = value.as_str().ok_or(ReadError::Refused(invalid))?;
    let name = crate::github::canonical_repository(name);
    name.split_once('/')
        .filter(|(owner, repo)| {
            !owner.is_empty()
                && !repo.is_empty()
                && !repo.contains('/')
                && [*owner, *repo].iter().all(|part| {
                    part.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                })
                && !matches!(*repo, "." | "..")
        })
        .ok_or(ReadError::Refused(invalid))?;
    Ok(name)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn invoke<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &str,
    action: &str,
    args: Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
    quota: &mut ReadQuota,
) -> Result<Value, ReadError> {
    let visible = || -> Result<(), ReadError> {
        if let Some(agent) = crate::scope::basal_flow_read_agent(principal, scope) {
            let handle = engine
                .store()
                .github_handle_for_repo(repository)
                .map_err(|_| ReadError::Denied(Denial::StoreFailure))?;
            if !handle.is_some_and(|handle| handle.agent_id == agent && handle.status == "enabled")
            {
                return Err(ReadError::Refused("repository_not_visible"));
            }
        }
        Ok(())
    };
    visible()?;
    let mut request = AuthorizationRequest::new(
        principal,
        crate::poller::GITHUB_ACTIONS_CONNECTION,
        action,
        args,
    )
    .with_diagnostic_tool("github");
    if let Some(scope) = scope {
        request = request.with_scope_attribution_only(scope.clone());
    }
    if let Some(agent) = attributed_agent {
        request = request.with_attributed_agent(agent);
    }
    let reservation = engine.authorize(request).map_err(ReadError::Denied)?;
    // Bindings can change during authorization; recheck before sending each leg.
    visible()?;
    quota.reserve(engine.store())?;
    match engine.revalidate_and_dispatch(&reservation).outcome {
        TransportOutcome::Completed {
            response: Some(value),
        } => Ok(value),
        other => Err(ReadError::Dispatch(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_retry_uses_the_pollers_exact_expiry() {
        let store = PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "ci-read-quota".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        store
            .reserve_github_actions_flow_read_quota(600, 10_000)
            .unwrap();
        for count in [2, 101, 2] {
            let mut quota = ReadQuota::new(count);
            assert_eq!(
                quota.reserve_at(&store, 11_234),
                Err(ReadError::QuotaExhausted {
                    retry_after_ms: 3_598_767
                })
            );
            assert_eq!(
                quota.reserve_at(&store, 3_610_000),
                Err(ReadError::QuotaExhausted { retry_after_ms: 1 })
            );
        }
        assert_eq!(ReadQuota::new(2).reserve_at(&store, 3_610_001), Ok(()));
    }
}
