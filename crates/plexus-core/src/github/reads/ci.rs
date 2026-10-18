//! Reads of GitHub Actions data (job logs, artifact files, run status) for
//! automated flows. Flows are scheduled scripts run by the Basal module; a flow
//! acting for an agent sees only repositories bound to that agent's enabled bot.
//! Every GitHub request a read makes is authorized and quota-counted separately.
use super::*;

/// Reserve one authenticated GitHub request immediately before dispatch. Storage
/// HEAD/GET requests are credentialless and do not consume the operator token's quota.
fn reserve(store: &PlexusStore, now: i64) -> Result<(), ReadError> {
    match store
        .reserve_github_actions_flow_read_quota(now)
        .map_err(|_| ReadError::Denied(Denial::StoreFailure))?
    {
        crate::QuotaAdmission::Reserved { .. } => Ok(()),
        crate::QuotaAdmission::Deferred { retry_at_ms } => Err(ReadError::QuotaExhausted {
            retry_after_ms: retry_at_ms.saturating_sub(now),
        }),
        crate::QuotaAdmission::Inactive => Err(ReadError::Denied(Denial::StoreFailure)),
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

pub(super) fn invoke<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &str,
    action: &str,
    args: Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
) -> Result<Value, ReadError> {
    let visible = || check_repository_visibility(engine.store(), principal, repository, scope);
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
    // Quota or visibility can change during authorization. Retire the unused
    // reservation when either check stops the send, without consuming quota
    // for calls that fail authorization in the first place.
    if let Err(error) = visible().and_then(|()| reserve(engine.store(), crate::storage::now_ms())) {
        engine
            .store()
            .abandon_reservation(&reservation.principal, &reservation.reservation_id)
            .map_err(|_| ReadError::Denied(Denial::StoreFailure))?;
        return Err(error);
    }
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
    fn quota_deferral_invalidates_the_unused_authorization_reservation() {
        use crate::{CatalogActionInput, GrantInput};
        use std::sync::Arc;
        let scratch = crate::test_scratch::Scratch::database("ci-quota-reservation");
        let store = Arc::new(
            PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "ci-quota-reservation".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.path().to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let connection = crate::poller::GITHUB_ACTIONS_CONNECTION;
        store
            .insert_connection("direct", connection, "fixture", "pending", &json!({}))
            .unwrap();
        let ticket = store
            .create_binding_ticket_bounded(
                "direct",
                connection,
                "credential_reference",
                b"api_key:ci-token",
                &crate::Ceiling::unrestricted_for_tests(),
            )
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: connection.into(),
                principal: "direct".into(),
                name: "read".into(),
                title: None,
                schema: json!({}),
                schema_hash: "schema".into(),
                risk: "read".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        store
            .insert_grant(&GrantInput {
                grant_id: "read-grant".into(),
                principal: "direct".into(),
                connection_id: connection.into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["read".into()],
                authority_kind: crate::AUTHORITY_INVOKE.into(),
                expires_at: None,
            })
            .unwrap();
        let transport = Arc::new(crate::transport::MockTransport::default());
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                crate::credentials::StubCredentialSource::with_default_success(b"token".to_vec()),
            ),
            transport.clone(),
        );
        for _ in 0..600 {
            reserve(&store, crate::storage::now_ms()).unwrap();
        }
        assert!(matches!(
            invoke(&engine, "direct", "org/repo", "read", json!({}), None, None),
            Err(ReadError::QuotaExhausted { .. })
        ));
        let db = rusqlite::Connection::open(scratch.path()).unwrap();
        let mut query = db.prepare("SELECT status FROM reservations").unwrap();
        let statuses: Vec<String> = query
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(statuses, ["invalidated"]);
        assert!(transport.requests().is_empty());
    }

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
        for _ in 0..600 {
            store
                .reserve_github_actions_flow_read_quota(10_000)
                .unwrap();
        }
        assert_eq!(
            reserve(&store, 11_234),
            Err(ReadError::QuotaExhausted {
                retry_after_ms: 3_598_767
            })
        );
        assert_eq!(
            reserve(&store, 3_610_000),
            Err(ReadError::QuotaExhausted { retry_after_ms: 1 })
        );
        assert_eq!(reserve(&store, 3_610_001), Ok(()));
    }
}
