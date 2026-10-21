use std::sync::Arc;

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::credentials::StubCredentialSource;
use plexus_core::governance::{
    compare_authority_baseline, facade_not_sent, pipeline_denial, AuthorityBaseline,
    AuthorizationRequest, CatalogDenial, Denial, FacadeNotSentCode, GovernanceEngine,
    GovernanceSeams, GrantDenial, PolicyDenial, RequestOrigin, ResolverDenial,
};
use plexus_core::storage::{CatalogAction, CatalogActionInput, GrantInput, PlexusStore};
use plexus_core::transport::MockTransport;

fn baseline() -> AuthorityBaseline {
    AuthorityBaseline {
        app_handle_generation: 1,
        repo_binding_generation: 1,
        credential_generation: 1,
        handle_enabled: true,
        agent_grant_generation: 1,
        module_grant_generation: 1,
        policy_effect_hash: "allow".into(),
    }
}

#[test]
fn authority_precedence_reports_first_of_two_moved_dimensions() {
    let old = baseline();
    let mut current = old.clone();
    current.agent_grant_generation += 1;
    current.credential_generation += 1;
    assert_eq!(
        compare_authority_baseline(&old, &current),
        Err("agent_grant_revoked")
    );
    current.handle_enabled = false;
    assert_eq!(
        compare_authority_baseline(&old, &current),
        Err("handle_disabled")
    );
    assert_eq!(compare_authority_baseline(&old, &old), Ok(()));
}

#[test]
fn every_baseline_dimension_has_its_named_refusal() {
    let old = baseline();
    let mut cases = Vec::new();
    let mut moved = old.clone();
    moved.repo_binding_generation += 1;
    cases.push((moved, "repository_rebound"));
    let mut moved = old.clone();
    moved.agent_grant_generation += 1;
    cases.push((moved, "agent_grant_revoked"));
    let mut moved = old.clone();
    moved.module_grant_generation += 1;
    cases.push((moved, "module_grant_revoked"));
    let mut moved = old.clone();
    moved.policy_effect_hash = "block".into();
    cases.push((moved, "policy_changed"));
    let mut moved = old.clone();
    moved.credential_generation += 1;
    cases.push((moved, "credential_rotated"));
    let mut moved = old.clone();
    moved.app_handle_generation += 1;
    cases.push((moved, "handle_row_changed"));
    for (current, expected) in cases {
        assert_eq!(compare_authority_baseline(&old, &current), Err(expected));
    }
}

#[test]
fn transport_not_sent_codes_have_distinct_refusals() {
    for (code, expected) in [
        (
            "aborted_stale_authorization",
            "stale_authority{authorization_snapshot_stale}",
        ),
        (
            "grant_hash_mismatch",
            "stale_authority{grant_hash_mismatch}",
        ),
        (
            "reservation_expired",
            "stale_authority{reservation_expired}",
        ),
        ("credential_missing", "handle_credential_unresolvable"),
    ] {
        assert_eq!(facade_not_sent(code), Some(expected));
    }
    for code in [
        FacadeNotSentCode::AbortedStaleAuthorization,
        FacadeNotSentCode::GrantHashMismatch,
        FacadeNotSentCode::ReservationExpired,
        FacadeNotSentCode::CredentialMissing,
    ] {
        assert_eq!(facade_not_sent(code.transport_code()), Some(code.refusal()));
    }
    assert_eq!(facade_not_sent("stale_authorization"), None);
}

#[test]
fn pipeline_denials_preserve_inner_variant_names() {
    for (denial, name) in [
        (Denial::Grant(GrantDenial::Missing), "Grant(Missing)"),
        (Denial::Grant(GrantDenial::Expired), "Grant(Expired)"),
        (
            Denial::Grant(GrantDenial::ActionSelector),
            "Grant(ActionSelector)",
        ),
        (
            Denial::Grant(GrantDenial::RiskCeiling),
            "Grant(RiskCeiling)",
        ),
        (Denial::Policy(PolicyDenial::Blocked), "Policy(Blocked)"),
        (
            Denial::Policy(PolicyDenial::ApprovalMissing),
            "Policy(ApprovalMissing)",
        ),
        (
            Denial::Policy(PolicyDenial::ApprovalExpired),
            "Policy(ApprovalExpired)",
        ),
        (
            Denial::Policy(PolicyDenial::ApprovalShapeMismatch),
            "Policy(ApprovalShapeMismatch)",
        ),
        (
            Denial::Policy(PolicyDenial::ApprovalConsumed),
            "Policy(ApprovalConsumed)",
        ),
        (
            Denial::Policy(PolicyDenial::ApprovalAlreadyDecided),
            "Policy(ApprovalAlreadyDecided)",
        ),
        (
            Denial::ActionRequestCreated {
                request_id: "r".into(),
            },
            "ActionRequestCreated",
        ),
        (
            Denial::Catalog(CatalogDenial::NotFound),
            "Catalog(NotFound)",
        ),
        (
            Denial::Catalog(CatalogDenial::SchemaMismatch),
            "Catalog(SchemaMismatch)",
        ),
        (
            Denial::Resolver(ResolverDenial::RepositoryUnbound),
            "Resolver(RepositoryUnbound)",
        ),
        (Denial::StoreFailure, "StoreFailure"),
    ] {
        assert_eq!(
            pipeline_denial(&denial, "G8"),
            format!("pipeline_denied{{gate: G8, denial: {name}}}")
        );
    }
}

struct TestSeams {
    reject_repository: bool,
}
impl GovernanceSeams for TestSeams {
    fn resolve_invoke(&self, request: &AuthorizationRequest) -> Result<(), ResolverDenial> {
        if request.args.get("repositories").is_some() {
            return Err(ResolverDenial::RequestFieldForbidden {
                field: "repositories".into(),
            });
        }
        if self.reject_repository {
            Err(ResolverDenial::RepositoryUnbound)
        } else {
            Ok(())
        }
    }
    fn facade_only(&self, action: &CatalogAction) -> bool {
        action.name == "write_item"
    }
}

fn engine(
    reject_repository: bool,
) -> (
    plexus_core::test_scratch::Scratch,
    GovernanceEngine<StubCredentialSource, MockTransport>,
) {
    let scratch = plexus_core::test_scratch::Scratch::database("governance-seams");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: scratch.path().to_string_lossy().into_owned(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
    store
        .insert_connection(
            "direct",
            "connection",
            "mock",
            "active",
            &serde_json::json!({}),
        )
        .unwrap();
    let schema = serde_json::json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".into(),
            principal: "direct".into(),
            name: "write_item".into(),
            title: None,
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
            risk: "write".into(),
            severity: "S2".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_grant(&GrantInput {
            grant_id: "other-invoke".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "other".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["write_item".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    (
        scratch,
        GovernanceEngine::new(
            store,
            Arc::new(StubCredentialSource::default()),
            Arc::new(MockTransport::default()),
        )
        .with_governance_seams(Arc::new(TestSeams { reject_repository })),
    )
}

/// Caller-supplied origin fields and agent identity cannot make an ordinary
/// request pass as a facade-originated one: each combination is refused with no
/// reservation and no transport request. The accepting side is
/// `private_facade_origin_passes_catalog_fence` in src/governance.rs, since only
/// that crate can construct a facade origin.
#[test]
fn ordinary_origin_cannot_be_promoted_by_caller_fields() {
    let (scratch, engine) = engine(false);
    for principal in ["direct", "other"] {
        for args in [
            serde_json::json!({}),
            serde_json::json!({"origin":"Facade"}),
        ] {
            for asserted in [false, true] {
                let mut request =
                    AuthorizationRequest::new(principal, "connection", "write_item", args.clone());
                if asserted {
                    request = request.with_bound_agent("agent", "handle");
                }
                assert_eq!(request.origin(), RequestOrigin::Ordinary);
                assert_eq!(
                    engine.authorize(request),
                    Err(Denial::BotActionRequiresFacade)
                );
            }
        }
    }
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let reservations: i64 = db
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reservations, 0);
    assert!(engine.transport().requests().is_empty());
    assert!(engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .all(|row| row.reason_code == "bot_action_requires_facade"
            && row.agent_id.is_none()
            && row.agent_handle.is_none()));
}

#[test]
fn resolver_refuses_before_connection_or_grant_lookup() {
    let (scratch, engine) = engine(true);
    let request =
        AuthorizationRequest::new("direct", "nonexistent", "write_item", serde_json::json!({}))
            .with_bound_agent("unverified", "caller-handle");
    assert_eq!(
        engine.authorize(request),
        Err(Denial::Resolver(ResolverDenial::RepositoryUnbound))
    );
    let rows = engine.store().list_audit("direct").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gate.as_deref(), Some("resolver"));
    assert!(rows[0].agent_id.is_none() && rows[0].agent_handle.is_none());
    assert!(rows[0].connection_id.is_none());
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let reservations: i64 = db
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reservations, 0);
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn resolver_rejects_second_repository_field_before_connection_load() {
    let (_scratch, engine) = engine(false);
    let request = AuthorizationRequest::new(
        "direct",
        "nonexistent",
        "write_item",
        serde_json::json!({"repositories":["o/r", "another/repo"]}),
    );
    assert_eq!(
        engine.authorize(request),
        Err(Denial::Resolver(ResolverDenial::RequestFieldForbidden {
            field: "repositories".into()
        }))
    );
    let rows = engine.store().list_audit("direct").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gate.as_deref(), Some("resolver"));
    assert!(rows[0].connection_id.is_none());
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn agent_grants_never_cross_module_selector() {
    use plexus_core::governance::{grant_key_matches, AgentGrantKey};
    let module = AgentGrantKey {
        connection_id: "c",
        principal: plexus_core::github::AFT_PRINCIPAL,
        agent_id: None,
    };
    let agent = AgentGrantKey {
        connection_id: "c",
        principal: plexus_core::github::AFT_PRINCIPAL,
        agent_id: Some("a"),
    };
    let other = AgentGrantKey {
        connection_id: "c",
        principal: plexus_core::github::AFT_PRINCIPAL,
        agent_id: Some("b"),
    };
    assert!(grant_key_matches(&module, &module));
    assert!(grant_key_matches(&agent, &agent));
    assert!(!grant_key_matches(&module, &agent));
    assert!(!grant_key_matches(&agent, &module));
    assert!(!grant_key_matches(&agent, &other));
    // A module row belongs to its grantee module; an agent row is the agent's
    // authority whichever module carries its assertion.
    let prefrontal_module = AgentGrantKey {
        principal: plexus_core::github::PREFRONTAL_PRINCIPAL,
        ..module.clone()
    };
    let prefrontal_agent = AgentGrantKey {
        principal: plexus_core::github::PREFRONTAL_PRINCIPAL,
        ..agent.clone()
    };
    assert!(!grant_key_matches(&module, &prefrontal_module));
    assert!(grant_key_matches(&agent, &prefrontal_agent));
    assert!(!grant_key_matches(&agent, &prefrontal_module));
    assert!(!grant_key_matches(&module, &prefrontal_agent));
}

#[test]
fn policy_matrix_preserves_stricter_module_or_agent_effect() {
    use plexus_core::governance::compose_policy_effect;
    for (module, agent, expected) in [
        ("allow", None, "allow"),
        ("allow", Some("allow"), "allow"),
        ("allow", Some("ask_first"), "ask_first"),
        ("allow", Some("block"), "block"),
        ("ask_first", Some("allow"), "ask_first"),
        ("ask_first", Some("block"), "block"),
        ("block", Some("allow"), "block"),
        ("block", Some("ask_first"), "block"),
    ] {
        assert_eq!(compose_policy_effect(module, agent), expected);
    }
}
