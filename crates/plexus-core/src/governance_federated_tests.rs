use super::*;
use crate::credentials::StubCredentialSource;
use crate::federated::FederatedCaller;
use crate::storage::CatalogActionInput;
use crate::transport::MockTransport;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use serde_json::json;
use subc_protocol::scope::{FederatedAttributes, FederatedPeerClass};

type Engine = GovernanceEngine<StubCredentialSource, MockTransport>;

fn fixture() -> (Engine, rusqlite::Connection) {
    let path = crate::test_scratch::store_path();
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_request_id(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite { path: path.clone() },
        })
        .unwrap(),
    );
    super::tests::install_system_manifest(&store, "mock", "S1");
    store
        .insert_connection("direct", "connection", "mock", "active", &json!({}))
        .unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: "connection".into(),
            name: "write_item".into(),
            title: None,
            schema: json!({"type":"object","properties":{"repo":{"type":"string"}}}),
            schema_hash: "schema".into(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        "UPDATE connections SET ceiling_risk='write', ceiling_selectors='[\"write_item\"]';",
    )
    .unwrap();
    (
        GovernanceEngine::new(
            store,
            Arc::new(StubCredentialSource::default()),
            Arc::new(MockTransport::default()),
        ),
        db,
    )
}

fn request(claim: Option<Value>) -> AuthorizationRequest {
    let mut attributes = FederatedAttributes::new(
        FederatedPeerClass::Computer,
        "a".repeat(32),
        "pairing".into(),
        "Peer".into(),
    );
    attributes.remote_claim = claim.map(|claim| serde_json::from_value(claim).unwrap());
    AuthorizationRequest::new(
        "reserved:callosum",
        "connection",
        "write_item",
        json!({"repo":"o/r"}),
    )
    .with_federated_caller(FederatedCaller::from_attributes(attributes).unwrap())
}

fn assert_no_consent_or_dispatch(engine: &Engine, db: &rusqlite::Connection) {
    for table in [
        "action_requests",
        "reservations",
        "federated_rows",
        "federated_card_records",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    assert!(engine.transport().requests().is_empty());
    let missing_identity: i64 = db.query_row("SELECT count(*) FROM audit_journal WHERE acting_principal='reserved:callosum' AND (agent_id IS NOT NULL OR peer_fingerprint IS NULL OR pairing_id IS NULL OR peer_class IS NULL OR claim_kind IS NULL OR canonical_claim_identity IS NULL OR federated_row_id IS NOT NULL OR card_ref IS NOT NULL)", [], |row| row.get(0)).unwrap();
    assert_eq!(missing_identity, 0);
}

#[test]
fn kept_gates_refuse_before_consent_without_local_grants() {
    let cases = [
        ("UPDATE connections SET status='disabled'", "connection_disabled"),
        ("UPDATE connections SET status='revoked'", "connection_revoked"),
        ("UPDATE connections SET status='pending'", "connection_pending"),
        ("UPDATE connections SET health_state='{\"healthy_enough\":false}'", "connection_unhealthy"),
        ("UPDATE catalog_actions SET status='disabled'", "catalog_action_disabled"),
        ("UPDATE catalog_actions SET status='quarantined'", "catalog_action_quarantined"),
        ("DELETE FROM catalog_actions", "catalog_action_not_found"),
        ("UPDATE connections SET resource_filters='{\"required\":[\"other\"]}'", "resource_filter_missing"),
        ("UPDATE connections SET ceiling_selectors='[\"other\"]'", "grant_action_selector"),
        ("UPDATE catalog_actions SET risk='write'; UPDATE connections SET ceiling_risk='read', resource_filters='{\"write_enabling\":[\"repo\"]}'", "grant_risk_ceiling"),
        ("UPDATE connections SET ceiling_risk=NULL", "grant_risk_ceiling"),
        ("UPDATE connections SET ceiling_risk='not-a-risk'", "grant_risk_ceiling"),
    ];
    for (sql, expected) in cases {
        let (engine, db) = fixture();
        db.execute_batch(sql).unwrap();
        let denial = engine.authorize(request(None)).unwrap_err();
        assert_eq!(denial.reason_code(), expected, "{sql}: {denial:?}");
        assert_no_consent_or_dispatch(&engine, &db);
    }
    for (req, expected) in [
        (
            request(None).with_schema_hash("wrong"),
            "catalog_schema_mismatch",
        ),
        (
            {
                let mut req = request(None);
                req.args = json!({"extra":"not-reviewed"});
                req
            },
            "argument_undeclared",
        ),
    ] {
        let (engine, db) = fixture();
        assert_eq!(engine.authorize(req).unwrap_err().reason_code(), expected);
        assert_no_consent_or_dispatch(&engine, &db);
    }
}

#[test]
fn block_and_severity_never_ask_even_with_a_decision_plane() {
    for (risk, tier) in [
        ("destructive", "S1"),
        ("unknown", "S1"),
        ("write", "S3"),
        ("write", "S4"),
    ] {
        let (engine, db) = fixture();
        super::tests::install_system_manifest(engine.store(), "mock", tier);
        // Exercise a corrupt/future stored risk as well as today's constrained values.
        db.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        db.execute("UPDATE catalog_actions SET risk=?1", [risk])
            .unwrap();
        let engine =
            engine.with_decision_plane(Arc::new(crate::decision_plane::StubDecisionPlane::new()));
        let denial = engine.authorize(request(None)).unwrap_err();
        assert!(
            matches!(denial, Denial::NeedsDecisionPlane(_)),
            "{risk}/{tier}: {denial:?}"
        );
        assert_eq!(denial.reason_code(), "needs_decision_plane");
        engine
            .store()
            .set_policy("direct", "connection", "*", "block", None)
            .unwrap();
        assert_eq!(
            engine.authorize(request(None)),
            Err(Denial::Policy(PolicyDenial::Blocked))
        );
        assert_no_consent_or_dispatch(&engine, &db);
    }
}

#[test]
fn direct_namespace_policy_and_claimless_audit_need_no_grant_tables() {
    let (engine, db) = fixture();
    engine
        .store()
        .insert_connection(
            "reserved:callosum",
            "callosum-only",
            "mock",
            "active",
            &json!({}),
        )
        .unwrap();
    engine
        .store()
        .set_policy("reserved:callosum", "connection", "*", "block", None)
        .unwrap();
    db.execute_batch("DROP TABLE grants;").unwrap();
    assert_eq!(
        engine.authorize(request(None)).unwrap_err().reason_code(),
        "consent_unavailable"
    );
    let mut missing = request(None);
    missing.connection_id = "callosum-only".into();
    assert_eq!(
        engine.authorize(missing).unwrap_err().reason_code(),
        "connection_not_found"
    );
    engine
        .store()
        .set_policy("direct", "connection", "*", "block", None)
        .unwrap();
    assert_eq!(
        engine.authorize(request(None)),
        Err(Denial::Policy(PolicyDenial::Blocked))
    );
    let mut stmt = db.prepare("SELECT agent_id,peer_fingerprint,pairing_id,peer_class,claim_kind,canonical_claim_identity,federated_row_id,card_ref FROM audit_journal").unwrap();
    let rows: Vec<Vec<Option<String>>> = stmt
        .query_map([], |row| (0..8).map(|column| row.get(column)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(
            row,
            vec![
                None,
                Some("a".repeat(32)),
                Some("pairing".into()),
                Some("computer".into()),
                Some("".into()),
                Some("".into()),
                None,
                None
            ]
        );
    }
    assert_no_consent_or_dispatch(&engine, &db);
}

#[test]
fn local_agent_identity_never_selects_federated_authority_or_recipients() {
    let (engine, db) = fixture();
    let manifest = engine
        .store()
        .parsed_manifest(crate::storage::CATALOG_PRINCIPAL, "mock")
        .unwrap()
        .unwrap()
        .unwrap();
    let mut manifest = serde_json::to_value(manifest.as_ref()).unwrap();
    manifest["actions_baseline"][0]["recipients"] = json!(["/repo"]);
    engine
        .store()
        .upsert_manifest(
            crate::storage::CATALOG_PRINCIPAL,
            &crate::ingest_value(manifest).unwrap(),
        )
        .unwrap();
    engine
        .store()
        .set_policy("direct", "connection", "*", "allow", None)
        .unwrap();
    db.execute_batch("INSERT INTO recipient_allowlist(principal,connection_id,agent_id,recipient) VALUES ('direct','connection','agent-a','o/r'); ALTER TABLE recipient_allowlist RENAME TO local_lists_not_for_federation;").unwrap();
    let mut req = request(Some(json!({"kind":"agent","agent_id":"agent-a"})));
    req.attributed_agent_id = Some("agent-a".into());
    req = req.with_scope(CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "head".into(),
        scope_epoch: 1,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: Some("agent-a".into()),
        flow_id: None,
        delegates: true,
        owner_authorized: true,
    });
    engine
        .store()
        .insert_grant(&crate::storage::GrantInput {
            grant_id: "legacy".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: format!("fed-computer:{}", "a".repeat(32)),
            risk_ceiling: "write".into(),
            action_selectors: vec!["*".into()],
            authority_kind: AUTHORITY_INVOKE.into(),
            expires_at: None,
        })
        .unwrap();
    let connection = engine
        .store()
        .connection("direct", "connection")
        .unwrap()
        .unwrap();
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    let authority = engine
        .evaluate_authority(&req, &connection, &action, engine.now_ms())
        .unwrap();
    assert!(authority.grant.is_none());
    assert!(authority.agent_grant_pin.is_none());
    assert!(authority.policy_inputs.is_none());
    assert_eq!(authority.policy_effect, "allow");
    assert_eq!(
        engine.authorize(req).unwrap_err().reason_code(),
        "consent_unavailable"
    );
    let row: (Option<String>, String, String) = db
        .query_row(
            "SELECT agent_id,claim_kind,canonical_claim_identity FROM audit_journal WHERE acting_principal='reserved:callosum'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (None, "agent".into(), "{\"agent_id\":\"agent-a\"}".into())
    );
    assert_no_consent_or_dispatch(&engine, &db);
}

#[test]
fn local_audit_keeps_federated_identity_columns_null() {
    let (engine, db) = fixture();
    assert_eq!(
        engine
            .authorize(AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                json!({})
            ))
            .unwrap_err()
            .reason_code(),
        "grant_missing"
    );
    let null_columns: bool = db.query_row("SELECT peer_fingerprint IS NULL AND pairing_id IS NULL AND peer_class IS NULL AND claim_kind IS NULL AND canonical_claim_identity IS NULL AND federated_row_id IS NULL AND card_ref IS NULL FROM audit_journal", [], |row| row.get(0)).unwrap();
    assert!(null_columns);
}

#[test]
fn connector_home_refuses_before_consent() {
    let (engine, db) = fixture();
    let engine = engine.with_connector_home_guard(Arc::new(|| {
        Some(json!({"error":{"code":"connector_home_not_held","message":"not home"}}))
    }));
    assert_eq!(
        engine.authorize(request(None)).unwrap_err().reason_code(),
        "connector_home_not_held"
    );
    assert_no_consent_or_dispatch(&engine, &db);
}
