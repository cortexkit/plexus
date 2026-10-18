use std::sync::Arc;

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    AuthorizationRequest, CatalogActionInput, GovernanceEngine, GrantInput, MockResponse,
    MockTransport, PlexusStore, PolicyInput, Scheduler, StubCredentialSource, TransportOutcome,
};
use serde_json::{json, Value};

type Engine = GovernanceEngine<StubCredentialSource, MockTransport>;

struct Fixture {
    engine: Engine,
    // Removing the store's directory on drop is the `Scratch` guard's own job,
    // which is why this fixture no longer has a `Drop` of its own. The hand
    // written one unlinked the `.db` by name and left the write-ahead-log pair
    // next to it.
    path: Scratch,
}

fn fixture(class: bool) -> Fixture {
    let path = Scratch::database("write-recon");
    let store = PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: path.to_string_lossy().into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into(),
        },
    })
    .unwrap();
    store
        .insert_connection(
            "direct",
            "conn",
            "mock",
            "pending",
            &json!({"required":["title"],"write_enabling":["title"]}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", "conn", b"test:binding")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    for (name, risk) in [("create", "write"), ("search", "read")] {
        store.upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(), connection_id: "conn".into(), name: name.into(), title: None,
            schema: json!({"type":"object"}), schema_hash: plexus_core::jcs_sha256(&json!({"type":"object"})).unwrap(),
            risk: risk.into(), severity: if risk == "read" { "S1" } else { "S2" }.into(), ask_first: false,
            status: "active".into(), quarantine_reason: None,
            reconciliation: (class && name == "create").then(|| json!({"correlation_fields":["title"],"read_back_action":"search","timeout_s":120})),
        }).unwrap();
        store
            .insert_policy(&PolicyInput {
                principal: "direct".into(),
                policy_id: name.into(),
                connection_id: "conn".into(),
                action_selector: name.into(),
                effect: "allow".into(),
                expires_at: None,
            })
            .unwrap();
    }
    store.insert_grant(&grant("owner", "direct")).unwrap();
    crate::system_manifest::install_system_manifest(&store, "mock", "S1");
    let credentials = StubCredentialSource::default();
    credentials.set_success(b"test:binding", b"vendor-key".to_vec(), None, 1);
    Fixture {
        engine: GovernanceEngine::new(
            Arc::new(store),
            Arc::new(credentials),
            Arc::new(MockTransport::default()),
        ),
        path,
    }
}

fn grant(id: &str, grantee: &str) -> GrantInput {
    GrantInput {
        grant_id: id.into(),
        principal: "direct".into(),
        connection_id: "conn".into(),
        grantee_principal: grantee.into(),
        risk_ceiling: "write".into(),
        action_selectors: vec!["*".into()],
        authority_kind: "invoke".into(),
        expires_at: None,
    }
}

fn dispatch(f: &Fixture, principal: &str, response: MockResponse) -> plexus_core::DispatchOutcome {
    f.engine.transport().set_response(response);
    let reservation = f
        .engine
        .authorize(AuthorizationRequest::new(
            principal,
            "conn",
            "create",
            json!({"title":"unique"}),
        ))
        .unwrap();
    assert!(
        reservation.intent_id.is_none(),
        "fixture exercises effective S2 without action_requests"
    );
    f.engine.revalidate_and_dispatch(&reservation)
}
fn db(f: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(&f.path).unwrap()
}
fn pending(f: &Fixture) -> i64 {
    db(f)
        .query_row(
            "SELECT count(*) FROM pending_write_reconciliations",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn tick(f: &Fixture) {
    Scheduler::new(
        f.engine.clone(),
        30 * plexus_core::storage::AUDIT_MILLIS_PER_DAY,
    )
    .run_pass(&[], plexus_core::storage::now_ms());
}
fn status(f: &Fixture) -> (String, Option<String>) {
    let rows = f
        .engine
        .store()
        .list_write_reconciliations("direct")
        .unwrap()
        .0;
    assert_eq!(rows.len(), 1);
    (rows[0].status.clone(), rows[0].reason.clone())
}
fn assert_settled(f: &Fixture, expected: &str, calls: usize) {
    assert_eq!(status(f).0, expected);
    assert_eq!(pending(f), 0, "terminal results remove arguments");
    tick(f);
    assert_eq!(
        f.engine.transport().requests().len(),
        calls,
        "terminal record is never swept again"
    );
}

#[test]
fn unknown_write_persists_pending() {
    let f = fixture(true);
    let outcome = dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    assert_eq!(outcome.outcome, TransportOutcome::OutcomeUnknown);
    assert_eq!(pending(&f), 1);
    assert_eq!(outcome.reconciliation.unwrap().status, "pending");
    let encoded: String = db(&f)
        .query_row(
            "SELECT record_json FROM pending_write_reconciliations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let record: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(record["args"], json!({"title":"unique"}));
    assert_eq!(record["acting_principal"], "direct");
}

#[test]
fn unknown_without_class_is_unreconcilable() {
    let f = fixture(false);
    let outcome = dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    assert_eq!(pending(&f), 0);
    assert_eq!(outcome.reconciliation.unwrap().status, "unreconcilable");
    assert_settled(&f, "unreconcilable", 1);
}

#[test]
fn completed_write_has_no_pending_record() {
    let f = fixture(true);
    let outcome = dispatch(&f, "direct", MockResponse::Success(json!({})));
    assert!(outcome.reconciliation.is_none());
    assert_eq!(pending(&f), 0);
    assert!(f
        .engine
        .store()
        .list_write_reconciliations("direct")
        .unwrap()
        .0
        .is_empty());
}

#[test]
fn fresh_record_runs_on_next_tick_and_confirms() {
    let f = fixture(true);
    dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    f.engine
        .transport()
        .set_response(MockResponse::Success(json!({"title":"unique"})));
    tick(&f);
    assert_settled(&f, "confirmed", 2);
    let requests = f.engine.transport().requests();
    assert_eq!(requests[0].action, "create");
    assert_eq!(requests[1].action, "search");
    assert_eq!(requests[1].args, json!({"title":"unique"}));
}

#[test]
fn over_age_record_timeout_exceeded_without_read_back() {
    let f = fixture(true);
    dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    db(&f).execute("UPDATE pending_write_reconciliations SET record_json=json_set(record_json,'$.occurred_at_ms',?1)", [plexus_core::storage::now_ms() - 121_000]).unwrap();
    tick(&f);
    assert_eq!(
        status(&f),
        ("ambiguous".into(), Some("timeout_exceeded".into()))
    );
    assert_settled(&f, "ambiguous", 1);
}

#[test]
fn not_found_and_ambiguous_are_terminal() {
    for (response, expected) in [
        (json!([{"title":"different"}]), "not_found"),
        (json!([{"title":"unique"},{"title":"unique"}]), "ambiguous"),
    ] {
        let f = fixture(true);
        dispatch(&f, "direct", MockResponse::OutcomeUnknown);
        f.engine
            .transport()
            .set_response(MockResponse::Success(response));
        tick(&f);
        assert_settled(&f, expected, 2);
    }
}

#[test]
fn revoked_connection_denied_without_read_back() {
    let f = fixture(true);
    dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    f.engine
        .store()
        .revoke_connection("direct", "conn")
        .unwrap();
    tick(&f);
    assert_settled(&f, "denied", 1);
}

#[test]
fn delegated_caller_revoked_grant_denied_without_read_back() {
    let f = fixture(true);
    f.engine
        .store()
        .insert_grant(&grant("delegate", "delegate"))
        .unwrap();
    dispatch(&f, "delegate", MockResponse::OutcomeUnknown);
    f.engine.store().revoke_grant("direct", "delegate").unwrap();
    tick(&f);
    assert_settled(&f, "denied", 1);
    let audit = f.engine.store().list_audit("direct").unwrap();
    let row = audit
        .iter()
        .find(|row| row.gate.as_deref() == Some("reconciliation"))
        .unwrap();
    assert_eq!(row.principal, "direct");
    assert_eq!(row.acting_principal, "delegate");
    assert_eq!(
        f.engine
            .store()
            .list_write_reconciliations("delegate")
            .unwrap()
            .0[0]
            .status,
        "denied"
    );
    assert!(f
        .engine
        .store()
        .list_write_reconciliations("stranger")
        .unwrap()
        .0
        .is_empty());
}

#[test]
fn read_only_refusals_are_terminal() {
    for self_target in [false, true] {
        let f = fixture(true);
        dispatch(&f, "direct", MockResponse::OutcomeUnknown);
        if self_target {
            db(&f).execute("UPDATE catalog_actions SET reconciliation_json=json_set(reconciliation_json,'$.read_back_action','create') WHERE name='create'", []).unwrap();
        } else {
            db(&f)
                .execute(
                    "UPDATE catalog_actions SET risk='write' WHERE name='search'",
                    [],
                )
                .unwrap();
        }
        tick(&f);
        assert_eq!(
            status(&f).1.as_deref(),
            Some(if self_target {
                "reconciliation_self_target"
            } else {
                "reconciliation_target_not_read"
            })
        );
        assert_settled(&f, "denied", 1);
    }
}

#[test]
fn persistence_screens_secret_arguments() {
    let f = fixture(true);
    let record = plexus_core::OutcomeUnknownRecord {
        request_id: "screen".into(),
        principal: "direct".into(),
        acting_principal: "direct".into(),
        actor: "direct".into(),
        connection_id: "conn".into(),
        action: "create".into(),
        args: json!({"nested":[{"access_token":"canary"}]}),
        occurred_at_ms: plexus_core::storage::now_ms(),
    };
    assert!(f
        .engine
        .store()
        .enqueue_write_reconciliation(&record, None)
        .unwrap_err()
        .to_string()
        .contains("secret_input_rejected"));
    assert_eq!(pending(&f), 0);
}

#[test]
fn retention_expires_pending_arguments_without_dispatch() {
    let f = fixture(true);
    dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    db(&f)
        .execute(
            "UPDATE pending_write_reconciliations SET expires_at_ms=0",
            [],
        )
        .unwrap();
    tick(&f);
    assert_eq!(status(&f).1.as_deref(), Some("retention_expired"));
    assert_settled(&f, "ambiguous", 1);
}

#[test]
fn caller_connection_id_collision_is_denied_without_read_back() {
    let f = fixture(true);
    let store = f.engine.store();
    store.insert_grant(&grant("delegate", "delegate")).unwrap();
    dispatch(&f, "delegate", MockResponse::OutcomeUnknown);
    store
        .insert_connection("delegate", "conn", "mock", "pending", &json!({}))
        .unwrap();
    let ticket = store
        .create_binding_ticket("delegate", "conn", b"test:binding")
        .unwrap();
    store
        .connect_with_ticket("delegate", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let mut own_grant = grant("own", "delegate");
    own_grant.principal = "delegate".into();
    store.insert_grant(&own_grant).unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "delegate".into(),
            connection_id: "conn".into(),
            name: "search".into(),
            title: None,
            schema: json!({"type":"object"}),
            schema_hash: plexus_core::jcs_sha256(&json!({"type":"object"})).unwrap(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_policy(&PolicyInput {
            principal: "delegate".into(),
            policy_id: "read".into(),
            connection_id: "conn".into(),
            action_selector: "search".into(),
            effect: "allow".into(),
            expires_at: None,
        })
        .unwrap();
    tick(&f);
    assert_eq!(
        status(&f).1.as_deref(),
        Some("reconciliation_owner_changed")
    );
    assert_settled(&f, "denied", 1);
}

fn discovery_manifest() -> Value {
    json!({
        "schema_version": 1, "key": "mock", "name": "Mock",
        "description": "Write reconciliation discovery fixture",
        "reuse_path": "mcp_direct", "reuse_rationale": "Integration fixture",
        "tier": "S2",
        "transport": {"kind": "rest_api", "url": "https://example.com"},
        "auth": {"mode": "none"}, "credential_bindings": [],
        "resource_filters": {"required": ["title"], "optional": [], "write_enabling": ["title"]},
        "actions_baseline": [
            {"name": "create", "risk": "write",
             "reconciliation": {"correlation_fields": ["title"], "read_back_action": "search", "timeout_s": 120},
             "http": {"method": "POST", "path": "/items", "args_schema": {"type": "object"}}},
            {"name": "search", "risk": "read",
             "http": {"method": "GET", "path": "/items", "args_schema": {"type": "object"}}},
            {"name": "run_sql", "risk": "write",
             "http": {"method": "POST", "path": "/sql", "args_schema": {"type": "object"}}}
        ],
        "defaults": {"ask_first_risk": ["write", "destructive"], "rate_limit": {"calls_per_min": 100}},
        "availability": "ga"
    })
}

fn install_discovery_manifest(f: &Fixture, manifest: Value) {
    let ingested = plexus_core::manifest::ingest_value(manifest).unwrap();
    f.engine
        .store()
        .upsert_manifest("system", &ingested)
        .unwrap();
}

fn discover(f: &Fixture) {
    // REST's ordinary discovery synthesizes tools from the reviewed manifest;
    // dispatch stays mocked so an uncertain vendor write is deterministic.
    let reconciler = plexus_core::catalog::CatalogReconciler::new(
        f.engine.store().clone(),
        Arc::new(plexus_core::mcp_remote::McpRemoteTransport::default()),
        plexus_core::catalog::CatalogRefreshPolicy::default(),
    );
    let actions = reconciler
        .discover_for_connection("direct", "conn", &StubCredentialSource::default(), None)
        .unwrap();
    assert_eq!(actions.len(), 3);
}

#[test]
fn discovery_preserves_declared_class_and_unknown_write_enqueues() {
    let f = fixture(false);
    let manifest = discovery_manifest();
    let expected = manifest["actions_baseline"][0]["reconciliation"].clone();
    // This case tests initial seeding from a reviewed manifest. Repeat seeding
    // must not overwrite existing schema/quarantine/read-back review decisions,
    // so begin with an empty catalog before installing those declarations.
    db(&f).execute_batch("DELETE FROM catalog_actions").unwrap();
    install_discovery_manifest(&f, manifest);
    assert_eq!(
        f.engine
            .store()
            .seed_catalog_from_manifest("direct", "conn", "mock")
            .unwrap(),
        0
    );
    assert_eq!(
        f.engine
            .store()
            .catalog_action("direct", "conn", "create")
            .unwrap()
            .unwrap()
            .reconciliation,
        Some(expected.clone())
    );

    discover(&f);
    assert_eq!(
        f.engine
            .store()
            .catalog_action("direct", "conn", "create")
            .unwrap()
            .unwrap()
            .reconciliation,
        Some(expected)
    );
    assert!(
        f.engine
            .store()
            .catalog_action("direct", "conn", "run_sql")
            .unwrap()
            .unwrap()
            .reconciliation
            .is_none(),
        "a write without a declared read-back must not inherit a neighbour's reconciliation class"
    );
    let outcome = dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    assert_eq!(outcome.outcome, TransportOutcome::OutcomeUnknown);
    assert_eq!(outcome.reconciliation.unwrap().status, "pending");
    assert_eq!(pending(&f), 1);
    f.engine
        .transport()
        .set_response(MockResponse::Success(json!({"title": "unique"})));
    tick(&f);
    assert_settled(&f, "confirmed", 2);
}

#[test]
fn discovery_clears_withdrawn_reconciliation_class() {
    let f = fixture(false);
    let mut manifest = discovery_manifest();
    db(&f).execute_batch("DELETE FROM catalog_actions").unwrap();
    install_discovery_manifest(&f, manifest.clone());
    f.engine
        .store()
        .seed_catalog_from_manifest("direct", "conn", "mock")
        .unwrap();
    assert!(f
        .engine
        .store()
        .catalog_action("direct", "conn", "create")
        .unwrap()
        .unwrap()
        .reconciliation
        .is_some());

    manifest["actions_baseline"][0]
        .as_object_mut()
        .unwrap()
        .remove("reconciliation");
    install_discovery_manifest(&f, manifest);
    discover(&f);
    assert!(f
        .engine
        .store()
        .catalog_action("direct", "conn", "create")
        .unwrap()
        .unwrap()
        .reconciliation
        .is_none());
    let outcome = dispatch(&f, "direct", MockResponse::OutcomeUnknown);
    assert_eq!(outcome.reconciliation.unwrap().status, "unreconcilable");
    assert_eq!(pending(&f), 0);
    assert_eq!(
        status(&f).1.as_deref(),
        Some("reconciliation_class_missing")
    );
}
