use super::*;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{ingest_value, PlexusStore};

const TEST_CONNECTION: &str = "conn-grant-expiry";

#[test]
fn deleting_connection_unregisters_transports_only_after_commit() {
    let (state, _store) = grant_test_state("delete-unregister");
    state
        .runtime
        .mcp_transport
        .register_connection(plexus_core::McpConnection::new(
            TEST_CONNECTION,
            "http://127.0.0.1:1",
        ));
    state
        .runtime
        .rest_transport
        .register_connection(plexus_core::RestConnection::new(
            TEST_CONNECTION,
            "http://127.0.0.1:1",
        ));
    let preview = delete_connection(&state, "direct", &json!({"connection_id":TEST_CONNECTION}));
    assert_eq!(preview["result"]["outcome"], "would_delete");
    assert!(state.runtime.mcp_transport.has_connection(TEST_CONNECTION));
    assert!(state.runtime.rest_transport.has_connection(TEST_CONNECTION));
    let deleted = delete_connection(
        &state,
        "direct",
        &json!({"connection_id":TEST_CONNECTION, "dry_run":false}),
    );
    assert_eq!(deleted["result"]["outcome"], "deleted");
    assert!(!state.runtime.mcp_transport.has_connection(TEST_CONNECTION));
    assert!(!state.runtime.rest_transport.has_connection(TEST_CONNECTION));
}

fn grant_test_state(label: &str) -> (Arc<ModuleState>, Arc<PlexusStore>) {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: label.to_string(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    grant_test_state_with_descriptor(&descriptor)
}

fn grant_test_state_with_descriptor(
    descriptor: &StorageDescriptor,
) -> (Arc<ModuleState>, Arc<PlexusStore>) {
    let store = Arc::new(PlexusStore::open(descriptor).expect("open grant test store"));
    let manifest = ingest_value(json!({
        "schema_version": 1,
        "key": "grant_expiry_test",
        "name": "Grant expiry test",
        "description": "Exercises management grant expiry parsing",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "tests",
        "tier": "S1",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [
            {"name": "read_item", "risk": "read"},
            {"name": "read_other", "risk": "read"}
        ],
        "defaults": {
            "ask_first_risk": ["write"],
            "rate_limit": {"calls_per_min": 30}
        },
        "availability": "ga"
    }))
    .expect("test manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &manifest)
        .expect("store test manifest");
    let ceiling = store
        .ceiling_within_manifest("grant_expiry_test", "read", &["*".to_string()])
        .expect("resolve test ceiling")
        .expect("test ceiling is within manifest");
    store
        .create_connection("direct", TEST_CONNECTION, "grant_expiry_test")
        .expect("create grant test connection");
    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            TEST_CONNECTION,
            "credential_reference",
            b"test:grant_expiry",
            &ceiling,
        )
        .expect("create bounded test ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume test ticket")
        .expect("activate test connection");
    let state = Arc::new(ModuleState {
        health: Arc::new(crate::health::HealthState::new()),
        runtime: crate::runtime_for_test(Arc::clone(&store)),
    });
    (state, store)
}

fn grant_params() -> Value {
    json!({
        "connection_id": TEST_CONNECTION,
        "risk_ceiling": "read",
        "action_selectors": ["read_item"]
    })
}

struct SelectorFixture {
    state: Arc<ModuleState>,
    store: Arc<PlexusStore>,
    // Removing this directory is the guard's own job, which is why this
    // fixture no longer has a `Drop` of its own.
    directory: Scratch,
}

impl SelectorFixture {
    fn new() -> Self {
        let directory = Scratch::directory("selectors");
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: "selector-shape".to_string(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: directory.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let (state, store) = grant_test_state_with_descriptor(&descriptor);
        Self {
            state,
            store,
            directory,
        }
    }

    fn ticket_count(&self) -> i64 {
        // Count the actual rows, including consumed tickets, so a refusal
        // cannot hide a ticket minted before the error response.
        rusqlite::Connection::open_with_flags(
            self.directory.join("store.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
        .query_row("SELECT COUNT(*) FROM binding_tickets", [], |row| row.get(0))
        .unwrap()
    }
}

fn audit_failure_scenario(operation: &str) {
    for fail in [false, true] {
        let fixture = SelectorFixture::new();
        let path = fixture.directory.join("store.db");
        let mut params = match operation {
            "issue_ticket" => ticket_params(),
            "grant" => grant_params(),
            "revoke_grant" => {
                let response = grant(&fixture.state, "direct", &grant_params());
                json!({"grant_id": response["result"]["grant"]["grant_id"]})
            }
            "set_policy" => {
                json!({"connection_id": TEST_CONNECTION, "action_selector": "read_item", "effect": "block"})
            }
            "remove_policy" => {
                let policy = fixture
                    .store
                    .set_policy("direct", TEST_CONNECTION, "read_item", "block", None)
                    .unwrap();
                json!({"policy_id": policy.policy_id})
            }
            "repin_action" => {
                fixture
                    .store
                    .upsert_catalog_action(&plexus_core::CatalogActionInput {
                        principal: "direct".into(),
                        connection_id: TEST_CONNECTION.into(),
                        name: "read_item".into(),
                        title: None,
                        schema: json!({"type":"object"}),
                        schema_hash: "reviewed-hash".into(),
                        risk: "read".into(),
                        severity: "S1".into(),
                        ask_first: false,
                        status: "quarantined".into(),
                        quarantine_reason: Some("schema_changed".into()),
                        reconciliation: None,
                    })
                    .unwrap();
                json!({"connection_id": TEST_CONNECTION, "action": "read_item", "expected_schema_hash": "reviewed-hash"})
            }
            _ => panic!("unknown ceremony"),
        };
        // Install the audit-insert fault after fixture setup so only the
        // operation under test loses its audit record.
        let before = fixture.store.list_audit("direct").unwrap().len();
        if fail {
            crate::audit_test::reject_inserts(&path);
        }
        let response = match operation {
            "issue_ticket" => issue_ticket(&fixture.state, "direct", &params),
            "grant" => grant(&fixture.state, "direct", &params),
            "revoke_grant" => revoke_grant(&fixture.state, "direct", &params),
            "set_policy" => set_policy(&fixture.state, "direct", &params),
            "remove_policy" => remove_policy(&fixture.state, "direct", &params),
            "repin_action" => repin_action(&fixture.state, "direct", &params),
            _ => unreachable!(),
        };
        assert_eq!(
            fixture.store.list_audit("direct").unwrap().len(),
            before + usize::from(!fail)
        );
        if fail {
            // The audit row shares the change's transaction, so a refused
            // row is a failed operation that changed nothing.
            assert!(
                response.get("error").is_some(),
                "{operation}: an unaudited change was reported as done: {response}"
            );
            audit_failure_left_nothing(&fixture, operation, &params);
            continue;
        }
        assert!(response.get("error").is_none(), "{response}");
        match operation {
            "issue_ticket" => {
                assert!(response["result"]["ticket_id"].is_string());
                assert_eq!(fixture.ticket_count(), 2);
            }
            "grant" => {
                assert!(response["result"]["grant"]["grant_id"].is_string());
                assert_eq!(
                    fixture
                        .store
                        .list_grants("direct", TEST_CONNECTION)
                        .unwrap()
                        .len(),
                    1
                );
            }
            "revoke_grant" => {
                assert_eq!(response["result"]["revoked"], true);
                assert_eq!(
                    revoke_grant(&fixture.state, "direct", &params)["result"]["revoked"],
                    false
                );
            }
            "remove_policy" => {
                assert_eq!(response["result"]["removed"], true);
                assert_eq!(
                    remove_policy(&fixture.state, "direct", &params)["result"]["removed"],
                    false
                );
            }
            "repin_action" => {
                assert_eq!(response["result"]["status"], "active");
                assert_eq!(
                    fixture
                        .store
                        .catalog_action("direct", TEST_CONNECTION, "read_item")
                        .unwrap()
                        .unwrap()
                        .status,
                    "active"
                );
            }
            "set_policy" => {
                assert_eq!(response["result"]["policy"]["effect"], "block");
                params["policy_id"] = response["result"]["policy"]["policy_id"].clone();
                assert!(fixture
                    .store
                    .remove_policy("direct", params["policy_id"].as_str().unwrap())
                    .unwrap());
            }
            _ => unreachable!(),
        }
    }
}

/// After a refused audit row, the state the operation would have changed
/// is exactly as the fixture left it.
fn audit_failure_left_nothing(fixture: &SelectorFixture, operation: &str, params: &Value) {
    let store = &fixture.store;
    match operation {
        "issue_ticket" => assert_eq!(
            fixture.ticket_count(),
            1,
            "issue_ticket: the unaudited ticket must not be kept"
        ),
        "grant" => assert!(
            store
                .list_grants("direct", TEST_CONNECTION)
                .unwrap()
                .is_empty(),
            "grant: the unaudited grant must not be kept"
        ),
        "revoke_grant" => assert!(
            store
                .grant_by_id("direct", params["grant_id"].as_str().unwrap())
                .unwrap()
                .is_some(),
            "revoke_grant: the grant must stay live when its revocation is unaudited"
        ),
        "set_policy" => assert!(
            store.list_policies("direct", None).unwrap().is_empty(),
            "set_policy: the unaudited policy must not be kept"
        ),
        "remove_policy" => assert!(
            store
                .policy_by_id("direct", params["policy_id"].as_str().unwrap())
                .unwrap()
                .is_some(),
            "remove_policy: the policy must stay when its removal is unaudited"
        ),
        "repin_action" => assert_eq!(
            store
                .catalog_action("direct", TEST_CONNECTION, "read_item")
                .unwrap()
                .unwrap()
                .status,
            "quarantined",
            "repin_action: the unaudited re-pin must not be kept"
        ),
        _ => unreachable!(),
    }
}

// Each operation's audit row commits with the change it records: when the
// row cannot be written the operation fails and changes nothing, and when
// it can, exactly one row is added.
#[test]
fn issue_ticket_audit_failure_rolls_back_the_ticket() {
    audit_failure_scenario("issue_ticket");
}
#[test]
fn grant_audit_failure_rolls_back_the_grant() {
    audit_failure_scenario("grant");
}
#[test]
fn revoke_grant_audit_failure_rolls_back_the_revocation() {
    audit_failure_scenario("revoke_grant");
}
#[test]
fn repin_action_audit_failure_rolls_back_the_repin() {
    audit_failure_scenario("repin_action");
}
#[test]
fn set_policy_audit_failure_rolls_back_the_policy() {
    audit_failure_scenario("set_policy");
}
#[test]
fn remove_policy_audit_failure_rolls_back_the_removal() {
    audit_failure_scenario("remove_policy");
}

/// The connection id the ticket tests issue tickets for. It does not
/// exist in the fixture, so issuing a ticket creates it as a pending
/// connection, and redeeming the ticket copies the ticket's limits (its
/// maximum risk and allowed actions) onto it for the tests to read back.
/// An active connection would refuse a new ticket; its credential is
/// replaced with the admin CLI's `rebind-credential` command instead.
const TICKET_TEST_CONNECTION: &str = "conn-selector-ticket";

fn ticket_params() -> Value {
    json!({
        "app_key": "grant_expiry_test",
        "connection_id": TICKET_TEST_CONNECTION,
        "credential_id": "test:selector",
        "action_selectors": ["read_item"]
    })
}

#[test]
fn issue_ticket_existing_connection_has_named_admin_refusal_without_mutation() {
    let fixture = SelectorFixture::new();
    let conn = rusqlite::Connection::open(fixture.directory.join("store.db")).unwrap();
    let snapshot = || {
        conn.query_row("SELECT credential_binding,generation FROM connections WHERE principal='direct' AND connection_id=?1",[TEST_CONNECTION],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,i64>(1)?))).unwrap()
    };
    let before = snapshot();
    let mut params = ticket_params();
    params["connection_id"] = json!(TEST_CONNECTION);
    let reply = issue_ticket(&fixture.state, "direct", &params);
    assert_eq!(
        reply["error"]["code"], "connection_exists",
        "admin issue-ticket --connection must refuse an existing live connection"
    );
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("rebind-credential"));
    assert_eq!(
        snapshot(),
        before,
        "refusal must leave credential bytes and generation unchanged"
    );
}

fn assert_selector_refusal(value: Value, message: &str, ticket: bool) {
    let fixture = SelectorFixture::new();
    let before = fixture.ticket_count();
    let mut params = if ticket {
        ticket_params()
    } else {
        grant_params()
    };
    params["action_selectors"] = value;
    let response = if ticket {
        issue_ticket(&fixture.state, "direct", &params)
    } else {
        grant(&fixture.state, "direct", &params)
    };
    assert_eq!(
        fixture.ticket_count(),
        before,
        "refusal must not write a ticket"
    );
    assert!(
        fixture
            .store
            .list_grants("direct", TEST_CONNECTION)
            .unwrap()
            .is_empty(),
        "refusal must not write a grant"
    );
    assert_eq!(response["error"]["code"], "invalid_request");
    assert_eq!(response["error"]["message"], message);
}

#[test]
fn grant_refuses_string_selectors_without_minting_authority() {
    assert_selector_refusal(
        json!("read_item"),
        "action_selectors must be an array of strings",
        false,
    );
}

#[test]
fn issue_ticket_refuses_string_selectors_without_issuing_ticket() {
    assert_selector_refusal(
        json!("read_item"),
        "action_selectors must be an array of strings",
        true,
    );
}

#[test]
fn both_callers_refuse_mixed_selector_arrays_without_authority() {
    for ticket in [false, true] {
        assert_selector_refusal(
            json!(["read_item", 7]),
            "action_selectors[1] must be a string",
            ticket,
        );
    }
}

#[test]
fn both_callers_refuse_other_non_array_selectors() {
    for ticket in [false, true] {
        for value in [Value::Null, json!(7), json!({}), json!(true)] {
            assert_selector_refusal(
                value,
                "action_selectors must be an array of strings",
                ticket,
            );
        }
    }
}

fn assert_selector_success(absent: bool) {
    for ticket in [false, true] {
        let fixture = SelectorFixture::new();
        let before = fixture.ticket_count();
        let mut params = if ticket {
            ticket_params()
        } else {
            grant_params()
        };
        if absent {
            params.as_object_mut().unwrap().remove("action_selectors");
        }
        let expected = if absent {
            vec!["read_item", "read_other"]
        } else {
            vec!["read_item"]
        };
        if ticket {
            let response = issue_ticket(&fixture.state, "direct", &params);
            assert_eq!(
                response["result"]["ceiling"]["action_selectors"],
                json!(expected)
            );
            assert_eq!(fixture.ticket_count(), before + 1);
            fixture
                .store
                .connect_with_ticket("direct", response["result"]["ticket_id"].as_str().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(
                fixture
                    .store
                    .connection_ceiling("direct", TICKET_TEST_CONNECTION)
                    .unwrap()
                    .unwrap()
                    .action_selectors,
                expected
            );
        } else {
            let response = grant(&fixture.state, "direct", &params);
            assert_eq!(
                response["result"]["grant"]["action_selectors"],
                json!(expected)
            );
            let grants = fixture
                .store
                .list_grants("direct", TEST_CONNECTION)
                .unwrap();
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].action_selectors, expected);
        }
    }
}

#[test]
fn both_callers_absent_selectors_still_authorize_full_bound() {
    assert_selector_success(true);
}

#[test]
fn both_callers_string_arrays_preserve_explicit_selection() {
    assert_selector_success(false);
}

#[test]
fn grant_refuses_a_string_expiry_without_minting_authority() {
    let (state, store) = grant_test_state("grant-string-expiry");
    let mut params = grant_params();
    params["expires_at"] = json!("1800000000000");

    let response = grant(&state, "direct", &params);

    assert_eq!(response["error"]["code"], "invalid_request");
    assert_eq!(
        response["error"]["message"],
        "expires_at must be an epoch milliseconds integer"
    );
    assert!(store
        .list_grants("direct", TEST_CONNECTION)
        .expect("list grants after refusal")
        .is_empty());
}

#[test]
fn regression_past_and_seconds_unit_expiries_are_refused() {
    let (state, store) = grant_test_state("grant-past-expiry");
    for expiry in [-1, 0, 1_792_246_701, plexus_core::now_ms() - 1] {
        let mut params = grant_params();
        params["expires_at"] = json!(expiry);
        let reply = grant(&state, "direct", &params);
        assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("milliseconds"));
        let reply = set_policy(
            &state,
            "direct",
            &json!({"connection_id":TEST_CONNECTION, "action_selector":"read_item", "effect":"allow", "expires_at":expiry}),
        );
        assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
    }
    assert!(store
        .list_grants("direct", TEST_CONNECTION)
        .unwrap()
        .is_empty());
    assert!(store
        .list_policies("direct", Some(TEST_CONNECTION))
        .unwrap()
        .is_empty());
}

#[test]
fn regression_malformed_preview_flags_are_named_refusals() {
    let (state, _) = grant_test_state("malformed-preview");
    for flag in [json!("false"), json!(0), Value::Null, json!({})] {
        let params = json!({"connection_id":TEST_CONNECTION,"connection":TEST_CONNECTION,
                "recipient":"person@example.com","backend":state.runtime.web_search.backend_name(),
                "per_caller_per_minute":10,"per_backend_per_minute":100,"dry_run":flag});
        for reply in [
            delete_connection(&state, "direct", &params),
            set_web_search_limit(&state, "direct", &params),
            recipients(&state, &params, crate::manifest::ADMIN_RECIPIENTS_ADD_OP),
        ] {
            assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
            assert_eq!(
                reply["error"]["message"], "dry_run must be a boolean",
                "{reply}"
            );
        }
    }
}

#[test]
fn web_search_preview_flags_are_named_refusals() {
    let (state, _) = grant_test_state("web-search-preview");
    for flag in [json!("false"), json!(0), Value::Null, json!({})] {
        let params = json!({"providers":["exa"],"provider":"exa","count":10,"dry_run":flag});
        for reply in [
            set_web_search_order(&state, "direct", &params),
            set_web_search_allowance(&state, "direct", &params),
        ] {
            assert_eq!(reply["error"]["code"], "invalid_request", "{reply}");
            assert_eq!(
                reply["error"]["message"], "dry_run must be a boolean",
                "{reply}"
            );
        }
        assert_eq!(state.store().web_search_order().unwrap(), None);
        assert_eq!(state.store().web_search_allowance("exa").unwrap(), None);
    }
}

#[test]
fn grant_with_integer_expiry_mints_with_that_expiry() {
    let (state, store) = grant_test_state("grant-integer-expiry");
    let expiry = 1_900_000_000_000_i64;
    let mut params = grant_params();
    params["expires_at"] = json!(expiry);

    let response = grant(&state, "direct", &params);

    assert_eq!(response["result"]["grant"]["expires_at"], expiry);
    let grants = store
        .list_grants("direct", TEST_CONNECTION)
        .expect("list bounded grant");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].expires_at, Some(expiry));
}

#[test]
fn grant_without_expiry_mints_until_revoked_authority() {
    let (state, store) = grant_test_state("grant-absent-expiry");

    let response = grant(&state, "direct", &grant_params());

    assert!(response["result"]["grant"]["expires_at"].is_null());
    let grants = store
        .list_grants("direct", TEST_CONNECTION)
        .expect("list until-revoked grant");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].expires_at, None);
    assert_eq!(grants[0].state, "until_revoked");
}

#[test]
fn null_grant_expiry_behaves_as_absent() {
    let (state, store) = grant_test_state("grant-null-expiry");
    let mut params = grant_params();
    params["expires_at"] = Value::Null;

    let response = grant(&state, "direct", &params);

    assert!(response["result"]["grant"]["expires_at"].is_null());
    let grants = store
        .list_grants("direct", TEST_CONNECTION)
        .expect("list null-expiry grant");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].expires_at, None);
    assert_eq!(grants[0].state, "until_revoked");
}

#[test]
fn policy_expiry_keeps_its_integer_and_wrong_type_behavior() {
    let (state, store) = grant_test_state("policy-expiry");
    let policy_params = |expires_at: Value| {
        json!({
            "connection_id": TEST_CONNECTION,
            "action_selector": "read_item",
            "effect": "allow",
            "expires_at": expires_at
        })
    };

    let refused = set_policy(&state, "direct", &policy_params(json!("1800000000000")));
    assert_eq!(refused["error"]["code"], "invalid_request");
    assert_eq!(
        refused["error"]["message"],
        "expires_at must be an epoch milliseconds integer"
    );
    assert!(store
        .list_policies("direct", Some(TEST_CONNECTION))
        .expect("list policies after refusal")
        .is_empty());

    let expiry = 1_900_000_000_000_i64;
    let accepted = set_policy(&state, "direct", &policy_params(json!(expiry)));
    assert_eq!(accepted["result"]["policy"]["expires_at"], expiry);
    let policies = store
        .list_policies("direct", Some(TEST_CONNECTION))
        .expect("list bounded policy");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].expires_at, Some(expiry));
}

#[test]
fn empty_action_selectors_have_a_named_wire_refusal() {
    let response = refusal_response(&CeremonyRefusal::EmptyActionSelectors);
    assert_eq!(response["error"]["code"], "empty_action_selectors");
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("at least one action"));
    assert!(requested_selectors(&json!({"action_selectors": []}))
        .unwrap()
        .is_empty());
    assert_eq!(
        requested_selectors(&json!({})).unwrap(),
        vec!["*".to_string()]
    );
}

#[test]
fn review_action_returns_store_failure_when_the_pinned_schema_hash_fails() {
    let review = plexus_core::CatalogActionReview {
        action: plexus_core::CatalogAction {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_item".to_string(),
            title: None,
            schema: json!({"type": "object"}),
            schema_hash: "sha256:current".to_string(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "quarantined".to_string(),
            quarantine_reason: Some("schema_changed_requires_review".to_string()),
            reconciliation: None,
            generation: 2,
        },
        reviewed_schema: Some(json!({"type": "object"})),
    };

    let response = action_review_response("connection", review, |_| {
        Err(plexus_core::JcsError::NonFiniteNumber)
    });

    assert_eq!(response["error"]["code"], "store_failure");
    assert!(response.get("result").is_none());
}
