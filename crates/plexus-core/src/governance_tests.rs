use super::*;
use crate::credentials::StubCredentialSource;
use crate::storage::{CatalogActionInput, GrantInput};
use crate::transport::MockTransport;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

fn ordinary_test_engine() -> GovernanceEngine<StubCredentialSource, MockTransport> {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().facade_only = false;
    engine
}

fn ordinary_request() -> AuthorizationRequest {
    AuthorizationRequest::new(
        "direct",
        "connection",
        "write_item",
        serde_json::json!({"repo":"o/r"}),
    )
}

fn pending_request(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    ceiling: &str,
    selectors: Vec<String>,
) -> String {
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "admin".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "operator".into(),
            risk_ceiling: ceiling.into(),
            action_selectors: selectors,
            authority_kind: "connection_admin".into(),
            expires_at: None,
        })
        .unwrap();
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    engine
        .store()
        .create_action_request(
            "direct",
            "connection",
            "write_item",
            &ordinary_request().args,
            &action.schema_hash,
            "direct",
            crate::storage::now_ms() + 60_000,
            None,
            None,
        )
        .unwrap()
}

#[test]
fn severe_ask_first_refuses_before_creating_consent() {
    let engine = ordinary_test_engine();
    install_system_manifest(engine.store(), "mock", "S3");
    engine
        .store()
        .set_policy("direct", "connection", "*", "ask_first", None)
        .unwrap();
    assert!(matches!(
        engine.authorize(ordinary_request()),
        Err(Denial::NeedsDecisionPlane(_))
    ));
    assert!(engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
}

#[test]
fn poll_authority_cannot_create_interactive_approval() {
    let engine = ordinary_test_engine();
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "poll".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["*".into()],
            authority_kind: AUTHORITY_POLL.into(),
            expires_at: None,
        })
        .unwrap();
    engine
        .store()
        .set_policy("direct", "connection", "*", "ask_first", None)
        .unwrap();
    assert_eq!(
        engine.authorize(ordinary_request().for_poll("subscription")),
        Err(Denial::Policy(PolicyDenial::AskFirst))
    );
    assert!(engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
}

#[test]
fn internal_calls_refuse_recursive_credential_material() {
    let engine = ordinary_test_engine();
    let request = AuthorizationRequest::new(
        "direct",
        "connection",
        "write_item",
        serde_json::json!({"nested":{"api_key":"never-forward"}}),
    );
    assert_eq!(
        engine.authorize(request),
        Err(Denial::CredentialMaterialForbidden)
    );
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn decision_and_dispatch_audit_use_effective_severity() {
    let engine = ordinary_test_engine();
    let reservation = engine.authorize(ordinary_request()).unwrap();
    let rows = engine.store().list_audit("direct").unwrap();
    let row = rows
        .iter()
        .find(|row| row.reason_code == "credential_resolved")
        .unwrap();
    assert_eq!(row.severity.as_deref(), Some(reservation.severity.as_str()));
    assert_eq!(row.severity.as_deref(), Some("S2"));
}

#[test]
fn terminal_preclaim_refusal_keeps_approval_retryable() {
    let engine = ordinary_test_engine().with_freshness_check(Arc::new(|_| {
        Err(("catalog_stale_write".into(), "refresh unavailable".into()))
    }));
    let id = pending_request(&engine, "write", vec!["*".into()]);
    let outcome = engine.approve_request("direct", &id, "operator").unwrap();
    assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
    let row = engine
        .store()
        .action_request("direct", &id)
        .unwrap()
        .unwrap();
    assert_eq!(
        row.scope_outcome.as_deref(),
        Some(crate::scope::APPROVED_WAITING)
    );
}

#[test]
fn admin_approval_and_denial_honor_selector_and_risk() {
    for (risk, selector) in [("read", "*"), ("write", "other_action")] {
        let engine = ordinary_test_engine();
        let id = pending_request(&engine, risk, vec![selector.into()]);
        assert_eq!(
            engine.approve_request("direct", &id, "operator"),
            Err(Denial::Grant(GrantDenial::ConnectionAdminRequired))
        );
        assert_eq!(
            engine.deny_request("direct", &id, "operator"),
            Err(Denial::Grant(GrantDenial::ConnectionAdminRequired))
        );
    }
}

#[test]
fn operator_denial_is_in_append_only_audit() {
    let engine = ordinary_test_engine();
    let id = pending_request(&engine, "write", vec!["*".into()]);
    assert!(engine.deny_request("direct", &id, "operator").unwrap());
    assert!(engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .any(|row| row.reason_code == "approval_denied" && row.actor == "operator"));
}

#[test]
fn consent_denial_expiry_and_withdrawal_are_audited() {
    for (state, code) in [
        ("answered", "consent_denied"),
        ("expired", "consent_expired"),
        ("withdrawn", "consent_withdrawn"),
    ] {
        let engine = ordinary_test_engine();
        let id = pending_request(&engine, "write", vec!["*".into()]);
        let mut request = engine
            .store()
            .action_request("direct", &id)
            .unwrap()
            .unwrap();
        request.elicitation_id = Some("card".into());
        let digest = request.args_hash.clone();
        let scope = CallScope {
            owner: "direct".into(),
            scope_ref: "session".into(),
            scope_epoch: 1,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: None,
            flow_id: None,
            delegates: false,
            owner_authorized: true,
        };
        let result = engine.finish_consent(request, &scope, serde_json::json!({"elicitation_id":"card", "kind":"consent", "args_digest":digest, "state":state, "answered_choice_id":"deny"}));
        assert!(matches!(result, Err(Denial::ConsentRefused { .. })));
        assert!(engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .any(|row| row.reason_code == code && row.actor == "consent_card:card"));
    }
}

#[test]
fn shape_reuse_never_crosses_requesters() {
    let engine = ordinary_test_engine();
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    let mut ids = Vec::new();
    for requester in ["carrier-a", "carrier-b"] {
        ids.push(
            engine
                .store()
                .ensure_action_request(
                    "direct",
                    "connection",
                    "write_item",
                    &serde_json::json!({"repo":"o/r"}),
                    &action.schema_hash,
                    requester,
                    crate::storage::now_ms() + 60_000,
                    None,
                    None,
                )
                .unwrap(),
        );
    }
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn approved_routing_is_persistent_and_immutable() {
    let engine = ordinary_test_engine();
    let id = pending_request(&engine, "write", vec!["*".into()]);
    let routing = serde_json::json!({"repository":"o/r", "tool":"github_read", "supports_per_call_approval":true});
    assert!(engine
        .store()
        .bind_action_request_routing("direct", &id, &routing)
        .unwrap());
    assert_eq!(
        engine
            .store()
            .action_request_routing("direct", &id)
            .unwrap(),
        Some(routing)
    );
    assert!(!engine
        .store()
        .bind_action_request_routing(
            "direct",
            &id,
            &serde_json::json!({"repository":"other/repo"})
        )
        .unwrap());
    engine
        .store()
        .decide_action_request("direct", &id, true, "operator")
        .unwrap();
    let request = ordinary_request().approved_from(id);
    assert_eq!(
        engine.authorize(request),
        Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch))
    );
}

#[test]
fn approved_dispatch_restores_internal_repository() {
    let (engine, seams) = facade_test_engine();
    {
        let mut state = seams.0.lock().unwrap();
        state.facade_only = false;
        state.expected_repository = Some("o/r".into());
    }
    let id = pending_request(&engine, "write", vec!["*".into()]);
    let routing = serde_json::json!({"repository":"o/r", "tool":"github_read", "supports_per_call_approval":true});
    engine
        .store()
        .bind_action_request_routing("direct", &id, &routing)
        .unwrap();
    let outcome = engine.approve_request("direct", &id, "operator").unwrap();
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));
    assert_eq!(engine.transport().requests().len(), 1);
}

#[test]
fn unknown_effects_and_statuses_fail_closed() {
    assert_eq!(compose_policy_effect("misspelled", Some("allow")), "block");
    assert_eq!(RequestStatus::of("approvd"), RequestStatus::Unknown);
    assert_ne!(RequestStatus::of("approvd"), RequestStatus::Approved);
}

#[test]
fn stale_arguments_and_grant_hash_abandon_reservations() {
    for grant_hash in [false, true] {
        let engine = ordinary_test_engine();
        let mut reservation = engine.authorize(ordinary_request()).unwrap();
        if grant_hash {
            reservation.decision_id = Some("decision".into());
            reservation.grant_hash = Some("wrong".into());
        } else {
            reservation.args = serde_json::json!({"repo":"changed"});
        }
        engine.revalidate_and_dispatch(&reservation);
        assert_eq!(
            engine
                .store()
                .reservation("direct", &reservation.reservation_id)
                .unwrap()
                .unwrap()
                .status,
            "invalidated"
        );
    }
}

#[test]
fn waiting_approval_batches_back_off_between_attempts() {
    let engine = ordinary_test_engine();
    let id = pending_request(&engine, "write", vec!["*".into()]);
    engine
        .store()
        .decide_action_request("direct", &id, true, "operator")
        .unwrap();
    engine.store().hold_scoped_approval("direct", &id).unwrap();
    assert_eq!(
        engine.store().waiting_scoped_approvals(10).unwrap().len(),
        1
    );
    assert!(engine
        .store()
        .waiting_scoped_approvals(10)
        .unwrap()
        .is_empty());
}

#[test]
fn waiting_scope_precheck_does_not_reserve_or_audit_again() {
    let scratch = crate::test_scratch::Scratch::file("waiting-scope-precheck", "store.db");
    let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
    seams.0.lock().unwrap().facade_only = false;
    let scope = CallScope {
        owner: "direct".into(),
        scope_ref: "session".into(),
        scope_epoch: 1,
        kind: None,
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: None,
        delegates: false,
        owner_authorized: true,
    };
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    let id = engine
        .store()
        .create_action_request(
            "direct",
            "connection",
            "write_item",
            &ordinary_request().args,
            &action.schema_hash,
            "direct",
            crate::storage::now_ms() + 60_000,
            Some(&scope),
            None,
        )
        .unwrap();
    engine
        .store()
        .decide_action_request("direct", &id, true, "operator")
        .unwrap();
    engine.store().hold_scoped_approval("direct", &id).unwrap();
    assert_eq!(engine.retry_waiting_approvals(10), 1);
    let count: i64 = rusqlite::Connection::open(scratch.path())
        .unwrap()
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 0,
        "an unconfirmed scope must not create another reservation"
    );
    assert!(engine.store().list_audit("direct").unwrap().is_empty());
}

#[test]
fn missing_connection_or_action_invalidates_claim_without_store_error() {
    for table in ["connections", "catalog_actions"] {
        let scratch = crate::test_scratch::Scratch::file("claim-missing-row", "store.db");
        let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
        seams.0.lock().unwrap().facade_only = false;
        let reservation = engine.authorize(ordinary_request()).unwrap();
        rusqlite::Connection::open(scratch.path())
            .unwrap()
            .execute(&format!("DELETE FROM {table}"), [])
            .unwrap();
        assert!(!engine
            .store()
            .claim_reservation(
                &reservation_record(&reservation),
                "attempt",
                &crate::storage::now_ms,
            )
            .unwrap());
        assert_eq!(
            engine
                .store()
                .reservation("direct", &reservation.reservation_id)
                .unwrap()
                .unwrap()
                .status,
            "invalidated"
        );
    }
}

#[test]
fn revoked_agent_identity_is_preserved_in_immutable_snapshot() {
    let scratch = crate::test_scratch::Scratch::file("agent-revocation", "store.db");
    let engine = hash_test_engine_at(scratch.path().to_str().unwrap());
    let conn = rusqlite::Connection::open(scratch.path()).unwrap();
    conn.execute(
        "UPDATE grants SET agent_id='agent-a' WHERE grant_id='grant'",
        [],
    )
    .unwrap();
    assert!(engine.store().revoke_grant("direct", "grant").unwrap());
    let agent: String = conn
        .query_row(
            "SELECT agent_id FROM grant_revocations WHERE grant_id='grant'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(agent, "agent-a");
}

#[test]
fn claim_pins_policy_identity_not_only_generation() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().facade_only = false;
    engine
        .store()
        .set_policy("direct", "connection", "*", "allow", None)
        .unwrap();
    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        ))
        .unwrap();
    engine
        .store()
        .set_policy("direct", "connection", "write_item", "block", None)
        .unwrap();
    assert!(!engine
        .store()
        .claim_reservation(
            &reservation_record(&reservation),
            "attempt",
            &crate::storage::now_ms,
        )
        .unwrap());
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn claim_rechecks_module_and_agent_expiry() {
    for agent in [false, true] {
        let scratch = crate::test_scratch::Scratch::file("claim-expiry", "store.db");
        let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
        seams.0.lock().unwrap().facade_only = false;
        let reservation = engine
            .authorize(AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            ))
            .unwrap();
        let mut record = reservation_record(&reservation);
        if agent {
            record.agent_grant = Some(crate::storage::PinnedGrant {
                grant_id: "agent-grant".into(),
                generation: 1,
            });
        }
        let conn = rusqlite::Connection::open(scratch.path()).unwrap();
        if agent {
            conn.execute("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms,agent_id) VALUES('agent-grant','direct','connection','direct','write','[\"write_item\"]','invoke',1,1,1,'agent-a')", []).unwrap();
            conn.execute("UPDATE reservations SET agent_grant_id='agent-grant'", [])
                .unwrap();
        } else {
            conn.execute("UPDATE grants SET expires_at=1 WHERE grant_id='grant'", [])
                .unwrap();
        }
        assert!(
            !engine
                .store()
                .claim_reservation(&record, "attempt", &crate::storage::now_ms)
                .unwrap(),
            "agent={agent}"
        );
    }
}

#[test]
fn module_matching_never_uses_an_agent_row() {
    let scratch = crate::test_scratch::Scratch::file("module-grant-layer", "store.db");
    let engine = hash_test_engine_at(scratch.path().to_str().unwrap());
    rusqlite::Connection::open(scratch.path())
        .unwrap()
        .execute(
            "UPDATE grants SET agent_id='agent-a' WHERE grant_id='grant'",
            [],
        )
        .unwrap();
    assert!(engine
        .store()
        .matching_grant(
            "direct",
            "connection",
            "direct",
            "write_item",
            AUTHORITY_INVOKE,
            crate::storage::now_ms(),
            Some("write")
        )
        .unwrap()
        .is_none());
}

#[test]
fn non_object_arguments_are_not_reviewable() {
    for args in [
        serde_json::json!([]),
        serde_json::json!("value"),
        serde_json::json!(1),
        serde_json::json!(false),
    ] {
        assert!(undeclared_argument(&serde_json::json!({"type":"object"}), &args).is_some());
    }
}

#[test]
fn missing_allowlisted_read_path_is_refused_and_nested_paths_resolve() {
    let engine = hash_test_engine();
    let mut connection = engine
        .store()
        .connection("direct", "connection")
        .unwrap()
        .unwrap();
    let mut action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    action.risk = "read".into();
    connection.resource_filters = serde_json::json!({"values":{"target.repo":["o/r"]}});
    assert_eq!(
        resource_denial(&connection, &action, &serde_json::json!({})),
        Some(ResourceDenial::MissingRequiredFilter("target.repo".into()))
    );
    assert_eq!(
        resource_denial(
            &connection,
            &action,
            &serde_json::json!({"target":{"repo":"o/r"}})
        ),
        None
    );
}

#[test]
fn checked_search_selection_requires_every_repository_to_be_allowed() {
    let engine = hash_test_engine();
    let mut connection = engine
        .store()
        .connection("direct", "connection")
        .unwrap()
        .unwrap();
    let mut action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    connection.app_key = "github_rest".into();
    connection.resource_filters = serde_json::json!({"values":{"owner":"org","repo":["a","b"]}});
    action.name = "github.issue.search".into();
    action.risk = "read".into();
    let args = serde_json::json!({"terms":["open"]});
    let allowed = AuthorizationRequest::new("direct", "connection", &action.name, args.clone())
        .with_resolved_github_search(vec!["org/a".into(), "org/b".into()]);
    let outside = AuthorizationRequest::new("direct", "connection", &action.name, args.clone())
        .with_resolved_github_search(vec!["org/a".into(), "other/b".into()]);
    assert_eq!(
        resource_denial_with_repositories(
            &connection,
            &action,
            &args,
            allowed.resolved_github_search_repositories()
        ),
        None
    );
    assert!(resource_denial_with_repositories(
        &connection,
        &action,
        &args,
        outside.resolved_github_search_repositories()
    )
    .is_some());
    assert!(resource_denial_with_repositories(&connection, &action, &args, None).is_some());
    assert!(resource_denial_with_repositories(&connection, &action, &args, Some(&[])).is_some());
}

/// Which schema shapes close the top level, and which argument is named.
#[test]
fn undeclared_argument_checks_only_a_closed_top_level() {
    use serde_json::json;
    let declared = json!({"type": "object", "properties": {"a": {}, "n": {"type": "object"}}});
    let args = json!({"a": 1, "z": 2, "b": 3, "n": {"unknown": true}});
    // The first undeclared key in sorted order; the nested unknown is ignored.
    assert_eq!(undeclared_argument(&declared, &args).as_deref(), Some("b"));
    assert_eq!(
        undeclared_argument(&declared, &json!({"a": 1, "n": {"unknown": true}})),
        None
    );
    let mut closed = declared.clone();
    closed["additionalProperties"] = json!(false);
    assert_eq!(undeclared_argument(&closed, &args).as_deref(), Some("b"));
    for open in [
        json!({"type": "object"}),
        json!({"type": "object", "additionalProperties": true}),
        json!({"type": "object", "properties": {"a": {}}, "additionalProperties": true}),
        json!({"type": "object", "properties": {"a": {}}, "additionalProperties": {"type": "string"}}),
        json!({"type": "object", "properties": {"a": {}}, "patternProperties": {"^x_": {}}}),
        json!({"type": "object", "properties": "not an object"}),
        json!(true),
    ] {
        assert_eq!(undeclared_argument(&open, &args), None, "{open}");
    }
    assert_eq!(undeclared_argument(&declared, &json!(null)), None);
}

#[derive(Clone)]
struct SeamState {
    handle: HandleAuthority,
    module_owner: String,
    agent_owner: String,
    module: bool,
    agent: bool,
    module_effect: Option<String>,
    agent_effect: Option<String>,
    approval: Option<ReceiptApprovalRow>,
    ownership_complete: bool,
    marker: bool,
    receipt_store: Option<Arc<PlexusStore>>,
    auth_failures: usize,
    preparations: usize,
    lose_handle_before_preparation: bool,
    change_during_preparation: Option<&'static str>,
    handle_missing: bool,
    handle_read_failure: bool,
    generation_read_failure: bool,
    facade_only: bool,
    expected_repository: Option<String>,
    abandoned_reservations: Vec<String>,
    /// When set, replaces the single default agent row (or module row) with
    /// one row per entry: its action selectors and optional expiry, in the
    /// order the store would return them.
    agent_rows: Option<Vec<(Vec<&'static str>, Option<i64>)>>,
    module_rows: Option<Vec<(Vec<&'static str>, Option<i64>)>>,
}

struct TestHandleSeams(std::sync::Mutex<SeamState>);

impl GovernanceSeams for TestHandleSeams {
    fn resolve_invoke(&self, request: &AuthorizationRequest) -> Result<(), ResolverDenial> {
        if let Some(expected) = &self.0.lock().unwrap().expected_repository {
            assert_eq!(
                request.resolved_repository.as_ref(),
                Some(expected),
                "approved dispatch lost its routing repository"
            );
        }
        Ok(())
    }
    fn facade_only(&self, action: &CatalogAction) -> bool {
        self.0.lock().unwrap().facade_only && action.name == "write_item"
    }
    fn handle_row(
        &self,
        _connection: &ConnectionRecord,
    ) -> Result<Option<HandleAuthority>, Denial> {
        let state = self.0.lock().unwrap();
        if state.handle_read_failure {
            return Err(Denial::StoreFailure);
        }
        Ok((!state.handle_missing).then(|| state.handle.clone()))
    }
    fn grant_rows(
        &self,
        connection: &ConnectionRecord,
        request: &AuthorizationRequest,
    ) -> Result<Vec<ScopedGrantRow>, Denial> {
        let state = self.0.lock().unwrap();
        let grant = GrantRecord {
            grant_id: "grant".into(),
            principal: state.module_owner.clone(),
            connection_id: connection.connection_id.clone(),
            grantee_principal: request.principal.clone(),
            risk_ceiling: "write".into(),
            action_selectors: vec![request.action.clone()],
            authority_kind: AUTHORITY_INVOKE.into(),
            expires_at: None,
            generation: 1,
            revoked_at_ms: None,
            revoked_by: None,
            state: "active".into(),
        };
        let mut rows = Vec::new();
        let listed =
            |owner: &str, specs: &[(Vec<&'static str>, Option<i64>)], agent_id: Option<&str>| {
                specs
                    .iter()
                    .enumerate()
                    .map(|(index, (selectors, expires_at))| {
                        let mut row = grant.clone();
                        row.grant_id = format!("grant-{index}");
                        row.principal = owner.into();
                        row.action_selectors = selectors.iter().map(|s| (*s).into()).collect();
                        row.expires_at = *expires_at;
                        ScopedGrantRow {
                            grant: row,
                            agent_id: agent_id.map(str::to_owned),
                        }
                    })
                    .collect::<Vec<_>>()
            };
        if let Some(specs) = &state.module_rows {
            rows.extend(listed(&state.module_owner, specs, None));
        } else if state.module {
            rows.push(ScopedGrantRow {
                grant: grant.clone(),
                agent_id: None,
            });
        }
        if let Some(specs) = &state.agent_rows {
            rows.extend(listed(&state.agent_owner, specs, Some("agent-a")));
        } else if state.agent {
            let mut agent_grant = grant;
            agent_grant.principal = state.agent_owner.clone();
            rows.push(ScopedGrantRow {
                grant: agent_grant,
                agent_id: Some("agent-a".into()),
            });
        }
        Ok(rows)
    }
    fn grant_generations(
        &self,
        _connection: &ConnectionRecord,
        _principal: &str,
        _agent_id: &str,
        _action: &str,
    ) -> Result<(i64, i64), Denial> {
        let state = self.0.lock().unwrap();
        if state.generation_read_failure {
            return Err(Denial::StoreFailure);
        }
        Ok((
            if state.agent { 1 } else { 2 },
            if state.module { 1 } else { 2 },
        ))
    }
    fn policy_inputs(
        &self,
        _connection: &ConnectionRecord,
        _agent_id: &str,
        _action: &CatalogAction,
    ) -> Result<PolicyInputs, Denial> {
        let state = self.0.lock().unwrap();
        Ok(PolicyInputs {
            module_effect: state.module_effect.clone(),
            agent_effect: state.agent_effect.clone(),
            module_generation: 0,
        })
    }
    fn receipt_approval(
        &self,
        _connection: &ConnectionRecord,
        _id: &str,
    ) -> Result<Option<ReceiptApprovalRow>, Denial> {
        Ok(self.0.lock().unwrap().approval.clone())
    }
    fn ownership_reads_complete(&self, _request: &AuthorizationRequest) -> bool {
        self.0.lock().unwrap().ownership_complete
    }
    fn pre_transmit(&self, reservation: &Reservation) -> bool {
        let mut state = self.0.lock().unwrap();
        let marked =
            if let (Some(store), Some(claim)) = (&state.receipt_store, &reservation.receipt) {
                store
                    .mark_github_dispatch(
                        &claim.agent_id,
                        &claim.request_nonce,
                        &claim.claim_owner,
                        claim.effect_index,
                        crate::storage::now_ms(),
                        &reservation.request_id,
                    )
                    .unwrap()
            } else {
                state.marker
            };
        // Lose the row after authority revalidation and receipt marking, but
        // before credential preparation reads it again. Earlier removal is
        // caught by the separate stale-authority fence instead.
        if marked && state.lose_handle_before_preparation {
            state.handle_missing = true;
        }
        marked
    }
    fn abandon_transmit(&self, reservation: &Reservation) {
        let store = {
            let mut state = self.0.lock().unwrap();
            state
                .abandoned_reservations
                .push(reservation.reservation_id.clone());
            state.receipt_store.clone()
        };
        if let Some(store) = store {
            crate::storage::github_store::GithubGovernanceSeams {
                store,
                credential_provider: None,
            }
            .abandon_transmit(reservation);
        }
    }
    fn prepare_handle_credential(
        &self,
        _connection: &ConnectionRecord,
        _handle: &HandleAuthority,
    ) -> Result<ResolvedCredential, &'static str> {
        let mut state = self.0.lock().unwrap();
        state.preparations += 1;
        match state.change_during_preparation {
            Some("grant") => state.agent = false,
            Some("handle") => state.handle.app_handle_generation += 1,
            Some("repository") => state.handle.repo_binding_generation += 1,
            _ => {}
        }
        Ok(ResolvedCredential::new(b"ghs_test".to_vec(), None, 1))
    }
    fn handle_auth_failure(&self, _connection: &ConnectionRecord, _handle: &HandleAuthority) {
        self.0.lock().unwrap().auth_failures += 1;
    }
}

fn facade_test_engine() -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Arc<TestHandleSeams>,
) {
    facade_test_engine_at(":memory:")
}

fn facade_test_engine_at(
    path: &str,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Arc<TestHandleSeams>,
) {
    let seams = Arc::new(TestHandleSeams(std::sync::Mutex::new(SeamState {
        handle: HandleAuthority {
            app_handle_generation: 1,
            repo_binding_generation: 1,
            credential_generation: 1,
            enabled: true,
            credential_reference: b"ref".to_vec(),
        },
        module_owner: "direct".into(),
        agent_owner: "direct".into(),
        module: true,
        agent: true,
        module_effect: None,
        agent_effect: None,
        approval: None,
        ownership_complete: true,
        marker: true,
        receipt_store: None,
        auth_failures: 0,
        preparations: 0,
        lose_handle_before_preparation: false,
        change_during_preparation: None,
        handle_missing: false,
        handle_read_failure: false,
        generation_read_failure: false,
        facade_only: true,
        expected_repository: None,
        abandoned_reservations: Vec::new(),
        agent_rows: None,
        module_rows: None,
    })));
    (
        hash_test_engine_at(path).with_governance_seams(seams.clone()),
        seams,
    )
}

fn facade_request() -> AuthorizationRequest {
    facade_origin::request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        )
        .with_bound_agent("agent-a", "handle-a"),
        None,
    )
}

#[test]
fn authority_changes_during_token_exchange_stop_transmission() {
    for dimension in ["grant", "handle", "repository"] {
        let (engine, seams) = facade_test_engine();
        let reservation = engine.authorize(facade_request()).expect("authorize");
        seams.0.lock().unwrap().change_during_preparation = Some(dimension);
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
                    if code.starts_with("stale_authority{")),
            "{dimension}: {outcome:?}"
        );
        assert_eq!(seams.0.lock().unwrap().preparations, 1);
        assert!(engine.transport().requests().is_empty());
        assert_eq!(
            seams.0.lock().unwrap().abandoned_reservations,
            [reservation.reservation_id]
        );
    }
}

#[test]
fn a_pre_transmit_refusal_invalidates_the_unclaimed_reservation() {
    let (engine, _) = facade_test_engine();
    let reservation = engine.authorize(facade_request()).unwrap();
    engine.refuse_before_transmit(&reservation, "freshness_failed", "target changed");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
    assert!(
        engine.transport().requests().is_empty(),
        "refused reservation remained claimable"
    );
}

#[test]
fn a_credential_store_failure_keeps_an_approved_call_waiting() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().facade_only = false;
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "approval-admin".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "operator".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["*".into()],
            authority_kind: "connection_admin".into(),
            expires_at: None,
        })
        .unwrap();
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    let id = engine
        .store()
        .create_action_request(
            "direct",
            "connection",
            "write_item",
            &serde_json::json!({"repo":"o/r"}),
            &action.schema_hash,
            "direct",
            crate::storage::now_ms() + 300_000,
            None,
            None,
        )
        .unwrap();
    let fail = seams.clone();
    let engine = engine.with_freshness_check(Arc::new(move |_| {
        fail.0.lock().unwrap().handle_read_failure = true;
        Ok(())
    }));
    let outcome = engine.approve_request("direct", &id, "operator").unwrap();
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "credential_store_unavailable"),
        "{outcome:?}"
    );
    assert_eq!(outcome.retryability, Retryability::AutoRetryable);
    assert!(engine.transport().requests().is_empty());
    let row = engine
        .store()
        .action_request("direct", &id)
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "approved", "store fault consumed approval");
    assert_eq!(
        row.scope_outcome.as_deref(),
        Some(crate::scope::APPROVED_WAITING)
    );
}

#[test]
fn a_binding_read_failure_is_not_a_missing_credential() {
    let scratch = crate::test_scratch::Scratch::database("binding-store-failure");
    let (mut engine, _) = facade_test_engine_at(scratch.path().to_str().unwrap());
    let reservation = engine.authorize(facade_request()).unwrap();
    rusqlite::Connection::open(scratch.path())
        .unwrap()
        .execute(
            "UPDATE connections SET credential_binding = ?1 WHERE connection_id = 'connection'",
            [vec![0xffu8]],
        )
        .unwrap();
    engine.seams = None;
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "credential_store_unavailable"),
        "{outcome:?}"
    );
    assert_eq!(outcome.retryability, Retryability::AutoRetryable);
    assert!(engine.transport().requests().is_empty());
}

/// A request built by the trusted internal facade router passes the catalog
/// guard that refuses ordinary caller-built requests for facade-only actions.
/// It lives here because only this crate can construct a facade origin; the
/// refusal side is `ordinary_origin_cannot_be_promoted_by_caller_fields` in
/// tests/governance_seams.rs, and a guard that refuses everything fails this
/// test while leaving that one green.
#[test]
fn private_facade_origin_passes_catalog_fence() {
    let (engine, _) = facade_test_engine();
    let reservation = engine
        .authorize(facade_request())
        .expect("facade reaches reservation");
    assert!(reservation.authority_baseline.is_some());
    let expected = fingerprint(&serde_json::to_vec(&(b"ref".to_vec(), 1_i64)).unwrap());
    assert_eq!(reservation.credential_fingerprint, expected);
    assert!(engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .any(|row| row.reason_code == "credential_resolved"
            && row.credential_fingerprint.as_deref() == Some(expected.as_str())));
    assert!(engine.transport().requests().is_empty());
}

fn claimed_facade_reservation(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    seams: &Arc<TestHandleSeams>,
    nonce: &str,
    owner: &str,
    claimed_at: i64,
) -> Reservation {
    use crate::github::receipt::{Claim, Effect};
    let receipt = engine
        .store()
        .claim_github_receipt(
            "agent-a",
            nonce,
            "canonical-request-fingerprint",
            owner,
            &serde_json::json!({}),
            &[Effect {
                effect: "write_item".into(),
                dispatch_attempted_at: None,
                request_id: None,
                outcome: None,
            }],
            None,
            claimed_at,
            60,
        )
        .unwrap();
    assert!(matches!(receipt, Claim::Owned(_)));
    seams.0.lock().unwrap().receipt_store = Some(Arc::clone(engine.store()));
    engine
        .authorize(facade_origin::receipt_request(
            facade_request(),
            None,
            ReceiptClaim {
                agent_id: "agent-a".into(),
                request_nonce: nonce.into(),
                claim_owner: owner.into(),
                effect_index: 0,
            },
            crate::github::facade::effects::OwnershipProof::new("reaction", vec![]),
        ))
        .expect("facade receipt reservation")
}

#[test]
fn superseded_receipt_claim_cas_refuses_nonce_in_flight_without_transport() {
    let (engine, seams) = facade_test_engine();
    let now = crate::storage::now_ms();
    let reservation =
        claimed_facade_reservation(&engine, &seams, "old-nonce", "old-worker", now - 121_000);
    use crate::github::receipt::Claim;
    let takeover = engine
        .store()
        .claim_github_receipt(
            "agent-a",
            "old-nonce",
            "canonical-request-fingerprint",
            "new-worker",
            &serde_json::json!({}),
            &[],
            None,
            now,
            60,
        )
        .unwrap();
    assert!(matches!(takeover, Claim::Owned(_)));
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "nonce_in_flight"),
        "{outcome:?}"
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(seams.0.lock().unwrap().preparations, 0);
}

/// An App write must not fall through to anonymous transport if its authority
/// row disappears between the final authority check and credential preparation.
#[test]
fn facade_app_authority_loss_refuses_anonymous_dispatch_and_abandons_reservation() {
    let (engine, seams) = facade_test_engine();
    let reservation = claimed_facade_reservation(
        &engine,
        &seams,
        "lost-app-authority",
        "worker",
        crate::storage::now_ms(),
    );
    assert_eq!(reservation.origin, RequestOrigin::Facade);
    assert_eq!(reservation.risk, Risk::Write);
    assert!(reservation.authority_baseline.is_some());
    seams.0.lock().unwrap().lose_handle_before_preparation = true;

    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(&outcome.outcome, TransportOutcome::NotSent { code, .. } if code == "credential_missing"),
        "missing App authority must refuse, not dispatch anonymously: {outcome:?}"
    );
    assert_eq!(outcome.transmission, TransmissionState::NotSent);
    assert!(
        engine.transport().requests().is_empty(),
        "no vendor request may leave"
    );
    assert!(
        engine.transport().authorization_headers().is_empty(),
        "no authenticated or anonymous transport call may leave"
    );
    let state = seams.0.lock().unwrap();
    assert!(
        state.handle_missing,
        "the post-authorization loss must execute"
    );
    assert_eq!(state.preparations, 0);
    assert_eq!(
        state.abandoned_reservations,
        vec![reservation.reservation_id.clone()]
    );
    drop(state);
    let receipt = engine
        .store()
        .github_receipt("agent-a", "lost-app-authority")
        .unwrap()
        .unwrap();
    assert!(
        receipt.effects[0].dispatch_attempted_at.is_none(),
        "abandon must clear the persisted pre-transmit marker"
    );
    assert!(receipt.effects[0].request_id.is_none());
}

#[test]
fn facade_dispatch_audit_uses_the_receipts_request_fingerprint() {
    let (engine, seams) = facade_test_engine();
    let reservation = claimed_facade_reservation(
        &engine,
        &seams,
        "write-nonce",
        "worker",
        crate::storage::now_ms(),
    );
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(engine.transport().requests().len(), 1);
    let audit = engine.store().list_audit("direct").unwrap();
    let dispatched = audit
        .iter()
        .find(|row| row.reason_code == "dispatched")
        .unwrap();
    assert_eq!(
        dispatched.idempotency_key_fingerprint.as_deref(),
        Some("canonical-request-fingerprint")
    );
    assert_eq!(dispatched.app_handle_id.as_deref(), Some("handle-a"));
}

#[test]
fn receipt_claim_is_private_and_never_enters_transport_args() {
    let ordinary = AuthorizationRequest::new(
        "direct",
        "connection",
        "write_item",
        serde_json::json!({"_receipt": {"claim_owner":"forged"}}),
    );
    assert!(
        ordinary.receipt.is_none(),
        "caller arguments cannot mint a receipt claim"
    );
    assert_eq!(ordinary.origin(), RequestOrigin::Ordinary);
    assert!(ordinary.ownership_proof().is_none());
    let (engine, _) = facade_test_engine();
    engine.credential_source().set_default_response(
        crate::credentials::StubCredentialResponse::Success {
            payload: b"token".to_vec(),
            expires_at_ms: None,
            record_version: 1,
        },
    );
    let request = facade_origin::receipt_request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        )
        .with_bound_agent("agent-a", "handle-a"),
        None,
        ReceiptClaim {
            agent_id: "agent-a".into(),
            request_nonce: "nonce".into(),
            claim_owner: "worker".into(),
            effect_index: 0,
        },
        crate::github::facade::effects::OwnershipProof::new("reaction", vec![]),
    );
    let reservation = engine.authorize(request).expect("facade reservation");
    assert_eq!(reservation.receipt.as_ref().unwrap().claim_owner, "worker");
    assert_eq!(reservation.origin, RequestOrigin::Facade);
    assert_eq!(reservation.args, serde_json::json!({"repo":"o/r"}));
    engine.revalidate_and_dispatch(&reservation);
    let sent = engine.transport().requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].args, serde_json::json!({"repo":"o/r"}));
}

#[test]
fn facade_write_reservation_waits_for_ownership_reads() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().ownership_complete = false;
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::OwnershipProofMissing)
    );
    assert!(engine
        .store()
        .list_audit("direct")
        .unwrap()
        .iter()
        .all(|row| row.reason_code != "credential_resolved"));
    assert!(
        engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .any(|row| row.reason_code == "ownership_proof_missing"),
        "ownership refusal went unaudited"
    );
    seams.0.lock().unwrap().ownership_complete = true;
    assert!(engine.authorize(facade_request()).is_ok());
}

#[test]
fn authority_snapshot_read_failure_is_audited() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().generation_read_failure = true;
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::StoreFailure)
    );
    assert!(
        engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .any(|row| row.reason_code == "store_failure"),
        "snapshot refusal went unaudited"
    );
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn dispatch_canonicalization_failure_is_audited() {
    let (engine, _) = facade_test_engine();
    let mut reservation = engine.authorize(facade_request()).unwrap();
    reservation.decision_id = Some("decision".into());
    reservation.grant_hash = Some("hash".into());
    let outcome =
        jcs::with_sha256_failure_on_call(0, || engine.revalidate_and_dispatch(&reservation));
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. } if code == "grant_hash_mismatch")
    );
    assert!(
        engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .any(|row| row.reason_code == "grant_hash_mismatch"),
        "hash refusal went unaudited"
    );
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn unknown_risks_fail_closed_and_known_risks_keep_their_severity() {
    assert!(is_write("unexpected"));
    assert_eq!(action_severity("unexpected", Severity::S1), Severity::S4);
    assert_eq!(parse_risk("unexpected"), Risk::Destructive);
    for ceiling in ["read", "write", "destructive", "unexpected"] {
        assert!(!risk_within_ceiling("unexpected", ceiling));
    }
    for (text, risk, severity, write) in [
        ("read", Risk::Read, Severity::S1, false),
        ("write", Risk::Write, Severity::S2, true),
        ("destructive", Risk::Destructive, Severity::S3, true),
    ] {
        assert_eq!(known_risk(text), Some(risk));
        assert_eq!(parse_risk(text), risk);
        assert_eq!(is_write(text), write);
        assert_eq!(action_severity(text, Severity::S1), severity);
        assert!(risk_within_ceiling(text, "destructive"));
        assert!(!risk_within_ceiling(text, "unexpected"));
        assert_eq!(
            action_severity(text, Severity::S4),
            if write { Severity::S4 } else { Severity::S2 }
        );
    }
}

#[test]
fn wildcard_grantees_do_not_match_a_module_or_agent() {
    for agent in [None, Some("agent-a")] {
        let row = AgentGrantKey {
            connection_id: "conn",
            principal: "*",
            agent_id: agent,
        };
        let sought = AgentGrantKey {
            principal: "direct",
            ..row
        };
        assert!(!grant_key_matches(&row, &sought));
    }
}

#[test]
fn authority_projection_matches_catalog_and_missing_agent_refusals() {
    let (engine, _) = facade_test_engine();
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "projection".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: PROJECTION_PRINCIPAL.into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["write_item".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let projected = engine
        .would_ask(None, "flow", None, "github", "connection", "write_item")
        .unwrap_err();
    let mut real = facade_request();
    real.attributed_agent_id = None;
    real.bound_agent_handle = None;
    real.scope = Some(CallScope {
        owner: PROJECTION_PRINCIPAL.into(),
        scope_ref: "grant-projection".into(),
        scope_epoch: 0,
        kind: None,
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: Some("flow".into()),
        delegates: false,
        owner_authorized: true,
    });
    let actual = engine.authorize(real).unwrap_err();
    assert_eq!(projected.reason_code(), actual.reason_code());
    assert_eq!(projected.reason_code(), "agent_grant_absent");
    for status in ["quarantined", "disabled"] {
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        engine
            .store()
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".into(),
                principal: "direct".into(),
                name: "write_item".into(),
                title: action.title,
                schema: action.schema,
                schema_hash: action.schema_hash,
                risk: action.risk,
                severity: action.severity,
                ask_first: action.ask_first,
                status: status.into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        let projected = engine
            .would_ask(
                Some("agent-a"),
                "flow",
                None,
                "github",
                "connection",
                "write_item",
            )
            .unwrap_err();
        let actual = engine.authorize(facade_request()).unwrap_err();
        assert_eq!(projected.reason_code(), actual.reason_code(), "{status}");
        assert!(projected.reason_code().starts_with("catalog_action_"));
    }
}

#[test]
fn wrong_owner_module_grant_refuses_despite_valid_agent_grant() {
    let scratch = crate::test_scratch::Scratch::database("governance-module-owner");
    let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
    {
        let mut state = seams.0.lock().unwrap();
        state.module_owner = "another-owner".into();
        assert!(state.module && state.agent);
        assert_eq!(state.agent_owner, "direct");
    }
    let denial = engine.authorize(facade_request()).unwrap_err();
    assert_eq!(denial, Denial::Grant(GrantDenial::Missing));
    assert_eq!(denial.reason_code(), "grant_missing");
    let rows = engine.store().list_audit("direct").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason_code, "grant_missing");
    assert_eq!(rows[0].gate.as_deref(), Some("grant"));
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let reservations: i64 = db
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reservations, 0);
    assert!(engine.transport().requests().is_empty());
    assert_eq!(seams.0.lock().unwrap().preparations, 0);
}

#[test]
fn facade_agent_grant_and_policy_are_enforced() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().agent = false;
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Grant(GrantDenial::Missing))
    );
    seams.0.lock().unwrap().agent = true;
    let other_agent = facade_origin::request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        )
        .with_bound_agent("agent-b", "handle-b"),
        None,
    );
    assert_eq!(
        engine.authorize(other_agent),
        Err(Denial::Grant(GrantDenial::Missing))
    );
    seams.0.lock().unwrap().module = false;
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Grant(GrantDenial::Missing))
    );
    let mut state = seams.0.lock().unwrap();
    state.module = true;
    state.module_owner = "other".into();
    state.agent_owner = "other".into();
    drop(state);
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Grant(GrantDenial::Missing))
    );
    let mut state = seams.0.lock().unwrap();
    state.module_owner = "direct".into();
    state.agent_owner = "direct".into();
    state.module_effect = Some("block".into());
    drop(state);
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Policy(PolicyDenial::Blocked))
    );
}

fn facade_request_for(action: &str) -> AuthorizationRequest {
    facade_origin::request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            action,
            serde_json::json!({"repo":"o/r"}),
        )
        .with_bound_agent("agent-a", "handle-a"),
        None,
    )
}

fn add_write_action(engine: &GovernanceEngine<StubCredentialSource, MockTransport>, name: &str) {
    let schema = serde_json::json!({"type":"object"});
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".into(),
            principal: "direct".into(),
            name: name.into(),
            title: None,
            schema: schema.clone(),
            schema_hash: jcs::jcs_sha256(&schema).unwrap(),
            risk: "write".into(),
            severity: "S2".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
}

// Grants are additive. An imported agent holds one row per granted action,
// so the row that happens to sort first must not decide for the others.
#[test]
fn facade_agent_rows_for_different_actions_each_authorize_their_own_action() {
    let (engine, seams) = facade_test_engine();
    add_write_action(&engine, "write_other");
    seams.0.lock().unwrap().agent_rows = Some(vec![
        (vec!["write_other"], None),
        (vec!["write_item"], None),
    ]);
    engine
        .authorize(facade_request_for("write_item"))
        .expect("second agent row authorizes write_item");
    engine
        .authorize(facade_request_for("write_other"))
        .expect("first agent row authorizes write_other");
}

#[test]
fn facade_module_rows_for_different_actions_each_authorize_their_own_action() {
    let (engine, seams) = facade_test_engine();
    add_write_action(&engine, "write_other");
    seams.0.lock().unwrap().module_rows = Some(vec![
        (vec!["write_other"], None),
        (vec!["write_item"], None),
    ]);
    engine
        .authorize(facade_request_for("write_item"))
        .expect("second module row authorizes write_item");
    engine
        .authorize(facade_request_for("write_other"))
        .expect("first module row authorizes write_other");
}

#[test]
fn facade_agent_grant_expired_row_beside_a_live_row_still_allows() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().agent_rows = Some(vec![
        (vec!["write_item"], Some(1)),
        (vec!["write_item"], None),
    ]);
    engine
        .authorize(facade_request())
        .expect("the live row authorizes despite the expired one");
}

#[test]
fn facade_agent_grant_only_expired_row_naming_the_action_reports_expiry() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().agent_rows = Some(vec![
        (vec!["write_other"], None),
        (vec!["write_item"], Some(1)),
    ]);
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Grant(GrantDenial::Expired))
    );
}

#[test]
fn facade_agent_rows_that_do_not_name_the_action_refuse_action_selector() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().agent_rows = Some(vec![
        (vec!["write_other"], None),
        (vec!["write_third"], None),
    ]);
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Grant(GrantDenial::ActionSelector))
    );
}

#[test]
fn facade_policy_matrix_is_enforced_on_authorize() {
    for (module, agent, expected) in [
        (None, None, "allow"),
        (Some("allow"), Some("ask_first"), "ask_first"),
        (Some("ask_first"), Some("allow"), "ask_first"),
        (Some("block"), Some("allow"), "block"),
        (Some("allow"), Some("block"), "block"),
    ] {
        let (engine, seams) = facade_test_engine();
        let mut state = seams.0.lock().unwrap();
        state.module_effect = module.map(str::to_owned);
        state.agent_effect = agent.map(str::to_owned);
        drop(state);
        let outcome = engine.authorize(facade_request());
        match expected {
            "allow" => assert!(outcome.is_ok()),
            "ask_first" => {
                assert_eq!(outcome, Err(Denial::Policy(PolicyDenial::ApprovalMissing)))
            }
            "block" => assert_eq!(outcome, Err(Denial::Policy(PolicyDenial::Blocked))),
            _ => unreachable!(),
        }
    }
}

#[test]
fn catalog_default_ask_first_survives_agent_allow_without_module_policy() {
    let (engine, seams) = facade_test_engine();
    let schema = serde_json::json!({"type":"object"});
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".into(),
            principal: "direct".into(),
            name: "write_item".into(),
            title: None,
            schema: schema.clone(),
            schema_hash: jcs::jcs_sha256(&schema).unwrap(),
            risk: "write".into(),
            severity: "S2".into(),
            ask_first: true,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    seams.0.lock().unwrap().agent_effect = Some("allow".into());
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Policy(PolicyDenial::ApprovalMissing))
    );
    assert!(engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
}

#[test]
fn facade_ask_first_without_receipt_approval_writes_no_action_request() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().agent_effect = Some("ask_first".into());
    assert_eq!(
        engine.authorize(facade_request()),
        Err(Denial::Policy(PolicyDenial::ApprovalMissing))
    );
    let rows = engine.store().list_audit("direct").unwrap();
    assert!(rows.iter().any(|row| row.reason_code == "approval_missing"));
    assert!(engine
        .store()
        .list_action_requests("direct")
        .unwrap()
        .is_empty());
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn receipt_approval_checks_agent_without_catalog_args_snapshot() {
    let (engine, seams) = facade_test_engine();
    seams.0.lock().unwrap().agent_effect = Some("ask_first".into());
    seams.0.lock().unwrap().approval = Some(ReceiptApprovalRow {
        action_request_id: "approved".into(),
        agent_id: "agent-a".into(),
        status: "approved".into(),
        expires_at_ms: crate::storage::now_ms() + 30_000,
    });
    let approval = ReceiptApproval {
        action_request_id: "approved".into(),
        agent_id: "agent-a".into(),
    };
    let request = facade_origin::request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r", "catalog": "different"}),
        )
        .with_bound_agent("agent-a", "handle-a"),
        Some(approval.clone()),
    );
    assert!(engine.authorize(request).is_ok());
    seams.0.lock().unwrap().approval.as_mut().unwrap().agent_id = "agent-b".into();
    let request = facade_origin::request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        )
        .with_bound_agent("agent-a", "handle-a"),
        Some(approval),
    );
    assert_eq!(
        engine.authorize(request),
        Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch))
    );
    let mut state = seams.0.lock().unwrap();
    state.approval.as_mut().unwrap().agent_id = "agent-a".into();
    state.module_effect = Some("block".into());
    drop(state);
    let request = facade_origin::request(
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        )
        .with_bound_agent("agent-a", "handle-a"),
        Some(ReceiptApproval {
            action_request_id: "approved".into(),
            agent_id: "agent-a".into(),
        }),
    );
    assert_eq!(
        engine.authorize(request),
        Err(Denial::Policy(PolicyDenial::Blocked))
    );
}

#[test]
fn policy_hash_change_after_reservation_refuses_transmission() {
    let (engine, seams) = facade_test_engine();
    let reservation = engine.authorize(facade_request()).unwrap();
    seams.0.lock().unwrap().module_effect = Some("block".into());
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "stale_authority{policy_changed}")
    );
    assert!(engine.transport().requests().is_empty());
}

#[test]
fn handle_provider_auth_failure_reports_only_401() {
    let (engine, seams) = facade_test_engine();
    engine.credential_source().set_default_response(
        crate::credentials::StubCredentialResponse::Success {
            payload: b"token".to_vec(),
            expires_at_ms: None,
            record_version: 1,
        },
    );
    engine
        .transport()
        .set_response(crate::transport::MockResponse::VendorError {
            code: "http_403".into(),
            message: "permission denied".into(),
        });
    let reservation = engine.authorize(facade_request()).unwrap();
    engine.revalidate_and_dispatch(&reservation);
    assert!(engine.credential_source().auth_failure_reports().is_empty());
    engine
        .transport()
        .set_response(crate::transport::MockResponse::VendorError {
            code: "http_401".into(),
            message: "unauthorized".into(),
        });
    let reservation = engine.authorize(facade_request()).unwrap();
    engine.revalidate_and_dispatch(&reservation);
    assert_eq!(seams.0.lock().unwrap().auth_failures, 1);
    assert_eq!(engine.transport().requests().len(), 2);
}

#[test]
fn authority_changes_and_claim_marker_stop_transmission() {
    let (engine, seams) = facade_test_engine();
    let reservation = engine.authorize(facade_request()).unwrap();
    seams.0.lock().unwrap().handle.credential_generation += 1;
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "stale_authority{credential_rotated}")
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(seams.0.lock().unwrap().preparations, 0);
    let reservation = engine.authorize(facade_request()).unwrap();
    {
        let mut state = seams.0.lock().unwrap();
        state.module = false;
        state.handle.credential_generation += 1;
    }
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "stale_authority{module_grant_revoked}")
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(seams.0.lock().unwrap().preparations, 0);
    seams.0.lock().unwrap().module = true;
    engine.credential_source().set_default_response(
        crate::credentials::StubCredentialResponse::Success {
            payload: b"token".to_vec(),
            expires_at_ms: None,
            record_version: 1,
        },
    );
    let reservation = engine.authorize(facade_request()).unwrap();
    seams.0.lock().unwrap().marker = false;
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "aborted_stale_authorization")
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(seams.0.lock().unwrap().preparations, 0);
}

fn hash_test_engine() -> GovernanceEngine<StubCredentialSource, MockTransport> {
    hash_test_engine_at(":memory:")
}

fn hash_test_engine_at(path: &str) -> GovernanceEngine<StubCredentialSource, MockTransport> {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("governance-hash-test-{}", new_request_id()),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open hash test store"));
    store
        .insert_connection(
            "direct",
            "connection",
            "mock",
            "active",
            &serde_json::json!({"write_enabling":["repo"]}),
        )
        .expect("insert connection");
    let schema = serde_json::json!({"type": "object"});
    let schema_hash = jcs::jcs_sha256(&schema).expect("test schema is JCS-compatible");
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "write_item".to_string(),
            title: None,
            schema,
            schema_hash,
            risk: "write".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("insert action");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["write_item".to_string()],
            authority_kind: AUTHORITY_INVOKE.to_string(),
            expires_at: None,
        })
        .expect("insert grant");
    install_system_manifest(&store, "mock", "S1");
    GovernanceEngine::new(
        store,
        Arc::new(StubCredentialSource::default()),
        Arc::new(MockTransport::default()),
    )
}

/// Install a reviewed system manifest for `app_key` at `tier`. Severity
/// reads the app's tier from it, and an app without one is gated at the
/// strongest tier, so every fixture app needs one.
fn install_system_manifest(store: &PlexusStore, app_key: &str, tier: &str) {
    let manifest = crate::ingest_value(serde_json::json!({
            "schema_version": 1,
            "key": app_key,
            "name": app_key,
            "description": "governance unit-test vendor",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "in-process tests",
            "tier": tier,
            "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": ["repo"]},
            "actions_baseline": [{"name": "write_item", "risk": "write", "input_schema":{"type":"object","properties":{"repo":{"type":"string"}}}}],
            "defaults": {"ask_first_risk": ["write", "destructive"], "rate_limit": {"calls_per_min": 30}},
            "availability": "ga"
        }))
        .expect("test manifest ingests");
    store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
        .expect("store test manifest");
}

#[test]
fn authorization_returns_store_failure_when_argument_hashing_fails() {
    let engine = hash_test_engine();
    let result = jcs::with_sha256_failure_on_call(0, || {
        engine.authorize(AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"team": "core"}),
        ))
    });
    assert_eq!(result, Err(Denial::StoreFailure));
}

#[test]
fn approval_comparison_reaches_credentials_without_hashing_snapshot() {
    let engine = hash_test_engine();
    let args = serde_json::json!({"repo": "core"});
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .expect("query action")
        .expect("action exists");
    let request_id = engine
        .store()
        .create_action_request(
            "direct",
            "connection",
            "write_item",
            &args,
            &action.schema_hash,
            "direct",
            crate::storage::now_ms() + 60_000,
            None,
            None,
        )
        .expect("create approved request");
    assert!(engine
        .store()
        .decide_action_request("direct", &request_id, true, "operator")
        .expect("approve request"));
    let request = AuthorizationRequest::new("direct", "connection", "write_item", args)
        .approved_from(request_id);

    let result = jcs::with_sha256_failure_on_call(1, || engine.authorize(request));
    assert_eq!(result, Err(Denial::Credential(CredentialDenial::Missing)));
}

#[test]
fn reservation_argument_mismatch_aborts_before_dispatch() {
    let engine = hash_test_engine();
    let reservation = Reservation {
        reservation_id: "reservation".to_string(),
        principal: "direct".to_string(),
        acting_principal: "direct".to_string(),
        actor: "direct".to_string(),
        attributed_agent_id: None,
        bound_agent_handle: None,
        connection_id: "connection".to_string(),
        app_key: "mock".to_string(),
        action: "write_item".to_string(),
        args: serde_json::json!({"team": "core"}),
        approved_args: serde_json::json!({"team": "other"}),
        grant_id: "grant".to_string(),
        approved_args_hash: "sha256:approved".to_string(),
        args_snapshot_hash: "sha256:approved".to_string(),
        schema_hash: "sha256:schema".to_string(),
        risk: Risk::Write,
        severity: Severity::S2,
        snapshot: SnapshotGenerations {
            connection: 1,
            catalog_action: 1,
            grant: 1,
            policy: 0,
            policy_id: None,
        },
        expires_at_ms: crate::storage::now_ms() + 60_000,
        request_id: "request".to_string(),
        credential_fingerprint: "credential:test".to_string(),
        decision_id: None,
        grant_hash: None,
        intent_id: None,
        authority_baseline: None,
        receipt: None,
        origin: RequestOrigin::Ordinary,
        scope: None,
        relay_origin: None,
        on_behalf_of_agent: None,
        agent_grant: None,
        approval_scope: None,
    };

    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert_eq!(outcome.transmission, TransmissionState::NotSent);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization"
    ));
    assert!(engine.transport().requests().is_empty());
}

/// GitHub treats owner and repository names as case-insensitive, and its
/// connections store those filters in lowercase. Accept a mixed-case name
/// for the same repository, but refuse a different repository. Keep exact
/// matching for other vendors' filter values.
#[test]
fn github_owner_and_repo_filters_match_case_insensitively() {
    let engine = hash_test_engine_at(":memory:");
    let store = engine.store();
    let filters = serde_json::json!({
        "values": {"owner": "cortexkit", "repo": ["aft"]},
        "write_enabling": ["owner", "repo"]
    });
    store
        .insert_connection("direct", "gh", "github_rest", "active", &filters)
        .expect("github connection");
    store
        .insert_connection("direct", "other", "mock", "active", &filters)
        .expect("non-github connection");
    let github = store.connection("direct", "gh").unwrap().unwrap();
    let other = store.connection("direct", "other").unwrap().unwrap();
    let write = store
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    let mixed_case = serde_json::json!({"owner": "CortexKit", "repo": "AFT"});
    assert_eq!(
        resource_denial(&github, &write, &mixed_case),
        None,
        "a mixed-case GitHub name must pass its lowercase filter"
    );
    assert_eq!(
        resource_denial(
            &github,
            &write,
            &serde_json::json!({"owner": "CortexKit", "repo": "Plexus"})
        ),
        Some(ResourceDenial::ValueNotAllowed("repo".into())),
        "another repository is still refused"
    );
    assert_eq!(
        resource_denial(&other, &write, &mixed_case),
        Some(ResourceDenial::ValueNotAllowed("owner".into())),
        "filter values outside GitHub names stay exact"
    );
}

#[test]
fn an_unknown_severity_string_gates_at_the_strongest_tier() {
    let path = crate::test_scratch::Scratch::database("unknown-tier");
    let engine = hash_test_engine_at(path.to_str().unwrap());
    let action = engine
        .store()
        .catalog_action("direct", "connection", "write_item")
        .unwrap()
        .unwrap();
    let db = rusqlite::Connection::open(&*path).unwrap();
    for tier in ["S5", "", "s1", "S1", "S2", "S3", "S4"] {
        db.execute("UPDATE app_manifests SET manifest_json=json_set(manifest_json,'$.tier',?1),content_hash=?1", [tier]).unwrap();
        let expected = match tier {
            "S1" | "S2" => Severity::S2,
            "S3" => Severity::S3,
            _ => Severity::S4,
        };
        assert_eq!(
            effective_severity(&action, "mock", engine.store()).unwrap(),
            expected,
            "{tier}"
        );
    }
    db.execute("DELETE FROM app_manifests", []).unwrap();
    assert_eq!(
        effective_severity(&action, "mock", engine.store()).unwrap(),
        Severity::S4
    );
    db.execute("DROP TABLE app_manifests", []).unwrap();
    assert!(
        effective_severity(&action, "mock", engine.store()).is_err(),
        "store errors must not become S4"
    );
}

/// A ROUTING failure and a VAULT failure must not render as the same code.
///
/// Both are transient credential failures, and both used to surface as
/// `credential_transient` — so an operator could not tell "the vault is
/// briefly locked, wait" from "this module is dialling a credential-module
/// id that no longer answers, fix the config". The second is invisible
/// precisely when it matters: credential resolution refuses rather than
/// degrades, so a stale route target produces a denial that reads like a
/// policy decision.
///
/// Asserts the codes are DISTINCT rather than pinning their spellings, so
/// a later rename of a code still passes while a collapse fails.
///
/// Mutation-proved: mapping all three variants back to one string fails
/// this test.
#[test]
fn transient_credential_failures_are_distinguishable() {
    let route = Denial::Credential(CredentialDenial::Transient(
        TransientCredentialError::RefreshFailed,
    ));
    let locked = Denial::Credential(CredentialDenial::Transient(
        TransientCredentialError::VaultLocked,
    ));
    let overflow = Denial::Credential(CredentialDenial::Transient(
        TransientCredentialError::ContextOverflow,
    ));

    let codes = [
        route.reason_code(),
        locked.reason_code(),
        overflow.reason_code(),
    ];
    let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "each transient credential failure needs its own operator-visible code, got {codes:?}"
    );

    // The routing one is named specifically, because it is the case a
    // reader must be able to act on: it means our route target is wrong,
    // not that the vault is having a moment.
    assert_eq!(route.reason_code(), "credential_route_failed");

    // Still terminal for this attempt, and still a credential-gate denial:
    // naming the cause must not change the authority semantics.
    assert_eq!(gate_for_denial(&route), "credential");
}

#[test]
fn denials_are_terminal_and_typed() {
    let denial = Denial::ResourceFilter(ResourceDenial::WriteFiltersAbsent);
    assert!(denial.terminal());
    assert_eq!(denial.retryability(), Retryability::Terminal);
    assert_eq!(denial.reason_code(), "write_filters_absent");
}

/// Two request IDs minted back to back, as an agent write and a background
/// poll can be, must differ: calls sharing an ID interleave their audit
/// journal rows and become indistinguishable there. IDs are random bytes
/// (`storage::new_id`) with no clock component, so this holds however the
/// clock moves; `request_ids_large_batch_are_all_distinct` covers many
/// mints at once.
#[test]
fn back_to_back_request_ids_are_distinct_and_well_formed() {
    let id1 = new_request_id();
    let id2 = new_request_id();
    assert_ne!(id1, id2, "back-to-back request IDs must not collide");
    for id in [&id1, &id2] {
        assert!(
            id.starts_with("req_"),
            "request ID must retain req_ prefix: {id}"
        );
        assert_eq!(
            id.len(),
            28,
            "request ID must be 28 characters (req_ + 24 hex)"
        );
    }
}

/// Two authorization requests built back to back (such as an agent write
/// and a poller read on different connections) receive distinct IDs.
#[test]
fn back_to_back_authorization_requests_receive_distinct_ids() {
    let write_req = AuthorizationRequest::new(
        "agent",
        "conn-example-rest",
        "add_reaction",
        serde_json::json!({"reaction": "eyes"}),
    );
    let poll_req = AuthorizationRequest::new(
        "poll",
        "conn-github-prs",
        "list_pull_requests",
        serde_json::json!({}),
    )
    .for_poll("sub-prs");
    assert_ne!(
        write_req.request_id, poll_req.request_id,
        "authorization requests built back to back must not share an ID"
    );
}

/// Mint a large batch of request IDs and assert that all generated IDs are distinct.
#[test]
fn request_ids_large_batch_are_all_distinct() {
    use std::collections::HashSet;
    const BATCH_SIZE: usize = 10_000;
    let mut seen = HashSet::with_capacity(BATCH_SIZE);
    for _ in 0..BATCH_SIZE {
        let id = new_request_id();
        assert!(
            id.starts_with("req_"),
            "request ID must retain req_ prefix: {id}"
        );
        assert_eq!(
            id.len(),
            28,
            "request ID must be 28 characters (req_ + 24 hex)"
        );
        assert!(
            seen.insert(id),
            "duplicate request ID observed in batch of {BATCH_SIZE}"
        );
    }
    assert_eq!(seen.len(), BATCH_SIZE);
}

/// Facade receipts persist `policy_effect_hash`, so a change to its inputs,
/// their order or their encoding would make every in-flight receipt refuse
/// `policy_changed`. The literals are SHA-256 of the JCS text, computed
/// independently of plexus.
#[test]
fn policy_effect_hash_matches_the_persisted_receipt_values() {
    for (module, agent, ask_first, expected) in [
        (
            None,
            None,
            false,
            "sha256:d0c06f5cabaeb2e06ebef933184a33727cb40e6e0b7d71c6b1e3ccba0cd5beb4",
        ),
        (
            None,
            None,
            true,
            "sha256:1cc61e13539ce66b9f6920e5f6567f18d1259b5cc4848ff5f198fba2a7c5a01a",
        ),
        (
            Some("allow"),
            None,
            false,
            "sha256:872858286cc8f048deb4244f23f7a1a0416478deb2f119f0fec6969b8fe87374",
        ),
        (
            Some("ask_first"),
            Some("block"),
            true,
            "sha256:967e9c4007e549c2d3ba6c6fd078440b31d13ce1e3e798a0c1f9c6ed8ec21875",
        ),
        (
            Some("block"),
            Some("ask_first"),
            false,
            "sha256:1e4f0c067f751469ccfb5c66fdab99164eda341bb592a702e4b656b80bed0711",
        ),
        (
            None,
            Some("allow"),
            true,
            "sha256:b84170c757f2bbbd1036a49de37e5d4216be547318141de37ce52c1c7cb1cc69",
        ),
    ] {
        assert_eq!(
            policy_effect_hash(module, agent, ask_first).unwrap(),
            expected,
            "module={module:?} agent={agent:?} ask_first={ask_first}"
        );
    }
}

/// The typed comparator and the facade's receipt comparator share
/// `AUTHORITY_DIMENSIONS`; this pins that the typed one checks the same
/// dimensions in the same order and names the same refusals.
#[test]
fn typed_authority_comparison_follows_the_shared_dimension_order() {
    let original = AuthorityBaseline {
        app_handle_generation: 1,
        repo_binding_generation: 1,
        credential_generation: 1,
        handle_enabled: true,
        agent_grant_generation: 1,
        module_grant_generation: 1,
        policy_effect_hash: "sha256:before".into(),
    };
    let moved = |field: &str| {
        let mut current = original.clone();
        match field {
            "handle_enabled" => current.handle_enabled = false,
            "repo_binding_generation" => current.repo_binding_generation += 1,
            "agent_grant_generation" => current.agent_grant_generation += 1,
            "module_grant_generation" => current.module_grant_generation += 1,
            "policy_effect_hash" => current.policy_effect_hash = "sha256:after".into(),
            "credential_generation" => current.credential_generation += 1,
            "app_handle_generation" => current.app_handle_generation += 1,
            other => panic!("dimension {other} has no typed field"),
        }
        current
    };
    let apply = |current: &mut AuthorityBaseline, from: &AuthorityBaseline| {
        if !from.handle_enabled {
            current.handle_enabled = false;
        }
        current.repo_binding_generation = current
            .repo_binding_generation
            .max(from.repo_binding_generation);
        current.agent_grant_generation = current
            .agent_grant_generation
            .max(from.agent_grant_generation);
        current.module_grant_generation = current
            .module_grant_generation
            .max(from.module_grant_generation);
        if from.policy_effect_hash != original.policy_effect_hash {
            current.policy_effect_hash = from.policy_effect_hash.clone();
        }
        current.credential_generation = current
            .credential_generation
            .max(from.credential_generation);
        current.app_handle_generation = current
            .app_handle_generation
            .max(from.app_handle_generation);
    };
    for (index, (field, refusal)) in AUTHORITY_DIMENSIONS.iter().enumerate() {
        assert_eq!(
            compare_authority_baseline(&original, &moved(field)),
            Err(*refusal),
            "{field} alone"
        );
        // Moving every later dimension too must still name this one.
        let mut current = moved(field);
        for (later, _) in &AUTHORITY_DIMENSIONS[index + 1..] {
            apply(&mut current, &moved(later));
        }
        assert_eq!(
            compare_authority_baseline(&original, &current),
            Err(*refusal),
            "{field} with every later dimension"
        );
    }
    assert_eq!(compare_authority_baseline(&original, &original), Ok(()));
}

/// Every audit row about a reservation starts from `for_reservation`; this pins
/// the fields it fills and that the bound handle is recorded as the app handle
/// for facade calls only.
#[test]
fn reservation_audit_rows_record_the_app_handle_only_for_facade_calls() {
    let mut reservation = Reservation {
        reservation_id: "reservation".to_string(),
        principal: "owner".to_string(),
        acting_principal: "caller".to_string(),
        actor: "actor".to_string(),
        attributed_agent_id: Some("agent-1".to_string()),
        bound_agent_handle: Some("handle-1".to_string()),
        connection_id: "connection".to_string(),
        app_key: "github".to_string(),
        action: "write_item".to_string(),
        args: serde_json::json!({}),
        approved_args: serde_json::json!({}),
        grant_id: "grant".to_string(),
        approved_args_hash: "sha256:approved".to_string(),
        args_snapshot_hash: "sha256:approved".to_string(),
        schema_hash: "sha256:schema".to_string(),
        risk: Risk::Write,
        severity: Severity::S2,
        snapshot: SnapshotGenerations {
            connection: 1,
            catalog_action: 1,
            grant: 1,
            policy: 0,
            policy_id: None,
        },
        expires_at_ms: 0,
        request_id: "request".to_string(),
        credential_fingerprint: "credential:test".to_string(),
        decision_id: None,
        grant_hash: None,
        intent_id: None,
        authority_baseline: None,
        receipt: None,
        origin: RequestOrigin::Facade,
        scope: None,
        relay_origin: None,
        on_behalf_of_agent: None,
        agent_grant: None,
        approval_scope: None,
    };
    let expected = |app_handle_id: Option<&str>| AuditRecord {
        principal: "owner".to_string(),
        actor: "actor".to_string(),
        acting_principal: "caller".to_string(),
        agent_id: Some("agent-1".to_string()),
        app_handle_id: app_handle_id.map(str::to_owned),
        agent_handle: Some("handle-1".to_string()),
        connection_id: Some("connection".to_string()),
        app_key: Some("github".to_string()),
        action: Some("write_item".to_string()),
        risk: None,
        severity: None,
        decision: "deny".to_string(),
        reason_code: "stale".to_string(),
        gate: Some("dispatch".to_string()),
        args_redaction_summary: None,
        outcome: None,
        latency_ms: None,
        request_id: Some("request".to_string()),
        credential_fingerprint: None,
        provider_account_fingerprint: None,
        attempt_no: None,
        vendor_request_id: None,
        idempotency_key_fingerprint: None,
        response_class: None,
        reconciliation_of: None,
    };
    assert_eq!(
        AuditRecord::for_reservation(&reservation, "deny", "stale", "dispatch"),
        expected(Some("handle-1")),
        "a facade call records its bound handle as the app handle"
    );
    reservation.origin = RequestOrigin::Ordinary;
    assert_eq!(
        AuditRecord::for_reservation(&reservation, "deny", "stale", "dispatch"),
        expected(None),
        "an ordinary call records no app handle"
    );
}

/// An engine built for production judges expiry on the real wall clock. A
/// clock frozen when the engine was built would never reach a future expiry,
/// so grants, policies and approvals that should lapse would stay live, while
/// the tests that run on a clock they move would stay green.
#[test]
fn a_new_engine_reads_the_real_wall_clock() {
    let engine = ordinary_test_engine();
    let before = crate::storage::now_ms();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let read = engine.now_ms();
    assert!(
        read >= before + 5 && read <= crate::storage::now_ms(),
        "the engine's clock must be the real wall clock: read {read}, before {before}"
    );
}
