use super::*;
use plexus_core::credentials::{CkcredCredentialSource, CkcredRouteError, CkcredRoutePeer};
use plexus_core::{
    AuthorizationRequest, CatalogActionInput, GovernanceEngine, GrantInput, PolicyInput,
    TransportOutcome,
};
use std::sync::Mutex;

const CONNECTION: &str = "conn-retire-rest";
const ID: &str = "apikey:exa";
const HANDLE: &[u8] = b"test:ckh_rebind_test_bearer_canary";
const TOKEN: &[u8] = b"vault-byte-array-secret-canary";
const MISMATCH_TOKEN: &[u8] = b"wrong-credential-payload-canary";

#[derive(Default)]
struct Vault {
    calls: Mutex<Vec<(String, Value)>>,
    changed: std::sync::Condvar,
    refusal: Mutex<bool>,
    resolved_id: Mutex<Option<&'static str>>,
}

impl Vault {
    fn wait_for_401_report(&self, credential_id: &str) {
        let calls = self.calls.lock().unwrap();
        let has_401 = |calls: &Vec<(String, Value)>| {
            calls.iter().any(|(operation, params)| {
                operation == "credential.report_auth_failure"
                    && params["provider_status"] == 401
                    && params["credential_id"] == credential_id
            })
        };
        let (calls, _) = self
            .changed
            .wait_timeout_while(calls, std::time::Duration::from_secs(5), |calls| {
                !has_401(calls)
            })
            .unwrap();
        assert!(
            has_401(&calls),
            "known 401 report must reach the vault peer"
        );
    }
}

impl CkcredRoutePeer for Vault {
    fn call(&self, operation: &str, params: Value) -> Result<Value, CkcredRouteError> {
        self.calls
            .lock()
            .unwrap()
            .push((operation.into(), params.clone()));
        self.changed.notify_all();
        if *self.refusal.lock().unwrap() {
            return Ok(json!({"result": {"error": {"code": "forbidden"}}}));
        }
        match operation {
            "credential.get_scoped" => {
                assert!(params["credential_id"] == ID || params["credential_id"] == std::str::from_utf8(HANDLE).unwrap());
                let resolved_id = *self.resolved_id.lock().unwrap();
                let payload = if resolved_id.is_some() {
                    MISMATCH_TOKEN
                } else {
                    TOKEN
                };
                Ok(
                    json!({"result": {"credential_id": resolved_id.unwrap_or(params["credential_id"].as_str().unwrap()), "payload": payload,
                    "expires_at_ms": null, "record_version": 17}}),
                )
            }
            "credential.report_auth_failure" => Ok(json!({"result": {}})),
            _ => panic!("unexpected vault operation {operation}"),
        }
    }
}

struct Fixture {
    path: Scratch,
    state: Arc<ModuleState>,
    vault: Arc<Vault>,
    transport: Arc<MockTransport>,
    credentials: Arc<CkcredCredentialSource<Vault>>,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let (path, store, _) = two_connection_fixture_with_retire_status(label,"pending");
        let ticket = store
            .create_binding_ticket("direct", CONNECTION, HANDLE)
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        let schema = json!({"type": "object"});
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: CONNECTION.into(),
                principal: "direct".into(),
                name: "search".into(),
                title: None,
                schema: schema.clone(),
                schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
                risk: "read".into(),
                severity: "S0".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-rebind".into(),
                principal: "direct".into(),
                connection_id: CONNECTION.into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["search".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        store
            .insert_policy(&PolicyInput {
                policy_id: "policy-rebind".into(),
                principal: "direct".into(),
                connection_id: CONNECTION.into(),
                action_selector: "search".into(),
                effect: "allow".into(),
                expires_at: None,
            })
            .unwrap();
        let vault = Arc::new(Vault::default());
        let credentials = Arc::new(CkcredCredentialSource::new(vault.clone()));
        let transport = Arc::new(MockTransport::default());
        let mut runtime = runtime_for_test(store.clone());
        runtime.engine = GovernanceEngine::new(
            store,
            credentials.clone() as Arc<dyn plexus_core::CredentialSource>,
            transport.clone() as Arc<dyn plexus_core::Transport>,
        );
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });
        Self {
            path,
            state,
            vault,
            transport,
            credentials,
        }
    }

    fn rebind(&self, apply: bool) -> Value {
        management_call(
            &self.state,
            Principal::Direct,
            manifest::ADMIN_REBIND_CREDENTIAL_OP,
            json!({"connection_id": CONNECTION, "credential_id": ID, "apply": apply}),
        )
    }

    fn snapshot(&self) -> (Vec<u8>, i64, i64) {
        rusqlite::Connection::open(&self.path).unwrap().query_row(
            "SELECT credential_binding, generation,
                (SELECT COUNT(*) FROM audit_journal WHERE reason_code = 'ceremony_rebind_credential')
             FROM connections WHERE connection_id = ?1", [CONNECTION],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap()
    }

    fn reserve(&self) -> plexus_core::Reservation {
        self.state
            .runtime
            .engine
            .authorize(AuthorizationRequest::new(
                "direct",
                CONNECTION,
                "search",
                json!({}),
            ))
            .expect("authorize read")
    }

    fn dispatch(&self) {
        let result = self
            .state
            .runtime
            .engine
            .revalidate_and_dispatch(&self.reserve());
        assert!(
            matches!(result.outcome, TransportOutcome::Completed { .. }),
            "{result:?}"
        );
        assert_eq!(
            self.transport.authorization_headers().last().unwrap(),
            &[b"Bearer ".as_slice(), TOKEN].concat()
        );
    }
}

#[test]
fn reference_dispatch_reads_once_by_id_before_and_after_rebind() {
    let fixture = Fixture::new("reference-dispatch");
    fixture.dispatch();
    assert!(fixture
        .vault
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(op, _)| op == "credential.get_scoped"));
    assert_eq!(fixture.rebind(true)["result"]["applied"], true);
    fixture.vault.calls.lock().unwrap().clear();
    fixture.dispatch();
    assert_eq!(
        *fixture.vault.calls.lock().unwrap(),
        vec![("credential.get_scoped".into(), json!({"credential_id": ID}))]
    );
    fixture.dispatch();
    assert_eq!(
        fixture.vault.calls.lock().unwrap().len(),
        2,
        "no cross-dispatch cache"
    );
}

#[test]
fn rebind_preview_apply_generation_audit_and_next_dispatch() {
    let fixture = Fixture::new("reference-rebind");
    let before = fixture.snapshot();
    let preview = fixture.rebind(false);
    assert_eq!(preview["result"]["current_binding_kind"], "reference");
    assert_eq!(preview["result"]["credential_id"], ID);
    assert_eq!(preview["result"]["applied"], false);
    assert_eq!(fixture.snapshot(), before);
    assert!(fixture.vault.calls.lock().unwrap().is_empty());
    let old = fixture.reserve();
    fixture.vault.calls.lock().unwrap().clear();
    let applied = fixture.rebind(true);
    assert_eq!(applied["result"]["applied"], true, "{applied}");
    let after = fixture.snapshot();
    assert_ne!(after.0, before.0);
    assert_eq!(after.1, before.1 + 1);
    assert_eq!(after.2, before.2 + 1);
    assert_eq!(
        *fixture.vault.calls.lock().unwrap(),
        vec![("credential.get_scoped".into(), json!({"credential_id": ID}))]
    );
    let stale = fixture.state.runtime.engine.revalidate_and_dispatch(&old);
    assert!(
        matches!(stale.outcome, TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization")
    );
    assert!(fixture.transport.requests().is_empty());
    fixture.dispatch();
}

#[test]
fn rebind_proving_refusal_keeps_binding_byte_identical() {
    let fixture = Fixture::new("reference-refused");
    let before = fixture.snapshot();
    *fixture.vault.refusal.lock().unwrap() = true;
    let result = fixture.rebind(true);
    assert_eq!(
        result["error"]["code"], "credential_read_refused",
        "{result}"
    );
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("apikey:exa read grant to reserved:plexus"));
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(fixture.vault.calls.lock().unwrap().len(), 1);
}

#[test]
fn rebind_requires_direct_active_and_valid_id() {
    let fixture = Fixture::new("reference-validation");
    let before = fixture.snapshot();
    let denied = management_call(
        &fixture.state,
        Principal::Reserved {
            module_id: "aft".into(),
        },
        manifest::ADMIN_REBIND_CREDENTIAL_OP,
        json!({"connection_id": CONNECTION, "credential_id": ID, "apply": true}),
    );
    assert_eq!(denied["error"]["code"], "operator_authority_required");
    for id in [
        "",
        "apikey:",
        "apikey:exa\n",
        "apikey:exa:extra",
        "ckh_bearer",
    ] {
        let denied = management_call(
            &fixture.state,
            Principal::Direct,
            manifest::ADMIN_REBIND_CREDENTIAL_OP,
            json!({"connection_id": CONNECTION, "credential_id": id, "apply": true}),
        );
        assert_eq!(denied["error"]["code"], "invalid_request", "{denied}");
    }
    assert_eq!(fixture.snapshot(), before);
    fixture
        .state
        .store()
        .revoke_connection("direct", CONNECTION)
        .unwrap();
    assert_eq!(
        fixture.rebind(true)["error"]["code"],
        "connection_not_active"
    );
    assert!(fixture.vault.calls.lock().unwrap().is_empty());
}

#[test]
fn reference_ticket_and_debug_never_expose_bearer_bytes() {
    let fixture = Fixture::new("reference-enrollment");
    let binding = fixture
        .state
        .store()
        .connection_credential_binding_kind("direct", CONNECTION)
        .unwrap()
        .unwrap();
    assert_eq!(binding, "reference");
    let issued = management_call(
        &fixture.state,
        Principal::Direct,
        manifest::ADMIN_ISSUE_TICKET_OP,
        json!({"app_key": "exa_rest", "connection_id": "new-reference", "credential_id": ID}),
    );
    assert!(issued["error"].is_null(), "{issued}");
    fixture
        .state
        .store()
        .connect_with_ticket("direct", issued["result"]["ticket_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let binding = fixture
        .state
        .store()
        .connection_credential_binding_kind("direct", "new-reference")
        .unwrap()
        .unwrap();
    assert_eq!(binding, "reference");
    let rendered = format!("{issued} {}", fixture.rebind(false));
    assert!(!rendered.contains(std::str::from_utf8(HANDLE).unwrap()));
    assert!(!rendered.contains(std::str::from_utf8(TOKEN).unwrap()));
}

#[test]
fn reference_dispatch_reports_401_but_not_403_by_id() {
    let fixture = Fixture::new("reference-auth-status");
    assert_eq!(fixture.rebind(true)["result"]["applied"], true);
    fixture.vault.calls.lock().unwrap().clear();
    for code in ["http_403", "http_401"] {
        fixture
            .transport
            .set_response(plexus_core::MockResponse::VendorError {
                code: code.into(),
                message: "provider refused".into(),
            });
        let result = fixture
            .state
            .runtime
            .engine
            .revalidate_and_dispatch(&fixture.reserve());
        assert!(matches!(
            result.outcome,
            TransportOutcome::VendorFailed { .. }
        ));
    }
    // A mistaken 403 authentication classification is also reported as 401 by
    // the binding hook. Use a distinct later marker on the same queue rather
    // than letting that erroneous early report satisfy the completion wait.
    const BARRIER_ID: &str = "apikey:report-barrier";
    fixture
        .credentials
        .report_scoped_auth_failure(BARRIER_ID, 401);
    fixture.vault.wait_for_401_report(BARRIER_ID);
    fixture
        .vault
        .calls
        .lock()
        .unwrap()
        .retain(|(operation, params)| {
            !(operation == "credential.report_auth_failure"
                && params["credential_id"] == BARRIER_ID)
        });
    assert_eq!(
        *fixture.vault.calls.lock().unwrap(),
        vec![
            ("credential.get_scoped".into(), json!({"credential_id": ID})),
            ("credential.get_scoped".into(), json!({"credential_id": ID})),
            (
                "credential.report_auth_failure".into(),
                json!({"credential_id": ID, "provider_status": 401})
            ),
        ]
    );
}

#[test]
fn reference_rebind_rolls_back_when_audit_insert_fails() {
    let fixture = Fixture::new("reference-audit-atomic");
    let before = fixture.snapshot();
    rusqlite::Connection::open(&fixture.path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_rebind_audit BEFORE INSERT ON audit_journal
         WHEN NEW.reason_code = 'ceremony_rebind_credential'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
        )
        .unwrap();
    let result = fixture.rebind(true);
    assert!(!result["error"].is_null(), "{result}");
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn reference_binding_log_fixture() {
    logging::init_child();
    let fixture = Fixture::new("reference-logs");
    let _ = fixture.rebind(false);
    let result = fixture.rebind(true);
    assert_eq!(result["result"]["applied"], true);
    fixture.dispatch();
    *fixture.vault.refusal.lock().unwrap() = true;
    assert_eq!(
        fixture.rebind(true)["error"]["code"],
        "credential_read_refused"
    );
}

#[test]
fn reference_binding_real_logs_do_not_leak_bytes() {
    let stderr =
        module_diagnostic_output("tests::credential_rebind::reference_binding_log_fixture");
    assert!(
        !stderr.contains(std::str::from_utf8(HANDLE).unwrap()),
        "{stderr}"
    );
    assert!(
        !stderr.contains(std::str::from_utf8(TOKEN).unwrap()),
        "{stderr}"
    );
}

#[test]
fn rebind_preserves_app_handle_authority() {
    let fixture = Fixture::new("reference-app-handle");
    rusqlite::Connection::open(&fixture.path)
        .unwrap()
        .execute(
            "INSERT INTO github_app_handle (app_handle_id, agent_id, app_id, credential_reference,
             status, connection_principal, connection_id)
         VALUES ('bot', 'bot-agent', 1, 'github_app:bot', 'enabled', 'direct', ?1)",
            [CONNECTION],
        )
        .unwrap();
    let before = fixture.snapshot();
    assert_eq!(fixture.rebind(true)["error"]["code"], "invalid_request");
    assert!(!fixture
        .state
        .store()
        .rebind_credential_reference("direct", CONNECTION, before.1, ID)
        .unwrap());
    assert_eq!(fixture.snapshot(), before);
    assert!(fixture.vault.calls.lock().unwrap().is_empty());
}

fn assert_mismatched_payload_absent(rendered: &str) {
    for representation in [
        std::str::from_utf8(MISMATCH_TOKEN).unwrap().to_owned(),
        serde_json::to_string(MISMATCH_TOKEN).unwrap(),
        format!("{MISMATCH_TOKEN:?}"),
    ] {
        assert!(
            !rendered.contains(&representation),
            "mismatched credential bytes escaped"
        );
    }
}

#[test]
fn reference_dispatch_rejects_mismatched_resolved_id_without_sending_or_leaking() {
    // Run the real dispatch in a child so the parent can inspect its actual
    // credential/error logs, including anything emitted before the refusal.
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let stderr = module_diagnostic_output(
            "tests::credential_rebind::reference_dispatch_rejects_mismatched_resolved_id_without_sending_or_leaking",
        );
        assert_mismatched_payload_absent(&stderr);
        return;
    }
    logging::init_child();
    let fixture = Fixture::new("reference-mismatched-dispatch");
    assert_eq!(fixture.rebind(true)["result"]["applied"], true);
    *fixture.vault.resolved_id.lock().unwrap() = Some("apikey:github");
    fixture.vault.calls.lock().unwrap().clear();
    let result = fixture
        .state
        .runtime
        .engine
        .revalidate_and_dispatch(&fixture.reserve());
    assert_eq!(result.transmission, plexus_core::TransmissionState::NotSent);
    assert_eq!(result.retryability, plexus_core::Retryability::Terminal);
    // The dispatch API deliberately projects Permanent(Corrupt) as the public
    // credential_permanent code, without exposing the vault reply or token.
    assert!(
        matches!(&result.outcome, TransportOutcome::NotSent { code, message }
        if code == "credential_permanent" && message == "credential could not be resolved")
    );
    assert!(fixture.transport.requests().is_empty());
    assert!(fixture.transport.authorization_headers().is_empty());
    assert_eq!(
        *fixture.vault.calls.lock().unwrap(),
        vec![("credential.get_scoped".into(), json!({"credential_id": ID})),]
    );
    let reply = dispatch_response(result);
    assert_eq!(reply["result"]["transmission"], "not_sent");
    assert_eq!(reply["result"]["response"]["code"], "credential_permanent");
    assert_mismatched_payload_absent(&reply.to_string());
}

#[test]
fn rebind_rejects_mismatched_resolved_id_without_mutating_or_leaking() {
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let stderr = module_diagnostic_output(
            "tests::credential_rebind::rebind_rejects_mismatched_resolved_id_without_mutating_or_leaking",
        );
        assert_mismatched_payload_absent(&stderr);
        return;
    }
    logging::init_child();
    let fixture = Fixture::new("reference-mismatched-rebind");
    let before = fixture.snapshot();
    *fixture.vault.resolved_id.lock().unwrap() = Some("apikey:github");
    let result = fixture.rebind(true);
    assert_eq!(result["error"]["code"], "credential_read_refused");
    assert_eq!(result["error"]["class"], "permanent");
    assert_eq!(
        fixture.snapshot(),
        before,
        "binding, generation and audit must be unchanged"
    );
    assert!(fixture.transport.requests().is_empty());
    assert!(fixture.transport.authorization_headers().is_empty());
    assert_eq!(
        *fixture.vault.calls.lock().unwrap(),
        vec![("credential.get_scoped".into(), json!({"credential_id": ID})),]
    );
    assert_mismatched_payload_absent(&result.to_string());
}

#[test]
fn enrollment_handle_is_refused_by_name_without_writing_rows() {
    let fixture = Fixture::new("removed-handle-input");
    let before = fixture.snapshot();
    for handle in [json!("ckh_removed"), Value::Null, json!(42)] {
        let response = management_call(&fixture.state, Principal::Direct, manifest::ADMIN_ISSUE_TICKET_OP,
            json!({"app_key": "retire_rest", "connection_id": "must-not-exist", "handle": handle, "credential_id": ID}));
        assert_eq!(response["error"]["code"], "handle_bindings_removed", "{response}");
        assert!(response["error"]["message"].as_str().unwrap().contains("credential_id"));
        assert!(fixture.state.store().connection("direct", "must-not-exist").unwrap().is_none());
        assert_eq!(fixture.snapshot(), before);
    }
    assert!(fixture.vault.calls.lock().unwrap().is_empty());
}
