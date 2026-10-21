//! End-to-end acceptance checks at the public GitHub bot-request boundary.
//! Fleet-level shim and event-wake checks require other products and are not a gate for this crate.
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
#[path = "../support/scope.rs"]
mod scope_support;
use plexus_core::credentials::{
    CkcredCredentialSource, CkcredRouteError, CkcredRoutePeer, ResolvedCredential,
};
use plexus_core::github::credential::{HandleCredentialPreparer, HandleCredentialProvider};
use plexus_core::github::facade::bot_request_scoped;
use plexus_core::governance::GovernanceEngine;
use plexus_core::scope::CallScope;
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
use plexus_core::PlexusStore;
use rusqlite::Connection;
use scope_support::{delegating_scope, LiveScopeReader};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[path = "../support/facade_rows.rs"]
mod facade_rows;
#[path = "../support/logging.rs"]
mod logging;

/// The shipped reviewed GitHub REST manifest, parsed from its JSONC source.
fn github_manifest() -> plexus_core::AppManifest {
    let source = include_str!("../../../../catalog/github_rest.jsonc");
    let clean = subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
    plexus_core::ingest_value(serde_json::from_str(&clean).unwrap())
        .unwrap()
        .manifest
}

#[derive(Default)]
struct RecordingGithub {
    credential: Mutex<Vec<String>>,
    repository: Mutex<Vec<TransportRequest>>,
    comments: Mutex<Vec<String>>,
    after_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    before_write: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    comment_author: Mutex<Option<String>>,
    response_override: Mutex<Option<TransportResponse>>,
    credential_failure: std::sync::atomic::AtomicBool,
}
impl RecordingGithub {
    fn actions(&self) -> Vec<String> {
        self.repository
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.action.clone())
            .collect()
    }
    fn clear_contacts(&self) {
        self.credential.lock().unwrap().clear();
        self.repository.lock().unwrap().clear();
    }
    fn zero_contacts(&self) {
        assert!(
            self.credential.lock().unwrap().is_empty(),
            "handle credential preparation occurred"
        );
        assert!(
            self.repository.lock().unwrap().is_empty(),
            "repository API contacted"
        );
    }
}
impl Transport for RecordingGithub {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        let action = request.action.clone();
        if !action.starts_with("github.") {
            if let Some(hook) = self.before_write.lock().unwrap().take() {
                hook();
            }
        }
        if let Some(response) = self.response_override.lock().unwrap().clone() {
            self.repository.lock().unwrap().push(request);
            return response;
        }
        let response = match action.as_str() {
            "github.issue_comments.list" => {
                json!([{"id": 101, "user":{"login":"app-fixture[bot]","type":"Bot"}}])
            }
            "github.issue_comment.get" => {
                json!({"id":101,"user":{"login":self.comment_author.lock().unwrap().clone().unwrap_or_else(|| "app-fixture[bot]".into()),"type":"Bot"}})
            }
            "github.issue.get" => json!({"user":{"login":"app-fixture[bot]","type":"Bot"}}),
            _ => {
                if action == "add_issue_comment" {
                    self.comments
                        .lock()
                        .unwrap()
                        .push(request.args["body"].as_str().unwrap().to_owned());
                }
                // Shaped like GitHub's comment body: the reply may carry only
                // its html_url and id, never the author, text or node id.
                json!({"id":101,"node_id":"IC_101",
                    "html_url":"https://github.com/org/repo/issues/42#issuecomment-101",
                    "body":request.args["body"],
                    "user":{"login":"app-fixture[bot]","type":"Bot"}})
            }
        };
        self.repository.lock().unwrap().push(request);
        if action == "github.issue_comment.get" || action == "github.issue.get" {
            if let Some(hook) = self.after_read.lock().unwrap().take() {
                hook();
            }
        }
        TransportResponse::success(response)
    }
}
struct Token(Arc<RecordingGithub>);
impl HandleCredentialProvider for Token {
    fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
        self.0
            .credential
            .lock()
            .unwrap()
            .push("credential.prepare(app-fixture)".into());
        if self
            .0
            .credential_failure
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("credential_missing");
        }
        Ok(ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

/// The vault's end of the `credential.get_scoped` route, answering with the
/// reply it currently holds.
struct Vault(Mutex<Value>);
impl CkcredRoutePeer for Vault {
    fn call(&self, operation: &str, _: Value) -> Result<Value, CkcredRouteError> {
        assert_eq!(operation, "credential.get_scoped");
        Ok(self.0.lock().unwrap().clone())
    }
}

fn vault_error(class: &str) -> Value {
    json!({"result": {"error": {"code": "vault_says_no", "class": class}}})
}

fn vault_token(credential_id: &str) -> Value {
    json!({"result": {
        "payload": b"installation.token",
        "expires_at_ms": NOW + 3_600_000,
        "record_version": 1,
        "credential_id": credential_id,
    }})
}

const NOW: i64 = 1_700_000_100_000;

type Engine = GovernanceEngine<plexus_core::credentials::StubCredentialSource, RecordingGithub>;
// Fields drop in declaration order: the scratch guard is last so the store
// and engine close before it removes their directory.
struct Fixture {
    store: Arc<PlexusStore>,
    engine: Engine,
    github: Arc<RecordingGithub>,
    scope: CallScope,
    path: std::path::PathBuf,
    now: i64,
    _scratch: plexus_core::test_scratch::Scratch,
}
impl Fixture {
    fn new(actions: &[(&str, &str)]) -> Self {
        Self::with_provider(actions, |github| Arc::new(Token(github)))
    }
    /// The facade stack over the real `HandleCredentialPreparer`, reading from
    /// a vault that answers every `credential.get_scoped` with `reply`.
    fn with_vault(actions: &[(&str, &str)], reply: Value) -> Self {
        Self::with_shared_vault(actions, Arc::new(Vault(Mutex::new(reply))))
    }
    /// As `with_vault`, keeping the vault so a test can change its answer.
    fn with_shared_vault(actions: &[(&str, &str)], vault: Arc<Vault>) -> Self {
        Self::with_provider(actions, |_| {
            Arc::new(HandleCredentialPreparer::new(
                CkcredCredentialSource::new(vault),
                Arc::new(|| NOW),
            ))
        })
    }
    fn with_provider(
        actions: &[(&str, &str)],
        provider: impl FnOnce(Arc<RecordingGithub>) -> Arc<dyn HandleCredentialProvider>,
    ) -> Self {
        let scratch = plexus_core::test_scratch::Scratch::database("github-acceptance");
        let path = scratch.path().to_path_buf();
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "github-acceptance".into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .insert_connection(
                "operator",
                "conn-fixture",
                "github_rest",
                "active",
                &json!({}),
            )
            .unwrap();
        store
            .put_github_handle(&GithubHandle {
                app_handle_id: "app-fixture".into(),
                agent_id: "agent-fixture".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app-fixture".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: Some(1),
                connection_principal: "operator".into(),
                connection_id: "conn-fixture".into(),
            })
            .unwrap();
        store.bind_github_repo("org/repo", "app-fixture").unwrap();
        let db = Connection::open(&path).unwrap();
        // The shipped reviewed manifest is stored directly, so nothing is
        // seeded from it: the facade reads each governed call's declared
        // arguments from it, and each catalog row pins that action's reviewed
        // argument schema, as an imported handle connection does.
        let manifest = github_manifest();
        facade_rows::insert_reviewed_manifest(&db, &serde_json::to_string(&manifest).unwrap());
        let selectors =
            serde_json::to_string(&actions.iter().map(|(a, _)| *a).collect::<Vec<_>>()).unwrap();
        for (action, risk) in actions {
            let schema = manifest
                .actions_baseline
                .iter()
                .find(|declared| declared.name == *action)
                .and_then(|declared| declared.http.as_ref())
                .map_or_else(|| json!({}), |http| http.args_schema.clone());
            facade_rows::insert_catalog_action(&db, action, risk, &schema.to_string(), false);
        }
        for (grant, agent) in [("module", None), ("agent", Some("agent-fixture"))] {
            facade_rows::insert_invoke_grant(&db, grant, "reserved:aft", &selectors, agent);
        }
        let scope = delegating_scope("agent-fixture");
        let github = Arc::new(RecordingGithub::default());
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                plexus_core::credentials::StubCredentialSource::with_default_success(
                    b"fixture".to_vec(),
                ),
            ),
            github.clone(),
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(provider(github.clone())),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
        Self {
            now: plexus_core::now_ms(),
            _scratch: scratch,
            store,
            engine,
            github,
            scope,
            path,
        }
    }
    fn call(&self, scope: Option<&CallScope>, request: &Value, nonce: &str, now: i64) -> Value {
        checked_reply(bot_request_scoped(
            &self.store,
            &self.engine,
            "reserved:aft",
            scope,
            request,
            nonce,
            nonce,
            "worker",
            now,
        ))
    }
    fn request(&self, request: &Value, nonce: &str) -> Value {
        self.call(Some(&self.scope), request, nonce, self.now)
    }
    fn audit(&self, code: &str, gate: &str, agent: Option<&str>, handle: Option<&str>) {
        let rows = self.store.list_audit("reserved:aft").unwrap();
        let row = rows.last().unwrap();
        assert_eq!(row.action.as_deref(), Some("github.bot_request"));
        assert_eq!(row.request_id.as_deref(), Some("case"));
        assert_eq!(row.gate.as_deref(), Some(gate));
        assert_eq!(row.agent_id.as_deref(), agent);
        assert_eq!(row.app_handle_id.as_deref(), handle);
        assert_eq!(row.reason_code, code);
    }
    fn refusal(
        &self,
        scope: Option<&CallScope>,
        request: &Value,
        code: &str,
        gate: &str,
        agent: Option<&str>,
        handle: Option<&str>,
    ) {
        let reply = self.call(scope, request, "case", self.now);
        let mut expected = json!({"status":"refused","refusal_code":code});
        if matches!(code, "module_grant_absent" | "agent_grant_absent") {
            let detail = &reply["result"]["detail"];
            let layer = if code == "module_grant_absent" {
                "module"
            } else {
                "agent"
            };
            assert_eq!(detail["layer"], layer);
            assert_eq!(detail["connection"], "conn-fixture");
            assert_eq!(detail["action"], "add_issue_comment");
            assert_eq!(detail["cause"], "missing");
            assert!(!detail["grant_label"].as_str().unwrap().is_empty());
            let target =
                plexus_core::grant_refusal::GrantTarget::decode(detail["grant"].as_str().unwrap())
                    .unwrap();
            assert_eq!(
                target.grantee,
                if layer == "module" {
                    "reserved:aft"
                } else {
                    "agent-fixture"
                }
            );
            expected["code"] = json!(code);
            expected["detail"] = detail.clone();
        }
        assert_eq!(reply["result"], expected);
        self.audit(code, gate, agent, handle);
        self.github.zero_contacts();
    }
    fn db(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
}

fn checked_reply(reply: Value) -> Value {
    if let Some(code) = reply["result"]["refusal_code"].as_str() {
        let prefix = code.split('{').next().unwrap();
        assert!(
            CLOSED_CODES.contains(&prefix),
            "facade escaped closed taxonomy: {code}"
        );
    }
    reply
}

const CLOSED_CODES: &[&str] = &[
    "delegating_scope_required",
    "agent_handle_unknown",
    "agent_repository_conflict",
    "repository_unbound",
    "request_kind_unmapped",
    "request_field_forbidden",
    "nonce_payload_mismatch",
    "nonce_in_flight",
    "handle_disabled",
    "probe_unproven",
    "module_grant_absent",
    "agent_grant_absent",
    "agent_grant_excludes_request",
    "policy_blocked",
    "approval_agent_mismatch",
    "approval_expired",
    "approval_denied",
    "comment_author_mismatch",
    "issue_author_mismatch",
    "stale_authority",
    "pipeline_denied",
    "handle_credential_unresolvable",
    "handle_credential_rejected",
    "vendor_rejected",
    "pre_dispatch_read_incomplete",
    "not_present",
    "issue_edit_not_own",
    "pr_head_cross_repository",
    "store_failure",
];
fn comment() -> Value {
    json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},"body":{"body":"hello"}})
}

#[test]
fn delegating_stamp_resolves_bound_bot_and_completes_request_end_to_end() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    assert_eq!(f.scope.acting_agent(), Some("agent-fixture"));
    let reply = f.call(Some(&f.scope), &comment(), "case", f.now);
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
    // The governed write appends its own rows after the facade's, so find the
    // facade row by its action rather than taking the last one.
    let rows = f.store.list_audit("reserved:aft").unwrap();
    let facade = rows
        .iter()
        .find(|row| row.action.as_deref() == Some("github.bot_request"))
        .unwrap();
    assert_eq!(facade.reason_code, "allowed");
    assert_eq!(facade.agent_id.as_deref(), Some("agent-fixture"));
    assert_eq!(facade.app_handle_id.as_deref(), Some("app-fixture"));
    assert_eq!(
        facade.agent_handle, None,
        "no token-only handle claim is written"
    );
}

#[test]
fn handle_credential_naming_another_app_refuses_unknown_with_zero_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    // The row still belongs to the stamped agent; only its credential names a
    // different App, so the login the ownership checks would use is not this handle's.
    f.db()
        .execute(
            "UPDATE github_app_handle SET credential_reference='github_app:other-app'",
            [],
        )
        .unwrap();
    f.refusal(
        Some(&f.scope),
        &comment(),
        "agent_handle_unknown",
        "G2",
        Some("agent-fixture"),
        None,
    );
    assert_eq!(f.github.comments.lock().unwrap().len(), 0);
}

#[test]
fn bot_request_handle_refusal_audits_and_logs_stamped_agent() {
    const TEST: &str = "bot_request_handle_refusal_audits_and_logs_stamped_agent";
    const CHILD: &str = "PLEXUS_BOT_REQUEST_STDERR_CHILD";
    const MESSAGE: &str = "bot_request handle refused (agent_handle_unknown) for caller reserved:aft: stamped agent agent-fixture";

    if std::env::var(CHILD).as_deref() == Ok(TEST) {
        logging::init_child();
        let f = Fixture::new(&[("add_issue_comment", "write")]);
        f.db()
            .execute("DELETE FROM github_repo_binding", [])
            .unwrap();
        f.db().execute("DELETE FROM github_app_handle", []).unwrap();
        f.refusal(
            Some(&f.scope),
            &comment(),
            "agent_handle_unknown",
            "G2",
            Some("agent-fixture"),
            None,
        );
        let rows = f.store.list_audit("reserved:aft").unwrap();
        assert_eq!(rows.last().unwrap().agent_handle.as_deref(), None);
        return;
    }

    // A separate process exposes the renderer's actual stderr, not libtest's capture buffer.
    let output = bounded::child_test_output(
        TEST,
        &[(CHILD, TEST), ("PLEXUS_LOG_STDERR_CHILD", "1")],
        std::time::Duration::from_secs(30),
        "test binary child",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "fixture did not run: {stdout}");
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("bot_request handle refused"))
        .collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    logging::assert_diagnostic(
        lines[0],
        cortexkit_log::ParsedLevel::Warn,
        "plexus.governance",
        MESSAGE,
    );
}

#[test]
fn pre_claim_refusals_have_exact_identity_and_zero_contact() {
    for (name, mutation, code, gate, handle) in [
        ("unknown", "unknown", "agent_handle_unknown", "G2", None),
        ("mismatch", "mismatch", "agent_handle_unknown", "G2", None),
        (
            "unbound",
            "unbound",
            "repository_unbound",
            "G2",
            Some("app-fixture"),
        ),
        (
            "module",
            "module",
            "module_grant_absent",
            "G6",
            Some("app-fixture"),
        ),
        (
            "agent",
            "agent",
            "agent_grant_absent",
            "G6",
            Some("app-fixture"),
        ),
        (
            "disabled",
            "disabled",
            "handle_disabled",
            "G5",
            Some("app-fixture"),
        ),
        (
            "probe",
            "probe",
            "probe_unproven",
            "G5",
            Some("app-fixture"),
        ),
    ] {
        let f = Fixture::new(&[("add_issue_comment", "write")]);
        match mutation {
            "unknown" => {
                f.db()
                    .execute("DELETE FROM github_repo_binding", [])
                    .unwrap();
                f.db().execute("DELETE FROM github_app_handle", []).unwrap();
            }
            "mismatch" => {
                f.db()
                    .execute("UPDATE github_app_handle SET agent_id='another'", [])
                    .unwrap();
            }
            "unbound" => {
                f.db()
                    .execute("DELETE FROM github_repo_binding", [])
                    .unwrap();
            }
            "module" | "agent" => {
                f.db()
                    .execute("DELETE FROM grants WHERE grant_id=?1", [mutation])
                    .unwrap();
            }
            "disabled" => {
                f.db()
                    .execute("UPDATE github_app_handle SET status='disabled'", [])
                    .unwrap();
            }
            "probe" => {
                f.db()
                    .execute("UPDATE github_app_handle SET proven_at=NULL", [])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        f.refusal(
            Some(&f.scope),
            &comment(),
            code,
            gate,
            Some("agent-fixture"),
            handle,
        );
        assert_eq!(f.github.comments.lock().unwrap().len(), 0, "{name}");
    }
}

#[test]
fn sequential_retry_replays_without_second_comment_or_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let first = f.request(&comment(), "replay");
    assert_eq!(
        first["result"],
        json!({"status":"completed","result":{
            "url":"https://github.com/org/repo/issues/42#issuecomment-101","id":101}}),
        "{first}"
    );
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    f.github.clear_contacts();
    let replay = f.request(&comment(), "replay");
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&first).unwrap()
    );
    f.github.zero_contacts();
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "replay")
            .unwrap()
            .unwrap()
            .state,
        "completed"
    );
}

#[test]
fn ownership_refusal_is_sticky_after_agent_grant_revocation() {
    let f = Fixture::new(&[
        ("github.issue_comment.get", "read"),
        ("update_issue_comment", "write"),
    ]);
    let request = json!({"action":"api:PATCH:/repos/*/*/issues/comments/*","repository":"org/repo",
        "target":{"comment_id":"123"},"body":{"body":"edited"}});
    *f.github.comment_author.lock().unwrap() = Some("someone-else[bot]".into());
    let first = f.request(&request, "ownership");
    assert_eq!(
        first["result"]["refusal_code"],
        "comment_author_mismatch{expected_login: app-fixture[bot], actual_login: someone-else[bot]}",
        "{first}"
    );
    assert_eq!(f.github.actions(), ["github.issue_comment.get"]);
    f.db()
        .execute("DELETE FROM grants WHERE grant_id='agent'", [])
        .unwrap();
    f.github.clear_contacts();
    assert_eq!(f.request(&request, "ownership")["result"], first["result"]);
    f.github.zero_contacts();
    assert_eq!(
        f.request(&request, "fresh")["result"]["refusal_code"],
        "agent_grant_absent"
    );
    f.github.zero_contacts();
}

#[test]
fn g9_barrier_blocks_edit_last_patch_after_ownership_reads() {
    let f = Fixture::new(&[
        ("github.issue_comments.list", "read"),
        ("github.issue_comment.get", "read"),
        ("update_issue_comment", "write"),
    ]);
    let path = f.path.clone();
    *f.github.after_read.lock().unwrap() = Some(Box::new(move || {
        // Revoking the module grant after the final ownership GET must block the write.
        let db = Connection::open(path).unwrap();
        db.execute("DELETE FROM grants WHERE grant_id='module'", [])
            .unwrap();
    }));
    let request = json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},
        "edit_last":true,"body":{"body":"replacement"}});
    let result = f.request(&request, "barrier");
    assert_eq!(
        result["result"]["refusal_code"], "stale_authority{dimension: module_grant_revoked}",
        "{result}"
    );
    assert_eq!(
        f.github.actions(),
        ["github.issue_comments.list", "github.issue_comment.get"]
    );
    assert_eq!(
        f.github.credential.lock().unwrap().as_slice(),
        [
            "credential.prepare(app-fixture)",
            "credential.prepare(app-fixture)"
        ]
    );
    assert!(f.github.comments.lock().unwrap().is_empty());
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "barrier")
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
}

#[test]
fn transient_missing_agent_grant_allows_same_nonce_after_minting() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    f.db()
        .execute("DELETE FROM grants WHERE grant_id='agent'", [])
        .unwrap();
    f.refusal(
        Some(&f.scope),
        &comment(),
        "agent_grant_absent",
        "G6",
        Some("agent-fixture"),
        Some("app-fixture"),
    );
    assert!(f
        .store
        .github_receipt("agent-fixture", "case")
        .unwrap()
        .is_none());
    facade_rows::insert_invoke_grant(
        &f.db(),
        "agent",
        "reserved:aft",
        "[\"add_issue_comment\"]",
        Some("agent-fixture"),
    );
    let completed = f.request(&comment(), "case");
    assert_eq!(completed["result"]["status"], "completed", "{completed}");
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
}

#[test]
fn completed_receipt_survives_handle_disablement_and_grant_revocation() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let first = f.request(&comment(), "done");
    assert_eq!(first["result"]["status"], "completed", "{first}");
    f.db()
        .execute("UPDATE github_app_handle SET status='disabled'", [])
        .unwrap();
    f.db()
        .execute("DELETE FROM grants WHERE grant_id='agent'", [])
        .unwrap();
    f.github.clear_contacts();
    assert_eq!(f.request(&comment(), "done")["result"], first["result"]);
    f.github.zero_contacts();
    assert_eq!(
        f.request(&comment(), "new")["result"]["refusal_code"],
        "handle_disabled"
    );
    f.github.zero_contacts();
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
}

#[test]
fn changed_payload_on_completed_nonce_does_not_add_comment() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    assert_eq!(
        f.request(&comment(), "nonce")["result"]["status"],
        "completed"
    );
    f.github.clear_contacts();
    let mut changed = comment();
    changed["body"]["body"] = json!("different");
    let reply = f.request(&changed, "nonce");
    assert_eq!(reply["result"]["refusal_code"], "nonce_payload_mismatch");
    f.github.zero_contacts();
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
}

#[test]
fn unmapped_and_forbidden_requests_stop_before_the_vendor() {
    for (request, code) in [
        (
            json!({"action":"unknown","repository":"org/repo"}),
            "request_kind_unmapped",
        ),
        (
            json!({"verb":"issue close","repository":"org/repo","body":"bad"}),
            "request_field_forbidden{field: body}",
        ),
    ] {
        let f = Fixture::new(&[("add_issue_comment", "write")]);
        f.refusal(
            Some(&f.scope),
            &request,
            code,
            "G3",
            Some("agent-fixture"),
            Some("app-fixture"),
        );
    }
}

#[path = "../support/bounded.rs"]
mod bounded;

fn pause_at_contact(
    hook: &Mutex<Option<Box<dyn FnOnce() + Send>>>,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    *hook.lock().unwrap() = Some(Box::new(move || {
        // A late hook must not rendezvous with a controller that already failed.
        let _ = entered_tx.send(());
        let _ = resume_rx.recv_timeout(bounded::STORE_WORK_WAIT);
    }));
    (entered_rx, resume_tx)
}

#[test]
fn concurrent_first_calls_claim_before_reads_and_write_once() {
    let f = Arc::new(Fixture::new(&[
        ("github.issue.get", "read"),
        ("edit_issue", "write"),
    ]));
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}});
    let (entered, resume) = pause_at_contact(&f.github.after_read);
    {
        // Owned workers avoid scope's unconditional autojoin during unwinding.
        let first = bounded::Task::spawn({
            let f = f.clone();
            let request = request.clone();
            move || f.request(&request, "race")
        });
        let contact = entered.recv_timeout(bounded::STORE_WORK_WAIT);
        let loser = contact.as_ref().ok().map(|_| {
            bounded::Task::spawn({
                let f = f.clone();
                let request = request.clone();
                move || f.request(&request, "race")
            })
            .join_timeout(bounded::STORE_WORK_WAIT)
        });
        let actions_before_resume = f.github.actions();
        // Release/disconnect before any assertion, even if notification or the
        // losing call timed out. A late hook then exits rather than trapping cleanup.
        let _ = resume.send(());
        drop(resume);
        drop(entered);
        let winner = first.join_timeout(bounded::STORE_WORK_WAIT);
        contact.expect("first call must reach the read hook within the store-work deadline");
        let loser = loser
            .unwrap()
            .expect("losing call finishes within the store-work deadline");
        let winner = winner.expect("winning call finishes within the store-work deadline");
        assert_eq!(
            loser["result"]["refusal_code"], "nonce_in_flight",
            "{loser}"
        );
        assert_eq!(
            actions_before_resume,
            ["github.issue.get"],
            "loser must not issue a GET"
        );
        assert_eq!(winner["result"]["status"], "completed", "{winner}");
    }
    assert_eq!(f.github.actions(), ["github.issue.get", "edit_issue"]);
    assert_eq!(
        f.github
            .actions()
            .iter()
            .filter(|action| *action == "edit_issue")
            .count(),
        1
    );
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "race")
            .unwrap()
            .unwrap()
            .state,
        "completed"
    );
}

#[test]
fn concurrent_approved_retries_mutate_once() {
    let f = Arc::new(Fixture::new(&[("add_issue_comment", "write")]));
    f.db()
        .execute(
            "UPDATE catalog_actions SET ask_first=1 WHERE name='add_issue_comment'",
            [],
        )
        .unwrap();
    let pending = f.request(&comment(), "approved-race");
    assert_eq!(pending["result"]["status"], "pending_approval", "{pending}");
    let approval = pending["result"]["action_request_id"].as_str().unwrap();
    f.db()
        .execute(
            "UPDATE action_requests SET status='approved' WHERE request_id=?1",
            [approval],
        )
        .unwrap();
    let (entered, resume) = pause_at_contact(&f.github.before_write);
    {
        let first = bounded::Task::spawn({
            let f = f.clone();
            move || f.request(&comment(), "approved-race")
        });
        let contact = entered.recv_timeout(bounded::STORE_WORK_WAIT);
        let loser = contact.as_ref().ok().map(|_| {
            bounded::Task::spawn({
                let f = f.clone();
                move || f.request(&comment(), "approved-race")
            })
            .join_timeout(bounded::STORE_WORK_WAIT)
        });
        let actions_before_resume = f.github.actions();
        let _ = resume.send(());
        drop(resume);
        drop(entered);
        let winner = first.join_timeout(bounded::STORE_WORK_WAIT);
        contact.expect("approved retry must reach the write hook within the store-work deadline");
        let loser = loser
            .unwrap()
            .expect("losing retry finishes within the store-work deadline");
        let winner = winner.expect("winning retry finishes within the store-work deadline");
        assert_eq!(
            loser["result"]["refusal_code"], "nonce_in_flight",
            "{loser}"
        );
        assert!(
            actions_before_resume.is_empty(),
            "losing retry must not transmit"
        );
        assert_eq!(winner["result"]["status"], "completed", "{winner}");
    }
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "approved-race")
            .unwrap()
            .unwrap()
            .state,
        "completed"
    );
}

fn authority_movement(sql: &[&str], expected: &str) {
    let f = Fixture::new(&[("github.issue.get", "read"), ("edit_issue", "write")]);
    let path = f.path.clone();
    let statements: Vec<String> = sql.iter().map(|statement| (*statement).into()).collect();
    *f.github.after_read.lock().unwrap() = Some(Box::new(move || {
        let db = Connection::open(path).unwrap();
        for statement in statements {
            db.execute_batch(&statement).unwrap();
        }
    }));
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}});
    let reply = f.request(&request, "moved");
    assert_eq!(
        reply["result"]["refusal_code"],
        format!("stale_authority{{dimension: {expected}}}"),
        "{reply}"
    );
    assert_eq!(
        f.github.actions(),
        ["github.issue.get"],
        "authority moved before mutation"
    );
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "moved")
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
}
macro_rules! baseline_case {
    ($name:ident, $dimension:literal, $sql:literal) => {
        #[test]
        fn $name() {
            authority_movement(&[$sql], $dimension);
        }
    };
}
baseline_case!(
    baseline_handle_disabled,
    "handle_disabled",
    "UPDATE github_app_handle SET status='disabled'"
);
baseline_case!(
    baseline_repository_rebound,
    "repository_rebound",
    "DELETE FROM github_repo_binding WHERE repository='org/repo'"
);
baseline_case!(
    baseline_agent_grant_revoked,
    "agent_grant_revoked",
    "DELETE FROM grants WHERE grant_id='agent'"
);
baseline_case!(
    baseline_module_grant_revoked,
    "module_grant_revoked",
    "DELETE FROM grants WHERE grant_id='module'"
);
baseline_case!(baseline_policy_changed, "policy_changed", "INSERT INTO policies (policy_id,principal,connection_id,action_selector,effect,updated_at_ms) VALUES ('changed','operator','conn-fixture','edit_issue','block',1)");
baseline_case!(
    baseline_credential_rotated,
    "credential_rotated",
    "UPDATE github_app_handle SET credential_generation=credential_generation+1"
);
baseline_case!(
    baseline_handle_row_changed,
    "handle_row_changed",
    "UPDATE github_app_handle SET app_id=app_id+1"
);

#[test]
fn simultaneous_baseline_movements_report_first_dimension() {
    authority_movement(
        &[
            "UPDATE github_app_handle SET credential_generation=credential_generation+1",
            "DELETE FROM grants WHERE grant_id='module'",
        ],
        "module_grant_revoked",
    );
}

#[test]
fn takeover_compares_its_new_baseline_not_the_expired_workers() {
    use plexus_core::github::facade::gates;
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let first = gates::run_scoped(
        &*f.store,
        "reserved:aft",
        Some(&f.scope),
        &comment(),
        "takeover",
        "claim",
        "dead-worker",
        f.now - 121_000,
        120,
    );
    assert!(first.refusal_code.is_none(), "{first:?}");
    f.db()
        .execute(
            "UPDATE github_app_handle SET credential_generation=credential_generation+1",
            [],
        )
        .unwrap();
    let replay = f.request(&comment(), "takeover");
    assert_eq!(replay["result"]["status"], "completed", "{replay}");
    let receipt = f
        .store
        .github_receipt("agent-fixture", "takeover")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.authority_baseline["credential_generation"], 2);
    assert_eq!(receipt.state, "completed");
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
}

#[test]
fn terminal_receipts_outlive_handle_disablement_and_grant_revocation() {
    for (movement, sql, fresh_code) in [
        (
            "disabled",
            "UPDATE github_app_handle SET status='disabled'",
            "handle_disabled",
        ),
        (
            "grant",
            "DELETE FROM grants WHERE grant_id='agent'",
            "agent_grant_absent",
        ),
    ] {
        for ownership_refusal in [false, true] {
            let f = if ownership_refusal {
                Fixture::new(&[
                    ("github.issue_comment.get", "read"),
                    ("update_issue_comment", "write"),
                ])
            } else {
                Fixture::new(&[("add_issue_comment", "write")])
            };
            let request = if ownership_refusal {
                *f.github.comment_author.lock().unwrap() = Some("other[bot]".into());
                json!({"action":"api:PATCH:/repos/*/*/issues/comments/*","repository":"org/repo",
                    "target":{"comment_id":"123"},"body":{"body":"edited"}})
            } else {
                comment()
            };
            let first = f.request(&request, "terminal");
            assert_eq!(
                first["result"]["status"],
                if ownership_refusal {
                    "refused"
                } else {
                    "completed"
                },
                "{movement}: {first}"
            );
            f.db().execute_batch(sql).unwrap();
            f.github.clear_contacts();
            let retry = f.request(&request, "terminal");
            assert_eq!(
                retry["result"], first["result"],
                "{movement} must not change a terminal outcome"
            );
            f.github.zero_contacts();
            let fresh = f.request(&request, "fresh");
            assert_eq!(
                fresh["result"]["refusal_code"], fresh_code,
                "{movement}: {fresh}"
            );
            f.github.zero_contacts();
        }
    }
}

#[test]
fn grant_selector_and_policy_refusals_have_zero_vendor_contact() {
    for (sql, code) in [
        ("UPDATE grants SET action_selectors='[]' WHERE grant_id='agent'", "agent_grant_excludes_request{request_kind: comment, repository: org/repo}"),
        ("INSERT INTO policies (policy_id,principal,connection_id,action_selector,effect,updated_at_ms) VALUES ('block','operator','conn-fixture','add_issue_comment','block',1)", "policy_blocked{source: module}"),
    ] {
        let f = Fixture::new(&[("add_issue_comment", "write")]);
        f.db().execute_batch(sql).unwrap();
        f.refusal(Some(&f.scope), &comment(), code, "G6", Some("agent-fixture"), Some("app-fixture"));
    }
}

#[test]
fn issue_author_mismatch_is_stored_before_write() {
    let f = Fixture::new(&[("github.issue.get", "read"), ("edit_issue", "write")]);
    *f.github.response_override.lock().unwrap() = Some(TransportResponse::success(
        json!({"user":{"login":"someone-else[bot]","type":"Bot"}}),
    ));
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},
        "body":{"title":"changed"},"author_scope":"own"});
    let result = f.request(&request, "issue-author");
    assert_eq!(
        result["result"]["refusal_code"], "issue_edit_not_own",
        "{result}"
    );
    assert_eq!(f.github.actions(), ["github.issue.get"]);
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "issue-author")
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
}

#[test]
fn unresolvable_credential_and_definitive_vendor_refusals_are_sticky() {
    for (label, credential_missing, vendor_code, expected) in [
        (
            "missing",
            true,
            None,
            "handle_credential_unresolvable{class: permanent}",
        ),
        ("401", false, Some("http_401"), "handle_credential_rejected"),
        (
            "403",
            false,
            Some("http_403"),
            "vendor_rejected{status: 403}",
        ),
    ] {
        let f = Fixture::new(&[("add_issue_comment", "write")]);
        f.github
            .credential_failure
            .store(credential_missing, std::sync::atomic::Ordering::SeqCst);
        if let Some(code) = vendor_code {
            *f.github.response_override.lock().unwrap() =
                Some(TransportResponse::vendor_error(code, "rejected"));
        }
        let first = f.request(&comment(), label);
        assert_eq!(
            first["result"]["refusal_code"], expected,
            "{label}: {first}"
        );
        assert_eq!(f.github.actions().len(), usize::from(vendor_code.is_some()));
        f.github.clear_contacts();
        assert_eq!(f.request(&comment(), label)["result"], first["result"]);
        f.github.zero_contacts();
        assert_eq!(
            f.store
                .github_receipt("agent-fixture", label)
                .unwrap()
                .unwrap()
                .state,
            "refused"
        );
    }
}

/// The gh shim retries only transient failures, so the facade code must carry
/// the class the vault itself reported: `auth_required` (a person must repair
/// the App) and `permanent` (a plexus setup fault) have to reach the agent.
#[test]
fn vault_failure_class_reaches_the_facade_refusal_code() {
    for (label, code, class, expected) in [
        (
            "vault-transient",
            "vault_locked",
            "transient",
            "handle_credential_unresolvable{class: transient}",
        ),
        (
            "vault-auth-required",
            "installation_ambiguous",
            "auth_required",
            "handle_credential_unresolvable{class: auth_required}",
        ),
        (
            "vault-permanent",
            "not_found",
            "permanent",
            "handle_credential_unresolvable{class: permanent}",
        ),
    ] {
        let f = Fixture::with_vault(
            &[("add_issue_comment", "write")],
            json!({"result": {"error": {"code": code, "class": class}}}),
        );
        let reply = f.request(&comment(), label);
        assert_eq!(
            reply["result"],
            json!({"status":"refused","refusal_code":expected}),
            "{label}: {reply}"
        );
        f.github.zero_contacts();
    }
}

/// A successful vault read that resolved a different credential is refused by
/// plexus itself; retrying the same read cannot change that, so it is permanent.
#[test]
fn vault_resolving_a_different_credential_is_a_permanent_refusal() {
    let reply_for = vault_token;
    // Control: the same reply naming the handle's own credential is accepted,
    // so the refusal below comes from the id mismatch alone.
    let matching = Fixture::with_vault(
        &[("add_issue_comment", "write")],
        reply_for("github_app:app-fixture"),
    );
    let accepted = matching.request(&comment(), "vault-match");
    assert_eq!(accepted["result"]["status"], "completed", "{accepted}");

    let f = Fixture::with_vault(
        &[("add_issue_comment", "write")],
        reply_for("github_app:someone-else"),
    );
    let reply = f.request(&comment(), "vault-mismatch");
    assert_eq!(
        reply["result"],
        json!({"status":"refused","refusal_code":"handle_credential_unresolvable{class: permanent}"}),
        "{reply}"
    );
    f.github.zero_contacts();
}

/// A transient vault failure is not the command's outcome: nothing reached
/// GitHub, so a retry with the same nonce must run again once the vault
/// recovers, and write exactly once.
#[test]
fn transient_credential_refusal_is_released_for_a_same_nonce_retry() {
    let vault = Arc::new(Vault(Mutex::new(vault_error("transient"))));
    let f = Fixture::with_shared_vault(&[("add_issue_comment", "write")], vault.clone());
    let first = f.request(&comment(), "retry-transient");
    assert_eq!(
        first["result"],
        json!({"status":"refused","refusal_code":"handle_credential_unresolvable{class: transient}"}),
        "{first}"
    );
    f.github.zero_contacts();
    *vault.0.lock().unwrap() = vault_token("github_app:app-fixture");
    let retry = f.request(&comment(), "retry-transient");
    assert_eq!(retry["result"]["status"], "completed", "{retry}");
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    assert_eq!(f.github.comments.lock().unwrap().len(), 1);
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "retry-transient")
            .unwrap()
            .unwrap()
            .state,
        "completed"
    );
}

/// `auth_required` needs a person to repair the App, so it stays the
/// command's outcome: a same-nonce retry replays it without contacting
/// GitHub, even after the vault recovers.
#[test]
fn auth_required_credential_refusal_stays_sticky_for_a_same_nonce_retry() {
    let vault = Arc::new(Vault(Mutex::new(vault_error("auth_required"))));
    let f = Fixture::with_shared_vault(&[("add_issue_comment", "write")], vault.clone());
    let first = f.request(&comment(), "retry-auth");
    assert_eq!(
        first["result"],
        json!({"status":"refused","refusal_code":"handle_credential_unresolvable{class: auth_required}"}),
        "{first}"
    );
    *vault.0.lock().unwrap() = vault_token("github_app:app-fixture");
    let retry = f.request(&comment(), "retry-auth");
    assert_eq!(retry["result"], first["result"]);
    f.github.zero_contacts();
    assert_eq!(
        f.store
            .github_receipt("agent-fixture", "retry-auth")
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
}

#[test]
fn terminal_receipt_outlives_repository_rebinding() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let first = f.request(&comment(), "terminal");
    assert_eq!(first["result"]["status"], "completed");
    f.db()
        .execute(
            "DELETE FROM github_repo_binding WHERE repository='org/repo'",
            [],
        )
        .unwrap();
    f.github.clear_contacts();
    assert_eq!(f.request(&comment(), "terminal")["result"], first["result"]);
    f.github.zero_contacts();
    assert_eq!(
        f.request(&comment(), "fresh")["result"]["refusal_code"],
        "repository_unbound"
    );
}

#[test]
fn conflicting_repository_binding_names_both_agents_without_vendor_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    f.store
        .insert_connection(
            "operator",
            "other-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    f.store
        .put_github_handle(&GithubHandle {
            app_handle_id: "other-handle".into(),
            agent_id: "another".into(),
            app_id: 2,
            installation_id: None,
            credential_reference: "github_app:other".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "other-connection".into(),
        })
        .unwrap();
    f.db().execute("UPDATE github_repo_binding SET app_handle_id='other-handle' WHERE repository='org/repo'", []).unwrap();
    f.refusal(
        Some(&f.scope),
        &comment(),
        "agent_repository_conflict{claimed_agent: agent-fixture, bound_agent: another}",
        "G2",
        Some("agent-fixture"),
        Some("app-fixture"),
    );
}

#[test]
fn rebound_repository_never_replays_changed_payload() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    assert_eq!(
        f.request(&comment(), "terminal")["result"]["status"],
        "completed"
    );
    f.db()
        .execute(
            "DELETE FROM github_repo_binding WHERE repository='org/repo'",
            [],
        )
        .unwrap();
    f.github.clear_contacts();
    let mut changed = comment();
    changed["body"]["body"] = json!("changed");
    assert_eq!(
        f.request(&changed, "terminal")["result"]["refusal_code"],
        "repository_unbound"
    );
    f.github.zero_contacts();
    assert_eq!(f.github.comments.lock().unwrap().as_slice(), ["hello"]);
}

#[test]
fn rebound_repository_does_not_replay_nonterminal_receipts() {
    let f = unbound_claimed_receipt("pending");
    let reply = f.request(&comment(), "claimed");
    assert_eq!(reply["result"]["refusal_code"], "repository_unbound");
    f.github.zero_contacts();
}

#[test]
fn rebound_repository_replays_terminal_unknown_without_contact() {
    let f = unbound_claimed_receipt("outcome_unknown");
    let reply = f.request(&comment(), "claimed");
    assert_eq!(reply["result"]["status"], "outcome_unknown");
    assert!(reply["result"]["refusal_code"].is_null());
    f.github.zero_contacts();
}

fn unbound_claimed_receipt(state: &str) -> Fixture {
    use plexus_core::github::facade::gates;
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let claim = gates::run_scoped(
        &*f.store,
        "reserved:aft",
        Some(&f.scope),
        &comment(),
        "claimed",
        "claim",
        "worker",
        f.now,
        120,
    );
    assert!(claim.refusal_code.is_none(), "{claim:?}");
    if state == "outcome_unknown" {
        assert_eq!(f.db().execute("UPDATE github_bot_receipt SET state='outcome_unknown' WHERE request_nonce='claimed'", []).unwrap(), 1);
    }
    assert_eq!(
        f.db()
            .execute(
                "DELETE FROM github_repo_binding WHERE repository='org/repo'",
                []
            )
            .unwrap(),
        1
    );
    f
}

#[test]
fn canonical_request_fingerprint_is_independent_of_binding() {
    use plexus_core::github::facade::request_map;
    use plexus_core::github::resolver::{Binding, ResolvedRepositories};
    let mapped = |handle: &str, connection: &str| {
        request_map::map(
            &comment(),
            &ResolvedRepositories {
                repositories: vec!["org/repo".into()],
                binding: Binding {
                    app_handle_id: handle.into(),
                    connection_id: connection.into(),
                },
            },
            "org/repo",
        )
        .unwrap()
    };
    let original = mapped("app-fixture", "conn-fixture");
    let rebound = mapped("other-handle", "other-connection");
    assert_eq!(original.fingerprint, rebound.fingerprint);
    assert_eq!(original.canonical, comment());
}

#[test]
fn completed_receipt_replays_after_repository_moves_to_another_agent() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let first = f.request(&comment(), "old-binding");
    assert_eq!(first["result"]["status"], "completed");
    f.store
        .insert_connection(
            "operator",
            "other-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    f.store
        .put_github_handle(&GithubHandle {
            app_handle_id: "other-handle".into(),
            agent_id: "another".into(),
            app_id: 2,
            installation_id: None,
            credential_reference: "github_app:other".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "other-connection".into(),
        })
        .unwrap();
    f.db().execute("UPDATE github_repo_binding SET app_handle_id='other-handle' WHERE repository='org/repo'", []).unwrap();
    f.github.clear_contacts();
    assert_eq!(
        f.request(&comment(), "old-binding")["result"],
        first["result"]
    );
    f.github.zero_contacts();
    assert_eq!(
        f.request(&comment(), "new-binding")["result"]["refusal_code"],
        "agent_repository_conflict{claimed_agent: agent-fixture, bound_agent: another}"
    );
    f.github.zero_contacts();
}

#[test]
fn stored_ownership_refusal_replays_after_repository_unbind() {
    let f = Fixture::new(&[
        ("github.issue_comment.get", "read"),
        ("update_issue_comment", "write"),
    ]);
    *f.github.comment_author.lock().unwrap() = Some("other[bot]".into());
    let request = json!({"action":"api:PATCH:/repos/*/*/issues/comments/*","repository":"org/repo",
        "target":{"comment_id":"123"},"body":{"body":"edited"}});
    let first = f.request(&request, "refused");
    assert_eq!(
        first["result"]["refusal_code"],
        "comment_author_mismatch{expected_login: app-fixture[bot], actual_login: other[bot]}"
    );
    f.db()
        .execute(
            "DELETE FROM github_repo_binding WHERE repository='org/repo'",
            [],
        )
        .unwrap();
    f.github.clear_contacts();
    assert_eq!(f.request(&request, "refused")["result"], first["result"]);
    f.github.zero_contacts();
    assert_eq!(
        f.request(&request, "fresh")["result"]["refusal_code"],
        "repository_unbound"
    );
    f.github.zero_contacts();
}
