use crate::facade_rows;
use crate::scope_support::{delegating_scope, LiveScopeReader};
use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::github::facade::bot_request_scoped;
use plexus_core::governance::GovernanceEngine;
use plexus_core::scope::CallScope;
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
use plexus_core::transport::{MockResponse, MockTransport};
use plexus_core::PlexusStore;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::sync::Arc;

mod pr_ready;
mod regressions;
mod review_threads;

struct Token;
impl HandleCredentialProvider for Token {
    fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
        Ok(ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}
type Setup = (
    plexus_core::test_scratch::Scratch,
    Arc<PlexusStore>,
    GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>,
    Arc<MockTransport>,
    CallScope,
);

/// The shipped reviewed GitHub REST manifest, parsed from its JSONC source.
fn github_manifest() -> plexus_core::AppManifest {
    parse_catalog_source(include_str!(concat!(
        "../",
        "../../../catalog/github_rest.jsonc"
    )))
}

fn parse_catalog_source(source: &str) -> plexus_core::AppManifest {
    let clean = subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
    plexus_core::ingest_value(serde_json::from_str(&clean).unwrap())
        .unwrap()
        .manifest
}

fn setup(label: &str, actions: &[(&str, &str)]) -> Setup {
    setup_as(label, actions, plexus_core::github::AFT_PRINCIPAL)
}

/// `module` is the calling module that holds the module grant. The agent grant
/// keeps the grantee the import gives it, reserved:aft.
fn setup_as(label: &str, actions: &[(&str, &str)], module: &str) -> Setup {
    let (scratch, store) = crate::scratch_store::open(label);
    let store = Arc::new(store);
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
    let db = Connection::open(scratch.path()).unwrap();
    // The shipped reviewed manifest is stored directly, so nothing is seeded
    // from it: the facade reads each leg's declared arguments from it, and each
    // catalog row below pins that action's reviewed argument schema, so
    // governance refuses any argument a leg sends that the schema does not
    // declare. An action the manifest does not declare keeps an empty schema.
    let manifest = github_manifest();
    facade_rows::insert_reviewed_manifest(&db, &serde_json::to_string(&manifest).unwrap());
    let selectors =
        serde_json::to_string(&actions.iter().map(|(action, _)| action).collect::<Vec<_>>())
            .unwrap();
    for (name, risk) in actions {
        let schema = manifest
            .actions_baseline
            .iter()
            .find(|declared| declared.name == *name)
            .and_then(|declared| declared.http.as_ref())
            .map_or_else(|| json!({}), |http| http.args_schema.clone());
        facade_rows::insert_catalog_action(&db, name, risk, &schema.to_string(), false);
    }
    for (grant, grantee, agent) in [
        ("module", module, None),
        (
            "agent",
            plexus_core::github::AFT_PRINCIPAL,
            Some("agent-fixture"),
        ),
    ] {
        facade_rows::insert_invoke_grant(&db, grant, grantee, &selectors, agent);
    }
    let scope = delegating_scope("agent-fixture");
    let transport = Arc::new(MockTransport::default());
    let seams = GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    };
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(seams))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    (scratch, store, engine, transport, scope)
}

/// Seen markers are sent by prefrontal-core, so the golden is captured from a
/// real facade run with prefrontal-core as the caller.
#[test]
fn seen_marker_reaction_golden_is_a_real_facade_dispatch() {
    let caller = plexus_core::github::PREFRONTAL_PRINCIPAL;
    let (scratch, store, engine, transport, scope) =
        setup_as("facade-seen-marker", &[("add_reaction", "write")], caller);
    // GitHub's reaction body; the reply carries only its id and content.
    transport.set_response(MockResponse::Success(json!({
        "id": 701,
        "node_id": "REA_701",
        "content": "eyes",
        "user": {"login":"app-fixture[bot]","type":"Bot"},
        "created_at": "2026-01-01T00:00:00Z"
    })));
    let request = json!({"operation":"gh.route","gh_route_schema":1,"action":"issue reaction","target":{"number":"42"},
        "body":{"reaction":"eyes"},"repository":"org/repo","manifest_version":14,"rung_as_of_unix_secs":1790209659,
        "metadata":{"agent_id":"agent-fixture","pid":6092}});
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        caller,
        Some(&scope),
        &request,
        "seen-marker-nonce",
        "seen-marker-id",
        "worker",
        now,
    );
    assert_eq!(first["result"]["status"], "completed", "{first}");
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].action, "add_reaction");
    assert_eq!(requests[0].args["content"], "eyes");
    assert_eq!(requests[0].args["owner"], "org");
    assert_eq!(requests[0].args["repo"], "repo");
    let second = bot_request_scoped(
        &store,
        &engine,
        caller,
        Some(&scope),
        &request,
        "seen-marker-nonce",
        "retry-id",
        "retry",
        now + 1,
    );
    assert_eq!(first["result"], second["result"]);
    assert_eq!(transport.requests().len(), 1);
    let refusal = bot_request_scoped(
        &store,
        &engine,
        caller,
        None,
        &request,
        "bad-nonce",
        "bad-id",
        "worker",
        now + 2,
    );
    assert_eq!(
        refusal["result"]["refusal_code"],
        "delegating_scope_required"
    );
    // The caller as the facade audit recorded it for the completed request.
    let audited: String = Connection::open(scratch.path())
        .unwrap()
        .query_row(
            "SELECT principal FROM audit_journal WHERE request_id='seen-marker-id'
             AND action='github.bot_request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let generated = json!({"scope":scope,"request":{"request":request,"request_nonce":"seen-marker-nonce"},
        "caller_principal":audited,"success":first,"refusal":refusal});
    let golden_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/github_facade/seen-marker-reaction.json"
    );
    if std::env::var_os("UPDATE_FACADE_GOLDEN").is_some() {
        std::fs::create_dir_all(std::path::Path::new(golden_path).parent().unwrap()).unwrap();
        std::fs::write(
            golden_path,
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let golden: Value =
        serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
    assert_eq!(generated, golden);
}

#[test]
fn close_with_comment_records_two_effects_and_replays_without_a_second_write() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-close-effects",
        &[
            ("github.issue.get", "read"),
            ("add_issue_comment", "write"),
            ("close_issue", "write"),
        ],
    );
    let request =
        json!({"verb":"issue close", "repository":"org/repo", "number":"42", "comment":"done"});
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "close-nonce",
        "close-id",
        "first",
        now,
    );
    assert_eq!(first["result"]["status"], "completed", "{first}");
    let actions: Vec<_> = transport
        .requests()
        .iter()
        .map(|request| request.action.clone())
        .collect();
    assert_eq!(actions, ["add_issue_comment", "close_issue"]);
    let sent = transport.requests();
    assert_eq!(
        sent[0].args,
        json!({"owner":"org","repo":"repo","issue_number":42,"body":"done"})
    );
    assert_eq!(
        sent[1].args,
        json!({"owner":"org","repo":"repo","issue_number":42,"state":"closed"})
    );
    let receipt = store
        .github_receipt("agent-fixture", "close-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.effects.len(), 2);
    assert!(receipt
        .effects
        .iter()
        .all(|effect| effect.outcome.is_some()));
    assert_eq!(
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "close-nonce",
            "retry-id",
            "second",
            now + 1
        )["result"],
        first["result"]
    );
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn binder_rejects_a_second_owner_even_with_the_same_repo_basename() {
    let (_scratch, store, _engine, _transport, _scope) =
        setup("facade-owner-fence", &[("add_reaction", "write")]);
    let failure = store
        .bind_github_repo("other-org/repo", "app-fixture")
        .unwrap_err();
    assert!(
        failure.to_string().contains("binding_owner_mismatch"),
        "{failure}"
    );
}

#[test]
fn issue_edit_human_using_bot_login_cannot_dispatch() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-issue-owner",
        &[("github.issue.get", "read"), ("edit_issue", "write")],
    );
    transport.set_response(MockResponse::Success(
        json!({"user":{"login":"app-fixture[bot]","type":"User"}}),
    ));
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},
        "body":{"title":"changed"},"author_scope":"own"});
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "issue-owner-nonce",
        "owner-id",
        "worker",
        now,
    );
    assert_eq!(
        first["result"]["refusal_code"], "issue_edit_not_own",
        "{first}"
    );
    assert_eq!(transport.requests().len(), 1);
    let receipt = store
        .github_receipt("agent-fixture", "issue-owner-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state, "refused");
    assert_eq!(receipt.refusal_code.as_deref(), Some("issue_edit_not_own"));
    assert_eq!(
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "issue-owner-nonce",
            "retry-id",
            "retry",
            now + 1
        )["result"],
        first["result"]
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn approved_close_with_comment_consumes_one_request_after_both_effects() {
    let (scratch, store, engine, transport, scope) = setup(
        "facade-approved-close",
        &[
            ("github.issue.get", "read"),
            ("add_issue_comment", "write"),
            ("close_issue", "write"),
        ],
    );
    let db = Connection::open(scratch.path()).unwrap();
    db.execute(
        "UPDATE catalog_actions SET ask_first=1 WHERE name='close_issue'",
        [],
    )
    .unwrap();
    let request =
        json!({"verb":"issue close", "repository":"org/repo", "number":"42", "comment":"done"});
    let now = plexus_core::now_ms();
    let pending = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "approval-nonce",
        "pending-id",
        "worker",
        now,
    );
    assert_eq!(pending["result"]["status"], "pending_approval");
    assert!(transport.requests().is_empty());
    let approval = pending["result"]["action_request_id"].as_str().unwrap();
    db.execute(
        "UPDATE action_requests SET status='approved' WHERE request_id=?1",
        [approval],
    )
    .unwrap();
    let complete = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "approval-nonce",
        "approved-id",
        "retry",
        now + 1,
    );
    assert_eq!(
        complete["result"]["status"],
        "completed",
        "{complete}; requests={:?}; receipt={:?}; audit={:?}",
        transport.requests(),
        store.github_receipt("agent-fixture", "approval-nonce"),
        store.list_audit(plexus_core::github::AFT_PRINCIPAL)
    );
    assert_eq!(transport.requests().len(), 2);
    let (count, status): (i64, String) = db
        .query_row(
            "SELECT count(*), max(status) FROM action_requests",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((count, status.as_str()), (1, "consumed"));
    let mut reused = request.clone();
    reused["approval_id"] = json!(approval);
    let denied = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reused,
        "second-nonce",
        "reuse-id",
        "second-worker",
        now + 2,
    );
    assert_eq!(
        denied["result"]["refusal_code"], "approval_denied",
        "{denied}"
    );
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn outcome_unknown_replays_without_dispatch_and_preserves_approval() {
    let (scratch, store, engine, transport, scope) =
        setup("facade-unknown", &[("add_reaction", "write")]);
    let db = Connection::open(scratch.path()).unwrap();
    db.execute(
        "UPDATE catalog_actions SET ask_first=1 WHERE name='add_reaction'",
        [],
    )
    .unwrap();
    let request = json!({"action":"issue reaction", "repository":"org/repo", "target":{"number":"42"}, "body":{"reaction":"eyes"}});
    let now = plexus_core::now_ms();
    let pending = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "unknown-nonce",
        "pending-id",
        "first",
        now,
    );
    let approval = pending["result"]["action_request_id"].as_str().unwrap();
    db.execute(
        "UPDATE action_requests SET status='approved' WHERE request_id=?1",
        [approval],
    )
    .unwrap();
    transport.set_response(MockResponse::OutcomeUnknown);
    let unknown = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "unknown-nonce",
        "unknown-id",
        "second",
        now + 1,
    );
    assert_eq!(unknown["result"]["status"], "outcome_unknown", "{unknown}");
    assert_eq!(
        store
            .github_receipt("agent-fixture", "unknown-nonce")
            .unwrap()
            .unwrap()
            .state,
        "outcome_unknown"
    );
    assert_eq!(
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "unknown-nonce",
            "replay-id",
            "third",
            now + 2
        )["result"],
        unknown["result"]
    );
    assert_eq!(transport.requests().len(), 1);
    let status: String = db
        .query_row("SELECT status FROM action_requests", [], |row| row.get(0))
        .unwrap();
    assert_eq!(status, "approved");
}

#[test]
fn vendor_403_is_sticky_but_a_401_rejects_the_credential_once() {
    for (label, status, expected) in [
        (
            "facade-vendor-403",
            "http_403",
            "vendor_rejected{status: 403}",
        ),
        (
            "facade-vendor-401",
            "http_401",
            "handle_credential_rejected",
        ),
    ] {
        let (_scratch, store, engine, transport, scope) =
            setup(label, &[("add_reaction", "write")]);
        transport.set_response(MockResponse::VendorError {
            code: status.into(),
            message: "rejected".into(),
        });
        let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"}, "body":{"reaction":"eyes"}});
        let now = plexus_core::now_ms();
        let first = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "vendor-nonce",
            "vendor-id",
            "worker",
            now,
        );
        assert_eq!(first["result"]["refusal_code"], expected);
        let row = store
            .github_receipt("agent-fixture", "vendor-nonce")
            .unwrap()
            .unwrap();
        assert_eq!(row.refusal_code.as_deref(), Some(expected));
        assert_eq!(row.state, "refused");
        assert_eq!(
            bot_request_scoped(
                &store,
                &engine,
                plexus_core::github::AFT_PRINCIPAL,
                Some(&scope),
                &request,
                "vendor-nonce",
                "retry-id",
                "retry",
                now + 1
            )["result"],
            first["result"]
        );
        assert_eq!(transport.requests().len(), 1);
    }
}

#[test]
fn g8_entry_grant_revalidation_stops_before_reads_or_credential() {
    use plexus_core::github::facade::{gates, vendor_band};
    let (scratch, store, engine, transport, scope) = setup(
        "facade-stale-before-read",
        &[("github.issue.get", "read"), ("close_issue", "write")],
    );
    let request = json!({"verb":"issue close", "repository":"org/repo", "number":"42"});
    let now = plexus_core::now_ms();
    let mut reply = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "entry-nonce",
        "entry-id",
        "worker",
        now,
        120,
    );
    assert!(matches!(
        reply.claim,
        Some(plexus_core::github::receipt::Claim::Owned(_))
    ));
    Connection::open(scratch.path())
        .unwrap()
        .execute("DELETE FROM grants WHERE grant_id='module'", [])
        .unwrap();
    let result = vendor_band::run(&engine, &store, &mut reply, "entry-nonce", "worker", now);
    assert_eq!(
        result["refusal_code"],
        "stale_authority{dimension: module_grant_revoked}"
    );
    assert!(transport.requests().is_empty());
    assert_eq!(
        store
            .github_receipt("agent-fixture", "entry-nonce")
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
}

#[test]
fn g9_policy_movement_after_get_stops_the_write() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct AfterRead {
        inner: MockTransport,
        path: std::path::PathBuf,
        moved: AtomicBool,
    }
    impl Transport for AfterRead {
        fn dispatch(
            &self,
            request: TransportRequest,
            credential: &ResolvedCredential,
        ) -> TransportResponse {
            let is_read = request.action == "github.issue.get";
            let response = self.inner.dispatch(request, credential);
            if is_read && !self.moved.swap(true, Ordering::SeqCst) {
                Connection::open(&self.path)
                    .unwrap()
                    .execute(
                        "INSERT INTO policies
                    (policy_id,principal,connection_id,action_selector,effect,updated_at_ms)
                     VALUES ('changed','operator','conn-fixture','edit_issue','block',1)",
                        [],
                    )
                    .unwrap();
            }
            response
        }
    }
    let (scratch, store, _, _, scope) = setup(
        "facade-g9-policy",
        &[("github.issue.get", "read"), ("edit_issue", "write")],
    );
    let transport = Arc::new(AfterRead {
        inner: MockTransport::default(),
        path: scratch.path().into(),
        moved: AtomicBool::new(false),
    });
    transport.inner.set_response(MockResponse::Success(
        json!({"user":{"login":"app-fixture[bot]","type":"Bot"}}),
    ));
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}});
    let now = plexus_core::now_ms();
    let result = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "g9-nonce",
        "g9-id",
        "worker",
        now,
    );
    assert_eq!(
        result["result"]["refusal_code"], "stale_authority{dimension: policy_changed}",
        "{result}"
    );
    assert_eq!(transport.inner.requests().len(), 1);
    assert_eq!(transport.inner.requests()[0].action, "github.issue.get");
}

#[test]
fn edit_last_paginates_then_gets_own_comment_before_patch() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-edit-last",
        &[
            ("github.issue_comments.list", "read"),
            ("github.issue_comment.get", "read"),
            ("update_issue_comment", "write"),
        ],
    );
    let mut first_page: Vec<Value> = (0..100)
        .map(|n| json!({"id":n,"user":{"login":"other","type":"User"}}))
        .collect();
    first_page[99] = json!({"id":100,"user":{"login":"app-fixture[bot]","type":"Bot"}});
    transport.set_response_for_method(
        "github.issue_comments.list",
        "",
        MockResponse::Success(Value::Array(first_page)),
    );
    transport.set_response_for_method(
        "github.issue_comment.get",
        "",
        MockResponse::Success(json!({"id":102,"user":{"login":"app-fixture[bot]","type":"Bot"}})),
    );
    // The page-aware transport returns a short second page; the last-page bot
    // comment wins over the previous page's candidate.
    struct Pages {
        inner: Arc<MockTransport>,
    }
    impl plexus_core::transport::Transport for Pages {
        fn dispatch(
            &self,
            request: plexus_core::transport::TransportRequest,
            credential: &ResolvedCredential,
        ) -> plexus_core::transport::TransportResponse {
            let second =
                request.action == "github.issue_comments.list" && request.args["page"] == 2;
            let response = self.inner.dispatch(request, credential);
            if second {
                plexus_core::transport::TransportResponse::success(json!([
                    {"id":101,"user":{"login":"app-fixture[bot]","type":"User"}},
                    {"id":102,"user":{"login":"app-fixture[bot]","type":"Bot"}}
                ]))
            } else {
                response
            }
        }
    }
    let paging = Arc::new(Pages {
        inner: transport.clone(),
    });
    let engine = GovernanceEngine::new(store.clone(), engine.credential_source().clone(), paging)
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request = json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},
        "edit_last":true,"body":{"body":"replacement"}});
    let now = plexus_core::now_ms();
    let result = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "edit-nonce",
        "edit-id",
        "worker",
        now,
    );
    assert_eq!(result["result"]["status"], "completed", "{result}");
    let requests = transport.requests();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.action.as_str())
            .collect::<Vec<_>>(),
        [
            "github.issue_comments.list",
            "github.issue_comments.list",
            "github.issue_comment.get",
            "update_issue_comment"
        ]
    );
    assert_eq!(requests.last().unwrap().args["comment_id"], 102);
}

#[test]
fn swept_uncertain_facade_effect_records_argument_free_disposition_with_original_request_id() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    struct Crash;
    impl Transport for Crash {
        fn dispatch(&self, _: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
            panic!("simulated crash after the durable pre-transmit marker");
        }
    }
    let (scratch, store, _, _, scope) =
        setup("facade-swept-disposition", &[("add_reaction", "write")]);
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        Arc::new(Crash),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::now_ms();
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "swept-nonce",
            "swept-id",
            "worker",
            now,
        )
    }));
    assert!(crashed.is_err());
    let receipt = store
        .github_receipt("agent-fixture", "swept-nonce")
        .unwrap()
        .unwrap();
    let id = receipt.effects[0].request_id.as_ref().unwrap();
    assert!(receipt.effects[0].dispatch_attempted_at.is_some());
    let db = Connection::open(scratch.path()).unwrap();
    let audit_count: i64 = db
        .query_row(
            "SELECT count(*) FROM audit_journal WHERE request_id=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        audit_count > 0,
        "original reservation audit should carry the request id"
    );
    assert_eq!(
        store
            .sweep_github_receipts(now + 121_000, 100)
            .unwrap()
            .len(),
        1
    );
    let dispositions = store
        .list_write_reconciliations(plexus_core::github::AFT_PRINCIPAL)
        .unwrap()
        .0;
    assert_eq!(dispositions.len(), 1);
    assert_eq!(dispositions[0].request_id, *id);
    assert_eq!(dispositions[0].status, "unreconcilable");
    assert_eq!(
        dispositions[0].reason.as_deref(),
        Some("reconciliation_class_missing")
    );
    assert!(
        store
            .github_receipt("agent-fixture", "swept-nonce")
            .unwrap()
            .unwrap()
            .state
            == "outcome_unknown"
    );
}

#[test]
fn swept_receipt_with_future_reconciliation_class_never_queues_empty_args() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    struct Crash;
    impl Transport for Crash {
        fn dispatch(&self, _: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
            panic!("crash after marker")
        }
    }
    let (scratch, store, _, _, scope) =
        setup("facade-swept-future-class", &[("add_reaction", "write")]);
    Connection::open(scratch.path()).unwrap().execute(
        "UPDATE catalog_actions SET reconciliation_json=?1 WHERE name='add_reaction'",
        [r#"{"correlation_fields":["id"],"read_back_action":"github.issue.get","timeout_s":30}"#]).unwrap();
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        Arc::new(Crash),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::now_ms();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "future-nonce",
            "future-id",
            "worker",
            now
        )))
        .is_err()
    );
    store.sweep_github_receipts(now + 121_000, 100).unwrap();
    let results = store
        .list_write_reconciliations(plexus_core::github::AFT_PRINCIPAL)
        .unwrap()
        .0;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, "unreconcilable");
    assert_eq!(
        results[0].reason.as_deref(),
        Some("reconciliation_args_unavailable")
    );
    let db = Connection::open(scratch.path()).unwrap();
    let pending: i64 = db
        .query_row(
            "SELECT count(*) FROM pending_write_reconciliations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0);
}

#[test]
fn resource_filter_rejects_cross_owner_same_basename_without_resolver() {
    use plexus_core::governance::{AuthorizationRequest, Denial};
    let (_scratch, store, _engine, transport, _) =
        setup("facade-filter-independent", &[("add_reaction", "write")]);
    // This engine does not resolve repository ownership. The resource filter
    // must independently reject another owner's repository with the same name.
    let engine = GovernanceEngine::new(
        store,
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    );
    let denied = engine
        .authorize(AuthorizationRequest::new(
            plexus_core::github::AFT_PRINCIPAL,
            "conn-fixture",
            "add_reaction",
            json!({"owner":"other-org","repo":"repo","issue_number":42,"content":"eyes"}),
        ))
        .unwrap_err();
    assert!(
        matches!(denied, Denial::ResourceFilter(plexus_core::governance::ResourceDenial::ValueNotAllowed(ref key)) if key == "owner"),
        "{denied:?}"
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn own_issue_label_edit_uses_ordered_mapped_legs() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-own-issue-labels",
        &[
            ("github.issue.get", "read"),
            ("edit_issue", "write"),
            ("add_issue_labels", "write"),
            ("remove_issue_label", "write"),
        ],
    );
    transport.set_response_for_method(
        "github.issue.get",
        "",
        MockResponse::Success(json!({"user":{"login":"app-fixture[bot]","type":"Bot"}})),
    );
    let mut request: Value = serde_json::from_str(include_str!(concat!(
        "../",
        "fixtures/gh_shim_wire/requests/v14-issue-edit-labels.request.json"
    )))
    .unwrap();
    request["repository"] = json!("org/repo");
    let now = plexus_core::now_ms();
    let result = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "issue-label-nonce",
        "issue-label-id",
        "worker",
        now,
    );
    assert_eq!(result["result"]["status"], "completed", "{result}");
    let requests = transport.requests();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.action.as_str())
            .collect::<Vec<_>>(),
        ["github.issue.get", "add_issue_labels", "remove_issue_label"]
    );
    assert_eq!(requests[1].args["labels"], json!(["triaged"]));
    assert_eq!(requests[2].args["label"], "needs-triage");
    assert!(requests[2].args.get("add_labels").is_none());
}

#[test]
fn missing_handle_credential_is_reported_at_the_kind_specific_gate() {
    for (label, request, actions, gate) in [
        (
            "facade-credential-read",
            json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}}),
            vec![("github.issue.get", "read"), ("edit_issue", "write")],
            "G8",
        ),
        (
            "facade-credential-write",
            json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}}),
            vec![("add_reaction", "write")],
            "G10",
        ),
    ] {
        let (_scratch, store, _, transport, scope) = setup(label, &actions);
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                plexus_core::credentials::StubCredentialSource::with_default_success(
                    b"test".to_vec(),
                ),
            ),
            transport.clone(),
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: None,
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
        let now = plexus_core::now_ms();
        let result = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "missing-token",
            "missing-id",
            "worker",
            now,
        );
        assert_eq!(
            result["result"]["refusal_code"], "handle_credential_unresolvable{class: permanent}",
            "{result}"
        );
        let audit = store
            .list_audit(plexus_core::github::AFT_PRINCIPAL)
            .unwrap();
        assert_eq!(audit.last().unwrap().gate.as_deref(), Some(gate));
        assert!(transport.requests().is_empty());
    }
}

#[test]
fn page_bound_is_sticky_without_treating_incomplete_list_as_no_comment() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-page-bound",
        &[
            ("github.issue_comments.list", "read"),
            ("github.issue_comment.get", "read"),
            ("update_issue_comment", "write"),
        ],
    );
    transport.set_response(MockResponse::Success(Value::Array(
        (0..100)
            .map(|id| json!({"id":id,"user":{"login":"other","type":"User"}}))
            .collect(),
    )));
    let request = json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},"edit_last":true,"body":{"body":"replacement"}});
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "bounded-nonce",
        "bounded-id",
        "worker",
        now,
    );
    assert_eq!(
        first["result"]["refusal_code"], "pre_dispatch_read_incomplete{reason: page_bound}",
        "{first}"
    );
    assert_eq!(
        transport.requests().len(),
        plexus_core::github::pagination::MAX_PAGES
    );
    assert!(transport
        .requests()
        .iter()
        .all(|r| r.action == "github.issue_comments.list"));
    assert_eq!(
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "bounded-nonce",
            "retry-id",
            "retry",
            now + 1
        )["result"],
        first["result"]
    );
    assert_eq!(
        transport.requests().len(),
        plexus_core::github::pagination::MAX_PAGES
    );
}

#[test]
fn invalid_or_expired_list_releases_claim_for_same_nonce_retry() {
    for (label, invalid, expected) in [
        (
            "facade-bad-list",
            true,
            "pre_dispatch_read_incomplete{reason: invalid_response}",
        ),
        (
            "facade-expired-list",
            false,
            "pre_dispatch_read_incomplete{reason: lease_expired}",
        ),
    ] {
        let (_scratch, store, engine, transport, scope) = setup(
            label,
            &[
                ("github.issue_comments.list", "read"),
                ("github.issue_comment.get", "read"),
                ("update_issue_comment", "write"),
            ],
        );
        transport.set_response(MockResponse::Success(if invalid {
            json!({})
        } else {
            json!([])
        }));
        let request = json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},"edit_last":true,"body":{"body":"replacement"}});
        let current = plexus_core::now_ms();
        let first = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "list-retry-nonce",
            "first-id",
            "first",
            if invalid { current } else { current - 121_000 },
        );
        assert_eq!(first["result"]["refusal_code"], expected, "{first}");
        assert_eq!(
            store
                .github_receipt("agent-fixture", "list-retry-nonce")
                .unwrap()
                .unwrap()
                .state,
            "pending"
        );
        let before = transport.requests().len();
        transport.set_response(MockResponse::Success(json!([])));
        let retry = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "list-retry-nonce",
            "retry-id",
            "retry",
            current + 1,
        );
        assert_eq!(retry["result"]["refusal_code"], "not_present", "{retry}");
        assert!(
            transport.requests().len() > before,
            "retry must issue a fresh list read"
        );
        assert!(transport
            .requests()
            .iter()
            .all(|r| r.action == "github.issue_comments.list"));
    }
}

#[test]
fn g8_read_ask_first_never_creates_an_inner_action_request() {
    let (scratch, store, engine, transport, scope) = setup(
        "facade-read-ask-first",
        &[("github.issue.get", "read"), ("edit_issue", "write")],
    );
    Connection::open(scratch.path())
        .unwrap()
        .execute(
            "UPDATE catalog_actions SET ask_first=1 WHERE name='github.issue.get'",
            [],
        )
        .unwrap();
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}});
    let now = plexus_core::now_ms();
    let result = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "inner-policy-nonce",
        "inner-id",
        "worker",
        now,
    );
    assert_eq!(
        result["result"]["refusal_code"],
        "pipeline_denied{gate: G8, denial: Policy(ApprovalMissing)}",
        "{result}"
    );
    assert!(transport.requests().is_empty());
    let db = Connection::open(scratch.path()).unwrap();
    let count: i64 = db
        .query_row("SELECT count(*) FROM action_requests", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        store
            .github_receipt("agent-fixture", "inner-policy-nonce")
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
}

#[test]
fn g8_read_401_is_sticky_and_never_retransmits() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-read-401",
        &[("github.issue.get", "read"), ("edit_issue", "write")],
    );
    transport.set_response(MockResponse::VendorError {
        code: "http_401".into(),
        message: "expired".into(),
    });
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}});
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "read-401-nonce",
        "read-id",
        "worker",
        now,
    );
    assert_eq!(
        first["result"]["refusal_code"],
        "handle_credential_rejected"
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "github.issue.get");
    assert_eq!(
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "read-401-nonce",
            "retry-id",
            "retry",
            now + 1
        )["result"],
        first["result"]
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn recording_transport_read_set_is_exact_for_every_kind() {
    type ReadCase = (
        &'static str,
        Value,
        Vec<(&'static str, &'static str)>,
        Vec<&'static str>,
    );
    let cases: Vec<ReadCase> = vec![
        (
            "facade-no-read-comment",
            json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hi"}}),
            vec![("add_issue_comment", "write")],
            vec![],
        ),
        (
            "facade-no-read-review",
            json!({"action":"pr review","target":{"number":"42"},"body":{"body":"looks good","event":"COMMENT"}}),
            vec![("add_pr_review", "write")],
            vec![],
        ),
        (
            "facade-no-read-reaction",
            json!({"action":"issue reaction","target":{"number":"42"},"body":{"reaction":"eyes"}}),
            vec![("add_reaction", "write")],
            vec![],
        ),
        (
            "facade-no-read-create",
            json!({"action":"issue create","body":{"title":"example"}}),
            vec![("create_issue", "write")],
            vec![],
        ),
        (
            "facade-comment-patch",
            json!({"action":"api:PATCH:/repos/*/*/issues/comments/*","target":{"comment_id":"123"},"body":{"body":"edited"}}),
            vec![
                ("github.issue_comment.get", "read"),
                ("update_issue_comment", "write"),
            ],
            vec!["github.issue_comment.get"],
        ),
        (
            "facade-close-no-read",
            json!({"verb":"issue close","number":"42"}),
            vec![("close_issue", "write")],
            vec![],
        ),
        (
            "facade-reopen-no-read",
            json!({"verb":"pr reopen","number":"42"}),
            vec![("reopen_issue", "write")],
            vec![],
        ),
    ];
    for (label, mut request, actions, expected_reads) in cases {
        request["repository"] = json!("org/repo");
        let (_scratch, store, engine, transport, scope) = setup(label, &actions);
        transport.set_response_for_method(
            "github.issue_comment.get",
            "",
            MockResponse::Success(
                json!({"id":123,"user":{"login":"app-fixture[bot]","type":"Bot"}}),
            ),
        );
        transport.set_response_for_method(
            "github.issue.get",
            "",
            MockResponse::Success(json!({"user":{"login":"app-fixture[bot]","type":"Bot"}})),
        );
        let now = plexus_core::now_ms();
        let result = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "read-set-nonce",
            "read-set-id",
            "worker",
            now,
        );
        assert_eq!(result["result"]["status"], "completed", "{label}: {result}");
        let requests = transport.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.action.starts_with("github."))
                .map(|r| r.action.as_str())
                .collect::<Vec<_>>(),
            expected_reads,
            "{label}"
        );
        assert_eq!(
            requests.len(),
            expected_reads.len() + 1,
            "one mutation after the exact read set: {label}"
        );
        assert_eq!(requests.last().unwrap().action, actions.last().unwrap().0);
    }
}

#[test]
fn comment_author_mismatch_refuses_before_patch_and_is_sticky() {
    let (_scratch, store, engine, transport, scope) = setup(
        "facade-comment-mismatch",
        &[
            ("github.issue_comment.get", "read"),
            ("update_issue_comment", "write"),
        ],
    );
    transport.set_response_for_method(
        "github.issue_comment.get",
        "",
        MockResponse::Success(json!({"id":123,"user":{"login":"another[bot]","type":"Bot"}})),
    );
    let request = json!({"action":"api:PATCH:/repos/*/*/issues/comments/*","repository":"org/repo",
        "target":{"comment_id":"123"},"body":{"body":"edited"}});
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "comment-mismatch-nonce",
        "first-id",
        "worker",
        now,
    );
    assert_eq!(
        first["result"]["refusal_code"],
        "comment_author_mismatch{expected_login: app-fixture[bot], actual_login: another[bot]}"
    );
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "github.issue_comment.get");
    assert_eq!(
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "comment-mismatch-nonce",
            "retry-id",
            "retry",
            now + 1
        )["result"],
        first["result"]
    );
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn vendor_path_fields_must_come_from_target_not_body() {
    let (_scratch, store, engine, transport, scope) =
        setup("facade-path-field", &[("add_issue_comment", "write")]);
    let request = json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},
        "body":{"body":"safe","issue_number":999}});
    let now = plexus_core::now_ms();
    let result = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "path-field-nonce",
        "path-field-id",
        "worker",
        now,
    );
    assert_eq!(
        result["result"]["refusal_code"], "request_field_forbidden{field: issue_number}",
        "{result}"
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn store_failure_before_vendor_contact_releases_claim_and_retry_sends_once() {
    let (scratch, store, engine, transport, scope) =
        setup("facade-store-failure", &[("add_reaction", "write")]);
    let db = Connection::open(scratch.path()).unwrap();

    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::now_ms();
    let mut reply = plexus_core::github::facade::gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "retryable-store-nonce",
        "first-id",
        "worker",
        now,
        120,
    );
    assert!(matches!(
        reply.claim,
        Some(plexus_core::github::receipt::Claim::Owned(_))
    ));
    db.execute_batch("ALTER TABLE catalog_actions RENAME TO catalog_actions_unavailable;")
        .unwrap();
    let first = plexus_core::github::facade::vendor_band::run(
        &engine,
        &store,
        &mut reply,
        "retryable-store-nonce",
        "worker",
        now,
    );
    assert_eq!(first["refusal_code"], "store_failure", "{first}");
    assert!(transport.requests().is_empty());
    assert_eq!(
        store
            .github_receipt("agent-fixture", "retryable-store-nonce")
            .unwrap()
            .unwrap()
            .state,
        "pending"
    );
    db.execute_batch("ALTER TABLE catalog_actions_unavailable RENAME TO catalog_actions;")
        .unwrap();
    let second = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "retryable-store-nonce",
        "retry-id",
        "worker",
        now + 1,
    );
    assert_eq!(second["result"]["status"], "completed", "{second}");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "add_reaction");
}

#[test]
fn expired_retry_records_unknown_disposition_before_any_sweep_and_never_resends() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    struct Crash;
    impl Transport for Crash {
        fn dispatch(&self, _: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
            panic!("stop after pre-transmit marker");
        }
    }
    let (scratch, store, engine, transport, scope) = setup(
        "facade-retry-unknown-disposition",
        &[("add_reaction", "write")],
    );
    let crash_engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        Arc::new(Crash),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::now_ms();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bot_request_scoped(
            &store,
            &crash_engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "unknown-retry-nonce",
            "first-id",
            "first",
            now
        )))
        .is_err()
    );
    let original = store
        .github_receipt("agent-fixture", "unknown-retry-nonce")
        .unwrap()
        .unwrap();
    let original_request_id = original.effects[0].request_id.as_ref().unwrap().clone();
    assert!(original.effects[0].dispatch_attempted_at.is_some());
    let db = Connection::open(scratch.path()).unwrap();
    db.execute("UPDATE github_bot_receipt SET claim_lease_expires_at=?1 WHERE agent_id='agent-fixture' AND request_nonce='unknown-retry-nonce'",
        [now-1]).unwrap();
    let retry = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "unknown-retry-nonce",
        "retry-id",
        "second",
        now + 1,
    );
    assert_eq!(retry["result"]["status"], "outcome_unknown", "{retry}");
    assert_eq!(
        store
            .github_receipt("agent-fixture", "unknown-retry-nonce")
            .unwrap()
            .unwrap()
            .state,
        "outcome_unknown"
    );
    assert!(transport.requests().is_empty());
    let result = store
        .list_write_reconciliations(plexus_core::github::AFT_PRINCIPAL)
        .unwrap()
        .0;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].request_id, original_request_id);
    assert_eq!(result[0].status, "unreconcilable");
    assert!(store
        .sweep_github_receipts(now + 121_000, 100)
        .unwrap()
        .is_empty());
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM write_reconciliation_results WHERE request_id=?1",
            [original_request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert!(transport.requests().is_empty());
}

#[test]
fn close_with_comment_retries_only_unfinished_state_after_second_pretransmit_stops() {
    let (scratch, store, engine, transport, scope) = setup(
        "facade-stop-between-close-effects",
        &[
            ("github.issue.get", "read"),
            ("add_issue_comment", "write"),
            ("close_issue", "write"),
        ],
    );
    let request =
        json!({"verb":"issue close","repository":"org/repo","number":"42","comment":"once"});
    let now = plexus_core::now_ms();
    let db = Connection::open(scratch.path()).unwrap();
    // Simulate a database failure when effect two is marked as about to be
    // sent. The state-changing request must not follow the completed comment.
    db.execute_batch(
        "CREATE TRIGGER stop_before_state_change BEFORE UPDATE OF effects ON github_bot_receipt
        WHEN json_type(NEW.effects,'$[1].dispatch_attempted_at')='integer'
         AND json_type(OLD.effects,'$[1].dispatch_attempted_at')='null'
        BEGIN SELECT RAISE(ABORT,'stop before state change'); END;",
    )
    .unwrap();
    let stopped = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "two-effect-stop",
        "initial-id",
        "worker-one",
        now,
    );
    assert_eq!(
        stopped["result"]["refusal_code"], "nonce_in_flight",
        "{stopped}"
    );
    let intermediate = store
        .github_receipt("agent-fixture", "two-effect-stop")
        .unwrap()
        .unwrap();
    assert_eq!(intermediate.state, "pending");
    assert_eq!(intermediate.effects.len(), 2);
    assert!(intermediate.effects[0].outcome.is_some());
    assert!(intermediate.effects[1].dispatch_attempted_at.is_none());
    assert_eq!(
        transport
            .requests()
            .iter()
            .filter(|r| r.action == "add_issue_comment")
            .count(),
        1
    );
    assert_eq!(
        transport
            .requests()
            .iter()
            .filter(|r| r.action == "close_issue")
            .count(),
        0
    );
    db.execute_batch("DROP TRIGGER stop_before_state_change;")
        .unwrap();
    db.execute("UPDATE github_bot_receipt SET claim_lease_expires_at=?1 WHERE agent_id='agent-fixture' AND request_nonce='two-effect-stop'",
        [now-1]).unwrap();
    let resumed = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "two-effect-stop",
        "retry-id",
        "worker-two",
        now + 1,
    );
    assert_eq!(resumed["result"]["status"], "completed", "{resumed}");
    let actions: Vec<_> = transport
        .requests()
        .iter()
        .map(|r| r.action.clone())
        .collect();
    assert_eq!(actions, ["add_issue_comment", "close_issue"]);
    let final_receipt = store
        .github_receipt("agent-fixture", "two-effect-stop")
        .unwrap()
        .unwrap();
    assert_eq!(final_receipt.state, "completed");
    assert!(final_receipt
        .effects
        .iter()
        .all(|effect| effect.outcome.is_some()));
}

struct ReadBranchCase {
    label: &'static str,
    request: Value,
    actions: Vec<(&'static str, &'static str)>,
    last_read: &'static str,
    write: &'static str,
}

fn read_branch_cases() -> Vec<ReadBranchCase> {
    vec![
        ReadBranchCase {
            label: "pr-ready",
            request: json!({"verb":"pr ready","repository":"org/repo","number":"7","undo":false}),
            actions: vec![
                ("github.pull_request.get", "read"),
                ("mark_pull_request_ready", "write"),
            ],
            last_read: "github.pull_request.get",
            write: "mark_pull_request_ready",
        },
        ReadBranchCase {
            label: "pr-draft",
            request: json!({"verb":"pr ready","repository":"org/repo","number":"7","undo":true}),
            actions: vec![
                ("github.pull_request.get", "read"),
                ("convert_pull_request_to_draft", "write"),
            ],
            last_read: "github.pull_request.get",
            write: "convert_pull_request_to_draft",
        },
        ReadBranchCase {
            label: "edit-last",
            request: json!({"action":"issue comment","edit_last":true,"repository":"org/repo","target":{"number":"42"},"body":{"body":"replacement"}}),
            actions: vec![
                ("github.issue_comments.list", "read"),
                ("github.issue_comment.get", "read"),
                ("update_issue_comment", "write"),
            ],
            last_read: "github.issue_comment.get",
            write: "update_issue_comment",
        },
        ReadBranchCase {
            label: "comment-patch",
            request: json!({"action":"api:PATCH:/repos/*/*/issues/comments/*","repository":"org/repo","target":{"comment_id":"123"},"body":{"body":"replacement"}}),
            actions: vec![
                ("github.issue_comment.get", "read"),
                ("update_issue_comment", "write"),
            ],
            last_read: "github.issue_comment.get",
            write: "update_issue_comment",
        },
        ReadBranchCase {
            label: "issue-edit",
            request: json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}}),
            actions: vec![("github.issue.get", "read"), ("edit_issue", "write")],
            last_read: "github.issue.get",
            write: "edit_issue",
        },
    ]
}

#[test]
fn g8_entry_matrix_blocks_each_read_branch_before_any_transport_contact() {
    use plexus_core::github::facade::{gates, vendor_band};
    for case in read_branch_cases() {
        for (movement, expected) in [
            ("grant", "stale_authority{dimension: module_grant_revoked}"),
            ("policy", "stale_authority{dimension: policy_changed}"),
        ] {
            let (scratch, store, engine, transport, scope) = setup(
                &format!("matrix-entry-{}-{movement}", case.label),
                &case.actions,
            );
            let now = plexus_core::now_ms();
            let mut reply = gates::run_scoped(
                store.as_ref(),
                plexus_core::github::AFT_PRINCIPAL,
                Some(&scope),
                &case.request,
                "entry-matrix-nonce",
                "entry-matrix-id",
                "worker",
                now,
                120,
            );
            assert!(
                matches!(
                    reply.claim,
                    Some(plexus_core::github::receipt::Claim::Owned(_))
                ),
                "{} {movement}",
                case.label
            );
            let db = Connection::open(scratch.path()).unwrap();
            if movement == "grant" {
                db.execute("DELETE FROM grants WHERE grant_id='module'", [])
                    .unwrap();
            } else {
                db.execute("INSERT INTO policies (policy_id,principal,connection_id,action_selector,effect,updated_at_ms)
                    VALUES ('movement','operator','conn-fixture',?1,'block',1)", [case.write]).unwrap();
            }
            let result = vendor_band::run(
                &engine,
                &store,
                &mut reply,
                "entry-matrix-nonce",
                "worker",
                now,
            );
            assert_eq!(
                result["refusal_code"], expected,
                "{} {movement}: {result}",
                case.label
            );
            assert!(transport.requests().is_empty(), "{} {movement}", case.label);
        }
    }
}

#[test]
fn g9_after_last_read_matrix_blocks_each_branch_before_mutation() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct AfterLastRead {
        inner: MockTransport,
        path: std::path::PathBuf,
        last_read: &'static str,
        write: &'static str,
        movement: &'static str,
        moved: AtomicBool,
    }
    impl Transport for AfterLastRead {
        fn dispatch(
            &self,
            request: TransportRequest,
            credential: &ResolvedCredential,
        ) -> TransportResponse {
            let last = request.action == self.last_read;
            let response = self.inner.dispatch(request, credential);
            if last && !self.moved.swap(true, Ordering::SeqCst) {
                let db = Connection::open(&self.path).unwrap();
                if self.movement == "grant" {
                    db.execute("DELETE FROM grants WHERE grant_id='module'", [])
                        .unwrap();
                } else {
                    db.execute("INSERT INTO policies (policy_id,principal,connection_id,action_selector,effect,updated_at_ms)
                        VALUES ('movement','operator','conn-fixture',?1,'block',1)", [self.write]).unwrap();
                }
            }
            response
        }
    }
    for case in read_branch_cases() {
        for (movement, expected) in [
            ("grant", "stale_authority{dimension: module_grant_revoked}"),
            ("policy", "stale_authority{dimension: policy_changed}"),
        ] {
            let (scratch, store, _, _, scope) = setup(
                &format!("matrix-after-read-{}-{movement}", case.label),
                &case.actions,
            );
            let inner = MockTransport::default();
            inner.set_response_for_method(
                "github.issue_comments.list",
                "",
                MockResponse::Success(
                    json!([{"id":123,"user":{"login":"app-fixture[bot]","type":"Bot"}}]),
                ),
            );
            inner.set_response_for_method(
                "github.issue_comment.get",
                "",
                MockResponse::Success(
                    json!({"id":123,"user":{"login":"app-fixture[bot]","type":"Bot"}}),
                ),
            );
            inner.set_response_for_method(
                "github.issue.get",
                "",
                MockResponse::Success(json!({"user":{"login":"app-fixture[bot]","type":"Bot"}})),
            );
            inner.set_response_for_method(
                "github.pull_request.get",
                "",
                MockResponse::Success(json!({"user":{"login":"app-fixture[bot]","type":"Bot"}})),
            );
            let transport = Arc::new(AfterLastRead {
                inner,
                path: scratch.path().into(),
                last_read: case.last_read,
                write: case.write,
                movement,
                moved: AtomicBool::new(false),
            });
            let engine = GovernanceEngine::new(
                store.clone(),
                Arc::new(
                    plexus_core::credentials::StubCredentialSource::with_default_success(
                        b"test".to_vec(),
                    ),
                ),
                transport.clone(),
            )
            .with_governance_seams(Arc::new(GithubGovernanceSeams {
                store: store.clone(),
                credential_provider: Some(Arc::new(Token)),
            }));
            let now = plexus_core::now_ms();
            let result = bot_request_scoped(
                &store,
                &engine,
                plexus_core::github::AFT_PRINCIPAL,
                Some(&scope),
                &case.request,
                "after-read-nonce",
                "after-read-id",
                "worker",
                now,
            );
            assert_eq!(
                result["result"]["refusal_code"], expected,
                "{} {movement}: {result}",
                case.label
            );
            assert!(
                transport.moved.load(Ordering::SeqCst),
                "{} last GET not reached",
                case.label
            );
            assert!(
                transport
                    .inner
                    .requests()
                    .iter()
                    .all(|r| r.action.starts_with("github.")),
                "{} {movement}",
                case.label
            );
            let receipt = store
                .github_receipt("agent-fixture", "after-read-nonce")
                .unwrap()
                .unwrap();
            assert!(
                receipt
                    .effects
                    .iter()
                    .all(|effect| effect.dispatch_attempted_at.is_none()),
                "{} {movement}",
                case.label
            );
        }
    }
}

// The caller-facing result of a completed request. GitHub's REST bodies carry
// far more than the reply may show (author, text, node ids, the API url); the
// bodies below include those fields so a reply that forwarded a body would be
// caught.

fn bot_user() -> Value {
    json!({"login":"app-fixture[bot]","type":"Bot","id":9,"node_id":"BOT_9"})
}

fn issue_body(number: u64, id: u64, state: &str, state_reason: Value) -> Value {
    json!({
        "id": id,
        "node_id": format!("I_{id}"),
        "number": number,
        "html_url": format!("https://github.com/org/repo/issues/{number}"),
        "url": format!("https://api.github.com/repos/org/repo/issues/{number}"),
        "title": "example",
        "body": "issue text",
        "state": state,
        "state_reason": state_reason,
        "user": bot_user(),
        "labels": [],
    })
}

fn comment_body(id: u64, text: &str) -> Value {
    json!({
        "id": id,
        "node_id": format!("IC_{id}"),
        "html_url": format!("https://github.com/org/repo/issues/42#issuecomment-{id}"),
        "url": format!("https://api.github.com/repos/org/repo/issues/comments/{id}"),
        "body": text,
        "user": bot_user(),
    })
}

/// An abridged GitHub pull request, as POST /repos/{owner}/{repo}/pulls
/// answers: the fields the reply keeps plus several it must not forward.
fn pull_body(number: u64, draft: bool) -> Value {
    json!({
        "id": 9100 + number,
        "node_id": format!("PR_{number}"),
        "number": number,
        "html_url": format!("https://github.com/org/repo/pull/{number}"),
        "url": format!("https://api.github.com/repos/org/repo/pulls/{number}"),
        "title": "example",
        "body": "pull request text",
        "state": "open",
        "draft": draft,
        "merged": false,
        "maintainer_can_modify": false,
        "user": bot_user(),
        "head": {"ref":"feature","label":"org:feature","sha":"abc"},
        "base": {"ref":"main","label":"org:main","sha":"def"},
    })
}

/// Realistic GitHub REST responses for every read and write the facade sends.
fn github_bodies(transport: &MockTransport) {
    for (action, body) in [
        (
            "github.issue_comments.list",
            json!([comment_body(101, "earlier")]),
        ),
        ("github.issue_comment.get", comment_body(101, "earlier")),
        (
            "github.issue.get",
            issue_body(42, 4200, "open", Value::Null),
        ),
        ("add_issue_comment", comment_body(501, "hello")),
        ("update_issue_comment", comment_body(101, "edited")),
        (
            "add_pr_review",
            json!({"id":601,"node_id":"PRR_601",
                "html_url":"https://github.com/org/repo/pull/42#pullrequestreview-601",
                "body":"looks good","state":"COMMENTED","user":bot_user()}),
        ),
        (
            "add_reaction",
            json!({"id":701,"node_id":"REA_701","content":"eyes","user":bot_user(),
                "created_at":"2026-01-01T00:00:00Z"}),
        ),
        ("create_issue", issue_body(43, 4300, "open", Value::Null)),
        ("create_pull_request", pull_body(12, true)),
        (
            "close_issue",
            issue_body(42, 4200, "closed", json!("completed")),
        ),
        ("reopen_issue", issue_body(42, 4200, "open", Value::Null)),
        ("edit_issue", issue_body(42, 4200, "open", Value::Null)),
        (
            "add_issue_labels",
            json!([{"id":1,"node_id":"LA_1","name":"triaged","color":"ededed"}]),
        ),
        ("remove_issue_label", json!([])),
        (
            "add_issue_assignees",
            issue_body(42, 4200, "open", Value::Null),
        ),
        (
            "remove_issue_assignees",
            issue_body(42, 4200, "open", Value::Null),
        ),
    ] {
        transport.set_response_for_method(action, "", MockResponse::Success(body));
    }
}

/// Grants for every read and write that any request kind dispatches, so each
/// test case needs to supply only its request.
fn result_actions() -> Vec<(&'static str, &'static str)> {
    let mut actions = vec![
        ("github.issue_comments.list", "read"),
        ("github.issue_comment.get", "read"),
        ("github.issue.get", "read"),
    ];
    for write in [
        "add_issue_comment",
        "update_issue_comment",
        "add_pr_review",
        "add_reaction",
        "create_issue",
        "create_pull_request",
        "close_issue",
        "reopen_issue",
        "edit_issue",
        "add_issue_labels",
        "remove_issue_label",
        "add_issue_assignees",
        "remove_issue_assignees",
    ] {
        actions.push((write, "write"));
    }
    actions
}

// Fields drop in declaration order, so the store and engine close before the
// scratch guard removes the directory holding their database.
struct ResultRun {
    store: Arc<PlexusStore>,
    engine: GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>,
    transport: Arc<MockTransport>,
    scope: CallScope,
    request: Value,
    now: i64,
    _scratch: plexus_core::test_scratch::Scratch,
}

impl ResultRun {
    /// A facade stack whose transport answers with realistic GitHub bodies;
    /// `adjust` may replace any of them before the request runs.
    fn new(label: &str, request: Value, adjust: impl FnOnce(&MockTransport)) -> Self {
        let mut request = request;
        request["repository"] = json!("org/repo");
        let (scratch, store, engine, transport, scope) = setup(label, &result_actions());
        github_bodies(&transport);
        adjust(&transport);
        Self {
            store,
            engine,
            transport,
            scope,
            _scratch: scratch,
            request,
            now: plexus_core::now_ms(),
        }
    }

    fn call(&self, nonce: &str, request_id: &str, owner: &str, offset: i64) -> Value {
        bot_request_scoped(
            &self.store,
            &self.engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&self.scope),
            &self.request,
            nonce,
            request_id,
            owner,
            self.now + offset,
        )
    }

    fn sent(&self) -> usize {
        self.transport.requests().len()
    }
}

/// Run `request` once and return the whole `result` of a completed reply.
fn completed_result(label: &str, request: Value) -> Value {
    let run = ResultRun::new(label, request, |_| {});
    let reply = run.call("result-nonce", "result-id", "worker", 0);
    assert_eq!(reply["result"]["status"], "completed", "{label}: {reply}");
    assert_eq!(reply["repo_binding_generation"], 1, "{label}: {reply}");
    reply["result"]["result"].clone()
}

#[test]
fn each_request_kind_returns_exactly_its_result_projection() {
    let comment_101 =
        json!({"url":"https://github.com/org/repo/issues/42#issuecomment-101","id":101});
    let issue_42 = json!({"url":"https://github.com/org/repo/issues/42","id":4200});
    let cases = [
        (
            "result-comment",
            json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hello"}}),
            json!({"url":"https://github.com/org/repo/issues/42#issuecomment-501","id":501}),
        ),
        (
            "result-edit-last",
            json!({"action":"pr comment","edit_last":true,"target":{"number":"42"},
                "body":{"body":"replacement"}}),
            comment_101.clone(),
        ),
        (
            "result-comment-edit",
            json!({"action":"api:PATCH:/repos/*/*/issues/comments/*",
                "target":{"comment_id":"101"},"body":{"body":"edited"}}),
            comment_101,
        ),
        (
            "result-pr-review",
            json!({"action":"pr review","target":{"number":"42"},
                "body":{"body":"looks good","event":"COMMENT"}}),
            json!({"url":"https://github.com/org/repo/pull/42#pullrequestreview-601","id":601}),
        ),
        (
            "result-issue-create",
            json!({"action":"issue create","body":{"title":"example"}}),
            json!({"url":"https://github.com/org/repo/issues/43","id":4300}),
        ),
        (
            "result-pr-create",
            pr_create_request(),
            json!({"number":12,"url":"https://github.com/org/repo/pull/12","state":"open","draft":true}),
        ),
        (
            "result-close",
            json!({"verb":"issue close","number":"42"}),
            json!({"state":"closed","state_reason":"completed"}),
        ),
        (
            "result-reopen",
            json!({"verb":"issue reopen","number":"42"}),
            json!({"state":"open","state_reason":null}),
        ),
        (
            "result-issue-edit-title",
            json!({"action":"issue edit","target":{"number":"42"},"body":{"title":"renamed"}}),
            issue_42.clone(),
        ),
        (
            // Label legs answer with a label list, so the issue comes from the
            // ownership read.
            "result-issue-edit-labels",
            json!({"action":"issue edit","target":{"number":"42"},
                "body":{"add_labels":["triaged"],"remove_labels":["needs-triage"]}}),
            issue_42.clone(),
        ),
        (
            "result-issue-edit-assignees",
            json!({"action":"issue edit","target":{"number":"42"},
                "body":{"add_assignees":["octocat"],"remove_assignees":["hubot"]}}),
            issue_42,
        ),
        (
            "result-reaction",
            json!({"action":"issue reaction","target":{"number":"42"},"body":{"reaction":"eyes"}}),
            json!({"id":701,"content":"eyes"}),
        ),
    ];
    for (label, request, expected) in cases {
        assert_eq!(completed_result(label, request), expected, "{label}");
    }
}

/// Every governed call the facade makes (ownership reads, the write, extra
/// legs) carries only arguments its own catalog action declares, never the
/// whole bot request. The REST transport sends every non-path argument, so a
/// close's comment on the issue read, or an issue number in a comment edit's
/// PATCH body, would reach GitHub unreviewed. Each request carries every field
/// its kind accepts, and each leg's recorded arguments are compared with both
/// the shipped schema and the exact set that leg should send.
#[test]
fn every_facade_leg_sends_only_its_actions_declared_arguments() {
    use std::collections::BTreeSet;
    let manifest = github_manifest();
    let declared = |action: &str| -> BTreeSet<String> {
        manifest
            .actions_baseline
            .iter()
            .find(|declared| declared.name == action)
            .and_then(|declared| declared.http.as_ref())
            .unwrap_or_else(|| panic!("{action} is a declared REST action"))
            .args_schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    };
    let issue = ["owner", "repo", "issue_number"];
    let with = |extra: &[&'static str]| -> Vec<&'static str> {
        issue.iter().chain(extra).copied().collect()
    };
    let comment_leg = ["owner", "repo", "comment_id"];
    // (label, bot request, each leg's action and the argument names it sends)
    type LegCase = (&'static str, Value, Vec<(&'static str, Vec<&'static str>)>);
    let cases: Vec<LegCase> = vec![
        (
            "legs-comment",
            json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hello"}}),
            vec![("add_issue_comment", with(&["body"]))],
        ),
        (
            "legs-edit-last",
            json!({"action":"pr comment","edit_last":true,"target":{"number":"42"},
                "body":{"body":"replacement"}}),
            vec![
                ("github.issue_comments.list", with(&["page", "per_page"])),
                ("github.issue_comment.get", comment_leg.to_vec()),
                (
                    "update_issue_comment",
                    ["owner", "repo", "comment_id", "body"].to_vec(),
                ),
            ],
        ),
        (
            "legs-comment-edit",
            json!({"action":"api:PATCH:/repos/*/*/issues/comments/*",
                "target":{"comment_id":"101"},"body":{"body":"edited"}}),
            vec![
                ("github.issue_comment.get", comment_leg.to_vec()),
                (
                    "update_issue_comment",
                    ["owner", "repo", "comment_id", "body"].to_vec(),
                ),
            ],
        ),
        (
            "legs-pr-review",
            json!({"action":"pr review","target":{"number":"42"},
                "body":{"body":"looks good","event":"COMMENT"}}),
            vec![(
                "add_pr_review",
                ["owner", "repo", "pull_number", "body", "event"].to_vec(),
            )],
        ),
        (
            "legs-reaction",
            json!({"action":"issue reaction","target":{"number":"42"},"body":{"reaction":"eyes"}}),
            vec![("add_reaction", with(&["content"]))],
        ),
        (
            "legs-issue-create",
            json!({"action":"issue create","body":{"title":"example","body":"text","labels":["bug"]}}),
            vec![(
                "create_issue",
                ["owner", "repo", "title", "body", "labels"].to_vec(),
            )],
        ),
        (
            "legs-pr-create",
            pr_create_request(),
            vec![(
                "create_pull_request",
                ["owner", "repo", "title", "body", "base", "head", "draft"].to_vec(),
            )],
        ),
        (
            "legs-close",
            json!({"verb":"issue close","number":"42","comment":"done","reason":"not_planned"}),
            vec![
                ("add_issue_comment", with(&["body"])),
                ("close_issue", with(&["state", "state_reason"])),
            ],
        ),
        (
            "legs-reopen",
            json!({"verb":"issue reopen","number":"42","comment":"again"}),
            vec![
                ("add_issue_comment", with(&["body"])),
                ("reopen_issue", with(&["state"])),
            ],
        ),
        (
            "legs-issue-edit",
            json!({"action":"issue edit","target":{"number":"42"},"body":{
                "title":"renamed","body":"text","labels":["a"],"assignees":["octocat"],
                "add_labels":["triaged"],"remove_labels":["needs-triage"],
                "add_assignees":["octocat"],"remove_assignees":["hubot"]}}),
            vec![
                ("github.issue.get", issue.to_vec()),
                (
                    "edit_issue",
                    with(&["title", "body", "labels", "assignees"]),
                ),
                ("add_issue_labels", with(&["labels"])),
                ("remove_issue_label", with(&["label"])),
                ("add_issue_assignees", with(&["assignees"])),
                ("remove_issue_assignees", with(&["assignees"])),
            ],
        ),
    ];
    for (label, request, expected) in cases {
        let run = ResultRun::new(label, request, |_| {});
        let reply = run.call("legs-nonce", "legs-id", "worker", 0);
        assert_eq!(reply["result"]["status"], "completed", "{label}: {reply}");
        let sent: Vec<(String, BTreeSet<String>)> = run
            .transport
            .requests()
            .into_iter()
            .map(|request| {
                let keys = request.args.as_object().unwrap().keys().cloned().collect();
                (request.action, keys)
            })
            .collect();
        for (action, keys) in &sent {
            assert!(
                keys.is_subset(&declared(action)),
                "{label}: {action} sent {keys:?}, declared {:?}",
                declared(action)
            );
        }
        let expected: Vec<(String, BTreeSet<String>)> = expected
            .into_iter()
            .map(|(action, keys)| {
                (
                    action.to_string(),
                    keys.into_iter().map(str::to_string).collect(),
                )
            })
            .collect();
        assert_eq!(sent, expected, "{label}");
    }
}

#[test]
fn result_never_carries_a_field_outside_the_allowlist() {
    // Every body here carries body, user and node_id (and the API url); none
    // of them, nor anything else GitHub sent, may reach the caller.
    let allowed = [
        "url",
        "id",
        "state",
        "state_reason",
        "content",
        "comment",
        "number",
        "draft",
    ];
    for (label, request) in [
        (
            "allowlist-comment",
            json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hello"}}),
        ),
        (
            "allowlist-close",
            json!({"verb":"issue close","number":"42","comment":"done"}),
        ),
        (
            "allowlist-issue-edit",
            json!({"action":"issue edit","target":{"number":"42"},"body":{"title":"renamed"}}),
        ),
        (
            "allowlist-reaction",
            json!({"action":"issue reaction","target":{"number":"42"},"body":{"reaction":"eyes"}}),
        ),
        ("allowlist-pr-create", pr_create_request()),
    ] {
        let result = completed_result(label, request);
        let text = result.to_string();
        for leaked in [
            "\"body\"",
            "\"user\"",
            "\"node_id\"",
            "api.github.com",
            "app-fixture",
        ] {
            assert!(!text.contains(leaked), "{label} leaked {leaked}: {text}");
        }
        let mut objects = vec![&result];
        if let Some(comment) = result.get("comment") {
            objects.push(comment);
        }
        for object in objects {
            for key in object.as_object().unwrap().keys() {
                assert!(
                    allowed.contains(&key.as_str()),
                    "{label}: {key} in {result}"
                );
            }
        }
    }
}

#[test]
fn close_with_comment_returns_state_fields_and_the_posted_comment() {
    for (verb, expected) in [
        (
            "issue close",
            json!({"state":"closed","state_reason":"completed",
                "comment":{"url":"https://github.com/org/repo/issues/42#issuecomment-501","id":501}}),
        ),
        (
            "issue reopen",
            json!({"state":"open","state_reason":null,
                "comment":{"url":"https://github.com/org/repo/issues/42#issuecomment-501","id":501}}),
        ),
    ] {
        let label = format!("result-{}", verb.replace(' ', "-"));
        let result = completed_result(&label, json!({"verb":verb,"number":"42","comment":"done"}));
        assert_eq!(result, expected, "{verb}");
    }
}

#[test]
fn completed_replay_returns_identical_reply_bytes_without_github_calls() {
    for (label, request) in [
        (
            "replay-comment",
            json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hello"}}),
        ),
        (
            "replay-close-with-comment",
            json!({"verb":"issue close","number":"42","comment":"done"}),
        ),
    ] {
        let run = ResultRun::new(label, request, |_| {});
        let first = run.call("replay-nonce", "first-id", "first", 0);
        assert_eq!(first["result"]["status"], "completed", "{label}: {first}");
        assert!(first["result"]["result"].is_object(), "{label}: {first}");
        let sent = run.sent();
        let replay = run.call("replay-nonce", "retry-id", "retry", 1);
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&first).unwrap(),
            "{label}"
        );
        assert_eq!(run.sent(), sent, "{label}: replay contacted GitHub");
    }
}

#[test]
fn missing_html_url_omits_url_and_still_completes() {
    let run = ResultRun::new(
        "result-missing-url",
        json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hello"}}),
        |transport| {
            let mut body = comment_body(501, "hello");
            body.as_object_mut().unwrap().remove("html_url");
            transport.set_response_for_method("add_issue_comment", "", MockResponse::Success(body));
        },
    );
    let reply = run.call("missing-url-nonce", "missing-url-id", "worker", 0);
    assert_eq!(
        reply["result"],
        json!({"status":"completed","result":{"id":501}}),
        "{reply}"
    );
}

/// A pull request request in the shim's nested shape.
fn pr_create_request() -> Value {
    json!({"action":"pr create","target":{},"body":{
        "title":"Add the thing","body":"Opened by the bot.","base":"main","head":"feature","draft":true}})
}

#[test]
fn pr_create_sends_one_post_with_only_the_allowlisted_fields_and_replays_the_receipt() {
    // GitHub's other body fields, and a second owner and repository, ride
    // inside the body; none of them may reach the vendor call.
    let mut request = pr_create_request();
    for (field, value) in [
        ("maintainer_can_modify", json!(true)),
        ("head_repo", json!("someone/fork")),
        ("issue", json!(7)),
        ("owner", json!("someone")),
        ("repo", json!("elsewhere")),
        ("labels", json!(["bug"])),
    ] {
        request["body"][field] = value;
    }
    let run = ResultRun::new("pr-create-happy", request, |_| {});
    let first = run.call("pr-create-nonce", "pr-create-id", "worker", 0);
    let projection = json!({"number":12,"url":"https://github.com/org/repo/pull/12",
        "state":"open","draft":true});
    assert_eq!(
        first["result"],
        json!({"status":"completed","result":projection}),
        "{first}"
    );
    let requests = run.transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].action, "create_pull_request");
    assert_eq!(
        requests[0].args,
        json!({"owner":"org","repo":"repo","title":"Add the thing","body":"Opened by the bot.",
            "base":"main","head":"feature","draft":true})
    );
    // The receipt stores the completed reply, so the retry below is answered
    // from it without a second POST.
    let receipt = run
        .store
        .github_receipt("agent-fixture", "pr-create-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state, "completed");
    assert_eq!(receipt.outcome.as_ref(), Some(&first["result"]));

    let retry = run.call("pr-create-nonce", "pr-create-retry-id", "retry", 1);
    assert_eq!(retry["result"], first["result"], "{retry}");
    assert_eq!(run.sent(), 1, "the retry contacted GitHub");
}

#[test]
fn pr_create_refuses_bad_heads_and_other_shapes_before_any_vendor_call() {
    let with = |field: &str, value: Value| {
        let mut request = pr_create_request();
        request["body"][field] = value;
        request
    };
    let without = |field: &str| {
        let mut request = pr_create_request();
        request["body"].as_object_mut().unwrap().remove(field);
        request
    };
    let top_level = |field: &str, value: Value| {
        let mut request = pr_create_request();
        request[field] = value;
        request
    };
    let cases = [
        (
            "cross-repo",
            with("head", json!("someone:branch")),
            "pr_head_cross_repository",
        ),
        (
            "empty-head",
            with("head", json!("")),
            "request_field_forbidden{field: head}",
        ),
        (
            "missing-head",
            without("head"),
            "request_field_forbidden{field: head}",
        ),
        (
            "empty-base",
            with("base", json!("")),
            "request_field_forbidden{field: base}",
        ),
        (
            "missing-base",
            without("base"),
            "request_field_forbidden{field: base}",
        ),
        (
            "head-is-base",
            with("head", json!("main")),
            "request_field_forbidden{field: head}",
        ),
        (
            "flat-title",
            top_level("title", json!("Add the thing")),
            "request_field_forbidden{field: title}",
        ),
        (
            "flat-head",
            top_level("head", json!("feature")),
            "request_field_forbidden{field: head}",
        ),
        (
            "string-body",
            top_level("body", json!("Opened by the bot.")),
            "request_field_forbidden{field: body}",
        ),
        (
            "top-level-owner",
            top_level("owner", json!("someone")),
            "request_field_forbidden{field: owner}",
        ),
        (
            "top-level-repo",
            top_level("repo", json!("elsewhere")),
            "request_field_forbidden{field: repo}",
        ),
    ];
    for (label, request, code) in cases {
        let run = ResultRun::new(&format!("pr-create-refuse-{label}"), request, |_| {});
        let reply = run.call("refuse-nonce", "refuse-id", "worker", 0);
        assert_eq!(
            reply["result"],
            json!({"status":"refused","refusal_code":code}),
            "{label}: {reply}"
        );
        assert_eq!(run.sent(), 0, "{label}: GitHub was contacted");
    }
}

#[test]
fn pr_create_without_the_agents_grant_refuses_and_sends_nothing() {
    // The calling module's grant covers create_pull_request; the agent's own
    // grant covers only create_issue.
    let (scratch, store, engine, transport, scope) = setup(
        "pr-create-no-grant",
        &[("create_issue", "write"), ("create_pull_request", "write")],
    );
    Connection::open(scratch.path())
        .unwrap()
        .execute(
            "UPDATE grants SET action_selectors='[\"create_issue\"]' WHERE grant_id='agent'",
            [],
        )
        .unwrap();
    github_bodies(&transport);
    let mut request = pr_create_request();
    request["repository"] = json!("org/repo");
    let reply = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "no-grant-nonce",
        "no-grant-id",
        "worker",
        plexus_core::now_ms(),
    );
    assert_eq!(
        reply["result"],
        json!({"status":"refused",
            "refusal_code":"agent_grant_excludes_request{request_kind: pr_create, repository: org/repo}"}),
        "{reply}"
    );
    assert!(transport.requests().is_empty());
}

#[path = "../support/http_server.rs"]
mod validation_http;

fn validation_rest_engine(
    store: Arc<PlexusStore>,
    status: u16,
    body: &str,
) -> (
    GovernanceEngine<
        plexus_core::credentials::StubCredentialSource,
        plexus_core::rest_api::RestTransport,
    >,
    validation_http::FixedRequestServer,
) {
    use plexus_core::manifest::{HttpMethod, HttpOperation};
    use plexus_core::rest_api::{RestConfig, RestTransport};
    let body = body.to_owned();
    let (endpoint, server) = validation_http::FixedRequestServer::start(
        1,
        "GitHub validation",
        move |_, _| {
            format!("HTTP/1.1 {status} Refused\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        },
    );
    let operation = HttpOperation {
        method: HttpMethod::Post,
        parameters: None,
        path: "/fixture".into(),
        args_schema: json!({"type":"object"}),
        request_constants: None,
        credentialless_tail: None,
        text_path_parameters: None,
        header_parameters: None,
    };
    let transport = Arc::new(RestTransport::new(RestConfig::new(endpoint).with_actions(
        std::collections::HashMap::from([
            ("add_reaction".into(), operation.clone()),
            ("get_issue".into(), operation),
        ]),
    )));
    let engine = GovernanceEngine::new(
        store,
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport,
    );
    (engine, server)
}

fn validation_facade_reply(label: &str, status: u16, body: &str) -> Value {
    let (_scratch, store, _, _, scope) = setup(label, &[("add_reaction", "write")]);
    let (engine, server) = validation_rest_engine(store.clone(), status, body);
    let engine = engine
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::now_ms();
    let reply = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "validation-nonce",
        "validation-id",
        "worker",
        now,
    );
    server.join().unwrap();
    let replay = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "validation-nonce",
        "retry-id",
        "worker",
        now + 1,
    );
    assert_eq!(reply["result"], replay["result"]);
    reply
}

#[test]
fn validation_422_real_facade_projects_only_structured_errors() {
    let reply = validation_facade_reply(
        "validation-structured",
        422,
        r#"{"message":"Validation Failed","documentation_url":"https://example.invalid/secret","errors":[{"resource":"PullRequest","field":"head","code":"invalid"}]}"#,
    );
    assert_eq!(reply["result"]["refusal_code"], "vendor_rejected{status: 422, errors: [{\"code\":\"invalid\",\"field\":\"head\",\"resource\":\"PullRequest\"}]}");
    let text = reply.to_string();
    assert!(!text.contains("Validation Failed"));
    assert!(!text.contains("message"));
    assert!(!text.contains("documentation_url"));
}

#[test]
fn validation_422_custom_real_facade_never_exposes_vendor_message() {
    let reply = validation_facade_reply(
        "validation-custom",
        422,
        r#"{"message":"ghs_planted_top_secret","errors":[{"resource":"PullRequest","field":"head","code":"custom","message":"ghs_planted_error_secret","documentation_url":"ghs_planted_url_secret"}]}"#,
    );
    assert_eq!(reply["result"]["refusal_code"], "vendor_rejected{status: 422, errors: [{\"code\":\"custom\",\"field\":\"head\",\"resource\":\"PullRequest\"}]}");
    assert!(!reply.to_string().contains("ghs_"));
    assert!(!reply.to_string().contains("message"));
}

#[test]
fn validation_422_real_facade_drops_invalid_entries_and_caps_at_ten() {
    let mut entries = vec![
        json!({"resource":"PullRequest","field":"head","code":"unexpected"}),
        json!({"resource":"PullRequest","field":"x".repeat(65),"code":"invalid"}),
        json!({"resource":"PullRequest","field":"head-secret!","code":"invalid"}),
        json!({"resource":"PullRequest","field":"head","code":"invalid","extra":"value"}),
        json!({"resource":"","field":"head","code":"invalid"}),
        json!({"resource":"非ASCII","field":"head","code":"invalid"}),
        json!({"resource":"PullRequest","field":null,"code":"invalid"}),
    ];
    for code in [
        "missing",
        "missing_field",
        "invalid",
        "already_exists",
        "unprocessable",
        "custom",
    ]
    .into_iter()
    .cycle()
    .take(12)
    {
        entries.push(json!({"resource":"Pull.Request_1","field":"head","code":code}));
    }
    let reply = validation_facade_reply(
        "validation-filter",
        422,
        &json!({"errors": entries}).to_string(),
    );
    let refusal = reply["result"]["refusal_code"].as_str().unwrap();
    let errors: Value = serde_json::from_str(
        refusal
            .strip_prefix("vendor_rejected{status: 422, errors: ")
            .unwrap()
            .strip_suffix('}')
            .unwrap(),
    )
    .unwrap();
    assert_eq!(errors, Value::Array(entries[7..17].to_vec()));
}

#[test]
fn validation_422_real_facade_drops_free_text_identifiers_but_keeps_valid_sibling() {
    for (key, invalid) in [
        ("field", "head branch".to_owned()),
        ("field", "head;rm".to_owned()),
        ("field", "héad".to_owned()),
        ("field", "x".repeat(65)),
        ("resource", "Pull Request".to_owned()),
    ] {
        let mut rejected = json!({"resource":"PullRequest","field":"head","code":"invalid"});
        rejected[key] = json!(invalid);
        let valid = json!({"resource":"PullRequest","field":"head","code":"invalid"});
        let reply = validation_facade_reply(
            "validation-identifier-boundaries",
            422,
            &json!({"errors": [rejected, valid]}).to_string(),
        );
        assert_eq!(
            reply["result"]["refusal_code"],
            "vendor_rejected{status: 422, errors: [{\"code\":\"invalid\",\"field\":\"head\",\"resource\":\"PullRequest\"}]}",
            "invalid {key}: {invalid} must be dropped while the valid sibling survives"
        );
        assert!(
            !reply.to_string().contains(&invalid),
            "invalid {key}: {invalid} leaked into the reply: {reply}"
        );
    }
}

#[test]
fn validation_422_real_facade_unparseable_body_has_no_errors() {
    let reply = validation_facade_reply("validation-unparseable", 422, "ghs_secret_not_json");
    assert_eq!(
        reply["result"]["refusal_code"],
        "vendor_rejected{status: 422}"
    );
    assert!(!reply.to_string().contains("ghs_"));
}

#[test]
fn validation_non_422_real_facade_is_unchanged() {
    let reply = validation_facade_reply(
        "validation-other-status",
        403,
        r#"{"message":"ghs_secret","errors":[{"resource":"PullRequest","field":"head","code":"invalid"}]}"#,
    );
    assert_eq!(
        reply["result"]["refusal_code"],
        "vendor_rejected{status: 403}"
    );
    assert!(!reply.to_string().contains("ghs_"));
}

#[test]
fn validation_422_ordinary_invoke_keeps_operator_only_diagnostic() {
    use plexus_core::governance::{AuthorizationRequest, TransportOutcome};
    let (_scratch, store, _, _, _) = setup("validation-ordinary", &[("get_issue", "read")]);
    // Generic invokes resolve a vault credential id on a normal connection.
    // Bot handles require a separate scoped App-token reader, not used here.
    let original = store
        .connection("operator", "conn-fixture")
        .unwrap()
        .unwrap();
    let input = store
        .catalog_action("operator", "conn-fixture", "get_issue")
        .unwrap()
        .unwrap();
    let ceiling = plexus_core::Ceiling {
        risk: plexus_core::Risk::Read,
        action_selectors: vec!["get_issue".into()],
    };
    let ticket = store
        .issue_binding_ticket(
            "operator",
            "conn-ordinary-validation",
            &original.app_key,
            "credential_reference",
            b"test:binding",
            &ceiling,
        )
        .unwrap()
        .unwrap();
    store
        .connect_with_ticket("operator", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            principal: "operator".into(),
            connection_id: "conn-ordinary-validation".into(),
            name: "get_issue".into(),
            title: input.title,
            schema: input.schema,
            schema_hash: input.schema_hash,
            risk: input.risk,
            severity: input.severity,
            ask_first: input.ask_first,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: input.reconciliation,
        })
        .unwrap();
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "ordinary-validation".into(),
            principal: "operator".into(),
            connection_id: "conn-ordinary-validation".into(),
            grantee_principal: plexus_core::github::AFT_PRINCIPAL.into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["get_issue".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let (engine, server) = validation_rest_engine(
        store,
        422,
        r#"{"message":"ghs_secret","errors":[{"resource":"PullRequest","field":"head","code":"invalid"}]}"#,
    );
    let reservation = engine
        .authorize(AuthorizationRequest::new(
            plexus_core::github::AFT_PRINCIPAL,
            "conn-ordinary-validation",
            "get_issue",
            json!({"repository":"org/repo", "owner":"org", "repo":"repo", "issue_number":42}),
        ))
        .unwrap();
    let outcome = engine.revalidate_and_dispatch(&reservation);
    server.join().unwrap();
    assert_eq!(
        outcome.outcome,
        TransportOutcome::VendorFailed {
            code: "http_422".into(),
            message: "vendor request failed; plexus logged the full diagnostic (see `ck module logs plexus`)".into()
        }
    );
}

// Bot requests on a route bound under a daemon scope. A scope that delegates
// to its agent identifies the agent, and the scope is read back from the daemon before
// each write. The daemon's `scope.describe` answers come from a scripted
// reader, so a test can end the scope, or make the daemon silent, at an exact
// point between the reads and the writes.

mod scoped {
    use super::*;
    use plexus_core::github::facade::bot_request_scoped;
    use plexus_core::scope::{
        CallScope, ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;

    type Answer = Result<ScopeDescription, ScopeReadError>;

    /// Answers `scope.describe` from a queue, then with `live` once the queue
    /// is empty, and counts every question.
    #[derive(Default)]
    struct ScriptedScope {
        queue: Mutex<VecDeque<Answer>>,
        asked: Mutex<usize>,
    }

    impl ScriptedScope {
        fn then(&self, answer: Answer) -> &Self {
            self.queue.lock().unwrap().push_back(answer);
            self
        }
        fn asked(&self) -> usize {
            *self.asked.lock().unwrap()
        }
    }

    impl ScopeReader for ScriptedScope {
        fn describe(&self, _: &str, _: &str) -> Answer {
            *self.asked.lock().unwrap() += 1;
            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(live(stamp("agent-fixture", true))))
        }
    }

    fn stamp(agent: &str, delegates: bool) -> CallScope {
        CallScope {
            owner: "reserved:prefrontal-core".into(),
            scope_ref: "head-1".into(),
            scope_epoch: 3,
            kind: Some("head".into()),
            parent: None,
            parent_state: None,
            agent_id: Some(agent.into()),
            delegates,
            owner_authorized: true,
            flow_id: None,
        }
    }

    fn live(scope: CallScope) -> ScopeDescription {
        ScopeDescription {
            status: ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(scope),
        }
    }

    fn ended() -> Answer {
        Ok(ScopeDescription {
            status: ScopeStatus::Ended,
            owner_synced: true,
            owner_configured: true,
            live: None,
        })
    }

    fn not_synced() -> Answer {
        Ok(ScopeDescription {
            status: ScopeStatus::NotLive,
            owner_synced: false,
            owner_configured: true,
            live: None,
        })
    }

    fn unanswered() -> Answer {
        Err(ScopeReadError("scope.describe timed out".into()))
    }

    // The scratch guard is declared last so it drops after the store it holds.
    struct Scoped {
        store: Arc<PlexusStore>,
        engine: GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>,
        transport: Arc<MockTransport>,
        reader: Arc<ScriptedScope>,
        scratch: plexus_core::test_scratch::Scratch,
    }

    fn scoped(label: &str, actions: &[(&str, &str)]) -> Scoped {
        let (scratch, store, engine, transport, _scope) = setup(label, actions);
        let reader = Arc::new(ScriptedScope::default());
        let engine = engine.with_scope_reader(Arc::clone(&reader) as Arc<dyn ScopeReader>);
        Scoped {
            scratch,
            store,
            engine,
            transport,
            reader,
        }
    }

    fn now() -> i64 {
        plexus_core::now_ms()
    }

    impl Scoped {
        /// Send a bot request with the daemon's route-session identity supplied
        /// separately as `scope`, never as a caller argument.
        fn send(&self, scope: &CallScope, request: &Value, nonce: &str, at: i64) -> Value {
            bot_request_scoped(
                &self.store,
                &self.engine,
                plexus_core::github::AFT_PRINCIPAL,
                Some(scope),
                request,
                nonce,
                &format!("{nonce}-{at}"),
                "worker",
                at,
            )
        }

        fn actions(&self) -> Vec<String> {
            self.transport
                .requests()
                .iter()
                .map(|request| request.action.clone())
                .collect()
        }
    }

    fn reaction() -> Value {
        json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}})
    }

    const CLOSE_ACTIONS: &[(&str, &str)] = &[
        ("github.issue.get", "read"),
        ("add_issue_comment", "write"),
        ("close_issue", "write"),
    ];

    #[test]
    fn a_delegating_stamp_posts_as_its_agents_bot() {
        let fixture = scoped("scoped-stamp-only", &[("add_reaction", "write")]);
        let reply = fixture.send(
            &stamp("agent-fixture", true),
            &reaction(),
            "stamp-only",
            now(),
        );
        assert_eq!(reply["result"]["status"], "completed", "{reply}");
        assert_eq!(fixture.actions(), ["add_reaction"]);
        assert_eq!(fixture.reader.asked(), 1, "the write re-read its scope");
        let receipt = fixture
            .store
            .github_receipt("agent-fixture", "stamp-only")
            .unwrap()
            .expect("the receipt belongs to the stamp's agent");
        assert_eq!(receipt.state, "completed");
        let (agent, handle, handle_claim): (String, String, Option<String>) =
            Connection::open(fixture.scratch.path())
                .unwrap()
                .query_row(
                    "SELECT agent_id, app_handle_id, agent_handle FROM audit_journal
                     WHERE action='github.bot_request' AND request_id LIKE 'stamp-only-%'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
        assert_eq!(
            (agent.as_str(), handle.as_str()),
            ("agent-fixture", "app-fixture"),
            "the agent's own bot handled the write"
        );
        assert_eq!(handle_claim, None, "the stamp does not claim a bot login");
    }

    #[test]
    fn a_stamp_that_does_not_act_as_its_agent_refuses_without_dispatch() {
        let fixture = scoped("scoped-non-delegating", &[("add_reaction", "write")]);
        let mut unauthorized = stamp("agent-fixture", true);
        unauthorized.owner_authorized = false;
        for (nonce, scope) in [
            ("not-delegating", stamp("agent-fixture", false)),
            ("owner-unauthorized", unauthorized),
        ] {
            let reply = fixture.send(&scope, &reaction(), nonce, now());
            assert_eq!(
                reply["result"]["refusal_code"], "delegating_scope_required",
                "{nonce}: {reply}"
            );
            assert!(fixture
                .store
                .github_receipt("agent-fixture", nonce)
                .unwrap()
                .is_none());
        }
        assert!(fixture.transport.requests().is_empty());
        assert_eq!(fixture.reader.asked(), 0);
    }

    #[test]
    fn a_delegating_agent_with_no_bot_refuses_by_name() {
        let fixture = scoped("scoped-no-bot", &[("add_reaction", "write")]);
        let reply = fixture.send(
            &stamp("agent-without-bot", true),
            &reaction(),
            "no-bot",
            now(),
        );
        assert_eq!(
            reply["result"]["refusal_code"], "agent_handle_unknown",
            "{reply}"
        );
        assert!(fixture.transport.requests().is_empty());
    }

    /// Counts every request for a handle's credential, standing in for the
    /// vault read an installation token needs.
    #[derive(Default)]
    struct CountingToken(Mutex<usize>);
    impl HandleCredentialProvider for CountingToken {
        fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
            *self.0.lock().unwrap() += 1;
            Ok(ResolvedCredential::anonymous())
        }
        fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
    }

    /// The bot a delegating stamp resolves must be the App its credential
    /// names; a handle row whose vault credential belongs to another App is
    /// refused before anything is read from the vault or sent to GitHub.
    #[test]
    fn a_stamp_resolved_handle_with_another_apps_credential_refuses_unknown() {
        let (scratch, store, _engine, transport, _scope) =
            setup("scoped-foreign-credential", &[("add_reaction", "write")]);
        let token = Arc::new(CountingToken::default());
        let reader = Arc::new(ScriptedScope::default());
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                plexus_core::credentials::StubCredentialSource::with_default_success(
                    b"test".to_vec(),
                ),
            ),
            transport.clone(),
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(token.clone()),
        }))
        .with_scope_reader(Arc::clone(&reader) as Arc<dyn ScopeReader>);
        let db = Connection::open(scratch.path()).unwrap();
        db.execute(
            "UPDATE github_app_handle SET credential_reference='github_app:someone-else'
             WHERE app_handle_id='app-fixture'",
            [],
        )
        .unwrap();
        let reply = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&stamp("agent-fixture", true)),
            &reaction(),
            "foreign-credential",
            "foreign-credential-id",
            "worker",
            now(),
        );
        assert_eq!(
            reply["result"]["refusal_code"], "agent_handle_unknown",
            "{reply}"
        );
        let gate: String = db
            .query_row(
                "SELECT gate FROM audit_journal WHERE request_id='foreign-credential-id'
                 AND action='github.bot_request'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(gate, "G2");
        assert!(transport.requests().is_empty(), "nothing sent to GitHub");
        assert_eq!(*token.0.lock().unwrap(), 0, "no credential was read");
        assert_eq!(reader.asked(), 0);
        assert!(store
            .github_receipt("agent-fixture", "foreign-credential")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_scope_ended_after_the_read_stops_the_write_and_the_refusal_replays() {
        let fixture = scoped(
            "scoped-ended-before-write",
            &[("github.issue.get", "read"), ("edit_issue", "write")],
        );
        fixture.transport.set_response(MockResponse::Success(
            json!({"user":{"login":"app-fixture[bot]","type":"Bot"}}),
        ));
        fixture.reader.then(ended());
        let close = json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}});
        let scope = stamp("agent-fixture", true);
        let first = fixture.send(&scope, &close, "ended-close", now());
        assert_eq!(
            first["result"],
            json!({"status":"refused","refusal_code":"scope_ended","legs_sent":[]}),
            "{first}"
        );
        assert_eq!(
            fixture.actions(),
            ["github.issue.get"],
            "the read ran, the write did not"
        );
        let receipt = fixture
            .store
            .github_receipt("agent-fixture", "ended-close")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "refused");
        assert_eq!(receipt.refusal_code.as_deref(), Some("scope_ended"));
        assert!(receipt.effects[0].dispatch_attempted_at.is_none());

        let retry = fixture.send(&scope, &close, "ended-close", now() + 1);
        assert_eq!(retry["result"], first["result"]);
        assert_eq!(
            fixture.actions(),
            ["github.issue.get"],
            "no second vendor call"
        );
        assert_eq!(fixture.reader.asked(), 1, "the replay did not ask again");
    }

    #[test]
    fn pr_ready_and_undo_recheck_scope_after_the_ownership_read() {
        for undo in [false, true] {
            let action = if undo {
                "convert_pull_request_to_draft"
            } else {
                "mark_pull_request_ready"
            };
            let fixture = scoped(
                "pr-ready-ended-scope",
                &[("github.pull_request.get", "read"), (action, "write")],
            );
            fixture.transport.set_response_for_method(
                "github.pull_request.get",
                "",
                MockResponse::Success(json!({
                    "user":{"login":"app-fixture[bot]","type":"Bot"}, "draft":!undo,
                    "node_id":"PR_7", "html_url":"https://github.com/org/repo/pull/7", "number":7
                })),
            );
            fixture.reader.then(ended());
            let request =
                json!({"verb":"pr ready","repository":"org/repo","number":"7","undo":undo});
            let reply = fixture.send(
                &stamp("agent-fixture", true),
                &request,
                "ready-ended",
                now(),
            );
            assert_eq!(reply["result"]["refusal_code"], "scope_ended", "{reply}");
            assert_eq!(fixture.actions(), ["github.pull_request.get"]);
            assert_eq!(fixture.reader.asked(), 1);
        }
    }

    #[test]
    fn a_scope_ended_between_legs_keeps_the_comment_and_skips_the_close() {
        let fixture = scoped("scoped-ended-between-legs", CLOSE_ACTIONS);
        fixture
            .reader
            .then(Ok(live(stamp("agent-fixture", true))))
            .then(ended());
        let close =
            json!({"verb":"issue close","repository":"org/repo","number":"42","comment":"done"});
        let scope = stamp("agent-fixture", true);
        let first = fixture.send(&scope, &close, "ended-between", now());
        assert_eq!(
            first["result"],
            json!({"status":"refused","refusal_code":"scope_ended","legs_sent":["add_issue_comment"]}),
            "{first}"
        );
        assert_eq!(fixture.actions(), ["add_issue_comment"]);
        let receipt = fixture
            .store
            .github_receipt("agent-fixture", "ended-between")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "refused");
        assert_eq!(receipt.effects[0].effect, "add_issue_comment");
        assert!(receipt.effects[0].outcome.is_some(), "the comment was sent");
        assert_eq!(receipt.effects[1].effect, "close_issue");
        assert!(
            receipt.effects[1].dispatch_attempted_at.is_none()
                && receipt.effects[1].outcome.is_none(),
            "the close was never attempted"
        );
        let retry = fixture.send(&scope, &close, "ended-between", now() + 1);
        assert_eq!(retry["result"], first["result"]);
        assert_eq!(fixture.actions().len(), 1);
    }

    #[test]
    fn delegation_turned_off_before_the_write_refuses_delegation_withdrawn() {
        let fixture = scoped("scoped-withdrawn", &[("add_reaction", "write")]);
        fixture.reader.then(Ok(live(stamp("agent-fixture", false))));
        let reply = fixture.send(
            &stamp("agent-fixture", true),
            &reaction(),
            "withdrawn",
            now(),
        );
        assert_eq!(
            reply["result"]["refusal_code"], "delegation_withdrawn",
            "{reply}"
        );
        assert!(fixture.transport.requests().is_empty());
    }

    #[test]
    fn a_not_synced_scope_sends_nothing_and_is_not_cached() {
        let fixture = scoped("scoped-not-synced", &[("add_reaction", "write")]);
        fixture.reader.then(not_synced());
        let scope = stamp("agent-fixture", true);
        let first = fixture.send(&scope, &reaction(), "not-synced", now());
        assert_eq!(
            first["result"],
            json!({"status":"refused","refusal_code":"scope_not_synced","legs_sent":[]}),
            "{first}"
        );
        assert!(fixture.transport.requests().is_empty());
        let receipt = fixture
            .store
            .github_receipt("agent-fixture", "not-synced")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "pending", "no refusal was recorded");
        assert_eq!(receipt.claim_owner, None, "the claim was released");
        assert!(receipt.effects[0].dispatch_attempted_at.is_none());

        let retry = fixture.send(&scope, &reaction(), "not-synced", now() + 1);
        assert_eq!(retry["result"]["status"], "completed", "{retry}");
        assert_eq!(fixture.actions(), ["add_reaction"], "sent exactly once");
        assert_eq!(fixture.reader.asked(), 2, "retry rechecks the synced owner");
    }

    #[test]
    fn a_not_synced_scope_between_legs_resumes_at_the_close_on_retry() {
        let fixture = scoped("scoped-not-synced-between", CLOSE_ACTIONS);
        fixture
            .reader
            .then(Ok(live(stamp("agent-fixture", true))))
            .then(not_synced());
        let close =
            json!({"verb":"issue close","repository":"org/repo","number":"42","comment":"once"});
        let scope = stamp("agent-fixture", true);
        let first = fixture.send(&scope, &close, "not-synced-between", now());
        assert_eq!(
            first["result"],
            json!({"status":"refused","refusal_code":"scope_not_synced","legs_sent":["add_issue_comment"]}),
            "{first}"
        );
        assert_eq!(fixture.actions(), ["add_issue_comment"]);
        let receipt = fixture
            .store
            .github_receipt("agent-fixture", "not-synced-between")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "pending");
        assert_eq!(receipt.claim_owner, None);
        assert!(receipt.effects[0].outcome.is_some(), "the comment was sent");
        assert!(receipt.effects[1].dispatch_attempted_at.is_none());
        assert!(
            receipt.effects[1].outcome.is_none(),
            "the close was not sent"
        );

        let retry = fixture.send(&scope, &close, "not-synced-between", now() + 1);
        assert_eq!(retry["result"]["status"], "completed", "{retry}");
        assert_eq!(
            fixture.actions(),
            ["add_issue_comment", "close_issue"],
            "the comment is not sent twice"
        );
        assert_eq!(
            fixture.reader.asked(),
            3,
            "only the unsent leg is rechecked"
        );
    }

    #[test]
    fn an_unanswered_scope_read_sends_nothing_and_is_not_cached() {
        let fixture = scoped("scoped-unverifiable", &[("add_reaction", "write")]);
        fixture.reader.then(unanswered());
        let scope = stamp("agent-fixture", true);
        let first = fixture.send(&scope, &reaction(), "unverifiable", now());
        assert_eq!(
            first["result"],
            json!({"status":"refused","refusal_code":"scope_unverifiable","legs_sent":[]}),
            "{first}"
        );
        assert!(fixture.transport.requests().is_empty());
        let receipt = fixture
            .store
            .github_receipt("agent-fixture", "unverifiable")
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "pending", "no refusal was recorded");
        assert_eq!(receipt.claim_owner, None, "the claim was released");

        let retry = fixture.send(&scope, &reaction(), "unverifiable", now() + 1);
        assert_eq!(retry["result"]["status"], "completed", "{retry}");
        assert_eq!(fixture.actions(), ["add_reaction"], "sent exactly once");
    }

    #[test]
    fn an_unanswered_read_between_legs_resumes_at_the_close_on_retry() {
        let fixture = scoped("scoped-unverifiable-between", CLOSE_ACTIONS);
        fixture
            .reader
            .then(Ok(live(stamp("agent-fixture", true))))
            .then(unanswered());
        let close =
            json!({"verb":"issue close","repository":"org/repo","number":"42","comment":"once"});
        let scope = stamp("agent-fixture", true);
        let first = fixture.send(&scope, &close, "unverifiable-between", now());
        assert_eq!(
            first["result"],
            json!({"status":"refused","refusal_code":"scope_unverifiable","legs_sent":["add_issue_comment"]}),
            "{first}"
        );
        let retry = fixture.send(&scope, &close, "unverifiable-between", now() + 1);
        assert_eq!(retry["result"]["status"], "completed", "{retry}");
        assert_eq!(
            fixture.actions(),
            ["add_issue_comment", "close_issue"],
            "the comment is not sent twice"
        );
    }
}

#[test]
fn handle_unbind_after_authorization_stops_dispatch() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    struct UnbindAfterRead {
        inner: MockTransport,
        store: Arc<PlexusStore>,
    }
    impl Transport for UnbindAfterRead {
        fn dispatch(
            &self,
            request: TransportRequest,
            credential: &ResolvedCredential,
        ) -> TransportResponse {
            let is_read = request.action == "github.issue.get";
            let response = self.inner.dispatch(request, credential);
            if is_read {
                plexus_core::github::control::unbind(
                    &self.store,
                    "direct",
                    "app-fixture",
                    "org/repo",
                    "in-flight-unbind",
                    false,
                )
                .unwrap();
            }
            response
        }
    }
    let (_scratch, store, _, _, scope) = setup(
        "unbind-in-flight",
        &[("github.issue.get", "read"), ("edit_issue", "write")],
    );
    let transport = Arc::new(UnbindAfterRead {
        inner: MockTransport::default(),
        store: store.clone(),
    });
    transport.inner.set_response(MockResponse::Success(
        json!({"user":{"login":"app-fixture[bot]","type":"Bot"}}),
    ));
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let now = plexus_core::now_ms();
    let result = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"action":"issue edit","repository":"org/repo","target":{"number":"42"},"body":{"title":"changed"}}),
        "unbind-flight",
        "unbind-flight-id",
        "worker",
        now,
    );
    assert_eq!(
        transport.inner.requests().len(),
        1,
        "no write may dispatch: {result}"
    );
    assert_eq!(transport.inner.requests()[0].action, "github.issue.get");
    assert_eq!(
        result["result"]["refusal_code"], "stale_authority{dimension: repository_rebound}",
        "{result}"
    );
}

/// A handle credential provider that refuses one chosen preparation (counted
/// from 1) as transient and serves every other.
struct TransientOnce {
    calls: std::sync::atomic::AtomicUsize,
    fail_at: usize,
}
impl HandleCredentialProvider for TransientOnce {
    fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if call == self.fail_at {
            return Err(plexus_core::github::credential::UNRESOLVABLE_TRANSIENT);
        }
        Ok(ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

/// Close an issue with a comment: the comment, then the close. The close's credential preparation fails once as transient, after
/// the comment was sent and answered with `comment_response`. A same-nonce
/// retry straight afterwards must resume at the close and complete, sending
/// the comment exactly once. Returns the actions GitHub received.
fn close_after_a_transient_second_leg(label: &str, comment_response: Value) -> Vec<String> {
    close_after_a_transient_second_leg_with_generation_failure(label, comment_response, false)
}

fn close_after_a_transient_second_leg_with_generation_failure(
    label: &str,
    comment_response: Value,
    generation_failure: bool,
) -> Vec<String> {
    let (scratch, store, _, transport, scope) = setup(
        label,
        &[
            ("github.issue.get", "read"),
            ("add_issue_comment", "write"),
            ("close_issue", "write"),
        ],
    );
    transport.set_response_for_method(
        "add_issue_comment",
        "",
        MockResponse::Success(comment_response),
    );
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        // Credential preparation runs before each write: posting the comment
        // is the first call, and changing the issue state is the second.
        credential_provider: Some(Arc::new(TransientOnce {
            calls: std::sync::atomic::AtomicUsize::new(0),
            fail_at: 2,
        })),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request =
        json!({"verb":"issue close","repository":"org/repo","number":"42","comment":"once"});
    let now = plexus_core::now_ms();
    let send = |owner: &str, at: i64| {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "transient-second-leg",
            owner,
            owner,
            at,
        )
    };
    let first = send("first", now);
    assert_eq!(
        first["result"]["refusal_code"],
        plexus_core::github::credential::UNRESOLVABLE_TRANSIENT,
        "{first}"
    );
    let receipt = store
        .github_receipt("agent-fixture", "transient-second-leg")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state, "pending");
    assert_eq!(
        receipt.claim_owner, None,
        "the claim was released: {receipt:?}"
    );
    if generation_failure {
        let db = Connection::open(scratch.path()).unwrap();
        let sent = transport.requests().len();
        db.execute_batch(
            "ALTER TABLE github_repo_binding_generation RENAME TO unavailable_generation;",
        )
        .unwrap();
        let blocked = send("metadata-failed", now + 1);
        assert_eq!(
            blocked["result"]["status"], "outcome_unknown",
            "a recorded partial write must not be described as nothing written"
        );
        assert!(blocked.get("repo_binding_generation").is_none());
        assert_eq!(
            transport.requests().len(),
            sent,
            "generation failure must resume no legs"
        );
        assert_eq!(
            store
                .github_receipt("agent-fixture", "transient-second-leg")
                .unwrap()
                .unwrap(),
            receipt,
            "generation failure must leave the resumable receipt unchanged"
        );
        db.execute_batch(
            "ALTER TABLE unavailable_generation RENAME TO github_repo_binding_generation;",
        )
        .unwrap();
    }
    let retry = send("retry", now + 1);
    assert_eq!(retry["result"]["status"], "completed", "{retry}");
    transport
        .requests()
        .iter()
        .map(|request| request.action.clone())
        .collect()
}

/// A transient failure after an earlier leg completed releases the claim, so
/// the same-nonce retry resumes at once instead of waiting out the lease as
/// nonce_in_flight.
#[test]
fn a_transient_failure_on_a_later_leg_lets_a_same_nonce_retry_resume() {
    assert_eq!(
        close_after_a_transient_second_leg("transient-second-leg", json!({"id": 9})),
        ["add_issue_comment", "close_issue"]
    );
}

/// The same, with the comment answered by an empty success body (the shape a
/// 204 takes): the completed comment is still a settled leg, not one in doubt.
#[test]
fn an_empty_success_body_on_an_earlier_leg_is_not_a_write_in_doubt() {
    assert_eq!(
        close_after_a_transient_second_leg("empty-body-first-leg", Value::Null),
        ["add_issue_comment", "close_issue"]
    );
}

fn receipt_persistence_failure(after_effect: bool) {
    let (scratch, store, engine, transport, scope) =
        setup("facade-receipt-persistence", &[("add_reaction", "write")]);
    transport.set_response(MockResponse::Success(json!({"id": 701, "content": "eyes"})));
    let db = Connection::open(scratch.path()).unwrap();
    let trigger = if after_effect {
        "CREATE TRIGGER fail_receipt BEFORE UPDATE OF state ON github_bot_receipt
         WHEN NEW.state='completed' BEGIN SELECT RAISE(FAIL, 'receipt unavailable'); END;"
    } else {
        "CREATE TRIGGER fail_receipt BEFORE UPDATE OF effects ON github_bot_receipt
         WHEN json_type(NEW.effects, '$[0].outcome')='object'
         BEGIN SELECT RAISE(FAIL, 'effect unavailable'); END;"
    };
    db.execute_batch(trigger).unwrap();
    let request = json!({"action":"issue reaction","repository":"org/repo",
        "target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::storage::now_ms();
    let send = |owner, at| {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "persist-nonce",
            "persist-request",
            owner,
            at,
        )
    };
    let first = send("first", now);
    assert_eq!(
        first["result"]["status"],
        if after_effect {
            "completed"
        } else {
            "outcome_unknown"
        },
        "a successful GitHub write must not be reported as refused: {first}"
    );
    assert_eq!(transport.requests().len(), 1);
    db.execute_batch("DROP TRIGGER fail_receipt;").unwrap();
    let second = send("second", now + 120_001);
    assert_eq!(
        second["result"], first["result"],
        "same nonce must replay the known outcome"
    );
    assert_eq!(
        transport.requests().len(),
        1,
        "same nonce must not send a second GitHub write"
    );
}

#[test]
fn an_unrecorded_successful_effect_reports_unknown_and_never_resends() {
    receipt_persistence_failure(false);
}

#[test]
fn durable_effects_return_completed_when_receipt_finish_fails_and_never_resend() {
    receipt_persistence_failure(true);
}

#[test]
fn unknown_receipt_replays_after_repository_unbind() {
    let (scratch, store, engine, transport, scope) =
        setup("facade-unknown-unbind", &[("add_reaction", "write")]);
    transport.set_response(MockResponse::OutcomeUnknown);
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::storage::now_ms();
    let send = |at| {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "unknown-unbind",
            "request",
            "owner",
            at,
        )
    };
    assert_eq!(send(now)["result"]["status"], "outcome_unknown");
    let db = Connection::open(scratch.path()).unwrap();
    db.execute(
        "DELETE FROM github_repo_binding WHERE repository='org/repo'",
        [],
    )
    .unwrap();
    assert_eq!(
        send(now + 1)["result"]["status"],
        "outcome_unknown",
        "unbinding must not turn an uncertain write into a refusal"
    );
    assert_eq!(
        transport.requests().len(),
        1,
        "terminal replay must not retransmit"
    );
}

#[test]
fn wildcard_module_grant_authorizes_no_scoped_bot_carrier() {
    let (scratch, store, engine, transport, scope) =
        setup("facade-wildcard", &[("add_reaction", "write")]);
    let db = Connection::open(scratch.path()).unwrap();
    db.execute(
        "UPDATE grants SET grantee_principal='*' WHERE grant_id='module'",
        [],
    )
    .unwrap();
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    for caller in [
        plexus_core::github::AFT_PRINCIPAL,
        plexus_core::github::PREFRONTAL_PRINCIPAL,
        "reserved:basal",
    ] {
        let seam = GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        };
        let connection = store
            .connection("operator", "conn-fixture")
            .unwrap()
            .unwrap();
        let authorization = plexus_core::AuthorizationRequest::new(
            caller,
            "conn-fixture",
            "add_reaction",
            json!({}),
        )
        .with_bound_agent("agent-fixture", "app-fixture");
        let rows = plexus_core::governance::GovernanceSeams::grant_rows(
            &seam,
            &connection,
            &authorization,
        )
        .unwrap();
        assert!(
            rows.iter().all(|row| row.grant.grantee_principal != "*"),
            "wildcard grants must be excluded from scoped authority rows"
        );
        let reply = bot_request_scoped(
            &store,
            &engine,
            caller,
            Some(&scope),
            &request,
            caller,
            "request",
            "owner",
            plexus_core::storage::now_ms(),
        );
        assert_eq!(
            reply["result"]["refusal_code"], "module_grant_absent",
            "a wildcard module grant must authorize no carrier: {reply}"
        );
    }
    assert!(transport.requests().is_empty());
}

#[test]
fn read_handle_store_failure_is_not_repository_unbound() {
    let (scratch, store, _, _, _) = setup("read-handle-failure", &[("github.issue.get", "read")]);
    let db = Connection::open(scratch.path()).unwrap();
    db.execute("UPDATE github_app_handle SET app_id='broken'", [])
        .unwrap();
    assert_eq!(
        plexus_core::github::reads::resolve_read(
            &store,
            "github.issue.get",
            &json!("org/repo"),
            &json!({"issue_number":42})
        ),
        Err(plexus_core::github::reads::ReadError::Denied(
            plexus_core::Denial::StoreFailure
        )),
        "a malformed handle row is a store failure, not an unbound repository"
    );
}

#[test]
fn read_page_bound_is_distinct_from_invalid_response() {
    let (_scratch, _, engine, transport, _) =
        setup("read-page-bound", &[("github.issue_comments.list", "read")]);
    transport.set_response(MockResponse::Success(json!((0..100)
        .map(|id| json!({"id":id}))
        .collect::<Vec<_>>())));
    let error = plexus_core::github::reads::read_scoped(
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        "github.issue_comments.list",
        &json!("org/repo"),
        &json!({"issue_number":42}),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error,
        plexus_core::github::reads::ReadError::PageBound,
        "bounded reads must retain the page-bound failure"
    );
}

#[test]
#[ignore = "manual live-sized reviewed catalog authorization measurement"]
fn measure_governance_manifest_parse_share() {
    let (_scratch, store, engine, _, _) =
        setup("manifest-parse-share", &[("github.issue.search", "read")]);
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    // Every shipped catalog is measured, however many there are: a fixed
    // count failed the first time a catalog was added, unnoticed while this
    // test is ignored.
    let mut count = 0;
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonc") {
            continue;
        }
        let manifest = parse_catalog_source(&std::fs::read_to_string(path).unwrap());
        let ingested = plexus_core::ingest_value(serde_json::to_value(manifest).unwrap()).unwrap();
        store
            .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &ingested)
            .unwrap();
        count += 1;
    }
    assert!(count > 0, "measure the complete live-sized catalog");
    let document = store
        .manifest_json(plexus_core::CATALOG_PRINCIPAL, "github_rest")
        .unwrap()
        .unwrap()
        .to_string();
    let start = std::time::Instant::now();
    for _ in 0..200 {
        engine
            .authorize(plexus_core::AuthorizationRequest::new(
                plexus_core::github::AFT_PRINCIPAL,
                "conn-fixture",
                "github.issue.search",
                // Agents send terms, never a raw `q`: governance refuses a
                // caller-supplied query string.
                json!({"repositories":["org/repo"],"terms":"bug"}),
            ))
            .unwrap();
    }
    let authorize = start.elapsed();
    let start = std::time::Instant::now();
    for _ in 0..200 {
        std::hint::black_box(serde_json::from_str::<Value>(&document).unwrap());
    }
    let parse = start.elapsed();
    println!("catalog={count}, GitHub document={} bytes, 200 authorizes={authorize:?}, 200 parses={parse:?}, per parse={:?}, share={:.3}%",
        document.len(), parse / 200, 100.0 * parse.as_secs_f64() / authorize.as_secs_f64());
}

#[test]
fn read_lookup_does_not_scan_unselected_bindings() {
    let (scratch, store, _, _, _) =
        setup("read-targeted-isolation", &[("github.issue.get", "read")]);
    let mut other = store
        .github_handle_and_bindings("app-fixture")
        .unwrap()
        .unwrap()
        .0;
    other.app_handle_id = "other-app".into();
    other.agent_id = "other-agent".into();
    other.connection_id = "other-connection".into();
    other.credential_reference = "github_app:other-app".into();
    store
        .insert_connection(
            "operator",
            "other-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store.put_github_handle(&other).unwrap();
    store.bind_github_repo("other/repo", "other-app").unwrap();
    let db = Connection::open(scratch.path()).unwrap();
    db.execute(
        "UPDATE github_app_handle SET agent_id=x'00ff' WHERE app_handle_id='other-app'",
        [],
    )
    .unwrap();
    let resolved = plexus_core::github::reads::resolve_read(
        &store,
        "github.issue.get",
        &json!("org/repo"),
        &json!({"issue_number":42}),
    );
    assert!(
        resolved.is_ok(),
        "selected repository reads must not scan unrelated malformed bindings: {resolved:?}"
    );
}

#[test]
fn generation_failure_precedes_admission_and_sends_nothing() {
    let (scratch, store, engine, transport, scope) =
        setup("generation-preflight", &[("add_reaction", "write")]);
    let db = Connection::open(scratch.path()).unwrap();
    db.execute_batch(
        "ALTER TABLE github_repo_binding_generation RENAME TO unavailable_generation;",
    )
    .unwrap();
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    for stamp in [Some(&scope), None] {
        let reply = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            stamp,
            &request,
            "generation-failure",
            "request",
            "owner",
            plexus_core::storage::now_ms(),
        );
        assert_eq!(
            reply["result"]["refusal_code"], "store_failure",
            "generation store failure must stop before facade admission"
        );
        assert!(
            reply.get("repo_binding_generation").is_none(),
            "a generation-read store failure must omit generation metadata"
        );
        assert_ne!(
            reply["repo_binding_generation"],
            json!(0),
            "an unknown binding generation must never be emitted as zero"
        );
        assert!(
            transport.requests().is_empty(),
            "generation failure must send nothing"
        );
        assert!(
            store
                .github_receipt("agent-fixture", "generation-failure")
                .unwrap()
                .is_none(),
            "generation failure must create no receipt claim"
        );
    }
}

#[test]
fn generation_failure_replays_verified_terminal_receipts() {
    for response in [
        MockResponse::Success(json!({"id":701,"content":"eyes"})),
        MockResponse::OutcomeUnknown,
        MockResponse::VendorError {
            code: "http_403".into(),
            message: "forbidden".into(),
        },
    ] {
        let (scratch, store, engine, transport, scope) =
            setup("generation-terminal", &[("add_reaction", "write")]);
        transport.set_response(response);
        let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
        let now = plexus_core::storage::now_ms();
        let first = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "terminal",
            "first",
            "owner",
            now,
        );
        let before = store
            .github_receipt("agent-fixture", "terminal")
            .unwrap()
            .unwrap();
        let sent = transport.requests().len();
        Connection::open(scratch.path())
            .unwrap()
            .execute_batch(
                "ALTER TABLE github_repo_binding_generation RENAME TO unavailable_generation;",
            )
            .unwrap();
        let replay = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "terminal",
            "retry",
            "next",
            now + 1,
        );
        assert_eq!(
            replay["result"], first["result"],
            "generation failure must preserve verified terminal outcomes"
        );
        assert!(replay.get("repo_binding_generation").is_none());
        assert_eq!(
            transport.requests().len(),
            sent,
            "generation failure replay must send nothing"
        );
        assert_eq!(
            store
                .github_receipt("agent-fixture", "terminal")
                .unwrap()
                .unwrap(),
            before
        );
    }
}

#[test]
fn generation_failure_preserves_g4_in_flight_answer() {
    let (scratch, store, engine, transport, scope) =
        setup("generation-inflight", &[("add_reaction", "write")]);
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}});
    let now = plexus_core::storage::now_ms();
    let claim = plexus_core::github::facade::gates::run_scoped(
        &*store,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "live",
        "first",
        "owner",
        now,
        120,
    );
    assert!(matches!(
        claim.claim,
        Some(plexus_core::github::receipt::Claim::Owned(_))
    ));
    store
        .mark_github_dispatch("agent-fixture", "live", "owner", 0, now, "first")
        .unwrap();
    let before = store
        .github_receipt("agent-fixture", "live")
        .unwrap()
        .unwrap();
    let normal = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "live",
        "retry",
        "next",
        now + 1,
    );
    assert_eq!(normal["result"]["refusal_code"], "nonce_in_flight");
    Connection::open(scratch.path())
        .unwrap()
        .execute_batch(
            "ALTER TABLE github_repo_binding_generation RENAME TO unavailable_generation;",
        )
        .unwrap();
    let failed = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request,
        "live",
        "retry",
        "next",
        now + 1,
    );
    assert_eq!(
        failed["result"], normal["result"],
        "generation failure must reuse the normal G4 in-flight answer"
    );
    assert!(failed.get("repo_binding_generation").is_none());
    assert!(transport.requests().is_empty());
    assert_eq!(
        store
            .github_receipt("agent-fixture", "live")
            .unwrap()
            .unwrap(),
        before
    );
}

#[test]
fn generation_failure_preserves_partial_write_and_later_resume() {
    assert_eq!(
        close_after_a_transient_second_leg_with_generation_failure(
            "generation-partial",
            json!({"id":9}),
            true
        ),
        ["add_issue_comment", "close_issue"],
        "a healthy same-nonce retry must send only the unfinished write leg"
    );
}

#[test]
fn read_upgrade_keeps_claimed_bot_write_live() {
    use plexus_core::github::facade::{gates, vendor_band};
    let (scratch, store, engine, transport, scope) = setup(
        "read-upgrade-inflight-write",
        &[("github.issue.get", "read"), ("close_issue", "write")],
    );
    let db = Connection::open(scratch.path()).unwrap();
    // Model an imported direct-owned handle while retaining the write fixture's
    // transport, scope reader, and separate module and agent grant layers.
    db.execute_batch("UPDATE connections SET principal='direct',ceiling_risk='write',ceiling_selectors='[\"github.issue.get\",\"close_issue\"]';
        UPDATE catalog_actions SET principal='direct';
        UPDATE grants SET principal='direct';
        UPDATE github_app_handle SET connection_principal='direct';").unwrap();
    let now = plexus_core::now_ms();
    let mut reply = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"verb":"issue close","repository":"org/repo","number":"42"}),
        "read-upgrade-nonce",
        "read-upgrade-id",
        "worker",
        now,
        120,
    );
    assert!(matches!(
        reply.claim,
        Some(plexus_core::github::receipt::Claim::Owned(_))
    ));
    let claimed = store
        .github_receipt("agent-fixture", "read-upgrade-nonce")
        .unwrap()
        .unwrap();
    let generation: i64 = db
        .query_row(
            "SELECT generation FROM grants WHERE grant_id='module'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let connection_generation: i64 = db
        .query_row(
            "SELECT generation FROM connections WHERE connection_id='conn-fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let plan = store
        .grant_github_handle_read(&plexus_core::storage::github_store::GithubHandleReadGrant {
            app_handle_id: Some("app-fixture".into()),
            all_handles: false,
            module: plexus_core::github::AFT_PRINCIPAL.into(),
            actions: vec!["github.repo.get".into()],
            dry_run: false,
        })
        .unwrap()
        .unwrap();
    assert_eq!(plan["handles"][0]["grants"][0]["op"], "extend");
    assert_eq!(plan["handles"][0]["grants"][0]["grant_id"], "module");
    let unchanged_generation: i64 = db
        .query_row(
            "SELECT generation FROM grants WHERE grant_id='module'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unchanged_generation, generation);
    let upgraded_generation: i64 = db
        .query_row(
            "SELECT generation FROM connections WHERE connection_id='conn-fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(upgraded_generation, connection_generation + 1);
    let after = store
        .github_receipt("agent-fixture", "read-upgrade-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(after.claim_owner, claimed.claim_owner);
    assert_eq!(after.authority_baseline, claimed.authority_baseline);
    let result = vendor_band::run(
        &engine,
        &store,
        &mut reply,
        "read-upgrade-nonce",
        "worker",
        now,
    );
    assert_eq!(result["status"], "completed", "{result}");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "close_issue");
    let receipt = store
        .github_receipt("agent-fixture", "read-upgrade-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state, "completed");
    assert!(receipt
        .effects
        .iter()
        .all(|effect| effect.outcome.is_some()));
}
