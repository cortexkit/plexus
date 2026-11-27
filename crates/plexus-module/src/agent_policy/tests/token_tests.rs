use super::*;
use crate::github_react_tests::{runtime_with_actions_and_provider, send, stamp, AGENT};
use plexus_core::credentials::CkcredCredentialSource;
use plexus_core::github::credential::HandleCredentialPreparer;
use plexus_core::{MockResponse, MockTransport};

const REPO: &str = "org/repo";
const IDENTITY: &str = "github_app:app-fixture";
const FIXTURE: &str =
    include_str!("../../../../plexus-core/tests/fixtures/vault-policy-token-v1/cases.json");
const DRAFT: &str = include_str!(
    "../../../../plexus-core/tests/fixtures/agent_policy/github-rules-revision-2-kinds.draft.json"
);

fn draft_policy() -> Value {
    let mut reply = ready_for(2, AGENT, IDENTITY, REPO);
    let mut policy: Value =
        serde_json::from_str(reply["result"]["policy_text"].as_str().unwrap()).unwrap();
    let rules = &mut policy["rule_sets"]["github"];
    rules["revision"] = json!(2);
    rules["kinds"]
        .as_array_mut()
        .unwrap()
        .extend(serde_json::from_str::<Vec<Value>>(DRAFT).unwrap());
    let text = policy.to_string();
    reply["result"]["policy_sha256"] = json!(format!("{:x}", Sha256::digest(&text)));
    reply["result"]["policy_text"] = json!(text);
    reply
}

fn vector(name: &str) -> Value {
    serde_json::from_str::<Value>(FIXTURE).unwrap()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()["body"]
        .clone()
}

struct TokenVault {
    active: Vault,
    reply: Mutex<Result<Value, CkcredRouteError>>,
    calls: Mutex<Vec<(String, Value)>>,
}

impl TokenVault {
    fn set_token_reply(&self, reply: Value) {
        *self.reply.lock().unwrap() = Ok(reply);
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }
}

impl CkcredRoutePeer for TokenVault {
    fn call(&self, op: &str, args: Value) -> Result<Value, CkcredRouteError> {
        if op == "policy.active" {
            return self.active.call(op, args);
        }
        self.calls.lock().unwrap().push((op.into(), args));
        match op {
            "credential.policy_token" => self.reply.lock().unwrap().clone(),
            "credential.get_scoped" => Ok(json!({"result":{
                "credential_id":IDENTITY,"record_version":1,
                "expires_at_ms":4_102_444_800_000_i64,"payload":[98,114,111,97,100]
            }})),
            _ => panic!("unexpected vault operation {op}"),
        }
    }

    fn watch_policy(&self) -> Result<CkcredWatch, CkcredRouteError> {
        self.active.watch_policy()
    }
}

struct Fixture {
    state: Arc<ModuleState>,
    transport: Arc<MockTransport>,
    vault: Arc<TokenVault>,
    _scratch: Scratch,
}

impl Fixture {
    fn new(apply: bool) -> Self {
        Self::with_policy(apply, ready_for(1, AGENT, IDENTITY, REPO))
    }

    fn with_policy(apply: bool, active: Value) -> Self {
        let version = active["result"]["version"].clone();
        let vault = Arc::new(TokenVault {
            active: Vault::new(active),
            reply: Mutex::new(Ok(vector("issue_none_kind"))),
            calls: Mutex::default(),
        });
        let provider = Arc::new(HandleCredentialPreparer::new(
            CkcredCredentialSource::new(vault.clone()),
            Arc::new(plexus_core::now_ms),
        ));
        let (mut state, transport, scratch) = runtime_with_actions_and_provider(
            "policy-token",
            "aft",
            &[
                "github.issue.get",
                "edit_issue",
                "add_issue_comment",
                "github.repo.get",
                "github.search.code",
                "github.issue_timeline.list",
            ],
            provider,
        );
        // Ordinary handle imports set a write ceiling. The react test fixture
        // creates the connection directly, so supply the ceiling apply expects.
        rusqlite::Connection::open(scratch.path())
            .unwrap()
            .execute(
                "UPDATE connections SET ceiling_risk='write', ceiling_selectors='[\"*\"]'
             WHERE principal='operator' AND connection_id='conn-react'",
                [],
            )
            .unwrap();
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.runtime.vault_peer = Some(vault.clone());
        configure_tokens(&mut state_mut.runtime, &state_mut.health);
        state.store().set_github_policy_apply(apply).unwrap();
        assert!(refresh(&state, vault.as_ref()));
        if apply {
            let status = health(&state);
            assert_eq!(status["apply"]["applied_version"], version, "{status}");
        }
        transport.set_response_for_method(
            "github.issue.get",
            "",
            MockResponse::Success(
                json!({"number":42,"user":{"login":"app-fixture[bot]","type":"Bot"}}),
            ),
        );
        transport.set_response_for_method(
            "github.repo.get",
            "",
            MockResponse::Success(json!({"status":200,"body":{"ok":true},"next_page":null})),
        );
        transport.set_response(MockResponse::Success(json!({"id":123,"number":42})));
        Self {
            state,
            transport,
            vault,
            _scratch: scratch,
        }
    }

    async fn send(&self, tool: &str, arguments: Value) -> Value {
        serde_json::from_slice(
            &send(
                &self.state,
                "aft",
                Some(stamp(true, false)),
                tool,
                arguments,
            )
            .await,
        )
        .unwrap()
    }

    async fn write(&self, nonce: &str, request: Value) -> Value {
        self.send(
            "github",
            json!({"op":"bot_request","request_nonce":nonce,"request":request}),
        )
        .await
    }

    async fn read_root(&self, path: &str) -> Value {
        self.read_repo(REPO, path, json!({})).await
    }

    async fn read_repo(&self, repository: &str, path: &str, query: Value) -> Value {
        self.send(
            "github_read",
            json!({"repository":repository,"action":"github.repo.get","args":{"path":path,"query":query}}),
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_suffix_reads_narrow_to_their_concrete_kinds() {
    let f = Fixture::with_policy(true, draft_policy());
    let sha = "a4ac141eb425b37be8767bec0288378eac16e9b5f1";
    for (path, query) in [
        (
            format!("commits/{sha}/check-runs"),
            json!({"filter":"latest"}),
        ),
        ("git/matching-refs/heads/feature/x".into(), json!({})),
        ("actions/runs/123/jobs".into(), json!({"per_page":"100"})),
        ("issues/7".into(), json!({})),
        ("pulls/8".into(), json!({})),
        ("actions/jobs/123".into(), json!({})),
    ] {
        let reply = f.read_repo(REPO, &path, query).await;
        assert!(reply.get("result").is_some(), "{path}: {reply}");
    }
    let refused = f.read_repo("org/other", "issues/7", json!({})).await;
    assert_eq!(refused["error"]["code"], "repository_not_visible");
    assert_eq!(
        f.vault.calls(),
        [
            narrowed("github.commit.check_runs", 2),
            narrowed("github.git.matching_refs", 2),
            narrowed("github.actions.run.jobs", 2),
            narrowed("github.issue.get", 2),
            narrowed("github.pull_request.get", 2),
            narrowed("github.actions.job.get", 2),
        ]
    );
    assert_eq!(
        health(&f.state)["token_legs"],
        json!({"narrowed":6,"broad":0})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_suffix_broad_legs_count_only_redacted_templates() {
    let f = Fixture::with_policy(true, draft_policy());
    for (path, query) in [
        ("branches/main/protection", json!({})),
        ("issues/7/timeline", json!({"unlisted":"query-value"})),
        ("issues/8/timeline", json!({"unlisted":"other-value"})),
    ] {
        let reply = f.read_repo(REPO, path, query).await;
        assert!(reply.get("result").is_some(), "{path}: {reply}");
    }
    assert_eq!(f.vault.calls(), [broad()]);
    let status = health(&f.state);
    assert_eq!(status["token_legs"], json!({"narrowed":0,"broad":3}));
    assert_eq!(
        status["broad_suffix_legs"],
        json!({"{}/{}/{}":1,"issues/{}/timeline":2})
    );

    let unapplied = Fixture::with_policy(false, draft_policy());
    let reply = unapplied.read_root("git/matching-refs/heads/issues").await;
    assert!(reply.get("result").is_some(), "{reply}");
    assert_eq!(unapplied.vault.calls(), [broad()]);
    assert_eq!(
        health(&unapplied.state)["broad_suffix_legs"],
        json!({"git/matching-refs/{}/{}":1})
    );
}

#[test]
fn draft_timeline_narrows_as_a_named_catalog_leg() {
    let f = Fixture::with_policy(true, draft_policy());
    let engine = &f.state.runtime.engine;
    let action = "github.issue_timeline.list";
    let request = plexus_core::AuthorizationRequest::new(
        "reserved:aft",
        "conn-react",
        action,
        json!({"owner":"org","repo":"repo","issue_number":7,"page":1}),
    );
    let dispatch = engine
        .authorize_and_dispatch_github_leg_for_test(request, AGENT, REPO)
        .unwrap();
    assert!(
        matches!(
            dispatch.outcome,
            plexus_core::TransportOutcome::Completed { .. }
        ),
        "{:?}",
        dispatch.outcome
    );
    assert_eq!(f.vault.calls(), [narrowed(action, 2)]);
    let status = health(&f.state);
    assert_eq!(status["token_legs"], json!({"narrowed":1,"broad":0}));
    assert_eq!(status["broad_suffix_legs"], json!({}));
}

fn issue_edit() -> Value {
    json!({"action":"issue edit","repository":REPO,"target":{"number":"42"},
        "body":{"title":"changed"},"author_scope":"own"})
}

fn comment() -> Value {
    json!({"action":"issue comment","repository":REPO,"target":{"number":"42"},
        "body":{"body":"verified"}})
}

fn narrowed(kind: &str, version: i64) -> (String, Value) {
    (
        "credential.policy_token".into(),
        json!({"identity":IDENTITY,"service":"github",
        "kind":kind,"resource":REPO,"policy_version":version}),
    )
}

fn broad() -> (String, Value) {
    (
        "credential.get_scoped".into(),
        json!({"credential_id":IDENTITY}),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_write_leg_uses_its_own_kind_only_while_apply_is_enabled() {
    for apply in [true, false] {
        let f = Fixture::new(apply);
        let reply = f.write("issue-edit", issue_edit()).await;
        assert_eq!(reply["result"]["status"], "completed", "{reply}");
        assert_eq!(
            f.transport
                .requests()
                .iter()
                .map(|r| r.action.as_str())
                .collect::<Vec<_>>(),
            ["github.issue.get", "edit_issue"]
        );
        assert_eq!(
            f.vault.calls(),
            if apply {
                vec![narrowed("github.issue.get", 1), narrowed("edit_issue", 1)]
            } else {
                vec![broad()]
            }
        );
        assert_eq!(
            health(&f.state)["token_legs"],
            if apply {
                json!({"narrowed":2,"broad":0})
            } else {
                json!({"narrowed":0,"broad":2})
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repo_get_root_uses_its_kind_and_a_v1_suffix_uses_its_matching_kind() {
    let f = Fixture::new(true);
    for path in ["issues/42", "", ""] {
        let reply = f.read_root(path).await;
        assert!(reply.get("result").is_some(), "{reply}");
    }
    assert_eq!(
        f.vault.calls(),
        [
            narrowed("github.issue.get", 1),
            narrowed("github.repo.get", 1),
            narrowed("github.repo.get", 1)
        ]
    );
    assert_eq!(
        health(&f.state)["token_legs"],
        json!({"narrowed":3,"broad":0})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unapplied_checked_version_keeps_the_scoped_path() {
    let f = Fixture::new(false);
    f.state.store().set_github_policy_apply(true).unwrap();
    let reply = f.read_root("").await;
    assert!(reply.get("result").is_some(), "{reply}");
    assert_eq!(f.vault.calls(), [broad()]);

    let f = Fixture::new(true);
    f.vault.active.reply(ready_for(2, AGENT, IDENTITY, REPO));
    f.state.health.agent_policy.lock().unwrap().observe(
        read_active(f.vault.as_ref()),
        read_catalog(&f.state).as_ref(),
    );
    assert_eq!(health(&f.state)["version"], 2);
    assert_eq!(health(&f.state)["apply"]["applied_version"], 1);
    let reply = f.read_root("").await;
    assert!(reply.get("result").is_some(), "{reply}");
    assert_eq!(f.vault.calls(), [broad()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_and_route_refusals_stop_the_leg_without_broad_fallback() {
    let f = Fixture::new(true);
    for (name, class, retry) in [
        ("issue_ungranted", "permanent", false),
        ("issue_wrong_service", "permanent", false),
        (
            "issue_unbound_resource_without_approval",
            "permanent",
            false,
        ),
        ("issue_no_approval_members", "permanent", false),
        ("issue_policy_changed", "permanent", false),
        ("issue_store_error", "transient", true),
        ("issue_provider_error", "transient", true),
        ("issue_needs_reauth", "auth_required", false),
        ("issue_retired", "auth_required", false),
        ("issue_deleted_record", "permanent", false),
        ("issue_record_changed_twice", "transient", true),
        ("issue_old_policy_without_proof", "transient", true),
        ("route-unavailable", "transient", true),
    ] {
        if name == "route-unavailable" {
            *f.vault.reply.lock().unwrap() = Err(CkcredRouteError::OutcomeUnknown);
        } else {
            f.vault.set_token_reply(vector(name));
        }
        let code = format!("handle_credential_unresolvable{{class: {class}}}");
        let reply = f.write(name, comment()).await;
        assert_eq!(
            reply["result"],
            json!({"status":"refused","refusal_code":code,
            "retry_same_nonce":retry}),
            "{name}: {reply}"
        );
        let reply = f.read_root("").await;
        assert_eq!(
            reply["error"],
            json!({"code":"read_dispatch_failed","transmission":"not_sent",
            "outcome":{"transmission":"not_sent","code":code,"message":"GitHub read dispatch did not complete"}}),
            "{name}: {reply}"
        );
    }
    assert!(f.transport.requests().is_empty());
    let expected: Vec<_> = (0..13)
        .flat_map(|_| {
            [
                narrowed("add_issue_comment", 1),
                narrowed("github.repo.get", 1),
            ]
        })
        .collect();
    assert_eq!(f.vault.calls(), expected);
    assert_eq!(
        health(&f.state)["token_legs"],
        json!({"narrowed":0,"broad":0})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replaced_record_uses_the_retried_narrowed_token_for_the_leg() {
    let f = Fixture::new(true);
    f.vault
        .set_token_reply(vector("issue_record_replaced_during_mint"));
    let reply = f.write("record-replaced", comment()).await;
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(f.vault.calls(), [narrowed("add_issue_comment", 1)]);
    let requests = f.transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].action, "add_issue_comment");
    assert_eq!(
        f.transport.authorization_headers(),
        [b"Bearer fixture-token-6".to_vec()]
    );
    assert_eq!(
        health(&f.state)["token_legs"],
        json!({"narrowed":1,"broad":0})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_an_explicit_unsupported_method_can_use_the_scoped_path() {
    for code in ["unknown_method", "unsupported_method"] {
        let f = Fixture::new(true);
        f.vault.set_token_reply(json!({"code":code}));
        let reply = f.read_root("").await;
        assert!(reply.get("result").is_some(), "{reply}");
        assert_eq!(f.vault.calls(), [narrowed("github.repo.get", 1), broad()]);
        assert_eq!(
            health(&f.state)["token_legs"],
            json!({"narrowed":0,"broad":1})
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_version_refusal_wakes_policy_reread_and_releases_the_nonce() {
    let f = Fixture::new(true);
    let (stop, rx) = mpsc::channel(1);
    let worker = spawn(
        f.state.clone(),
        rx,
        Arc::clone(&f.state.health.agent_policy_wakes),
    );
    until(|| !f.vault.active.watches.lock().unwrap().is_empty()).await;
    let calls_before = f.vault.active.calls();
    f.vault.active.reply(ready_for(2, AGENT, IDENTITY, REPO));
    f.vault
        .set_token_reply(vector("issue_old_policy_without_proof"));
    let reply = f.write("retry-after-policy", comment()).await;
    assert_eq!(reply["result"]["retry_same_nonce"], true, "{reply}");
    assert!(f.transport.requests().is_empty());
    until(|| health(&f.state)["apply"]["applied_version"] == 2).await;
    assert_eq!(f.vault.active.calls(), calls_before + 1);
    f.vault.set_token_reply(vector("issue_none_kind"));
    let reply = f.write("retry-after-policy", comment()).await;
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(
        f.vault.calls(),
        [
            narrowed("add_issue_comment", 1),
            narrowed("add_issue_comment", 2)
        ]
    );
    assert_eq!(f.transport.requests().len(), 1);
    stop.send(()).await.unwrap();
    worker.await.unwrap();
}
