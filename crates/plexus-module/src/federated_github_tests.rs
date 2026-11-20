use super::*;
use crate::github_react_tests::{bot_request, react, runtime_with_actions, AGENT};
use plexus_core::credentials::CredentialSource;
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::github_identity::{PrefrontalRouteError, PrefrontalRoutePeer};
use plexus_core::governance::GovernanceEngine;
use plexus_core::storage::github_store::GithubGovernanceSeams;
use plexus_core::transport::{MockResponse, Transport};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const PEER_BOX: &str = "628c5a7a92589861e4f9f74836c34819";
const OTHER_BOX: &str = "0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct Credentials(AtomicUsize);

impl HandleCredentialProvider for Credentials {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        _: &str,
    ) -> Result<plexus_core::ResolvedCredential, &'static str> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(plexus_core::ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

struct Entorhinal {
    residence: Mutex<Value>,
    transport: Arc<MockTransport>,
    move_after_comment: bool,
    calls: Mutex<Vec<String>>,
}

impl PrefrontalRoutePeer for Entorhinal {
    fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError> {
        assert_eq!(params, json!({"agent_id":AGENT}));
        self.calls.lock().unwrap().push(operation.into());
        match operation {
            "agent.resolve" => Ok(json!({"result":{
                "agent_id":AGENT, "generation":7, "gone":null,
                "incarnation":"0123456789abcdef", "merged_into":null, "status":"live"
            }})),
            "agent.where" => {
                let mut residence = self.residence.lock().unwrap().clone();
                if self.move_after_comment
                    && self
                        .transport
                        .requests()
                        .iter()
                        .any(|r| r.action == "add_issue_comment")
                {
                    residence["epoch"] = json!(2);
                }
                Ok(json!({"result":residence}))
            }
            _ => panic!("unexpected Entorhinal operation: {operation}"),
        }
    }
}

struct Fixture {
    state: Arc<ModuleState>,
    transport: Arc<MockTransport>,
    credentials: Arc<Credentials>,
    entorhinal: Arc<Entorhinal>,
    _scratch: Scratch,
}

impl Fixture {
    fn new(label: &str, carrier: &str, move_after_comment: bool) -> Self {
        let (mut state, transport, scratch) = runtime_with_actions(
            label,
            carrier,
            &[
                "add_reaction",
                "add_issue_comment",
                "close_issue",
                "github.repo.get",
            ],
        );
        let entorhinal = Arc::new(Entorhinal {
            residence: Mutex::new(json!({
                "status":"held_elsewhere", "known":true, "stale":false, "epoch":1,
                "holder_box":PEER_BOX, "holder":"a".repeat(32), "read_at_ms":1
            })),
            transport: transport.clone(),
            move_after_comment,
            calls: Mutex::new(Vec::new()),
        });
        let credentials = Arc::new(Credentials::default());
        let store = state.store().clone();
        let runtime = &mut Arc::get_mut(&mut state).unwrap().runtime;
        runtime.agent_registry = Arc::new(plexus_core::EntorhinalAgentRegistry::new(
            entorhinal.clone(),
        ));
        runtime.engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(StubCredentialSource::default()) as Arc<dyn CredentialSource>,
            transport.clone() as Arc<dyn Transport>,
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store,
            credential_provider: Some(credentials.clone()),
        }));
        runtime.set_federated_callers_enabled_for_test(true);
        Self {
            state,
            transport,
            credentials,
            entorhinal,
            _scratch: scratch,
        }
    }

    async fn send(&self, facts: Value, request: Value) -> Frame {
        self.send_in_mode(facts, request, CallMode::Classic).await
    }

    async fn send_in_mode(&self, facts: Value, request: Value, mode: CallMode) -> Frame {
        let mut wire = bind_body(reserved("callosum"), Some(stamp()), mode);
        let target = wire["scope"]["attributes"]["federated"]
            .as_object_mut()
            .unwrap();
        target.extend(facts.as_object().unwrap().clone());
        let routes = bind_wire_accepted(&self.state, wire).await;
        call(&self.state, &routes, request).await
    }

    fn assert_unsent(&self) {
        assert_eq!(
            self.credentials.0.load(Ordering::SeqCst),
            0,
            "read a credential"
        );
        assert!(self.transport.requests().is_empty(), "contacted GitHub");
    }
}

fn agent() -> Value {
    json!({"kind":"agent", "agent_id":AGENT})
}

fn run() -> Value {
    json!({"kind":"run", "agent_id":AGENT, "run_id":"run-1"})
}

fn flow() -> Value {
    json!({"kind":"flow", "flow_id":"flow", "flow_version":1,
        "flow_install_id":"install", "flow_code_hash":"b".repeat(64), "agent_id":AGENT})
}

fn facts(claim: Value, carrier: &str) -> Value {
    json!({"remote_claim":claim, "peer_box_id":PEER_BOX,
        "origin_principal":{"kind":"reserved", "module_id":carrier}})
}

fn write(nonce: &str) -> Value {
    json!({"name":"github", "arguments":bot_request(nonce, "eyes")})
}

async fn assert_admitted(fixture: &Fixture, call_facts: Value) {
    let actual = reply(fixture.send(call_facts, write("admitted")).await);
    assert_eq!(actual["result"]["status"], "completed", "{actual}");
    let sent = fixture.transport.requests();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].action, "add_reaction");
    assert_eq!(sent[0].connection_id, "conn-react");
    assert_eq!(fixture.credentials.0.load(Ordering::SeqCst), 1);
    assert!(fixture
        .state
        .store()
        .github_receipt(AGENT, "admitted")
        .unwrap()
        .is_some());
    let calls = fixture.entorhinal.calls.lock().unwrap();
    assert!(
        calls.starts_with(&["agent.where".into(), "agent.resolve".into()]),
        "{calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moved_agent_bot_request_uses_its_own_handle_and_origin_grant() {
    let fixture = Fixture::new("moved-admitted", "aft", false);
    assert_admitted(&fixture, facts(agent(), "aft")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moved_run_is_attribution_only_in_codemode_and_classic() {
    let fixture = Fixture::new("moved-run", "aft", false);
    let reaction = json!({"name":"github_react", "arguments":react("run-react", "eyes")});
    for (request, mode) in [
        (write("run-write"), CallMode::Codemode),
        (reaction, CallMode::Codemode),
        (write("run-classic"), CallMode::Classic),
    ] {
        let tool = request["name"].clone();
        let actual = reply(
            fixture
                .send_in_mode(facts(run(), "aft"), request, mode)
                .await,
        );
        assert_eq!(actual["error"]["code"], "call_mode_unsupported", "{actual}");
        assert_eq!(
            actual["error"]["detail"],
            json!({"tool":tool,"mode":"codemode"}),
            "{actual}"
        );
    }
    fixture.assert_unsent();
    fixture.transport.set_response_for_method(
        "github.repo.get",
        "",
        MockResponse::Success(json!({"status":200,"body":{"name":"repo"},"next_page":null})),
    );
    let params = json!({"action":"github.repo.get","repository":"org/repo","args":{"path":""}});
    for request in [
        json!({"name":"github_read","arguments":params}),
        json!({"method":"github.read.bulk","params":params}),
    ] {
        let actual = reply(
            fixture
                .send_in_mode(facts(run(), "aft"), request, CallMode::Codemode)
                .await,
        );
        assert_eq!(actual["result"]["body"]["name"], "repo", "{actual}");
    }
}

// Each refusal has a positive control: blackholing all remote GitHub calls
// cannot pass these tests just by producing caller_not_allowed.
macro_rules! refused_case {
    ($name:ident, $change:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let fixture = Fixture::new(stringify!($name), "aft", false);
            let good_residence = fixture.entorhinal.residence.lock().unwrap().clone();
            let mut call_facts = facts(agent(), "aft");
            let mut request = write("denied");
            ($change)(&fixture, &mut call_facts, &mut request);
            assert_frame_denied(&request, fixture.send(call_facts, request.clone()).await);
            fixture.assert_unsent();
            *fixture.entorhinal.residence.lock().unwrap() = good_residence;
            fixture.entorhinal.calls.lock().unwrap().clear();
            assert_admitted(&fixture, facts(agent(), "aft")).await;
        }
    };
}

refused_case!(holder_box_mismatch, |f: &Fixture, _, _| f
    .entorhinal
    .residence
    .lock()
    .unwrap()["holder_box"] =
    json!(OTHER_BOX));
refused_case!(holder_box_absent, |f: &Fixture, _, _| {
    f.entorhinal
        .residence
        .lock()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("holder_box");
});
refused_case!(stale_residence, |f: &Fixture, _, _| f
    .entorhinal
    .residence
    .lock()
    .unwrap()["stale"] =
    json!(true));
refused_case!(zero_residence_epoch, |f: &Fixture, _, _| f
    .entorhinal
    .residence
    .lock()
    .unwrap()["epoch"] =
    json!(0));
refused_case!(held_here, |f: &Fixture, _, _| f
    .entorhinal
    .residence
    .lock()
    .unwrap()["status"] =
    json!("held_here"));
refused_case!(origin_absent, |_, facts: &mut Value, _| {
    facts.as_object_mut().unwrap().remove("origin_principal");
});
refused_case!(origin_not_reserved, |_, facts: &mut Value, _| facts
    ["origin_principal"] =
    json!({"kind":"direct"}));
refused_case!(peer_box_absent, |_, facts: &mut Value, _| {
    facts.as_object_mut().unwrap().remove("peer_box_id");
});
refused_case!(unbound_repository, |_, _, request: &mut Value| request
    ["arguments"]["request"]["repository"] =
    json!("org/unbound"));
refused_case!(worker_claim, |_, facts: &mut Value, _| facts
    ["remote_claim"] = json!({"kind":"worker", "owner_module_id":"aft", "worker_ref":"worker-1", "on_behalf_of":AGENT}));
refused_case!(
    flow_without_agent,
    |_, facts: &mut Value, request: &mut Value| {
        facts["remote_claim"] = flow();
        facts["remote_claim"]
            .as_object_mut()
            .unwrap()
            .remove("agent_id");
        *request = json!({"name":"github_react", "arguments":react("flow-no-agent", "eyes")});
    }
);
refused_case!(flow_bot_request, |_, facts: &mut Value, _| facts
    ["remote_claim"] =
    flow());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_agents_bot_is_not_visible() {
    use plexus_core::storage::github_store::GithubHandle;
    let fixture = Fixture::new("moved-other-bot", "aft", false);
    let store = fixture.state.store();
    store
        .insert_connection(
            "operator",
            "conn-other",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "another-app".into(),
            agent_id: "another-agent".into(),
            app_id: 2,
            installation_id: None,
            credential_reference: "github_app:another-app".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-other".into(),
        })
        .unwrap();
    store.bind_github_repo("org/other", "another-app").unwrap();
    let mut request = write("other");
    request["arguments"]["request"]["repository"] = json!("org/other");
    assert_frame_denied(
        &request,
        fixture.send(facts(agent(), "aft"), request.clone()).await,
    );
    fixture.assert_unsent();
    fixture.entorhinal.calls.lock().unwrap().clear();
    assert_admitted(&fixture, facts(agent(), "aft")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_residence_epoch_stops_unsent_leg_and_keeps_the_sent_comment() {
    let fixture = Fixture::new("moved-between-legs", "aft", true);
    let request: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/github-moved-bot/stale-residence.request.json"
    ))
    .unwrap();
    let frame = fixture.send(facts(agent(), "aft"), request.clone()).await;
    let actual: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(actual["result"]["code"], "stale_authority", "{actual}");
    assert_eq!(actual["result"]["dimension"], "residence", "{actual}");
    assert_eq!(actual["result"]["transmission"], "not_sent", "{actual}");
    assert_eq!(
        actual["result"]["legs_sent"],
        json!(["add_issue_comment"]),
        "{actual}"
    );
    let expected: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/github-moved-bot/stale-residence.reply.json"
    ))
    .unwrap();
    assert_eq!(
        frame.body,
        serde_json::to_vec(&expected).unwrap(),
        "{actual}"
    );
    let actions: Vec<_> = fixture
        .transport
        .requests()
        .into_iter()
        .map(|r| r.action)
        .collect();
    assert_eq!(actions, ["add_issue_comment"]);
    assert_eq!(fixture.credentials.0.load(Ordering::SeqCst), 1);
    let original = fixture
        .state
        .store()
        .github_receipt(AGENT, "partial")
        .unwrap()
        .unwrap();
    assert_eq!(
        original.authority_baseline["residence"],
        json!({"holder_box":PEER_BOX,"epoch":1})
    );

    // The agent retries on the new holder with the same nonce. The new
    // route must prove residence and resume at close_issue, not post again.
    fixture.entorhinal.residence.lock().unwrap()["holder_box"] = json!(OTHER_BOX);
    let mut relocated = facts(agent(), "aft");
    relocated["peer_box_id"] = json!(OTHER_BOX);
    let resumed = reply(fixture.send(relocated, request).await);
    assert_eq!(resumed["result"]["status"], "completed", "{resumed}");
    let actions: Vec<_> = fixture
        .transport
        .requests()
        .into_iter()
        .map(|r| r.action)
        .collect();
    assert_eq!(actions, ["add_issue_comment", "close_issue"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_remote_run_scope_retains_the_local_fail_closed_check() {
    let fixture = Fixture::new("moved-run-scope", "aft", false);
    let mut request = write("run-scope");
    request["arguments"]["run_scope"] =
        json!({"owner":"reserved:aft", "ref":"remote-run", "epoch":1});
    let actual = reply(fixture.send(facts(agent(), "aft"), request).await);
    assert_eq!(
        actual["result"]["refusal_code"], "scope_unverifiable",
        "{actual}"
    );
    assert_eq!(actual["result"]["scope_role"], "run", "{actual}");
    assert_eq!(actual["result"]["transmission"], "not_sent", "{actual}");
    assert_eq!(actual["result"]["retry_same_nonce"], true, "{actual}");
    fixture.assert_unsent();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moved_agent_flow_reacts_and_reads_as_that_agent() {
    let fixture = Fixture::new("moved-flow", "basal", false);
    fixture.transport.set_response_for_method(
        "github.repo.get",
        "",
        MockResponse::Success(json!({"status":200,"body":{"name":"repo"},"next_page":null})),
    );
    let call_facts = facts(flow(), "basal");
    let request = json!({"name":"github_react", "arguments":react("flow-react", "eyes")});
    let actual = reply(
        fixture
            .send_in_mode(call_facts.clone(), request, CallMode::Flow)
            .await,
    );
    assert_eq!(actual["result"]["status"], "completed", "{actual}");
    // Reads still use only the module's grant, even when a flow chose the bot.
    assert!(fixture
        .state
        .store()
        .revoke_grant("operator", "agent")
        .unwrap());
    let request = json!({"name":"github_read","arguments":{"action":"github.repo.get","repository":"org/repo","args":{"path":""}}});
    let actual = reply(
        fixture
            .send_in_mode(call_facts.clone(), request, CallMode::Flow)
            .await,
    );
    assert_eq!(actual["result"]["body"]["name"], "repo", "{actual}");
    let request = json!({"name":"github_read","arguments":{"action":"github.bindings.list"}});
    let actual = reply(
        fixture
            .send_in_mode(call_facts, request, CallMode::Flow)
            .await,
    );
    assert_eq!(
        actual["result"]["bindings"],
        json!([{"repository":"org/repo","app_handle_id":"app-fixture","agent_id":AGENT}]),
        "{actual}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moved_agent_bulk_reads_and_closed_methods_are_still_distinguished() {
    let fixture = Fixture::new("moved-bulk", "aft", false);
    fixture.transport.set_response_for_method(
        "github.repo.get",
        "",
        MockResponse::Success(json!({"status":200,"body":{"name":"repo"},"next_page":null})),
    );
    let params = json!({"action":"github.repo.get","repository":"org/repo","args":{"path":""}});
    let request = json!({"method":"github.read.bulk","params":params});
    for denied in [
        json!({"method":"github.read.bulk","name":"github_read","params":params}),
        json!({"method":"events.get","params":{}}),
        request.clone(),
    ]
    .into_iter()
    .zip([agent(), agent(), flow()])
    {
        let (request, claim) = denied;
        assert_frame_denied(
            &request,
            fixture.send(facts(claim, "aft"), request.clone()).await,
        );
    }
    fixture.assert_unsent();
    let actual = reply(fixture.send(facts(agent(), "aft"), request).await);
    assert_eq!(actual["result"]["body"]["name"], "repo", "{actual}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entorhinal_residence_samples_go_through_the_same_reader() {
    let fixtures = [
        ("off-hub", include_str!("../tests/fixtures/entorhinal-agent-sessions/agent-sessions-v1/where-holder-box.json")),
        ("off-hub-many", include_str!("../tests/fixtures/entorhinal-agent-sessions/agent-sessions-v1/where-many-holder-box.json")),
        ("hub", include_str!("../tests/fixtures/entorhinal-agent-sessions/agent-sessions-v1/where-hub.json")),
    ];
    for (name, bytes) in fixtures {
        let records: Vec<Value> = serde_json::from_str(bytes).unwrap();
        let fixture = Fixture::new(name, "aft", false);
        for record in records.iter().rev() {
            let body = &record["reply"]["result"];
            // agent.where_many lists the same records inside result.agents.
            // Feed each row as the body of agent.where, the operation we use.
            let rows = body["agents"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(std::slice::from_ref(body));
            for row in rows.iter().rev() {
                *fixture.entorhinal.residence.lock().unwrap() = row.clone();
                let mut stamped = facts(agent(), "aft");
                let eligible = row["status"] == "held_elsewhere" && row["holder_box"].is_string();
                if eligible {
                    stamped["peer_box_id"] = row["holder_box"].clone();
                    fixture.entorhinal.calls.lock().unwrap().clear();
                    assert_admitted(&fixture, stamped).await;
                } else {
                    let request = write("sample-not-resident");
                    assert_frame_denied(&request, fixture.send(stamped, request.clone()).await);
                    fixture.assert_unsent();
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_moved_agent_cannot_raise_a_consent_card() {
    let fixture = Fixture::new("moved-ask-first", "aft", false);
    let store = fixture.state.store();
    assert!(store
        .remove_policy("operator", "allow-add_reaction")
        .unwrap());
    let actual = reply(
        fixture
            .send(facts(agent(), "aft"), write("ask-first"))
            .await,
    );
    assert_eq!(actual["result"]["code"], "consent_unavailable", "{actual}");
    assert_eq!(actual["result"]["transmission"], "not_sent", "{actual}");
    assert!(store.github_receipt(AGENT, "ask-first").unwrap().is_none());
    fixture.assert_unsent();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_moved_agent_cannot_continue_a_local_approval_under_allow_policy() {
    let fixture = Fixture::new("moved-existing-approval", "aft", false);
    let store = fixture.state.store();
    assert!(store
        .remove_policy("operator", "allow-add_reaction")
        .unwrap());
    let nonce = "local-approval";
    let bytes = crate::github_react_tests::send(
        &fixture.state,
        "aft",
        Some(crate::github_react_tests::stamp(true, false)),
        "github",
        bot_request(nonce, "eyes"),
    )
    .await;
    let local: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(local["result"]["status"], "pending_approval", "{local}");
    let approval_id = local["result"]["action_request_id"].as_str().unwrap();
    store
        .insert_policy(&plexus_core::PolicyInput {
            policy_id: "allow-add_reaction".into(),
            principal: "operator".into(),
            connection_id: "conn-react".into(),
            action_selector: "add_reaction".into(),
            effect: "allow".into(),
            expires_at: None,
        })
        .unwrap();

    for approved in [false, true] {
        if approved {
            assert!(store
                .decide_action_request("operator", approval_id, true, "operator")
                .unwrap());
        }
        let actual = reply(fixture.send(facts(agent(), "aft"), write(nonce)).await);
        assert_eq!(actual["result"]["code"], "consent_unavailable", "{actual}");
        assert_eq!(actual["result"]["transmission"], "not_sent", "{actual}");
        let receipt = store.github_receipt(AGENT, nonce).unwrap().unwrap();
        assert_eq!(receipt.state, "pending_approval");
        assert_eq!(receipt.action_request_id.as_deref(), Some(approval_id));
        fixture.assert_unsent();
    }
}
