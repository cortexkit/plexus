//! `tool.withdraw` through the module's tool handler: a real store, the mock
//! transport, and routes whose bind carried a constructed scope stamp (the
//! in-process daemon cannot open scoped routes; see the note in
//! `web_search_tests`). The daemon's `scope.describe` answer is scripted.

use super::*;
use plexus_core::scope::{ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use plexus_core::{jcs_sha256, CatalogActionInput, GrantInput};
use rusqlite::Connection;
use std::sync::Mutex;
use subc_protocol::scope::ScopeStamp;

/// Needs approval before it runs.
const HELD: &str = "conn-held";
/// Runs in its own request, with no approval.
const OPEN: &str = "conn-open";
const HANDLE: &[u8] = b"test:withdraw-handle";

fn aft() -> Principal {
    Principal::Reserved {
        module_id: "aft".to_string(),
    }
}

fn broca() -> Principal {
    Principal::Reserved {
        module_id: "broca".to_string(),
    }
}

/// The owner of the test scope.
fn owner() -> Principal {
    Principal::Reserved {
        module_id: "prefrontal-core".to_string(),
    }
}

/// A worker session scope that names no agent. Calls carried under it are
/// authorized by the grant held by the carrying module (the module that
/// forwards the call to plexus) alone, with no agent grant involved.
fn stamp() -> ScopeStamp {
    stamp_at(4)
}

fn stamp_at(scope_epoch: u64) -> ScopeStamp {
    crate::consent_test_support::worker_stamp("worker-7", scope_epoch)
}

fn live() -> ScopeDescription {
    ScopeDescription {
        status: ScopeStatus::Live,
        owner_synced: true,
        owner_configured: true,
        live: Some(CallScope::from_stamp(&stamp())),
    }
}

fn ended() -> ScopeDescription {
    ScopeDescription {
        status: ScopeStatus::Ended,
        owner_synced: true,
        owner_configured: true,
        live: None,
    }
}

/// Answers `scope.describe` with whatever the test last scripted.
#[derive(Default)]
struct ScriptedReader(Mutex<Option<ScopeDescription>>);

impl ScopeReader for ScriptedReader {
    fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| ScopeReadError("no answer scripted".into()))
    }
}

pub(super) struct Fixture {
    pub(super) cards: Arc<plexus_core::ConsentCards>,
    pub(super) store: Arc<PlexusStore>,
    pub(super) transport: Arc<MockTransport>,
    credentials: Arc<StubCredentialSource>,
    reader: Arc<ScriptedReader>,
    pub(super) path: Scratch,
}

impl Fixture {
    /// Two Exa REST connections owned by `direct`: on `conn-held` the
    /// `search` action asks first, on `conn-open` it runs at once. The
    /// carriers `reserved:aft` and `reserved:broca` hold module grants on
    /// both, and `direct` may decide requests.
    pub(super) fn new(label: &str) -> Self {
        let path = Scratch::database(&format!("withdraw-{label}"));
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".to_string(),
                storage_namespace: format!("withdraw-{label}"),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .expect("open store"),
        );
        let credentials = Arc::new(StubCredentialSource::default());
        credentials.set_success(HANDLE, b"exa-key".to_vec(), None, 1);
        let fixture = Self {
            cards: crate::consent_test_support::pending_cards(),
            store,
            transport: Arc::new(MockTransport::default()),
            credentials,
            reader: Arc::new(ScriptedReader::default()),
            path,
        };
        fixture.add_connection(HELD, true);
        fixture.add_connection(OPEN, false);
        fixture
    }

    fn add_connection(&self, connection_id: &str, ask_first: bool) {
        self.store
            .insert_connection(
                "direct",
                connection_id,
                "exa_rest",
                "pending",
                &json!({"required": [], "optional": [], "write_enabling": []}),
            )
            .expect("insert connection");
        let ticket = self
            .store
            .create_binding_ticket("direct", connection_id, HANDLE)
            .expect("create binding ticket");
        self.store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("consume binding ticket")
            .expect("activate connection");
        let schema = json!({"type": "object"});
        self.store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: connection_id.to_string(),
                principal: "direct".to_string(),
                name: "search".to_string(),
                title: Some("Search".to_string()),
                schema: schema.clone(),
                schema_hash: jcs_sha256(&schema).expect("schema is JCS-compatible"),
                risk: "read".to_string(),
                severity: "S1".to_string(),
                ask_first,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("insert search action");
        for (grantee, kind, selector) in [
            (aft(), "invoke", "search"),
            (broca(), "invoke", "search"),
            (Principal::Direct, "connection_admin", "*"),
        ] {
            let grantee = principal::principal_key(&grantee);
            self.store
                .insert_grant(&GrantInput {
                    grant_id: format!("{connection_id}-{grantee}-{kind}"),
                    principal: "direct".to_string(),
                    connection_id: connection_id.to_string(),
                    grantee_principal: grantee,
                    risk_ceiling: "read".to_string(),
                    action_selectors: vec![selector.to_string()],
                    authority_kind: kind.to_string(),
                    expires_at: None,
                })
                .expect("insert grant");
        }
    }

    pub(super) fn runtime(&self) -> ModuleRuntime {
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&self.store),
            Arc::clone(&self.credentials),
            Arc::clone(&self.transport),
        );
        runtime.engine = runtime
            .engine
            .with_scope_reader(Arc::clone(&self.reader) as Arc<dyn ScopeReader>)
            .with_consent_cards(self.cards.clone());
        runtime
    }

    fn script(&self, answer: ScopeDescription) {
        *self.reader.0.lock().unwrap() = Some(answer);
    }

    async fn send(&self, principal: Principal, scope: Option<ScopeStamp>, body: Value) -> Value {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            41,
            1,
            7,
            serde_json::to_vec(&body).expect("serialize request"),
        )
        .expect("build request frame");
        let (writer, mut responses) = mpsc::channel(1);
        handle_scoped_tool_request_for_test(frame, &writer, self.runtime(), principal, scope)
            .await
            .expect("handle request");
        serde_json::from_slice(
            &recv_within(
                responses.recv(),
                std::time::Duration::from_secs(5),
                "response frame",
            )
            .await
            .body,
        )
        .expect("response JSON")
    }

    /// Invoke `search` on `connection` as `carrier` under the test scope,
    /// with `call_key` as the request's top-level key when given.
    async fn invoke(
        &self,
        carrier: Principal,
        connection: &str,
        query: &str,
        call_key: Option<&str>,
    ) -> Value {
        let mut body = json!({"name": manifest::INVOKE_TOOL, "arguments": {
            "op": "call", "connection": connection, "action": "search",
            "args": {"query": query}
        }});
        if let Some(call_key) = call_key {
            body[CALL_KEY_FIELD] = json!(call_key);
        }
        self.send(carrier, Some(stamp()), body).await
    }

    /// Make the ask-first call and return the request it parked.
    async fn park(&self, carrier: Principal, query: &str, call_key: Option<&str>) -> String {
        let reply = self.invoke(carrier, HELD, query, call_key).await;
        assert_eq!(code(&reply), "access_pending", "{reply}");
        self.store
            .list_action_requests("direct")
            .expect("list requests")
            .into_iter()
            .find(|request| request.args_snapshot["query"] == query)
            .expect("the call parked a request")
            .request_id
    }

    async fn withdraw(
        &self,
        caller: Principal,
        scope: Option<ScopeStamp>,
        arguments: Value,
    ) -> Value {
        self.send(
            caller,
            scope,
            json!({"name": manifest::WITHDRAW_TOOL, "arguments": arguments}),
        )
        .await
    }

    /// The approver decides the request from its own, unscoped route.
    async fn approve(&self, request_id: &str) -> Value {
        self.send(
            Principal::Direct,
            None,
            json!({"name": manifest::REQUESTS_TOOL, "arguments": {
                "op": "approve", "request_id": request_id
            }}),
        )
        .await
    }

    /// The request as the approver's request list shows it.
    async fn listed(&self, request_id: &str) -> Value {
        let reply = self
            .send(
                Principal::Direct,
                None,
                json!({"name": manifest::REQUESTS_TOOL, "arguments": {"op": "list"}}),
            )
            .await;
        reply["result"]["requests"]
            .as_array()
            .expect("requests list")
            .iter()
            .find(|request| request["request_id"] == request_id)
            .cloned()
            .expect("the request is listed")
    }

    fn status(&self, request_id: &str) -> String {
        self.store
            .list_action_requests("direct")
            .expect("list requests")
            .into_iter()
            .find(|request| request.request_id == request_id)
            .expect("request exists")
            .status
    }

    fn sent(&self) -> usize {
        self.transport.requests().len()
    }
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"]
        .as_str()
        .or_else(|| reply["structuredContent"]["code"].as_str())
        .unwrap_or("")
}

fn answer(reply: &Value) -> &Value {
    reply
        .get("result")
        .unwrap_or_else(|| panic!("expected a withdrawal answer, got {reply}"))
}

/// The carrier withdraws its held call: the answer is `withdrawn`, the
/// approver's list shows the request withdrawn, and approving it afterwards
/// is refused and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_carrier_withdraws_a_pending_call_and_a_later_approval_sends_nothing() {
    let fixture = Fixture::new("carrier");
    let request_id = fixture.park(aft(), "q", Some("run-1:call-0")).await;

    let reply = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "run-1:call-0"}))
        .await;
    assert_eq!(answer(&reply), &json!({"answer": "withdrawn"}));
    assert_eq!(fixture.status(&request_id), "cancelled");
    let listed = fixture.listed(&request_id).await;
    assert_eq!(
        (&listed["status"], &listed["withdrawn"], &listed["call_key"]),
        (&json!("cancelled"), &json!(true), &json!("run-1:call-0")),
        "{listed}"
    );

    fixture.script(live());
    let approved = fixture.approve(&request_id).await;
    assert_eq!(code(&approved), "approval_withdrawn", "{approved}");
    assert_eq!(fixture.sent(), 0, "a withdrawn call is never sent");
}

/// The scope's owner withdraws a call another module carried by naming that
/// carrier. Without naming it, the owner is refused, not told the call is
/// unknown, and the call stays held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_withdraws_by_naming_the_carrier() {
    let fixture = Fixture::new("owner");
    let request_id = fixture.park(aft(), "q", Some("k")).await;

    let unnamed = fixture
        .withdraw(owner(), Some(stamp()), json!({"call_key": "k"}))
        .await;
    assert_eq!(code(&unnamed), "withdraw_not_permitted", "{unnamed}");
    assert_eq!(fixture.status(&request_id), "pending");

    let named = fixture
        .withdraw(
            owner(),
            Some(stamp()),
            json!({"call_key": "k", "carrier": "reserved:aft"}),
        )
        .await;
    assert_eq!(answer(&named), &json!({"answer": "withdrawn"}));
    assert_eq!(fixture.status(&request_id), "cancelled");
}

/// A carrier may name itself as the carrier, but naming another carrier is
/// refused: only the scope's owner may withdraw a call someone else carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_carrier_naming_another_carrier_is_refused() {
    let fixture = Fixture::new("other-carrier");
    let aft_request = fixture.park(aft(), "q-aft", Some("k-aft")).await;
    let broca_request = fixture.park(broca(), "q-broca", Some("k-broca")).await;

    let refused = fixture
        .withdraw(
            aft(),
            Some(stamp()),
            json!({"call_key": "k-broca", "carrier": "reserved:broca"}),
        )
        .await;
    assert_eq!(code(&refused), "withdraw_not_permitted", "{refused}");
    assert_eq!(fixture.status(&broca_request), "pending");
    assert_eq!(fixture.status(&aft_request), "pending");

    let own = fixture
        .withdraw(
            aft(),
            Some(stamp()),
            json!({"call_key": "k-aft", "carrier": "reserved:aft"}),
        )
        .await;
    assert_eq!(answer(&own), &json!({"answer": "withdrawn"}));
    assert_eq!(fixture.status(&aft_request), "cancelled");
    assert_eq!(fixture.status(&broca_request), "pending");
}

/// Once the approved call has been sent, a withdrawal reports
/// `already_started` with the outcome plexus recorded for that send in its
/// audit journal, never the call's result, and every permitted caller on
/// every repeat gets the same answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_after_the_claim_reports_already_started_with_the_audit_outcome() {
    let fixture = Fixture::new("started");
    let request_id = fixture.park(aft(), "q", Some("k")).await;
    fixture.script(live());
    let approved = fixture.approve(&request_id).await;
    assert_eq!(
        approved["result"]["transmission"], "completed",
        "{approved}"
    );
    assert_eq!(fixture.sent(), 1);

    let expected = json!({"answer": "already_started", "outcome": "completed"});
    for (caller, arguments) in [
        (aft(), json!({"call_key": "k"})),
        (aft(), json!({"call_key": "k"})),
        (owner(), json!({"call_key": "k", "carrier": "reserved:aft"})),
    ] {
        let reply = fixture.withdraw(caller, Some(stamp()), arguments).await;
        assert_eq!(answer(&reply), &expected);
    }
    assert_eq!(fixture.status(&request_id), "consumed");
    assert_eq!(fixture.sent(), 1);
}

/// `withdrawn` is read back from the stored request: a repeat by the carrier
/// and a later withdrawal by the owner get the identical answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeat_and_another_permitted_caller_get_the_identical_answer() {
    let fixture = Fixture::new("repeat");
    fixture.park(aft(), "q", Some("k")).await;
    let first = fixture
        .withdraw(
            owner(),
            Some(stamp()),
            json!({"call_key": "k", "carrier": "reserved:aft"}),
        )
        .await;
    let repeat = fixture
        .withdraw(
            owner(),
            Some(stamp()),
            json!({"call_key": "k", "carrier": "reserved:aft"}),
        )
        .await;
    let carrier = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "k"}))
        .await;
    assert_eq!(answer(&first), &json!({"answer": "withdrawn"}));
    assert_eq!(repeat, first);
    assert_eq!(carrier, first);
}

/// Withdrawing a key under which plexus never held a call answers
/// `unknown_call`, for the carrier and for the owner. That includes an
/// ordinary call that needed no approval and ran in its own request: plexus
/// sent it but never held it, so `unknown_call` does not mean "not sent".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_never_held_is_unknown_call() {
    let fixture = Fixture::new("unknown");
    let never = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "never"}))
        .await;
    assert_eq!(answer(&never), &json!({"answer": "unknown_call"}));
    let owner_never = fixture
        .withdraw(owner(), Some(stamp()), json!({"call_key": "never"}))
        .await;
    assert_eq!(answer(&owner_never), &json!({"answer": "unknown_call"}));

    let ran = fixture.invoke(aft(), OPEN, "q", Some("ran")).await;
    assert_eq!(ran["result"]["transmission"], "completed", "{ran}");
    assert_eq!(fixture.sent(), 1);
    let reply = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "ran"}))
        .await;
    assert_eq!(answer(&reply), &json!({"answer": "unknown_call"}));
}

/// Withdrawing a held request whose approval window (`expires_at`) has passed
/// answers `refused` with reason `expired`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_request_is_refused_expired() {
    let fixture = Fixture::new("expired");
    let request_id = fixture.park(aft(), "q", Some("k")).await;
    Connection::open(fixture.path.as_ref() as &Path)
        .expect("open store file")
        .execute(
            "UPDATE action_requests SET expires_at = 1 WHERE request_id = ?1",
            [&request_id],
        )
        .expect("lapse the request");
    let reply = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "k"}))
        .await;
    assert_eq!(
        answer(&reply),
        &json!({"answer": "refused", "reason": "expired"})
    );
}

/// An approved request that plexus retired unsent because the scope it was
/// raised under had ended by the time it would run answers `refused` with
/// reason `scope_ended`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_refused_at_the_scope_recheck_is_refused_scope_ended() {
    let fixture = Fixture::new("scope-ended");
    let request_id = fixture.park(aft(), "q", Some("k")).await;
    fixture.script(ended());
    let approved = fixture.approve(&request_id).await;
    assert_eq!(
        approved["result"]["response"]["code"], "scope_ended",
        "{approved}"
    );
    assert_eq!(fixture.sent(), 0);
    let reply = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "k"}))
        .await;
    assert_eq!(
        answer(&reply),
        &json!({"answer": "refused", "reason": "scope_ended"})
    );
}

/// A request the approver denied answers `refused` with reason `denied`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_denied_request_is_refused_denied() {
    let fixture = Fixture::new("denied");
    let request_id = fixture.park(aft(), "q", Some("k")).await;
    let denied = fixture
        .send(
            Principal::Direct,
            None,
            json!({"name": manifest::REQUESTS_TOOL, "arguments": {
                "op": "deny", "request_id": request_id
            }}),
        )
        .await;
    assert_eq!(denied["result"]["denied"], true, "{denied}");
    let reply = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "k"}))
        .await;
    assert_eq!(
        answer(&reply),
        &json!({"answer": "refused", "reason": "denied"})
    );
}

/// A call sent without a `call_key` is held and approved exactly as before,
/// but nothing can withdraw it: it is stored under no key, so a withdrawal
/// leaves it held and approving it still sends it. (What such a withdrawal
/// answers is `unknown_call`, covered by the test for keys never held.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_without_a_key_still_works_but_cannot_be_withdrawn() {
    let fixture = Fixture::new("keyless");
    let request_id = fixture.park(aft(), "q", None).await;
    assert!(fixture.listed(&request_id).await.get("call_key").is_none());

    for caller in [aft(), owner()] {
        let reply = fixture
            .withdraw(caller, Some(stamp()), json!({"call_key": "q"}))
            .await;
        assert!(reply.get("result").is_some(), "{reply}");
    }
    assert_eq!(fixture.status(&request_id), "pending");

    fixture.script(live());
    let approved = fixture.approve(&request_id).await;
    assert_eq!(
        approved["result"]["transmission"], "completed",
        "{approved}"
    );
    assert_eq!(fixture.sent(), 1);
}

/// The scope comes from the route's stamp. A withdrawal from a route stamped
/// with another scope, or with none, is refused, and so is one stating a
/// scope that is not the stamp's. Stating the stamp's own scope is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_under_another_scope_is_refused() {
    let fixture = Fixture::new("other-scope");
    let request_id = fixture.park(aft(), "q", Some("k")).await;

    let later_epoch = fixture
        .withdraw(aft(), Some(stamp_at(5)), json!({"call_key": "k"}))
        .await;
    assert_eq!(
        code(&later_epoch),
        "withdraw_not_permitted",
        "{later_epoch}"
    );
    let unscoped = fixture
        .withdraw(aft(), None, json!({"call_key": "k"}))
        .await;
    assert_eq!(code(&unscoped), "withdraw_not_permitted", "{unscoped}");
    let claimed = fixture
        .withdraw(
            aft(),
            Some(stamp()),
            json!({"call_key": "k", "scope": {
                "owner": "reserved:prefrontal-core", "ref": "worker-7", "scope_epoch": 5
            }}),
        )
        .await;
    assert_eq!(code(&claimed), "withdraw_not_permitted", "{claimed}");
    assert_eq!(fixture.status(&request_id), "pending");

    let matching = fixture
        .withdraw(
            aft(),
            Some(stamp()),
            json!({"call_key": "k", "scope": {
                "owner": "reserved:prefrontal-core", "ref": "worker-7", "scope_epoch": 4
            }}),
        )
        .await;
    assert_eq!(answer(&matching), &json!({"answer": "withdrawn"}));
}

/// The withdrawal names its target in `arguments.call_key` and carries no key
/// of its own, and it is not a model tool: plexus does not advertise it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_withdraw_request_is_validated_and_not_advertised() {
    let fixture = Fixture::new("shape");
    fixture.park(aft(), "q", Some("k")).await;

    let own_key = fixture
        .send(
            aft(),
            Some(stamp()),
            json!({"name": manifest::WITHDRAW_TOOL, "call_key": "w-1",
                   "arguments": {"call_key": "k"}}),
        )
        .await;
    assert_eq!(
        (code(&own_key), &own_key["error"]["field"]),
        ("invalid_request", &json!(CALL_KEY_FIELD)),
        "{own_key}"
    );
    let missing = fixture.withdraw(aft(), Some(stamp()), json!({})).await;
    assert_eq!(
        (code(&missing), &missing["error"]["field"]),
        ("invalid_request", &json!("arguments.call_key")),
        "{missing}"
    );

    let advertised = serde_json::to_string(&manifest::build("plexus")).expect("manifest JSON");
    assert!(
        advertised.contains(&format!("\"{}\"", manifest::REQUESTS_TOOL)),
        "the manifest lists the advertised tools by name: {advertised}"
    );
    assert!(!advertised.contains(manifest::WITHDRAW_TOOL));
}

/// An `invoke` of the held action carrying `call_key` and, when given, the
/// relayed-call `origin`.
fn relayed_invoke(query: &str, call_key: &str, origin: Option<Value>) -> Value {
    let mut body = json!({"name": manifest::INVOKE_TOOL, "arguments": {
        "op": "call", "connection": HELD, "action": "search",
        "args": {"query": query}
    }, "call_key": call_key});
    if let Some(origin) = origin {
        body["origin"] = origin;
    }
    body
}

/// An origin carried by `reserved:broca` under `call_key`.
fn broca_origin(call_key: &str) -> Value {
    json!({"carrier": {"kind": "reserved", "module_id": "broca"}, "call_key": call_key})
}

/// Each relayed-call vector, sent as an `invoke` on a connection whose action
/// needs approval, parks an approval request. For the Broca and Claude Code
/// bridge vectors, which state an `origin`, the stored request's
/// `relay_origin` holds that origin's key as the vector writes it and its
/// carrier in the stored principal form (`reserved:broca`). The OpenCode plugin vector states no origin, so its
/// `relay_origin` is NULL. The origin is kept for attribution only: the
/// request as the approver's `requests` list shows it has no `relay_origin`
/// or `origin` field and never mentions the carrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_relayed_call_records_its_origin_on_the_request() {
    let fixture = Fixture::new("relayed-held");
    for (label, source) in crate::relay_vectors::RELAYED {
        let vector = crate::relay_vectors::parse(source);
        let call = crate::relay_vectors::relayed_as(
            &vector,
            manifest::INVOKE_TOOL,
            json!({"op": "call", "connection": HELD, "action": "search",
                   "args": {"query": label}}),
        );
        let reply = fixture.send(aft(), Some(stamp()), call).await;
        assert_eq!(code(&reply), "access_pending", "{label}: {reply}");
        let request = fixture
            .store
            .list_action_requests("direct")
            .expect("list requests")
            .into_iter()
            .find(|request| request.args_snapshot["query"] == label)
            .expect("the call parked a request");
        let expected = crate::relay_vectors::recorded_origin(&vector);
        assert_eq!(
            request
                .relay_origin
                .map(|origin| (origin.carrier, origin.call_key)),
            expected,
            "{label}"
        );
        let listed = fixture.listed(&request.request_id).await;
        assert!(listed.get("relay_origin").is_none(), "{label}: {listed}");
        assert!(listed.get("origin").is_none(), "{label}: {listed}");
        if let Some((carrier, _)) = expected {
            let listed = listed.to_string();
            assert!(!listed.contains(&carrier), "{label}: {listed}");
        }
    }
    assert_eq!(fixture.sent(), 0);
}

/// The origin is attribution, never a key. Two calls stating the same origin
/// under different `call_key`s are held as two requests; the same call sent
/// again under its `call_key` with a different origin is the same request;
/// and withdrawing by the origin's key finds nothing, while withdrawing by
/// the carrier's own `call_key` withdraws the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_origin_is_never_a_key_for_holding_or_withdrawing() {
    let fixture = Fixture::new("relayed-not-a-key");
    let origin = broca_origin("lin_7f3a9c2e:42");
    let first = fixture
        .send(
            aft(),
            Some(stamp()),
            relayed_invoke("a", "pf:A", Some(origin.clone())),
        )
        .await;
    assert_eq!(code(&first), "access_pending", "{first}");
    let second = fixture
        .send(
            aft(),
            Some(stamp()),
            relayed_invoke("b", "pf:B", Some(origin.clone())),
        )
        .await;
    assert_eq!(code(&second), "access_pending", "{second}");
    let resent = fixture
        .send(
            aft(),
            Some(stamp()),
            relayed_invoke("a", "pf:A", Some(broca_origin("lin_other:7"))),
        )
        .await;
    assert_eq!(code(&resent), "access_pending", "{resent}");

    // Two requests, not three: the resend under `pf:A` reused its request.
    let requests = fixture
        .store
        .list_action_requests("direct")
        .expect("list requests");
    assert_eq!(requests.len(), 2, "{requests:?}");
    let mut keys: Vec<_> = requests
        .iter()
        .map(|request| request.call_key.clone())
        .collect();
    keys.sort();
    assert_eq!(keys, [Some("pf:A".to_string()), Some("pf:B".to_string())]);

    for caller in [aft(), broca()] {
        let reply = fixture
            .withdraw(
                caller,
                Some(stamp()),
                json!({"call_key": "lin_7f3a9c2e:42"}),
            )
            .await;
        assert_eq!(answer(&reply), &json!({"answer": "unknown_call"}));
    }
    for request in &requests {
        assert_eq!(fixture.status(&request.request_id), "pending");
    }
    let withdrawn = fixture
        .withdraw(aft(), Some(stamp()), json!({"call_key": "pf:A"}))
        .await;
    assert_eq!(answer(&withdrawn), &json!({"answer": "withdrawn"}));
}
