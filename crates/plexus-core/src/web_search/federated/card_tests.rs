use super::*;
use crate::consent_card::{ConsentCards, ElicitationCallError, ElicitationRoute};
use crate::scope::CallScope;
use std::time::Instant;

#[derive(Default)]
struct Requester {
    cards: Mutex<Vec<Value>>,
    ops: Mutex<Vec<String>>,
}
impl Requester {
    fn answer(&self, index: usize, state: &str, choice: Option<&str>) {
        let mut cards = self.cards.lock().unwrap();
        cards[index]["state"] = json!(state);
        if let Some(choice) = choice {
            cards[index]["answered_choice_id"] = json!(choice);
        }
    }
    fn count(&self) -> usize {
        self.cards.lock().unwrap().len()
    }
}
impl ElicitationRoute for Requester {
    fn call_scoped(
        &self,
        scope: &CallScope,
        op: &str,
        params: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        assert_eq!(scope.owner, "reserved:callosum");
        self.ops.lock().unwrap().push(op.into());
        let mut cards = self.cards.lock().unwrap();
        if op == "consent.request" {
            let id = format!("el_search_{}", cards.len());
            let mut card = params;
            card["elicitation_id"] = json!(id);
            card["state"] = json!("pending");
            cards.push(card);
            return Ok(json!({"elicitation_id":id}));
        }
        Ok(cards
            .iter()
            .find(|c| c["elicitation_id"] == params["elicitation_id"])
            .unwrap()
            .clone())
    }
}

fn setup(tool: Tool) -> (Fixture, Arc<Requester>) {
    let mut f = Fixture::new(tool);
    let requester = Arc::new(Requester::default());
    f.engine = f
        .engine
        .with_consent_cards(Arc::new(ConsentCards::new(requester.clone())));
    (f, requester)
}
fn scope() -> CallScope {
    CallScope {
        owner: "reserved:callosum".into(),
        scope_ref: "fed-claim:route".into(),
        scope_epoch: 1,
        kind: Some("federated".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: None,
        delegates: false,
        owner_authorized: false,
    }
}
fn search(
    f: &Fixture,
    caller: &FederatedCaller,
    args: &Value,
    declared: bool,
) -> Result<bool, Value> {
    search_until(f, caller, args, declared, Instant::now())
}

fn search_until(
    f: &Fixture,
    caller: &FederatedCaller,
    args: &Value,
    declared: bool,
    deadline: Instant,
) -> Result<bool, Value> {
    let wait = Some((declared, deadline));
    match f.tool {
        Tool::Code => f
            .code
            .search_federated_held(
                &f.engine,
                caller,
                args.as_object().unwrap(),
                Some(&scope()),
                None,
                wait,
            )
            .map(|_| false)
            .map_err(|e| e.to_wire()),
        _ => f
            .web
            .search_federated_held(
                &f.engine,
                caller,
                args.as_object().unwrap(),
                Some(&scope()),
                None,
                wait,
            )
            .map(|r| r.cached)
            .map_err(|e| e.to_wire()),
    }
}
fn args() -> Value {
    json!({"query":"rust async book"})
}
fn pending(f: &Fixture, requester: &Requester, arguments: &Value) {
    let wire = search(f, &caller(), arguments, true).unwrap_err();
    assert_eq!(
        wire["error"],
        json!({"code":"access_pending", "message":"Waiting for the user to answer this request. Send the same call again to collect the answer.",
        "elicitation_id":format!("el_search_{}", requester.count()-1),"transmission":"not_sent"})
    );
}
fn count(f: &Fixture, table: &str) -> i64 {
    f.db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn state(f: &Fixture, index: usize) -> String {
    f.db.query_row(
        "SELECT state FROM federated_card_records WHERE card_ref=?1",
        [format!("el_search_{index}")],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn first_search_cards_use_tool_inputs_and_allow_one_dispatch_or_cached_result() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for cached in [false, true] {
            if cached && matches!(tool, Tool::Code) {
                continue;
            }
            let (f, requester) = setup(tool);
            if cached {
                f.cache();
            }
            pending(&f, &requester, &args());
            assert_eq!(*f.reader.calls.lock().unwrap(), 0, "filing never describes");
            let body = requester.cards.lock().unwrap()[0].clone();
            assert_eq!(
                body["prompt"],
                if matches!(tool, Tool::Code) {
                    "search public code on GitHub"
                } else {
                    "search the web"
                }
            );
            assert_eq!(
                body["args_digest"],
                crate::jcs::jcs_sha256(&args()).unwrap()
            );
            assert_eq!(
                body["options"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| o["id"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["allow_once", "allow_always", "deny_once", "deny_always"]
            );
            requester.answer(0, "answered", Some("allow_once"));
            assert_eq!(search(&f, &caller(), &args(), true), Ok(cached), "{tool:?}");
            assert_eq!(state(&f, 0), "consumed");
            assert_eq!(count(&f, "federated_rows"), 0);
            assert_eq!(count(&f, "action_requests"), 0);
            assert_eq!(f.engine.transport().requests().len(), usize::from(!cached));
            if !cached {
                let card_ref: String =
                    f.db.query_row("SELECT card_ref FROM reservations", [], |r| r.get(0))
                        .unwrap();
                assert_eq!(card_ref, "el_search_0", "dispatch carries the consumed use");
            }
            pending(&f, &requester, &args());
            assert_eq!(requester.count(), 2, "identical replay must ask again");
        }
    }
}

#[test]
fn always_allow_commits_the_read_search_subject_then_never_reads_a_card() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let (f, requester) = setup(tool);
        pending(&f, &requester, &args());
        requester.answer(0, "answered", Some("allow_always"));
        assert!(search(&f, &caller(), &args(), true).is_ok());
        let row: (String, String, String, String) =
            f.db.query_row(
                "SELECT owner_principal,subject,scope,effect FROM federated_rows",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "".into(),
                tool.subject().into(),
                "read".into(),
                "allow".into()
            )
        );
        let reads = requester.ops.lock().unwrap().len();
        assert!(search(&f, &caller(), &args(), true).is_ok());
        assert_eq!(reads, requester.ops.lock().unwrap().len());
        assert_eq!(requester.count(), 1);
    }
}

#[test]
fn a_cached_allow_charges_the_federated_rate_bucket_once_and_rate_limited_keeps_the_next_answer() {
    for tool in [Tool::Web, Tool::OrderedWeb] {
        let (mut f, requester) = setup(tool);
        let clock = Arc::new(std::sync::atomic::AtomicI64::new(NOW));
        let service_clock = clock.clone();
        f.web = WebSearchService::with_clock(
            Arc::new(ExaRestBackend),
            Arc::new(move || service_clock.load(std::sync::atomic::Ordering::SeqCst)),
        );
        f.cache();
        f.limits(2, 100);
        pending(&f, &requester, &args());
        requester.answer(0, "answered", Some("allow_once"));
        assert_eq!(search(&f, &caller(), &args(), true), Ok(true));
        pending(&f, &requester, &args());
        requester.answer(1, "answered", Some("allow_once"));
        assert_eq!(
            search(&f, &caller(), &args(), true),
            Ok(true),
            "the first cache hit charged only once"
        );
        pending(&f, &requester, &args());
        requester.answer(2, "answered", Some("allow_once"));
        assert_eq!(
            search(&f, &caller(), &args(), true).unwrap_err()["error"]["code"],
            "rate_limited"
        );
        assert_eq!(state(&f, 2), "pending");
        clock.store(NOW + 60_000, std::sync::atomic::Ordering::SeqCst);
        f.cache();
        assert_eq!(search(&f, &caller(), &args(), true), Ok(true));
        assert_eq!(state(&f, 2), "consumed");
        assert!(f.engine.transport().requests().is_empty());
    }
}

#[test]
fn cannot_wait_files_no_search_card_for_either_tool() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for (declared, claim) in [
            (false, None),
            (true, Some(json!({"kind":"run","agent_id":"run"}))),
            (
                true,
                Some(
                    json!({"kind":"flow","flow_id":"f","flow_version":1,"flow_code_hash":"hash","flow_install_id":"i"}),
                ),
            ),
        ] {
            let (f, requester) = setup(tool);
            let mut attributes = caller().attributes;
            attributes.remote_claim = claim.map(|v| serde_json::from_value(v).unwrap());
            let caller = FederatedCaller::from_attributes(attributes).unwrap();
            let wire = search(&f, &caller, &args(), declared).unwrap_err();
            assert_eq!(wire["error"]["code"], "consent_unavailable");
            assert_eq!(wire["error"]["action"], tool.subject());
            assert_eq!(wire["error"]["transmission"], "not_sent");
            assert_eq!(requester.count(), 0);
            f.assert_no_cards();
        }
    }
}

#[test]
fn per_call_refusals_have_invoke_members_and_are_delivered_once() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for (answer_state, choice, code, terminal) in [
            ("answered", Some("deny_once"), "consent_denied", "declined"),
            ("expired", None, "consent_expired", "expired"),
            ("withdrawn", None, "consent_withdrawn", "withdrawn"),
        ] {
            let (f, requester) = setup(tool);
            pending(&f, &requester, &args());
            requester.answer(0, answer_state, choice);
            assert_eq!(
                search(&f, &caller(), &args(), true).unwrap_err()["error"],
                json!({"code":code,"message":code,"elicitation_id":"el_search_0","transmission":"not_sent"})
            );
            assert_eq!(state(&f, 0), terminal);
            assert_eq!(count(&f, "federated_rows"), 0);
            pending(&f, &requester, &args());
            assert_eq!(requester.count(), 2);
        }
    }
}

#[test]
fn different_arguments_never_collect_or_consume_another_search_answer() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let (f, requester) = setup(tool);
        pending(&f, &requester, &args());
        requester.answer(0, "answered", Some("allow_once"));
        let other_args = json!({"query":"different search words"});
        pending(&f, &requester, &other_args);
        assert_eq!(state(&f, 0), "pending");
        assert!(search(&f, &caller(), &args(), true).is_ok());
        assert_eq!(state(&f, 0), "consumed");
        assert_eq!(state(&f, 1), "pending");
        assert_eq!(requester.count(), 2);
    }
}

#[test]
fn no_non_grant_refusal_files_a_card_or_consumes_an_answer_or_rate_token() {
    let cases = [
        ("UPDATE connections SET status='auth_required'", "UPDATE connections SET status='active'", "connection_disabled"),
        ("UPDATE catalog_actions SET status='quarantined'", "UPDATE catalog_actions SET status='active'", "catalog_action_quarantined"),
        ("UPDATE catalog_actions SET risk='destructive'", "UPDATE catalog_actions SET risk='read'", "needs_decision_plane"),
        ("UPDATE connections SET ceiling_risk=NULL", "UPDATE connections SET ceiling_risk='write'", "grant_risk_ceiling"),
        ("UPDATE connections SET ceiling_selectors='[]'", "", "grant_action_selector"),
        ("UPDATE connections SET resource_filters='{\"required\":[\"missing\"]}'", "UPDATE connections SET resource_filters='{}'", "resource_filter_missing"),
        ("UPDATE catalog_actions SET schema_json='{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}'", "UPDATE catalog_actions SET schema_json='{\"type\":\"object\"}'", "argument_undeclared"),
    ];
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for (mutation, reset, code) in cases {
            let (f, requester) = setup(tool);
            f.cache();
            f.limits(1, 1);
            f.db.execute_batch(mutation).unwrap();
            assert_eq!(
                search(&f, &caller(), &args(), true).unwrap_err()["error"]["code"],
                code
            );
            assert_eq!(requester.count(), 0, "refused before any card");
            f.db.execute_batch(reset).unwrap();
            f.db.execute(
                "UPDATE connections SET ceiling_selectors=?1",
                [json!([tool.action()]).to_string()],
            )
            .unwrap();
            pending(&f, &requester, &args());
            requester.answer(0, "answered", Some("allow_once"));
            // The kept gate wins even over an answer and a standing allow together.
            f.allow();
            f.db.execute_batch(mutation).unwrap();
            assert_eq!(
                search(&f, &caller(), &args(), true).unwrap_err()["error"]["code"],
                code
            );
            assert_eq!(state(&f, 0), "pending");
            assert_eq!(requester.count(), 1);
            f.db.execute_batch(reset).unwrap();
            f.db.execute_batch("DELETE FROM federated_rows").unwrap();
            f.db.execute(
                "UPDATE connections SET ceiling_selectors=?1",
                [json!([tool.action()]).to_string()],
            )
            .unwrap();
            assert!(
                search(&f, &caller(), &args(), true).is_ok(),
                "gate refusals must charge nothing"
            );
            assert_eq!(state(&f, 0), "consumed");
        }
    }
}

#[test]
fn a_provider_failure_does_not_restore_a_consumed_search_answer() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let (f, requester) = setup(tool);
        pending(&f, &requester, &args());
        requester.answer(0, "answered", Some("allow_once"));
        f.engine
            .transport()
            .set_response(MockResponse::OutcomeUnknown);
        assert!(search(&f, &caller(), &args(), true).is_err());
        assert_eq!(f.engine.transport().requests().len(), 1);
        assert_eq!(state(&f, 0), "consumed");
        pending(&f, &requester, &args());
        assert_eq!(requester.count(), 2);
    }
}

#[test]
fn non_live_search_answers_keep_the_answer_and_invoke_liveness_members() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for (status, synced, configured, code, retryable) in [
            (
                ScopeStatus::Ended,
                true,
                true,
                "federated_pairing_ended",
                false,
            ),
            (
                ScopeStatus::NotLive,
                true,
                true,
                "federated_pairing_ended",
                false,
            ),
            (
                ScopeStatus::NotLive,
                true,
                false,
                "federated_liveness_unavailable",
                true,
            ),
            (
                ScopeStatus::NotLive,
                false,
                true,
                "federated_liveness_unavailable",
                true,
            ),
        ] {
            let (mut f, requester) = setup(tool);
            f.cache();
            f.limits(1, 1);
            pending(&f, &requester, &args());
            requester.answer(0, "answered", Some("allow_once"));
            let live = f.engine.clone();
            f.engine = f.engine.with_scope_reader(Arc::new(Reader {
                answer: Ok(description(status, synced, configured)),
                calls: Mutex::new(0),
            }));
            assert_eq!(
                search(&f, &caller(), &args(), true).unwrap_err()["error"],
                json!({"code":code,"message":code,"retryable":retryable,"transmission":"not_sent"})
            );
            assert_eq!(state(&f, 0), "pending");
            f.engine = live;
            assert!(search(&f, &caller(), &args(), true).is_ok());
            assert_eq!(state(&f, 0), "consumed");
        }
    }
}

#[test]
fn consumed_search_use_authorizes_vendor_arguments_without_reading_the_card_again() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let (f, requester) = setup(tool);
        pending(&f, &requester, &args());
        requester.answer(0, "answered", Some("allow_once"));
        let mut authority = SearchAuthorization::new(
            &caller(),
            if matches!(tool, Tool::Code) {
                crate::web_search::facade::SearchTool::Code
            } else {
                crate::web_search::facade::SearchTool::Web
            },
            args().as_object().unwrap(),
        )
        .unwrap();
        authority.wait = Some((true, Instant::now()));
        let request = authority
            .bind(crate::governance::AuthorizationRequest::new(
                "reserved:callosum",
                "backing",
                tool.action(),
                json!({"vendor_argument":"not the tool arguments"}),
            ))
            .with_scope_attribution_only(scope());
        f.engine
            .preflight_federated_search(request.clone())
            .unwrap();
        f.engine
            .apply_federated_search(&request, &mut authority)
            .unwrap();
        f.engine.consume_federated_search(&mut authority).unwrap();
        assert_eq!(state(&f, 0), "consumed");
        f.db.execute("DELETE FROM federated_card_records", [])
            .unwrap();
        let reservation = f.engine.authorize(authority.bind(request)).unwrap();
        assert_eq!(
            reservation.federated_card_ref.as_deref(),
            Some("el_search_0")
        );
        assert_eq!(
            f.engine.revalidate_and_dispatch(&reservation).transmission,
            crate::transport::TransmissionState::Sent
        );
        assert_eq!(requester.count(), 1);
    }
}

#[test]
fn one_call_allow_covers_all_backends_tried_but_not_the_next_call() {
    let (mut f, requester) = setup(Tool::OrderedWeb);
    let mut manifest: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../../../catalog/tavily_rest.jsonc"))
            .unwrap(),
    )
    .unwrap();
    manifest["auth"] = json!({"mode":"none"});
    manifest["credential_bindings"] = json!([]);
    f.engine
        .store()
        .upsert_manifest(CATALOG_PRINCIPAL, &crate::ingest_value(manifest).unwrap())
        .unwrap();
    f.engine
        .store()
        .insert_connection(
            "direct",
            "tavily-backing",
            "tavily_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    f.engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: "tavily-backing".into(),
            name: "search".into(),
            title: None,
            schema: json!({"type":"object"}),
            schema_hash: "tavily-schema".into(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    f.db.execute(
        "UPDATE connections SET ceiling_risk='read',ceiling_selectors='[\"search\"]'",
        [],
    )
    .unwrap();
    f.web = f
        .web
        .with_chain_backend(Arc::new(crate::web_search::TavilyRestBackend));
    f.engine
        .store()
        .set_web_search_order(&["exa".into(), "tavily".into()])
        .unwrap();
    f.engine.transport().set_response_sequence_for_method(
        "search",
        "",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "unavailable".into(),
            },
            MockResponse::Success(json!({"results":[]})),
        ],
    );
    pending(&f, &requester, &args());
    requester.answer(0, "answered", Some("allow_once"));
    assert_eq!(search(&f, &caller(), &args(), true), Ok(false));
    let requests = f.engine.transport().requests();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.connection_id.as_str())
            .collect::<Vec<_>>(),
        ["backing", "tavily-backing"]
    );
    assert_eq!(state(&f, 0), "consumed");
    assert_eq!(count(&f, "federated_rows"), 0);
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM reservations WHERE card_ref='el_search_0'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    pending(&f, &requester, &args());
    assert_eq!(requester.count(), 2);
    assert_eq!(f.engine.transport().requests().len(), 2);
}

#[test]
fn searches_hold_on_the_requester_and_serve_an_answer_received_during_the_wait() {
    struct AwaitAnswer(Arc<Requester>);
    impl ElicitationRoute for AwaitAnswer {
        fn call_scoped(
            &self,
            scope: &CallScope,
            op: &str,
            params: Value,
            timeout: Duration,
        ) -> Result<Value, ElicitationCallError> {
            if op == "consent.await" {
                self.0.answer(0, "answered", Some("allow_once"));
            }
            self.0.call_scoped(scope, op, params, timeout)
        }
    }
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let (mut f, requester) = setup(tool);
        f.engine = f
            .engine
            .with_consent_cards(Arc::new(ConsentCards::new(Arc::new(AwaitAnswer(
                requester.clone(),
            )))));
        assert_eq!(
            search_until(
                &f,
                &caller(),
                &args(),
                true,
                Instant::now() + Duration::from_secs(10)
            ),
            Ok(false)
        );
        assert!(requester
            .ops
            .lock()
            .unwrap()
            .iter()
            .any(|op| op == "consent.await"));
        assert_eq!(state(&f, 0), "consumed");
        assert_eq!(f.engine.transport().requests().len(), 1);
    }
}

#[test]
fn rate_limited_code_search_keeps_its_answer_until_the_bucket_refills() {
    let (mut f, requester) = setup(Tool::Code);
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(NOW));
    let service_clock = clock.clone();
    f.code = crate::code_search::CodeSearchService::with_clock(Arc::new(move || {
        service_clock.load(std::sync::atomic::Ordering::SeqCst)
    }));
    f.limits(1, 100);
    pending(&f, &requester, &args());
    requester.answer(0, "answered", Some("allow_once"));
    assert_eq!(search(&f, &caller(), &args(), true), Ok(false));
    pending(&f, &requester, &args());
    requester.answer(1, "answered", Some("allow_once"));
    assert_eq!(
        search(&f, &caller(), &args(), true).unwrap_err()["error"]["code"],
        "rate_limited"
    );
    assert_eq!(state(&f, 1), "pending");
    clock.store(NOW + 60_000, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(search(&f, &caller(), &args(), true), Ok(false));
    assert_eq!(state(&f, 1), "consumed");
    assert_eq!(f.engine.transport().requests().len(), 2);
}
