use super::*;
use plexus_core::github::facade::bot_request_scoped_with_preconditions;
use plexus_core::scope::{ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use subc_protocol::scope::ScopeParent;

type Answer = Result<ScopeDescription, ScopeReadError>;

struct Reader {
    route: CallScope,
    run: Mutex<Answer>,
    asked: Mutex<Vec<(String, String)>>,
}

impl ScopeReader for Reader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Answer {
        self.asked
            .lock()
            .unwrap()
            .push((owner.into(), scope_ref.into()));
        if (owner, scope_ref) == (self.route.owner.as_str(), self.route.scope_ref.as_str()) {
            return Ok(live(self.route.clone()));
        }
        assert_eq!((owner, scope_ref), ("reserved:aft", "run-1"));
        self.run.lock().unwrap().clone()
    }
}

fn live(scope: CallScope) -> ScopeDescription {
    ScopeDescription {
        status: ScopeStatus::Live,
        owner_synced: true,
        owner_configured: true,
        live: Some(scope),
        parent: None,
        expires_at_ms: None,
    }
}

fn run() -> Value {
    json!({"owner":"reserved:aft", "ref":"run-1", "epoch":11})
}

fn install(f: &mut Fixture) -> Arc<Reader> {
    let mut stamp = f.scope.clone();
    stamp.owner = "reserved:aft".into();
    stamp.scope_ref = "run-1".into();
    stamp.scope_epoch = 11;
    // The run deliberately has no delegation: it must never supply authority.
    stamp.delegates = false;
    stamp.agent_id = None;
    let mut described = live(stamp);
    described.parent = Some(ScopeParent::new(
        plexus_core::scope::parse_scope_owner(&f.scope.owner).unwrap(),
        &f.scope.scope_ref,
        f.scope.scope_epoch,
    ));
    let reader = Arc::new(Reader {
        route: f.scope.clone(),
        run: Mutex::new(Ok(described)),
        asked: Mutex::new(Vec::new()),
    });
    f.engine = f.engine.clone().with_scope_reader(reader.clone());
    reader
}

fn send(f: &Fixture, request: &Value, nonce: &str, run_scope: Option<&Value>) -> Value {
    checked_reply(bot_request_scoped_with_preconditions(
        &f.store,
        &f.engine,
        "reserved:aft",
        Some(&f.scope),
        request,
        nonce,
        None,
        run_scope,
        nonce,
        "worker",
        f.now,
    ))
}

fn ended(reader: &Reader) {
    let mut answer = reader.run.lock().unwrap();
    let description = answer.as_mut().unwrap();
    description.status = ScopeStatus::Ended;
    description.live = None;
    description.parent = None;
}

fn refusal(reply: &Value, code: &str, legs: Value) {
    assert_eq!(
        reply["result"],
        json!({
            "status":"refused", "refusal_code":code, "scope_role":"run",
            "transmission":"not_sent", "legs_sent":legs,
        }),
        "run scope must refuse the unsent write: {reply}"
    );
}

#[test]
fn live_child_sends_under_route_authority() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    reader.run.lock().unwrap().as_mut().unwrap().expires_at_ms = Some(u64::MAX);
    let reply = send(&f, &comment(), "live", Some(&run()));
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    assert_eq!(
        *reader.asked.lock().unwrap(),
        [
            (f.scope.owner.clone(), f.scope.scope_ref.clone()),
            ("reserved:aft".into(), "run-1".into()),
        ]
    );
    let request = &f.github.repository.lock().unwrap()[0];
    assert!(request.args.get("run_scope").is_none());
}

#[test]
fn run_ended_after_ownership_read_stops_first_write() {
    let mut f = Fixture::new(&[("github.issue.get", "read"), ("edit_issue", "write")]);
    let reader = install(&mut f);
    *f.github.after_read.lock().unwrap() = Some(Box::new(move || ended(&reader)));
    let edit = json!({"action":"issue edit", "repository":"org/repo", "target":{"number":"42"}, "body":{"title":"changed"}});
    refusal(
        &send(&f, &edit, "ended-first", Some(&run())),
        "scope_ended",
        json!([]),
    );
    assert_eq!(f.github.actions(), ["github.issue.get"]);
    let row = f
        .store
        .github_receipt("agent-fixture", "ended-first")
        .unwrap()
        .unwrap();
    assert!(row
        .effects
        .iter()
        .all(|effect| effect.dispatch_attempted_at.is_none()));
}

#[test]
fn run_scope_described_before_each_unsent_leg() {
    let mut f = Fixture::new(&[("add_issue_comment", "write"), ("close_issue", "write")]);
    let reader = install(&mut f);
    *f.github.before_write.lock().unwrap() = Some(Box::new(move || ended(&reader)));
    let close =
        json!({"verb":"issue close", "repository":"org/repo", "number":"42", "comment":"done"});
    let reply = send(&f, &close, "between", Some(&run()));
    refusal(&reply, "scope_ended", json!(["add_issue_comment"]));
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    assert_eq!(*f.github.comments.lock().unwrap(), ["done"]);
    let row = f
        .store
        .github_receipt("agent-fixture", "between")
        .unwrap()
        .unwrap();
    assert!(
        row.effects[0].outcome.is_some(),
        "the first write stays recorded"
    );
    assert!(row.effects[1].dispatch_attempted_at.is_none());
    assert_eq!(
        send(&f, &close, "between", Some(&run()))["result"],
        reply["result"]
    );
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
}

#[test]
fn run_epoch_mismatch_is_ended() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    reader
        .run
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .live
        .as_mut()
        .unwrap()
        .scope_epoch += 1;
    refusal(
        &send(&f, &comment(), "epoch", Some(&run())),
        "scope_ended",
        json!([]),
    );
    f.github.zero_contacts();
}

#[test]
fn run_expiry_is_checked_even_when_daemon_reports_live() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    reader.run.lock().unwrap().as_mut().unwrap().expires_at_ms = Some(0);
    refusal(
        &send(&f, &comment(), "expired", Some(&run())),
        "scope_ended",
        json!([]),
    );
    f.github.zero_contacts();
}

#[test]
fn run_parent_must_match_route_owner_ref_and_epoch() {
    for dimension in ["owner", "ref", "epoch"] {
        let mut f = Fixture::new(&[("add_issue_comment", "write")]);
        let reader = install(&mut f);
        {
            let mut answer = reader.run.lock().unwrap();
            let parent = answer.as_mut().unwrap().parent.as_mut().unwrap();
            match dimension {
                "owner" => {
                    parent.owner = subc_protocol::Principal::Reserved {
                        module_id: "other".into(),
                    }
                }
                "ref" => parent.scope_ref.push_str("-other"),
                _ => parent.scope_epoch += 1,
            }
        }
        refusal(
            &send(&f, &comment(), dimension, Some(&run())),
            "run_scope_not_child",
            json!([]),
        );
        f.github.zero_contacts();
    }
}

#[test]
fn unsynced_run_releases_claim_for_same_nonce_retry() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    let healthy = reader.run.lock().unwrap().clone();
    {
        let mut answer = reader.run.lock().unwrap();
        let description = answer.as_mut().unwrap();
        description.status = ScopeStatus::NotLive;
        description.owner_synced = false;
        description.live = None;
    }
    refusal(
        &send(&f, &comment(), "retry", Some(&run())),
        "scope_not_synced",
        json!([]),
    );
    f.github.zero_contacts();
    let row = f
        .store
        .github_receipt("agent-fixture", "retry")
        .unwrap()
        .unwrap();
    assert!(row.claim_owner.is_none());
    assert!(row.outcome.is_none());
    *reader.run.lock().unwrap() = healthy;
    assert_eq!(
        send(&f, &comment(), "retry", Some(&run()))["result"]["status"],
        "completed"
    );
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
}

#[test]
fn unverifiable_or_incomplete_run_fails_closed() {
    for kind in [
        "unavailable",
        "parent_missing",
        "stamp_missing",
        "wrong_identity",
        "unconfigured",
    ] {
        let mut f = Fixture::new(&[("add_issue_comment", "write")]);
        let reader = install(&mut f);
        {
            let mut answer = reader.run.lock().unwrap();
            if kind == "unavailable" {
                *answer = Err(ScopeReadError("daemon disconnected".into()));
            } else {
                let description = answer.as_mut().unwrap();
                match kind {
                    "parent_missing" => description.parent = None,
                    "stamp_missing" => description.live = None,
                    "wrong_identity" => {
                        description.live.as_mut().unwrap().owner = "reserved:other".into()
                    }
                    _ => {
                        description.status = ScopeStatus::NotLive;
                        description.owner_synced = false;
                        description.owner_configured = false;
                        description.live = None;
                    }
                }
            }
        }
        refusal(
            &send(&f, &comment(), kind, Some(&run())),
            "scope_unverifiable",
            json!([]),
        );
        f.github.zero_contacts();
    }
}

#[test]
fn absent_run_after_owner_sync_is_ended() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    {
        let mut answer = reader.run.lock().unwrap();
        let description = answer.as_mut().unwrap();
        description.status = ScopeStatus::NotLive;
        description.live = None;
    }
    refusal(
        &send(&f, &comment(), "absent", Some(&run())),
        "scope_ended",
        json!([]),
    );
    f.github.zero_contacts();
}

#[test]
fn malformed_run_fields_are_named_before_claim_or_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    for (value, field) in [
        (Value::Null, "run_scope"),
        (json!([]), "run_scope"),
        (json!({"ref":"run-1","epoch":11}), "run_scope.owner"),
        (json!({"owner":"reserved:aft","epoch":11}), "run_scope.ref"),
        (
            json!({"owner":"reserved:aft","ref":"run-1"}),
            "run_scope.epoch",
        ),
        (
            json!({"owner":3,"ref":"run-1","epoch":11}),
            "run_scope.owner",
        ),
        (
            json!({"owner":"reserved:aft","ref":null,"epoch":11}),
            "run_scope.ref",
        ),
        (
            json!({"owner":"reserved:aft","ref":"run-1","epoch":-1}),
            "run_scope.epoch",
        ),
        (
            json!({"owner":"reserved:aft","ref":"run-1","epoch":1.0}),
            "run_scope.epoch",
        ),
        (
            json!({"owner":"reserved:aft","ref":"run-1","epoch":1.5}),
            "run_scope.epoch",
        ),
        (
            json!({"owner":"reserved:aft","ref":"run-1","epoch":"11"}),
            "run_scope.epoch",
        ),
        (
            json!({"owner":"reserved:aft","ref":"run-1","epoch":true}),
            "run_scope.epoch",
        ),
        (
            json!({"owner":"reserved:aft","ref":"run-1","epoch":11,"other":true}),
            "run_scope.other",
        ),
    ] {
        let reply = send(&f, &comment(), "invalid", Some(&value));
        assert_eq!(
            reply["result"],
            json!({"status":"refused", "refusal_code":"invalid_request",
            "code":"invalid_request", "field":field, "transmission":"not_sent"}),
            "{value}: {reply}"
        );
        assert!(f
            .store
            .github_receipt("agent-fixture", "invalid")
            .unwrap()
            .is_none());
        f.github.zero_contacts();
    }
}

#[test]
fn different_run_scope_replays_terminal_nonce_without_payload_mismatch() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    let first = send(&f, &comment(), "replay", Some(&run()));
    assert_eq!(first["result"]["status"], "completed");
    let changed = json!({"owner":"reserved:forged", "ref":"another-run", "epoch":0});
    for value in [Some(&changed), None] {
        let replay = send(&f, &comment(), "replay", value);
        assert_eq!(
            replay, first,
            "run_scope must not enter the request fingerprint"
        );
    }
    assert_eq!(
        reader.asked.lock().unwrap().len(),
        2,
        "terminal replays never describe R"
    );
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    f.store.unbind_github_repo("org/repo").unwrap();
    assert_eq!(
        send(&f, &comment(), "replay", Some(&changed))["result"],
        first["result"]
    );
}

#[test]
fn no_run_scope_preserves_legacy_reply_and_fingerprint() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    let reader = install(&mut f);
    let legacy = f.request(&comment(), "legacy-run");
    assert_eq!(
        serde_json::to_vec(&legacy).unwrap(),
        serde_json::to_vec(&send(&f, &comment(), "legacy-run", None)).unwrap()
    );
    assert_eq!(reader.asked.lock().unwrap().len(), 1);
    let row = f
        .store
        .github_receipt("agent-fixture", "legacy-run")
        .unwrap()
        .unwrap();
    assert_eq!(
        row.request_fingerprint,
        "exact-json-v1:b964419a4dc1e71039a2d87a328757cd38d28e1da866b3d5db1dd5dec6a42a58"
    );
}

#[test]
fn forged_run_cannot_supply_missing_route_authority() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    install(&mut f);
    f.scope.delegates = false;
    let reply = send(&f, &comment(), "no-authority", Some(&run()));
    assert_eq!(
        reply["result"],
        json!({"status":"refused", "refusal_code":"delegating_scope_required", "scope_role":"route"})
    );
    f.github.zero_contacts();
}
