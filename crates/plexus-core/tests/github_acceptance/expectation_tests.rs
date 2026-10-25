use super::*;
use plexus_core::github::facade::bot_request_scoped_with_expect;
use plexus_core::scope::{ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};

fn expected(f: &Fixture) -> Value {
    json!({"app_handle_id":"app-fixture", "repo_binding_generation":f.store.github_repo_binding_generation().unwrap()})
}

fn call(f: &Fixture, expect: Option<&Value>, nonce: &str) -> Value {
    checked_reply(bot_request_scoped_with_expect(
        &f.store,
        &f.engine,
        "reserved:aft",
        Some(&f.scope),
        &comment(),
        nonce,
        expect,
        nonce,
        "worker",
        f.now,
    ))
}

fn no_claim(f: &Fixture, nonce: &str) {
    assert!(f
        .store
        .github_receipt("agent-fixture", nonce)
        .unwrap()
        .is_none());
    f.github.zero_contacts();
}

#[test]
fn matching_expectation_sends_and_pins_the_compared_authority() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let expect = expected(&f);
    let reply = call(&f, Some(&expect), "match");
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
    let receipt = f
        .store
        .github_receipt("agent-fixture", "match")
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.authority_baseline["app_handle_id"],
        expect["app_handle_id"]
    );
    assert_eq!(
        receipt.authority_baseline["repo_binding_generation"],
        expect["repo_binding_generation"]
    );
}

#[test]
fn expected_handle_mismatch_refuses_before_claim_or_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let mut expect = expected(&f);
    expect["app_handle_id"] = json!("previous-app");
    let reply = call(&f, Some(&expect), "handle");
    assert_eq!(
        reply["result"]["refusal_code"], "stale_authority{dimension: expected_handle}",
        "caller-pinned handle must refuse before claiming or contacting GitHub"
    );
    assert_eq!(reply["result"]["dimension"], "expected_handle");
    assert_eq!(reply["result"]["code"], "stale_authority");
    assert_eq!(reply["result"]["transmission"], "not_sent");
    no_claim(&f, "handle");
}

#[test]
fn expected_binding_mismatch_refuses_before_claim_or_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let mut expect = expected(&f);
    expect["repo_binding_generation"] =
        json!(expect["repo_binding_generation"].as_u64().unwrap() + 1);
    let reply = call(&f, Some(&expect), "binding");
    assert_eq!(
        reply["result"]["refusal_code"], "stale_authority{dimension: expected_binding}",
        "caller-pinned binding must refuse before claiming or contacting GitHub"
    );
    assert_eq!(reply["result"]["dimension"], "expected_binding");
    assert_eq!(reply["result"]["transmission"], "not_sent");
    no_claim(&f, "binding");
}

#[test]
fn malformed_expectations_name_the_field_without_claim_or_contact() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    for (expect, field) in [
        (Value::Null, "expect"),
        (json!([]), "expect"),
        (json!({"repo_binding_generation":0}), "expect.app_handle_id"),
        (
            json!({"app_handle_id":"app-fixture"}),
            "expect.repo_binding_generation",
        ),
        (
            json!({"app_handle_id":"app-fixture","repo_binding_generation":0,"other":true}),
            "expect.other",
        ),
        (
            json!({"app_handle_id":42,"repo_binding_generation":0}),
            "expect.app_handle_id",
        ),
        (
            json!({"app_handle_id":"app-fixture","repo_binding_generation":-1}),
            "expect.repo_binding_generation",
        ),
        (
            json!({"app_handle_id":"app-fixture","repo_binding_generation":1.5}),
            "expect.repo_binding_generation",
        ),
        (
            json!({"app_handle_id":"app-fixture","repo_binding_generation":1.0}),
            "expect.repo_binding_generation",
        ),
        (
            json!({"app_handle_id":"app-fixture","repo_binding_generation":"1"}),
            "expect.repo_binding_generation",
        ),
    ] {
        let reply = call(&f, Some(&expect), "invalid");
        assert_eq!(
            reply["result"]["refusal_code"], "invalid_request",
            "{expect}: {reply}"
        );
        assert_eq!(reply["result"]["field"], field);
        assert_eq!(reply["result"]["transmission"], "not_sent");
        no_claim(&f, "invalid");
    }
}

#[test]
fn absent_expectation_keeps_legacy_reply_bytes_and_fingerprint() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let legacy = f.request(&comment(), "legacy");
    let replay = call(&f, None, "legacy");
    assert_eq!(
        serde_json::to_vec(&legacy).unwrap(),
        serde_json::to_vec(&replay).unwrap()
    );
    let row = f
        .store
        .github_receipt("agent-fixture", "legacy")
        .unwrap()
        .unwrap();
    assert_eq!(
        row.request_fingerprint,
        "exact-json-v1:b964419a4dc1e71039a2d87a328757cd38d28e1da866b3d5db1dd5dec6a42a58"
    );
    assert_eq!(f.github.actions(), ["add_issue_comment"]);
}

#[test]
fn changed_expectation_on_same_nonce_is_payload_mismatch_even_after_unbind() {
    let f = Fixture::new(&[("add_issue_comment", "write")]);
    let expect = expected(&f);
    let first = call(&f, Some(&expect), "nonce");
    assert_eq!(first["result"]["status"], "completed");
    f.github.clear_contacts();
    for field in ["app_handle_id", "repo_binding_generation"] {
        let mut changed = expect.clone();
        changed[field] = if field == "app_handle_id" {
            json!("another-app")
        } else {
            json!(0)
        };
        let reply = call(&f, Some(&changed), "nonce");
        assert_eq!(
            reply["result"]["refusal_code"], "nonce_payload_mismatch",
            "{reply}"
        );
    }
    assert_eq!(
        call(&f, None, "nonce")["result"]["refusal_code"],
        "nonce_payload_mismatch"
    );
    f.store.unbind_github_repo("org/repo").unwrap();
    let replay = call(&f, Some(&expect), "nonce");
    assert_eq!(first["result"], replay["result"]);
    let mut changed = expect.clone();
    changed["app_handle_id"] = json!("another-app");
    assert_eq!(
        call(&f, Some(&changed), "nonce")["result"]["refusal_code"],
        "nonce_payload_mismatch"
    );
    f.github.zero_contacts();
}

struct ChangedEpochScopeReader {
    stamp: CallScope,
    reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl ScopeReader for ChangedEpochScopeReader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        assert_eq!(
            (owner, scope_ref),
            (self.stamp.owner.as_str(), self.stamp.scope_ref.as_str())
        );
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut live = self.stamp.clone();
        live.scope_epoch += 1;
        Ok(ScopeDescription {
            parent: None,
            expires_at_ms: None,
            status: ScopeStatus::Live,
            live: Some(live),
            owner_synced: true,
            owner_configured: true,
        })
    }
}

#[test]
fn new_nonce_without_prereads_rechecks_changed_scope_epoch_before_first_write() {
    let mut f = Fixture::new(&[("add_issue_comment", "write")]);
    assert_eq!(f.scope.acting_agent(), Some("agent-fixture"));
    assert!(f
        .store
        .github_receipt("agent-fixture", "new-nonce")
        .unwrap()
        .is_none());
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    f.engine = f
        .engine
        .with_scope_reader(Arc::new(ChangedEpochScopeReader {
            stamp: f.scope.clone(),
            reads: reads.clone(),
        }));
    let reply = f.request(&comment(), "new-nonce");
    assert_eq!(
        reply["result"]["refusal_code"], "scope_ended",
        "a cached open route must re-describe scope before its first write"
    );
    assert!(reads.load(std::sync::atomic::Ordering::SeqCst) > 0);
    assert!(
        f.github.actions().is_empty(),
        "changed scope epoch sent a GitHub write"
    );
    assert!(f.github.comments.lock().unwrap().is_empty());
    let row = f
        .store
        .github_receipt("agent-fixture", "new-nonce")
        .unwrap()
        .unwrap();
    assert!(row
        .effects
        .iter()
        .all(|effect| effect.dispatch_attempted_at.is_none()));
}
