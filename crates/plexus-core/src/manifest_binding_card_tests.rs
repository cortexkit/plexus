use super::*;
use crate::github::manifest_binding::{
    wire::Proposal, BindingCards, CardReply, CardRequest, CardState,
};
use std::{collections::VecDeque, sync::Mutex};

const ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../plexus-module/tests/fixtures/cingulate-consent-requester/vectors/manifest-binding-v1/"
);

fn vector(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("{ROOT}{name}.json")).unwrap()).unwrap()
}
fn proposal() -> Proposal {
    serde_json::from_value(vector("vault-samples")["samples"]["propose.reply"]["result"].clone())
        .unwrap()
}

#[derive(Default)]
struct Route {
    calls: Mutex<Vec<(String, Value)>>,
    replies: Mutex<VecDeque<Value>>,
    refusal: Mutex<Option<String>>,
}
impl ElicitationRoute for Route {
    fn call_scoped(
        &self,
        _: &CallScope,
        _: &str,
        _: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        panic!("manifest cards must never carry an agent/session scope")
    }
    fn call_unscoped(
        &self,
        method: &str,
        params: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        self.calls.lock().unwrap().push((method.into(), params));
        if let Some(code) = self.refusal.lock().unwrap().clone() {
            return Err(ElicitationCallError::Refused {
                code,
                message: "fixture refusal".into(),
            });
        }
        Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("fixture reply"))
    }
}

#[test]
fn card_filing_and_repeat_match_the_closed_unscoped_producer_requests() {
    let route = Arc::new(Route::default());
    for name in ["filer-request", "filer-request-repeat"] {
        route
            .replies
            .lock()
            .unwrap()
            .push_back(vector(name)["reply"]["result"].clone());
    }
    let cards = ConsentCards::new(route.clone());
    let proposal = proposal();
    let handle = crate::storage::github_store::GithubHandle {
        app_handle_id: "plex-alfonso".into(),
        agent_id: "agent_4444444444444444".into(),
        app_id: 4617236,
        installation_id: None,
        credential_reference: "github_app:plex-alfonso".into(),
        credential_generation: 1,
        status: "enabled".into(),
        proven_at: None,
        connection_principal: "direct".into(),
        connection_id: "bot".into(),
    };
    assert_eq!(
        cards.manifest_binding_card(CardRequest::Available).unwrap(),
        CardReply::Available
    );
    for name in ["filer-request", "filer-request-repeat"] {
        assert_eq!(
            cards
                .manifest_binding_card(CardRequest::File {
                    handle: &handle,
                    proposal: &proposal
                })
                .unwrap(),
            CardReply::Filed("el_1".into())
        );
        let (method, params) = route.calls.lock().unwrap().last().unwrap().clone();
        assert_eq!(method, vector(name)["method"]);
        assert_eq!(params, vector(name)["params"]);
        assert_eq!(params.as_object().unwrap().len(), 2);
        assert!(params.get("expires_at_ms").is_none());
        assert!(params.get("expires_in_ms").is_none());
    }
    *route.refusal.lock().unwrap() = Some("elicitation_request_conflict".into());
    assert_eq!(
        cards
            .manifest_binding_card(CardRequest::File {
                handle: &handle,
                proposal: &proposal
            })
            .unwrap(),
        CardReply::Conflict
    );
}

#[test]
fn get_and_await_decode_allowed_declined_and_expired_samples() {
    let proposal = proposal();
    for (suffix, state) in [
        ("allowed", CardState::Approved),
        ("declined", CardState::Declined),
        ("expired", CardState::Expired),
    ] {
        for method in ["get", "await"] {
            let sample = vector(&format!("filer-{method}-{suffix}"));
            let route = Arc::new(Route::default());
            route
                .replies
                .lock()
                .unwrap()
                .push_back(sample["reply"]["result"].clone());
            let cards = ConsentCards::new(route.clone());
            let request = if method == "get" {
                CardRequest::Get {
                    card_id: "el_1",
                    statement_b64url: &proposal.statement_b64url,
                }
            } else {
                CardRequest::Await {
                    card_id: "el_1",
                    statement_b64url: &proposal.statement_b64url,
                    timeout_ms: sample["params"]["timeout_ms"].as_u64().unwrap(),
                }
            };
            assert_eq!(
                cards.manifest_binding_card(request).unwrap(),
                CardReply::State(state)
            );
            assert_eq!(
                route.calls.lock().unwrap()[0],
                (
                    sample["method"].as_str().unwrap().to_owned(),
                    sample["params"].clone()
                )
            );
        }
    }
}

#[test]
fn unscoped_withdraw_accepts_repeat_and_already_settled_cards() {
    let mut withdrawn: Value = serde_json::from_slice(
        &std::fs::read(format!("{ROOT}../consent-requester-v1/withdraw-reply.json")).unwrap(),
    )
    .unwrap();
    withdrawn["result"]["kind"] = json!("manifest_binding");
    withdrawn["result"]["elicitation_id"] = json!("el_1");
    let withdrawn = withdrawn["result"].clone();
    let route = Arc::new(Route::default());
    route.replies.lock().unwrap().extend([
        withdrawn.clone(),
        withdrawn,
        vector("filer-get-allowed")["reply"]["result"].clone(),
        vector("filer-get-declined")["reply"]["result"].clone(),
        vector("filer-get-expired")["reply"]["result"].clone(),
    ]);
    for _ in 0..5 {
        let cards = ConsentCards::new(route.clone());
        assert_eq!(
            cards
                .manifest_binding_card(CardRequest::Withdraw { card_id: "el_1" })
                .unwrap(),
            CardReply::Withdrawn
        );
    }
    assert_eq!(
        *route.calls.lock().unwrap(),
        vec![("consent.withdraw".into(), json!({"elicitation_id":"el_1"})); 5]
    );
    *route.refusal.lock().unwrap() = Some("route_closed".into());
    assert_eq!(
        ConsentCards::new(route).manifest_binding_card(CardRequest::Withdraw { card_id: "el_1" }),
        Err("route_closed".into())
    );
}

#[test]
fn unscoped_withdraw_rejects_mismatched_or_unsettled_records() {
    for (field, value) in [
        ("elicitation_id", json!("other")),
        ("kind", json!("consent")),
        ("state", json!("pending")),
    ] {
        let route = Arc::new(Route::default());
        let mut record = vector("filer-get-expired")["reply"]["result"].clone();
        record[field] = value;
        route.replies.lock().unwrap().push_back(record);
        assert_eq!(
            ConsentCards::new(route)
                .manifest_binding_card(CardRequest::Withdraw { card_id: "el_1" }),
            Err("manifest_binding_card_reply_invalid".into())
        );
    }
}

#[test]
fn get_and_await_decode_withdrawn_cards_after_a_lost_reply() {
    let proposal = proposal();
    for await_reply in [false, true] {
        let mut record = vector("filer-get-expired")["reply"]["result"].clone();
        record["state"] = json!("withdrawn");
        let route = Arc::new(Route::default());
        route.replies.lock().unwrap().push_back(record);
        let request = if await_reply {
            CardRequest::Await {
                card_id: "el_1",
                statement_b64url: &proposal.statement_b64url,
                timeout_ms: 0,
            }
        } else {
            CardRequest::Get {
                card_id: "el_1",
                statement_b64url: &proposal.statement_b64url,
            }
        };
        assert_eq!(
            ConsentCards::new(route)
                .manifest_binding_card(request)
                .unwrap(),
            CardReply::State(CardState::Withdrawn)
        );
    }
}

#[test]
fn inconsistent_or_unbound_answer_records_are_never_used() {
    let statement = proposal().statement_b64url;
    let allowed = vector("filer-get-allowed")["reply"]["result"].clone();
    for (field, value) in [
        ("kind", json!("consent")),
        ("elicitation_id", json!("other")),
        ("answered_choice_id", json!("decline")),
    ] {
        let mut bad = allowed.clone();
        bad[field] = value;
        assert!(manifest_binding_answer(bad, "el_1", &statement).is_err());
    }
    let mut bad = allowed.clone();
    bad["manifest_binding_answer"]["statement_sha256"] = json!("0".repeat(64));
    assert!(manifest_binding_answer(bad, "el_1", &statement).is_err());
    let mut bad = allowed.clone();
    bad["manifest_binding"]["repo"] = json!("Other/Repo");
    assert!(manifest_binding_answer(bad, "el_1", &statement).is_err());
    let mut bad = allowed;
    bad["manifest_binding_answer"]["envelope_sha256"] = Value::Null;
    assert!(manifest_binding_answer(bad, "el_1", &statement).is_err());
    let mut bad = vector("filer-get-declined")["reply"]["result"].clone();
    bad["manifest_binding_answer"]["envelope_sha256"] = json!("0".repeat(64));
    assert!(manifest_binding_answer(bad, "el_1", &statement).is_err());
    let mut bad = vector("filer-get-expired")["reply"]["result"].clone();
    bad["answered_choice_id"] = json!("allow");
    assert!(manifest_binding_answer(bad, "el_1", &statement).is_err());
}

#[test]
fn manifest_card_corpus_is_byte_pinned() {
    use sha2::{Digest, Sha256};
    let sums = std::fs::read_to_string(format!("{ROOT}SHA256SUMS")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(sums.as_bytes())),
        "e2e453876167a4f192be76c0a5768c0ae51333b3306d69ed514d92390157f35c"
    );
    let mut count = 0;
    for line in sums.lines() {
        let (hash, file) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(format!("{ROOT}{file}")).unwrap();
        assert_eq!(hex::encode(Sha256::digest(bytes)), hash, "{file}");
        count += 1;
    }
    assert_eq!(count, 15);
}
