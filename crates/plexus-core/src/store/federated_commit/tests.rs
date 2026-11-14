use super::*;
use crate::federated::card::{CallBinding, Scope};
use crate::scope::{ScopeDescription, ScopeReadError};
use crate::test_scratch::Scratch;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use serde_json::{json, Value};
use std::sync::Mutex;
use subc_protocol::scope::{FederatedAttributes, FederatedPeerClass};

fn fixture() -> (Scratch, StorageDescriptor, PlexusStore) {
    let scratch = Scratch::directory("federated-standing-commit");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "federated-standing-commit".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).unwrap();
    (scratch, descriptor, store)
}

fn caller(claim: Option<Value>) -> FederatedCaller {
    let mut attributes = FederatedAttributes::new(
        FederatedPeerClass::Computer,
        "a".repeat(32),
        "pairing".into(),
        "Juniper".into(),
    );
    attributes.remote_claim = claim.map(|value| serde_json::from_value(value).unwrap());
    FederatedCaller::from_attributes(attributes).unwrap()
}

fn card(store: &PlexusStore, caller: &FederatedCaller, id: &str) -> Record {
    let mut record = Record {
        id: id.into(),
        binding: CallBinding {
            caller: CallerIdentity {
                peer_fingerprint: caller.attributes.peer_fingerprint.clone(),
                pairing_id: caller.attributes.pairing_id.clone(),
                peer_class: "computer".into(),
                claim_kind: caller.claim.claim_kind.into(),
                canonical_claim_identity: caller.claim.canonical_claim_identity.clone(),
            },
            owner_principal: "direct".into(),
            subject: "conn".into(),
            action: "read".into(),
            args_digest: format!("sha256:{id}"),
        },
        selector: if caller.claim.claim_kind.is_empty() {
            "claimless"
        } else {
            "exact_claim"
        }
        .into(),
        scope: Scope::Read,
        filed_scope: json!({"owner":"reserved:callosum","ref":"filed","scope_epoch":3}),
        schema_hash: Some("schema-v1".into()),
        state: State::Pending,
        card_ref: None,
    };
    store
        .inner
        .with_conn_fenced(|tx| {
            cards::insert_on_conn(tx, &record)?;
            cards::attach_card_ref_on_conn(tx, id, &format!("el_{id}"))
        })
        .unwrap();
    record.card_ref = Some(format!("el_{id}"));
    record
}

struct Reader {
    answer: Result<ScopeDescription, ScopeReadError>,
    calls: Mutex<Vec<(String, String)>>,
}
impl ScopeReader for Reader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        self.calls
            .lock()
            .unwrap()
            .push((owner.into(), scope_ref.into()));
        self.answer.clone()
    }
}
fn reader(status: ScopeStatus, synced: bool, configured: bool) -> Reader {
    Reader {
        answer: Ok(ScopeDescription {
            status,
            owner_synced: synced,
            owner_configured: configured,
            live: None,
            parent: None,
            expires_at_ms: None,
        }),
        calls: Mutex::new(Vec::new()),
    }
}
fn live() -> Reader {
    reader(ScopeStatus::Live, true, true)
}
fn commit(
    store: &PlexusStore,
    reader: Option<&dyn ScopeReader>,
    caller: &FederatedCaller,
    record: &Record,
    answer: Answer,
    now_ms: i64,
) -> Result<CommitOutcome, CommitFailure> {
    store.commit_federated_standing_answer(
        reader,
        &CommitInput {
            caller,
            record,
            answer,
            now_ms,
            standing_choices_offered: true,
        },
    )
}
fn committed(result: Result<CommitOutcome, CommitFailure>, expected: Effect) -> String {
    match result.unwrap() {
        CommitOutcome::Committed { row_id, effect } => {
            assert_eq!(effect, expected);
            row_id
        }
        other => panic!("expected committed, got {other:?}"),
    }
}
fn count(store: &PlexusStore, table: &str) -> i64 {
    store
        .inner
        .with_read(|db| {
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
        })
        .unwrap()
}
fn state(store: &PlexusStore, id: &str) -> State {
    store
        .inner
        .with_conn_fenced(|tx| Ok(cards::read_on_conn(tx, id)?.unwrap().state))
        .unwrap()
}
fn processed(store: &PlexusStore) -> Vec<String> {
    store
        .inner
        .with_read(|db| {
            db.prepare("SELECT card_ref FROM federated_processed_cards ORDER BY card_ref")?
                .query_map([], |row| row.get(0))?
                .collect()
        })
        .unwrap()
}
fn row(store: &PlexusStore, id: &str) -> Value {
    store.inner.with_read(|db| db.query_row(
        "SELECT peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,
         owner_principal,subject,scope,claim_json,peer_name,effect,granted_at_ms,card_ref,card_refs_json
         FROM federated_rows WHERE id=?1", [id], |r| Ok(json!({
            "peer_fingerprint":r.get::<_,String>(0)?,"pairing_id":r.get::<_,String>(1)?,
            "peer_class":r.get::<_,String>(2)?,"selector":r.get::<_,String>(3)?,
            "claim_kind":r.get::<_,String>(4)?,"identity":r.get::<_,String>(5)?,
            "owner_principal":r.get::<_,String>(6)?,"subject":r.get::<_,String>(7)?,
            "scope":r.get::<_,String>(8)?,"claim":r.get::<_,Option<String>>(9)?.map(|s|serde_json::from_str::<Value>(&s).unwrap()),
            "peer_name":r.get::<_,String>(10)?,"effect":r.get::<_,String>(11)?,
            "granted_at_ms":r.get::<_,i64>(12)?,"card_ref":r.get::<_,String>(13)?,
            "card_refs":serde_json::from_str::<Value>(&r.get::<_,String>(14)?).unwrap(),
        })))).unwrap()
}

#[test]
fn only_explicit_standing_choices_mint_and_default_outcomes_do_nothing() {
    let (_scratch, _descriptor, store) = fixture();
    let caller = caller(None);
    let r = card(&store, &caller, "default");
    let reader = live();
    for answer in [
        Answer::AllowOnce,
        Answer::DenyOnce,
        Answer::Expired,
        Answer::TimedOut,
        Answer::Withdrawn,
        Answer::Dismissed,
    ] {
        assert_eq!(answer.standing_effect(), None);
        assert_eq!(
            answer.choice_id(),
            if answer == Answer::AllowOnce {
                "allow_once"
            } else {
                "deny_once"
            }
        );
        assert_eq!(
            commit(&store, Some(&reader), &caller, &r, answer, 1).unwrap(),
            CommitOutcome::PerCall(answer)
        );
        assert_eq!(count(&store, "federated_rows"), 0);
        assert!(processed(&store).is_empty());
        assert_eq!(state(&store, &r.id), State::Pending);
    }
    assert!(reader.calls.lock().unwrap().is_empty());
    for (answer, effect, text) in [
        (Answer::AllowAlways, Effect::Allow, "allow"),
        (Answer::DenyAlways, Effect::Deny, "deny"),
    ] {
        let r = card(&store, &caller, text);
        let id = committed(
            commit(&store, Some(&reader), &caller, &r, answer, 42),
            effect,
        );
        assert_eq!(row(&store, &id)["effect"], text);
        assert_eq!(state(&store, &r.id), State::Committed);
    }
}

#[test]
fn minted_fields_are_normalized_from_stamp_with_only_exact_or_claimless_selectors() {
    let claims = [
        None,
        Some(json!({"kind":"agent","agent_id":"agent","agent_name":"invalid\nname"})),
        Some(
            json!({"kind":"flow","flow_id":"flow","flow_version":2,"flow_install_id":"install",
            "flow_code_hash":"b".repeat(64),"flow_name":"Flow Name"}),
        ),
    ];
    for claim in claims {
        let (_scratch, _descriptor, store) = fixture();
        let caller = caller(claim.clone());
        let r = card(&store, &caller, "mint");
        let id = committed(
            commit(&store, Some(&live()), &caller, &r, Answer::AllowAlways, 42),
            Effect::Allow,
        );
        assert!(id.starts_with("plxf_"));
        let mut expected_claim = claim;
        if let Some(claim) = expected_claim.as_mut().filter(|v| v["kind"] == "agent") {
            claim.as_object_mut().unwrap().remove("agent_name");
        }
        let (kind, identity) = match expected_claim.as_ref().map(|c| c["kind"].as_str().unwrap()) {
            None => ("", String::new()),
            Some("agent") => ("agent", r#"{"agent_id":"agent"}"#.into()),
            _ => (
                "flow",
                format!(
                    r#"{{"flow_code_hash":"{}","flow_id":"flow","flow_install_id":"install","flow_version":2}}"#,
                    "b".repeat(64)
                ),
            ),
        };
        assert_eq!(
            row(&store, &id),
            json!({"peer_fingerprint":"a".repeat(32),"pairing_id":"pairing",
            "peer_class":"computer","selector":if kind.is_empty(){"claimless"}else{"exact_claim"},
            "claim_kind":kind,"identity":identity,"owner_principal":"direct","subject":"conn","scope":"read",
            "claim":expected_claim,"peer_name":"Juniper","effect":"allow","granted_at_ms":42,
            "card_ref":"el_mint","card_refs":["el_mint"]})
        );
        assert_eq!(processed(&store), ["el_mint"]);
        assert_eq!(state(&store, &r.id), State::Committed);
        assert_eq!(
            commit(&store, Some(&live()), &caller, &r, Answer::AllowAlways, 99).unwrap(),
            CommitOutcome::Reask
        );
        assert_eq!(count(&store, "federated_rows"), 1);
        assert_eq!(state(&store, &r.id), State::Retired);
        assert_eq!(row(&store, &id)["granted_at_ms"], 42);
    }
}

#[test]
fn commit_liveness_table_never_mints_deletes_or_consumes_on_non_live_rows() {
    for answer in [Answer::AllowAlways, Answer::DenyAlways] {
        let mut cases = Vec::new();
        for status in [ScopeStatus::Live, ScopeStatus::Ended, ScopeStatus::NotLive] {
            for synced in [false, true] {
                for configured in [false, true] {
                    let expected = match status {
                        ScopeStatus::Live => None,
                        ScopeStatus::Ended => Some("federated_pairing_ended"),
                        ScopeStatus::NotLive if synced && configured => {
                            Some("federated_pairing_ended")
                        }
                        _ => Some("federated_liveness_unavailable"),
                    };
                    cases.push((reader(status, synced, configured), expected));
                }
            }
        }
        cases.push((
            Reader {
                answer: Err(ScopeReadError("offline".into())),
                calls: Mutex::new(Vec::new()),
            },
            Some("federated_liveness_unavailable"),
        ));
        for (reader, expected) in cases {
            let (_scratch, _descriptor, store) = fixture();
            let caller = caller(None);
            let first = card(&store, &caller, "first");
            let opposite = if answer == Answer::AllowAlways {
                Answer::DenyAlways
            } else {
                Answer::AllowAlways
            };
            let original = committed(
                commit(&store, Some(&live()), &caller, &first, opposite, 1),
                opposite.standing_effect().unwrap(),
            );
            let before = row(&store, &original);
            let pending = card(&store, &caller, "pending");
            let result = commit(&store, Some(&reader), &caller, &pending, answer, 2);
            if let Some(code) = expected {
                let error = result.unwrap_err();
                assert_eq!(error.denial.reason_code(), code, "{:?}", reader.answer);
                assert_eq!(
                    error.denial.clears_by_waiting(),
                    code == "federated_liveness_unavailable"
                );
                assert_eq!(error.transmission, TransmissionState::NotSent);
                assert_eq!(state(&store, &pending.id), State::Pending);
                assert_eq!(processed(&store), ["el_first"]);
                assert_eq!(row(&store, &original), before);
            } else {
                committed(result, answer.standing_effect().unwrap());
                assert_eq!(state(&store, &pending.id), State::Committed);
            }
            assert_eq!(count(&store, "federated_rows"), 1);
            assert_eq!(
                *reader.calls.lock().unwrap(),
                vec![(
                    "reserved:callosum".into(),
                    format!("fed-base:{}:pairing", "a".repeat(32))
                )]
            );
        }
    }
    let (_scratch, _descriptor, store) = fixture();
    let caller = caller(None);
    let pending = card(&store, &caller, "pending");
    let error = commit(&store, None, &caller, &pending, Answer::AllowAlways, 1).unwrap_err();
    assert_eq!(error.denial.reason_code(), "federated_liveness_unavailable");
    assert_eq!(error.transmission, TransmissionState::NotSent);
    assert!(processed(&store).is_empty());
    assert_eq!(state(&store, &pending.id), State::Pending);
}

#[test]
fn same_effect_absorbs_refs_without_changing_mint_metadata() {
    for answer in [Answer::AllowAlways, Answer::DenyAlways] {
        let (_scratch, _descriptor, store) = fixture();
        let mut caller = caller(Some(
            json!({"kind":"agent","agent_id":"agent","agent_name":"Original"}),
        ));
        let first = card(&store, &caller, "first");
        let second = card(&store, &caller, "second");
        let reader = live();
        let id = committed(
            commit(&store, Some(&reader), &caller, &first, answer, 10),
            answer.standing_effect().unwrap(),
        );
        let mut expected = row(&store, &id);
        assert_eq!(
            state(&store, &second.id),
            State::Pending,
            "another held call keeps waiting"
        );
        caller.attributes.peer_name = "Renamed".into();
        caller.attributes.remote_claim = Some(
            serde_json::from_value(
                json!({"kind":"agent","agent_id":"agent","agent_name":"Renamed"}),
            )
            .unwrap(),
        );
        let reaffirmed = committed(
            commit(&store, Some(&reader), &caller, &second, answer, 20),
            answer.standing_effect().unwrap(),
        );
        assert_eq!(id, reaffirmed);
        expected["card_refs"] = json!(["el_first", "el_second"]);
        assert_eq!(row(&store, &id), expected);
        assert_eq!(processed(&store), ["el_first", "el_second"]);
        assert_eq!(state(&store, &second.id), State::Committed);
        assert_eq!(count(&store, "federated_rows"), 1);
        assert_eq!(
            reader.calls.lock().unwrap().len(),
            2,
            "each commit has its own describe"
        );
        assert_eq!(
            commit(&store, Some(&reader), &caller, &second, answer, 30).unwrap(),
            CommitOutcome::Reask
        );
        assert_eq!(row(&store, &id), expected);
    }
}

#[test]
fn unoffered_selectors_workers_runs_and_changed_bindings_cannot_mint() {
    let claims = [
        Some(json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64)})),
        Some(json!({"kind":"run","agent_id":"agent"})),
    ];
    for claim in claims {
        let (_scratch, _descriptor, store) = fixture();
        let caller = caller(claim);
        let r = card(&store, &caller, "unmintable");
        for answer in [Answer::AllowAlways, Answer::DenyAlways] {
            assert_eq!(
                commit(&store, Some(&live()), &caller, &r, answer, 1)
                    .unwrap_err()
                    .denial
                    .reason_code(),
                "consent_unavailable"
            );
        }
        assert_eq!(count(&store, "federated_rows"), 0);
        assert!(processed(&store).is_empty());
    }
    let (_scratch, _descriptor, store) = fixture();
    let caller = caller(None);
    let r = card(&store, &caller, "unoffered");
    let reader = live();
    let input = CommitInput {
        caller: &caller,
        record: &r,
        answer: Answer::AllowAlways,
        now_ms: 1,
        standing_choices_offered: false,
    };
    assert_eq!(
        store
            .commit_federated_standing_answer(Some(&reader), &input)
            .unwrap_err()
            .denial
            .reason_code(),
        "consent_unavailable"
    );
    let mut all_claims = r.clone();
    all_claims.selector = "all_claims".into();
    assert!(commit(
        &store,
        Some(&reader),
        &caller,
        &all_claims,
        Answer::AllowAlways,
        1
    )
    .is_err());
    assert!(reader.calls.lock().unwrap().is_empty());
    for mutate in [0, 1, 2, 3, 4] {
        let mut changed = r.clone();
        match mutate {
            0 => changed.scope = Scope::Write,
            1 => changed.schema_hash = Some("repinned".into()),
            2 => changed.binding.args_digest = "different".into(),
            3 => changed.binding.action = "other".into(),
            _ => changed.binding.subject = "other".into(),
        }
        assert_eq!(
            commit(
                &store,
                Some(&reader),
                &caller,
                &changed,
                Answer::AllowAlways,
                1
            )
            .unwrap(),
            CommitOutcome::Reask
        );
    }
    assert_eq!(state(&store, &r.id), State::Pending);
    assert_eq!(count(&store, "federated_rows"), 0);
    assert!(processed(&store).is_empty());
}

#[path = "restore_tests.rs"]
mod restore_tests;

#[test]
fn revoke_during_describe_retires_the_answer_instead_of_recreating_authority() {
    struct RevokingReader<'a> {
        store: &'a PlexusStore,
        row_id: String,
    }
    impl ScopeReader for RevokingReader<'_> {
        fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
            // Describe must not hold a `with_conn_fenced` transaction: the
            // revoke needs its own transaction to retire the pending answer
            // before commit can re-read it.
            assert!(self.store.delete_federated_row(&self.row_id).unwrap());
            live().answer
        }
    }
    let (_scratch, _descriptor, store) = fixture();
    let caller = caller(None);
    let first = card(&store, &caller, "first");
    let id = committed(
        commit(
            &store,
            Some(&live()),
            &caller,
            &first,
            Answer::AllowAlways,
            1,
        ),
        Effect::Allow,
    );
    let pending = card(&store, &caller, "pending");
    let reader = RevokingReader {
        store: &store,
        row_id: id,
    };
    assert_eq!(
        commit(
            &store,
            Some(&reader),
            &caller,
            &pending,
            Answer::AllowAlways,
            2
        )
        .unwrap(),
        CommitOutcome::Reask
    );
    assert_eq!(state(&store, &pending.id), State::Retired);
    assert_eq!(count(&store, "federated_rows"), 0);
    assert_eq!(processed(&store), ["el_first", "el_pending"]);
}

#[test]
fn read_write_and_search_subject_keys_are_minted_separately() {
    let (_scratch, _descriptor, store) = fixture();
    let caller = caller(None);
    let mut ids = BTreeSet::new();
    for (id, owner, subject, scope) in [
        ("read", "direct", "web_search", Scope::Read),
        ("write", "direct", "web_search", Scope::Write),
        ("web", "", "web_search", Scope::Read),
        ("code", "", "code_search", Scope::Read),
    ] {
        let mut r = card(&store, &caller, id);
        r.binding.owner_principal = owner.into();
        r.binding.subject = subject.into();
        r.scope = scope;
        store
            .inner
            .with_conn_fenced(|tx| {
                tx.execute(
            "UPDATE federated_card_records SET owner_principal=?2,subject=?3,scope=?4 WHERE id=?1",
            params![id,owner,subject,scope.as_str()],
        )
            })
            .unwrap();
        let row_id = committed(
            commit(&store, Some(&live()), &caller, &r, Answer::AllowAlways, 1),
            Effect::Allow,
        );
        assert_eq!(row(&store, &row_id)["scope"], scope.as_str());
        assert_eq!(row(&store, &row_id)["subject"], subject);
        assert_eq!(row(&store, &row_id)["owner_principal"], owner);
        assert!(ids.insert(row_id));
    }
    assert_eq!(count(&store, "federated_rows"), 4);
}
