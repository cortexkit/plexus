use super::*;
use crate::permissions::list_with_scope_reader;
use crate::scope::{ScopeDescription, ScopeReadError};
use crate::test_scratch::Scratch;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use rusqlite::params;
use std::sync::Mutex;

fn fixture() -> (Scratch, StorageDescriptor, PlexusStore) {
    let scratch = Scratch::directory("federated-permissions-list");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "permissions-list".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).unwrap();
    (scratch, descriptor, store)
}

fn sample_rows(text: &str) -> Vec<Value> {
    let fixture: Value = serde_json::from_str(text).unwrap();
    fixture["reply"]["grants"]
        .as_array()
        .or_else(|| fixture["reply"]["modules"][0]["grants"].as_array())
        .unwrap()
        .clone()
}

const HOLDERS: &str = include_str!(
    "../../../plexus-module/tests/fixtures/permissions-federated-v1/federated-holders.json"
);
const NAMED: &str = include_str!(
    "../../../plexus-module/tests/fixtures/permissions-federated-v1/federated-holders-named.json"
);
const DENY: &str = include_str!("../../../plexus-module/tests/fixtures/permissions-federated-v1/provider-list-federated-deny.json");

fn seed(store: &PlexusStore, sample: &Value, id: &str, owner: &str, subject: &str, scope: &str) {
    let holder = &sample["holder"];
    let raw_claim = holder.get("claim").cloned();
    let claim: Option<RemoteClaim> = raw_claim
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .unwrap();
    let canonical = canonicalize_claim(claim.as_ref()).unwrap();
    store.inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO federated_rows
            (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,
             owner_principal,subject,scope,claim_json,peer_name,effect,granted_at_ms,card_ref,card_refs_json)
            VALUES (?1,?2,?3,'computer',?4,?5,?6,?7,?8,?9,?10,'Juniper',?11,?12,?13,?14)",
            params![id,holder["peer_fingerprint"].as_str().unwrap(),holder["pairing_id"].as_str().unwrap(),
                holder["selector"].as_str().unwrap(),canonical.claim_kind,canonical.canonical_claim_identity,
                owner,subject,scope,raw_claim.map(|v| v.to_string()),sample["effect"].as_str().unwrap_or("allow"),
                sample["granted_at_ms"].as_i64().unwrap(),sample["card_ref"].as_str().unwrap(),
                json!([sample["card_ref"]]).to_string()])?;
        Ok(())
    }).unwrap();
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
        calls: Mutex::new(vec![]),
    }
}
fn list(store: &PlexusStore, reader: &dyn ScopeReader) -> Result<Vec<Value>, ListError> {
    list_with_scope_reader(store, Some(reader), None, 1_060_000)
}
fn shape(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), shape(value)))
                .collect(),
        ),
        Value::Array(_) => json!("array"),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("boolean"),
        Value::Null => Value::Null,
    }
}

#[test]
fn list_rows_match_every_vendored_holder_and_deny_shape_and_label() {
    for text in [HOLDERS, NAMED, DENY] {
        for sample in sample_rows(text) {
            let (_scratch, _, store) = fixture();
            seed(&store, &sample, "plxf_sample", "", "web_search", "read");
            let result = list(&store, &reader(ScopeStatus::Live, true, true)).unwrap();
            assert_eq!(result.len(), 1);
            let row = &result[0];
            assert_eq!(shape(row), shape(&sample));
            assert_eq!(row["holder"], sample["holder"]);
            assert_eq!(row["effect"], sample["effect"]);
            assert_eq!(row["card_ref"], sample["card_ref"]);
            assert_eq!(row["granted_at_ms"], sample["granted_at_ms"]);
        }
    }
}

#[test]
fn list_rechecks_names_and_cuts_label_at_eighty_scalars() {
    for (claim, expected) in [
        (
            json!({"kind":"agent","agent_id":"Sage","agent_name":"bad\nname"}),
            "Juniper · Sage",
        ),
        (
            json!({"kind":"agent","agent_id":"Sage","agent_name":"bad\u{202e}name"}),
            "Juniper · Sage",
        ),
        (
            json!({"kind":"agent","agent_id":"Sage","agent_name":"🌳".repeat(81)}),
            "Juniper · Sage",
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),"agent_name":"Remote Sage"}),
            "Juniper · worker",
        ),
        (
            json!({"kind":"flow","flow_id":"Morning-digest","flow_version":3,"flow_install_id":"install","flow_code_hash":"c".repeat(64),"flow_name":""}),
            "Juniper · flow Morning-digest v3",
        ),
    ] {
        let (_scratch, _, store) = fixture();
        let mut sample = sample_rows(NAMED).remove(0);
        sample["holder"]["claim"] = claim;
        seed(&store, &sample, "plxf_name", "", "web_search", "read");
        let rows = list(&store, &reader(ScopeStatus::Live, true, true)).unwrap();
        assert_eq!(rows[0]["holder"]["label"], expected);
        assert!(rows[0]["holder"]["claim"].get("agent_name").is_none());
        assert!(rows[0]["holder"]["claim"].get("flow_name").is_none());
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute("UPDATE federated_rows SET peer_name=?1", ["🌳".repeat(76)])
            })
            .unwrap();
        let rows = list(&store, &reader(ScopeStatus::Live, true, true)).unwrap();
        let full = format!(
            "{} · {}",
            "🌳".repeat(76),
            expected.strip_prefix("Juniper · ").unwrap()
        );
        assert_eq!(
            rows[0]["holder"]["label"],
            full.chars().take(80).collect::<String>()
        );
    }
}

fn count(store: &PlexusStore, table: &str) -> i64 {
    store
        .inner
        .with_read(|conn| {
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
        })
        .unwrap()
}

#[test]
fn list_liveness_table_deletes_only_confirmed_ended_and_journals() {
    for status in [ScopeStatus::Live, ScopeStatus::Ended, ScopeStatus::NotLive] {
        for synced in [false, true] {
            for configured in [false, true] {
                let (scratch, descriptor, store) = fixture();
                seed(
                    &store,
                    &sample_rows(HOLDERS)[0],
                    "plxf_live",
                    "",
                    "web_search",
                    "read",
                );
                let read = reader(status, synced, configured);
                let result = list(&store, &read);
                let ended = status == ScopeStatus::Ended
                    || (status == ScopeStatus::NotLive && synced && configured);
                match status {
                    ScopeStatus::Live => assert_eq!(result.unwrap().len(), 1),
                    _ if ended => assert!(result.unwrap().is_empty()),
                    _ => assert!(matches!(result, Err(ListError::LivenessUnavailable))),
                }
                assert_eq!(
                    read.calls.lock().unwrap().as_slice(),
                    &[(
                        "reserved:callosum".into(),
                        format!("fed-base:{}:pairing-invented-1", "a".repeat(32))
                    )]
                );
                assert_eq!(count(&store, "federated_rows"), i64::from(!ended));
                assert_eq!(count(&store, "federated_processed_cards"), i64::from(ended));
                let journal =
                    std::fs::read_to_string(scratch.join(crate::federated_journal::NAME)).unwrap();
                assert_eq!(!journal.is_empty(), ended);
                if ended {
                    assert!(journal.contains("plxf_live") && journal.contains("el_1"));
                }
                drop(store);
                let reopened = PlexusStore::open(&descriptor).unwrap();
                assert_eq!(count(&reopened, "federated_rows"), i64::from(!ended));
            }
        }
    }
    let (_scratch, _, store) = fixture();
    seed(
        &store,
        &sample_rows(HOLDERS)[0],
        "plxf_error",
        "",
        "web_search",
        "read",
    );
    let read = Reader {
        answer: Err(ScopeReadError("offline".into())),
        calls: Mutex::new(vec![]),
    };
    assert!(matches!(
        list(&store, &read),
        Err(ListError::LivenessUnavailable)
    ));
    assert!(matches!(
        list_with_scope_reader(&store, None, None, 0),
        Err(ListError::LivenessUnavailable)
    ));
    assert_eq!(count(&store, "federated_rows"), 1);
}

#[test]
fn list_skips_describe_without_federated_rows_or_with_agent_filter() {
    let (_scratch, _, store) = fixture();
    let read = reader(ScopeStatus::Ended, true, true);
    assert!(list(&store, &read).unwrap().is_empty());
    seed(
        &store,
        &sample_rows(HOLDERS)[0],
        "plxf_filtered",
        "",
        "web_search",
        "read",
    );
    assert!(list_with_scope_reader(&store, Some(&read), Some("Sage"), 0)
        .unwrap()
        .is_empty());
    assert!(read.calls.lock().unwrap().is_empty());
    assert_eq!(count(&store, "federated_rows"), 1);
}

#[test]
fn list_labels_cover_connection_scopes_searches_denials_and_app_name_fallback() {
    let (_scratch, _, store) = fixture();
    store.inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO connections (connection_id,principal,app_key,status,created_at_ms,updated_at_ms) VALUES ('conn','direct','mock','active',0,0)", [])?;
        Ok(())
    }).unwrap();
    for (name, display) in [(" Mock service ", "Mock service"), ("", "mock")] {
        let manifest = crate::ingest_value(json!({
            "schema_version":1,"key":"mock","name":name,"description":"list fixture",
            "reuse_path":"mcp_direct","reuse_rationale":"in-process test","tier":"S1",
            "transport":{"kind":"mcp_remote","url":"https://example.invalid/mcp"},
            "auth":{"mode":"api_key"},
            "credential_bindings":[{"ref_role":"api_key","placement":"header","key":"Authorization","prefix":"Bearer ","required":true}],
            "resource_filters":{"required":[],"optional":[],"write_enabling":[]},
            "actions_baseline":[{"name":"list_items","risk":"read"}],
            "defaults":{"ask_first_risk":["write","destructive"],"rate_limit":{"calls_per_min":30}},
            "availability":"ga"
        })).unwrap();
        store
            .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
            .unwrap();
        for (owner, subject, scope, expected_subject, expected_scope) in [
            (
                "direct",
                "conn",
                "read",
                display,
                format!("read from {display}"),
            ),
            (
                "direct",
                "conn",
                "write",
                display,
                format!("make changes in {display}"),
            ),
            (
                "",
                "web_search",
                "read",
                "Web search",
                "search the web".into(),
            ),
            (
                "",
                "code_search",
                "read",
                "Code search",
                "search public code".into(),
            ),
        ] {
            for deny in [false, true] {
                let mut sample = sample_rows(HOLDERS).remove(0);
                if deny {
                    sample["effect"] = json!("deny");
                }
                seed(&store, &sample, "plxf_labels", owner, subject, scope);
                let rows = list(&store, &reader(ScopeStatus::Live, true, true)).unwrap();
                assert_eq!(rows[0]["subject_label"], expected_subject);
                assert_eq!(rows[0]["scope"], scope);
                assert_eq!(
                    rows[0]["scope_label"],
                    if deny {
                        format!("never {expected_scope}")
                    } else {
                        expected_scope.clone()
                    }
                );
                assert_eq!(rows[0].get("effect"), deny.then_some(&json!("deny")));
                store.delete_federated_row("plxf_labels").unwrap();
            }
        }
    }
}

#[test]
fn list_describes_distinct_pairs_and_deletes_ended_even_when_another_is_unknown() {
    struct Mixed {
        calls: Mutex<Vec<String>>,
    }
    impl ScopeReader for Mixed {
        fn describe(&self, _: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
            self.calls.lock().unwrap().push(scope_ref.into());
            if scope_ref.ends_with(":a-unknown") {
                Err(ScopeReadError("offline".into()))
            } else {
                reader(ScopeStatus::Ended, true, true).answer
            }
        }
    }
    let (scratch, descriptor, store) = fixture();
    let mut sample = sample_rows(HOLDERS).remove(0);
    for (id, pairing, fingerprint, subject) in [
        ("plxf_unknown", "a-unknown", "a".repeat(32), "web_search"),
        ("plxf_ended1", "z-ended", "a".repeat(32), "web_search"),
        ("plxf_ended2", "z-ended", "a".repeat(32), "code_search"),
        ("plxf_other_peer", "z-ended", "b".repeat(32), "web_search"),
    ] {
        sample["holder"]["pairing_id"] = json!(pairing);
        sample["holder"]["peer_fingerprint"] = json!(fingerprint);
        seed(&store, &sample, id, "", subject, "read");
    }
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "INSERT INTO federated_processed_cards VALUES ('el_keep')",
                [],
            )
        })
        .unwrap();
    let read = Mixed {
        calls: Mutex::new(vec![]),
    };
    assert!(matches!(
        list(&store, &read),
        Err(ListError::LivenessUnavailable)
    ));
    assert_eq!(read.calls.lock().unwrap().len(), 3);
    assert_eq!(count(&store, "federated_rows"), 1);
    assert_eq!(count(&store, "federated_processed_cards"), 2);
    let journal = std::fs::read_to_string(scratch.join(crate::federated_journal::NAME)).unwrap();
    assert_eq!(journal.lines().count(), 3);
    drop(store);
    let reopened = PlexusStore::open(&descriptor).unwrap();
    assert_eq!(count(&reopened, "federated_rows"), 1);
    assert_eq!(count(&reopened, "federated_processed_cards"), 2);
}

#[test]
fn list_describe_releases_store_fence_and_journal_failure_fails_the_list() {
    struct RevokingReader<'a>(&'a PlexusStore);
    impl ScopeReader for RevokingReader<'_> {
        fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
            self.0
                .delete_federated_row("plxf_revoke_during_describe")
                .unwrap();
            reader(ScopeStatus::Live, true, true).answer
        }
    }
    let (scratch, _, store) = fixture();
    let sample = sample_rows(HOLDERS).remove(0);
    seed(
        &store,
        &sample,
        "plxf_revoke_during_describe",
        "",
        "web_search",
        "read",
    );
    list(&store, &RevokingReader(&store)).unwrap();
    assert_eq!(count(&store, "federated_rows"), 0);
    seed(
        &store,
        &sample,
        "plxf_bad_journal",
        "",
        "web_search",
        "read",
    );
    let journal = scratch.join(crate::federated_journal::NAME);
    std::fs::remove_file(&journal).unwrap();
    std::fs::create_dir(&journal).unwrap();
    assert!(matches!(
        list(&store, &reader(ScopeStatus::Ended, true, true)),
        Err(ListError::Store(_))
    ));
    assert_eq!(count(&store, "federated_rows"), 1);
}

#[test]
fn listed_mint_card_and_time_survive_absorbing_another_standing_answer() {
    use crate::federated::card::{CallBinding, CallerIdentity, Record, Scope, State};
    use crate::federated::FederatedCaller;
    use crate::storage::federated_store::{
        cards,
        commit::{Answer, CommitInput, CommitOutcome},
    };
    use subc_protocol::scope::{FederatedAttributes, FederatedPeerClass};
    let (_scratch, _, store) = fixture();
    let sample = sample_rows(HOLDERS).remove(0);
    seed(&store, &sample, "plxf_mint", "", "web_search", "read");
    let mut attributes = FederatedAttributes::new(
        FederatedPeerClass::Computer,
        "a".repeat(32),
        "pairing-invented-1".into(),
        "Juniper".into(),
    );
    attributes.remote_claim =
        Some(serde_json::from_value(sample["holder"]["claim"].clone()).unwrap());
    let caller = FederatedCaller::from_attributes(attributes).unwrap();
    let mut record = Record {
        id: "record_second".into(),
        binding: CallBinding {
            caller: CallerIdentity {
                peer_fingerprint: "a".repeat(32),
                pairing_id: "pairing-invented-1".into(),
                peer_class: "computer".into(),
                claim_kind: caller.claim.claim_kind.into(),
                canonical_claim_identity: caller.claim.canonical_claim_identity.clone(),
            },
            owner_principal: "".into(),
            subject: "web_search".into(),
            action: "web_search".into(),
            args_digest: "digest_second".into(),
        },
        selector: "exact_claim".into(),
        scope: Scope::Read,
        filed_scope: json!({}),
        schema_hash: None,
        state: State::Pending,
        card_ref: None,
        standing_choices_offered: true,
    };
    store
        .inner
        .with_conn_fenced(|conn| {
            cards::insert_on_conn(conn, &record)?;
            cards::attach_card_ref_on_conn(conn, &record.id, "el_second")
        })
        .unwrap();
    record.card_ref = Some("el_second".into());
    let read = reader(ScopeStatus::Live, true, true);
    let before = list(&store, &read).unwrap();
    assert!(matches!(
        store
            .commit_federated_standing_answer(
                Some(&read),
                &CommitInput {
                    caller: &caller,
                    record: &record,
                    answer: Answer::AllowAlways,
                    standing_choices_offered: true,
                    now_ms: 2_000_000
                }
            )
            .unwrap(),
        CommitOutcome::Committed { .. }
    ));
    assert_eq!(list(&store, &read).unwrap(), before);
    let refs: String = store
        .inner
        .with_read(|conn| {
            conn.query_row("SELECT card_refs_json FROM federated_rows", [], |row| {
                row.get(0)
            })
        })
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&refs).unwrap(),
        json!(["el_1", "el_second"])
    );
}
