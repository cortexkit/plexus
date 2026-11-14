use super::*;
use rusqlite::Connection;
use serde_json::json;

fn database() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::storage::PlexusStore::apply_migrations(&conn).unwrap();
    conn
}

fn record(id: &str) -> Record {
    Record {
        id: id.into(),
        binding: CallBinding {
            caller: CallerIdentity {
                peer_fingerprint: "a".repeat(32),
                pairing_id: "pairing".into(),
                peer_class: "computer".into(),
                claim_kind: "agent".into(),
                canonical_claim_identity: r#"{"agent_id":"agent"}"#.into(),
            },
            owner_principal: "direct".into(),
            subject: "connection".into(),
            action: "list_items".into(),
            args_digest: "sha256:args".into(),
        },
        selector: "exact_claim".into(),
        scope: Scope::Read,
        filed_scope: json!({"owner":"reserved:callosum","ref":"filed","scope_epoch":3}),
        schema_hash: Some("schema-v1".into()),
        state: State::Pending,
        standing_choices_offered: true,
        card_ref: None,
    }
}

#[test]
fn insert_read_and_write_once_attachment_preserve_one_record_per_id() {
    let mut db = database();
    let tx = db.transaction().unwrap();
    let mut record = record("requester-ref");
    insert_on_conn(&tx, &record).unwrap();
    assert_eq!(read_on_conn(&tx, &record.id).unwrap(), Some(record.clone()));
    assert!(insert_on_conn(&tx, &record).is_err());
    assert_eq!(read_on_conn(&tx, "missing").unwrap(), None);
    attach_card_ref_on_conn(&tx, &record.id, "el_card").unwrap();
    record.card_ref = Some("el_card".into());
    assert_eq!(read_on_conn(&tx, &record.id).unwrap(), Some(record.clone()));
    for card_ref in ["el_card", "el_other", ""] {
        assert!(attach_card_ref_on_conn(&tx, &record.id, card_ref).is_err());
        assert_eq!(read_on_conn(&tx, &record.id).unwrap(), Some(record.clone()));
    }
    assert!(attach_card_ref_on_conn(&tx, "missing", "el_new").is_err());
    let mut second = record.clone();
    second.id = "other-record".into();
    assert!(
        insert_on_conn(&tx, &second).is_err(),
        "cannot insert a pre-filed record"
    );
    second.card_ref = None;
    insert_on_conn(&tx, &second).unwrap();
    assert!(
        attach_card_ref_on_conn(&tx, &second.id, "el_card").is_err(),
        "one Cingulate ref cannot belong to two records"
    );
    assert_eq!(read_on_conn(&tx, &second.id).unwrap(), Some(second));
    let locals: i64 = tx
        .query_row("SELECT count(*) FROM action_requests", [], |row| row.get(0))
        .unwrap();
    let processed: i64 = tx
        .query_row(
            "SELECT count(*) FROM federated_processed_cards",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((locals, processed), (0, 0));
    tx.commit().unwrap();
}

#[test]
fn inserts_and_attachments_rollback_with_the_callers_transaction() {
    let mut db = database();
    let record = record("rollback");
    {
        let tx = db.transaction().unwrap();
        insert_on_conn(&tx, &record).unwrap();
        attach_card_ref_on_conn(&tx, &record.id, "el_rollback").unwrap();
        assert!(read_on_conn(&tx, &record.id).unwrap().is_some());
        tx.rollback().unwrap();
    }
    let tx = db.transaction().unwrap();
    assert_eq!(read_on_conn(&tx, &record.id).unwrap(), None);
    insert_on_conn(&tx, &record).unwrap();
    tx.commit().unwrap();
    let tx = db.transaction().unwrap();
    attach_card_ref_on_conn(&tx, &record.id, "el_rollback").unwrap();
    tx.rollback().unwrap();
    let tx = db.transaction().unwrap();
    assert_eq!(read_on_conn(&tx, &record.id).unwrap(), Some(record));
}

#[test]
fn terminal_records_cannot_be_inserted_attached_or_selected_as_pending() {
    let mut db = database();
    let tx = db.transaction().unwrap();
    for state in [
        State::Consumed,
        State::Declined,
        State::Expired,
        State::Withdrawn,
        State::Committed,
        State::Retired,
    ] {
        let mut record = record(state.as_str());
        record.state = state;
        assert!(insert_on_conn(&tx, &record).is_err());
        assert_eq!(read_on_conn(&tx, &record.id).unwrap(), None);
        record.state = State::Pending;
        insert_on_conn(&tx, &record).unwrap();
        tx.execute(
            "UPDATE federated_card_records SET state=?2 WHERE id=?1",
            (&record.id, state.as_str()),
        )
        .unwrap();
        record.state = state;
        assert!(attach_card_ref_on_conn(&tx, &record.id, "el_terminal").is_err());
        assert_eq!(read_on_conn(&tx, &record.id).unwrap(), Some(record.clone()));
        assert_eq!(
            pending_on_conn(
                &tx,
                &record.binding,
                record.scope,
                record.schema_hash.as_deref()
            )
            .unwrap(),
            None
        );
    }
}

#[test]
fn pending_lookup_requires_every_binding_member_scope_and_schema() {
    let mut db = database();
    let tx = db.transaction().unwrap();
    let record = record("pending");
    insert_on_conn(&tx, &record).unwrap();
    let lookup = |binding: &CallBinding, scope, schema| {
        pending_on_conn(&tx, binding, scope, schema).unwrap()
    };
    assert_eq!(
        lookup(&record.binding, Scope::Read, Some("schema-v1")),
        Some(record.clone())
    );
    for index in 0..9 {
        let mut other = record.binding.clone();
        let field = match index {
            0 => &mut other.caller.peer_fingerprint,
            1 => &mut other.caller.pairing_id,
            2 => &mut other.caller.peer_class,
            3 => &mut other.caller.claim_kind,
            4 => &mut other.caller.canonical_claim_identity,
            5 => &mut other.owner_principal,
            6 => &mut other.subject,
            7 => &mut other.action,
            _ => &mut other.args_digest,
        };
        field.push_str(":|\",");
        assert_eq!(
            lookup(&other, Scope::Read, Some("schema-v1")),
            None,
            "member {index}"
        );
    }
    assert_eq!(
        lookup(&record.binding, Scope::Write, Some("schema-v1")),
        None
    );
    assert_eq!(
        lookup(&record.binding, Scope::Read, Some("schema-v2")),
        None
    );
    assert_eq!(lookup(&record.binding, Scope::Read, None), None);
    for (id, action, digest) in [
        ("other-action", "get_item", "sha256:args"),
        ("other-args", "list_items", "sha256:other"),
    ] {
        let mut other = record.clone();
        other.id = id.into();
        other.binding.action = action.into();
        other.binding.args_digest = digest.into();
        insert_on_conn(&tx, &other).unwrap();
        assert_eq!(
            lookup(&other.binding, Scope::Read, Some("schema-v1")),
            Some(other)
        );
    }
    assert_eq!(
        lookup(&record.binding, Scope::Read, Some("schema-v1")),
        Some(record)
    );
}

#[test]
fn search_and_claimless_records_round_trip_null_schema_and_empty_identity_sentinels() {
    let mut db = database();
    let tx = db.transaction().unwrap();
    for tool in ["web_search", "code_search"] {
        let mut record = record(tool);
        record.binding.owner_principal.clear();
        record.binding.subject = tool.into();
        record.binding.action = tool.into();
        record.binding.caller.claim_kind.clear();
        record.binding.caller.canonical_claim_identity.clear();
        record.selector = "claimless".into();
        record.schema_hash = None;
        insert_on_conn(&tx, &record).unwrap();
        assert_eq!(
            pending_on_conn(&tx, &record.binding, Scope::Read, None).unwrap(),
            Some(record.clone())
        );
        let mut connection = record.binding.clone();
        connection.owner_principal = "direct".into();
        assert_eq!(
            pending_on_conn(&tx, &connection, Scope::Read, None).unwrap(),
            None
        );
    }
}

#[test]
fn prepared_body_and_stored_record_share_one_requester_ref() {
    use crate::federated::card::{Context, PreparedCard, Search};
    use subc_protocol::scope::{FederatedAttributes, FederatedPeerClass};
    let caller = crate::federated::FederatedCaller::from_attributes(FederatedAttributes::new(
        FederatedPeerClass::Computer,
        "a".repeat(32),
        "pairing".into(),
        "Peer".into(),
    ))
    .unwrap();
    let filed_scope = crate::scope::CallScope {
        owner: "reserved:callosum".into(),
        scope_ref: "filed".into(),
        scope_epoch: 3,
        kind: None,
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: None,
        delegates: false,
        owner_authorized: false,
    };
    let card = PreparedCard::search(
        &Context {
            caller: &caller,
            filed_scope: &filed_scope,
            expires_in_ms: 42_000,
            per_call_only: false,
        },
        Search::Code,
        &json!({"query":"rust"}),
    )
    .unwrap();
    let mut db = database();
    let tx = db.transaction().unwrap();
    insert_on_conn(&tx, &card.record).unwrap();
    let id = card.body["requester_ref"].as_str().unwrap();
    assert_eq!(read_on_conn(&tx, id).unwrap(), Some(card.record.clone()));
    attach_card_ref_on_conn(&tx, id, "el_from_cingulate").unwrap();
    let stored = pending_on_conn(&tx, &card.record.binding, Scope::Read, None)
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, id);
    assert_eq!(stored.card_ref.as_deref(), Some("el_from_cingulate"));
    assert_eq!(stored.binding.args_digest, card.body["args_digest"]);
    let count: i64 = tx
        .query_row("SELECT count(*) FROM federated_card_records", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}
