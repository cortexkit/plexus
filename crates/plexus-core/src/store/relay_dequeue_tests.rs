use super::*;

fn setup() -> (PlexusStore, Event) {
    let store = ci_relay_store();
    store
        .insert_connection("direct", "pr", "github", "active", &json!({}))
        .unwrap();
    store.inner.with_conn_fenced(|conn| {
        for action in ["list_issues","list_pull_requests"] {
            conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args)
                VALUES (?1,'direct','pr',?1,300,'ordered_timestamp','hash','active',1,'{\"owner\":\"cortexkit\",\"repo\":\"aft\"}')",[action])?;
        }
        Ok(())
    }).unwrap();
    let body = serde_json::from_str(include_str!(
        "../../../plexus-module/tests/fixtures/webhook-relay/pull-request-dequeued.json"
    ))
    .unwrap();
    let event = Event {
        seq: 1,
        delivery_id: "dequeue-1".into(),
        event: "pull_request".into(),
        action: Some("dequeued".into()),
        installation_id: 42,
        received_at: "2026-10-23T09:00:00.000Z".into(),
        stub: None,
        body,
    };
    (store, event)
}

#[test]
fn delayed_webhook_keeps_relay_observation_time() {
    for dequeue in [false, true] {
        let (store, mut event) = setup();
        event.received_at = "2026-10-23T09:00:00.123Z".into();
        if !dequeue {
            event.action = Some("enqueued".into());
        }
        store
            .commit_relay_event("github", "stream", &event)
            .unwrap();
        let row = store.drain_event_outbox(10).unwrap().remove(0);
        let inserted_at: i64 = store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT created_at_ms FROM event_outbox WHERE event_key=?1",
                    [&row.event_key],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_ne!(
            inserted_at,
            parse_to_millis(&event.received_at).unwrap(),
            "fixture must model a delayed relay delivery"
        );
        let body: Value =
            serde_json::from_str(row.envelope_v2.as_deref().unwrap_or(&row.body)).unwrap();
        assert_eq!(
            body["observed_at"], event.received_at,
            "delayed webhook must keep relay receipt time, not insert or publish time"
        );
        if !dequeue {
            assert_eq!(
                row.body,
                serde_json::to_string(&event.body["pull_request"]).unwrap()
            );
        }
        store
            .mark_event_published(&row.event_key, now_ms())
            .unwrap();
        store
            .mark_event_version_published(&row.event_key, 2, now_ms())
            .unwrap();
        event.seq += 1;
        event.received_at = "2026-10-24T21:00:00.456Z".into();
        store
            .commit_relay_event("github", "stream", &event)
            .unwrap();
        let after = store
            .canonical_event_by_key(&row.event_key)
            .unwrap()
            .unwrap();
        assert_eq!(after.body, row.body);
        assert_eq!(after.digest, row.digest);
        assert_eq!(after.envelope_v2, row.envelope_v2);
        assert_eq!(after.digest_v2, row.digest_v2);
    }
}

#[test]
fn dequeue_delivery_identity_is_distinct_and_redelivery_deduplicates() {
    let (store, mut event) = setup();
    // A normal PR change with the same timestamp must not swallow the dequeue.
    event.action = Some("enqueued".into());
    event.delivery_id = "enqueue".into();
    assert_eq!(
        store
            .commit_relay_event_with_outcome("github", "stream", &event)
            .unwrap(),
        CommitOutcome::Stored
    );
    event.seq = 2;
    event.action = Some("dequeued".into());
    event.delivery_id = "dequeue-1".into();
    assert_eq!(
        store
            .commit_relay_event_with_outcome("github", "stream", &event)
            .unwrap(),
        CommitOutcome::Stored
    );
    let rows = store.drain_event_outbox(10).unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| row.event_name == crate::event_key::GITHUB_PR_CHANGED)
            .count(),
        1,
        "dequeue creates no PR-changed event"
    );
    let dequeues: Vec<_> = rows
        .iter()
        .filter(|row| row.event_name == crate::event_key::GITHUB_PR_DEQUEUED)
        .collect();
    assert_eq!(dequeues.len(), 1);
    let expected: Value = serde_json::from_str(include_str!(
        "../../../plexus-module/tests/fixtures/webhook-relay/pull-request-dequeued.body-v1.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&dequeues[0].body).unwrap(),
        expected
    );
    assert!(
        dequeues[0].envelope_v2.is_none(),
        "normalized notices publish only v1"
    );
    assert_eq!(dequeues[0].headers.pr.as_deref(), Some("42"));
    assert_eq!(dequeues[0].subscription_id, "list_pull_requests");
    event.seq = 3;
    event.body["reason"] = json!("a changed reason on a redelivery");
    assert_eq!(
        store
            .commit_relay_event_with_outcome("github", "stream", &event)
            .unwrap(),
        CommitOutcome::Dropped(DropReason::AlreadyDelivered)
    );
    event.seq = 4;
    event.delivery_id = "dequeue-2".into();
    assert_eq!(
        store
            .commit_relay_event_with_outcome("github", "stream", &event)
            .unwrap(),
        CommitOutcome::Stored
    );
    let rows = store.drain_event_outbox(10).unwrap();
    let dequeues: Vec<_> = rows
        .iter()
        .filter(|row| row.event_name == crate::event_key::GITHUB_PR_DEQUEUED)
        .collect();
    assert_eq!(
        dequeues.len(),
        2,
        "separate deliveries with the same PR updated_at must not collapse"
    );
    assert_ne!(dequeues[0].event_key, dequeues[1].event_key);
    assert_eq!(stored_count(&store, "trigger_events"), 3);
}

#[test]
fn dequeue_needs_no_pr_timestamp_and_preserves_unknown_reason() {
    let (store, mut event) = setup();
    event.body["pull_request"]
        .as_object_mut()
        .unwrap()
        .remove("updated_at");
    event.body["reason"] = json!("future_reason Spelling");
    assert_eq!(
        store
            .commit_relay_event_with_outcome("github", "stream", &event)
            .unwrap(),
        CommitOutcome::Stored
    );
    let rows = store.drain_event_outbox(10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&rows[0].body).unwrap()["reason"],
        "future_reason Spelling"
    );
    assert!(store.drain_event_outbox_version(10, 2).unwrap().is_empty());
}

#[test]
fn dequeue_requires_the_existing_active_pr_watch() {
    let (store, event) = setup();
    store.inner.with_conn_fenced(|conn| {
        conn.execute("UPDATE trigger_subscriptions SET status='retired' WHERE action='list_pull_requests'",[])?;
        Ok(())
    }).unwrap();
    assert_eq!(
        store
            .commit_relay_event_with_outcome("github", "stream", &event)
            .unwrap(),
        CommitOutcome::Dropped(DropReason::UnwatchedRepository)
    );
    assert_eq!(stored_count(&store, "trigger_events"), 0);
}
