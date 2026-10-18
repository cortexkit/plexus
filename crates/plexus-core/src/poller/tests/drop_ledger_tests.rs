use super::*;

fn commit_derived(
    store: &PlexusStore,
    subscription: &TriggerSubscription,
    advance: &CursorAdvance,
) -> Vec<TriggerEventInsertOutcome> {
    let inputs = advance
        .events
        .iter()
        .map(|event| PollEventInput {
            vendor_event_id: &event.vendor_event_id,
            payload: &event.payload,
            observed_at_ms: 4000,
            item_kind: Some("issue"),
            activity_at_ms: event.activity_at_ms,
            actor: &crate::actor_attribution::ActorAttribution::NotEnriched,
        })
        .collect::<Vec<_>>();
    store
        .commit_poll_success(
            "direct",
            "connection",
            &subscription.subscription_id,
            &advance.cursor_state,
            &inputs,
            4000,
            None,
        )
        .unwrap()
}

fn list_poll(strategy: &dyn CursorStrategy) -> CursorAdvance {
    let (store, _, _) = poll_engine(json!({}));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .unwrap()
        .unwrap();
    let boundary = json!({"id": "1", "updated_at": "1970-01-01T00:00:02Z"});
    let seed = strategy
        .derive(&json!({}), &json!({"items": [boundary.clone()]}))
        .unwrap();
    commit_derived(&store, &subscription, &seed);
    let new = json!({"id": "2", "updated_at": "1970-01-01T00:00:03Z"});
    let mut advance = strategy.derive(
        &json!({"watermark_ms": 2000, "watermark_id": "1"}),
        &json!({"items": [boundary, {"id": "0", "updated_at": "1969-12-31T23:58:59Z"}, new.clone(), new]}),
    ).unwrap();
    assert_eq!(advance.items_examined, 4);
    retain_changed_replay_candidates(&mut advance.events, &mut advance.dropped, |candidates| {
        store.unchanged_event_payloads("direct", &subscription.subscription_id, candidates)
    });
    let outcomes = commit_derived(&store, &subscription, &advance);
    let inserted = accounting::account_insert_outcomes(&mut advance, &outcomes);
    assert_eq!(
        advance.items_examined,
        inserted + advance.dropped.len(),
        "end-to-end drop ledger identity"
    );
    advance
}

#[test]
fn drop_ledger_sync_token_identity() {
    let advance = list_poll(&SyncTokenStrategy::new(None));
    assert_eq!(
        advance.dropped,
        vec![
            ("1".into(), DropReason::AlreadyDelivered),
            ("2".into(), DropReason::AlreadyDelivered)
        ]
    );
}

#[test]
fn drop_ledger_ordered_timestamp_identity() {
    let advance = list_poll(&ordered_strategy());
    assert_eq!(
        advance.dropped,
        vec![
            ("1".into(), DropReason::AlreadyDelivered),
            ("2".into(), DropReason::AlreadyDelivered)
        ]
    );
}

#[test]
fn drop_ledger_sorted_head_identity() {
    let advance = list_poll(&SortedHeadStrategy {
        items_field: Some("items".into()),
        timestamp_field: "updated_at".into(),
        tiebreaker_id_field: "id".into(),
        page_size: 30,
    });
    assert_eq!(
        advance.dropped,
        vec![
            ("0".into(), DropReason::OlderThanWatermark),
            ("1".into(), DropReason::UnchangedBoundaryReplay),
            ("2".into(), DropReason::AlreadyDelivered)
        ]
    );
}

fn observations(strategy: &dyn CursorStrategy, first: Value, second: Value) {
    let baseline = strategy.derive(&json!({}), &first).unwrap();
    let unchanged = strategy.derive(&baseline.cursor_state, &first).unwrap();
    let changed = strategy.derive(&baseline.cursor_state, &second).unwrap();
    assert_eq!(baseline.dropped.len(), 1);
    assert_eq!(baseline.dropped[0].1, DropReason::InitialBaseline);
    assert_eq!(unchanged.dropped.len(), 1);
    assert_eq!(unchanged.dropped[0].1, DropReason::UnchangedObservation);
    assert!(changed.dropped.is_empty());
    for advance in [baseline, unchanged, changed] {
        assert_eq!(advance.items_examined, 1);
        assert_eq!(
            advance.items_examined,
            advance.events.len() + advance.dropped.len()
        );
    }
}

#[test]
fn drop_ledger_scalar_identity() {
    observations(
        &ScalarDiffStrategy {
            scalar_field: "tag".into(),
        },
        json!({"tag": "v1"}),
        json!({"tag": "v2"}),
    );
}

#[test]
fn drop_ledger_probe_identity() {
    observations(&ProbeStrategy, json!(false), json!(true));
}
