use super::*;

/// The shape a manifest must declare for this kind, matching what
/// `list_pull_requests` actually needs.
fn head_shape(items_field: Option<&str>) -> PollShape {
    PollShape {
        cursor_kind: crate::manifest::CursorKind::SortedHead,
        token_field: None,
        request_token_field: None,
        items_field: items_field.map(str::to_string),
        timestamp_field: Some("updated_at".to_string()),
        tiebreaker_id_field: Some("number".to_string()),
        item_count_ceiling: None,
        item_kind: "issue".to_string(),
        pagination: None,
        request_page_size_field: Some("perPage".to_string()),
        request_since_field: None,
        request_constants: Some(std::collections::BTreeMap::from([(
            "perPage".to_string(),
            json!(2),
        )])),
        scalar_field: None,
    }
}

fn strategy(items_field: Option<&str>) -> SortedHeadStrategy {
    SortedHeadStrategy::new(Some(&head_shape(items_field))).expect("sorted head strategy")
}

fn item(number: i64, updated: &str) -> Value {
    json!({"number": number, "updated_at": updated, "title": format!("pr {number}")})
}

/// A BARE ARRAY response is read, and so is an enveloped one.
///
/// Measured on the live GitHub MCP server: `list_pull_requests` answers a
/// bare `[...]` while `list_issues` answers `{issues, totalCount, pageInfo}`
/// — the same server, the same session. Every other list strategy here calls
/// `as_object()` first and would suspend a pull-request watch on shape
/// before any cursor logic ran, which is why `items_field` is optional for
/// this kind alone.
///
/// Mutation-proved: requiring an object fails the bare-array leg; ignoring a
/// declared items_field and always treating the response as the array fails
/// the enveloped leg.
#[test]
fn both_response_envelopes_are_read() {
    let bare = json!([item(1, "2026-08-13T10:00:00Z")]);
    let advance = strategy(None)
        .derive(&json!({}), &bare)
        .expect("a bare array must be readable");
    assert_eq!(advance.events.len(), 1, "the bare array item must be seen");

    let wrapped = json!({"items": [item(1, "2026-08-13T10:00:00Z")], "totalCount": 1});
    let advance = strategy(Some("items"))
        .derive(&json!({}), &wrapped)
        .expect("an enveloped array must be readable");
    assert_eq!(advance.events.len(), 1, "the enveloped item must be seen");

    // The declaration is not advisory: a strategy told to expect an envelope
    // must refuse a bare array rather than silently read it, or a manifest
    // typo would look like a working watch.
    assert!(
        strategy(Some("items")).derive(&json!({}), &bare).is_err(),
        "a declared items_field must not silently accept a bare array"
    );
}

/// Strictly newer items remain established events, while equality at the
/// watermark is now a replay candidate resolved by stored content.
///
/// The old contract excluded equality outright. That is unsafe for vendors
/// whose update timestamp has only second resolution: content can change while
/// the timestamp remains fixed. Unchanged boundary content is still removed so
/// an idle head does not look active or consume enrichment work.
///
/// Mutation-proved: restoring the strict-greater-only filter loses id `2` from
/// the changed-boundary leg; ignoring the content result leaves id `2` in the
/// unchanged-boundary leg.
#[test]
fn strictly_past_items_and_changed_boundary_items_are_emitted() {
    let page = json!([
        item(3, "2026-08-13T12:00:00Z"),
        item(2, "2026-08-13T11:00:00Z"),
        item(1, "2026-08-13T10:00:00Z"),
    ]);
    let state = json!({
        "watermark_ms": iso8601::parse_to_millis("2026-08-13T11:00:00Z").unwrap(),
        "watermark_id": "2"
    });
    let mut unchanged = strategy(None).derive(&state, &page).expect("derive");
    assert_eq!(
        unchanged
            .events
            .iter()
            .map(|event| (event.vendor_event_id.as_str(), event.replay_candidate))
            .collect::<Vec<_>>(),
        vec![("3", false), ("2", true)],
        "newer items are established and the boundary is explicitly marked"
    );
    retain_changed_replay_candidates(
        &mut unchanged.events,
        &mut unchanged.dropped,
        |_candidates| Ok::<Vec<bool>, ()>(vec![true]),
    );
    assert_eq!(
        unchanged
            .events
            .iter()
            .map(|event| event.vendor_event_id.as_str())
            .collect::<Vec<_>>(),
        vec!["3"],
        "unchanged boundary content must be filtered"
    );

    let mut edited_page = page;
    edited_page[1]["title"] = json!("edited within the same second");
    let mut changed = strategy(None)
        .derive(&state, &edited_page)
        .expect("derive edited boundary");
    retain_changed_replay_candidates(&mut changed.events, &mut changed.dropped, |_candidates| {
        Ok::<Vec<bool>, ()>(vec![false])
    });
    assert_eq!(
        changed
            .events
            .iter()
            .map(|event| event.vendor_event_id.as_str())
            .collect::<Vec<_>>(),
        vec!["3", "2"],
        "changed boundary content must survive alongside strictly newer items"
    );
    assert_eq!(
        changed.cursor_state["watermark_id"], "3",
        "the watermark must advance to the newest item on the page"
    );
}

#[test]
fn disappeared_newest_item_keeps_watermark_pair_and_excludes_older_head() {
    let strategy = strategy(None);
    let prior = json!({"watermark_ms": iso8601::parse_to_millis("2026-08-13T10:00:00Z").unwrap(), "watermark_id":"9"});
    let page = json!([item(2, "2026-08-12T10:00:00Z")]);
    let first = strategy.derive(&prior, &page).unwrap();
    assert_eq!(first.cursor_state, prior);
    assert!(first.events.is_empty());
    let second = strategy.derive(&first.cursor_state, &page).unwrap();
    assert!(second.events.is_empty());
    // A lower id at the same instant must not replace the paired id either.
    let tied = strategy
        .derive(&prior, &json!([item(2, "2026-08-13T10:00:00Z")]))
        .unwrap();
    assert_eq!(tied.cursor_state, prior);
}

/// Items outside the replay window remain excluded from historical rescans.
#[test]
fn items_older_than_the_watermark_remain_excluded() {
    let state = json!({
        "watermark_ms": iso8601::parse_to_millis("2026-08-13T11:00:00Z").unwrap(),
        "watermark_id": "2"
    });
    let advance = strategy(None)
        .derive(
            &state,
            &json!([
                item(2, "2026-08-13T11:00:00Z"),
                item(1, "2026-08-13T10:58:59Z")
            ]),
        )
        .expect("derive boundary and older item");
    assert_eq!(advance.events.len(), 1, "only the boundary is reconsidered");
    assert_eq!(advance.events[0].vendor_event_id, "2");
    assert!(advance.events[0].replay_candidate);
}

/// A page whose OLDEST item is still newer than the watermark records a
/// coverage gap.
///
/// This is the honest cost of reading a sorted head instead of a filtered
/// window. If more items change between two polls than fit on one page, the
/// surplus falls off the bottom, and because the watermark advances to the
/// newest item no later poll will ever ask for it again. That is silent
/// event loss and it is invisible from outside: the feed keeps delivering,
/// just not everything.
///
/// It is detectable exactly when the whole page is new, which is what this
/// asserts. The gap does not stop the poll — the items that DID arrive are
/// real and must be delivered — it records what could not be established.
///
/// Mutation-proved: returning `None` unconditionally fails the saturated
/// leg; dropping the `oldest > watermark` condition reports a gap on the
/// partial page and fails the second leg.
#[test]
fn a_saturated_page_records_a_coverage_gap() {
    let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
    let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});

    // Every item newer than the watermark: the page may have been cut short.
    let full = json!([
        item(9, "2026-08-13T12:00:00Z"),
        item(8, "2026-08-13T11:00:00Z"),
    ]);
    let advance = strategy(None).derive(&state, &full).expect("derive");
    let gap = advance
        .coverage_gap
        .expect("a fully-new page must report a coverage gap");
    assert_eq!(gap.reason, "sorted_head_page_saturated");
    assert_eq!(gap.from_ms, watermark_ms, "the gap starts at the watermark");
    assert_eq!(
        gap.to_ms,
        iso8601::parse_to_millis("2026-08-13T11:00:00Z").unwrap(),
        "the gap ends at the oldest item actually seen"
    );
    assert_eq!(
        advance.events.len(),
        2,
        "a gap must not suppress the events that did arrive"
    );

    // A page reaching back past the watermark proves nothing was missed.
    let partial = json!([
        item(9, "2026-08-13T12:00:00Z"),
        item(1, "2026-08-13T08:00:00Z"),
    ]);
    assert!(
        strategy(None)
            .derive(&state, &partial)
            .expect("derive")
            .coverage_gap
            .is_none(),
        "a page reaching past the watermark establishes coverage"
    );
}

#[test]
fn a_full_page_ending_at_the_watermark_records_a_gap() {
    let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
    let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});
    // Another edited item at 09:00 may be beyond this two-item page.
    let page = json!([
        item(9, "2026-08-13T12:00:00Z"),
        item(1, "2026-08-13T09:00:00Z"),
    ]);
    let advance = strategy(None).derive(&state, &page).expect("derive");
    let gap = advance
        .coverage_gap
        .expect("a full boundary page cannot prove coverage");
    assert_eq!(gap.reason, "sorted_head_page_saturated");
    assert_eq!(gap.from_ms, watermark_ms);
    assert_eq!(gap.to_ms, watermark_ms);
    assert_eq!(advance.events.len(), 2);
}

#[test]
fn a_full_page_reaching_before_the_watermark_records_no_gap() {
    let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
    let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});
    let page = json!([
        item(9, "2026-08-13T12:00:00Z"),
        item(1, "2026-08-13T08:00:00Z"),
    ]);
    assert!(strategy(None)
        .derive(&state, &page)
        .expect("derive")
        .coverage_gap
        .is_none());
}

#[test]
fn a_short_page_records_no_gap_at_any_boundary_position() {
    let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
    let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});
    for timestamp in [
        "2026-08-13T08:00:00Z",
        "2026-08-13T09:00:00Z",
        "2026-08-13T10:00:00Z",
    ] {
        let page = json!([item(9, timestamp)]);
        assert!(
            strategy(None)
                .derive(&state, &page)
                .expect("derive")
                .coverage_gap
                .is_none(),
            "a short page is complete even when its oldest timestamp is {timestamp}"
        );
    }
}

/// The FIRST poll never reports a gap, and an empty page advances nothing.
///
/// With no prior watermark every item is new by definition, so the
/// saturation test would fire on every first poll and cry wolf on a watch
/// that is working correctly. An empty page has no maximum to advance to,
/// so the state must survive unchanged or the next poll would compare
/// against nothing and re-emit the whole page.
///
/// Mutation-proved: dropping the prior-watermark condition fails the first
/// leg; returning a fresh state on an empty page fails the second.
#[test]
fn a_first_poll_and_an_empty_page_report_no_gap() {
    let advance = strategy(None)
        .derive(&json!({}), &json!([item(1, "2026-08-13T10:00:00Z")]))
        .expect("derive");
    assert!(
        advance.coverage_gap.is_none(),
        "a first poll has no coverage claim to violate"
    );
    assert_eq!(advance.events.len(), 1, "a first poll backfills its page");

    let state = json!({"watermark_ms": 1_700_000_000_000i64, "watermark_id": "7"});
    let advance = strategy(None).derive(&state, &json!([])).expect("derive");
    assert!(advance.events.is_empty(), "an empty page emits nothing");
    assert!(
        advance.coverage_gap.is_none(),
        "an empty page cannot be saturated"
    );
    assert_eq!(
        advance.cursor_state, state,
        "an empty page must not move the watermark"
    );
}

/// An item missing its declared timestamp or tiebreaker fails the whole
/// derive rather than being skipped.
///
/// Same discipline as every other list strategy here: a silently skipped
/// item is a lost event, and the caller suspends so the gap is visible.
///
/// Mutation-proved: skipping malformed items instead of failing turns both
/// legs green.
#[test]
fn a_malformed_item_refuses_the_whole_page() {
    let missing_ts = json!([json!({"number": 1})]);
    assert!(
        strategy(None).derive(&json!({}), &missing_ts).is_err(),
        "an item with no timestamp must refuse the page"
    );
    let missing_id = json!([json!({"updated_at": "2026-08-13T10:00:00Z"})]);
    assert!(
        strategy(None).derive(&json!({}), &missing_id).is_err(),
        "an item with no tiebreaker must refuse the page"
    );
}
