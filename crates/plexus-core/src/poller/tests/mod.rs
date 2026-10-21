mod liveness_tests;
use super::*;

#[test]
fn outbound_year_zero_overlap_is_clamped_without_changing_cursor() {
    let strategy = ordered_strategy();
    let state = json!({"watermark_ms": -62_167_219_200_000_i64, "window_ms":60_000});
    let args = strategy.build_args(&state).unwrap();
    assert_eq!(
        args["since"], "0000-01-01T00:00:00.000Z",
        "outbound overlap must remain RFC3339"
    );
    assert_eq!(state["watermark_ms"], -62_167_219_200_000_i64);
}

#[test]
fn transient_credential_code_never_contains_error_details() {
    use crate::credentials::TransientCredentialError;
    let failure = GovernedReadFailure::Denied(Denial::Credential(CredentialDenial::Transient(
        TransientCredentialError::VaultLocked,
    )));
    assert_eq!(
        failure.code(),
        "credential_transient",
        "credential code must be stable and detail-free"
    );
}

#[test]
fn newest_conversation_comment_uses_existing_actor_window_only() {
    let response = json!([
        {"created_at":"2026-10-10T00:00:00Z","updated_at":"2026-10-10T00:00:00Z","html_url":"old","user":{"login":"old"}},
        {"created_at":"2026-10-10T00:00:02Z","updated_at":"2026-10-10T00:00:04Z","html_url":"newest","user":{"login":"new"}},
        {"created_at":"2026-10-10T00:00:03Z","updated_at":"2026-10-10T00:00:03Z","html_url":"second","user":{"login":"second"}}
    ]);
    let previous = iso8601::parse_to_millis("2026-10-10T00:00:01Z");
    assert_eq!(
        newest_window_comment(&response, previous).unwrap()["html_url"],
        "newest"
    );
    assert!(
        newest_window_comment(&response, iso8601::parse_to_millis("2026-10-10T00:00:04Z"))
            .is_none()
    );
    assert!(newest_window_comment(&json!({"unexpected":[]}), previous).is_none());
}

#[test]
fn only_a_github_noreply_email_names_a_commit_login() {
    assert_eq!(
        noreply_login("1234+octocat@users.noreply.github.com"),
        Some("octocat")
    );
    assert_eq!(
        noreply_login("octocat@Users.NoReply.GitHub.com"),
        Some("octocat")
    );
    assert_eq!(
        noreply_login("42716385+octo-release[bot]@users.noreply.github.com"),
        Some("octo-release[bot]")
    );
    for email in [
        "octocat@example.com",
        "octocat@users.noreply.github.com.evil.example",
        "abc+octocat@users.noreply.github.com",
        "+octocat@users.noreply.github.com",
        "1234+@users.noreply.github.com",
        "1234+octo cat@users.noreply.github.com",
        "1234+-octocat@users.noreply.github.com",
        "no-at-sign",
    ] {
        assert_eq!(noreply_login(email), None, "{email}");
    }
}

#[test]
fn two_method_event_at_the_cap_boundary_refuses_the_call_past_the_cap() {
    // Spend all but the last two calls on complete two-method events, so the
    // final event reserves exactly the remaining slots whatever the cap is.
    let cap = ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE;
    assert_eq!(cap % 2, 0, "this boundary is stated for an even cap");
    let budget = CallBudget::new(cap);
    for _ in 0..cap / 2 - 1 {
        let mut permit = budget.try_take(2).expect("complete two-method event fits");
        assert!(permit.take_one().is_some());
        assert!(permit.take_one().is_some());
    }
    let mut event = budget.try_take(2).expect("two first attempts still fit");
    assert!(event.take_one().is_some());
    assert!(
        budget.try_take(1).is_none(),
        "a retry would exceed the cap while the second method is still reserved"
    );
    assert!(event.take_one().is_some());
    assert!(budget.try_take(1).is_none());
}

#[test]
fn call_permit_cannot_issue_more_slots_than_taken() {
    let budget = CallBudget::new(2);
    let mut permit = budget.try_take(2).expect("2 fit");
    assert!(permit.take_one().is_some());
    assert!(permit.take_one().is_some());
    assert!(
        permit.take_one().is_none(),
        "a permit cannot spend more than it took"
    );
    assert!(
        budget.try_take(1).is_none(),
        "exhausted tokens stay exhausted"
    );
}

#[test]
fn unused_permit_tokens_return_when_the_permit_drops() {
    let budget = CallBudget::new(2);
    {
        let mut permit = budget.try_take(2).expect("2 fit");
        assert!(permit.take_one().is_some());
    }
    let _returned = budget.try_take(1).expect("unused token returned on drop");
    assert!(budget.try_take(1).is_none());
}

#[test]
fn sync_token_builds_no_argument_before_the_first_poll() {
    let strategy = SyncTokenStrategy::new(None);
    assert_eq!(
        strategy.build_args(&json!({})).expect("empty state"),
        json!({})
    );
    assert_eq!(
        strategy
            .build_args(&json!({ "sync_token": null }))
            .expect("null token"),
        json!({})
    );
}

#[test]
fn sync_token_resumes_from_a_stored_token() {
    let strategy = SyncTokenStrategy::new(None);
    assert_eq!(
        strategy
            .build_args(&json!({ "sync_token": "tok-1" }))
            .expect("stored token"),
        json!({ "sync_token": "tok-1" })
    );
}

#[test]
fn sync_token_rejects_a_non_string_cursor() {
    let strategy = SyncTokenStrategy::new(None);
    // Mutation proved: replacing the InvalidState arm with a fallback to
    // {} would let a corrupt cursor poll silently from the beginning; this
    // assertion fails the moment that guard is removed.
    assert!(matches!(
        strategy.build_args(&json!({ "sync_token": 42 })),
        Err(CursorError::InvalidState(_))
    ));
}

#[test]
fn sync_token_derives_events_and_advances_to_the_next_cursor() {
    let strategy = SyncTokenStrategy::new(None);
    let response = json!({
        "items": [
            { "id": "e1", "title": "first" },
            { "id": "e2", "title": "second" }
        ],
        "next_cursor": "tok-2"
    });
    let advance = strategy.derive(&json!({}), &response).expect("derive");
    assert_eq!(advance.cursor_state, json!({ "sync_token": "tok-2" }));
    assert_eq!(advance.events.len(), 2);
    assert_eq!(advance.events[0].vendor_event_id, "e1");
    assert_eq!(
        advance.events[0].payload,
        json!({ "id": "e1", "title": "first" })
    );
}

#[test]
fn sync_token_keeps_the_watermark_when_the_response_has_no_next_cursor() {
    let strategy = SyncTokenStrategy::new(None);
    let advance = strategy
        .derive(&json!({ "sync_token": "tok-1" }), &json!({ "items": [] }))
        .expect("derive");
    assert_eq!(advance.cursor_state, json!({ "sync_token": "tok-1" }));
    assert!(advance.events.is_empty());
}

#[test]
fn sync_token_refuses_an_item_without_a_stable_id() {
    let strategy = SyncTokenStrategy::new(None);
    // Mutation proved: synthesizing an id for an id-less item (instead of
    // refusing) would let two different id-less records collide on the same
    // dedupe key and suppress one another; this fails if that guard goes.
    let response = json!({ "items": [{ "title": "no id here" }], "next_cursor": "tok-2" });
    assert!(matches!(
        strategy.derive(&json!({}), &response),
        Err(CursorError::InvalidResponse(_))
    ));
}

#[test]
fn strategy_resolution_by_cursor_kind() {
    // sync_token has a reference-envelope default for every field, so it
    // resolves even with no manifest poll shape.
    assert!(strategy_for("sync_token", None).is_some());
    // ordered_timestamp has NO honest default for its timestamp/tiebreaker
    // fields, so without a usable poll shape it is refused, not guessed.
    assert!(strategy_for("ordered_timestamp", None).is_none());
    assert!(strategy_for("ordered_timestamp", Some(&ordered_shape())).is_some());
    // A shape missing its required fields resolves to nothing either.
    let bare = PollShape {
        cursor_kind: crate::manifest::CursorKind::OrderedTimestamp,
        token_field: None,
        request_token_field: None,
        items_field: None,
        timestamp_field: None,
        tiebreaker_id_field: None,
        item_count_ceiling: None,
        item_kind: "issue".to_string(),
        pagination: None,
        request_page_size_field: None,
        request_since_field: None,
        request_constants: Some(Default::default()),
        scalar_field: None,
    };
    assert!(strategy_for("ordered_timestamp", Some(&bare)).is_none());
    // snapshot_diff and unknown kinds are not implemented in this slice.
    assert!(strategy_for("snapshot_diff", None).is_none());
    assert!(strategy_for("probe", None).is_some());
    assert!(strategy_for("ci_runs", None).is_none());
    assert!(strategy_for("anything_else", None).is_none());
}

// --- Ordered-timestamp cursor strategy -----------------------------------
//
// Each test states the mutation it proves. The arithmetic under test is the
// whole difficulty of this cursor kind: a settled watermark that resumes
// from `watermark - window`, an adaptive window that only grows, and a
// response that is refused whole when it does not match its declared shape.

/// A manifest poll shape for an ordered-timestamp action using the field
/// names the strategy must honour: `updated_at` for the timestamp and `id`
/// for the tiebreaker, with the reference `items` envelope and the default
/// `since` request parameter.
fn ordered_shape() -> PollShape {
    PollShape {
        cursor_kind: crate::manifest::CursorKind::OrderedTimestamp,
        token_field: None,
        request_token_field: None,
        items_field: None,
        timestamp_field: Some("updated_at".to_string()),
        tiebreaker_id_field: Some("id".to_string()),
        item_count_ceiling: None,
        item_kind: "issue".to_string(),
        pagination: None,
        request_page_size_field: None,
        request_since_field: None,
        request_constants: Some(Default::default()),
        scalar_field: None,
    }
}

fn ordered_strategy() -> OrderedTimestampStrategy {
    OrderedTimestampStrategy::new(Some(&ordered_shape())).expect("ordered strategy")
}

#[test]
fn ordered_timestamp_requests_everything_before_the_first_poll() {
    let strategy = ordered_strategy();
    assert_eq!(
        strategy.build_args(&json!({})).expect("empty state"),
        json!({})
    );
    assert_eq!(
        strategy
            .build_args(&json!({ "watermark_ms": null }))
            .expect("null watermark"),
        json!({})
    );
}

/// The settled watermark subtracts the window: a resumed poll requests from
/// `watermark - window`, not from the bare maximum.
///
/// Mutation proved: resuming from the bare maximum makes the request
/// timestamp equal `watermark_ms`, so the equality with `watermark - window`
/// fails the moment that subtraction is removed.
#[test]
fn ordered_timestamp_resumes_from_watermark_minus_window() {
    let strategy = ordered_strategy();
    let watermark_ms = 1_700_000_000_000_i64;
    let window_ms = 60_000_i64;
    let args = strategy
        .build_args(&json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }))
        .expect("resume args");
    let since = args.get("since").and_then(Value::as_str).expect("since");
    assert_eq!(
        super::iso8601::parse_to_millis(since),
        Some(watermark_ms - window_ms),
        "the request must resume from watermark - window, not the bare maximum"
    );
}

/// Boundary rows are re-fetched, not skipped: after a watermark is derived
/// from rows whose newest is at time T, the next request resumes strictly
/// BEFORE T, so a row at exactly the watermark satisfies the inclusive
/// (`>=`) filter and comes back to be discarded by dedupe rather than being
/// dropped.
///
/// Mutation proved: resuming from the bare maximum makes the request
/// timestamp equal T, so the strict `resume < T` assertion fails.
#[test]
fn ordered_timestamp_refetches_rows_at_the_boundary() {
    let strategy = ordered_strategy();
    let response = json!({
        "items": [
            { "id": "a", "updated_at": "2024-01-15T10:00:00Z" },
            { "id": "b", "updated_at": "2024-01-15T10:00:05Z" }
        ]
    });
    let advance = strategy.derive(&json!({}), &response).expect("derive");
    let watermark_ms = advance
        .cursor_state
        .get("watermark_ms")
        .and_then(Value::as_i64)
        .expect("watermark");
    assert_eq!(
        watermark_ms,
        super::iso8601::parse_to_millis("2024-01-15T10:00:05Z").unwrap(),
        "the watermark is the newest row"
    );
    // The next request resumes from watermark - window, strictly before the
    // watermark, so the row at the watermark is inside the `>=` range.
    let args = strategy
        .build_args(&advance.cursor_state)
        .expect("resume args");
    let resume_ms =
        super::iso8601::parse_to_millis(args.get("since").and_then(Value::as_str).expect("since"))
            .expect("parseable since");
    assert!(
            resume_ms < watermark_ms,
            "resume {resume_ms} must be strictly before the watermark {watermark_ms} so the boundary row is re-fetched"
        );
}

/// The window widens on evidence: a row below the current resume point
/// leaves a LARGER `window_ms` in the stored cursor state.
///
/// Mutation proved: not widening on evidence leaves `window_ms` unchanged,
/// so the assertion on the doubled stored value fails.
#[test]
fn ordered_timestamp_widens_the_window_on_evidence() {
    let strategy = ordered_strategy();
    let window_ms = 60_000_i64;
    let watermark_ms = 1_700_000_000_000_i64;
    let resume_ms = watermark_ms - window_ms;
    // A row 30s below the resume point: had it arrived one poll later it
    // would have been missed, so the window must grow.
    let late = super::iso8601::format_millis(resume_ms - 30_000);
    let newest = super::iso8601::format_millis(watermark_ms + 5_000);
    let response = json!({
        "items": [
            { "id": "late", "updated_at": late },
            { "id": "new", "updated_at": newest }
        ]
    });
    let advance = strategy
        .derive(
            &json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }),
            &response,
        )
        .expect("derive");
    assert_eq!(
        advance
            .cursor_state
            .get("window_ms")
            .and_then(Value::as_i64),
        Some(window_ms * 2),
        "evidence below the resume point must double the stored window"
    );
}

/// The window never shrinks on an ordinary poll: when no row falls below the
/// resume point, the stored `window_ms` is carried forward unchanged even
/// though the rows cluster tightly around the watermark.
///
/// Mutation proved: recomputing the window from the observed spread (or
/// resetting it toward the initial value) changes the stored value, so the
/// equality with the prior window fails.
#[test]
fn ordered_timestamp_never_shrinks_the_window() {
    let strategy = ordered_strategy();
    let window_ms = 240_000_i64; // already widened well past the initial value
    let watermark_ms = 1_700_000_000_000_i64;
    // Every row is at or above the resume point: an ordinary, quiet poll.
    let at = super::iso8601::format_millis(watermark_ms + 1_000);
    let response = json!({
        "items": [{ "id": "x", "updated_at": at }]
    });
    let advance = strategy
        .derive(
            &json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }),
            &response,
        )
        .expect("derive");
    assert_eq!(
        advance
            .cursor_state
            .get("window_ms")
            .and_then(Value::as_i64),
        Some(window_ms),
        "an ordinary poll must leave the window unchanged"
    );
}

/// The window doubles only up to its ceiling.
///
/// Mutation proved: dropping the `.min(MAX_WINDOW_MS)` ceiling lets the
/// stored window exceed the cap, so this assertion fails.
#[test]
fn ordered_timestamp_window_is_capped() {
    let strategy = ordered_strategy();
    let window_ms = super::MAX_WINDOW_MS; // already at the ceiling
    let watermark_ms = 1_700_000_000_000_i64;
    let resume_ms = watermark_ms - window_ms;
    let late = super::iso8601::format_millis(resume_ms - 1_000);
    let response = json!({
        "items": [{ "id": "late", "updated_at": late }]
    });
    let advance = strategy
        .derive(
            &json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }),
            &response,
        )
        .expect("derive");
    assert_eq!(
        advance
            .cursor_state
            .get("window_ms")
            .and_then(Value::as_i64),
        Some(super::MAX_WINDOW_MS),
        "the window must not grow past its ceiling"
    );
}

/// A healthy poll advances the watermark and derives its events (the
/// survival direction: a suite that only expects errors cannot tell a real
/// parser from one that rejects everything).
#[test]
fn ordered_timestamp_derives_events_and_advances_the_watermark() {
    let strategy = ordered_strategy();
    let response = json!({
        "items": [
            { "id": "a", "updated_at": "2024-01-15T10:00:00Z", "title": "first" },
            { "id": "b", "updated_at": "2024-01-15T10:00:05Z", "title": "second" }
        ]
    });
    let advance = strategy.derive(&json!({}), &response).expect("derive");
    assert_eq!(advance.events.len(), 2);
    assert_eq!(advance.events[0].vendor_event_id, "a");
    assert_eq!(advance.events[1].vendor_event_id, "b");
    assert_eq!(
        advance.events[0].payload,
        json!({ "id": "a", "updated_at": "2024-01-15T10:00:00Z", "title": "first" })
    );
    assert_eq!(
        advance
            .cursor_state
            .get("watermark_ms")
            .and_then(Value::as_i64),
        super::iso8601::parse_to_millis("2024-01-15T10:00:05Z"),
        "the watermark is the newest timestamp"
    );
    assert_eq!(
        advance
            .cursor_state
            .get("watermark_id")
            .and_then(Value::as_str),
        Some("b"),
        "the watermark id is the row that set it"
    );
    assert_eq!(
        advance
            .cursor_state
            .get("window_ms")
            .and_then(Value::as_i64),
        Some(super::INITIAL_WINDOW_MS),
        "the first poll seeds the initial window"
    );
}

/// A malformed item fails the whole poll rather than being skipped: a
/// missing timestamp, an unparseable timestamp, or a missing tiebreaker id
/// each yield `InvalidResponse`, so the caller suspends instead of silently
/// losing the event.
///
/// Mutation proved: skipping a bad item (instead of erroring) returns `Ok`
/// with the remaining events, so every `Err` assertion here fails.
#[test]
fn ordered_timestamp_refuses_a_malformed_item() {
    let strategy = ordered_strategy();
    let missing_timestamp = json!({ "items": [{ "id": "a" }] });
    assert!(matches!(
        strategy.derive(&json!({}), &missing_timestamp),
        Err(CursorError::InvalidResponse(_))
    ));
    let unparseable_timestamp = json!({ "items": [{ "id": "a", "updated_at": "yesterday" }] });
    assert!(matches!(
        strategy.derive(&json!({}), &unparseable_timestamp),
        Err(CursorError::InvalidResponse(_))
    ));
    let missing_tiebreaker = json!({ "items": [{ "updated_at": "2024-01-15T10:00:00Z" }] });
    assert!(matches!(
        strategy.derive(&json!({}), &missing_tiebreaker),
        Err(CursorError::InvalidResponse(_))
    ));
    // One good row alongside one bad row is still refused whole: a partial
    // commit would advance the watermark past the skipped row.
    let mixed = json!({ "items": [
            { "id": "good", "updated_at": "2024-01-15T10:00:00Z" },
            { "id": "bad", "updated_at": "not-a-date" }
        ] });
    assert!(matches!(
        strategy.derive(&json!({}), &mixed),
        Err(CursorError::InvalidResponse(_))
    ));
}

/// An integer tiebreaker is accepted and canonicalized to a string.
///
/// Vendors do not agree on the type of a stable row id: GitHub's `number`
/// is an integer, while the event log stores vendor ids as strings.
/// Requiring a JSON string would refuse every item from such a vendor on
/// the first poll — the strategy refuses a malformed item whole rather
/// than skipping it, so one integer id would fail the entire cycle.
///
/// The ids here are 2 and 10 at the SAME timestamp, deliberately: that is
/// the pair where numeric and lexical ordering disagree, so the assertion
/// also fences the comparison that picks which id is stored.
///
/// Mutation proved: comparing tiebreakers lexically stores 2 instead
/// of 10.
#[test]
fn ordered_timestamp_accepts_an_integer_tiebreaker() {
    let mut shape = ordered_shape();
    shape.tiebreaker_id_field = Some("number".to_string());
    let strategy = OrderedTimestampStrategy::new(Some(&shape)).expect("strategy");
    let advance = strategy
        .derive(
            &json!({}),
            &json!({
                "items": [
                    {
                        "number": 2,
                        "updated_at": "2024-01-15T10:00:00Z"
                    },
                    {
                        "number": 10,
                        "updated_at": "2024-01-15T10:00:00Z"
                    }
                ]
            }),
        )
        .expect("integer tiebreaker is a valid stable id");
    assert_eq!(advance.events.len(), 2);
    assert_eq!(advance.cursor_state["watermark_id"], "10");
}

/// Field names come from the manifest, not hardcoded: a poll shape declaring
/// unusual names is honoured in BOTH the request argument and the response
/// parsing.
///
/// Mutation proved: hardcoding any of `since`, `items`, `updated_at`, or
/// `id` makes the corresponding assertion fail — the request key would be
/// wrong, or the response would yield zero events or a missing timestamp.
#[test]
fn ordered_timestamp_honours_manifest_field_names() {
    let shape = PollShape {
        cursor_kind: crate::manifest::CursorKind::OrderedTimestamp,
        token_field: None,
        request_token_field: None,
        items_field: Some("records".to_string()),
        timestamp_field: Some("modified_at".to_string()),
        tiebreaker_id_field: Some("uid".to_string()),
        item_count_ceiling: None,
        item_kind: "issue".to_string(),
        pagination: None,
        request_page_size_field: None,
        request_since_field: Some("after".to_string()),
        request_constants: Some(Default::default()),
        scalar_field: None,
    };
    let strategy = OrderedTimestampStrategy::new(Some(&shape)).expect("strategy");
    // The request argument uses the declared request parameter name.
    let args = strategy
        .build_args(&json!({ "watermark_ms": 1_700_000_000_000_i64, "window_ms": 60_000_i64 }))
        .expect("args");
    assert!(args.get("after").is_some(), "request must use 'after'");
    assert!(
        args.get("since").is_none(),
        "request must not use the default 'since'"
    );
    // The response is read from the declared items/timestamp/tiebreaker fields.
    let response = json!({
        "records": [{ "uid": "r1", "modified_at": "2024-01-15T10:00:00Z" }]
    });
    let advance = strategy.derive(&json!({}), &response).expect("derive");
    assert_eq!(advance.events.len(), 1);
    assert_eq!(advance.events[0].vendor_event_id, "r1");
    assert_eq!(
        advance
            .cursor_state
            .get("watermark_ms")
            .and_then(Value::as_i64),
        super::iso8601::parse_to_millis("2024-01-15T10:00:00Z")
    );
}

// --- ISO 8601 conversion -------------------------------------------------

fn chrono_rfc3339_millis(input: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(input)
        .ok()
        .map(|timestamp| timestamp.timestamp_millis())
}

fn assert_iso8601_matches_chrono(input: &str, chrono_input: &str) {
    let ours = iso8601::parse_to_millis(input);
    let oracle = chrono_rfc3339_millis(chrono_input);
    assert_eq!(
            ours, oracle,
            "ISO-8601 oracle disagreement for {input:?} (chrono input {chrono_input:?}): ours={ours:?}, chrono={oracle:?}"
        );
}

#[test]
fn iso8601_exhaustively_matches_chrono_for_calendar_dates() {
    let mut case_count = 0;
    for year in 1970..=2100 {
        for month in 0..=13 {
            for day in 0..=32 {
                let input = format!("{year:04}-{month:02}-{day:02}T00:00:00Z");
                assert_iso8601_matches_chrono(&input, &input);
                case_count += 1;
            }
        }
    }
    assert_eq!(case_count, 60_522);
}

#[test]
fn iso8601_matches_chrono_at_gregorian_century_boundaries() {
    for input in [
        "1900-02-29T00:00:00Z",
        "1900-03-01T00:00:00Z",
        "2000-02-29T00:00:00Z",
        "2000-03-01T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2100-03-01T00:00:00Z",
    ] {
        assert_iso8601_matches_chrono(input, input);
    }
}

#[test]
fn iso8601_exhaustively_matches_chrono_for_times_and_offset_spellings() {
    let offset_spellings = [
        ("Z", "Z"),
        ("z", "Z"),
        ("+05:30", "+05:30"),
        ("-05:30", "-05:30"),
        ("+0530", "+05:30"),
        ("-0530", "-05:30"),
        ("+05", "+05:00"),
        ("-05", "-05:00"),
    ];
    let mut case_count = 0;
    let mut chrono_only_leap_seconds = 0;

    for hour in 0..=24 {
        for minute in 0..=60 {
            for second in 0..=61 {
                for (suffix, chrono_suffix) in offset_spellings {
                    let local = format!("2000-01-01T{hour:02}:{minute:02}:{second:02}");
                    let input = format!("{local}{suffix}");
                    let chrono_input = format!("{local}{chrono_suffix}");
                    let ours = iso8601::parse_to_millis(&input);
                    let oracle = chrono_rfc3339_millis(&chrono_input);
                    case_count += 1;

                    // Chrono represents an RFC 3339 `:60` as a leap second. This
                    // parser's malformed-input contract deliberately rejects seconds
                    // outside 00..=59, so preserve and name that divergence.
                    if second == 60 && ours.is_none() && oracle.is_some() {
                        chrono_only_leap_seconds += 1;
                        continue;
                    }

                    assert_eq!(
                            ours, oracle,
                            "ISO-8601 oracle disagreement for {input:?} (chrono input {chrono_input:?}): ours={ours:?}, chrono={oracle:?}"
                        );
                }
            }
        }
    }

    assert_eq!(case_count, 756_400);
    assert_eq!(
            chrono_only_leap_seconds, 11_520,
            "chrono must accept every valid local time's leap-second spelling while our parser rejects it"
        );
}

#[test]
fn iso8601_fractional_seconds_match_chrono_truncation() {
    for (fraction, expected_millis) in [
        ("1", 100),
        ("123", 123),
        ("123999", 123),
        ("123999999", 123),
    ] {
        let input = format!("2020-01-01T00:00:00.{fraction}Z");
        let oracle = chrono_rfc3339_millis(&input);
        assert_eq!(
            oracle,
            Some(1_577_836_800_000 + expected_millis),
            "chrono oracle did not truncate {fraction:?} to milliseconds"
        );
        assert_iso8601_matches_chrono(&input, &input);
    }
}

#[test]
fn iso8601_parses_utc_and_offsets_to_epoch_millis() {
    use super::iso8601;
    assert_eq!(iso8601::parse_to_millis("1970-01-01T00:00:00Z"), Some(0));
    // A well-known anchor: 2020-01-01T00:00:00Z == 1577836800 s.
    assert_eq!(
        iso8601::parse_to_millis("2020-01-01T00:00:00Z"),
        Some(1_577_836_800_000)
    );
    // A +02:00 offset is two hours ahead of UTC, so it maps back to midnight.
    assert_eq!(
        iso8601::parse_to_millis("2020-01-01T02:00:00+02:00"),
        Some(1_577_836_800_000)
    );
    // A negative offset puts local time behind UTC.
    assert_eq!(
        iso8601::parse_to_millis("2019-12-31T19:00:00-05:00"),
        Some(1_577_836_800_000)
    );
    // Compact and hour-only offsets are accepted too.
    assert_eq!(
        iso8601::parse_to_millis("2020-01-01T02:00:00+0200"),
        Some(1_577_836_800_000)
    );
    assert_eq!(
        iso8601::parse_to_millis("2020-01-01T02:00:00+02"),
        Some(1_577_836_800_000)
    );
    // Fractional seconds truncate to milliseconds.
    assert_eq!(
        iso8601::parse_to_millis("1970-01-01T00:00:00.5Z"),
        Some(500)
    );
    assert_eq!(
        iso8601::parse_to_millis("1970-01-01T00:00:00.123Z"),
        Some(123)
    );
    assert_eq!(
        iso8601::parse_to_millis("1970-01-01T00:00:00.123456Z"),
        Some(123)
    );
    // A space separator is accepted in place of 'T'.
    assert_eq!(
        iso8601::parse_to_millis("2020-01-01 00:00:00Z"),
        Some(1_577_836_800_000)
    );
}

#[test]
fn iso8601_calendar_boundaries() {
    for (input, expected) in [
        ("2026-02-31T00:00:00Z", None),
        ("2026-02-29T00:00:00Z", None),
        ("2026-04-31T00:00:00Z", None),
        ("2026-06-31T00:00:00Z", None),
        ("2026-09-31T00:00:00Z", None),
        ("2026-11-31T00:00:00Z", None),
        ("2026-13-01T00:00:00Z", None),
        ("2026-00-01T00:00:00Z", None),
        ("2026-01-00T00:00:00Z", None),
        ("2024-02-30T00:00:00Z", None),
        ("1900-02-29T00:00:00Z", None),
        ("2026-03-03T00:00:00Z", Some(1_772_496_000_000)),
        ("2024-02-29T00:00:00Z", Some(1_709_164_800_000)),
        ("2000-02-29T00:00:00Z", Some(951_782_400_000)),
        ("1900-02-28T00:00:00Z", Some(-2_203_977_600_000)),
        ("2026-04-30T00:00:00Z", Some(1_777_507_200_000)),
        ("2026-01-31T00:00:00Z", Some(1_769_817_600_000)),
    ] {
        assert_eq!(super::iso8601::parse_to_millis(input), expected, "{input}");
    }
}

#[test]
fn iso8601_rejects_malformed_input() {
    use super::iso8601;
    for bad in [
        "",
        "not-a-date",
        "2020-01-01",                // date only
        "2020-01-01T00:00:00",       // missing zone
        "2020-01-01T00:00:00Zextra", // trailing garbage
        "2020-13-01T00:00:00Z",      // month out of range
        "2020-01-32T00:00:00Z",      // day out of range
        "2020-01-01T24:00:00Z",      // hour out of range
        "2020-01-01T00:60:00Z",      // minute out of range
        "2020-01-01T00:00:60Z",      // second out of range
        "2020-01-01T00:00:00.Z",     // empty fraction
        "2020-01-01T00:00:00+25:00", // offset hour out of range
        "2020-01-01T00:00:00+02:60", // offset minute out of range
    ] {
        assert_eq!(iso8601::parse_to_millis(bad), None, "should reject {bad:?}");
    }
}

#[test]
fn iso8601_round_trips_millisecond_precision() {
    use super::iso8601;
    assert_eq!(iso8601::format_millis(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(
        iso8601::format_millis(1_577_836_800_000),
        "2020-01-01T00:00:00.000Z"
    );
    for millis in [
        0_i64,
        1,
        999,
        1_577_836_800_123,
        1_700_000_000_000,
        86_399_999,
    ] {
        assert_eq!(
            iso8601::parse_to_millis(&iso8601::format_millis(millis)),
            Some(millis),
            "round trip {millis}"
        );
    }
}

mod drop_ledger_tests;

// --- Poll-path retention tests -------------------------------------------
//
// These tests drive `Poller::poll_once` through the full governance chain
// to prove the retention bound is enforced from the poll path, not merely
// implemented in `prune`. They need a `sync_token` cursor strategy, which
// is the only kind `strategy_for` supports in this slice.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::credentials::StubCredentialSource;
use crate::governance::GovernanceEngine;
use crate::storage::{now_ms, CatalogActionInput, Ceiling, GrantInput, PlexusStore};
use crate::transport::{MockResponse, MockTransport};
use cortexkit_store::StorageDescriptor;
use cortexkit_store_types::{Isolation, StorageBackend};

static POLL_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Build a store whose manifest declares a `sync_token` read action, with a
/// poll grant and an active credentialed connection, plus a governance
/// engine over it with a mock transport programmed to return `response`.
/// The connection is enrolled through the same binding-ticket ceremony the
/// real facade uses, so `revalidate_and_dispatch` can resolve a credential
/// and reach the transport.
fn poll_engine(
    response: Value,
) -> (
    Arc<PlexusStore>,
    GovernanceEngine<StubCredentialSource, MockTransport>,
    MockTransport,
) {
    poll_engine_with_shape(
        response,
        json!({
            "item_kind": "issue",
            "cursor_kind": "sync_token",
            "request_token_field": "cursor",
            "request_constants": {
                "cursor": "manifest",
                "scope": "manifest",
                "constant_only": "constant"
            }
        }),
    )
}

fn poll_engine_with_shape(
    response: Value,
    poll_shape: Value,
) -> (
    Arc<PlexusStore>,
    GovernanceEngine<StubCredentialSource, MockTransport>,
    MockTransport,
) {
    let (store, credentials) = poll_store_with_shape(poll_shape);
    let transport = MockTransport::default();
    transport.set_response(MockResponse::Success(response));
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(credentials),
        Arc::new(transport.clone()),
    );
    (store, engine, transport)
}

/// The store and credentials behind [`poll_engine_with_shape`], for a test
/// that needs its own transport.
fn poll_store_with_shape(poll_shape: Value) -> (Arc<PlexusStore>, StubCredentialSource) {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!(
            "poll-test-{}-{}",
            now_ms(),
            POLL_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open poll store"));
    store
        .insert_connection(
            "direct",
            "connection",
            "poll_fixture",
            "pending",
            &serde_json::json!({}),
        )
        .expect("insert connection");
    let manifest = serde_json::json!({
        "schema_version": 1,
        "key": "poll_fixture",
        "name": "Poll fixture",
        "description": "manifest used by poll-path retention tests",
        "reuse_path": "deep_wrapper",
        "reuse_rationale": "test",
        "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [{
            "name": "read_action",
            "risk": "read",
            "poll": poll_shape
        }],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
        "availability": "ga"
    });
    let manifest = crate::manifest::ingest_value(manifest).expect("manifest");
    store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
        .expect("store manifest");
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_action".to_string(),
            title: Some("read_action".to_string()),
            schema: serde_json::json!({"type": "object"}),
            schema_hash: "hash-read".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("catalog action");
    // Enroll the connection through the binding-ticket ceremony so the
    // dispatch path can resolve a credential. The handle is a test canary
    // the stub credential source is programmed to return.
    let handle = b"test:test-handle";
    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            "connection",
            "credential_reference",
            handle,
            &Ceiling::unrestricted_for_tests(),
        )
        .expect("binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("connect")
        .expect("connection activated");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-poll".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("poll grant");
    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    (store, credentials)
}

/// When the stored-payload lookup fails, an item already stored is kept
/// and enriched, so an unreadable history can cost a comment read but
/// never lose an edit. Storage then drops it as a duplicate, and the
/// test-build ledger assertion in `record_completion` checks the balance.
///
/// The same second pass without the injected failure makes no comment read,
/// which shows the item is one the skip would otherwise remove.
///
/// MUTATION: skipping the item on a lookup error drops the comment read on
/// the failing pass and fails the dispatch assertion.
#[test]
fn a_failing_stored_payload_lookup_keeps_and_enriches_the_item() {
    let item = json!({
        "id": "issue-17",
        "number": 17,
        "updated_at": "2026-08-20T12:00:00Z",
        "title": "unchanged"
    });
    let (store, engine, transport) = poll_engine_with_shape(
        json!({"items": [item]}),
        json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_constants": {}
        }),
    );
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "issue_read".to_string(),
            title: Some("issue_read".to_string()),
            schema: json!({"type": "object"}),
            schema_hash: "hash-issue-read".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("actor catalog action");
    // The watched read must declare the repository arguments the
    // subscription fixes, which the actor read reuses, and the `since`
    // resume point its ordered-timestamp poll sends.
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_action".to_string(),
            title: Some("read_action".to_string()),
            schema: json!({
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "since": {"type": "string"}
                }
            }),
            schema_hash: "hash-read-repository".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("watched catalog action");
    let id = store
        .subscribe_with_cursor_state(
            "direct",
            "connection",
            "read_action",
            30,
            &json!({}),
            &json!({"owner": "cortexkit", "repo": "plexus"}),
        )
        .expect("subscribe")
        .expect("subscription")
        .subscription_id;
    store
        .set_subscription_actor_source(
            "direct",
            &id,
            Some(&ActorSource {
                connection_id: "connection".to_string(),
                action: "issue_read".to_string(),
                methods: vec!["get_comments".to_string()],
            }),
        )
        .expect("actor source");
    transport.set_response_for_method(
        "issue_read",
        "get_comments",
        MockResponse::Success(json!([])),
    );
    let comment_reads = || {
        transport
            .requests()
            .iter()
            .filter(|request| request.action == "issue_read")
            .count()
    };
    let poller = Poller::new(engine);
    assert_eq!(
        poller.poll_once("direct", &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(comment_reads(), 1, "a new item is enriched");

    assert_eq!(
        poller.poll_once("direct", &id),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(comment_reads(), 1, "a stored item is skipped");

    FAIL_STORED_PAYLOAD_LOOKUP.with(|fail| fail.set(true));
    let cycle = poller.poll_once("direct", &id);
    FAIL_STORED_PAYLOAD_LOOKUP.with(|fail| fail.set(false));
    assert_eq!(
        cycle,
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(
        comment_reads(),
        2,
        "an item whose stored state is unknown is enriched"
    );
    assert_eq!(
        store.list_events("direct", None, Some(&id)).unwrap().len(),
        1
    );
}

#[test]
fn scalar_transition_repeats_are_distinct_stored_events() {
    let a = json!({"tag_name": "v1", "id": 1});
    let b = json!({"tag_name": "v2", "id": 2});
    let (store, engine, transport) = poll_engine_with_shape(
        a.clone(),
        json!({
            "item_kind": "release",
            "cursor_kind": "scalar_diff",
            "scalar_field": "tag_name"
        }),
    );
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let id = &subscription.subscription_id;
    let poller = Poller::new(engine);
    let mut cycles = Vec::new();
    for response in [a.clone(), b.clone(), a.clone(), b.clone()] {
        transport.set_response(MockResponse::Success(response));
        cycles.push(poller.poll_once("direct", id));
    }
    let events = store
        .list_events("direct", None, Some(id))
        .expect("stored events");
    assert_eq!(
        events.len(),
        3,
        "four observations must persist three transitions"
    );
    assert!(events.iter().all(|event| event.kind == "event"));
    assert_eq!(events.iter().filter(|event| event.payload == b).count(), 2);
    assert_eq!(events.iter().filter(|event| event.payload == a).count(), 1);
    assert!(matches!(
        cycles[0],
        PollCycle::Completed {
            inserted: 0,
            duplicates: 0
        }
    ));
    for cycle in &cycles[1..] {
        assert!(
            matches!(
                cycle,
                PollCycle::Completed {
                    inserted: 1,
                    duplicates: 0
                }
            ),
            "every transition, including the fourth observation, must insert: {cycle:?}"
        );
    }
    assert_eq!(
        store
            .subscription("direct", id)
            .unwrap()
            .unwrap()
            .cursor_state,
        json!({"scalar": "v2", "scalar_ordinal": 3})
    );
}

#[test]
fn scalar_transition_ordinal_does_not_grow_on_unchanged_polls() {
    let (store, engine, transport) = poll_engine_with_shape(
        json!({"tag_name": "v2"}),
        json!({
            "item_kind": "release",
            "cursor_kind": "scalar_diff",
            "scalar_field": "tag_name"
        }),
    );
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let id = &subscription.subscription_id;
    // Simulate a successful poll persisted by a version without ordinal support.
    assert!(store
        .record_poll_success("direct", id, &json!({"scalar": "v1"}), now_ms())
        .unwrap());
    let poller = Poller::new(engine);
    assert!(matches!(
        poller.poll_once("direct", id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    ));
    let changed_state = store
        .subscription("direct", id)
        .unwrap()
        .unwrap()
        .cursor_state;
    assert_eq!(changed_state, json!({"scalar": "v2", "scalar_ordinal": 1}));
    transport.set_response(MockResponse::Success(json!({"tag_name": "v2"})));
    for _ in 0..3 {
        assert!(matches!(
            poller.poll_once("direct", id),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 0
            }
        ));
        assert_eq!(
            store
                .subscription("direct", id)
                .unwrap()
                .unwrap()
                .cursor_state,
            changed_state,
            "unchanged polls must not grow the transition ordinal"
        );
    }
    assert_eq!(
        store.list_events("direct", None, Some(id)).unwrap().len(),
        1
    );
}

/// A TRANSIENT credential failure is counted, not suspended.
///
/// Reference credentials resolve at dispatch, so a locked vault produces an
/// inconclusive, unsent poll rather than an authorization suspension or a
/// vendor failure. The subscription remains active for the next tick.
#[test]
fn a_transient_reference_failure_is_inconclusive_without_suspension() {
    let (store, engine, _transport) = poll_engine(json!({"items": []}));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");

    // The vault is momentarily unavailable. Authority is untouched.
    engine.credential_source().set_error(
        b"test:test-handle",
        crate::credentials::CredentialError::Transient(
            crate::credentials::TransientCredentialError::VaultLocked,
        ),
    );

    let poller = Poller::new(engine);
    let cycle = poller.poll_once("direct", &subscription.subscription_id);
    assert!(
        matches!(cycle, PollCycle::Inconclusive { .. }),
        "a transient credential error must not be a suspension: {cycle:?}"
    );

    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(
        stored.status, "active",
        "a momentary vault failure suspended the subscription, which never auto-resumes"
    );
    assert_eq!(
        stored.consecutive_vendor_failures, 0,
        "an unsent vault failure is not a vendor failure"
    );
    assert!(
        store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("list events")
            .is_empty(),
        "a transient failure wrote a coverage gap marker for a subscription that is still active"
    );
}

/// Poll-path pruning keeps young bodies even beyond the ceiling, but trims
/// older rows once the seven-day floor no longer protects them.
#[test]
fn poll_path_enforces_the_retention_ceiling() {
    for aged in [false, true] {
        let (store, engine, _transport) = poll_engine(json!({"items": []}));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        for i in 0..(super::UNACKED_MAX_ROWS + 1) {
            store
                .insert_event(
                    "direct",
                    "connection",
                    &subscription.subscription_id,
                    &format!("vendor-{i}"),
                    &json!({"id": format!("vendor-{i}")}),
                    now_ms(),
                )
                .expect("pre-load event");
        }
        if aged {
            store
                .age_subscription_events_for_test(
                    &subscription.subscription_id,
                    now_ms() - 8 * crate::storage::AUDIT_MILLIS_PER_DAY,
                )
                .expect("age beyond body floor");
        }
        let poller = Poller::new(engine);
        let cycle = poller.poll_once("direct", &subscription.subscription_id);
        assert!(
            matches!(cycle, PollCycle::Completed { .. }),
            "poll should complete, got {cycle:?}"
        );
        let events = store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("events after poll");
        let ordinary = events.iter().filter(|event| event.kind == "event").count();
        if aged {
            assert_eq!(
                ordinary,
                super::UNACKED_MAX_ROWS,
                "older rows are trimmed to the ceiling by the real poll path"
            );
            assert_eq!(events.iter().filter(|event| event.kind == "gap").count(), 1);
        } else {
            assert_eq!(
                ordinary,
                super::UNACKED_MAX_ROWS + 1,
                "seven-day body floor overrides the ceiling for young rows"
            );
            assert_eq!(events.iter().filter(|event| event.kind == "gap").count(), 0);
        }
    }
}

/// A recent unacked event survives the poll-path prune and is still
/// delivered by `list`. This is the survival direction: a suite where every
/// vector expects removal cannot distinguish a real implementation from one
/// that deletes everything.
#[test]
fn poll_path_keeps_a_recent_unacked_event() {
    let (store, engine, _transport) = poll_engine(json!({"items": []}));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    // One fresh event well within both the age and row bounds.
    let payload = serde_json::json!({"id": "fresh", "value": 42});
    store
        .insert_event(
            "direct",
            "connection",
            &subscription.subscription_id,
            "fresh",
            &payload,
            now_ms(),
        )
        .expect("fresh event");
    let poller = Poller::new(engine);
    let cycle = poller.poll_once("direct", &subscription.subscription_id);
    assert!(
        matches!(cycle, PollCycle::Completed { .. }),
        "poll should complete, got {cycle:?}"
    );
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("events after poll");
    let fresh = events
        .iter()
        .find(|event| event.vendor_event_id.as_deref() == Some("fresh"))
        .expect("the fresh unacked event survived the poll-path prune");
    assert_eq!(
        fresh.payload, payload,
        "the payload is intact and delivered by list"
    );
}

// --- Ordered-timestamp poll-path tests -----------------------------------
//
// These drive `Poller::poll_once` through the full governance chain with an
// `ordered_timestamp` manifest, proving the cursor arithmetic holds end to
// end: what the resumed request actually asks for, and that a malformed
// response suspends without committing anything.

/// Build a store whose manifest declares an `ordered_timestamp` read action
/// (timestamp field `updated_at`, tiebreaker `id`), with a poll grant and an
/// active credentialed connection, plus a governance engine over it with a
/// mock transport programmed to return `response`. The transport handle is
/// returned (it shares state with the engine's copy) so a test can inspect
/// the request arguments actually dispatched.
fn ordered_poll_engine(
    response: Value,
) -> (
    Arc<PlexusStore>,
    GovernanceEngine<StubCredentialSource, MockTransport>,
    MockTransport,
) {
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!(
            "ordered-poll-test-{}-{}",
            now_ms(),
            POLL_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).expect("open ordered poll store"));
    store
        .insert_connection(
            "direct",
            "connection",
            "ordered_fixture",
            "pending",
            &serde_json::json!({}),
        )
        .expect("insert connection");
    let manifest = serde_json::json!({
        "schema_version": 1,
        "key": "ordered_fixture",
        "name": "Ordered fixture",
        "description": "manifest used by ordered-timestamp poll-path tests",
        "reuse_path": "deep_wrapper",
        "reuse_rationale": "test",
        "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [{
            "name": "read_action",
            "risk": "read",
            "poll": {
                "item_kind": "issue",
                "cursor_kind": "ordered_timestamp",
                "timestamp_field": "updated_at",
                "tiebreaker_id_field": "id",
                "request_constants": {
                    "scope": "manifest",
                    "constant_only": "constant"
                }
            }
        }],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
        "availability": "ga"
    });
    let manifest = crate::manifest::ingest_value(manifest).expect("manifest");
    store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
        .expect("store manifest");
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "connection".to_string(),
            principal: "direct".to_string(),
            name: "read_action".to_string(),
            title: Some("read_action".to_string()),
            // Declares every argument the poll shape above sends (its
            // request constants and the `since` resume point), because
            // governance refuses an argument the schema does not declare.
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "scope": {"type": "string"},
                    "fixed_only": {"type": "string"},
                    "constant_only": {"type": "string"},
                    "since": {"type": "string"}
                }
            }),
            schema_hash: "hash-read".to_string(),
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("catalog action");
    let handle = b"test:test-handle";
    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            "connection",
            "credential_reference",
            handle,
            &Ceiling::unrestricted_for_tests(),
        )
        .expect("binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("connect")
        .expect("connection activated");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-poll".to_string(),
            principal: "direct".to_string(),
            connection_id: "connection".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
            expires_at: Some(now_ms() + 60_000),
        })
        .expect("poll grant");
    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let transport = MockTransport::default();
    transport.set_response(MockResponse::Success(response));
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(credentials),
        Arc::new(transport.clone()),
    );
    (store, engine, transport)
}

/// The request layers are ordered fixed_args < request_constants < cursor.
/// This uses a legacy-row mutation to exercise all three values on the same
/// request key; current subscriptions refuse that fixed/cursor collision.
///
/// Mutation proved: swapping either merge extension changes the received
/// `cursor` or `scope` assertion, so the test observes the transport's
/// request rather than trusting a local intermediate value.
#[test]
fn poll_path_merges_fixed_args_constants_and_cursor_in_reviewed_order() {
    let (store, engine, transport) = poll_engine(json!({
        "items": [{"id": "first"}],
        "next_cursor": "tok-1"
    }));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let before = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(
        before.fixed_args,
        json!({}),
        "legacy-row mutation starts empty"
    );

    let poller = Poller::new(engine);
    assert!(matches!(
        poller.poll_once("direct", &subscription.subscription_id),
        PollCycle::Completed { .. }
    ));
    store
        .replace_fixed_args_for_test(
            "direct",
            &subscription.subscription_id,
            &json!({
                "cursor": "fixed",
                "scope": "fixed",
                "fixed_only": "fixed"
            }),
        )
        .expect("mutate legacy fixed args");
    let mutated = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read mutated subscription")
        .expect("subscription exists after mutation");
    assert_eq!(
        mutated.fixed_args,
        json!({
            "cursor": "fixed",
            "scope": "fixed",
            "fixed_only": "fixed"
        }),
        "precondition: the legacy row must carry all fixed-layer values"
    );

    transport.set_response(MockResponse::Success(json!({"items": []})));
    assert!(matches!(
        poller.poll_once("direct", &subscription.subscription_id),
        PollCycle::Completed { .. }
    ));
    let request = transport
        .requests()
        .last()
        .cloned()
        .expect("second poll request received by transport");
    assert_eq!(request.args["cursor"], json!("tok-1"));
    assert_eq!(request.args["scope"], json!("manifest"));
    assert_eq!(request.args["fixed_only"], json!("fixed"));
    assert_eq!(request.args["constant_only"], json!("constant"));
}

/// A healthy ordered-timestamp poll advances the stored watermark and
/// commits its events (the survival direction at the poll-path level).
#[test]
fn ordered_poll_path_advances_the_watermark_and_commits_events() {
    let response = json!({
        "items": [
            { "id": "a", "updated_at": "2024-01-15T10:00:00Z" },
            { "id": "b", "updated_at": "2024-01-15T10:00:05Z" }
        ]
    });
    let (store, engine, _transport) = ordered_poll_engine(response);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let poller = Poller::new(engine);
    let cycle = poller.poll_once("direct", &subscription.subscription_id);
    assert!(
        matches!(cycle, PollCycle::Completed { inserted: 2, .. }),
        "expected two inserted events, got {cycle:?}"
    );
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(
        stored
            .cursor_state
            .get("watermark_ms")
            .and_then(Value::as_i64),
        super::iso8601::parse_to_millis("2024-01-15T10:00:05Z"),
        "the stored watermark is the newest timestamp"
    );
    assert_eq!(
        stored
            .cursor_state
            .get("watermark_id")
            .and_then(Value::as_str),
        Some("b")
    );
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    let ids: Vec<String> = events
        .iter()
        .filter_map(|event| event.vendor_event_id.clone())
        .collect();
    assert!(
        ids.contains(&"a".to_string()) && ids.contains(&"b".to_string()),
        "{ids:?}"
    );
}

/// The settled watermark subtracts the window at the poll path: after a
/// successful poll establishes a watermark, the NEXT dispatched request
/// carries `since = watermark - window`, not the bare watermark.
///
/// Mutation proved: resuming from the bare maximum makes the recorded
/// request timestamp equal the watermark, so the equality with
/// `watermark - window` fails.
#[test]
fn ordered_poll_path_requests_from_watermark_minus_window() {
    let response = json!({
        "items": [
            { "id": "a", "updated_at": "2024-01-15T10:00:00Z" },
            { "id": "b", "updated_at": "2024-01-15T10:00:05Z" }
        ]
    });
    let (store, engine, transport) = ordered_poll_engine(response);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let poller = Poller::new(engine);
    // First poll: empty cursor, so the request carries no `since` and the
    // watermark is established from the response.
    assert!(matches!(
        poller.poll_once("direct", &subscription.subscription_id),
        PollCycle::Completed { .. }
    ));
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    let watermark_ms = stored
        .cursor_state
        .get("watermark_ms")
        .and_then(Value::as_i64)
        .expect("watermark");
    let window_ms = stored
        .cursor_state
        .get("window_ms")
        .and_then(Value::as_i64)
        .expect("window");
    // Quiet second page: the watermark does not move, so the resume point is
    // observable on the next dispatched request.
    transport.set_response(MockResponse::Success(json!({ "items": [] })));
    assert!(matches!(
        poller.poll_once("direct", &subscription.subscription_id),
        PollCycle::Completed { .. }
    ));
    let requests = transport.requests();
    let last = requests.last().expect("a second request was dispatched");
    let since = last
        .args
        .get("since")
        .and_then(Value::as_str)
        .expect("since argument");
    assert_eq!(
        super::iso8601::parse_to_millis(since),
        Some(watermark_ms - window_ms),
        "the resumed request must start at watermark - window"
    );
    assert_ne!(
        super::iso8601::parse_to_millis(since),
        Some(watermark_ms),
        "the resumed request must not start at the bare watermark"
    );
}

#[test]
fn ordered_poll_path_impossible_date_preserves_watermark() {
    let (store, engine, transport) = ordered_poll_engine(json!({
        "items": [{ "id": "baseline", "updated_at": "2026-02-28T00:00:00Z" }]
    }));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let poller = Poller::new(engine);
    assert!(matches!(
        poller.poll_once("direct", &subscription.subscription_id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let baseline = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read baseline")
        .expect("subscription exists");
    assert_eq!(
        baseline.cursor_state["watermark_ms"],
        json!(1_772_236_800_000_i64)
    );
    transport.set_response(MockResponse::Success(json!({
        "items": [
            { "id": "good", "updated_at": "2026-03-01T00:00:00Z" },
            { "id": "bad", "updated_at": "2026-02-31T00:00:00Z" }
        ]
    })));
    let cycle = poller.poll_once("direct", &subscription.subscription_id);
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read subscription")
        .expect("subscription exists");
    assert_eq!(
        stored.cursor_state, baseline.cursor_state,
        "an impossible date must not advance the watermark"
    );
    assert!(
        matches!(
            cycle,
            PollCycle::Suspended { ref reason } if reason.starts_with("response_shape_invalid:")
        ),
        "expected response_shape_invalid suspension, got {cycle:?}"
    );
    assert_eq!(stored.status, "suspended");
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    let ordinary: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "event")
        .collect();
    assert_eq!(ordinary.len(), 1, "the refused page must commit no events");
    assert_eq!(ordinary[0].vendor_event_id.as_deref(), Some("baseline"));
    assert!(events.iter().any(|event| event.kind == "gap"));
}

/// A malformed item fails the poll rather than being skipped: the
/// subscription is suspended and NO events are committed.
///
/// Mutation proved: skipping the bad item (instead of refusing the response)
/// commits the good row and completes the poll, so both the suspension and
/// the empty-event assertions fail.
#[test]
fn ordered_poll_path_refuses_a_malformed_item_without_committing() {
    let response = json!({
        "items": [
            { "id": "good", "updated_at": "2024-01-15T10:00:00Z" },
            { "id": "bad", "updated_at": "not-a-timestamp" }
        ]
    });
    let (store, engine, _transport) = ordered_poll_engine(response);
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let poller = Poller::new(engine);
    let cycle = poller.poll_once("direct", &subscription.subscription_id);
    assert!(
        matches!(cycle, PollCycle::Suspended { ref reason } if reason.starts_with("response_shape_invalid:")),
        "a malformed item must suspend the poll, got {cycle:?}"
    );
    let events = store
        .list_events("direct", None, Some(&subscription.subscription_id))
        .expect("list events");
    let ordinary: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "event")
        .collect();
    assert!(
            ordinary.is_empty(),
            "no ordinary events may be committed when the response does not match its declared shape: {ordinary:?}"
        );
    // The suspension itself records a coverage gap marker. That is correct
    // and expected — it is the visible hole the suspension creates, not a
    // committed vendor event.
    assert!(
        events.iter().any(|event| event.kind == "gap"),
        "the suspension must record its coverage gap"
    );
}

/// A validation failure must not retire a `once` probe. A malformed return
/// is not a successful fire, and treating it as one silently kills the
/// watch it was meant to serve.
///
/// Mutation-proved: retiring on any non-success completion, or retiring
/// before checking the outcome, leaves this row `retired`.
#[test]
fn a_validation_failure_does_not_retire_a_once_probe() {
    let (store, engine, _transport) = poll_engine(json!({}));
    let subscription = store
        .register_probe(
            "direct",
            "connection",
            crate::storage::ProbeRegistration {
                name: "once-watch",
                actions: &["read_action".to_string()],
                script_source: "() => 1",
                return_schema: &json!({"kind": "bool"}),
                rearm: "once",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({}),
            },
        )
        .expect("store")
        .expect("accepted");
    let cycle = Poller::new(engine).poll_once("direct", &subscription.subscription_id);
    assert!(
        matches!(&cycle, PollCycle::Suspended { reason } if reason.starts_with("probe_return_invalid:")),
        "a type-mismatched return must pause visibly: {cycle:?}"
    );
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read")
        .expect("present");
    assert_eq!(
        stored.status, "suspended",
        "a validation failure must suspend, not retire a once probe"
    );
}

/// A failed replay lookup keeps the candidate in the batch that reaches the
/// real event commit, preferring insert-time dedupe over permanent loss.
///
/// Mutation-proved: changing the lookup-error branch to clear candidates
/// makes the committed outcome count zero instead of one.
#[test]
fn store_read_failure_keeps_replay_candidate_for_commit() {
    let (store, _engine, _transport) = poll_engine(json!({}));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription accepted");
    let mut events = vec![DerivedEvent {
        vendor_event_id: "boundary-1".to_string(),
        payload: json!({"id": "boundary-1", "title": "possibly changed"}),
        replay_candidate: true,
        activity_at_ms: Some(1_000),
    }];

    retain_changed_replay_candidates(&mut events, &mut Vec::new(), |_candidates| {
        Err::<Vec<bool>, _>("injected store read failure")
    });
    let inputs = events
        .iter()
        .map(|event| PollEventInput {
            vendor_event_id: &event.vendor_event_id,
            payload: &event.payload,
            observed_at_ms: 2_000,
            item_kind: Some("issue"),
            activity_at_ms: event.activity_at_ms,
            actor: &crate::actor_attribution::ActorAttribution::NotEnriched,
        })
        .collect::<Vec<_>>();
    let outcomes = store
        .commit_poll_success(
            "direct",
            "connection",
            &subscription.subscription_id,
            &json!({}),
            &inputs,
            2_000,
            None,
        )
        .expect("candidate reaches insert after lookup failure");
    assert_eq!(
        outcomes.len(),
        1,
        "lookup failure must keep the candidate for insert-time dedupe"
    );
    assert!(matches!(
        outcomes[0],
        TriggerEventInsertOutcome::Inserted { .. }
    ));
}

/// Ordered-timestamp events are established window results, so they never
/// invoke the sorted-head replay lookup.
///
/// Mutation-proved: setting `replay_candidate` to true in the ordered strategy
/// increments the lookup count and fails this test.
#[test]
fn ordered_timestamp_issues_no_replay_candidate_lookup() {
    let mut advance = ordered_strategy()
        .derive(
            &json!({}),
            &json!({
                "items": [{
                    "id": "ordered-1",
                    "updated_at": "2026-09-06T12:00:00Z"
                }]
            }),
        )
        .expect("derive ordered event");
    let lookup_calls = std::cell::Cell::new(0usize);
    retain_changed_replay_candidates(&mut advance.events, &mut advance.dropped, |_candidates| {
        lookup_calls.set(lookup_calls.get() + 1);
        Ok::<Vec<bool>, ()>(Vec::new())
    });
    assert_eq!(
        lookup_calls.get(),
        0,
        "ordered-timestamp must not issue a replay-candidate lookup"
    );
    assert_eq!(advance.events.len(), 1, "the ordered event remains intact");
}

/// A successful `once` fire retires in the same commit as the event.
#[test]
fn a_successful_once_fire_retires_the_probe() {
    let (store, engine, _transport) = poll_engine(json!({}));
    let subscription = store
        .register_probe(
            "direct",
            "connection",
            crate::storage::ProbeRegistration {
                name: "once-watch",
                actions: &["read_action".to_string()],
                script_source: "() => 'fired'",
                return_schema: &json!({"kind": "string", "max_len": 16}),
                rearm: "once",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({"baseline": "seed", "observation_ordinal": 0}),
            },
        )
        .expect("store")
        .expect("accepted");
    let cycle = Poller::new(engine).poll_once("direct", &subscription.subscription_id);
    match cycle {
        PollCycle::Completed { inserted, .. } => {
            assert_eq!(inserted, 1, "the seeded change must deliver");
        }
        other => panic!("expected a completed fire, got {other:?}"),
    }
    let stored = store
        .subscription("direct", &subscription.subscription_id)
        .expect("read")
        .expect("present");
    assert_eq!(
        stored.status, "retired",
        "a successful once fire must retire"
    );
}

/// Wait up to ten seconds for `condition` to become true, allowing another
/// thread to change the state it checks.
fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !condition() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// A comment created in the previous observation's own second but edited in
/// a later one was acted on after that observation, so its author is inside
/// the window. Only activity confined to that second, or to it and earlier
/// seconds, is ambiguous.
#[test]
fn an_edit_after_a_same_second_creation_is_inside_the_actor_window() {
    let previous = 1_787_227_200_500;
    let same_second = 1_787_227_200_000;
    let later = 1_787_227_205_000;
    let earlier = 1_787_227_190_000;
    assert_eq!(
        in_actor_window(same_second, later, Some(previous)),
        Ok(true)
    );
    assert_eq!(in_actor_window(later, later, Some(previous)), Ok(true));
    assert_eq!(in_actor_window(earlier, later, Some(previous)), Ok(true));
    assert_eq!(
        in_actor_window(same_second, same_second, Some(previous)),
        Err(ExtractionMiss::SameSecond)
    );
    assert_eq!(
        in_actor_window(earlier, same_second, Some(previous)),
        Err(ExtractionMiss::SameSecond)
    );
    assert_eq!(in_actor_window(earlier, earlier, Some(previous)), Ok(false));
}

/// A seeded cursor is input: values the strategy could never have written
/// are refused instead of overflowing the resume arithmetic or, for a
/// negative window, moving the resume point past the watermark and
/// skipping rows for good.
#[test]
fn ordered_timestamp_refuses_cursor_values_it_could_not_have_written() {
    let strategy = ordered_strategy();
    // A paginated strategy accepts a stored page continuation, which takes
    // a separate early-return branch in `build_args`.
    let paginated = OrderedTimestampStrategy::new(Some(&PollShape {
        pagination: Some(crate::manifest::PollPagination {
            request_cursor_field: "after".to_string(),
            response_cursor_pointer: "/next".to_string(),
        }),
        ..ordered_shape()
    }))
    .expect("paginated ordered strategy");
    let page = json!({"items": [{"id": "1", "updated_at": "2024-01-01T00:00:00Z"}]});
    let resume = json!({"after": "vendor-cursor-2"});
    assert!(
        paginated
            .build_args(&json!({"watermark_ms": 1_700_000_000_000_i64, "page_resume": resume}))
            .is_ok(),
        "a sound cursor with a page continuation must stay usable"
    );
    for state in [
        json!({"watermark_ms": i64::MIN}),
        json!({"watermark_ms": i64::MAX}),
        json!({"watermark_ms": MIN_WATERMARK_MS - 1}),
        json!({"watermark_ms": MAX_WATERMARK_MS + 1}),
        json!({"watermark_ms": 1_700_000_000_000_i64, "window_ms": -1}),
        json!({"watermark_ms": 1_700_000_000_000_i64, "window_ms": i64::MIN}),
        json!({"watermark_ms": 1_700_000_000_000_i64, "window_ms": MAX_WINDOW_MS + 1}),
        json!({"watermark_ms": 1_700_000_000_000_i64, "window_changed_ms": "soon"}),
    ] {
        // Refusing before the vendor read matters: a value only `derive`
        // refuses has already spent a governed call by then.
        assert!(
            matches!(
                strategy.build_args(&state),
                Err(CursorError::InvalidState(_))
            ),
            "build_args accepted {state}"
        );
        let mut resuming = state.clone();
        resuming["page_resume"] = resume.clone();
        assert!(
            matches!(
                paginated.build_args(&resuming),
                Err(CursorError::InvalidState(_))
            ),
            "build_args accepted {resuming} through its page continuation"
        );
        assert!(
            matches!(
                strategy.derive(&state, &page),
                Err(CursorError::InvalidState(_))
            ),
            "derive accepted {state}"
        );
    }
    // The accepted range is exactly what a vendor timestamp can parse to.
    for (input, bound) in [
        ("0000-01-01T00:00:00+23:59", MIN_WATERMARK_MS),
        ("9999-12-31T23:59:59.999-23:59", MAX_WATERMARK_MS),
    ] {
        let parsed = iso8601::parse_to_millis(input).expect("parses");
        let state = json!({"watermark_ms": parsed, "window_ms": MAX_WINDOW_MS});
        assert!(strategy.build_args(&state).is_ok(), "{input}");
        assert!((parsed - bound).abs() < 86_400_000, "{input}");
    }
}

/// A probe whose observation ordinal is at its limit refuses to advance
/// rather than overflowing.
#[test]
fn probe_ordinal_exhaustion_is_refused() {
    let state = json!({"baseline": false, "observation_ordinal": i64::MAX});
    assert!(matches!(
        ProbeStrategy.derive(&state, &json!(true)),
        Err(CursorError::InvalidState(_))
    ));
    // An unchanged value does not advance the ordinal, so it still derives.
    assert!(ProbeStrategy.derive(&state, &json!(false)).is_ok());
}

/// A page whose newest row is older than the stored watermark (the row that
/// set it was deleted, or no longer matches the filter) leaves the
/// watermark where it was; moving it back would widen every later request.
#[test]
fn ordered_timestamp_watermark_never_moves_backwards() {
    let strategy = ordered_strategy();
    let watermark_ms = iso8601::parse_to_millis("2024-01-15T10:00:50Z").unwrap();
    let prior = json!({"watermark_ms": watermark_ms, "watermark_id": "b", "window_ms": 60_000});
    let older = json!({"items": [{"id": "a", "updated_at": "2024-01-15T10:00:20Z"}]});
    let advance = strategy.derive(&prior, &older).expect("derive");
    assert_eq!(advance.cursor_state, prior);
    assert_eq!(advance.events.len(), 1, "the row itself is still delivered");
    // Same timestamp, smaller id: the pair does not move back either.
    let tie = json!({"items": [{"id": "a", "updated_at": "2024-01-15T10:00:50Z"}]});
    assert_eq!(
        strategy.derive(&prior, &tie).expect("derive").cursor_state,
        prior
    );
    // A newer row still advances it.
    let newer = json!({"items": [{"id": "c", "updated_at": "2024-01-15T10:01:00Z"}]});
    assert_eq!(
        strategy
            .derive(&prior, &newer)
            .expect("derive")
            .cursor_state["watermark_id"],
        "c"
    );
}

/// The overlap window doubles on a confirmed late row, then after a full
/// quiet day halves back toward the initial window, one step per day.
#[test]
fn the_overlap_window_widens_on_a_late_row_and_decays_after_a_quiet_day() {
    let watermark = json!({"watermark_ms": 1_700_000_000_000_i64, "watermark_id": "1"});
    let with = |window: i64, changed: Option<i64>| {
        let mut state = watermark.clone();
        state["window_ms"] = json!(window);
        if let Some(changed) = changed {
            state["window_changed_ms"] = json!(changed);
        }
        state
    };
    let settle = |prior: &Value, late: bool, now: i64| {
        let mut next = prior.clone();
        settle_ordered_window(prior, &mut next, late, now);
        next
    };
    let t0 = 1_800_000_000_000_i64;
    // A confirmed late row doubles the window and starts the quiet period.
    let widened = settle(&with(INITIAL_WINDOW_MS, None), true, t0);
    assert_eq!(widened, with(2 * INITIAL_WINDOW_MS, Some(t0)));
    // Further late rows keep doubling it, up to the ceiling.
    assert_eq!(
        settle(&with(MAX_WINDOW_MS, Some(t0)), true, t0 + 5),
        with(MAX_WINDOW_MS, Some(t0 + 5))
    );
    // Short of a quiet day nothing changes.
    let quiet = with(4 * INITIAL_WINDOW_MS, Some(t0));
    assert_eq!(settle(&quiet, false, t0 + WINDOW_DECAY_QUIET_MS - 1), quiet);
    // A quiet day halves it once and restarts the clock.
    let halved = settle(&quiet, false, t0 + WINDOW_DECAY_QUIET_MS);
    assert_eq!(
        halved,
        with(2 * INITIAL_WINDOW_MS, Some(t0 + WINDOW_DECAY_QUIET_MS))
    );
    // It never decays below the initial window.
    let floor = settle(
        &with(INITIAL_WINDOW_MS + 1, Some(t0)),
        false,
        t0 + WINDOW_DECAY_QUIET_MS,
    );
    assert_eq!(floor["window_ms"], json!(INITIAL_WINDOW_MS));
    // A wide window with no stamp (seeded, or widened before stamps were
    // kept) starts its quiet period now instead of halving at once.
    assert_eq!(
        settle(&with(MAX_WINDOW_MS, None), false, t0),
        with(MAX_WINDOW_MS, Some(t0))
    );
    // The initial window needs no stamp at all.
    assert_eq!(
        settle(&with(INITIAL_WINDOW_MS, None), false, t0),
        with(INITIAL_WINDOW_MS, None)
    );
}

/// Through the real poll path: a never-stored row well below the previous
/// watermark (late visibility under a server-side `since` filter) widens
/// the window and is counted for the watch, while a change to a stored
/// row's content that leaves its timestamp alone, such as a reaction
/// count, does not.
#[test]
fn ordered_poll_path_widens_only_on_a_row_that_arrived_late() {
    let b = json!({ "id": "b", "updated_at": "2024-01-15T10:00:50Z" });
    let (store, engine, transport) = ordered_poll_engine(json!({
        "items": [{ "id": "a", "updated_at": "2024-01-15T10:00:00Z", "reactions": 0 }, b]
    }));
    let subscription = store
        .subscribe("direct", "connection", "read_action", 30)
        .expect("subscribe")
        .expect("subscription");
    let id = subscription.subscription_id;
    let poller = Poller::new(engine);
    let stored = |store: &PlexusStore| {
        store
            .subscription("direct", &id)
            .expect("read")
            .expect("exists")
            .cursor_state
    };
    let late_rows = || poll_accounting_metrics()["lateRowsBySubscription"][&id].clone();
    assert!(matches!(
        poller.poll_once("direct", &id),
        PollCycle::Completed { inserted: 2, .. }
    ));
    assert_eq!(stored(&store)["window_ms"], json!(INITIAL_WINDOW_MS));

    // Row `a` sits 50 s below the watermark with new content but its own
    // stored timestamp: not late.
    transport.set_response(MockResponse::Success(json!({
        "items": [{ "id": "a", "updated_at": "2024-01-15T10:00:00Z", "reactions": 1 }, b]
    })));
    assert!(matches!(
        poller.poll_once("direct", &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    assert_eq!(stored(&store)["window_ms"], json!(INITIAL_WINDOW_MS));
    assert_eq!(late_rows(), Value::Null);

    // Row `c` was never seen and sits 40 s below the watermark: it became
    // visible after the previous poll had read past its timestamp.
    transport.set_response(MockResponse::Success(json!({
        "items": [{ "id": "c", "updated_at": "2024-01-15T10:00:10Z" }, b]
    })));
    assert!(matches!(
        poller.poll_once("direct", &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let cursor = stored(&store);
    assert_eq!(cursor["window_ms"], json!(2 * INITIAL_WINDOW_MS));
    assert!(cursor["window_changed_ms"].is_i64(), "{cursor}");
    assert_eq!(late_rows(), json!(1));
}

/// A transport whose calls block until the test opens the gate, so a probe
/// action call outlives its callback deadline.
struct GatedTransport {
    open: std::sync::Mutex<bool>,
    opened: std::sync::Condvar,
    calls: AtomicU64,
}

impl crate::transport::Transport for GatedTransport {
    fn dispatch(
        &self,
        _request: crate::transport::TransportRequest,
        _credential: &crate::credentials::ResolvedCredential,
    ) -> crate::transport::TransportResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.opened.wait(open).unwrap();
        }
        crate::transport::TransportResponse::success(json!(true))
    }
}

/// A probe action call abandoned at its deadline keeps running, because a
/// request on the wire cannot be recalled. Until it ends, the next poll of
/// that probe must not start a second call against the same vendor; once
/// it ends, polling resumes normally.
#[test]
fn an_abandoned_probe_call_blocks_the_next_poll_until_it_ends() {
    let (store, credentials) = poll_store_with_shape(json!({
        "item_kind": "issue",
        "cursor_kind": "sync_token"
    }));
    let transport = Arc::new(GatedTransport {
        open: std::sync::Mutex::new(false),
        opened: std::sync::Condvar::new(),
        calls: AtomicU64::new(0),
    });
    let engine = GovernanceEngine::new(store.clone(), Arc::new(credentials), transport.clone());
    let id = store
        .register_probe(
            "direct",
            "connection",
            crate::storage::ProbeRegistration {
                name: "slow-vendor",
                actions: &["read_action".to_string()],
                script_source: "() => invoke('read_action', {})",
                return_schema: &json!({"kind": "bool"}),
                rearm: "always",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({}),
            },
        )
        .expect("store")
        .expect("accepted")
        .subscription_id;
    let poller = Poller::new(engine);
    let calls = || transport.calls.load(Ordering::SeqCst);

    assert_eq!(
        poller.poll_once("direct", &id),
        PollCycle::Inconclusive {
            code: "probe_action_failed".to_string()
        }
    );
    wait_until("the abandoned call reaches the vendor", || calls() == 1);
    assert_eq!(
        poller.poll_once("direct", &id),
        PollCycle::Inconclusive {
            code: PROBE_ACTION_IN_FLIGHT.to_string()
        }
    );
    assert_eq!(calls(), 1, "a second call overlapped the abandoned one");

    *transport.open.lock().unwrap() = true;
    transport.opened.notify_all();
    wait_until("the abandoned call ends", || !ProbeCallInFlight::held(&id));
    assert!(matches!(
        poller.poll_once("direct", &id),
        PollCycle::Completed { .. }
    ));
    assert_eq!(calls(), 2);
}
