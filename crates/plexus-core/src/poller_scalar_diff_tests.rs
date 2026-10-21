use super::*;

fn scalar_shape() -> PollShape {
    PollShape {
        cursor_kind: crate::manifest::CursorKind::ScalarDiff,
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
        request_constants: None,
        scalar_field: Some("tag_name".to_string()),
    }
}

fn scalar_strategy() -> ScalarDiffStrategy {
    ScalarDiffStrategy::new(Some(&scalar_shape())).expect("scalar strategy")
}

/// The whole shape in one vector: baseline on first sight, silence while
/// unchanged, one event on change.
///
/// All three legs matter and they fail in opposite directions. Emitting on
/// the first observation would announce a release that may be weeks old as
/// news. Emitting while unchanged would fire on every tick forever, since
/// the value is re-read each cycle rather than being consumed. Emitting
/// nothing on change is the watch silently not working -- the failure this
/// whole design exists to prevent, and the one that reads as a quiet period.
///
/// Mutation-proved: treating an absent predecessor as a change fails the
/// baseline leg; comparing with `!=` inverted fails the unchanged leg;
/// returning no events unconditionally fails the change leg.
#[test]
fn a_scalar_baselines_then_emits_only_on_change() {
    let strategy = scalar_strategy();

    // Leg 1: no stored predecessor. The value is recorded, nothing is
    // emitted -- the subscriber asked to hear about CHANGES and nothing has
    // changed yet.
    let advance = strategy
        .derive(&json!({}), &json!({"tag_name": "v1.0.0", "id": 1}))
        .expect("first observation derives");
    assert!(
        advance.events.is_empty(),
        "a first observation with no threshold must baseline rather than emit: {:?}",
        advance.events
    );
    assert_eq!(
        advance.cursor_state,
        json!({"scalar": "v1.0.0", "scalar_ordinal": 0}),
        "the observed value must be stored so the next poll can compare"
    );

    // Leg 2: same value again. A cursor would advance; this must not speak.
    let advance = strategy
        .derive(
            &advance.cursor_state,
            &json!({"tag_name": "v1.0.0", "id": 1}),
        )
        .expect("unchanged observation derives");
    assert!(
        advance.events.is_empty(),
        "an unchanged scalar must emit nothing, or the watch fires every tick"
    );

    // Leg 3: the value moves. One event, carrying the whole response so a
    // consumer can render it without a second call.
    let advance = strategy
        .derive(
            &advance.cursor_state,
            &json!({"tag_name": "v1.1.0", "id": 2}),
        )
        .expect("changed observation derives");
    assert_eq!(advance.events.len(), 1, "a changed scalar must emit once");
    assert_eq!(
        advance.events[0].vendor_event_id, "1:v1.1.0",
        "the event identity must distinguish the transition as well as its value"
    );
    assert_eq!(
        advance.events[0].payload,
        json!({"tag_name": "v1.1.0", "id": 2}),
        "the payload must carry the whole vendor response"
    );
    assert_eq!(
        advance.cursor_state,
        json!({"scalar": "v1.1.0", "scalar_ordinal": 1})
    );
}

/// A seeded scalar is the threshold, and it makes the first observation
/// meaningful rather than silent.
///
/// This is how "tell me when it goes past X" is expressed without a new
/// field: `subscribe` already accepts a starting cursor state, so seeding
/// the scalar states the value the subscriber has already seen. Without this
/// leg, baseline-on-first would be indistinguishable from ignoring the seed.
#[test]
fn a_seeded_scalar_emits_on_the_first_poll_when_it_has_already_moved() {
    let strategy = scalar_strategy();
    let advance = strategy
        .derive(&json!({"scalar": "v1.0.0"}), &json!({"tag_name": "v2.0.0"}))
        .expect("seeded observation derives");
    assert_eq!(
        advance.events.len(),
        1,
        "a seeded watch whose value already moved must report on its first poll"
    );
    assert_eq!(advance.events[0].vendor_event_id, "1:v2.0.0");
}

/// A missing or null scalar field is refused, never read as "unchanged".
///
/// The two are indistinguishable downstream -- both leave the log quiet --
/// so a misdeclared field name would make the watch report healthy silence
/// forever while observing nothing. Refusing turns a silent misconfiguration
/// into a vendor failure the scheduler backs off and reports.
///
/// Mutation-proved: returning the stored state unchanged instead of an error
/// fails both legs.
#[test]
fn an_absent_or_null_scalar_is_refused_rather_than_read_as_unchanged() {
    let strategy = scalar_strategy();
    let error = strategy
        .derive(&json!({}), &json!({"name": "v1.0.0"}))
        .expect_err("a response without the declared field must refuse");
    assert!(
        matches!(error, CursorError::InvalidResponse(ref message) if message.contains("tag_name")),
        "the refusal must name the field the manifest declared: {error:?}"
    );

    let error = strategy
        .derive(&json!({}), &json!({"tag_name": null}))
        .expect_err("a null value must refuse");
    assert!(
        matches!(error, CursorError::InvalidResponse(ref message) if message.contains("null")),
        "a null scalar must be refused as uncomparable: {error:?}"
    );
}

/// The strategy requires its declared field and owns no request keys.
///
/// No default is possible for the field: a wrong name reads as unchanged
/// forever. And owning no keys is what makes this shape different from a
/// cursor -- there is no window argument a subscription could collide with,
/// so `fixed_args` may carry anything the vendor's schema accepts.
#[test]
fn the_strategy_needs_its_field_and_reserves_no_request_keys() {
    assert!(
        ScalarDiffStrategy::new(None).is_none(),
        "no poll shape means no strategy"
    );
    let mut bare = scalar_shape();
    bare.scalar_field = None;
    assert!(
        ScalarDiffStrategy::new(Some(&bare)).is_none(),
        "a shape without scalar_field must not resolve to a guessing strategy"
    );
    bare.scalar_field = Some("   ".to_string());
    assert!(
        ScalarDiffStrategy::new(Some(&bare)).is_none(),
        "a blank field name must not resolve either"
    );

    assert!(
        strategy_for("scalar_diff", Some(&scalar_shape())).is_some(),
        "the kind must be reachable through the resolver the poller uses"
    );
    assert!(
        strategy_for("scalar_diff", None).is_none(),
        "the resolver must refuse the kind without a declared shape"
    );
    assert_eq!(
        scalar_strategy().state_keys(),
        vec!["scalar", "scalar_ordinal"]
    );
    assert!(
        scalar_strategy().owned_keys().is_empty(),
        "a shape with no window owns no request keys"
    );
    assert_eq!(
        scalar_strategy()
            .build_args(&json!({"scalar": "v1.0.0"}))
            .expect("build args"),
        json!({}),
        "the request must carry no cursor arguments at all"
    );
}
