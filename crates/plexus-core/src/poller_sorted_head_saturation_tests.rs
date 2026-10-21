use super::*;

fn shape(page_size: u64) -> PollShape {
    let mut constants = std::collections::BTreeMap::new();
    constants.insert("perPage".to_string(), json!(page_size));
    constants.insert("direction".to_string(), json!("desc"));
    PollShape {
        cursor_kind: crate::manifest::CursorKind::SortedHead,
        token_field: None,
        request_token_field: None,
        items_field: None,
        timestamp_field: Some("updated_at".to_string()),
        tiebreaker_id_field: Some("number".to_string()),
        request_since_field: None,
        request_constants: Some(constants),
        scalar_field: None,
        item_count_ceiling: None,
        item_kind: "issue".to_string(),
        pagination: None,
        request_page_size_field: Some("perPage".to_string()),
    }
}

fn page(count: usize, start_day: u32) -> Value {
    Value::Array(
        (0..count)
            .map(|index| {
                json!({
                    "updated_at": format!(
                        "2026-08-{:02}T{:02}:{:02}:00Z",
                        start_day,
                        index / 60,
                        index % 60
                    ),
                    "number": 100 + index as i64
                })
            })
            .collect(),
    )
}

/// A SHORT page never reports truncation, however new its items are.
///
/// This is the production defect: the check asks whether every item beat the
/// watermark, which is evidence of a cut-short page only when the vendor had
/// no room to send more. A repository with fewer pull requests than one page
/// reported two coverage gaps in a day over windows containing zero and one
/// real changes -- a feed telling its consumer it had holes that did not
/// exist.
///
/// Both arms, because a fix that simply stopped reporting gaps would pass the
/// first assertion alone and destroy the guard.
#[test]
fn only_a_full_page_can_report_truncation() {
    let strategy = SortedHeadStrategy::new(Some(&shape(100))).expect("strategy");
    let watermark = json!({
        WATERMARK_MS_KEY: iso8601::parse_to_millis("2026-08-01T00:00:00Z").expect("parse"),
        WATERMARK_ID_KEY: "1"
    });

    // SHORT page, every item newer than the watermark: the vendor sent its
    // whole collection, so nothing can lie beyond the edge.
    let short = strategy
        .derive(&watermark, &page(3, 10))
        .expect("derive short page");
    assert_eq!(
        short.coverage_gap, None,
        "a page shorter than the cap is the complete answer and must not report a gap"
    );
    assert_eq!(short.events.len(), 3, "the items are still delivered");

    // FULL page, same condition: now truncation is genuinely possible.
    let full = strategy
        .derive(&watermark, &page(100, 10))
        .expect("derive full page");
    assert!(
        full.coverage_gap.is_some(),
        "a full page whose oldest item beats the watermark must still report truncation"
    );
}

/// A shape with no declared page cap is REFUSED rather than defaulted.
///
/// A default would restore the false-gap behaviour: any guess about the cap
/// is wrong for some vendor, and guessing high makes every page look short
/// (never reporting real truncation) while guessing low makes every page look
/// full (reporting it constantly).
#[test]
fn a_shape_without_a_page_cap_is_refused() {
    let mut without = shape(100);
    without.request_page_size_field = None;
    assert!(
        SortedHeadStrategy::new(Some(&without)).is_none(),
        "no declared cap must refuse the strategy rather than default one"
    );

    let mut zero = shape(0);
    assert!(
        SortedHeadStrategy::new(Some(&zero)).is_none(),
        "a zero cap must be refused: every page would look full"
    );
    zero.request_page_size_field = Some("absent".to_string());
    assert!(
        SortedHeadStrategy::new(Some(&zero)).is_none(),
        "naming a key that request_constants does not carry must be refused"
    );
}
