//! Ephemeral end-to-end poll accounting. Only cumulative counters leave memory.

use super::{CursorAdvance, TriggerEventInsertOutcome};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const SUBSCRIPTION_METRIC_CAP: usize = 4096;

/// Reasons observed at the strategy, replay filter, and insert-result boundaries.
/// A closed vocabulary constrains recorded reasons; the count identity detects
/// omissions from the ledger, which an enum alone cannot prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    OlderThanWatermark,
    InitialBaseline,
    UnchangedObservation,
    UnchangedBoundaryReplay,
    AlreadyDelivered,
}

impl DropReason {
    const ALL: [Self; 5] = [
        Self::OlderThanWatermark,
        Self::InitialBaseline,
        Self::UnchangedObservation,
        Self::UnchangedBoundaryReplay,
        Self::AlreadyDelivered,
    ];

    fn slot(self) -> usize {
        match self {
            Self::OlderThanWatermark => 0,
            Self::InitialBaseline => 1,
            Self::UnchangedObservation => 2,
            Self::UnchangedBoundaryReplay => 3,
            Self::AlreadyDelivered => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OlderThanWatermark => "olderThanWatermark",
            Self::InitialBaseline => "initialBaseline",
            Self::UnchangedObservation => "unchangedObservation",
            Self::UnchangedBoundaryReplay => "unchangedBoundaryReplay",
            Self::AlreadyDelivered => "alreadyDelivered",
        }
    }
}

struct Counters {
    examined: AtomicU64,
    inserted: AtomicU64,
    violations: AtomicU64,
    dropped: [AtomicU64; 5],
    /// Count, per subscription, of rows an ordered-timestamp watch saw late: a
    /// new row whose timestamp lies well below the watermark the previous poll
    /// reached, so it was not yet visible when that span was first read. The
    /// overlap window (the span each poll re-reads below its watermark) exists
    /// to catch such rows, and this map shows how often a watch needed it.
    /// Late rows are inserted like any other row and already counted as
    /// inserted, so this map is not a term in the check that the rows examined
    /// equal the rows inserted plus the rows dropped. At the
    /// metric cap, the entry with the lowest subscription id is evicted to
    /// make room.
    late_rows: Mutex<BTreeMap<String, u64>>,
    /// Connections whose credential needs a person to repair it (sign in
    /// again, replace a revoked or broken credential), keyed
    /// `principal/connection_id`, with the code dispatch reported. An entry
    /// is added by the first such failure and removed by the first successful
    /// poll on that connection. Bounded by the number of connections.
    credential_repair: Mutex<BTreeMap<String, String>>,
}

impl Counters {
    const fn new() -> Self {
        Self {
            examined: AtomicU64::new(0),
            inserted: AtomicU64::new(0),
            violations: AtomicU64::new(0),
            dropped: [const { AtomicU64::new(0) }; 5],
            late_rows: Mutex::new(BTreeMap::new()),
            credential_repair: Mutex::new(BTreeMap::new()),
        }
    }

    fn record_late_rows(&self, subscription_id: &str, count: usize) {
        let mut late_rows = self
            .late_rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !late_rows.contains_key(subscription_id) && late_rows.len() >= SUBSCRIPTION_METRIC_CAP {
            late_rows.pop_first();
        }
        *late_rows.entry(subscription_id.to_string()).or_default() += count as u64;
    }

    fn record(
        &self,
        examined: usize,
        dropped: &[(String, DropReason)],
        inserted: usize,
        balanced: bool,
    ) {
        self.examined.fetch_add(examined as u64, Ordering::Relaxed);
        self.inserted.fetch_add(inserted as u64, Ordering::Relaxed);
        self.violations
            .fetch_add(u64::from(!balanced), Ordering::Relaxed);
        let mut counts = [0u64; 5];
        for (_, reason) in dropped {
            counts[reason.slot()] += 1;
        }
        for (counter, count) in self.dropped.iter().zip(counts) {
            counter.fetch_add(count, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Value {
        let reasons: serde_json::Map<String, Value> = DropReason::ALL
            .into_iter()
            .map(|reason| {
                (
                    reason.label().to_string(),
                    json!(self.dropped[reason.slot()].load(Ordering::Relaxed)),
                )
            })
            .collect();
        let late_rows = self
            .late_rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let credential_repair = self
            .credential_repair
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        json!({
            "itemsExamined": self.examined.load(Ordering::Relaxed),
            "eventsInserted": self.inserted.load(Ordering::Relaxed),
            "identityViolations": self.violations.load(Ordering::Relaxed),
            "droppedByReason": reasons,
            "lateRowsBySubscription": late_rows,
            "credentialNeedsRepairByConnection": credential_repair,
        })
    }
}

static COUNTERS: Counters = Counters::new();

/// Mark `connection` (`principal/connection_id`) as needing credential repair
/// with `code`. Returns true when this changes the recorded state (a new
/// entry or a different code), so the caller logs each change once rather
/// than on every poll.
pub(super) fn mark_credential_repair(connection: &str, code: &str) -> bool {
    let mut repair = COUNTERS
        .credential_repair
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    repair
        .insert(connection.to_string(), code.to_string())
        .as_deref()
        != Some(code)
}

/// Clear a connection's credential-repair entry after a successful poll on it.
/// Returns the code it had, if any, so the caller can log the recovery once.
pub(super) fn clear_credential_repair(connection: &str) -> Option<String> {
    COUNTERS
        .credential_repair
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(connection)
}

/// Count ordered-timestamp rows that storage confirmed arrived late for one
/// subscription; exposed as `lateRowsBySubscription` in the metrics.
pub(super) fn record_late_rows(subscription_id: &str, count: usize) {
    COUNTERS.record_late_rows(subscription_id, count);
}

pub(crate) fn forget_subscription(subscription_id: &str) {
    COUNTERS
        .late_rows
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .remove(subscription_id);
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn late_row_metric_is_bounded_at_4097_subscriptions() {
        let counters = Counters::new();
        for id in 0..4097 {
            counters.record_late_rows(&format!("watch-{id:05}"), 1);
        }
        assert_eq!(
            counters.late_rows.lock().unwrap().len(),
            4096,
            "deleted watch keys must not grow metrics forever"
        );
    }
}

/// Process-lifetime counters for completed polls, including explicitly invoked
/// polls as well as scheduler polls. Atomic snapshots may overlap an update;
/// identityViolations is checked per poll, never inferred from snapshot totals.
pub fn poll_accounting_metrics() -> Value {
    COUNTERS.snapshot()
}

pub(super) fn account_insert_outcomes(
    advance: &mut CursorAdvance,
    outcomes: &[TriggerEventInsertOutcome],
) -> usize {
    account_outcomes(
        advance
            .events
            .iter()
            .map(|event| event.vendor_event_id.as_str()),
        outcomes,
        &mut advance.dropped,
    )
}

/// Record every insert-time duplicate as delivered already and return how many
/// events storage inserted. `event_ids` aligns positionally with `outcomes`.
fn account_outcomes<'a>(
    event_ids: impl IntoIterator<Item = &'a str>,
    outcomes: &[TriggerEventInsertOutcome],
    dropped: &mut Vec<(String, DropReason)>,
) -> usize {
    for (event_id, outcome) in event_ids.into_iter().zip(outcomes) {
        if matches!(outcome, TriggerEventInsertOutcome::Duplicate { .. }) {
            dropped.push((event_id.to_string(), DropReason::AlreadyDelivered));
        }
    }
    outcomes
        .iter()
        .filter(|outcome| matches!(outcome, TriggerEventInsertOutcome::Inserted { .. }))
        .count()
}

/// The ledger's own alarm, at the level its content asserts.
///
/// An identity violation means items were examined and then neither emitted nor
/// recorded as dropped: the ledger cannot account for events that existed, and
/// no counter, quiet window, or later poll recovers them. That needs a person,
/// which is what `error` says — the message used to carry the word itself,
/// before the line had a level that could.
///
/// A named function rather than an inline site because `check_identity` takes
/// its sink as an argument, which is the seam that lets a test capture the
/// rendered alarm.
fn identity_violation_alarm(args: std::fmt::Arguments<'_>) {
    eprintln!(error poller: "{args}");
}

/// The injected event sink keeps accounting testable without owning a subscriber.
/// The production fleet sink swallows write failures, preserving poll success.
fn check_identity(
    subscription_id: &str,
    examined: usize,
    inserted: usize,
    dropped: usize,
    log: &mut impl FnMut(std::fmt::Arguments<'_>),
) -> bool {
    let balanced = inserted.checked_add(dropped) == Some(examined);
    if !balanced {
        log(format_args!("poll_accounting_identity_violation subscription_id={subscription_id:?} items_examined={examined} events_emitted={inserted} dropped={dropped}"));
    }
    balanced
}

pub(super) fn record_completion(
    subscription_id: &str,
    advance: &mut CursorAdvance,
    outcomes: &[TriggerEventInsertOutcome],
) {
    let inserted = account_insert_outcomes(advance, outcomes);
    close_ledger(
        subscription_id,
        advance.items_examined,
        &advance.dropped,
        inserted,
    );
}

/// The ledger for a poll whose items are not a [`CursorAdvance`]: a CI cycle,
/// which examines run and job objects across several reads. `event_ids` align
/// with `outcomes`; `dropped` already holds the items that never became events.
pub(super) fn record_ledger<'a>(
    subscription_id: &str,
    items_examined: usize,
    event_ids: impl IntoIterator<Item = &'a str>,
    mut dropped: Vec<(String, DropReason)>,
    outcomes: &[TriggerEventInsertOutcome],
) {
    let inserted = account_outcomes(event_ids, outcomes, &mut dropped);
    close_ledger(subscription_id, items_examined, &dropped, inserted);
}

fn close_ledger(
    subscription_id: &str,
    items_examined: usize,
    dropped: &[(String, DropReason)],
    inserted: usize,
) {
    let balanced = check_identity(
        subscription_id,
        items_examined,
        inserted,
        dropped.len(),
        &mut identity_violation_alarm,
    );
    COUNTERS.record(items_examined, dropped, inserted, balanced);
    // Unit-test polls fail hard, while production always preserves poll success.
    #[cfg(test)]
    assert!(
        balanced,
        "poll accounting identity violated for {subscription_id}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_logging as logging;

    #[test]
    fn drop_ledger_violation_logs_without_panicking() {
        const TEST: &str =
            "poller::accounting::tests::drop_ledger_violation_logs_without_panicking";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            logging::init_child();
            assert!(!check_identity(
                "subscription-canary",
                4,
                1,
                2,
                &mut identity_violation_alarm
            ));
            assert!(check_identity("balanced", 4, 2, 2, &mut |_| panic!(
                "balanced ledger emitted an alarm"
            )));
            return;
        }
        let output = crate::test_http::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            std::time::Duration::from_secs(30),
            "poll accounting diagnostic test child",
        )
        .expect("run child");
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        let log = String::from_utf8(output.stderr).unwrap();
        let lines: Vec<_> = log
            .lines()
            .filter(|line| line.contains("poll_accounting_identity_violation"))
            .collect();
        assert_eq!(lines.len(), 1, "{log}");
        logging::assert_diagnostic(
            lines[0],
            cortexkit_log::ParsedLevel::Error,
            "plexus.poller",
            "poll_accounting_identity_violation subscription_id=\"subscription-canary\" items_examined=4 events_emitted=1 dropped=2",
        );
    }

    #[test]
    fn drop_ledger_counters_are_cumulative() {
        let counters = Counters::new();
        let advance = CursorAdvance {
            cursor_state: json!({}),
            events: Vec::new(),
            items_examined: 3,
            dropped: vec![
                ("a".into(), DropReason::AlreadyDelivered),
                ("b".into(), DropReason::AlreadyDelivered),
            ],
            coverage_gap: None,
        };
        counters.record(advance.items_examined, &advance.dropped, 1, true);
        counters.record(advance.items_examined, &advance.dropped, 0, false);
        assert_eq!(
            counters.snapshot(),
            json!({
                "itemsExamined": 6, "eventsInserted": 1, "identityViolations": 1,
                "droppedByReason": {"olderThanWatermark": 0, "initialBaseline": 0, "unchangedObservation": 0, "unchangedBoundaryReplay": 0, "alreadyDelivered": 4},
                "lateRowsBySubscription": {},
                "credentialNeedsRepairByConnection": {}
            })
        );
    }
}
