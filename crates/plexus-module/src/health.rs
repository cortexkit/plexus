//! Health-v2 reports for the wire control lane are generated independently of transport operations.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use subc_protocol::session::{HealthStatus, ModuleControlResponse};

const HEARTBEAT_STALE_MS: u64 = 2_000;
/// Healthy passes normally finish in well under a second, with occasional
/// outliers of a few seconds, so three full subscription cadences
/// leave orders of magnitude for vendor jitter while still surfacing a total-
/// success outage long before it can run for hours.
const SCHEDULER_STALL_CADENCES: u64 = 3;
const MILLIS_PER_SECOND: u64 = 1_000;
/// Smallest wall-versus-monotonic divergence accepted as a host suspension.
///
/// While the process is running the two clocks advance together, so a healthy
/// module measures zero here no matter how slow a pass is. The margin only has
/// to cover coarse clock reads and small wall-clock corrections such as an NTP
/// step; a real suspend lasts minutes or hours, orders of magnitude larger.
///
/// Divergence below the margin is deliberately left UNCLAIMED rather than
/// absorbed into the reference: a run of brief suspends keeps accumulating
/// until it is worth reporting, instead of being swallowed a few seconds at a
/// time and never showing up anywhere.
const HOST_SUSPENSION_MIN_MS: u64 = 5_000;
const MILLIS_PER_MINUTE: f64 = 60_000.0;
/// How long, in awake time, health stays degraded after a report first sees
/// the transports' panic-recovery count rise.
///
/// A recovery means a thread panicked while it held a vendor connection's
/// lock. The transport healed the connection, so the module keeps serving,
/// but the panic is a defect someone should read about in the transport log.
/// Degrading until a restart would page for a condition that has already
/// cleared; never degrading would hide it behind a counter. An hour spans many
/// supervisor health checks, so a recovery is seen, and then the module
/// returns to ok by itself while the cumulative count stays in the metrics.
const PANIC_RECOVERY_DEGRADED_MS: u64 = 60 * 60 * 1_000;

/// How many connections each vendor transport has healed after a panic
/// poisoned a connection lock, since the transport was built (at boot).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportPanicRecoveries {
    pub mcp: u64,
    pub rest: u64,
}

impl TransportPanicRecoveries {
    fn total(self) -> u64 {
        self.mcp.saturating_add(self.rest)
    }
}

/// Reads the connections whose credential needs a person to repair it: keys
/// are `principal/connection_id`, values the refusal code the failed poll got
/// (for example `credential_missing`).
type CredentialRepairSource = Box<dyn Fn() -> BTreeMap<String, String> + Send + Sync>;

pub struct HealthState {
    pub(crate) relay: Arc<crate::relay::Status>,
    pub(crate) store_metrics: std::sync::Mutex<serde_json::Value>,
    publish_error: std::sync::Mutex<Option<String>>,
    started_at_ms: u64,
    /// Wall-clock instant when the dispatch loop last showed it was responsive.
    /// This drives the operator-facing age gauge, not the health verdict.
    last_heartbeat_ms: AtomicU64,
    /// Awake-clock instant for the same heartbeat.
    ///
    /// `Instant` does not advance while this host is suspended, so subtracting
    /// this stamp from the current awake clock excludes every sleep without a
    /// wake-specific reset that repeated suspensions could keep advancing.
    last_heartbeat_awake_ms: AtomicU64,
    /// Whether the trigger scheduler task is still running.
    ///
    /// The scheduler runs on its own task precisely so a slow vendor cannot
    /// stall the dispatch loop, which means the dispatch heartbeat says nothing
    /// about it: if that task dies, polling stops permanently and every health
    /// report stays `ok`. A trigger that silently delivers nothing is the exact
    /// failure this plane is built to avoid, so the liveness of the task has to
    /// be observable on its own.
    scheduler_alive: AtomicBool,
    /// Connection counts observed by the last health probe, and whether a probe
    /// has ever run.
    ///
    /// The flag is not redundant. Without it an unprobed module reports zero
    /// connections, which is indistinguishable from a module that genuinely has
    /// none — the same false-zero that makes "nothing checked" read as "nothing
    /// wrong". Unobserved is reported as null instead, so a reader can tell the
    /// two apart.
    ///
    /// Stamped by the probe rather than computed here, because `report` must
    /// stay free of store access: it answers a control frame handled inline on
    /// the dispatch loop, and the report is a freshness check on that very
    /// loop.
    connections_observed: AtomicBool,
    connections_total: AtomicU64,
    connections_degraded: AtomicU64,
    /// When the scheduler last began a pass. Reported as a metric only, never
    /// as a verdict — a pass is sequential over subscriptions and each poll can
    /// legitimately take tens of seconds against a slow vendor, so any staleness
    /// threshold would eventually fire on a scheduler that is working correctly.
    /// It exists to diagnose a WEDGED pass, which the liveness flag cannot see
    /// because a stuck task is still a live one.
    last_scheduler_pass_ms: AtomicU64,
    /// What the scheduler's passes have PRODUCED, as opposed to whether they
    /// ran.
    ///
    /// `scheduler_alive` proves the task exists and `last_scheduler_pass_ms`
    /// proves it is ticking. Neither can tell a scheduler doing useful work
    /// from one that wakes every tick and accomplishes nothing: a poller
    /// refusing every subscription reports identically to an idle one, because
    /// the steady state of total failure looks like the steady state of no
    /// demand.
    ///
    /// Counted as attempted-and-completed rather than classified by failure
    /// reason, because the useful reading needs no judgement about WHY.
    /// Quota deferrals count as neither attempted nor completed: they wait for
    /// admission, not vendor progress. Nothing attempted is honest idleness; many
    /// attempted beside zero completed is the state that was previously
    /// invisible.
    scheduler_polls_attempted: AtomicU64,
    /// Polls attempted without completing since the last pass that completed
    /// one. The stall verdict reads this, not the cumulative counters: those
    /// keep an early failure forever, so a single failed poll at boot would
    /// later turn any quiet stretch (quota deferrals, say) into a stall.
    scheduler_uncompleted_since_success: AtomicU64,
    scheduler_selection_failures: AtomicU64,
    /// Current subscriptions that are active rather than suspended.
    ///
    /// The outcome counters are cumulative and survive an unsubscribe or
    /// circuit-breaker suspension. Without the current count, an old failure
    /// would eventually degrade an idle module even though no work remains.
    scheduler_active_subscriptions: AtomicU64,
    /// Longest cadence among the current active subscriptions, in milliseconds.
    ///
    /// Refreshed beside the active count after every scheduler pass so adding or
    /// removing a slower watch immediately changes the no-success allowance.
    /// Zero is stored only by the explicit no-active-subscriptions arm; the count
    /// suppresses the verdict in that state because an empty set has no maximum.
    scheduler_max_active_cadence_ms: AtomicU64,
    /// Longest observed duration of a pass that polled at least one
    /// subscription.
    ///
    /// Paired with a separate observed flag rather than using zero as the
    /// "never happened" sentinel: a pass whose polls all fail fast genuinely
    /// completes in under a millisecond, so zero is a REAL measurement here and
    /// a sentinel that collides with it reports a working scheduler as one that
    /// has never run. Same reasoning as `scheduler_ever_completed` beside it.
    scheduler_pass_max_ms: AtomicU64,
    /// Duration of the MOST RECENT pass that polled at least one subscription.
    ///
    /// Read beside the maximum, never instead of it. A max-since-boot is
    /// monotonic, so one legitimate outlier pins it for the life of the process
    /// and it then describes history rather than the present.
    scheduler_pass_last_ms: AtomicU64,
    /// Whether any pass has polled at least one subscription. Distinguishes a
    /// measured zero from an absent measurement.
    scheduler_pass_observed: AtomicBool,
    scheduler_polls_completed: AtomicU64,
    /// When a poll last completed, and whether one ever has.
    ///
    /// Null until the first success, for the same reason the connection counts
    /// are: reporting a start timestamp would make "never succeeded" render
    /// identically to "succeeded at boot", which is the false-zero this gauge
    /// exists to remove.
    scheduler_ever_completed: AtomicBool,
    /// Wall-clock instant of the last completed poll. This remains the source
    /// for `schedulerSuccessAgeMs`, including time spent asleep.
    last_scheduler_success_ms: AtomicU64,
    /// Awake-clock instant of the last completed poll. Only this companion
    /// stamp feeds the scheduler stall verdict.
    last_scheduler_success_awake_ms: AtomicU64,
    /// Wall-clock milliseconds minus monotonic milliseconds, as of the last
    /// sample accepted as a suspension boundary.
    ///
    /// A suspended host stops the monotonic clock and does not stop the wall
    /// clock, so this difference is constant for as long as the process keeps
    /// running and JUMPS by the suspended duration across a sleep. That jump is
    /// the only available evidence that the machine was away: from inside the
    /// process a suspend is indistinguishable from time passing, and the stall
    /// alarm below was counting it as time the poller failed to make progress.
    ///
    /// On macOS, Rust's `Instant` reads `CLOCK_UPTIME_RAW`, which stops while
    /// the machine sleeps, so after a night asleep a laptop's uptime clock can
    /// trail the wall clock by many hours.
    ///
    /// Kept as one DIFFERENCE rather than a pair of timestamps for two reasons.
    /// A single atomic can be advanced with a compare-exchange, so a scheduler
    /// tick and a health report checking at the same moment cannot both claim
    /// one jump and each see half of it. And because both clocks advance during
    /// a slow pass, a pass cannot look like a suspension however long it runs —
    /// which matters, because a pass can take tens of seconds when a vendor is
    /// slow, and a detector that timed whole loop iterations would silence the stall
    /// alarm during exactly the degradation it exists to catch.
    wall_minus_monotonic_ms: AtomicU64,
    /// Whether the outbox drain task has ended. Like the scheduler, it runs on
    /// its own task, so the dispatch heartbeat says nothing about it; a drain
    /// that died would otherwise leave every report `ok` while no event notice
    /// is ever published again.
    outbox_drain_stopped: AtomicBool,
    /// Outbox rows the drain found it can never publish and now skips.
    outbox_unpublishable: AtomicU64,
    /// Origin for the monotonic half of the sample above. Never used as a wall
    /// clock: it deliberately does not count suspended time. Verdict stamps use
    /// the same elapsed clock, anchored numerically at `started_at_ms` so tests
    /// can move a reference into the past without waiting through a threshold.
    monotonic_origin: Instant,
    /// The highest combined transport panic-recovery count a report has seen.
    /// Transports are built at boot with a count of zero, so this starts there.
    transport_panic_recoveries_seen: AtomicU64,
    /// Awake-clock instant at which a report last saw that count rise, valid
    /// once `panic_recovery_observed` is set.
    last_panic_recovery_awake_ms: AtomicU64,
    panic_recovery_observed: AtomicBool,
    /// Where the report reads connections whose credential needs repair.
    ///
    /// Injected rather than read directly, because production's source is
    /// the poller's process-wide accounting: tests run many modules in one
    /// process, and a credential failure one test provokes on purpose must
    /// not degrade another test's health report. `None` reads as no
    /// connection needing repair.
    credential_repair_source: Option<CredentialRepairSource>,
}

impl HealthState {
    pub fn record_publish_error(&self, error: impl Into<String>) {
        *self.publish_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(error.into());
    }
    pub fn clear_publish_error(&self) {
        *self.publish_error.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
    pub fn last_publish_error(&self) -> Option<String> {
        self.publish_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn new() -> Self {
        let monotonic_origin = Instant::now();
        let now = now_ms();
        Self {
            relay: Arc::new(crate::relay::Status::default()),
            store_metrics: std::sync::Mutex::new(serde_json::json!({})),
            publish_error: std::sync::Mutex::new(None),
            started_at_ms: now,
            last_heartbeat_ms: AtomicU64::new(now),
            last_heartbeat_awake_ms: AtomicU64::new(now),
            scheduler_alive: AtomicBool::new(true),
            connections_observed: AtomicBool::new(false),
            connections_total: AtomicU64::new(0),
            connections_degraded: AtomicU64::new(0),
            last_scheduler_pass_ms: AtomicU64::new(now),
            scheduler_polls_attempted: AtomicU64::new(0),
            scheduler_uncompleted_since_success: AtomicU64::new(0),
            scheduler_selection_failures: AtomicU64::new(0),
            scheduler_active_subscriptions: AtomicU64::new(0),
            scheduler_max_active_cadence_ms: AtomicU64::new(0),
            scheduler_pass_max_ms: AtomicU64::new(0),
            scheduler_pass_last_ms: AtomicU64::new(0),
            scheduler_pass_observed: AtomicBool::new(false),
            scheduler_polls_completed: AtomicU64::new(0),
            scheduler_ever_completed: AtomicBool::new(false),
            last_scheduler_success_ms: AtomicU64::new(now),
            last_scheduler_success_awake_ms: AtomicU64::new(now),
            wall_minus_monotonic_ms: AtomicU64::new(now),
            outbox_drain_stopped: AtomicBool::new(false),
            outbox_unpublishable: AtomicU64::new(0),
            monotonic_origin,
            transport_panic_recoveries_seen: AtomicU64::new(0),
            last_panic_recovery_awake_ms: AtomicU64::new(0),
            panic_recovery_observed: AtomicBool::new(false),
            credential_repair_source: None,
        }
    }

    /// Degrade health while `source` names any connection whose credential
    /// needs a person to repair it.
    pub fn with_credential_repair_source(
        mut self,
        source: impl Fn() -> BTreeMap<String, String> + Send + Sync + 'static,
    ) -> Self {
        self.credential_repair_source = Some(Box::new(source));
        self
    }

    /// Production's credential-repair source: the poller's
    /// `credentialNeedsRepairByConnection` metric. The poller adds a connection
    /// when a poll on it fails because its credential is missing, permanently
    /// unusable, or needs the user to sign in again, and removes it after the next
    /// successful poll on that connection.
    pub fn with_poller_credential_repair(self) -> Self {
        self.with_credential_repair_source(|| {
            credential_repair_from_poll_accounting(&plexus_core::poller::poll_accounting_metrics())
        })
    }

    pub fn stamp_heartbeat(&self) {
        self.stamp_heartbeat_at(now_ms(), self.awake_ms());
    }

    fn stamp_heartbeat_at(&self, wall_ms: u64, awake_ms: u64) {
        self.last_heartbeat_ms.store(wall_ms, Ordering::Relaxed);
        self.last_heartbeat_awake_ms
            .store(awake_ms, Ordering::Release);
    }

    /// Push both views of the dispatch heartbeat into the past, so a test can
    /// reach the stale branch without sleeping through the real threshold.
    #[cfg(test)]
    pub(crate) fn backdate_heartbeat(&self, by_ms: u64) {
        self.last_heartbeat_ms
            .store(now_ms().saturating_sub(by_ms), Ordering::Relaxed);
        self.last_heartbeat_awake_ms
            .store(self.awake_ms().saturating_sub(by_ms), Ordering::Release);
    }

    /// Read the awake-clock heartbeat reference exactly as stored. A stamp the
    /// clock can never reach would hold every later age at zero and permanently
    /// disarm the only witness to a wedged dispatch loop.
    #[cfg(test)]
    pub(crate) fn heartbeat_awake_stamp_ms(&self) -> u64 {
        self.last_heartbeat_awake_ms.load(Ordering::Acquire)
    }

    /// Record what the health probe saw, so an operator can confirm a claim
    /// about connector state rather than take it on someone's reading.
    pub fn stamp_connections(&self, total: u64, degraded: u64) {
        self.connections_total.store(total, Ordering::Relaxed);
        self.connections_degraded.store(degraded, Ordering::Relaxed);
        // Set LAST: a reader that sees the flag must find both counts already
        // written, never a total from this probe beside a degraded count from
        // the previous one.
        self.connections_observed.store(true, Ordering::Release);
    }

    /// Record that the scheduler began a pass.
    pub fn stamp_scheduler_pass(&self) {
        self.last_scheduler_pass_ms
            .store(now_ms(), Ordering::Relaxed);
    }

    /// Record how long a pass that actually polled something took.
    ///
    /// The scheduler polls its due subscriptions SEQUENTIALLY, which is
    /// deliberate: it makes the no-overlap requirement structural instead of
    /// needing a lease per subscription. The cost is head-of-line blocking --
    /// one wedged vendor holds its full request timeout and every subscription
    /// behind it waits, so the last one waits N times that in the worst case.
    ///
    /// At two subscriptions that trade is obviously right; at twenty it is
    /// obviously wrong; and nothing measured where the line falls, so the
    /// question could only be argued from intuition. This is the cheap half of
    /// answering it: the expensive half would be a concurrent poller, which is
    /// the machinery the sequential design exists to avoid, and it should not be
    /// built before the numbers say it is needed.
    ///
    /// The MAXIMUM is kept rather than an average, because the failure this
    /// exists to catch is one slow vendor rather than a uniformly slow fleet,
    /// and an average over mostly-empty passes hides exactly that.
    ///
    /// Passes that polled NOTHING are excluded. With a 300s cadence most passes
    /// are empty and take microseconds, so including them would drag any
    /// aggregate toward zero and make a real stall look like noise.
    ///
    /// THE LAST PASS IS RECORDED BESIDE THE MAXIMUM, and the max alone is why.
    /// A max-since-boot is monotonic, so ONE legitimate outlier pins it for the
    /// life of the process and it reports that number forever regardless of what
    /// the scheduler is doing now. A first poll that backfills dozens of pull
    /// requests can set it to several seconds, and many polls later it still
    /// reads that value -- the gauge built to answer "are passes getting
    /// slow?" could no longer answer it, because its worst case had already
    /// happened and was not a problem.
    ///
    /// Neither number is sufficient alone and they fail in opposite directions.
    /// The max cannot show the present; the last pass cannot show a stall that
    /// happened between reads. Together they separate "one slow pass once" from
    /// "slow right now", which is the distinction an operator needs before
    /// deciding whether the sequential poller has stopped being the right trade.
    pub fn stamp_scheduler_pass_duration(&self, polled: u64, elapsed_ms: u64) {
        if polled == 0 {
            return;
        }
        self.scheduler_pass_max_ms
            .fetch_max(elapsed_ms, Ordering::Relaxed);
        // STORED, not max-ed. This gauge exists precisely because the maximum
        // beside it is monotonic and goes stale: one legitimate outlier pins the
        // max for the life of the process, so a second monotonic gauge would
        // duplicate the blindness rather than fix it.
        self.scheduler_pass_last_ms
            .store(elapsed_ms, Ordering::Relaxed);
        // Published AFTER both durations, so a reader that sees the flag set is
        // guaranteed to see them behind it. The reverse order would leave a
        // window where the gauge claims an observation it cannot yet show.
        self.scheduler_pass_observed.store(true, Ordering::Release);
    }

    /// Record the current active set and its longest cadence after a scheduler pass.
    pub fn stamp_scheduler_subscription_count(&self, active: u64, max_cadence_s: u64) {
        debug_assert!(active > 0);
        debug_assert!(max_cadence_s > 0);
        self.scheduler_max_active_cadence_ms.store(
            max_cadence_s.saturating_mul(MILLIS_PER_SECOND),
            Ordering::Relaxed,
        );
        // Publish the count last so a reader that observes work also observes
        // the cadence measured from that same active set.
        self.scheduler_active_subscriptions
            .store(active, Ordering::Release);
    }

    /// Record an explicitly empty active set. There is no maximum cadence to
    /// choose in this state, and the zero count suppresses the stall predicate.
    pub fn stamp_scheduler_no_active_subscriptions(&self) {
        self.scheduler_active_subscriptions
            .store(0, Ordering::Release);
        self.scheduler_max_active_cadence_ms
            .store(0, Ordering::Relaxed);
    }

    /// Record what one pass produced: how many subscriptions it polled and how
    /// many of those reached the vendor and committed.
    ///
    /// Cumulative rather than last-pass-only, because a single pass is a poor
    /// sample: with a 300s cadence most passes legitimately poll nothing, so a
    /// last-pass gauge reads zero-of-zero almost always and carries no signal.
    /// Totals since boot let a reader see the ratio that matters.
    /// Callers use `PassReport::poll_counts`, which excludes quota deferrals.
    pub fn stamp_scheduler_outcomes(&self, attempted: u64, completed: u64) {
        self.stamp_scheduler_outcomes_at(attempted, completed, now_ms(), self.awake_ms());
    }

    /// Replace the last-pass gauge even on an empty pass: a successful selection
    /// retry must clear the alarm without requiring a vendor poll to complete.
    pub fn stamp_scheduler_selection_failures(&self, failures: u64) {
        self.scheduler_selection_failures
            .store(failures, Ordering::Relaxed);
    }

    fn stamp_scheduler_outcomes_at(
        &self,
        attempted: u64,
        completed: u64,
        wall_ms: u64,
        awake_ms: u64,
    ) {
        if attempted == 0 {
            return;
        }
        self.scheduler_polls_attempted
            .fetch_add(attempted, Ordering::Relaxed);
        let uncompleted = attempted.saturating_sub(completed);
        if completed > 0 {
            // A pass that completed a poll starts the count over; only its
            // own failures remain.
            self.scheduler_uncompleted_since_success
                .store(uncompleted, Ordering::Relaxed);
        } else {
            self.scheduler_uncompleted_since_success
                .fetch_add(uncompleted, Ordering::Relaxed);
        }
        if completed > 0 {
            self.scheduler_polls_completed
                .fetch_add(completed, Ordering::Relaxed);
            self.last_scheduler_success_ms
                .store(wall_ms, Ordering::Relaxed);
            self.last_scheduler_success_awake_ms
                .store(awake_ms, Ordering::Release);
            // Set LAST, so a reader seeing the flag finds both timestamps already
            // written rather than the boot values.
            self.scheduler_ever_completed.store(true, Ordering::Release);
        }
    }

    /// Record how many outbox rows the drain currently skips as unpublishable.
    pub fn stamp_outbox_unpublishable(&self, rows: u64) {
        self.outbox_unpublishable.store(rows, Ordering::Relaxed);
    }

    /// Move both scheduler last-success references into the past so tests can
    /// cross the cadence-derived stall threshold without sleeping.
    #[cfg(test)]
    pub(crate) fn backdate_scheduler_success(&self, by_ms: u64) {
        self.last_scheduler_success_ms
            .store(now_ms().saturating_sub(by_ms), Ordering::Relaxed);
        self.last_scheduler_success_awake_ms
            .store(self.awake_ms().saturating_sub(by_ms), Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn scheduler_success_awake_stamp_ms(&self) -> u64 {
        self.last_scheduler_success_awake_ms.load(Ordering::Acquire)
    }

    /// Notice a host suspension that ended since the last check and report how
    /// long the host was away.
    ///
    /// WHY THIS EXISTS: on a laptop that keeps going to sleep, the stall alarm
    /// fires again and again. Every report is true (no poll has completed) and
    /// none is actionable, because nobody can poll a vendor
    /// from a suspended machine and the module recovers by itself on wake. An
    /// alarm that fires on a healthy module gets ignored, and the next genuine
    /// silent outage would arrive to an audience trained to ignore it.
    ///
    /// The suspension is detected as DIVERGENCE between the wall clock and the
    /// monotonic clock, which is available because `Instant` does not count
    /// suspended time (see `wall_minus_monotonic_ms`). Divergence is the right
    /// measurement rather than merely a convenient one: a slow pass advances
    /// both clocks equally, so even a pass of a minute or more cannot be
    /// mistaken for a sleep and cannot mute the alarm.
    ///
    /// The detector no longer adjusts either health arm. Both verdicts subtract
    /// stamps on the monotonic awake clock directly, so there is no per-wake
    /// baseline for a dense sequence of suspensions to keep resetting. The
    /// detector remains because the suspension is LOGGED rather than quietly
    /// absorbed. Time that
    /// disappears from a health signal with nothing said about it is the same
    /// defect one layer down, so an operator reading a gap in the record can
    /// find the line that says where it went.
    pub fn note_host_suspension(&self) -> Option<u64> {
        self.note_host_suspension_at(now_ms(), self.monotonic_elapsed_ms())
    }

    fn monotonic_elapsed_ms(&self) -> u64 {
        self.monotonic_origin
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }

    fn awake_ms(&self) -> u64 {
        self.awake_ms_at(self.monotonic_elapsed_ms())
    }

    fn awake_ms_at(&self, monotonic_elapsed_ms: u64) -> u64 {
        self.started_at_ms.saturating_add(monotonic_elapsed_ms)
    }

    /// The clock arithmetic behind `note_host_suspension`, taking both samples
    /// as arguments so a test can present a timeline without sleeping a machine.
    fn note_host_suspension_at(&self, wall_ms: u64, monotonic_ms: u64) -> Option<u64> {
        let offset_ms = wall_ms.saturating_sub(monotonic_ms);
        let previous_ms = self.wall_minus_monotonic_ms.load(Ordering::Relaxed);
        // Saturating, so a wall clock that steps BACKWARD reads as no
        // suspension and leaves the reference where it is. That avoids
        // inventing a suspension duration from a clock correction.
        let suspended_ms = offset_ms.saturating_sub(previous_ms);
        if suspended_ms < HOST_SUSPENSION_MIN_MS {
            return None;
        }
        if self
            .wall_minus_monotonic_ms
            .compare_exchange(previous_ms, offset_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            // A concurrent caller already claimed and is logging this jump.
            // Claiming it twice would report one sleep as two shorter ones.
            return None;
        }
        eprintln!(info health:
            "host was suspended for {suspended_ms}ms ({:.1} minutes); \
             scheduler stall and dispatch heartbeat verdicts measure awake time",
            suspended_ms as f64 / MILLIS_PER_MINUTE
        );
        Some(suspended_ms)
    }

    /// Place the clock reference at an exact sample pair, so a test can state
    /// both clock readings instead of working around whatever the real ones say.
    #[cfg(test)]
    pub(crate) fn seed_clock_sample(&self, wall_ms: u64, monotonic_ms: u64) {
        self.wall_minus_monotonic_ms
            .store(wall_ms.saturating_sub(monotonic_ms), Ordering::Relaxed);
    }

    /// Reads atomics and both clocks; no persistent-store or transport
    /// operation is performed on this path.
    ///
    /// The one side effect is the host-suspension check, retained solely to make
    /// the missing wall time visible in the operator log. Verdict arithmetic
    /// uses the awake clock directly and does not depend on detecting a wake.
    #[cfg(test)]
    pub fn report(&self) -> ModuleControlResponse {
        self.report_with_transports(None)
    }

    /// [`Self::report`], also judging the vendor transports' panic-recovery
    /// counts (connections healed after a panic poisoned their lock). `None`
    /// means no transports were supplied: the counts are reported as null, and
    /// health is degraded only by a recovery an earlier report saw within the
    /// last hour.
    pub fn report_with_transports(
        &self,
        recoveries: Option<TransportPanicRecoveries>,
    ) -> ModuleControlResponse {
        let now = now_ms();
        let monotonic_elapsed_ms = self.monotonic_elapsed_ms();
        self.note_host_suspension_at(now, monotonic_elapsed_ms);
        self.report_with_transports_at(now, self.awake_ms_at(monotonic_elapsed_ms), recoveries)
    }

    #[cfg(test)]
    fn report_at(&self, now: u64, awake_now_ms: u64) -> ModuleControlResponse {
        self.report_with_transports_at(now, awake_now_ms, None)
    }

    /// Record a rise in the transports' panic-recovery count, and return how
    /// long ago in awake time a report last saw it rise, if one ever has.
    fn note_panic_recoveries(
        &self,
        recoveries: Option<TransportPanicRecoveries>,
        awake_now_ms: u64,
    ) -> Option<u64> {
        if let Some(recoveries) = recoveries {
            let total = recoveries.total();
            let previous = self
                .transport_panic_recoveries_seen
                .fetch_max(total, Ordering::AcqRel);
            if total > previous {
                self.last_panic_recovery_awake_ms
                    .store(awake_now_ms, Ordering::Release);
                // Store the timestamp before setting the observed flag, so a
                // reader that sees the flag also sees the timestamp.
                self.panic_recovery_observed.store(true, Ordering::Release);
            }
        }
        if !self.panic_recovery_observed.load(Ordering::Acquire) {
            return None;
        }
        Some(awake_now_ms.saturating_sub(self.last_panic_recovery_awake_ms.load(Ordering::Acquire)))
    }

    fn report_with_transports_at(
        &self,
        now: u64,
        awake_now_ms: u64,
        recoveries: Option<TransportPanicRecoveries>,
    ) -> ModuleControlResponse {
        let heartbeat_awake_age_ms =
            awake_now_ms.saturating_sub(self.last_heartbeat_awake_ms.load(Ordering::Acquire));
        let heartbeat_wall_age_ms =
            now.saturating_sub(self.last_heartbeat_ms.load(Ordering::Relaxed));
        let lifetime_ms = now.saturating_sub(self.started_at_ms);
        let scheduler_alive = self.scheduler_alive.load(Ordering::Relaxed);
        let scheduler_pass_age_ms =
            now.saturating_sub(self.last_scheduler_pass_ms.load(Ordering::Relaxed));
        let scheduler_polls_attempted = self.scheduler_polls_attempted.load(Ordering::Relaxed);
        let scheduler_polls_completed = self.scheduler_polls_completed.load(Ordering::Relaxed);
        // Time the machine spent suspended is not time the poller failed to make
        // progress. This stamp and `awake_now_ms` advance on the same monotonic
        // clock, so any number of sleeps disappear from the subtraction without
        // a wake baseline that can be reset repeatedly. The reported
        // `schedulerSuccessAgeMs` below deliberately remains wall-clock time.
        let scheduler_stall_age_ms = awake_now_ms
            .saturating_sub(self.last_scheduler_success_awake_ms.load(Ordering::Acquire));
        let scheduler_active_subscriptions =
            self.scheduler_active_subscriptions.load(Ordering::Acquire);
        let scheduler_stall_threshold_ms = self
            .scheduler_max_active_cadence_ms
            .load(Ordering::Relaxed)
            .saturating_mul(SCHEDULER_STALL_CADENCES);
        let scheduler_stalled = scheduler_is_stalled(
            scheduler_alive,
            scheduler_active_subscriptions,
            self.scheduler_uncompleted_since_success
                .load(Ordering::Relaxed),
            self.scheduler_selection_failures.load(Ordering::Relaxed),
            scheduler_stall_age_ms,
            scheduler_stall_threshold_ms,
        );

        let outbox_drain_stopped = self.outbox_drain_stopped.load(Ordering::Relaxed);
        let outbox_unpublishable = self.outbox_unpublishable.load(Ordering::Relaxed);
        let credential_repair = self
            .credential_repair_source
            .as_ref()
            .map(|source| source())
            .unwrap_or_default();
        let panic_recovery_age_ms = self.note_panic_recoveries(recoveries, awake_now_ms);
        let seen_panic_recoveries = self.transport_panic_recoveries_seen.load(Ordering::Acquire);
        // Independent dispatch, task-liveness, and useful-progress facts can
        // each degrade the module. A live scheduler is not necessarily a useful
        // one: it may keep ticking while every due poll fails.
        let (status, detail) = if let Some(message) = self.relay.degraded_message() {
            (HealthStatus::Degraded, Some(message.into()))
        } else if heartbeat_awake_age_ms > HEARTBEAT_STALE_MS {
            (
                HealthStatus::Degraded,
                Some(format!(
                    "dispatch heartbeat stale for {heartbeat_awake_age_ms}ms \
                     (threshold {HEARTBEAT_STALE_MS}ms awake time)"
                )),
            )
        } else if !scheduler_alive {
            (
                HealthStatus::Degraded,
                Some(
                    "trigger scheduler task is not running; subscriptions are not being polled"
                        .to_string(),
                ),
            )
        } else if scheduler_stalled {
            (
                HealthStatus::Degraded,
                Some(format!(
                    "trigger scheduler has active work but no poll has completed for \
                     {scheduler_stall_age_ms}ms (threshold {scheduler_stall_threshold_ms}ms)"
                )),
            )
        } else if outbox_drain_stopped {
            (
                HealthStatus::Degraded,
                Some(
                    "outbox drain task is not running; event notices are not being published"
                        .to_string(),
                ),
            )
        } else if outbox_unpublishable > 0 {
            (
                HealthStatus::Degraded,
                Some(format!(
                    "{outbox_unpublishable} outbox event(s) cannot be published and are skipped; \
                     the bus log names each one"
                )),
            )
        } else if !credential_repair.is_empty() {
            // A watch on a connection whose credential needs repair delivers
            // nothing and is retried at most hourly until a person signs in
            // again or replaces the credential, so the module is failing at
            // its job until then.
            let connections = credential_repair
                .iter()
                .map(|(connection, code)| format!("{connection} ({code})"))
                .collect::<Vec<_>>()
                .join(", ");
            (
                HealthStatus::Degraded,
                Some(format!(
                    "credential needs repair by a person for {} connection(s): {connections}",
                    credential_repair.len()
                )),
            )
        } else if let Some(age_ms) =
            panic_recovery_age_ms.filter(|age_ms| *age_ms <= PANIC_RECOVERY_DEGRADED_MS)
        {
            (
                HealthStatus::Degraded,
                Some(format!(
                    "a vendor transport healed a connection after a panic poisoned its lock \
                     {age_ms}ms ago ({seen_panic_recoveries} recovery(ies) since boot); \
                     the transport log names each one at ERROR"
                )),
            )
        } else {
            (HealthStatus::Ok, None)
        };
        // Null only when no pass has polled anything. A pass whose polls all
        // fail fast finishes in under a millisecond and legitimately measures
        // zero, so keying the null on the VALUE would report a scheduler that is
        // working -- and failing quickly -- as one that has never run.
        // Both gauges share the observed flag, so they appear and disappear
        // together: a reader seeing one without the other could not tell whether
        // the missing half was unmeasured or lost.
        let observed = self.scheduler_pass_observed.load(Ordering::Acquire);
        let scheduler_pass_max = if observed {
            json!(self.scheduler_pass_max_ms.load(Ordering::Relaxed))
        } else {
            Value::Null
        };
        let scheduler_pass_last = if observed {
            json!(self.scheduler_pass_last_ms.load(Ordering::Relaxed))
        } else {
            Value::Null
        };
        let scheduler_success_age = if self.scheduler_ever_completed.load(Ordering::Acquire) {
            json!(now.saturating_sub(self.last_scheduler_success_ms.load(Ordering::Relaxed)))
        } else {
            Value::Null
        };
        let observed = self.connections_observed.load(Ordering::Acquire);
        let (connections, connections_degraded) = if observed {
            (
                json!(self.connections_total.load(Ordering::Relaxed)),
                json!(self.connections_degraded.load(Ordering::Relaxed)),
            )
        } else {
            (Value::Null, Value::Null)
        };
        ModuleControlResponse::HealthCheck {
            status,
            detail,
            metrics: Some(json!({
                "githubPolling": self.relay.polling_status(),
                "heartbeatAgeMs": heartbeat_wall_age_ms,
                "heartbeatThresholdMs": HEARTBEAT_STALE_MS,
                "moduleLifetimeMs": lifetime_ms,
                "schedulerAlive": scheduler_alive,
                "schedulerPassAgeMs": scheduler_pass_age_ms,
                // Null until the first probe: see `connections_observed`. A
                // count is reported, never a verdict -- a degraded connection
                // is a per-connector condition an operator acts on, not a
                // reason to call the module unhealthy.
                "connections": connections,
                "connectionsDegraded": connections_degraded,
                // The longest duration of any pass that polled something. The
                // scheduler polls due subscriptions one after another, so one
                // slow vendor delays every subscription queued behind it; this
                // maximum makes that delay visible as a number.
                // Null until a pass has actually polled something: a measured
                // zero and "nothing has been due yet" are different claims, and
                // rendering both as 0 would let an idle scheduler read as a fast
                // one.
                "schedulerPassMaxMs": scheduler_pass_max,
                // The most recent such pass, reported beside the maximum. The
                // maximum never goes down, so one legitimate slow pass fixes
                // it for the life of the process: a first poll that backfills
                // dozens of items can set it to several seconds, and it still
                // reads that many polls later. The last pass shows how long
                // passes take now.
                "schedulerPassLastMs": scheduler_pass_last,
                // Cumulative counts of polls the scheduler started and polls
                // that reached the vendor and committed (quota deferrals are
                // in neither). No attempts means the scheduler is idle; many
                // attempted beside few completed means polls are failing.
                "schedulerPollsAttempted": scheduler_polls_attempted,
                "schedulerSelectionFailures": self.scheduler_selection_failures.load(Ordering::Relaxed),
                "schedulerPollsCompleted": scheduler_polls_completed,
                // Process-lifetime poll accounting, including manual polls. Only
                // the per-poll violation counter is authoritative during updates.
                "schedulerPollAccounting": plexus_core::poller::poll_accounting_metrics(),
                "repositoryIdentity": plexus_core::poller::repo_identity_metrics(),
                // Process-lifetime CI watch counters (deferred polls, vanished
                // and expired runs), which operators watch during a CI rollout.
                "ciRuns": plexus_core::poller::Poller::<
                    dyn plexus_core::credentials::CredentialSource,
                    dyn plexus_core::transport::Transport,
                >::ci_metrics(),
                "outboxDrainAlive": !outbox_drain_stopped,
                "outboxUnpublishable": outbox_unpublishable,
                // Connections healed after a panic poisoned their lock, per
                // transport since boot. Null when the caller supplied no
                // transports. The age is awake time since a report last saw
                // the count rise; health is degraded for an hour after that.
                "transportPanicRecoveries": recoveries.map(|recoveries| json!({
                    "mcp": recoveries.mcp,
                    "rest": recoveries.rest,
                })),
                "transportPanicRecoveryAgeMs": panic_recovery_age_ms,
                // Null until the first success: an age computed from boot would
                // make "never succeeded" look like "succeeded recently".
                "schedulerSuccessAgeMs": scheduler_success_age,
                // Embedded source identity and dependency-lock digest identify the build.
                "buildCommit": env!("PLEXUS_BUILD_COMMIT"),
                "lockDigest": env!("PLEXUS_LOCK_DIGEST"),
            })),
        }
    }
}

/// Marks the scheduler dead when it stops running, however it stops.
///
/// A drop guard rather than an explicit call at the end of the task, because
/// the case worth catching is the one nobody writes code for: a panic inside
/// the scheduler unwinds the task and never reaches an explicit teardown line,
/// leaving the flag reading `true` for a task that no longer exists. Drop runs
/// on the unwind path too, so the two ways the task can end — the one that was
/// planned and the one that was not — both mark it.
///
/// A clean shutdown also trips this, which is correct: the module is on its way
/// down and nothing is polling any more, so a report claiming otherwise would
/// be false in exactly the same way.
pub struct SchedulerLiveness {
    health: Arc<HealthState>,
}

impl SchedulerLiveness {
    pub fn new(health: Arc<HealthState>) -> Self {
        health.scheduler_alive.store(true, Ordering::Relaxed);
        Self { health }
    }
}

impl Drop for SchedulerLiveness {
    fn drop(&mut self) {
        self.health.scheduler_alive.store(false, Ordering::Relaxed);
    }
}

/// Marks the outbox drain stopped when its task ends, however it ends.
///
/// A drop guard for the same reason as [`SchedulerLiveness`]: a panic unwinds
/// past any explicit teardown line, and Drop still runs.
pub struct OutboxDrainLiveness {
    health: Arc<HealthState>,
}

impl OutboxDrainLiveness {
    pub fn new(health: Arc<HealthState>) -> Self {
        health.outbox_drain_stopped.store(false, Ordering::Relaxed);
        Self { health }
    }
}

impl Drop for OutboxDrainLiveness {
    fn drop(&mut self) {
        self.health
            .outbox_drain_stopped
            .store(true, Ordering::Relaxed);
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

fn scheduler_is_stalled(
    scheduler_alive: bool,
    active_subscriptions: u64,
    uncompleted_since_success: u64,
    selection_failures: u64,
    success_age_ms: u64,
    threshold_ms: u64,
) -> bool {
    scheduler_alive
        && active_subscriptions > 0
        && (uncompleted_since_success > 0 || selection_failures > 0)
        && success_age_ms > threshold_ms
}

#[cfg(test)]
pub(crate) const fn scheduler_stall_threshold_ms_for_test(cadence_s: u64) -> u64 {
    cadence_s * MILLIS_PER_SECOND * SCHEDULER_STALL_CADENCES
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// The connections in the poller's `credentialNeedsRepairByConnection` metric,
/// which maps `principal/connection_id` to the refusal code of the poll that
/// failed. A missing or malformed field reads as none. A code that is not a
/// string is kept as its JSON text, so the connection still appears in the
/// verdict.
fn credential_repair_from_poll_accounting(metrics: &Value) -> BTreeMap<String, String> {
    metrics
        .get("credentialNeedsRepairByConnection")
        .and_then(Value::as_object)
        .map(|connections| {
            connections
                .iter()
                .map(|(connection, code)| {
                    let code = code
                        .as_str()
                        .map_or_else(|| code.to_string(), str::to_string);
                    (connection.clone(), code)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(response: &ModuleControlResponse) -> HealthStatus {
        match response {
            ModuleControlResponse::HealthCheck { status, .. } => *status,
            other => panic!("expected a health check response, got {other:?}"),
        }
    }

    fn detail_of(response: &ModuleControlResponse) -> Option<String> {
        match response {
            ModuleControlResponse::HealthCheck { detail, .. } => detail.clone(),
            other => panic!("expected a health check response, got {other:?}"),
        }
    }

    /// A pass measuring ZERO milliseconds is still a pass that happened.
    ///
    /// The gauge reports null when no pass has polled anything, and the obvious
    /// implementation uses the value itself as that sentinel. That is wrong
    /// here, and not theoretically: a pass whose polls all fail fast -- no
    /// credential binding, a refused grant -- completes in well under a
    /// millisecond, so `as_millis` truncates to zero and a value-keyed sentinel
    /// reports a scheduler that IS running as one that has never run.
    ///
    /// Found as an intermittent test failure rather than by reading the code,
    /// which is the tell: the outcome depended on whether a real pass happened
    /// to land under or over 1ms.
    ///
    /// Asserted directly rather than through a spawned scheduler, because a
    /// timing-dependent test cannot serve as its own mutation control -- the
    /// mutant passed eight consecutive runs while the defect was present.
    ///
    /// Mutation-proved: keying the null on the value fails this deterministically.
    #[test]
    fn a_zero_millisecond_pass_is_reported_rather_than_read_as_never() {
        let health = HealthState::new();

        // Nothing has polled yet: null is correct here.
        let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        assert_eq!(
            metrics["schedulerPassMaxMs"],
            Value::Null,
            "with no pass observed the gauge must be null: {metrics}"
        );

        // A pass that polled one subscription and finished inside a millisecond.
        health.stamp_scheduler_pass_duration(1, 0);
        let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        assert_eq!(
            metrics["schedulerPassMaxMs"],
            json!(0),
            "a pass that measured zero must report zero, not null -- a fast \
             failing scheduler is still a running one: {metrics}"
        );

        // An empty pass must still not register: there was nothing to time.
        let health = HealthState::new();
        health.stamp_scheduler_pass_duration(0, 0);
        let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        assert_eq!(
            metrics["schedulerPassMaxMs"],
            Value::Null,
            "a pass that polled nothing must not count as an observation: {metrics}"
        );
    }

    /// Before any probe, connection counts are NULL rather than zero.
    ///
    /// Zero would be a false negative of exactly the kind this codebase keeps
    /// finding: "nothing observed" rendered identically to "nothing there", so
    /// an operator checking whether a connector survived a deploy would read a
    /// confident zero from a module that has not looked yet.
    ///
    /// Mutation-proved: reporting the raw counters regardless of the observed
    /// flag fails this.
    #[test]
    fn connection_counts_are_null_until_a_probe_has_run() {
        let health = HealthState::new();
        let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        assert_eq!(
            metrics.get("connections"),
            Some(&Value::Null),
            "an unprobed module must not report a connection count"
        );
        assert_eq!(metrics.get("connectionsDegraded"), Some(&Value::Null));
    }

    /// After a probe, the counts are what the probe observed.
    ///
    /// Pairs with `connection_counts_are_null_until_a_probe_has_run`: that test
    /// alone is satisfied by reporting null forever, which is
    /// indistinguishable from never reporting connection counts at all.
    #[test]
    fn a_probe_publishes_the_counts_it_observed() {
        let health = HealthState::new();
        health.stamp_connections(3, 1);
        let ModuleControlResponse::HealthCheck {
            metrics, status, ..
        } = health.report()
        else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        assert_eq!(metrics.get("connections").and_then(Value::as_u64), Some(3));
        assert_eq!(
            metrics.get("connectionsDegraded").and_then(Value::as_u64),
            Some(1)
        );
        // A degraded CONNECTION is not a degraded MODULE. The module is serving
        // correctly; one connector needs attention, which is a fact an operator
        // acts on rather than a reason to page anyone about plexus.
        assert_eq!(
            status,
            HealthStatus::Ok,
            "a degraded connection must not degrade the module"
        );
    }

    /// The binary reports which dependency set it linked, not just its source.
    ///
    /// This is the one provenance fact no deploy-side check can recover. Inode
    /// identity, `LC_UUID` and the build commit all establish which SOURCE an
    /// artifact came from; two builds at the same commit can still link
    /// different dependency versions, and the operator staging the binary did
    /// not build it and cannot tell.
    ///
    /// Compared against the REAL lock rather than checked for shape, because a
    /// well-formed digest of the wrong bytes is the failure that matters: it
    /// reads as provenance while answering a different question. Asserting
    /// only length and hex would pass a digest of any file at all.
    ///
    /// Mutation-proved: hashing a different file in build.rs (Cargo.toml
    /// rather than Cargo.lock) fails this. NOT proved against a stale digest
    /// from a missing `rerun-if-changed` — that attempt re-ran the script for
    /// unrelated reasons and passed, so the staleness case is unfenced.
    #[test]
    fn the_health_report_carries_the_dependency_set_it_linked() {
        use sha2::{Digest, Sha256};

        let health = HealthState::new();
        let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("metrics present");
        let digest = metrics
            .get("lockDigest")
            .and_then(Value::as_str)
            .expect("lockDigest reported");

        let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
        let bytes = std::fs::read(&lock).expect("workspace lock is readable");
        let expected = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            digest, expected,
            "the embedded digest does not match the workspace Cargo.lock"
        );
        assert!(
            metrics.get("buildCommit").and_then(Value::as_str).is_some(),
            "buildCommit must be reported alongside it"
        );
    }

    #[test]
    fn fresh_state_reports_healthy() {
        let health = HealthState::new();
        assert!(matches!(
            health.report(),
            ModuleControlResponse::HealthCheck {
                status: HealthStatus::Ok,
                ..
            }
        ));
    }

    /// Active work whose due polls have all failed for three cadences is a
    /// scheduler stall even while the task and dispatch loop remain live.
    #[test]
    fn active_due_subscriptions_without_a_completion_degrade_after_three_cadences() {
        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(2, 300);
        health.stamp_scheduler_outcomes(6, 0);
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();

        let report = health.report();
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a live scheduler that completes no due work for three cadences must degrade"
        );
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("no poll has completed"),
            "the detail must identify missing scheduler progress"
        );
    }

    /// A historical failed attempt must not turn an empty or fully suspended
    /// store into an alarm. Outcome totals are cumulative, so the CURRENT active
    /// count is the fact that separates no work from work that is still failing.
    ///
    /// Mutation control: removing the active-subscription term from the stall
    /// predicate makes this test fail in the false-alarm direction.
    #[test]
    fn zero_active_subscriptions_do_not_report_a_stall_at_any_elapsed_time() {
        let health = HealthState::new();
        health.stamp_scheduler_no_active_subscriptions();
        health.stamp_scheduler_outcomes(1, 0);
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();

        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "no active subscriptions means there is no scheduler work to stall"
        );
    }

    #[test]
    fn subscriptions_inside_the_first_cadence_do_not_report_a_stall() {
        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(2, 300);
        health.backdate_scheduler_success(300 * MILLIS_PER_SECOND - 1);
        health.stamp_heartbeat();

        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "subscriptions that have not become due are legitimate idleness"
        );
    }

    /// A watch slower than the current fleet must extend the threshold instead
    /// of inheriting a fixed 300-second assumption.
    ///
    /// Mutation control: pinning the threshold base back to 300 seconds makes
    /// the first assertion fail in the false-alarm direction.
    #[test]
    fn a_long_cadence_does_not_stall_at_the_old_fixed_threshold() {
        const LONG_CADENCE_S: u64 = 1_800;
        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(1, LONG_CADENCE_S);
        health.stamp_scheduler_outcomes(1, 0);
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();

        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "an 1800-second watch is still within three of its own cadences"
        );

        health
            .backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(LONG_CADENCE_S) + 1);
        health.stamp_heartbeat();
        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Degraded,
            "the derived threshold must still fire after three long cadences"
        );
    }

    /// Active subscriptions with no attempted/completed shortfall are idle,
    /// not stalled, even when the last success is older than the threshold.
    /// This covers watches that are not due and scheduler passes that correctly
    /// attempt nothing.
    ///
    /// Mutation control: deleting the shortfall term from the predicate makes
    /// this test fail in the false-alarm direction.
    #[test]
    fn an_idle_but_healthy_scheduler_is_not_a_stalled_one() {
        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(2, 300);
        health.stamp_scheduler_outcomes(4, 4);
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();

        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "equal attempted and completed totals mean no unsuccessful work remains"
        );
    }

    #[test]
    fn quota_deferred_cycles_do_not_report_a_scheduler_stall() {
        use plexus_core::scheduler::PassReport;
        use plexus_core::{PassOutcome, PollCycle};

        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(2, 300);
        // Classify real pass outcomes through the same entry point the module
        // uses, rather than feeding precomputed zero counts to the health state.
        for _ in 0..6 {
            let report = PassReport {
                outcomes: vec![PassOutcome {
                    principal: "direct".into(),
                    subscription_id: "ci-watch".into(),
                    cycle: PollCycle::Deferred {
                        reason: "github_actions_quota".into(),
                    },
                }],
                selection_failures: 0,
            };
            let (attempted, completed) = report.poll_counts();
            health.stamp_scheduler_outcomes(attempted, completed);
        }
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();
        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "quota waits are not attempted work and must not trigger a stall"
        );
        assert_eq!(health.scheduler_polls_attempted.load(Ordering::Relaxed), 0);
        assert_eq!(health.scheduler_polls_completed.load(Ordering::Relaxed), 0);
    }

    /// A scheduler that is not running is a task-liveness failure, never a
    /// useful-progress stall, even if every other stall input is present.
    #[test]
    fn a_dead_scheduler_is_not_classified_as_a_progress_stall() {
        let threshold_ms = scheduler_stall_threshold_ms_for_test(300);
        assert!(
            !scheduler_is_stalled(false, 1, 1, 0, threshold_ms + 1, threshold_ms),
            "a dead scheduler must not satisfy the live-scheduler stall predicate"
        );
    }

    /// One failed poll long ago does not turn a later quiet stretch into a
    /// stall: after a completion, only failures since then count. Here a
    /// failure, then a success, then a stretch past the threshold with nothing
    /// attempted (quota deferrals) must stay ok.
    #[test]
    fn an_early_failure_does_not_degrade_a_later_quiet_stretch() {
        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(1, 300);
        health.stamp_scheduler_outcomes(1, 0);
        health.stamp_scheduler_outcomes(1, 1);
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();
        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "no poll has failed since the last success"
        );
        // A failure after that success does count.
        health.stamp_scheduler_outcomes(1, 0);
        health.stamp_heartbeat();
        assert_eq!(status_of(&health.report()), HealthStatus::Degraded);
    }

    /// The outbox drain's liveness and unpublishable rows reach health, and
    /// the CI watch counters are reported.
    #[test]
    fn a_stopped_outbox_drain_or_unpublishable_rows_degrade_health() {
        let health = Arc::new(HealthState::new());
        health.stamp_heartbeat();
        {
            let _liveness = OutboxDrainLiveness::new(Arc::clone(&health));
            assert_eq!(status_of(&health.report()), HealthStatus::Ok);
            health.stamp_outbox_unpublishable(2);
            let report = health.report();
            assert_eq!(status_of(&report), HealthStatus::Degraded);
            assert!(detail_of(&report)
                .unwrap_or_default()
                .contains("2 outbox event"));
            health.stamp_outbox_unpublishable(0);
            assert_eq!(status_of(&health.report()), HealthStatus::Ok);
        }
        let report = health.report();
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a stopped outbox drain must degrade health"
        );
        assert!(detail_of(&report)
            .unwrap_or_default()
            .contains("outbox drain"));
        let ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = report
        else {
            panic!("health metrics");
        };
        assert!(metrics["ciRuns"]["ci_polls_deferred"].is_u64(), "{metrics}");
        assert_eq!(metrics["outboxDrainAlive"], false);
    }

    /// A success clears the verdict even though the cumulative attempted and
    /// completed counters retain failures from before it.
    #[test]
    fn a_completion_resets_a_scheduler_stall() {
        let health = HealthState::new();
        health.stamp_scheduler_subscription_count(1, 300);
        health.stamp_scheduler_outcomes(1, 0);
        health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(300) + 1);
        health.stamp_heartbeat();
        assert_eq!(status_of(&health.report()), HealthStatus::Degraded);

        health.stamp_scheduler_outcomes(1, 1);
        health.stamp_heartbeat();
        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "one completion must reset the stall window even while an older gap remains"
        );
    }

    /// A dead scheduler degrades the module even though the dispatch loop is
    /// perfectly healthy.
    ///
    /// This is the whole point of tracking it separately: the two run on
    /// different tasks, so a fresh dispatch heartbeat is not evidence about the
    /// scheduler, and before this the module reported `ok` while polling had
    /// stopped permanently.
    ///
    /// Mutation-proved: dropping the `scheduler_alive` branch from `report`
    /// leaves this test failing on the status assertion.
    #[test]
    fn a_dead_scheduler_degrades_a_module_with_a_fresh_heartbeat() {
        let health = Arc::new(HealthState::new());
        {
            let _liveness = SchedulerLiveness::new(Arc::clone(&health));
            health.stamp_heartbeat();
            assert_eq!(
                status_of(&health.report()),
                HealthStatus::Ok,
                "a running scheduler with a fresh heartbeat must be ok, or this \
                 test would pass for the wrong reason"
            );
        }

        // The guard is gone: the task has ended.
        health.stamp_heartbeat();
        let report = health.report();
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a module that stopped polling must not report ok"
        );
        let detail = detail_of(&report).unwrap_or_default();
        assert!(
            detail.contains("scheduler"),
            "the detail must name the scheduler so an operator is not sent to \
             the dispatch loop; got {detail:?}"
        );
    }

    /// The liveness flag is cleared by a PANIC inside the scheduler, not just
    /// by a clean exit.
    ///
    /// This is why the mechanism is a drop guard rather than a line at the end
    /// of the task: an unwind never reaches an explicit teardown, so the
    /// failure mode with no code written for it is exactly the one that would
    /// leave the flag reading `true` forever.
    #[test]
    fn a_panicking_scheduler_is_marked_dead() {
        let health = Arc::new(HealthState::new());
        let handle = {
            let health = Arc::clone(&health);
            std::thread::spawn(move || {
                let _liveness = SchedulerLiveness::new(health);
                panic!("pass exploded");
            })
        };
        assert!(handle.join().is_err(), "the thread must have panicked");

        health.stamp_heartbeat();
        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Degraded,
            "an unwound scheduler task must not keep reporting ok"
        );
    }

    /// The pass timestamp is reported but never turned into a verdict.
    ///
    /// Deliberate: a pass is sequential over subscriptions and a single poll
    /// can legitimately take tens of seconds against a slow vendor, so any
    /// staleness threshold here would eventually degrade a scheduler that is
    /// working correctly. It is a diagnostic for a WEDGED pass, which the
    /// liveness flag cannot see because a stuck task is still a live one.
    #[test]
    fn a_stale_pass_is_reported_as_a_metric_but_is_not_a_verdict() {
        let health = Arc::new(HealthState::new());
        let _liveness = SchedulerLiveness::new(Arc::clone(&health));
        health.stamp_heartbeat();

        let ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = health.report()
        else {
            panic!("expected a health check response");
        };
        assert_eq!(status, HealthStatus::Ok);
        let metrics = metrics.expect("metrics present");
        assert_eq!(metrics["schedulerAlive"], serde_json::json!(true));
        assert!(
            metrics["schedulerPassAgeMs"].is_number(),
            "the pass age must be observable for diagnosing a wedged pass"
        );
    }

    /// The pass-duration gauge records the WORST pass, ignores empty ones, and
    /// stays null until a real pass has run.
    ///
    /// All three legs matter and they fail in opposite directions. Averaging
    /// would hide the case this exists to catch -- one wedged vendor among many
    /// fast ones -- because the scheduler polls sequentially, so a single slow
    /// subscription delays every one behind it. Counting empty passes would drag
    /// any aggregate toward zero, since with a 300s cadence most passes poll
    /// nothing and return in microseconds. And rendering an unobserved gauge as
    /// 0 would make an idle scheduler read as an exceptionally fast one, which
    /// is the false-zero this codebase already refuses for connection counts and
    /// success ages.
    ///
    /// Mutation-proved: storing instead of max-ing fails the worst-pass leg;
    /// dropping the empty-pass guard fails the null leg.
    #[test]
    fn the_pass_duration_gauge_keeps_the_worst_non_empty_pass() {
        let health = HealthState::new();
        let read = |health: &HealthState| {
            let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
                panic!("expected a health check response");
            };
            metrics.expect("metrics present")["schedulerPassMaxMs"].clone()
        };

        assert_eq!(
            read(&health),
            Value::Null,
            "an unobserved gauge must be null rather than a measured zero"
        );

        // An empty pass is not evidence about vendor latency.
        health.stamp_scheduler_pass_duration(0, 9_999);
        assert_eq!(
            read(&health),
            Value::Null,
            "a pass that polled nothing must not be recorded"
        );

        health.stamp_scheduler_pass_duration(2, 120);
        assert_eq!(read(&health), json!(120));

        // A FASTER pass must not erase the worst one: the slow pass is the
        // finding, and a later quick pass does not undo it.
        health.stamp_scheduler_pass_duration(2, 5);
        assert_eq!(
            read(&health),
            json!(120),
            "the maximum must survive a faster subsequent pass"
        );

        health.stamp_scheduler_pass_duration(3, 30_000);
        assert_eq!(
            read(&health),
            json!(30_000),
            "a new worst pass must replace the old maximum"
        );
    }

    /// The LAST pass is reported beside the maximum, and tracks the present.
    ///
    /// A max-since-boot is monotonic, so one legitimate outlier pins it for the
    /// life of the process and it then describes history rather than now.
    /// For example, a first poll that backfills dozens of pull requests can set
    /// the max to several seconds, and many polls later it still reads that --
    /// the gauge built to answer "are passes getting slow?" could no longer
    /// answer it, because its worst case had already happened and was not a
    /// problem.
    ///
    /// So the load-bearing assertion here is the FALLING one: after a slow pass
    /// followed by a fast one, the two gauges must DISAGREE. A test that only
    /// checked the last value rising would pass against an implementation that
    /// simply aliased the maximum.
    ///
    /// Both share the observed flag deliberately, so they appear together: a
    /// reader seeing one without the other could not tell whether the missing
    /// half was unmeasured or lost.
    ///
    /// Mutation-proved: max-ing the last gauge instead of storing it fails the
    /// falling leg; dropping the shared flag and rendering zero fails the null
    /// leg.
    #[test]
    fn the_last_pass_gauge_tracks_the_present_while_the_max_keeps_the_worst() {
        let health = HealthState::new();
        let read = |health: &HealthState| {
            let ModuleControlResponse::HealthCheck { metrics, .. } = health.report() else {
                panic!("expected a health check response");
            };
            let metrics = metrics.expect("metrics present");
            (
                metrics["schedulerPassMaxMs"].clone(),
                metrics["schedulerPassLastMs"].clone(),
            )
        };

        assert_eq!(
            read(&health),
            (Value::Null, Value::Null),
            "both gauges must be null before any pass has polled"
        );

        health.stamp_scheduler_pass_duration(2, 4_675);
        assert_eq!(
            read(&health),
            (json!(4_675), json!(4_675)),
            "the first non-empty pass sets both"
        );

        // The production case: a slow backfill, then ordinary passes. The max
        // must remember the outlier and the last must not.
        health.stamp_scheduler_pass_duration(2, 40);
        assert_eq!(
            read(&health),
            (json!(4_675), json!(40)),
            "the max must keep the outlier while the last pass reports the present"
        );

        // An empty pass is not an observation of vendor latency and must not
        // reset the present to zero -- that would read as an instant pass.
        health.stamp_scheduler_pass_duration(0, 9_999);
        assert_eq!(
            read(&health),
            (json!(4_675), json!(40)),
            "an empty pass must move neither gauge"
        );
    }

    /// A twelve-minute host sleep, shorter than the fifteen-minute scheduler
    /// threshold but much longer than the dispatch threshold.
    const SUSPENDED_MS: u64 = 720_000;
    /// A pass slow enough to dwarf the dispatch threshold, as one slow vendor
    /// can cause.
    const LONG_PASS_MS: u64 = 99_578;

    /// Repeated sleeps cannot keep resetting a wedged poller's stall window.
    ///
    /// A laptop that sleeps often produces runs of sub-threshold wake gaps. Three awake
    /// intervals here remain below the threshold even though their intervening
    /// sleeps push wall time far past it; a fourth interval crosses the awake
    /// threshold. A wall-clock verdict fails the first checkpoint, while the old
    /// per-wake baseline fails the second by resetting on every wake.
    ///
    /// Mutation-proved: replacing the awake subtraction with wall-clock age
    /// fails the below-threshold checkpoint.
    #[test]
    fn repeated_short_suspensions_cannot_keep_a_wedged_poller_healthy() {
        let health = HealthState::new();
        let threshold_ms = scheduler_stall_threshold_ms_for_test(300);
        let awake_gap_ms = threshold_ms / 4 + 1;
        let mut wall_ms = now_ms();
        let mut monotonic_ms = 10_000;
        let success_wall_ms = wall_ms;
        let success_awake_ms = health.awake_ms_at(monotonic_ms);

        health.seed_clock_sample(wall_ms, monotonic_ms);
        health.stamp_scheduler_subscription_count(2, 300);
        health.stamp_scheduler_outcomes_at(1, 1, success_wall_ms, success_awake_ms);
        health.stamp_scheduler_outcomes_at(6, 0, wall_ms, success_awake_ms);

        for wake in 1..=3 {
            wall_ms += awake_gap_ms + SUSPENDED_MS;
            monotonic_ms += awake_gap_ms;
            assert_eq!(
                health.note_host_suspension_at(wall_ms, monotonic_ms),
                Some(SUSPENDED_MS),
                "short suspension {wake} must be claimed exactly once"
            );
        }

        let awake_ms = health.awake_ms_at(monotonic_ms);
        health.stamp_heartbeat_at(wall_ms, awake_ms);
        assert_eq!(
            status_of(&health.report_at(wall_ms, awake_ms)),
            HealthStatus::Ok,
            "three awake gaps remain below the scheduler threshold even though \
             their accumulated wall time is well above it"
        );

        wall_ms += awake_gap_ms + SUSPENDED_MS;
        monotonic_ms += awake_gap_ms;
        assert_eq!(
            health.note_host_suspension_at(wall_ms, monotonic_ms),
            Some(SUSPENDED_MS),
            "the fourth sub-threshold suspension must also be claimed"
        );

        let awake_ms = health.awake_ms_at(monotonic_ms);
        health.stamp_heartbeat_at(wall_ms, awake_ms);
        let report = health.report_at(wall_ms, awake_ms);
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a poller completing nothing must degrade after one threshold of \
             total awake time regardless of how many sleeps intervene"
        );
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("no poll has completed"),
            "the chained-suspension failure must come from the scheduler stall arm"
        );
    }

    /// One long suspension advances wall-clock gauges but neither verdict.
    #[test]
    fn a_single_long_suspension_does_not_age_either_verdict() {
        let health = HealthState::new();
        let wall_ms = now_ms();
        let monotonic_ms = 10_000;
        let awake_ms = health.awake_ms_at(monotonic_ms);

        health.seed_clock_sample(wall_ms, monotonic_ms);
        health.stamp_scheduler_subscription_count(2, 300);
        health.stamp_scheduler_outcomes_at(1, 1, wall_ms, awake_ms);
        health.stamp_scheduler_outcomes_at(6, 0, wall_ms, awake_ms);
        health.stamp_heartbeat_at(wall_ms, awake_ms);
        health
            .last_scheduler_pass_ms
            .store(wall_ms, Ordering::Relaxed);

        let wake_wall_ms = wall_ms + SUSPENDED_MS;
        assert_eq!(
            health.note_host_suspension_at(wake_wall_ms, monotonic_ms),
            Some(SUSPENDED_MS),
            "the wall-only jump must be reported as a suspension"
        );

        let report = health.report_at(wake_wall_ms, awake_ms);
        assert_eq!(
            status_of(&report),
            HealthStatus::Ok,
            "suspended time is not failed poller or dispatch-loop time"
        );
        let ModuleControlResponse::HealthCheck { metrics, .. } = report else {
            panic!("expected a health check response");
        };
        let metrics = metrics.expect("health metrics");
        assert_eq!(metrics["heartbeatAgeMs"], json!(SUSPENDED_MS));
        assert_eq!(metrics["schedulerPassAgeMs"], json!(SUSPENDED_MS));
        assert_eq!(metrics["schedulerSuccessAgeMs"], json!(SUSPENDED_MS));
    }

    /// A module that makes no progress while awake still degrades exactly as it
    /// did before suspension handling existed.
    ///
    /// Mutation-proved: forcing the scheduler awake age to zero fails this.
    #[test]
    fn a_stall_with_no_suspension_still_degrades_at_the_threshold() {
        let health = HealthState::new();
        let threshold_ms = scheduler_stall_threshold_ms_for_test(300);
        health.stamp_scheduler_subscription_count(2, 300);
        health.stamp_scheduler_outcomes(6, 0);
        health.backdate_scheduler_success(threshold_ms + 1);
        health.stamp_heartbeat();

        assert_eq!(
            health.note_host_suspension(),
            None,
            "an awake host advances both clocks together and must register no suspension"
        );

        let report = health.report();
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a live scheduler with active work and no completion for three cadences must degrade"
        );
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("no poll has completed"),
            "the detail must identify missing scheduler progress"
        );
    }

    /// Repeated sleeps cannot keep a dead dispatch loop healthy either.
    /// Three awake gaps remain below the heartbeat threshold despite much more
    /// wall time passing; the fourth crosses the threshold without any wake
    /// resetting the reference.
    #[test]
    fn a_dead_dispatch_loop_after_a_wake_still_degrades_on_the_heartbeat() {
        const SHORT_SLEEP_MS: u64 = HOST_SUSPENSION_MIN_MS + 1_000;

        let health = HealthState::new();
        let awake_gap_ms = HEARTBEAT_STALE_MS / 4 + 1;
        let mut wall_ms = now_ms();
        let mut monotonic_ms = 10_000;
        let heartbeat_awake_ms = health.awake_ms_at(monotonic_ms);
        health.seed_clock_sample(wall_ms, monotonic_ms);
        health.stamp_heartbeat_at(wall_ms, heartbeat_awake_ms);

        for wake in 1..=3 {
            wall_ms += awake_gap_ms + SHORT_SLEEP_MS;
            monotonic_ms += awake_gap_ms;
            assert_eq!(
                health.note_host_suspension_at(wall_ms, monotonic_ms),
                Some(SHORT_SLEEP_MS),
                "short dispatch suspension {wake} must be claimed"
            );
        }
        let awake_ms = health.awake_ms_at(monotonic_ms);
        assert_eq!(
            status_of(&health.report_at(wall_ms, awake_ms)),
            HealthStatus::Ok,
            "three awake gaps remain below the heartbeat threshold"
        );

        wall_ms += awake_gap_ms + SHORT_SLEEP_MS;
        monotonic_ms += awake_gap_ms;
        assert_eq!(
            health.note_host_suspension_at(wall_ms, monotonic_ms),
            Some(SHORT_SLEEP_MS)
        );
        let report = health.report_at(wall_ms, health.awake_ms_at(monotonic_ms));
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a dead dispatch loop must degrade after one threshold of total awake time"
        );
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("dispatch heartbeat stale"),
            "the detail must name the dispatch heartbeat"
        );
    }

    /// The old wake-stamp fence is replaced by this direct awake-stamp fence.
    /// The dispatch loop, not the detector, writes the verdict reference, and it
    /// must write the observed monotonic instant rather than an unreachable one
    /// that would pin the age at zero forever.
    #[test]
    fn a_dispatch_heartbeat_stamps_the_current_awake_instant() {
        let health = HealthState::new();
        let wall_ms = now_ms();
        let awake_ms = health.awake_ms_at(10_000);

        health.stamp_heartbeat_at(wall_ms, awake_ms);

        assert_eq!(
            health.heartbeat_awake_stamp_ms(),
            awake_ms,
            "the awake clock must be able to reach every heartbeat reference"
        );
    }

    /// The old post-wake stall-baseline fence is replaced by the corresponding
    /// completion-stamp fence. A completion is the only event that resets the
    /// direct awake-time stall measurement.
    #[test]
    fn a_scheduler_completion_stamps_the_current_awake_instant() {
        let health = HealthState::new();
        let wall_ms = now_ms();
        let awake_ms = health.awake_ms_at(10_000);

        health.stamp_scheduler_outcomes_at(1, 1, wall_ms, awake_ms);

        assert_eq!(
            health.scheduler_success_awake_stamp_ms(),
            awake_ms,
            "the awake clock must be able to reach every completion reference"
        );
    }

    /// An ordinary stale heartbeat on a host that never slept degrades exactly
    /// as it did before suspension handling existed.
    #[test]
    fn a_stale_heartbeat_with_no_suspension_still_degrades() {
        let health = HealthState::new();
        health.stamp_heartbeat();
        assert_eq!(status_of(&health.report()), HealthStatus::Ok);

        health.backdate_heartbeat(HEARTBEAT_STALE_MS + 1);
        assert_eq!(
            health.note_host_suspension(),
            None,
            "an awake host advances both clocks together and must register no suspension"
        );

        let report = health.report();
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a dispatch loop silent past the awake threshold must degrade"
        );
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("dispatch heartbeat stale"),
            "the detail must name the dispatch heartbeat"
        );
    }

    /// A ninety-nine-second pass is not a sleeping host.
    ///
    /// `run_pass` runs INLINE on the scheduler tick and polls subscriptions
    /// sequentially, so one slow vendor holds the whole loop for tens of
    /// seconds or more. Detecting suspension by timing the
    /// loop iteration would read that pass as a sleep and mute the stall alarm
    /// during exactly the degradation it exists to catch.
    ///
    /// Divergence cannot make that mistake, and the two assertions differ only
    /// in whether the monotonic clock moved: identical wall-clock gap, opposite
    /// verdict.
    #[test]
    fn a_long_pass_with_both_clocks_advancing_is_not_a_suspension() {
        let health = HealthState::new();
        let wall_ms = now_ms();
        let monotonic_ms = 10_000;
        health.seed_clock_sample(wall_ms, monotonic_ms);

        assert_eq!(
            health.note_host_suspension_at(wall_ms + LONG_PASS_MS, monotonic_ms + LONG_PASS_MS),
            None,
            "a slow pass advances both clocks and must never be read as a \
             suspension"
        );

        assert_eq!(
            health.note_host_suspension_at(wall_ms + LONG_PASS_MS, monotonic_ms),
            Some(LONG_PASS_MS),
            "the same wall-clock gap with the monotonic clock standing still IS \
             a suspension"
        );
    }

    /// A vendor transport that healed a connection after a panic poisoned its
    /// lock degrades health with a reason. Health returns to ok an hour of
    /// awake time after a report last saw the count rise, while the counts
    /// stay in the metrics, and a later recovery degrades it again.
    #[test]
    fn a_transport_panic_recovery_degrades_health_for_an_hour() {
        let health = HealthState::new();
        let wall_ms = now_ms();
        let awake_ms = health.awake_ms_at(10_000);
        let report_at = |awake_ms: u64, recoveries: TransportPanicRecoveries| {
            // A fresh heartbeat at each instant, so only the recovery verdict
            // can degrade the report.
            let wall_ms = wall_ms + (awake_ms - health.awake_ms_at(10_000));
            health.stamp_heartbeat_at(wall_ms, awake_ms);
            health.report_with_transports_at(wall_ms, awake_ms, Some(recoveries))
        };
        let metrics_of = |report: ModuleControlResponse| match report {
            ModuleControlResponse::HealthCheck {
                metrics: Some(metrics),
                ..
            } => metrics,
            other => panic!("expected health metrics, got {other:?}"),
        };

        let quiet = TransportPanicRecoveries::default();
        let report = report_at(awake_ms, quiet);
        assert_eq!(status_of(&report), HealthStatus::Ok, "{report:?}");
        assert_eq!(
            metrics_of(report)["transportPanicRecoveries"],
            json!({"mcp": 0, "rest": 0})
        );

        let healed = TransportPanicRecoveries { mcp: 1, rest: 0 };
        let report = report_at(awake_ms, healed);
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a transport panic recovery must degrade health"
        );
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("panic poisoned its lock"),
            "{report:?}"
        );
        let metrics = metrics_of(report);
        assert_eq!(
            metrics["transportPanicRecoveries"],
            json!({"mcp": 1, "rest": 0})
        );
        assert_eq!(metrics["transportPanicRecoveryAgeMs"], json!(0));

        // The same count an hour later is still the same recovery: visible.
        let hour_later = awake_ms + PANIC_RECOVERY_DEGRADED_MS;
        assert_eq!(
            status_of(&report_at(hour_later, healed)),
            HealthStatus::Degraded
        );

        // Past the hour with no new recovery, health is ok again and the
        // count remains reported.
        let report = report_at(hour_later + 1, healed);
        assert_eq!(
            status_of(&report),
            HealthStatus::Ok,
            "health must return to ok an hour after the last recovery: {report:?}"
        );
        assert_eq!(
            metrics_of(report)["transportPanicRecoveries"],
            json!({"mcp": 1, "rest": 0})
        );

        // A recovery on the other transport is new, and degrades again.
        let report = report_at(hour_later + 2, TransportPanicRecoveries { mcp: 1, rest: 1 });
        assert_eq!(status_of(&report), HealthStatus::Degraded);
        assert!(
            detail_of(&report)
                .unwrap_or_default()
                .contains("2 recovery(ies) since boot"),
            "{report:?}"
        );
    }

    /// While any connection's credential needs a person to repair it, health
    /// is degraded and the reason names each connection and its code; when
    /// the condition clears, health is ok again.
    #[test]
    fn a_credential_needing_repair_degrades_health_until_it_is_repaired() {
        let repair = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let source = Arc::clone(&repair);
        let health = HealthState::new()
            .with_credential_repair_source(move || source.lock().unwrap().clone());
        health.stamp_heartbeat();
        assert_eq!(status_of(&health.report()), HealthStatus::Ok);

        repair.lock().unwrap().extend([
            (
                "direct/conn-a".to_string(),
                "credential_missing".to_string(),
            ),
            (
                "ops/conn-b".to_string(),
                "credential_auth_required".to_string(),
            ),
        ]);
        health.stamp_heartbeat();
        let report = health.report();
        assert_eq!(
            status_of(&report),
            HealthStatus::Degraded,
            "a credential needing repair must degrade health"
        );
        let detail = detail_of(&report).unwrap_or_default();
        assert!(
            detail.contains("direct/conn-a (credential_missing)")
                && detail.contains("ops/conn-b (credential_auth_required)"),
            "the reason must name each connection and its code: {detail}"
        );

        repair.lock().unwrap().clear();
        health.stamp_heartbeat();
        assert_eq!(
            status_of(&health.report()),
            HealthStatus::Ok,
            "a repaired credential must clear the verdict"
        );
    }

    /// The production credential-repair source reads the poller's
    /// `credentialNeedsRepairByConnection` field under the name the poller
    /// publishes it.
    #[test]
    fn the_poller_repair_map_is_read_from_its_accounting_field() {
        assert!(
            plexus_core::poller::poll_accounting_metrics()
                .get("credentialNeedsRepairByConnection")
                .is_some_and(Value::is_object),
            "the poller no longer publishes the field this source reads"
        );
        let metrics = json!({
            "itemsExamined": 3,
            "credentialNeedsRepairByConnection": {"direct/conn-a": "credential_permanent"}
        });
        assert_eq!(
            credential_repair_from_poll_accounting(&metrics),
            BTreeMap::from([(
                "direct/conn-a".to_string(),
                "credential_permanent".to_string()
            )]),
            "the source must read the poller's repair map"
        );
        assert!(credential_repair_from_poll_accounting(&json!({})).is_empty());
    }
}
