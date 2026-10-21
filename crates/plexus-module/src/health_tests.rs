#[test]
fn regression_publish_failure_degrades_until_recovery() {
    let health = super::HealthState::new();
    health.record_publish_error("nats_publish_failed");
    let subc_protocol::session::ModuleControlResponse::HealthCheck { status, detail, .. } =
        health.report()
    else {
        panic!("health reply")
    };
    assert_eq!(status, subc_protocol::session::HealthStatus::Degraded);
    assert!(detail.unwrap().contains("publishing"));
    health.clear_publish_error();
    let subc_protocol::session::ModuleControlResponse::HealthCheck { status, .. } = health.report()
    else {
        panic!("health reply")
    };
    assert_eq!(status, subc_protocol::session::HealthStatus::Ok);
}

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

    health.backdate_scheduler_success(scheduler_stall_threshold_ms_for_test(LONG_CADENCE_S) + 1);
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

/// A twelve-minute host sleep, shorter than the fifteen-minute scheduler threshold.
const SUSPENDED_MS: u64 = 720_000;
/// A slow vendor can keep one pass busy for over a minute.
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
    health.last_heartbeat_ms.store(wall_ms, Ordering::Relaxed);
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
    health.last_heartbeat_ms.store(wall_ms, Ordering::Relaxed);
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
    health.last_heartbeat_ms.store(wall_ms, Ordering::Relaxed);
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
        let wall_ms = wall_ms + (awake_ms - health.awake_ms_at(10_000));
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
    let health =
        HealthState::new().with_credential_repair_source(move || source.lock().unwrap().clone());
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
