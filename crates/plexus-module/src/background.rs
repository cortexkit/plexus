//! Background task lifetimes, subscription scheduling and cached connection health.

use super::*;

/// How often the trigger scheduler wakes to look for due subscriptions.
///
/// Cadences are whole seconds and due-selection is a cheap store query, so a
/// one-second tick keeps a poll's start within a second of its cadence without
/// meaningful overhead. The tick is NOT the expensive part — the vendor round
/// trip is — and that only runs when something is actually due. A tick that
/// fires while a pass is still running is deliberately dropped rather than
/// queued (see `spawn_trigger_scheduler`), so a slow vendor cannot build up a
/// backlog of replayed polls.
const SCHEDULER_TICK: std::time::Duration = std::time::Duration::from_secs(1);
/// How often the scheduler task sweeps idle vendor connections out of the
/// transport pools.
///
/// Rides the scheduler tick because that tick already runs inside a blocking
/// section, which an eviction requires: dropping a pooled entry drops a
/// `reqwest::blocking` client and its internal runtime with it. Gated on an
/// interval rather than running every tick because the pools use a 300s idle
/// timeout, so sweeping at 1Hz would take the pool lock 300 times per eviction
/// it could possibly make.
const POOL_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// How often the scheduler refreshes connection health from vendor catalogs.
///
/// A health probe may make one blocking vendor call per connection, so it must
/// not run on the one-second scheduler tick. Sixty seconds bounds recovery
/// latency while keeping that work away from the daemon's health checks, which
/// plexus must answer within five seconds;
/// no caller depends on sub-minute connection recovery.
const HEALTH_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

pub(super) struct BackgroundTasks {
    shutdown: Vec<mpsc::Sender<()>>,
    tasks: Vec<(
        &'static str,
        tokio::task::JoinHandle<()>,
        std::time::Duration,
    )>,
}

impl BackgroundTasks {
    pub(super) async fn stop(self) {
        drop(self.shutdown);
        for (name, task, grace) in self.tasks {
            stop_task(name, task, grace).await;
        }
    }
}

pub(super) fn spawn_background_tasks(
    state: Arc<ModuleState>,
    connection_file: &Path,
    audit_retention: settings::AuditRetention,
) -> BackgroundTasks {
    // Drive trigger polling on a dedicated task rather than from the dispatch
    // loop below (see `spawn_trigger_scheduler`). The shutdown sender is held
    // here: when the loop exits on ANY path the sender is dropped, the task
    // observes the closed channel and stops. Shutdown waits a bounded time for
    // that (`stop_task`), then aborts the task, so one wedged pass cannot hold
    // the module open after its route has closed. A poll in flight at shutdown
    // is left to finish or abandoned; `commit_keyed_poll_success` is a single fenced
    // transaction, so an abandoned poll leaves the cursor unadvanced and the
    // events unwritten, which is the correct outcome.
    let (claim_shutdown, mut claim_stop) = mpsc::channel::<()>(1);
    let claim_state = Arc::clone(&state);
    let claim_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_refresh_error: Option<String> = None;
        loop {
            tokio::select! {
                _ = claim_stop.recv() => break,
                _ = tick.tick() => {
                    // The refresh logs ownership transitions itself; a failed
                    // read keeps the last state by design. The failure is
                    // logged when its code changes (not every 30 seconds), so
                    // a claim route that never answers is visible without
                    // flooding the log.
                    let outcome = blocking_section(|| claim_state.runtime.connector_home.refresh());
                    let code = outcome.as_ref().err().map(|error| error.code.clone());
                    if code != last_refresh_error {
                        match &outcome {
                            Err(error) => eprintln!(warn wire: "connector home refresh failed ({}): {}", error.code, error.message),
                            Ok(_) => eprintln!(info wire: "connector home refresh recovered"),
                        }
                        last_refresh_error = code;
                    }
                }
            }
        }
    });
    // Compile the probe sandbox in the background so the first probe poll does
    // not pay for it inside a scheduler pass. It must not delay the dispatch
    // loop below: compiling can take seconds on a slow machine, and the
    // supervisor's first health check gives the module only five seconds to
    // answer. A probe that runs before warm-up finishes waits on the same
    // one-time initialization.
    tokio::task::spawn_blocking(|| {
        if let Err(error) = plexus_probe::ProbeSandbox::warm_up() {
            eprintln!(warn scheduler: "probe sandbox warm-up failed; initialization will retry on use: {error}");
        }
    });
    let (scheduler_shutdown, scheduler_stop) = mpsc::channel::<()>(1);
    let scheduler_task =
        spawn_trigger_scheduler(Arc::clone(&state), scheduler_stop, audit_retention);

    let (outbox_shutdown, outbox_stop) = mpsc::channel::<()>(1);
    let outbox_task = crate::bus::spawn_outbox_drain(
        Arc::clone(&state),
        outbox_stop,
        crate::bus::session_factory(Some(connection_file.to_path_buf())),
    );

    let (relay_shutdown, relay_stop) = mpsc::channel::<()>(1);
    let relay_task = relay::spawn(Arc::clone(&state), relay_stop);

    let (search_shutdown, search_stop) = mpsc::channel::<()>(1);
    let search_task = web_search_auto::spawn(Arc::clone(&state), search_stop);

    let (manifest_shutdown, manifest_stop) = mpsc::channel::<()>(1);
    let manifest_task = manifest_binding::spawn(Arc::clone(&state), manifest_stop);

    BackgroundTasks {
        shutdown: vec![
            claim_shutdown,
            scheduler_shutdown,
            outbox_shutdown,
            relay_shutdown,
            search_shutdown,
            manifest_shutdown,
        ],
        tasks: vec![
            ("connector-home refresh", claim_task, TASK_SHUTDOWN_GRACE),
            ("trigger scheduler", scheduler_task, TASK_SHUTDOWN_GRACE),
            ("outbox drain", outbox_task, BUS_SHUTDOWN_GRACE),
            ("relay", relay_task, BUS_SHUTDOWN_GRACE),
            ("search key watch", search_task, TASK_SHUTDOWN_GRACE),
            ("manifest binding", manifest_task, TASK_SHUTDOWN_GRACE),
        ],
    }
}

/// How long shutdown waits for the connector-home refresh, scheduler and
/// scheduler tasks after signalling them. Their slowest step is one vendor or
/// route call, each with its own timeout of a few seconds.
const TASK_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// How long shutdown waits for the outbox drain and the relay.
const BUS_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Wait up to `grace` for a signalled background task to stop, then abort it.
///
/// Every outcome other than a clean stop is logged by name. Abort takes effect
/// at the task's next await, so a task inside a blocking call finishes that
/// call first, but shutdown itself no longer waits on it.
pub(super) async fn stop_task(
    name: &str,
    mut task: tokio::task::JoinHandle<()>,
    grace: std::time::Duration,
) {
    match tokio::time::timeout(grace, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!(warn wire: "{name} task ended abnormally before shutdown: {error}");
        }
        Err(_) => {
            eprintln!(warn wire: "{name} task did not stop within {grace:?} of shutdown; aborting it");
            task.abort();
        }
    }
}

pub(super) fn connector_gate_transition(gate: &Value) -> (Value, Value, Value) {
    (
        gate["state"].clone(),
        gate["epoch"].clone(),
        gate["holder_name"].clone(),
    )
}

pub(super) fn spawn_trigger_scheduler(
    state: Arc<ModuleState>,
    stop: mpsc::Receiver<()>,
    audit_retention: impl Into<settings::AuditRetention>,
) -> tokio::task::JoinHandle<()> {
    spawn_trigger_scheduler_every(SCHEDULER_TICK, state, stop, audit_retention)
}

/// `spawn_trigger_scheduler` with its tick interval named. The module always
/// runs `SCHEDULER_TICK`; tests pass a short tick so that waiting for the
/// scheduler's next pass takes milliseconds instead of a second.
pub(super) fn spawn_trigger_scheduler_every(
    tick_interval: std::time::Duration,
    state: Arc<ModuleState>,
    mut stop: mpsc::Receiver<()>,
    audit_retention: impl Into<settings::AuditRetention>,
) -> tokio::task::JoinHandle<()> {
    let audit_retention = audit_retention.into();
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scheduler =
        plexus_core::Scheduler::new(state.runtime.engine.clone(), audit_retention.window_ms())
            .with_stop_flag(Arc::clone(&stopping))
            .with_relay_health(state.health.relay.clone())
            .with_ownership_resume(Arc::clone(&state.runtime.ownership_resume))
            .with_agent_registry(Arc::clone(&state.runtime.agent_registry))
            .with_agent_sweep_resume(Arc::clone(&state.runtime.agent_sweep_resume));
    let mut scheduler = match &state.runtime.repository_registry {
        Some(registry) => scheduler.with_repository_registry(Arc::clone(registry)),
        None => scheduler,
    };
    tokio::spawn(async move {
        // A separate task can receive shutdown while the pass is inside
        // block_in_place. The JoinSet aborts the listener if the scheduler
        // unwinds or is aborted, rather than leaving a detached task behind.
        let mut stop_listener = tokio::task::JoinSet::new();
        let stop_flag = Arc::clone(&stopping);
        stop_listener.spawn(async move {
            stop.recv().await;
            stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        // Held for the life of the task: dropping it — on a clean break, or on
        // an unwind if a pass panics — marks the scheduler dead in the health
        // report, so a module that has silently stopped polling stops claiming
        // to be ok.
        let _liveness = health::SchedulerLiveness::new(Arc::clone(&state.health));
        let mut tick = tokio::time::interval(tick_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Start due, so the first tick performs each periodic task rather than
        // waiting a full interval. That is the ordinary reading of "every 60
        // seconds" and makes the wiring observable in a test measured in ticks
        // instead of minutes — a call site nothing can reach in a test is one
        // nothing proves is reached at all.
        let mut last_gate_state = None;
        // `None` means "never run", so both are due on the first tick. Not
        // `Instant::now() - interval`: that panics when the monotonic clock
        // reads less than the interval, as it can shortly after boot.
        let mut last_sweep: Option<std::time::Instant> = None;
        let mut last_health_probe: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
                biased;
                _ = stop_listener.join_next() => break,
                _ = tick.tick() => {
                    // Checked on every tick, because the tick is this task's
                    // first action once the host comes back: a suspended machine
                    // polls nothing, and without this check the time it spent
                    // asleep counts against the poller and reports a stall
                    // nobody can act on. Cheap enough for a one-second tick --
                    // two clock reads and an atomic load, writing only on the
                    // rare tick that follows a wake.
                    let gate = state.runtime.connector_home.status();
                    let transition = connector_gate_transition(&gate);
                    if last_gate_state.as_ref() != Some(&transition) {
                        eprintln!(info scheduler: "connector home scheduler gate: {gate}");
                        last_gate_state = Some(transition);
                    }
                    if !state.runtime.connector_home.held() { continue; }
                    state.health.note_host_suspension();
                    state.health.stamp_scheduler_pass();
                    // Poll for the same principals the health probes refresh:
                    // the operator principal plus every principal that owns a
                    // subscription or connection. Due-selection is
                    // principal-scoped, so each is scanned through its own query.
                     let principals = blocking_section(|| health_probe_principals(&state));
                     if stopping.load(std::sync::atomic::Ordering::Relaxed) { break; }
                     let now = plexus_core::storage::now_ms();
                    let sweep_due = last_sweep.is_none_or(|last| last.elapsed() >= POOL_SWEEP_INTERVAL);
                    if sweep_due {
                        last_sweep = Some(std::time::Instant::now());
                    }
                    let health_probe_due = last_health_probe
                        .is_none_or(|last| last.elapsed() >= HEALTH_PROBE_INTERVAL);
                    if health_probe_due {
                        last_health_probe = Some(std::time::Instant::now());
                    }
                    // The poll pass, health probe, and pool sweep run inside one
                    // blocking section. The probe makes blocking vendor calls, and
                    // the sweep is not merely tidy work that happens to sit here:
                    // evicting a pooled entry drops a reqwest::blocking client,
                    // which owns an internal tokio runtime, and dropping that on
                    // an async worker panics. This is the same hazard as every
                    // other transport call site in this module.
                    blocking_section(|| {
                        // The pass outcomes were previously DISCARDED here, and
                        // discarding them is what made a scheduler that refuses
                        // every poll indistinguishable from an idle one on the
                        // health surface.
                        // Timed around run_pass only, not around the sweep: the
                        // sweep is fixed housekeeping, and folding it in would
                        // attribute its cost to vendor latency, which is the one
                        // thing this measurement exists to isolate.
                        let started = std::time::Instant::now();
                        scheduler.set_audit_retention_window_ms(audit_retention.window_ms());
                        let report = scheduler.run_pass_report(&principals, now);
                        state.health.stamp_scheduler_selection_failures(report.selection_failures);
                        let (attempted, completed) = report.poll_counts();
                        let outcomes = report.outcomes;
                        let elapsed_ms = started.elapsed().as_millis() as u64;
                        // NAME THE UNCOMPLETED OUTCOMES, because the counters
                        // cannot.
                        //
                        // `schedulerPollsAttempted` and `schedulerPollsCompleted`
                        // are deliberately unclassified -- the useful reading of
                        // a healthy poller needs no judgement about why. But a
                        // persistent gap between them then has no explanation
                        // anywhere: twice now a restart has left a frozen
                        // shortfall (20, then 59) with every subscription active
                        // and zero vendor failures, and neither the gauges nor
                        // the store could say what the difference was.
                        //
                        // Logged per pass rather than counted per variant, so
                        // the numbers stay judgement-free and the DIAGNOSIS
                        // lives in the log where an operator reads it. Silent
                        // when every poll completes, which is the normal case,
                        // so this costs nothing on a healthy module.
                        if completed < attempted {
                            let mut reasons: Vec<String> = outcomes
                                .iter()
                                .filter(|outcome| {
                                    !matches!(outcome.cycle, PollCycle::Completed { .. } | PollCycle::Deferred { .. })
                                })
                                .map(|outcome| {
                                    let cause = match &outcome.cycle {
                                         PollCycle::Completed { .. } | PollCycle::Deferred { .. } => unreachable!("filtered outcomes"),
                                        PollCycle::VendorFailed { code } => {
                                            format!("vendor_failed:{code}")
                                        }
                                        PollCycle::Inconclusive { code } => {
                                            format!("inconclusive:{code}")
                                        }
                                        PollCycle::Suspended { reason } => {
                                            format!("suspended:{reason}")
                                        }
                                        PollCycle::NotEligible { reason } => {
                                            format!("not_eligible:{reason}")
                                        }
                                        PollCycle::StoreFailed { reason } => {
                                            format!("store_failed:{reason}")
                                        }
                                    };
                                    format!("{}={}", outcome.subscription_id, cause)
                                })
                                .collect();
                            // Bounded: a pass over every subscription could
                            // otherwise write one enormous line into a shared
                            // fleet log. The count is reported in full even when
                            // the list is truncated, so the number is never a
                            // sample.
                            let total = reasons.len();
                            reasons.truncate(8);
                            eprintln!(warn scheduler:
                                "scheduler pass: {} of {} polls did not complete: {}{}",
                                total,
                                attempted,
                                reasons.join(" "),
                                if total > 8 { " ..." } else { "" }
                            );
                        }
                        // Re-read after the pass because it may have suspended the
                        // final active subscription. Reporting the pre-pass count
                        // would briefly turn a deliberate circuit-breaker state into
                        // a scheduler-stall alarm.
                        match scheduler.store().active_subscription_schedule() {
                            Ok(Some((active, max_cadence_s))) => {
                                state
                                    .health
                                    .stamp_scheduler_subscription_count(active, max_cadence_s);
                            }
                            Ok(None) => {
                                // An empty active set has no maximum cadence. Clear
                                // both observations explicitly rather than assigning
                                // an invented cadence to scheduler idleness.
                                state.health.stamp_scheduler_no_active_subscriptions();
                            }
                            Err(error) => {
                                eprintln!(warn scheduler:
                                    "scheduler active-subscription schedule failed: {error}"
                                );
                            }
                        }
                        state
                            .health
                            .stamp_scheduler_outcomes(attempted, completed);
                        state
                            .health
                            .stamp_scheduler_pass_duration(attempted, elapsed_ms);
                        if health_probe_due && !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                              run_health_probes_for(&state, &principals, || stopping.load(std::sync::atomic::Ordering::Relaxed));
                        }
                        if health_probe_due && !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                              refresh_store_health(&state, &principals);
                        }
                        // Rebuilding the declaration reads every owner's connections.
                        // Do it on the housekeeping tick, not every poll tick.
                        if sweep_due && !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                            if let Some(declarations) = &state.runtime.search_declarations {
                                declarations.reconcile(state.store(), &principals, &state.runtime.web_search);
                            }
                        }
                        if sweep_due && !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                            state.runtime.mcp_transport.sweep_idle();
                        }
                        if sweep_due && !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                            state.runtime.rest_transport.sweep_idle();
                        }
                    });
                }
            }
        }
    })
}

/// Build the last observed health report without doing store or vendor IO.
pub(super) fn connector_home_health(state: &ModuleState) -> ModuleControlResponse {
    let mut report = state
        .health
        .report_with_transports(Some(health::TransportPanicRecoveries {
            mcp: state.runtime.mcp_transport.panic_recoveries(),
            rest: state.runtime.rest_transport.panic_recoveries(),
        }));
    if let ModuleControlResponse::HealthCheck {
        status,
        detail,
        metrics,
    } = &mut report
    {
        if !state.runtime.connector_home.held() {
            *status = subc_protocol::session::HealthStatus::Degraded;
            *detail = Some("connector_home_not_held".into());
        }
        if let Some(metrics) = metrics {
            metrics["ready"] = json!(true);
            metrics["connectorHome"] = state.runtime.connector_home.status();
            let cached = state
                .health
                .store_metrics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = cached.as_object() {
                for (key, value) in cached {
                    metrics[key] = value.clone();
                }
            }
            metrics["lastPublishError"] = json!(state.health.last_publish_error());
            metrics["webSearch"] = web_search_health::render(
                state
                    .health
                    .web_search
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref(),
                &state.runtime.web_search,
                state
                    .runtime
                    .search_declarations
                    .as_ref()
                    .map(|declarations| declarations.status())
                    .as_ref(),
            );
        }
    }
    report
}

pub(super) fn refresh_store_health(state: &ModuleState, principals: &[String]) {
    let mut metrics = json!({});
    // The outbox aggregates count and join hundred-thousand-row tables, so
    // they are sampled hourly and cached; the rest of this refresh stays
    // per-minute. A failed re-query keeps the previous sample instead of
    // dropping the gauge, because a store hiccup is not an empty outbox.
    {
        let mut cached = state
            .health
            .outbox_health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let due = cached.as_ref().is_none_or(|sample| {
            sample.sampled_at.elapsed() >= crate::health::OUTBOX_HEALTH_INTERVAL
        });
        if due {
            match state.store().event_outbox_health() {
                Ok(outbox) => {
                    let sample = crate::health::CachedOutboxHealth {
                        sampled_at: std::time::Instant::now(),
                        depth: outbox.depth,
                        overlapping_key_rows: outbox.overlapping_key_rows,
                        dropped_on_unsubscribe: outbox.dropped_on_unsubscribe,
                        dropped_on_delete: outbox.dropped_on_delete,
                        orphaned_markers: outbox.orphaned_markers,
                    };
                    *cached = Some(sample);
                }
                Err(error) => eprintln!(warn health: "outbox health read failed: {error}"),
            }
        }
        if let Some(sample) = cached.as_ref() {
            metrics["outboxDepth"] = json!(sample.depth);
            metrics["overlappingKeyRows"] = json!(sample.overlapping_key_rows);
            metrics["droppedOnUnsubscribe"] = json!(sample.dropped_on_unsubscribe);
            metrics["droppedOnDelete"] = json!(sample.dropped_on_delete);
            metrics["orphanedMarkers"] = json!(sample.orphaned_markers);
        }
    }
    let stored_cadence = effective_ci_cadence_from_store(
        state.store(),
        principals,
        plexus_core::scheduler::RelayPollingHealth::slow_polling(state.health.relay.as_ref()),
    );
    match stored_cadence
        .map(Ok)
        .unwrap_or_else(|| state.store().ci_quota_cadence_s())
    {
        Ok(cadence) => metrics["effectiveCiCadenceS"] = json!(cadence),
        Err(error) => {
            eprintln!(warn health: "CI quota cadence read failed: {error}");
            metrics["effectiveCiCadenceS"] = Value::Null;
        }
    }
    let web_search = match web_search_health::snapshot(
        state.store(),
        principals,
        state.runtime.web_search.now_ms(),
    ) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            eprintln!(warn health: "web search health read failed: {error}");
            None
        }
    };
    *state
        .health
        .web_search
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = web_search;
    *state
        .health
        .store_metrics
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = metrics;
}

fn effective_ci_cadence_from_store(
    store: &PlexusStore,
    principals: &[String],
    relay_slow: bool,
) -> Option<i64> {
    let mut stored_cadence: Option<i64> = None;
    let mut cadences = plexus_core::scheduler::PollingCadences::new(store, relay_slow);
    for principal in principals {
        match store.list_subscriptions(principal, None, None) {
            Ok(subs) => {
                for sub in subs {
                    if sub.status == "active" && sub.cursor_kind.as_str() == "ci_runs" {
                        // The CI cadence reported is the shortest among active
                        // CI-run watches, since that watch is due soonest.
                        let cadence = cadences.effective_cadence_s(&sub);
                        stored_cadence = Some(stored_cadence.map_or(cadence, |s| s.min(cadence)));
                    }
                }
            }
            Err(error) => eprintln!(warn health: "CI cadence read failed for {principal}: {error}"),
        }
    }
    stored_cadence
}

pub(super) fn run_health_probes_for(
    state: &ModuleState,
    principals: &[String],
    stop_requested: impl Fn() -> bool,
) {
    let mut total = 0_u64;
    let mut degraded = 0_u64;
    for principal in principals {
        let connections = match state.store().list_connections(principal) {
            Ok(connections) => connections,
            Err(error) => {
                eprintln!(warn health:
                    "health probe connection listing failed for principal {principal}: {error}"
                );
                continue;
            }
        };
        for summary in connections {
            // `degraded` is probed alongside `active`, and that is the whole
            // point of the probe rather than an edge case.
            //
            // A refresh failure sets `degraded`, and only a successful refresh
            // clears it. Skipping non-active connections would make that
            // recovery unreachable: nothing else re-runs discovery either,
            // because reads return early from the freshness check (only writes
            // reach it) and `connect` consumes a single-use ticket that no
            // longer exists.
            //
            // Without this, a connection can stay degraded indefinitely, across
            // restarts, while its vendor is reachable the whole time. Every
            // other status is deliberately skipped: `revoked` and `pending`
            // describe authority, not health, and probing them would resurrect
            // a connection an operator deliberately stopped, so a revoked one
            // is neither probed nor logged here. No production path writes any
            // further status, so none is probed for recovery.
            if summary.status != "active" && summary.status != "degraded" {
                continue;
            }
            if stop_requested() {
                return;
            }
            total += 1;
            if summary.status == "degraded" {
                degraded += 1;
            }
            if let Err(error) = state.runtime.reconciler.health_probe_connection(
                principal,
                &summary.connection_id,
                state.runtime.credential_source().as_ref(),
            ) {
                eprintln!(warn health:
                    "health probe failed for principal {principal}, connection {}: {error}",
                    summary.connection_id
                );
            }
        }
    }
    // Counted BEFORE probing, from the rows as they stood, so the numbers
    // describe what this pass set out to check. Counting after would report
    // recoveries this pass performed and hide the condition that prompted them.
    state.health.stamp_connections(total, degraded);
}

/// The principals worth scanning: the operator principal plus owners of a
/// subscription or connection.
///
/// The operator principal remains unconditional so a fresh store still gets its
/// boot-time transport registration and health-probe pass. The stored owners
/// come from the two bounded tables that represent work the scheduler can act
/// on; audit history can remain after that work disappears.
pub(super) fn health_probe_principals(state: &ModuleState) -> Vec<String> {
    let mut principals = vec!["direct".to_string()];
    match state.store().poll_and_probe_principals() {
        Ok(rows) => {
            for principal in rows {
                if !principals.iter().any(|value| value == &principal) {
                    principals.push(principal);
                }
            }
        }
        // Falling back to direct narrows polling as well as probing. The
        // selection-failure gauge cannot see omitted principals: they never
        // reach selection. Keep the lost coverage visible in the diagnostic.
        Err(error) => eprintln!(error health:
            "health probe principal enumeration failed for stored subscription and connection owners; falling back to principal direct only: {error}"
        ),
    }
    principals
}
