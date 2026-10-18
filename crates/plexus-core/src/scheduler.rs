//! The trigger scheduler: decides WHEN due subscriptions are polled.
//!
//! [`Poller::poll_once`](crate::poller::Poller::poll_once) performs exactly one
//! poll cycle and is deliberately clock-free; this module is the clock. It
//! selects the subscriptions that are due, applies failure backoff and the
//! circuit breaker, and drives `poll_once` over them.
//!
//! The selection is split across two layers on purpose:
//!
//! - [`PlexusStore::due_subscriptions`](crate::storage::PlexusStore::due_subscriptions)
//!   is the base cadence bound — `active` and either never polled or last polled
//!   at least one `cadence_s` ago. It knows nothing about failures.
//! - This module layers quota and relay cadence floors and the failure policy
//!   on top of those rows. A failing subscription waits out exponential backoff;
//!   after `CIRCUIT_BREAKER_FAILURES` consecutive failed polls it is suspended,
//!   so a broken vendor or credential stops costing requests until an operator
//!   resumes it.
//!
//! Cadence floors and the failure policy only ever lengthen the wait or stop
//! polling; they never make a subscription poll faster than its stored cadence.
//!
//! # One poll at a time, sequentially
//!
//! [`Scheduler::run_pass`] polls the due subscriptions ONE AT A TIME in a single
//! sequential pass. That is a deliberate simplification, not an oversight: it
//! makes the "no overlap" requirement (a subscription is never polled twice
//! at once) structural rather than something enforced with generation
//! counters or leases. A single sequential pass cannot start a second poll for
//! a subscription that is already polling, because it is not doing anything
//! else while a poll runs.
//!
//! The cost is head-of-line blocking — a slow vendor delays every other
//! subscription behind it in the pass. For a personal fleet with a handful of
//! subscriptions that is the right trade, and it is far easier to reason about
//! than a concurrent poller that would need an atomic per-subscription claim to
//! keep two ticks from overlapping.
//!
//! # Missed ticks collapse
//!
//! If the daemon was asleep or busy and several cadence intervals passed, a
//! subscription is polled ONCE, not once per missed interval. The cursor makes
//! replay pointless: the next successful poll fetches everything since the last
//! cursor, so catching up on skipped ticks would re-fetch the same events and
//! burn quota to produce duplicates the dedupe layer discards. Selection is a
//! boolean "is it due now", never a count of how overdue it is.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use crate::agent_registry::AgentRegistry;
use crate::agent_retirement::AGENT_RETIREMENT_SWEEP_INTERVAL_MS;
use crate::credentials::CredentialSource;
use crate::governance::GovernanceEngine;
use crate::poller::{PollCycle, Poller};
use crate::storage::{PlexusStore, TriggerSubscription, CIRCUIT_BREAKER_SUSPENSION_REASON};
use crate::transport::Transport;

/// Exponential base for failure backoff: each consecutive vendor failure
/// multiplies the wait before the next attempt by this factor.
///
/// Base 2 is the conventional exponential backoff. It pulls a failing
/// subscription off a struggling vendor quickly — 2x, 4x, 8x, 16x cadence —
/// while a one- or two-failure blip, which is the common case, recovers within
/// a couple of cadences. A larger base would recover transient blips too
/// slowly; a smaller one would not relieve vendor quota pressure fast enough.
const BACKOFF_BASE: i64 = 2;

/// Absolute ceiling on the backoff interval, in seconds.
///
/// The exponential interval is capped here so a still-active failing
/// subscription is retried at least hourly rather than pushed arbitrarily far
/// into the future on a long cadence. The ceiling only matters near the
/// circuit-breaker threshold: well below it the exponential interval is what
/// spaces attempts out, and at the threshold the breaker suspends outright. Its
/// job is to keep the final pre-suspension attempts from being spaced far apart
/// when the subscription's own cadence is long (a 5-minute cadence at four
/// failures would otherwise wait 80 minutes).
const BACKOFF_CEILING_S: i64 = 3600;

/// Consecutive vendor failures at which the circuit breaker trips.
///
/// Five consecutive vendor failures is the point at which "the endpoint is
/// down" becomes a far better explanation than "transient blip". With base-2
/// backoff the four waits between those attempts are 2, 4, 8 and 16
/// cadences before the one-hour ceiling (never shorter than the cadence).
/// A vendor that recovers within those waits is caught by an
/// ordinary attempt; past it, continuing to poll only burns quota against a
/// dead endpoint. Suspending makes the
/// dead subscription visible to the operator instead of failing silently
/// forever. A suspension never auto-resumes, so reinstating it is a fresh
/// operator consent — which is correct, because a vendor that was down long
/// enough to trip the breaker may have changed underneath the subscription.
const CIRCUIT_BREAKER_FAILURES: i64 = 5;

/// Most approvals waiting on a daemon scope that one pass retries. Each retry
/// is one `scope.describe` round trip; the rest wait for the next pass.
const WAITING_APPROVAL_RETRIES_PER_PASS: usize = 16;

/// How long a watch waits before its next poll after one that failed on a
/// credential only a person can repair (sign in again, replace a revoked or
/// broken credential): one hour.
///
/// Such a failure is not counted toward the circuit breaker, because one
/// expired credential is usually shared by every watch on its connection and
/// suspending them all would need each one resumed by hand after the repair.
/// Polling at the normal cadence would only repeat a failure nothing will
/// change until a person acts, so the watch is retried hourly instead, and the
/// first poll that succeeds puts it back on its cadence. The vendor-failure
/// streak cannot carry this (it would feed the breaker), so the wait is kept
/// here, in memory: a restart polls once, finds the same failure, and waits
/// again.
const CREDENTIAL_REPAIR_RETRY_MS: i64 = 3_600_000;

/// Whether the GitHub webhook relay has stayed connected, with no gap or reset,
/// long enough that polling can slow down. The module's health report reads the
/// same in-memory relay status, so the mode it reports is the mode the
/// scheduler is actually using.
pub trait RelayPollingHealth: Send + Sync {
    fn slow_polling(&self) -> bool;
}

/// After a healthy relay hour, GitHub issue, pull-request and CI-run watches
/// (the kinds webhooks also deliver) wait at least 30 minutes between polls;
/// release watches keep their cadence because the relay carries no release
/// events. Stored cadences and CI quota spacing remain lower bounds; this
/// calculation never writes a subscription's cadence back to the store.
fn effective_cadence_s(
    subscription: &TriggerSubscription,
    ci_quota_cadence_s: i64,
    github_slow: bool,
) -> i64 {
    let cadence = if subscription.cursor_kind == "ci_runs" {
        subscription.cadence_s.max(ci_quota_cadence_s)
    } else {
        subscription.cadence_s
    };
    if github_slow
        && matches!(
            subscription.action.as_str(),
            "list_issues" | "list_pull_requests" | "list_workflow_runs"
        )
    {
        cadence.max(1800)
    } else {
        cadence
    }
}

/// Lazily read cadence inputs once per scheduling pass or health refresh, not
/// once per watch. Recreating this snapshot each pass observes connection and
/// quota changes without a persistent cache or invalidation protocol.
pub struct PollingCadences<'a> {
    store: &'a PlexusStore,
    relay_slow: bool,
    ci_quota_cadence_s: Option<i64>,
    github_connections: HashMap<String, HashSet<String>>,
}

impl<'a> PollingCadences<'a> {
    pub fn new(store: &'a PlexusStore, relay_slow: bool) -> Self {
        Self {
            store,
            relay_slow,
            ci_quota_cadence_s: None,
            github_connections: HashMap::new(),
        }
    }

    pub fn effective_cadence_s(&mut self, subscription: &TriggerSubscription) -> i64 {
        let ci_floor = if subscription.cursor_kind == "ci_runs" {
            *self.ci_quota_cadence_s.get_or_insert_with(|| {
                // A failed quota read defers timed CI polls for this pass rather
                // than risking requests beyond the budget.
                self.store.ci_quota_cadence_s().unwrap_or_else(|error| {
                    eprintln!(warn scheduler: "CI cadence read failed: {error}");
                    i64::MAX
                })
            })
        } else {
            0
        };
        let github_slow = if self.relay_slow {
            if !self
                .github_connections
                .contains_key(&subscription.principal)
            {
                let connections = self
                    .store
                    .list_connections(&subscription.principal)
                    .unwrap_or_else(|error| {
                        eprintln!(warn scheduler: "relay cadence connection read failed: {error}");
                        Vec::new()
                    });
                let github = connections
                    .into_iter()
                    .filter(|connection| {
                        matches!(connection.app_key.as_str(), "github" | "github_actions")
                    })
                    .map(|connection| connection.connection_id)
                    .collect();
                self.github_connections
                    .insert(subscription.principal.clone(), github);
            }
            self.github_connections[&subscription.principal].contains(&subscription.connection_id)
        } else {
            false
        };
        effective_cadence_s(subscription, ci_floor, github_slow)
    }
}

/// The scheduler's decision for one cadence-due subscription.
///
/// The store query has already established the subscription is `active` and
/// past its base cadence; this classifies what the failure policy does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DueDecision {
    /// Poll now: no failures, or the backoff interval has elapsed.
    Poll,
    /// Failing, but the backoff interval has not elapsed yet. Skip this pass.
    InBackoff,
    /// Failing past the circuit-breaker threshold. Suspend instead of polling.
    BreakerTripped,
}

/// Decides when trigger subscriptions are polled and drives one poll cycle for
/// each that is due.
///
/// Constructible and drivable without a live daemon: [`due_now`](Self::due_now)
/// answers "what is due right now" and [`run_pass`](Self::run_pass) runs one
/// scheduling pass synchronously, so tests exercise the whole policy without
/// waiting on a real timer.
pub struct Scheduler<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    store: Arc<PlexusStore>,
    poller: Poller<C, T>,
    engine: GovernanceEngine<C, T>,
    audit_retention_window_ms: i64,
    /// Registry consulted by the hourly retired-agent sweep. Absent means the
    /// sweep does not run.
    agent_registry: Option<Arc<dyn AgentRegistry>>,
    /// Pass clock reading of the last retired-agent sweep, if one has run.
    last_agent_sweep_ms: Mutex<Option<i64>>,
    /// Where the next retired-agent sweep starts after one stopped early.
    agent_sweep_resume: crate::agent_retirement::SweepResume,
    repository_registry: Option<Arc<dyn crate::repository_ownership::RepositoryRegistry>>,
    ownership_throttle: crate::repository_ownership::OwnershipThrottle,
    /// Where the next ownership reconciliation starts after one stopped early.
    ownership_resume: crate::repository_ownership::OwnershipResume,
    /// Watches waiting out [`CREDENTIAL_REPAIR_RETRY_MS`], by subscription id,
    /// with the pass time before which they are not polled.
    credential_repair_waits: Mutex<std::collections::HashMap<String, i64>>,
    relay_health: Option<Arc<dyn RelayPollingHealth>>,
}

/// The outcome of one subscription within a scheduling pass.
#[derive(Debug, Clone, PartialEq)]
pub struct PassOutcome {
    pub principal: String,
    pub subscription_id: String,
    pub cycle: PollCycle,
}

/// Whole-pass observations, including principal selection failures that have no subscription ID.
#[derive(Debug, Default)]
pub struct PassReport {
    pub outcomes: Vec<PassOutcome>,
    pub selection_failures: u64,
}

impl PassReport {
    /// Admission deferrals did not attempt work and are not failures. Keep the
    /// warning and health counters on this same classification so a quota wait
    /// cannot masquerade as a scheduler stall.
    pub fn poll_counts(&self) -> (u64, u64) {
        let attempted = self
            .outcomes
            .iter()
            .filter(|outcome| !matches!(outcome.cycle, PollCycle::Deferred { .. }))
            .count() as u64;
        let completed = self
            .outcomes
            .iter()
            .filter(|outcome| matches!(outcome.cycle, PollCycle::Completed { .. }))
            .count() as u64;
        (attempted, completed)
    }
}

impl<C, T> Scheduler<C, T>
where
    C: CredentialSource + ?Sized + 'static,
    T: Transport + ?Sized + 'static,
{
    /// Build a scheduler over the same governance engine the facade dispatches
    /// through. Polls therefore pass the identical authority chain; the
    /// scheduler decides WHEN and the poller decides WHETHER and HOW.
    pub fn new(engine: GovernanceEngine<C, T>, audit_retention_window_ms: i64) -> Self {
        let store = Arc::clone(engine.store());
        Self {
            store,
            poller: Poller::new(engine.clone()),
            engine,
            audit_retention_window_ms,
            agent_registry: None,
            last_agent_sweep_ms: Mutex::new(None),
            agent_sweep_resume: Default::default(),
            repository_registry: None,
            ownership_throttle: Default::default(),
            ownership_resume: Default::default(),
            credential_repair_waits: Mutex::new(Default::default()),
            relay_health: None,
        }
    }

    pub fn with_relay_health(mut self, relay: Arc<dyn RelayPollingHealth>) -> Self {
        self.relay_health = Some(relay);
        self
    }

    /// Enable the hourly sweep that revokes grants of agents the registry
    /// reports retired. The first pass sweeps; later passes wait out
    /// [`AGENT_RETIREMENT_SWEEP_INTERVAL_MS`] of pass time.
    pub fn with_agent_registry(mut self, registry: Arc<dyn AgentRegistry>) -> Self {
        self.agent_registry = Some(registry);
        self
    }

    /// Hourly, refresh GitHub watches' project labels from the repository
    /// registry and create missing issue and pull-request watches.
    pub fn with_repository_registry(
        mut self,
        registry: Arc<dyn crate::repository_ownership::RepositoryRegistry>,
    ) -> Self {
        self.repository_registry = Some(registry);
        self
    }

    pub fn store(&self) -> &Arc<PlexusStore> {
        &self.store
    }

    /// The subscriptions that would be polled by a pass at `now_ms`, across the
    /// given principals: cadence-due, out of backoff, and below the
    /// circuit-breaker threshold.
    ///
    /// This is a pure read with no side effects — it does not suspend
    /// breaker-tripped subscriptions or advance any cursor — so a test can ask
    /// "what is due right now" without mutating state. A breaker-tripped
    /// subscription is excluded here (a pass would suspend it, not poll it).
    pub fn due_now(&self, principals: &[String], now_ms: i64) -> Vec<TriggerSubscription> {
        let mut due = Vec::new();
        let mut cadences = self.polling_cadences();
        for principal in principals {
            let candidates = match self.store.due_subscriptions(principal, now_ms) {
                Ok(candidates) => candidates,
                Err(error) => {
                    eprintln!(warn scheduler: "due selection failed for principal {principal}: {error}");
                    continue;
                }
            };
            for subscription in candidates {
                if self.classify_subscription(&subscription, now_ms, &mut cadences)
                    == DueDecision::Poll
                {
                    due.push(subscription);
                }
            }
        }
        due
    }

    /// Test-facing shorthand for [`Self::run_pass_report`] returning only poll
    /// outcomes. Production also consumes the report's selection-failure count.
    pub fn run_pass(&self, principals: &[String], now_ms: i64) -> Vec<PassOutcome> {
        self.run_pass_report(principals, now_ms).outcomes
    }

    /// Run one scheduling pass: suspend any cadence-due subscription whose
    /// vendor-failure streak has reached the circuit breaker, then poll the
    /// remaining due subscriptions ONE AT A TIME, sequentially.
    ///
    /// Subscriptions still in backoff are skipped this pass and produce no
    /// outcome. Audit and reservation retention ride the same scheduler pass and
    /// each remove at most one storage-level batch; neither suppresses due polling
    /// if a trim fails. Returns the terminal [`PollCycle`] for every subscription
    /// that was suspended or polled, in selection order, together with the
    /// selection-failure count for this pass only, not since boot.
    pub fn run_pass_report(&self, principals: &[String], now_ms: i64) -> PassReport {
        if let Some(registry) = &self.repository_registry {
            if self.ownership_throttle.due(now_ms) {
                crate::repository_ownership::run_and_report(
                    &self.store,
                    registry.as_ref(),
                    now_ms,
                    &self.ownership_resume,
                );
            }
        }
        // Read uncertain writes before ordinary polls consume their timeout window.
        if let Err(error) = self
            .engine
            .sweep_write_reconciliations(now_ms, self.audit_retention_window_ms)
        {
            eprintln!(warn scheduler: "write reconciliation sweep failed: {error}");
        }
        match self
            .store
            .prune_audit(now_ms, self.audit_retention_window_ms)
        {
            Ok(removed) if removed > 0 => {
                // Trigger-event pruning writes a marker because it can destroy an
                // UNACKED payload. Audit rows have no unseen/seen distinction, and
                // writing one audit marker per pruning tick would feed retention
                // back into the table with self-referential noise. The operator log
                // records the destructive pass without manufacturing more journal
                // history that will itself be pruned later.
                eprintln!(debug scheduler: "audit retention pruned {removed} row(s)");
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!(warn scheduler: "audit retention pass failed: {error}");
            }
        }

        match crate::github::sweeper::sweep_receipts(&self.store, now_ms) {
            Ok(uncertain) if !uncertain.is_empty() => {
                eprintln!(warn scheduler: "receipt sweep recorded {} uncertain write(s)", uncertain.len());
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!(warn scheduler: "receipt sweep failed: {error}");
            }
        }

        match self.store.prune_reservations(now_ms) {
            Ok(removed) if removed > 0 => {
                eprintln!(debug scheduler: "reservation retention pruned {removed} row(s)");
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!(warn scheduler: "reservation retention pass failed: {error}");
            }
        }

        // Approvals held unsent because their daemon scope could not be
        // confirmed (typically the owner has not re-synced since a daemon
        // restart). Each retry asks the daemon once; the bound keeps one pass
        // from queuing many daemon round trips.
        let retried = self
            .engine
            .retry_waiting_approvals(WAITING_APPROVAL_RETRIES_PER_PASS);
        if retried > 0 {
            eprintln!(debug scheduler: "retried {retried} approval(s) waiting on a scope");
        }

        let mut outcomes = Vec::new();
        let mut selection_failures = 0;
        let mut cadences = self.polling_cadences();
        for principal in principals {
            let candidates = match self.store.due_subscriptions(principal, now_ms) {
                Ok(candidates) => candidates,
                Err(error) => {
                    eprintln!(error scheduler: "scheduler selection failed for principal {principal}: {error}");
                    selection_failures += 1;
                    continue;
                }
            };
            for subscription in candidates {
                match self.classify_subscription(&subscription, now_ms, &mut cadences) {
                    DueDecision::BreakerTripped => {
                        self.credential_repair_waits
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .remove(&subscription.subscription_id);
                        crate::poller::forget_subscription(&subscription.subscription_id);
                        // Suspend with a machine-readable reason. `suspend`
                        // records the coverage gap this creates, so the operator
                        // sees the interval the poller stopped covering.
                        let cycle = match self.store.suspend(
                            principal,
                            &subscription.subscription_id,
                            CIRCUIT_BREAKER_SUSPENSION_REASON,
                        ) {
                            Ok(_) => PollCycle::Suspended {
                                reason: CIRCUIT_BREAKER_SUSPENSION_REASON.to_string(),
                            },
                            Err(error) => PollCycle::StoreFailed {
                                reason: error.to_string(),
                            },
                        };
                        outcomes.push(PassOutcome {
                            principal: principal.clone(),
                            subscription_id: subscription.subscription_id,
                            cycle,
                        });
                    }
                    DueDecision::InBackoff => {}

                    DueDecision::Poll => {
                        let cycle = self
                            .poller
                            .poll_once(principal, &subscription.subscription_id);
                        self.note_credential_repair(&subscription.subscription_id, &cycle, now_ms);
                        outcomes.push(PassOutcome {
                            principal: principal.clone(),
                            subscription_id: subscription.subscription_id,
                            cycle,
                        });
                    }
                }
            }
        }
        // After the polls, not beside the other housekeeping above: the sweep
        // makes one registry round trip per agent, and running it first would
        // hold this pass's polls behind that traffic once an hour.
        self.sweep_retired_agents_if_due(now_ms);
        PassReport {
            outcomes,
            selection_failures,
        }
    }

    fn polling_cadences(&self) -> PollingCadences<'_> {
        PollingCadences::new(
            &self.store,
            self.relay_health
                .as_ref()
                .is_some_and(|relay| relay.slow_polling()),
        )
    }

    fn classify_subscription(
        &self,
        subscription: &TriggerSubscription,
        now_ms: i64,
        cadences: &mut PollingCadences<'_>,
    ) -> DueDecision {
        let decision = classify(subscription, now_ms);
        // Extra cadence floors can only delay a poll. Watches already held by
        // backoff, credential repair or quota need no cadence database reads.
        if decision != DueDecision::Poll {
            return decision;
        }
        if self.waiting_for_credential_repair(&subscription.subscription_id, now_ms)
            || self
                .poller
                .waiting_for_ci_quota(&subscription.subscription_id, now_ms)
        {
            return DueDecision::InBackoff;
        }
        let Some(last_polled) = subscription.last_polled_at_ms else {
            return DueDecision::Poll;
        };
        let cadence = cadences.effective_cadence_s(subscription);
        if now_ms.saturating_sub(last_polled)
            < effective_interval_ms(cadence, subscription.consecutive_vendor_failures)
        {
            return DueDecision::InBackoff;
        }
        DueDecision::Poll
    }

    /// Whether this watch's last poll failed on a credential needing repair
    /// less than [`CREDENTIAL_REPAIR_RETRY_MS`] ago.
    fn waiting_for_credential_repair(&self, subscription_id: &str, now_ms: i64) -> bool {
        self.credential_repair_waits
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(subscription_id)
            .is_some_and(|until| now_ms < *until)
    }

    /// Start an hour's wait after a credential-repair failure. Any other
    /// outcome ends the wait, so the first poll that gets past the credential
    /// returns the watch to its cadence. (A poll only runs once any earlier
    /// wait has expired, so dropping the entry never shortens one.)
    fn note_credential_repair(&self, subscription_id: &str, cycle: &PollCycle, now_ms: i64) {
        let mut waits = self
            .credential_repair_waits
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if crate::poller::needs_credential_repair(cycle) {
            waits.retain(|_, until| *until > now_ms);
            if !waits.contains_key(subscription_id) && waits.len() >= 4096 {
                if let Some(oldest) = waits
                    .iter()
                    .min_by_key(|(_, until)| **until)
                    .map(|(id, _)| id.clone())
                {
                    waits.remove(&oldest);
                }
            }
            waits.insert(
                subscription_id.to_string(),
                now_ms.saturating_add(CREDENTIAL_REPAIR_RETRY_MS),
            );
        } else {
            waits.remove(subscription_id);
        }
    }

    /// Run the retired-agent sweep when an hour of pass time has passed since
    /// the last one. The timestamp is taken before the sweep runs, so a sweep
    /// that fails waits the full interval too instead of retrying every tick
    /// against a registry that is down.
    fn sweep_retired_agents_if_due(&self, now_ms: i64) {
        let Some(registry) = self.agent_registry.as_deref() else {
            return;
        };
        {
            let mut last = self
                .last_agent_sweep_ms
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if last.is_some_and(|last| {
                now_ms.saturating_sub(last) < AGENT_RETIREMENT_SWEEP_INTERVAL_MS
            }) {
                return;
            }
            *last = Some(now_ms);
        }
        crate::agent_retirement::run_and_report(&self.store, registry, &self.agent_sweep_resume);
    }
}

/// Classify a cadence-due subscription under the failure policy.
fn classify(subscription: &TriggerSubscription, now_ms: i64) -> DueDecision {
    if subscription.consecutive_vendor_failures >= CIRCUIT_BREAKER_FAILURES {
        return DueDecision::BreakerTripped;
    }
    if backoff_elapsed(subscription, now_ms) {
        DueDecision::Poll
    } else {
        DueDecision::InBackoff
    }
}

/// Whether enough time has passed since the last attempt to poll again, given
/// the subscription's current failure streak. A never-polled subscription is
/// always ready; a healthy one waits exactly its cadence (the store query has
/// already established that much); a failing one waits the exponential backoff.
fn backoff_elapsed(subscription: &TriggerSubscription, now_ms: i64) -> bool {
    let Some(last_polled_at_ms) = subscription.last_polled_at_ms else {
        return true;
    };
    let interval = effective_interval_ms(
        subscription.cadence_s,
        subscription.consecutive_vendor_failures,
    );
    now_ms.saturating_sub(last_polled_at_ms) >= interval
}

/// The wait before the next attempt for a subscription with the given cadence
/// and consecutive vendor-failure count, in milliseconds.
///
/// Zero failures yields exactly the cadence. Each consecutive failure multiplies
/// the cadence by [`BACKOFF_BASE`], capped at [`BACKOFF_CEILING_S`]. The result
/// never drops below the cadence itself: backoff only ever lengthens the wait,
/// so even a long-cadence subscription held against the ceiling is not polled
/// more often than it asked for.
fn effective_interval_ms(cadence_s: i64, consecutive_vendor_failures: i64) -> i64 {
    let cadence_ms = cadence_s.saturating_mul(1000);
    if consecutive_vendor_failures <= 0 {
        return cadence_ms;
    }
    // Bound the exponent so a corrupt or absurd failure count cannot overflow
    // the power; the ceiling clamps the result regardless.
    let exponent = consecutive_vendor_failures.min(63) as u32;
    let multiplier = BACKOFF_BASE.saturating_pow(exponent);
    let backoff_ms = cadence_ms.saturating_mul(multiplier);
    let ceiling_ms = BACKOFF_CEILING_S.saturating_mul(1000);
    backoff_ms.min(ceiling_ms).max(cadence_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::agent_registry::{AgentLookup, StubAgentRegistry};
    use crate::credentials::StubCredentialSource;
    use crate::governance::GovernanceEngine;
    use crate::storage::{
        now_ms, CatalogActionInput, Ceiling, GrantInput, AUDIT_MILLIS_PER_DAY,
        DEFAULT_AUDIT_RETENTION_DAYS, RESERVATION_RETENTION_MS,
    };
    use crate::transport::{MockResponse, MockTransport};
    use cortexkit_store::StorageDescriptor;
    use cortexkit_store_types::{Isolation, StorageBackend};
    use serde_json::json;

    static SCHEDULER_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn credential_waits_are_bounded_at_4097_subscriptions() {
        let (_, _, engine) = scheduler_engine(json!({"items":[],"next_cursor":"next"}));
        let scheduler = Scheduler::new(engine, 86_400_000);
        for id in 0..4097 {
            scheduler.note_credential_repair(
                &format!("watch-{id:05}"),
                &PollCycle::Inconclusive {
                    code: "credential_auth_required".into(),
                },
                0,
            );
        }
        assert_eq!(
            scheduler.credential_repair_waits.lock().unwrap().len(),
            4096,
            "retired watch waits must remain bounded"
        );
    }

    /// Build a store with a `sync_token` read action, a poll grant, and an
    /// active credentialed connection, plus a governance engine over it with a
    /// mock transport programmed to return `response`. Mirrors the poll-path
    /// fixture so `run_pass` drives `poll_once` through the full authority
    /// chain and reaches the transport.
    fn scheduler_engine(
        response: serde_json::Value,
    ) -> (
        Arc<PlexusStore>,
        Arc<MockTransport>,
        GovernanceEngine<StubCredentialSource, MockTransport>,
    ) {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!(
                "scheduler-test-{}-{}",
                now_ms(),
                SCHEDULER_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open scheduler store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "scheduler_fixture",
                "pending",
                &json!({}),
            )
            .expect("insert connection");
        let manifest = json!({
            "schema_version": 1,
            "key": "scheduler_fixture",
            "name": "Scheduler fixture",
            "description": "manifest used by scheduler tests",
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
                "poll": {"item_kind": "issue", "cursor_kind": "sync_token"}
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
                schema: json!({"type": "object"}),
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
        let transport = Arc::new(MockTransport::default());
        transport.set_response(MockResponse::Success(response));
        let engine = GovernanceEngine::new(
            Arc::clone(&store),
            Arc::new(credentials),
            Arc::clone(&transport),
        );
        (store, transport, engine)
    }

    /// Subscribe and return the subscription id.
    fn subscribe(store: &PlexusStore, cadence_s: i64) -> String {
        store
            .subscribe("direct", "connection", "read_action", cadence_s)
            .expect("subscribe")
            .expect("subscription")
            .subscription_id
    }

    fn principals() -> Vec<String> {
        vec!["direct".to_string()]
    }

    /// Read a subscription's stored state back from the store.
    fn stored(store: &PlexusStore, subscription_id: &str) -> TriggerSubscription {
        store
            .subscription("direct", subscription_id)
            .expect("read subscription")
            .expect("subscription exists")
    }

    #[test]
    fn cadence_inputs_skip_connections_in_normal_mode_and_reads_for_held_watches() {
        let (store, _, engine) = scheduler_engine(json!({"items":[]}));
        let id = subscribe(&store, 300);
        let mut sub = stored(&store, &id);
        let mut cadences = PollingCadences::new(&store, false);
        assert_eq!(cadences.effective_cadence_s(&sub), 300);
        assert!(
            cadences.github_connections.is_empty(),
            "normal mode must not load connection membership"
        );
        assert_eq!(cadences.ci_quota_cadence_s, None);
        sub.cursor_kind = "ci_runs".into();
        assert_eq!(cadences.effective_cadence_s(&sub), 300);
        assert!(
            cadences.github_connections.is_empty(),
            "normal CI must not load connection membership"
        );
        assert_eq!(cadences.ci_quota_cadence_s, Some(300));

        let scheduler = Scheduler::new(engine, 86_400_000);
        let mut cadences = PollingCadences::new(&store, true);
        sub.last_polled_at_ms = Some(0);
        sub.consecutive_vendor_failures = 4;
        assert_eq!(
            scheduler.classify_subscription(&sub, 301_000, &mut cadences),
            DueDecision::InBackoff
        );
        assert_eq!(
            cadences.ci_quota_cadence_s, None,
            "backoff must not read CI quota inputs"
        );
        assert!(
            cadences.github_connections.is_empty(),
            "backoff must not read connection membership"
        );
    }

    /// Retention is scheduler work even when no subscription is due.
    ///
    /// The storage tests prove each deletion predicate; this test proves the
    /// production pass invokes both. Removing either prune call leaves its old
    /// row visible and fails this control.
    #[test]
    fn scheduler_pass_runs_retention_when_no_subscription_is_due() {
        let (store, _transport, engine) = scheduler_engine(json!({"items": []}));
        let audit_retention_window_ms = DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY;
        let scheduler = Scheduler::new(engine, audit_retention_window_ms);
        let now = now_ms();
        store
            .append_audit_at_for_test("direct", now - audit_retention_window_ms - 1, "expired")
            .expect("insert expired audit row");
        store
            .insert_reservation_at_for_test(
                "direct",
                "expired-reservation",
                "dispatched",
                now - RESERVATION_RETENTION_MS - 1,
            )
            .expect("insert expired terminal reservation");
        assert_eq!(
            store.list_audit("direct").unwrap().len(),
            1,
            "the fixture needs an expired audit row before the pass"
        );
        assert!(
            store
                .reservation("direct", "expired-reservation")
                .unwrap()
                .is_some(),
            "the fixture needs an expired terminal reservation before the pass"
        );

        let outcomes = scheduler.run_pass(&[], now);
        assert!(outcomes.is_empty(), "no subscription should be polled");
        assert!(
            store.list_audit("direct").unwrap().is_empty(),
            "the scheduler pass did not run audit retention"
        );
        assert!(
            store
                .reservation("direct", "expired-reservation")
                .unwrap()
                .is_none(),
            "the scheduler pass did not run reservation retention"
        );
    }

    #[test]
    fn scheduler_pass_sweeps_receipts_and_sweep_failure_does_not_suppress_polls() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);
        let now = now_ms();
        store
            .claim_github_receipt(
                "agent",
                "nonce",
                "fingerprint",
                "owner",
                &json!({}),
                &[crate::github::receipt::Effect {
                    effect: "comment".into(),
                    dispatch_attempted_at: None,
                    request_id: None,
                    outcome: None,
                }],
                None,
                now - 121_000,
                120,
            )
            .unwrap();
        store
            .mark_github_dispatch("agent", "nonce", "owner", 0, now - 120_999, "test-request")
            .unwrap();
        scheduler.run_pass(&[], now);
        assert_eq!(
            store
                .github_receipt("agent", "nonce")
                .unwrap()
                .unwrap()
                .state,
            "outcome_unknown"
        );
        let id = subscribe(&store, 30);
        store
            .record_poll_attempt("direct", &id, now - 31_000)
            .unwrap();
        store.drop_github_receipts_for_test();
        let outcomes = scheduler.run_pass(&principals(), now);
        assert_eq!(
            outcomes.len(),
            1,
            "receipt sweep failure suppressed due poll"
        );
        assert_eq!(transport.requests().len(), 1);
    }

    fn agent_grant(store: &PlexusStore, grant_id: &str, agent_id: &str) {
        store
            .insert_agent_grant_for_test(
                &GrantInput {
                    grant_id: grant_id.to_string(),
                    principal: "direct".to_string(),
                    connection_id: "connection".to_string(),
                    grantee_principal: "direct".to_string(),
                    risk_ceiling: "write".to_string(),
                    action_selectors: vec!["*".to_string()],
                    authority_kind: crate::governance::AUTHORITY_INVOKE.to_string(),
                    expires_at: None,
                },
                agent_id,
            )
            .expect("agent grant");
    }

    /// The retired-agent sweep rides the pass but runs at most once an hour of
    /// pass time, however many passes fall inside that hour.
    #[test]
    fn retired_agent_sweep_runs_at_most_once_an_hour() {
        let (store, _transport, engine) = scheduler_engine(json!({"items": []}));
        agent_grant(&store, "grant-agent", "agent-1");
        let registry = Arc::new(StubAgentRegistry::with_default_response(AgentLookup::Known));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY)
            .with_agent_registry(Arc::clone(&registry) as Arc<dyn AgentRegistry>);
        let now = now_ms();

        scheduler.run_pass(&[], now);
        scheduler.run_pass(&[], now + AGENT_RETIREMENT_SWEEP_INTERVAL_MS - 1);
        assert_eq!(
            registry.requests(),
            ["agent-1"],
            "two passes inside the hour resolved the agent more than once"
        );

        scheduler.run_pass(&[], now + AGENT_RETIREMENT_SWEEP_INTERVAL_MS);
        assert_eq!(
            registry.requests().len(),
            2,
            "the sweep did not run again once the hour had passed"
        );
    }

    /// A registry that answers `Unavailable` and records, at each lookup, how
    /// many vendor requests the poll pass had already sent.
    struct FailingRegistry {
        transport: Arc<MockTransport>,
        polls_sent_at_lookup: Mutex<Vec<usize>>,
    }

    impl AgentRegistry for FailingRegistry {
        fn lookup(&self, _agent_id: &str) -> AgentLookup {
            self.polls_sent_at_lookup
                .lock()
                .unwrap()
                .push(self.transport.requests().len());
            AgentLookup::Unavailable
        }
    }

    /// A registry failure neither fails the pass nor holds its polls back: the
    /// due subscription completes, and the registry is only consulted after
    /// the poll has already gone out.
    #[test]
    fn retired_agent_sweep_failure_does_not_fail_or_delay_the_poll_pass() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        agent_grant(&store, "grant-agent", "agent-1");
        let registry = Arc::new(FailingRegistry {
            transport: Arc::clone(&transport),
            polls_sent_at_lookup: Mutex::new(Vec::new()),
        });
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY)
            .with_agent_registry(Arc::clone(&registry) as Arc<dyn AgentRegistry>);
        let now = now_ms();
        let id = subscribe(&store, 30);
        store
            .record_poll_attempt("direct", &id, now - 31_000)
            .unwrap();

        let outcomes = scheduler.run_pass(&principals(), now);

        assert_eq!(outcomes.len(), 1, "the due subscription was not polled");
        assert!(
            matches!(outcomes[0].cycle, PollCycle::Completed { .. }),
            "{:?}",
            outcomes[0].cycle
        );
        assert_eq!(
            *registry.polls_sent_at_lookup.lock().unwrap(),
            [1],
            "the sweep must run once, after the poll's vendor request"
        );
        assert_eq!(
            store.grants_held_by_agent("agent-1").unwrap().len(),
            1,
            "a registry failure revoked a grant"
        );
    }

    /// Due selection is a bound in BOTH directions: a subscription whose cadence
    /// has elapsed IS due, and one whose cadence has not elapsed is NOT.
    ///
    /// Two subscriptions share a connection and cadence; only the elapsed one is
    /// returned. A selector that returned everything would include the unelapsed
    /// one; a selector that returned nothing would miss the elapsed one — either
    /// mutation fails here.
    ///
    /// Mutation proved: dropping the cadence comparison from `due_subscriptions`
    /// (selecting every active row) makes the unelapsed subscription appear;
    /// inverting it to select nothing makes the elapsed one disappear.
    #[test]
    fn due_selection_is_a_bound_in_both_directions() {
        let (store, _transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let elapsed = subscribe(&store, 30);
        let unelapsed = subscribe(&store, 30);
        let now = now_ms();
        // Elapsed: last polled 31s ago, past the 30s cadence.
        store
            .record_poll_attempt("direct", &elapsed, now - 31_000)
            .expect("stamp elapsed");
        // Unelapsed: last polled 10s ago, inside the 30s cadence.
        store
            .record_poll_attempt("direct", &unelapsed, now - 10_000)
            .expect("stamp unelapsed");

        let due = scheduler.due_now(&principals(), now);
        let due_ids: Vec<&str> = due.iter().map(|s| s.subscription_id.as_str()).collect();
        assert!(
            due_ids.contains(&elapsed.as_str()),
            "a subscription past its cadence must be due: {due_ids:?}"
        );
        assert!(
            !due_ids.contains(&unelapsed.as_str()),
            "a subscription inside its cadence must NOT be due: {due_ids:?}"
        );

        // The boundary itself: the same subscription is not due one millisecond
        // before its cadence elapses and due exactly when it does.
        let boundary = subscribe(&store, 30);
        store
            .record_poll_attempt("direct", &boundary, now - 30_000)
            .expect("stamp boundary");
        let just_before = scheduler.due_now(&principals(), now - 1);
        assert!(
            !just_before.iter().any(|s| s.subscription_id == boundary),
            "due one millisecond before the cadence elapsed"
        );
        let exactly = scheduler.due_now(&principals(), now);
        assert!(
            exactly.iter().any(|s| s.subscription_id == boundary),
            "not due exactly when the cadence elapsed"
        );
    }

    /// Backoff actually delays: a subscription carrying a vendor-failure streak
    /// is NOT due at a time when an otherwise identical healthy one IS.
    ///
    /// Both subscriptions are past their cadence, so the base query returns
    /// both; only the backoff filter separates them. The assertion is against
    /// the stored failure count, not a sleep.
    ///
    /// Mutation proved: ignoring `consecutive_vendor_failures` in the backoff
    /// (treating every streak as zero) makes the failing subscription due
    /// alongside the healthy one, failing the exclusion assertion.
    #[test]
    fn backoff_delays_a_failing_subscription_past_a_healthy_one() {
        let (store, _transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let healthy = subscribe(&store, 30);
        let failing = subscribe(&store, 30);
        let now = now_ms();
        // Both last polled 31s ago: past the 30s cadence, so the base cadence
        // bound selects both.
        store
            .record_poll_attempt("direct", &healthy, now - 31_000)
            .expect("stamp healthy");
        store
            .record_poll_attempt("direct", &failing, now - 31_000)
            .expect("stamp failing");
        // One consecutive vendor failure on the failing subscription. Backoff is
        // cadence * 2^1 = 60s, and only 31s have passed.
        store
            .record_vendor_failure("direct", &failing)
            .expect("record failure");

        // Assert against the stored failure count, not the return value.
        assert_eq!(
            stored(&store, &failing).consecutive_vendor_failures,
            1,
            "the fixture must carry exactly one stored failure"
        );

        let due = scheduler.due_now(&principals(), now);
        let due_ids: Vec<&str> = due.iter().map(|s| s.subscription_id.as_str()).collect();
        assert!(
            due_ids.contains(&healthy.as_str()),
            "a healthy subscription past its cadence must be due: {due_ids:?}"
        );
        assert!(
            !due_ids.contains(&failing.as_str()),
            "a failing subscription inside its backoff window must NOT be due: {due_ids:?}"
        );

        // Once the backoff window (60s) elapses, the failing subscription IS due
        // again — backoff delays, it does not stop.
        let later = scheduler.due_now(&principals(), now - 31_000 + 60_000);
        assert!(
            later.iter().any(|s| s.subscription_id == failing),
            "a failing subscription must become due once its backoff window elapses"
        );
    }

    /// Backoff is enforced by the pass, not merely decided by the classifier.
    ///
    /// `due_now` proving the classifier says "not due" is necessary but not
    /// sufficient: `run_pass` is the only caller that matters (the module's
    /// spawned task invokes it), and a predicate can be perfectly tested yet
    /// never consulted. This test drives `run_pass` with a subscription inside
    /// its backoff window and asserts the vendor is NOT called, using the same
    /// `transport.requests()` instrument the missed-ticks test uses.
    ///
    /// Mutation proved: making the `InBackoff` arm poll anyway dispatches a
    /// vendor call inside the window, so `transport.requests()` is non-empty and
    /// the first assertion fails. The classifier test above stays green under
    /// that mutation — only this one catches it.
    #[test]
    fn backoff_is_enforced_by_the_pass_not_just_the_classifier() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let failing = subscribe(&store, 30);
        let now = now_ms();
        // Last polled 31s ago: past the 30s cadence (so the base query returns
        // it) but inside the 60s backoff window one failure implies.
        store
            .record_poll_attempt("direct", &failing, now - 31_000)
            .expect("stamp attempt");
        store
            .record_vendor_failure("direct", &failing)
            .expect("record failure");
        assert_eq!(
            stored(&store, &failing).consecutive_vendor_failures,
            1,
            "the fixture must carry exactly one stored failure"
        );

        // Inside the window: the pass produces no outcome and, crucially, never
        // reaches the vendor.
        let outcomes = scheduler.run_pass(&principals(), now);
        assert!(
            outcomes.is_empty(),
            "an in-backoff subscription produces no pass outcome: {outcomes:?}"
        );
        assert!(
            transport.requests().is_empty(),
            "backoff must stop the vendor call in the pass, not just the classifier decision"
        );

        // Control: the same subscription IS pollable once the window elapses, so
        // the empty request list above is because of backoff, not because the
        // subscription is otherwise unpollable.
        let later_outcomes = scheduler.run_pass(&principals(), now - 31_000 + 60_000);
        assert_eq!(
            later_outcomes.len(),
            1,
            "out of backoff the subscription polls: {later_outcomes:?}"
        );
        assert_eq!(
            transport.requests().len(),
            1,
            "out of backoff the vendor is called exactly once"
        );
    }

    /// The circuit breaker suspends a subscription past the failure threshold,
    /// records the machine-readable reason, and the subscription stops being
    /// selected afterwards — without ever reaching the vendor.
    ///
    /// Mutation proved: removing the breaker arm (letting a streak at the
    /// threshold poll again) leaves the status `active` and the reason unset,
    /// failing the state assertions; it would also record a vendor call.
    #[test]
    fn circuit_breaker_suspends_past_the_threshold_and_stops_selecting() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let subscription = subscribe(&store, 30);
        let now = now_ms();
        store
            .record_poll_attempt("direct", &subscription, now - 31_000)
            .expect("stamp attempt");
        for _ in 0..CIRCUIT_BREAKER_FAILURES {
            store
                .record_vendor_failure("direct", &subscription)
                .expect("record failure");
        }
        assert_eq!(
            stored(&store, &subscription).consecutive_vendor_failures,
            CIRCUIT_BREAKER_FAILURES,
            "the fixture must be exactly at the breaker threshold"
        );

        let outcomes = scheduler.run_pass(&principals(), now);
        assert!(
            outcomes
                .iter()
                .any(|outcome| outcome.subscription_id == subscription
                    && matches!(
                        &outcome.cycle,
                        PollCycle::Suspended { reason } if reason == CIRCUIT_BREAKER_SUSPENSION_REASON
                    )),
            "the breaker must suspend with its machine-readable reason: {outcomes:?}"
        );

        // State read back from the store: suspended, with the reason recorded.
        let after = stored(&store, &subscription);
        assert_eq!(after.status, "suspended", "breaker did not suspend");
        assert_eq!(
            after.suspended_reason.as_deref(),
            Some(CIRCUIT_BREAKER_SUSPENSION_REASON),
            "the suspension reason must be recorded"
        );
        // The breaker suspended instead of polling: no vendor call was made.
        assert!(
            transport.requests().is_empty(),
            "the breaker must stop polling, not dispatch one more vendor call"
        );
        // And it is never selected afterwards.
        assert!(
            scheduler.due_now(&principals(), now).is_empty(),
            "a breaker-suspended subscription must never be selected again"
        );
    }

    /// Missed ticks collapse: a subscription overdue by several cadence
    /// intervals is polled ONCE, not once per missed interval. The cursor makes
    /// replay pointless — the single poll fetches everything since the last
    /// cursor — so catching up would only re-fetch the same events.
    ///
    /// Mutation proved: replaying one poll per missed interval (here three)
    /// would record three vendor calls; this asserts exactly one.
    #[test]
    fn missed_ticks_collapse_into_a_single_poll() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let subscription = subscribe(&store, 30);
        let now = now_ms();
        // Overdue by three full cadence intervals (last polled 90s ago).
        store
            .record_poll_attempt("direct", &subscription, now - 90_000)
            .expect("stamp attempt");

        let outcomes = scheduler.run_pass(&principals(), now);
        assert_eq!(
            outcomes.len(),
            1,
            "an overdue subscription is one scheduling decision, not three: {outcomes:?}"
        );
        assert!(
            matches!(outcomes[0].cycle, PollCycle::Completed { .. }),
            "the single poll must complete: {outcomes:?}"
        );
        assert_eq!(
            transport.requests().len(),
            1,
            "three missed intervals must collapse into exactly one vendor call"
        );
    }

    /// A suspended subscription is never selected and never polled.
    ///
    /// Mutation proved: dropping `status = 'active'` from `due_subscriptions`
    /// would return the suspended row, making `due_now` non-empty and recording
    /// a vendor call; both assertions fail.
    #[test]
    fn a_suspended_subscription_is_never_selected() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let subscription = subscribe(&store, 30);
        let now = now_ms();
        // Never polled, so it would be cadence-due if it were active.
        store
            .suspend("direct", &subscription, "operator_unsubscribed")
            .expect("suspend");

        assert!(
            scheduler.due_now(&principals(), now).is_empty(),
            "a suspended subscription must never be due"
        );
        let outcomes = scheduler.run_pass(&principals(), now);
        assert!(
            outcomes.is_empty(),
            "a suspended subscription must produce no pass outcome: {outcomes:?}"
        );
        assert!(
            transport.requests().is_empty(),
            "a suspended subscription must never reach the vendor"
        );
    }

    /// A healthy subscription polls at exactly its declared cadence: a pass
    /// dispatches one vendor call and clears no failures because there are none.
    /// This is the control that the failure policy does not perturb the happy
    /// path.
    #[test]
    fn a_healthy_subscription_polls_at_cadence() {
        let (store, transport, engine) = scheduler_engine(json!({"items": []}));
        let scheduler = Scheduler::new(engine, DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY);

        let subscription = subscribe(&store, 30);
        let now = now_ms();
        store
            .record_poll_attempt("direct", &subscription, now - 31_000)
            .expect("stamp attempt");

        let outcomes = scheduler.run_pass(&principals(), now);
        assert_eq!(
            outcomes.len(),
            1,
            "exactly one due subscription: {outcomes:?}"
        );
        assert!(
            matches!(outcomes[0].cycle, PollCycle::Completed { .. }),
            "a healthy poll completes: {outcomes:?}"
        );
        assert_eq!(transport.requests().len(), 1, "one vendor call");
        assert_eq!(
            stored(&store, &subscription).consecutive_vendor_failures,
            0,
            "a success leaves no failure streak"
        );
    }
}
