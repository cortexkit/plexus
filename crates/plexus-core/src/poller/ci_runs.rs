//! Bounded, multi-action CI polling. The cursor tracks attempts, not pages:
//! rereading a whole attempt is safe because completed objects have semantic keys.

use super::*;
use crate::storage::event_outbox::{QuotaAdmission, QuotaRequest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

const RUN_READ: &str = "get_workflow_run";
const JOBS_READ: &str = "list_jobs_for_workflow_run_attempt";
const RUN_EVENT: &str = crate::event_key::GITHUB_CI_RUN_COMPLETED;
const REQUEST_CAP: usize = 8;
const CI_PAGE_SIZE: u64 = 100;
const AGE_FLOOR_MS: i64 = (7 * 24 - 1) * 60 * 60 * 1000;

static CI_POLLS_DEFERRED: AtomicU64 = AtomicU64::new(0);
static RUNS_VANISHED: AtomicU64 = AtomicU64::new(0);
static RUNS_EXPIRED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    // Count actual admission calls, including refusals that write no row.
    // Polls run on the caller's thread, so parallel tests cannot share the count.
    static CI_QUOTA_ADMISSION_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiCursor {
    #[serde(default)]
    scanned_through_ms: Option<i64>,
    #[serde(default)]
    pinned: BTreeMap<String, String>,
    #[serde(default)]
    open: BTreeMap<String, OpenAttempt>,
    #[serde(default)]
    rescan_from_ms: Option<i64>,
    #[serde(default)]
    rescan_to_ms: Option<i64>,
    #[serde(default)]
    rescan_page: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAttempt {
    created_at: String,
    last_checked_ms: i64,
    run: RunMetadata,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunMetadata {
    run_id: i64,
    run_attempt: i64,
    head_branch: Option<String>,
    pull_requests: Vec<Value>,
    event: String,
    repository_id: i64,
}

struct CiEvent {
    vendor_id: String,
    payload: Value,
    activity_at_ms: i64,
    item_kind: &'static str,
    event_name: &'static str,
    key: String,
    repo_id: i64,
    headers: EventHeaders,
}

// A 404 is local to one open attempt, unlike every other read failure.
enum ReadFailure {
    Vanished,
    Cycle(PollCycle),
}

fn timestamp(body: &Value, field: &str) -> Option<i64> {
    iso8601::parse_to_millis(body.get(field)?.as_str()?)
}

fn metadata(run: &Value) -> Option<RunMetadata> {
    Some(RunMetadata {
        run_id: run.get("id")?.as_i64().filter(|id| *id > 0)?,
        run_attempt: run.get("run_attempt")?.as_i64().filter(|id| *id > 0)?,
        head_branch: match run.get("head_branch")? {
            Value::Null => None,
            Value::String(branch) => Some(branch.clone()),
            _ => return None,
        },
        pull_requests: run.get("pull_requests")?.as_array()?.clone(),
        event: run.get("event")?.as_str()?.to_owned(),
        repository_id: run
            .pointer("/repository/id")?
            .as_i64()
            .filter(|id| *id > 0)?,
    })
}

fn run_key(run: &Value, meta: &RunMetadata) -> Result<Option<String>, ()> {
    run.get("conclusion")
        .ok_or(())?
        .as_str()
        .map(|conclusion| {
            crate::event_key::derive_event_key(
                RUN_EVENT,
                &json!({
                    "repo_id":meta.repository_id, "run_id":meta.run_id,
                    "run_attempt":meta.run_attempt, "conclusion":conclusion,
                }),
            )
            .map_err(|_| ())
        })
        .transpose()
}

fn page(body: Value, field: &str) -> Option<(u64, Vec<Value>)> {
    Some((
        body.get("total_count")?.as_u64()?,
        body.get(field)?.as_array()?.clone(),
    ))
}

fn completed_conclusion(body: &Value) -> Option<&str> {
    (body.get("status")?.as_str()? == "completed")
        .then(|| body.get("conclusion")?.as_str())
        .flatten()
}

impl<C, T> Poller<C, T>
where
    C: CredentialSource + ?Sized + 'static,
    T: Transport + ?Sized + 'static,
{
    /// Process-lifetime CI counters, including direct/manual polls.
    pub fn ci_metrics() -> Value {
        json!({"ci_polls_deferred":CI_POLLS_DEFERRED.load(Ordering::Relaxed),
            "runs_vanished":RUNS_VANISHED.load(Ordering::Relaxed),
            "runs_expired":RUNS_EXPIRED.load(Ordering::Relaxed)})
    }

    fn ci_vendor_failure(
        &self,
        principal: &str,
        sub: &TriggerSubscription,
        code: String,
    ) -> PollCycle {
        self.vendor_failure_cycle(principal, &sub.subscription_id, code)
    }

    // Authorize each page read separately and record each dispatch. Before
    // calling this helper, the cycle reserves its vendor-request allowance.
    // Use `governed_read` and `read_failure_cycle` like other subscription polls.
    // Only CI treats an allowed 404 as a tracked run attempt that disappeared.
    #[allow(clippy::too_many_arguments)]
    fn ci_read(
        &self,
        principal: &str,
        sub: &TriggerSubscription,
        action: &str,
        pin: &str,
        args: Value,
        used: &mut usize,
        allow_404: bool,
    ) -> Result<Value, ReadFailure> {
        if *used >= REQUEST_CAP {
            return Err(ReadFailure::Cycle(PollCycle::Inconclusive {
                code: "ci_request_cap_exhausted".into(),
            }));
        }
        *used += 1;
        match governed_read(
            &self.engine,
            principal,
            &sub.connection_id,
            action,
            args,
            &sub.subscription_id,
            pin,
        ) {
            Ok(Some(body)) => Ok(body),
            // Transports represent an empty successful HTTP body as JSON null,
            // not `None`. Reject a missing body too: neither supplies a CI page.
            Ok(None) => Err(ReadFailure::Cycle(self.ci_vendor_failure(
                principal,
                sub,
                "response_shape_invalid".into(),
            ))),
            Err(GovernedReadFailure::VendorFailed { code, .. })
                if allow_404 && code == "http_404" =>
            {
                Err(ReadFailure::Vanished)
            }
            Err(failure) => Err(ReadFailure::Cycle(self.read_failure_cycle(
                principal,
                &sub.subscription_id,
                failure,
            ))),
        }
    }

    pub(crate) fn waiting_for_ci_quota(&self, subscription_id: &str, now: i64) -> bool {
        self.ci_quota_waits
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(subscription_id)
            .is_some_and(|until| now < *until)
    }

    pub(super) fn poll_ci_runs(&self, principal: &str, sub: &TriggerSubscription) -> PollCycle {
        self.poll_ci_runs_at(principal, sub, now_ms())
    }

    // An explicit start time makes restart/outage/budget tests deterministic,
    // without replacing the real authorization, dispatch or fenced commit path.
    fn poll_ci_runs_at(&self, principal: &str, sub: &TriggerSubscription, now: i64) -> PollCycle {
        if self.waiting_for_ci_quota(&sub.subscription_id, now) {
            return PollCycle::Deferred {
                reason: "github_actions_quota".into(),
            };
        }
        let store = self.engine.store();
        let store_failed = |error: cortexkit_store::StoreError| PollCycle::StoreFailed {
            reason: error.to_string(),
        };
        // Validate the subscription's cursor and fixed arguments, and look up
        // required action schemas before reserving requests. All CI subscriptions
        // share a request limit over the preceding hour, and reservations never
        // receive refunds. A subscription that cannot poll must not consume
        // the allowance other subscriptions need.
        let invalid = || self.ci_vendor_failure(principal, sub, "response_shape_invalid".into());
        let mut cursor: CiCursor = match serde_json::from_value(sub.cursor_state.clone()) {
            Ok(cursor) => cursor,
            Err(_) => {
                return self.suspend(principal, &sub.subscription_id, "cursor_state_unusable")
            }
        };
        let Some(fixed) = sub.fixed_args.as_object() else {
            return self.suspend(principal, &sub.subscription_id, "fixed_args_unusable");
        };
        let Some((owner, repo)) = fixed
            .get("owner")
            .and_then(Value::as_str)
            .zip(fixed.get("repo").and_then(Value::as_str))
        else {
            return self.suspend(principal, &sub.subscription_id, "fixed_args_unusable");
        };
        for action in [RUN_READ, JOBS_READ] {
            if !cursor.pinned.contains_key(action) {
                match store.catalog_action(principal, &sub.connection_id, action) {
                    Ok(Some(action_row)) => {
                        cursor.pinned.insert(action.into(), action_row.schema_hash);
                    }
                    Ok(None) => {
                        return self.suspend(principal, &sub.subscription_id, "action_not_found")
                    }
                    Err(error) => return store_failed(error),
                }
            }
        }
        #[cfg(test)]
        CI_QUOTA_ADMISSION_CALLS.with(|calls| calls.set(calls.get() + 1));
        match store.reserve_github_actions_quota(
            principal,
            &sub.subscription_id,
            QuotaRequest::CiCycle,
            now,
        ) {
            Ok(QuotaAdmission::Reserved { .. }) => {}
            Ok(QuotaAdmission::Inactive) => {
                return PollCycle::NotEligible {
                    reason: "subscription_not_active".into(),
                }
            }
            Ok(QuotaAdmission::Deferred { retry_at_ms }) => {
                let mut waits = self
                    .ci_quota_waits
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                waits.retain(|_, until| *until > now);
                if waits.len() >= 4096 && !waits.contains_key(&sub.subscription_id) {
                    if let Some(oldest) = waits
                        .iter()
                        .min_by_key(|(_, until)| **until)
                        .map(|(id, _)| id.clone())
                    {
                        waits.remove(&oldest);
                    }
                }
                waits.insert(sub.subscription_id.clone(), retry_at_ms);
                CI_POLLS_DEFERRED.fetch_add(1, Ordering::Relaxed);
                return PollCycle::Deferred {
                    reason: "github_actions_quota".into(),
                };
            }
            Err(error) => return store_failed(error),
        }
        match store.record_poll_attempt(principal, &sub.subscription_id, now) {
            Ok(true) => {}
            Ok(false) => {
                return PollCycle::NotEligible {
                    reason: "subscription_not_active".into(),
                }
            }
            Err(error) => return store_failed(error),
        }
        let repo_name = format!("{owner}/{repo}").to_lowercase();
        let base = json!({"owner":owner, "repo":repo});
        let scanned = cursor.scanned_through_ms.unwrap_or(now);
        let from = scanned.saturating_sub(sub.cadence_s.saturating_mul(2_000));
        let floor = now.saturating_sub(AGE_FLOOR_MS);
        let mut gaps = Vec::new();
        if scanned < floor {
            gaps.push(PollGapInput {
                from_ms: scanned,
                to_ms: floor,
                reason: "ci_runs_outage",
            });
        }
        let mut used = 0;
        let mut discovered = Vec::new();
        let mut total = 0;
        for number in 1..=1 {
            let mut args = base.clone();
            args["created"] = json!(format!(">={}", iso8601::format_millis(from)));
            args["page"] = json!(number);
            let body = match self.ci_read(
                principal,
                sub,
                &sub.action,
                &sub.schema_hash,
                args,
                &mut used,
                false,
            ) {
                Ok(body) => body,
                Err(ReadFailure::Cycle(cycle)) => return cycle,
                Err(ReadFailure::Vanished) => unreachable!(),
            };
            let Some((count, runs)) = page(body, "workflow_runs") else {
                return invalid();
            };
            total = total.max(count);
            discovered.extend(runs);
            if total <= discovered.len() as u64 {
                break;
            }
        }
        if total > discovered.len() as u64 {
            let Some(oldest) = discovered
                .iter()
                .map(|run| timestamp(run, "created_at"))
                .collect::<Option<Vec<_>>>()
                .and_then(|times| times.into_iter().min())
            else {
                return invalid();
            };
            gaps.push(PollGapInput {
                from_ms: from,
                to_ms: oldest,
                reason: "ci_runs_page_cap",
            });
        }
        // GitHub filters by original creation time, not rerun activity. Walk a
        // fixed recent window one page per cycle, within the same reservation.
        // Freeze both bounds until the rotation finishes so advancing time does
        // not remove older runs from beneath a saved page number.
        let rescan_from = *cursor.rescan_from_ms.get_or_insert(floor);
        let rescan_to = *cursor.rescan_to_ms.get_or_insert(now);
        let rescan_page = cursor.rescan_page.max(1);
        let mut args = base.clone();
        args["created"] = json!(format!(
            "{}..{}",
            iso8601::format_millis(rescan_from),
            iso8601::format_millis(rescan_to)
        ));
        args["page"] = json!(rescan_page);
        let body = match self.ci_read(
            principal,
            sub,
            &sub.action,
            &sub.schema_hash,
            args,
            &mut used,
            false,
        ) {
            Ok(body) => body,
            Err(ReadFailure::Cycle(cycle)) => return cycle,
            Err(ReadFailure::Vanished) => unreachable!(),
        };
        let Some((rescan_count, runs)) = page(body, "workflow_runs") else {
            return invalid();
        };
        // GitHub's filtered list endpoint exposes at most 1,000 results. Make
        // that coverage limit visible rather than paging beyond its contract.
        if rescan_count > 1_000 && rescan_page == 10 {
            gaps.push(PollGapInput {
                from_ms: rescan_from,
                to_ms: rescan_to,
                reason: "ci_runs_page_cap",
            });
        }
        discovered.extend(runs);
        if rescan_page.saturating_mul(CI_PAGE_SIZE) >= rescan_count.min(1_000) {
            cursor.rescan_page = 1;
            cursor.rescan_from_ms = None;
            cursor.rescan_to_ms = None;
        } else {
            cursor.rescan_page = rescan_page + 1;
        }
        for run in discovered {
            let Some(meta) = metadata(&run) else {
                return invalid();
            };
            let key = format!("{}:{}", meta.run_id, meta.run_attempt);
            if cursor.open.contains_key(&key) {
                continue;
            }
            match run_key(&run, &meta) {
                Ok(Some(key)) => match store.canonical_event_by_key(&key) {
                    Ok(Some(_)) => continue,
                    Ok(None) => {}
                    Err(error) => return store_failed(error),
                },
                Ok(None) => {}
                Err(_) => return invalid(),
            }
            let Some(created) = run
                .get("created_at")
                .and_then(Value::as_str)
                .filter(|s| iso8601::parse_to_millis(s).is_some())
            else {
                return invalid();
            };
            cursor.open.insert(
                key,
                OpenAttempt {
                    created_at: created.into(),
                    last_checked_ms: 0,
                    run: meta,
                },
            );
        }
        let mut order = Vec::with_capacity(cursor.open.len());
        for (key, attempt) in &cursor.open {
            let Some(created) = iso8601::parse_to_millis(&attempt.created_at) else {
                return invalid();
            };
            order.push((key.clone(), attempt.last_checked_ms, created));
        }
        order.sort_by(|(ak, checked_a, created_a), (bk, checked_b, created_b)| {
            (checked_a, created_a, ak).cmp(&(checked_b, created_b, bk))
        });
        let mut events = Vec::new();
        // Count each completed run or job read this cycle in the poll metrics.
        // Either insert its event, reject it because its activity timestamp
        // precedes the oldest allowed time, or count it as an existing duplicate.
        // Use `OlderThanWatermark` for age rejections because this cursor has no
        // other lower timestamp bound. Discovery rows and unfinished objects
        // only track work for later cycles; do not count them as delivery items.
        let mut examined = 0usize;
        let mut dropped: Vec<(String, DropReason)> = Vec::new();
        let (mut vanished, mut expired) = (0, 0);
        for (position, (key, _, created)) in order.into_iter().enumerate() {
            if created < floor {
                cursor.open.remove(&key);
                expired += 1;
                gaps.push(PollGapInput {
                    from_ms: created,
                    to_ms: floor,
                    reason: "ci_runs_attempt_expired",
                });
                continue;
            }
            // A run read without its first jobs page cannot progress an attempt.
            // Untouched attempts keep their rank; partially read skips rotate.
            if REQUEST_CAP - used < 2 {
                continue;
            }
            let attempt = cursor.open[&key].clone();
            let mut args = base.clone();
            args["run_id"] = json!(attempt.run.run_id);
            args["attempt_number"] = json!(attempt.run.run_attempt);
            let run = match self.ci_read(
                principal,
                sub,
                RUN_READ,
                &cursor.pinned[RUN_READ],
                args.clone(),
                &mut used,
                true,
            ) {
                Ok(body) => body,
                Err(ReadFailure::Vanished) => {
                    cursor.open.remove(&key);
                    vanished += 1;
                    continue;
                }
                Err(ReadFailure::Cycle(cycle)) => return cycle,
            };
            // The per-attempt endpoint must not silently serve a newer rerun.
            if metadata(&run).is_none_or(|meta| {
                meta.run_id != attempt.run.run_id
                    || meta.run_attempt != attempt.run.run_attempt
                    || meta.repository_id != attempt.run.repository_id
            }) {
                return invalid();
            }
            args["page"] = json!(1);
            let first = match self.ci_read(
                principal,
                sub,
                JOBS_READ,
                &cursor.pinned[JOBS_READ],
                args.clone(),
                &mut used,
                true,
            ) {
                Ok(body) => body,
                Err(ReadFailure::Vanished) => {
                    cursor.open.remove(&key);
                    vanished += 1;
                    continue;
                }
                Err(ReadFailure::Cycle(cycle)) => return cycle,
            };
            let Some((count, mut jobs)) = page(first, "jobs") else {
                return invalid();
            };
            let pages = count.div_ceil(CI_PAGE_SIZE).max(1);
            let oversized = count > 500;
            if !oversized && pages - 1 > (REQUEST_CAP - used) as u64 {
                cursor
                    .open
                    .get_mut(&key)
                    .expect("open attempt")
                    .last_checked_ms = now;
                continue;
            }
            if !oversized {
                let mut gone = false;
                for number in 2..=pages {
                    args["page"] = json!(number);
                    let body = match self.ci_read(
                        principal,
                        sub,
                        JOBS_READ,
                        &cursor.pinned[JOBS_READ],
                        args.clone(),
                        &mut used,
                        true,
                    ) {
                        Ok(body) => body,
                        Err(ReadFailure::Vanished) => {
                            gone = true;
                            break;
                        }
                        Err(ReadFailure::Cycle(cycle)) => return cycle,
                    };
                    let Some((page_count, next)) = page(body, "jobs") else {
                        return invalid();
                    };
                    if page_count != count {
                        return invalid();
                    }
                    jobs.extend(next);
                }
                if gone {
                    cursor.open.remove(&key);
                    vanished += 1;
                    continue;
                }
                if jobs.len() as u64 != count {
                    return invalid();
                }
                for job in jobs {
                    if completed_conclusion(&job).is_none() {
                        continue;
                    }
                    examined += 1;
                    match ci_event(
                        job,
                        &attempt.run,
                        false,
                        floor,
                        &repo_name,
                        sub.project_id.clone(),
                    ) {
                        Ok(CiItem::Event(event)) => events.push(*event),
                        Ok(CiItem::BelowAgeFloor(id)) => {
                            dropped.push((id, DropReason::OlderThanWatermark))
                        }
                        Err(()) => return invalid(),
                    }
                }
            }
            if completed_conclusion(&run).is_some() {
                if oversized {
                    let Some(updated) = timestamp(&run, "updated_at") else {
                        return invalid();
                    };
                    gaps.push(PollGapInput {
                        from_ms: created,
                        to_ms: updated,
                        reason: "ci_attempt_too_large",
                    });
                }
                examined += 1;
                match ci_event(
                    run,
                    &attempt.run,
                    true,
                    floor,
                    &repo_name,
                    sub.project_id.clone(),
                ) {
                    Ok(CiItem::Event(event)) => events.push(*event),
                    Ok(CiItem::BelowAgeFloor(id)) => {
                        dropped.push((id, DropReason::OlderThanWatermark))
                    }
                    Err(()) => return invalid(),
                }
                cursor.open.remove(&key);
            } else {
                cursor
                    .open
                    .get_mut(&key)
                    .expect("open attempt")
                    .last_checked_ms = now.saturating_add(position as i64 + 1);
            }
        }
        cursor.scanned_through_ms = Some(now);
        let cursor = serde_json::to_value(cursor).expect("serializable CI cursor");
        let inputs = events
            .iter()
            .map(|event| KeyedPollEventInput {
                event: PollEventInput {
                    vendor_event_id: &event.vendor_id,
                    payload: &event.payload,
                    observed_at_ms: now,
                    item_kind: Some(event.item_kind),
                    activity_at_ms: Some(event.activity_at_ms),
                    actor: &ActorAttribution::NotEnriched,
                },
                identity: Some(KeyedEventIdentity {
                    event_key: &event.key,
                    event_name: event.event_name,
                    repo_id: event.repo_id,
                    change: None,
                    headers: &event.headers,
                }),
                delivery_id: None,
                envelope_context: Default::default(),
            })
            .collect::<Vec<_>>();
        match store.commit_keyed_poll_success(
            principal,
            &sub.connection_id,
            &sub.subscription_id,
            &cursor,
            &inputs,
            now,
            &gaps,
        ) {
            Ok(outcomes) => {
                RUNS_VANISHED.fetch_add(vanished, Ordering::Relaxed);
                RUNS_EXPIRED.fetch_add(expired, Ordering::Relaxed);
                accounting::record_ledger(
                    &sub.subscription_id,
                    examined,
                    events.iter().map(|event| event.vendor_id.as_str()),
                    dropped,
                    &outcomes,
                );
                let inserted = outcomes
                    .iter()
                    .filter(|o| matches!(o, TriggerEventInsertOutcome::Inserted { .. }))
                    .count();
                PollCycle::Completed {
                    inserted,
                    duplicates: outcomes.len() - inserted,
                }
            }
            Err(crate::storage::PollCommitError::Inactive) => PollCycle::NotEligible {
                reason: "subscription_not_active".into(),
            },
            Err(error) => PollCycle::StoreFailed {
                reason: error.to_string(),
            },
        }
    }
}

/// Classify one completed run or job as an event or an item too old to deliver.
enum CiItem {
    Event(Box<CiEvent>),
    /// Reject an item whose activity timestamp precedes the oldest allowed
    /// time, and retain the vendor identity its event would have used.
    BelowAgeFloor(String),
}

fn ci_event(
    mut body: Value,
    meta: &RunMetadata,
    is_run: bool,
    floor: i64,
    repo: &str,
    project: Option<String>,
) -> Result<CiItem, ()> {
    let conclusion = completed_conclusion(&body).ok_or(())?.to_owned();
    let activity_at_ms =
        timestamp(&body, if is_run { "updated_at" } else { "completed_at" }).ok_or(())?;
    let kind = if is_run { "run" } else { "job" };
    if activity_at_ms < floor {
        diag!(warn poller:
            "ci_age_floor_refused run_id={} run_attempt={} item_kind={} item_id={}",
            meta.run_id,
            meta.run_attempt,
            if is_run { "ci_run" } else { "ci_job" },
            body["id"]
        );
        return Ok(CiItem::BelowAgeFloor(format!(
            "{kind}:{}:{}",
            body["id"], meta.run_attempt
        )));
    }
    let id = body
        .get("id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or(())?;
    let event_name = if is_run {
        RUN_EVENT
    } else if matches!(conclusion.as_str(), "failure" | "timed_out") {
        crate::event_key::GITHUB_CI_JOB_FAILED
    } else {
        crate::event_key::GITHUB_CI_JOB_COMPLETED
    };
    let key = crate::event_key::derive_event_key(
        event_name,
        &json!({"repo_id":meta.repository_id,
        "run_id":meta.run_id, "job_id":id, "run_attempt":meta.run_attempt, "conclusion":conclusion}),
    )
    .map_err(|_| ())?;
    if !is_run {
        body["run"] = serde_json::to_value(meta).map_err(|_| ())?;
    }
    Ok(CiItem::Event(Box::new(CiEvent {
        vendor_id: format!("{kind}:{id}:{}", meta.run_attempt),
        payload: body,
        activity_at_ms,
        item_kind: if is_run { "ci_run" } else { "ci_job" },
        event_name,
        key,
        repo_id: meta.repository_id,
        headers: EventHeaders {
            repo: repo.into(),
            project,
            branch: meta.head_branch.clone(),
            conclusion: Some(conclusion),
            pr: (meta.pull_requests.len() == 1)
                .then(|| {
                    meta.pull_requests[0]
                        .get("number")
                        .and_then(Value::as_i64)
                        .map(|number| number.to_string())
                })
                .flatten(),
        },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        CredentialError, ResolvedCredential, StubCredentialSource, TransientCredentialError,
    };
    use crate::storage::{CatalogActionInput, Ceiling, GrantInput, PlexusStore};
    use crate::test_scratch::Scratch;
    use crate::transport::{TransportRequest, TransportResponse};
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    const PRINCIPAL: &str = "ci-owner";
    const CONNECTION: &str = "conn-github-actions";
    const HANDLE: &[u8] = b"test:ci-handle";

    #[test]
    fn ci_polling_and_flow_read_bursts_share_the_hourly_ledger() {
        let f = Fixture::new();
        for count in [101, 101, 101, 101, 101]
            .into_iter()
            .chain(std::iter::repeat_n(2, 43))
        {
            assert!(matches!(
                f.engine
                    .store()
                    .reserve_github_actions_flow_read_quota(count, f.now)
                    .unwrap(),
                QuotaAdmission::Reserved { .. }
            ));
        }
        let poller = TestPoller::new(f.engine.clone());
        assert!(matches!(
            poller.poll_ci_runs_at(PRINCIPAL, &f.watch(), f.now),
            PollCycle::Completed { .. }
        ));
        let used: i64 = f
            .conn()
            .query_row("SELECT SUM(requests) FROM github_actions_quota", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            used, 599,
            "591 flow requests plus the unchanged eight-request cycle"
        );
        assert!(matches!(
            f.engine
                .store()
                .reserve_github_actions_flow_read_quota(2, f.now)
                .unwrap(),
            QuotaAdmission::Deferred { .. }
        ));
        let before = f.requests().len();
        assert!(matches!(
            poller.poll_ci_runs_at(PRINCIPAL, &f.watch(), f.now + 300_000),
            PollCycle::Deferred { .. }
        ));
        assert_eq!(
            f.requests().len(),
            before,
            "polling defers without sending when flow reads filled its window"
        );
        assert_eq!(
            f.conn()
                .query_row("SELECT SUM(requests) FROM github_actions_quota", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
            599
        );
    }

    #[test]
    fn deferred_ci_waits_without_admission_until_the_exact_deadline() {
        let f = Fixture::new();
        for id in 0..75 {
            f.sql(&format!(
                "INSERT INTO github_actions_quota VALUES ('full-{id}', {}, 8)",
                f.now
            ));
        }
        let watch = f.watch();
        let poller = TestPoller::new(f.engine.clone());
        let retry_at = f.now + 3_600_001;
        CI_QUOTA_ADMISSION_CALLS.with(|calls| calls.set(0));
        assert!(matches!(
            poller.poll_ci_runs_at(PRINCIPAL, &watch, f.now),
            PollCycle::Deferred { .. }
        ));
        assert_eq!(
            poller
                .ci_quota_waits
                .lock()
                .unwrap()
                .get(&watch.subscription_id),
            Some(&retry_at)
        );
        assert_eq!(CI_QUOTA_ADMISSION_CALLS.with(Cell::get), 1);
        let quota_rows = || {
            f.conn()
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(requests), 0) FROM github_actions_quota",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap()
        };
        assert_eq!(quota_rows(), (75, 600));
        for before_deadline in [f.now + 1, f.now + 1000, f.now + 1_000_000, retry_at - 1] {
            assert!(matches!(
                poller.poll_ci_runs_at(PRINCIPAL, &watch, before_deadline),
                PollCycle::Deferred { .. }
            ));
            assert_eq!(
                CI_QUOTA_ADMISSION_CALLS.with(Cell::get),
                1,
                "cached CI quota wait must skip admission before its deadline"
            );
            assert_eq!(
                quota_rows(),
                (75, 600),
                "deferred ticks must not reserve or prune quota rows"
            );
            assert!(f.requests().is_empty());
            assert_eq!(f.watch().last_polled_at_ms, None);
        }
        assert!(matches!(
            poller.poll_ci_runs_at(PRINCIPAL, &watch, retry_at),
            PollCycle::Completed { .. }
        ));
        assert_eq!(CI_QUOTA_ADMISSION_CALLS.with(Cell::get), 2);
        assert_eq!(
            quota_rows(),
            (1, 8),
            "the first admissible tick must reserve a complete cycle"
        );
        assert_eq!(f.requests().len(), 2);
    }

    #[test]
    fn scheduler_skips_ci_quota_waits_until_the_deadline() {
        let f = Fixture::new();
        for id in 0..75 {
            f.sql(&format!(
                "INSERT INTO github_actions_quota VALUES ('full-{id}', {}, 8)",
                f.now
            ));
        }
        let scheduler = crate::scheduler::Scheduler::new(f.engine.clone(), 86_400_000);
        let principals = vec![PRINCIPAL.to_owned()];
        let retry_at = f.now + 3_600_001;
        CI_QUOTA_ADMISSION_CALLS.with(|calls| calls.set(0));
        let first = scheduler.run_pass_report(&principals, f.now);
        assert_eq!(first.outcomes.len(), 1);
        assert!(matches!(
            first.outcomes[0].cycle,
            PollCycle::Deferred { .. }
        ));
        assert_eq!(CI_QUOTA_ADMISSION_CALLS.with(Cell::get), 1);
        for before_deadline in [f.now + 1, f.now + 1000, f.now + 1_000_000, retry_at - 1] {
            assert_eq!(
                f.store
                    .due_subscriptions(PRINCIPAL, before_deadline)
                    .unwrap()
                    .len(),
                1,
                "the active CI watch remains cadence-due while waiting for quota"
            );
            assert!(
                scheduler
                    .run_pass_report(&principals, before_deadline)
                    .outcomes
                    .is_empty(),
                "quota-waiting CI watch must not be polled"
            );
            assert!(
                scheduler.due_now(&principals, before_deadline).is_empty(),
                "quota-waiting CI watch must be excluded from due selection"
            );
            assert_eq!(CI_QUOTA_ADMISSION_CALLS.with(Cell::get), 1);
            assert!(f.requests().is_empty());
        }
        // At the deadline the scheduler selects the watch again. Selection is
        // judged at the pass time this test passes in (`retry_at`). The test
        // stops at selection: running the pass would call `poll_once`, which
        // checks the quota wait against the real wall clock, and this
        // deterministic test does not move the real clock to the deadline.
        assert_eq!(scheduler.due_now(&principals, retry_at).len(), 1);
        assert_eq!(CI_QUOTA_ADMISSION_CALLS.with(Cell::get), 1);
    }

    #[test]
    fn ci_page_size_matches_the_catalog_transport_constants() {
        let source = include_str!("../../../../catalog/github_actions.jsonc")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let manifest: Value = serde_json::from_str(&source).unwrap();
        for name in ["list_workflow_runs", JOBS_READ] {
            let action = manifest["actions_baseline"]
                .as_array()
                .unwrap()
                .iter()
                .find(|action| action["name"] == name)
                .unwrap();
            assert_eq!(
                action["http"]["request_constants"]["per_page"], CI_PAGE_SIZE,
                "CI page arithmetic must match the vendor transport"
            );
        }
    }

    #[test]
    #[ignore = "audit quota admission measurement, not a timing gate"]
    fn audit_full_quota_failed_admissions_per_hour() {
        let f = Fixture::new();
        for id in 0..75 {
            f.sql(&format!(
                "INSERT INTO github_actions_quota VALUES ('full-{id}', {}, 8)",
                f.now
            ));
        }
        let watch = f.watch();
        let before = CI_POLLS_DEFERRED.load(Ordering::Relaxed);
        let started = std::time::Instant::now();
        for second in 0..3600 {
            assert!(matches!(
                TestPoller::new(f.engine.clone()).poll_ci_runs_at(
                    PRINCIPAL,
                    &watch,
                    f.now + second * 1000
                ),
                PollCycle::Deferred { .. }
            ));
        }
        println!(
            "full-quota hour without retained deadline: {} failed admissions, {}ms",
            CI_POLLS_DEFERRED.load(Ordering::Relaxed) - before,
            started.elapsed().as_millis()
        );
        let poller = TestPoller::new(f.engine.clone());
        let before = CI_POLLS_DEFERRED.load(Ordering::Relaxed);
        let started = std::time::Instant::now();
        for second in 0..3600 {
            assert!(matches!(
                poller.poll_ci_runs_at(PRINCIPAL, &watch, f.now + second * 1000),
                PollCycle::Deferred { .. }
            ));
        }
        let failed = CI_POLLS_DEFERRED.load(Ordering::Relaxed) - before;
        println!(
            "full-quota hour with retained deadline: {failed} failed admissions, {}ms",
            started.elapsed().as_millis()
        );
        assert_eq!(failed, 1);
        assert!(matches!(
            poller.poll_ci_runs_at(PRINCIPAL, &watch, f.now + 3_600_001),
            PollCycle::Completed { .. }
        ));
    }

    #[test]
    #[ignore = "audit performance measurement, not a timing gate"]
    fn audit_polling_cost_measurement() {
        let f = Fixture::new();
        let waiting = run(1, 1, f.now, "waiting", None);
        f.open(std::slice::from_ref(&waiting));
        f.add(waiting, jobs(500, f.now), false);
        let started = std::time::Instant::now();
        f.poll_checked(0);
        println!(
            "waiting 500-job attempt: {} requests, {}ms, {} delivered jobs",
            f.requests().len(),
            started.elapsed().as_millis(),
            f.events().len()
        );
        let started = std::time::Instant::now();
        for id in 1..=200 {
            f.store
                .canonical_event_by_key(&format!("missing-{id}"))
                .unwrap();
        }
        println!(
            "200 canonical lookup round trips: {}us",
            started.elapsed().as_micros()
        );
        let started = std::time::Instant::now();
        let _ = page(json!({"total_count":500,"jobs":jobs(500, f.now)}), "jobs").unwrap();
        println!(
            "owned 500-job page extraction including body construction: {}us",
            started.elapsed().as_micros()
        );
        let mut attempts = (0..1000)
            .map(|id| {
                (
                    id,
                    OpenAttempt {
                        created_at: iso8601::format_millis(f.now - id * 1000),
                        last_checked_ms: id % 7,
                        run: metadata(&run(id + 1, 1, f.now, "waiting", None)).unwrap(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let parses = std::cell::Cell::new(0);
        let started = std::time::Instant::now();
        attempts.sort_by(|(ak, a), (bk, b)| {
            parses.set(parses.get() + 2);
            (
                a.last_checked_ms,
                iso8601::parse_to_millis(&a.created_at),
                ak,
            )
                .cmp(&(
                    b.last_checked_ms,
                    iso8601::parse_to_millis(&b.created_at),
                    bk,
                ))
        });
        println!(
            "1000 open-attempt comparator sort: {}us, {} timestamp parses",
            started.elapsed().as_micros(),
            parses.get()
        );
    }

    #[test]
    fn older_rerun_is_found_within_a_rotation_and_large_attempt_fits() {
        let f = Fixture::new();
        for id in 1..=200 {
            f.add(
                run(id, 1, f.now - 86_400_000, "waiting", None),
                vec![],
                true,
            );
        }
        f.add(
            run(201, 2, f.now - 86_400_001, "completed", Some("success")),
            jobs(500, f.now),
            true,
        );
        // Each poll reads one page of recently created runs (the cadence
        // lookback), one page of a rescan that rotates through the last week
        // of runs a page per poll, and then checks open attempts, up to eight
        // requests in all. The rerun (run 201) is older than the lookback, so
        // only the rescan finds it, on its third page. Once found, its older
        // creation time ranks it ahead of the waiting runs not yet checked.
        // Finishing it takes six reads, one for the run and five 100-job
        // pages, which is exactly what the two discovery reads leave.
        for tick in 0..3 {
            let mut cursor = f.cursor();
            cursor["scanned_through_ms"] = json!(f.now + tick * 300_000);
            f.set_cursor(cursor);
            f.poll_checked(tick);
        }
        assert!(
            f.events()
                .iter()
                .any(|(_, payload, _)| payload["id"] == 201),
            "older rerun discovered within one rotation"
        );
        assert_eq!(
            f.events()
                .iter()
                .filter(|(kind, _, _)| kind == "ci_job")
                .count(),
            500,
            "large attempt finishes while rotation is active"
        );
    }

    #[test]
    fn expired_attempt_persists_a_coverage_gap() {
        let f = Fixture::new();
        let created = f.now - AGE_FLOOR_MS - 1;
        f.open(&[run(1, 1, created, "waiting", None)]);
        f.poll_checked(0);
        assert!(
            f.gaps()
                .iter()
                .any(|gap| gap["reason"] == "ci_runs_attempt_expired"
                    && gap["from_ms"] == created
                    && gap["to_ms"] == f.now - AGE_FLOOR_MS),
            "expired attempt coverage gap must be durable"
        );
    }

    #[test]
    fn extreme_cadence_does_not_overflow_discovery() {
        let f = Fixture::new();
        let mut sub = f.watch();
        sub.cadence_s = i64::MAX;
        assert!(matches!(
            TestPoller::new(f.engine.clone()).poll_ci_runs_at(PRINCIPAL, &sub, f.now),
            PollCycle::Completed { .. }
        ));
    }

    #[test]
    fn actor_reads_do_not_retry_throttling_but_retry_server_errors() {
        for (code, expected) in [("http_429", 1), ("http_503", 2)] {
            let f = Fixture::new();
            f.store
                .reserve_github_actions_quota(
                    PRINCIPAL,
                    &f.watch.subscription_id,
                    QuotaRequest::CiCycle,
                    f.now,
                )
                .unwrap();
            f.fail(RUN_READ, 1, 1, 1, code);
            let poller = TestPoller::new(f.engine.clone());
            let budget = CallBudget::new(32);
            let source = ActorSource {
                connection_id: CONNECTION.into(),
                action: RUN_READ.into(),
                methods: vec![],
            };
            let first = budget.try_take(1).unwrap().take_one().unwrap();
            assert!(poller
                .dispatch_actor_read_with_retry(
                    PRINCIPAL,
                    &f.watch(),
                    &source,
                    "pin-get_workflow_run",
                    json!({"owner":"OWNER","repo":"Repo","run_id":1,"attempt_number":1}),
                    ActorRetryAttempt {
                        first,
                        budget: &budget
                    }
                )
                .is_err());
            assert_eq!(
                f.requests().len(),
                expected,
                "actor retry dispatch count for {code}"
            );
        }
    }

    #[test]
    fn exhausted_actor_budget_skips_remaining_history_queries() {
        let f = Fixture::new();
        let mut sub = f.watch();
        sub.actor_source = Some(ActorSource {
            connection_id: CONNECTION.into(),
            action: RUN_READ.into(),
            methods: vec!["get_comments".into()],
        });
        let events = (0..150)
            .map(|id| DerivedEvent {
                vendor_event_id: format!("issue-{id}"),
                payload: json!({"id":id,"number":id+1}),
                replay_candidate: false,
                activity_at_ms: None,
            })
            .collect::<Vec<_>>();
        PREVIOUS_OBSERVATION_READS.with(|reads| reads.set(0));
        let started = std::time::Instant::now();
        let (actors, _) = TestPoller::new(f.engine.clone()).enrich_actor_logins(
            PRINCIPAL,
            &sub,
            &events,
            Some("issue"),
        );
        let reads = PREVIOUS_OBSERVATION_READS.with(Cell::get);
        println!(
            "150-row enrichment: {reads} history queries, {}us",
            started.elapsed().as_micros()
        );
        assert_eq!(
            reads, 32,
            "exhausted actor budget must not query remaining history"
        );
        assert!(matches!(
            actors.last().unwrap(),
            ActorAttribution::Unknown {
                code: ActorUnknownCode::CallCapExhausted,
                ..
            }
        ));
    }

    #[test]
    fn failure_after_deactivation_is_not_a_vendor_failure() {
        let f = Fixture::new();
        f.store
            .suspend(PRINCIPAL, &f.watch.subscription_id, "test suspension")
            .unwrap();
        assert!(
            matches!(
                TestPoller::new(f.engine.clone()).vendor_failure_cycle(
                    PRINCIPAL,
                    &f.watch.subscription_id,
                    "http_500".into()
                ),
                PollCycle::NotEligible { .. }
            ),
            "inactive failure must not report a recorded vendor failure"
        );
    }

    #[test]
    fn inactive_selected_ci_watch_is_not_a_store_or_vendor_failure() {
        let f = Fixture::new();
        let selected = f.watch();
        f.store
            .suspend(PRINCIPAL, &selected.subscription_id, "test suspension")
            .unwrap();
        assert!(
            matches!(
                TestPoller::new(f.engine.clone()).poll_ci_runs_at(PRINCIPAL, &selected, f.now),
                PollCycle::NotEligible { .. }
            ),
            "inactive quota admission must be NotEligible"
        );
        assert_eq!(f.watch().consecutive_vendor_failures, 0);
        assert!(f.requests().is_empty());
    }

    #[test]
    fn request_cap_is_a_cycle_outcome_not_a_panic() {
        let f = Fixture::new();
        let poller = TestPoller::new(f.engine.clone());
        let mut used = 8;
        assert!(
            matches!(poller.ci_read(PRINCIPAL, &f.watch(), RUN_READ, "pin-get_workflow_run", json!({}), &mut used, false), Err(ReadFailure::Cycle(PollCycle::Inconclusive { code })) if code == "ci_request_cap_exhausted")
        );
        assert!(f.requests().is_empty());
    }

    #[test]
    fn pr_headers_require_integer_identity_and_preserve_unsigned_numbers() {
        for number in [Value::Null, json!("42"), json!(u64::MAX)] {
            let f = Fixture::new();
            let response = json!({"items":[{"id":"pr-1","number":number,"updated_at":"2026-10-13T00:00:00Z"}],"next_cursor":"next"});
            let repository = PollRepository {
                name: "owner/repo".into(),
                event_name: crate::event_key::GITHUB_PR_CHANGED,
                repo_id: Some(101),
            };
            let result = TestPoller::new(f.engine.clone()).complete(
                PRINCIPAL,
                &f.watch(),
                &SyncTokenStrategy::new(None),
                Some(&response),
                f.now,
                Some("pull_request"),
                None,
                Some(&repository),
            );
            if number == json!(u64::MAX) {
                assert!(matches!(result, PollCycle::Completed { inserted: 1, .. }));
                assert_eq!(
                    f.markers()[0].headers.pr.as_deref(),
                    Some("18446744073709551615"),
                    "validated unsigned PR number must remain exact"
                );
            } else {
                assert!(
                    matches!(result, PollCycle::Suspended { reason } if reason == "event_identity_invalid")
                );
                assert!(
                    f.markers().is_empty(),
                    "null and quoted-string PR headers cannot be committed"
                );
            }
        }
    }

    #[test]
    fn ci_deactivation_between_selection_and_commit_is_not_eligible() {
        let f = Fixture::new();
        let before = f.watch();
        f.script.lock().unwrap().deactivate_at_request = Some((2, f.watch.subscription_id.clone()));
        assert_eq!(
            f.poll(0),
            PollCycle::NotEligible {
                reason: "subscription_not_active".into()
            }
        );
        assert_eq!(
            f.script.lock().unwrap().requests.len(),
            2,
            "both discovery reads reached the commit boundary"
        );
        let after = f.watch();
        assert_eq!(after.cursor_state, before.cursor_state);
        assert_eq!(after.last_success_at_ms, before.last_success_at_ms);
        assert_eq!(
            after.consecutive_vendor_failures,
            before.consecutive_vendor_failures
        );
        assert!(f.markers().is_empty());
    }

    #[derive(Default)]
    struct Script {
        discovery: Vec<Value>,
        attempts: BTreeMap<(i64, i64), Value>,
        jobs: BTreeMap<(i64, i64), Vec<Value>>,
        failures: BTreeMap<(String, i64, i64, i64), String>,
        requests: Vec<TransportRequest>,
        deny_after_first_jobs: bool,
        deactivate_at_request: Option<(usize, String)>,
    }
    struct CheckedTransport {
        path: std::path::PathBuf,
        script: Arc<Mutex<Script>>,
        credentials: Arc<StubCredentialSource>,
    }
    impl Transport for CheckedTransport {
        fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
            let conn = rusqlite::Connection::open(&self.path).unwrap();
            let units: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(requests),0) FROM github_actions_quota",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let mut script = self.script.lock().unwrap();
            assert!(
                units >= (script.requests.len() + 1) as i64 && units <= 600,
                "CI HTTP must have a committed quota reservation"
            );
            let page = request
                .args
                .get("page")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            let id = request
                .args
                .get("run_id")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let attempt = request
                .args
                .get("attempt_number")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let action = request.action.clone();
            script.requests.push(request.clone());
            if let Some((count, id)) = &script.deactivate_at_request {
                if script.requests.len() == *count {
                    assert_eq!(conn.execute("UPDATE trigger_subscriptions SET status='suspended' WHERE subscription_id=?1", [id]).unwrap(), 1);
                }
            }
            if let Some(code) = script.failures.get(&(action.clone(), id, attempt, page)) {
                // `local_not_sent` simulates a local refusal before sending.
                // `local_outcome_unknown` simulates an unknown request outcome.
                // Neither represents a definitive vendor failure.
                return match code.as_str() {
                    "local_not_sent" => {
                        TransportResponse::transient_not_sent("injected local refusal")
                    }
                    "local_outcome_unknown" => TransportResponse::unknown(),
                    code => TransportResponse::vendor_error(code, "injected read failure"),
                };
            }
            let body = match action.as_str() {
                "list_workflow_runs" => {
                    let created = request.args["created"].as_str().unwrap();
                    let matches = script
                        .discovery
                        .iter()
                        .filter(|run| {
                            let at = timestamp(run, "created_at").unwrap();
                            if let Some(from) = created.strip_prefix(">=") {
                                at >= iso8601::parse_to_millis(from).unwrap()
                            } else {
                                let (from, to) = created.split_once("..").unwrap();
                                at >= iso8601::parse_to_millis(from).unwrap()
                                    && at <= iso8601::parse_to_millis(to).unwrap()
                            }
                        })
                        .collect::<Vec<_>>();
                    json!({"total_count":matches.len(), "workflow_runs":matches.into_iter().skip(((page-1)*100) as usize).take(100).cloned().collect::<Vec<_>>() })
                }
                RUN_READ => script.attempts.get(&(id, attempt)).cloned().unwrap(),
                JOBS_READ => {
                    if script.deny_after_first_jobs {
                        self.credentials.set_error(
                            HANDLE,
                            CredentialError::Transient(TransientCredentialError::VaultLocked),
                        );
                    }
                    let jobs = script.jobs.get(&(id, attempt)).unwrap();
                    json!({"total_count":jobs.len(), "jobs":jobs.iter().skip(((page-1)*100) as usize).take(100).cloned().collect::<Vec<_>>()})
                }
                _ => panic!("unexpected CI action {action}"),
            };
            TransportResponse::success(body)
        }
    }
    type TestPoller = Poller<StubCredentialSource, CheckedTransport>;
    struct Fixture {
        path: Scratch,
        store: Arc<PlexusStore>,
        credentials: Arc<StubCredentialSource>,
        script: Arc<Mutex<Script>>,
        engine: GovernanceEngine<StubCredentialSource, CheckedTransport>,
        watch: TriggerSubscription,
        now: i64,
    }
    impl Fixture {
        fn new() -> Self {
            let path = Scratch::database("ci-runs");
            let store = Arc::new(
                PlexusStore::open(&StorageDescriptor {
                    module_id: "plexus".into(),
                    storage_namespace: path.to_string_lossy().into_owned(),
                    isolation: Isolation::Module,
                    backend: StorageBackend::Sqlite {
                        path: path.to_string_lossy().into_owned(),
                    },
                })
                .unwrap(),
            );
            let source = include_str!("../../../../catalog/github_actions.jsonc")
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let manifest =
                crate::manifest::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
            store
                .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
                .unwrap();
            store
                .insert_connection(
                    PRINCIPAL,
                    CONNECTION,
                    "github_actions",
                    "pending",
                    &json!({}),
                )
                .unwrap();
            for action in ["list_workflow_runs", RUN_READ, JOBS_READ, "get_repository"] {
                let schema = manifest
                    .manifest
                    .actions_baseline
                    .iter()
                    .find(|row| row.name == action)
                    .unwrap()
                    .http
                    .as_ref()
                    .unwrap()
                    .args_schema
                    .clone();
                store
                    .upsert_catalog_action(&CatalogActionInput {
                        connection_id: CONNECTION.into(),
                        principal: PRINCIPAL.into(),
                        name: action.into(),
                        title: None,
                        schema,
                        schema_hash: format!("pin-{action}"),
                        risk: "read".into(),
                        severity: "S2".into(),
                        ask_first: false,
                        status: "active".into(),
                        quarantine_reason: None,
                        reconciliation: None,
                    })
                    .unwrap();
            }
            let ticket = store
                .create_binding_ticket_bounded(
                    PRINCIPAL,
                    CONNECTION,
                    "credential_reference",
                    HANDLE,
                    &Ceiling::unrestricted_for_tests(),
                )
                .unwrap();
            store
                .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
                .unwrap()
                .unwrap();
            store
                .insert_grant(&GrantInput {
                    grant_id: "ci-poll".into(),
                    principal: PRINCIPAL.into(),
                    connection_id: CONNECTION.into(),
                    grantee_principal: PRINCIPAL.into(),
                    risk_ceiling: "read".into(),
                    action_selectors: vec![
                        "list_workflow_runs".into(),
                        RUN_READ.into(),
                        JOBS_READ.into(),
                    ],
                    authority_kind: crate::governance::AUTHORITY_POLL.into(),
                    expires_at: Some(now_ms() + 86_400_000),
                })
                .unwrap();
            let watch = store
                .subscribe_with_cursor_state(
                    PRINCIPAL,
                    CONNECTION,
                    "list_workflow_runs",
                    300,
                    &json!({}),
                    &json!({"owner":"OWNER","repo":"Repo"}),
                )
                .unwrap()
                .unwrap();
            let credentials = Arc::new(StubCredentialSource::default());
            credentials.set_success(HANDLE, b"ci-token".to_vec(), None, 1);
            let script = Arc::new(Mutex::new(Script::default()));
            let engine = GovernanceEngine::new(
                store.clone(),
                credentials.clone(),
                Arc::new(CheckedTransport {
                    path: path.to_path_buf(),
                    script: script.clone(),
                    credentials: credentials.clone(),
                }),
            );
            Self {
                path,
                store,
                credentials,
                script,
                engine,
                watch,
                now: now_ms(),
            }
        }
        fn conn(&self) -> rusqlite::Connection {
            rusqlite::Connection::open(&*self.path).unwrap()
        }
        fn sql(&self, sql: &str) {
            self.conn().execute_batch(sql).unwrap();
        }
        fn watch(&self) -> TriggerSubscription {
            self.store
                .subscription(PRINCIPAL, &self.watch.subscription_id)
                .unwrap()
                .unwrap()
        }
        fn cursor(&self) -> Value {
            self.watch().cursor_state
        }
        fn set_cursor(&self, cursor: Value) {
            self.conn()
                .execute(
                    "UPDATE trigger_subscriptions SET cursor_state = ?1 WHERE subscription_id = ?2",
                    (cursor.to_string(), &self.watch.subscription_id),
                )
                .unwrap();
        }
        fn poll(&self, tick: i64) -> PollCycle {
            // Re-create the executor and reload the persisted cursor each tick.
            TestPoller::new(self.engine.clone()).poll_ci_runs_at(
                PRINCIPAL,
                &self.watch(),
                self.now + tick * 300_000,
            )
        }
        fn poll_checked(&self, tick: i64) -> usize {
            let before = self.requests().len();
            let result = self.poll(tick);
            let count = self.requests().len() - before;
            assert!(count <= 8, "no CI poll exceeds 8 HTTP requests");
            match result {
                PollCycle::Completed { inserted, .. } => inserted,
                _ => panic!("{result:?}"),
            }
        }
        fn requests(&self) -> Vec<TransportRequest> {
            self.script.lock().unwrap().requests.clone()
        }
        fn add(&self, run: Value, jobs: Vec<Value>, discover: bool) {
            let key = (
                run["id"].as_i64().unwrap(),
                run["run_attempt"].as_i64().unwrap(),
            );
            let mut script = self.script.lock().unwrap();
            if discover {
                script.discovery.push(run.clone());
            } else if let Some(existing) = script.discovery.iter_mut().find(|existing| {
                existing["id"] == run["id"] && existing["run_attempt"] == run["run_attempt"]
            }) {
                *existing = run.clone();
            }
            script.attempts.insert(key, run);
            script.jobs.insert(key, jobs);
        }
        fn open(&self, runs: &[Value]) {
            let mut open = serde_json::Map::new();
            for (position, run) in runs.iter().enumerate() {
                let meta = metadata(run).unwrap();
                open.insert(format!("{}:{}",meta.run_id,meta.run_attempt), json!({"created_at":run["created_at"], "last_checked_ms":position+1, "run":meta}));
            }
            self.set_cursor(json!({"scanned_through_ms":self.now,"pinned":{},"open":open}));
        }
        fn events(&self) -> Vec<(String, Value, i64)> {
            let conn = self.conn();
            let mut statement = conn.prepare("SELECT item_kind, payload, activity_at_ms FROM trigger_events WHERE kind = 'event' ORDER BY rowid").unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        serde_json::from_str(&row.get::<_, String>(1)?).unwrap(),
                        row.get(2)?,
                    ))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        }
        fn gaps(&self) -> Vec<Value> {
            let conn = self.conn();
            let mut statement = conn
                .prepare("SELECT gap_reason, gap_from_ms, gap_to_ms FROM trigger_events WHERE kind = 'gap' ORDER BY rowid")
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok(json!({"reason":row.get::<_,String>(0)?, "from_ms":row.get::<_,i64>(1)?, "to_ms":row.get::<_,i64>(2)?}))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        }
        fn markers(&self) -> Vec<crate::storage::event_outbox::CanonicalEvent> {
            self.store.drain_event_outbox(1000).unwrap()
        }
        fn fail(&self, action: &str, id: i64, attempt: i64, page: i64, code: &str) {
            self.script
                .lock()
                .unwrap()
                .failures
                .insert((action.into(), id, attempt, page), code.into());
        }
    }
    fn run(id: i64, attempt: i64, created: i64, status: &str, conclusion: Option<&str>) -> Value {
        json!({"id":id,"run_attempt":attempt,"created_at":iso8601::format_millis(created),"updated_at":iso8601::format_millis(created+60_000),
            "status":status,"conclusion":conclusion,"head_branch":"feature", "pull_requests":[{"number":42}],"event":"pull_request","repository":{"id":101}})
    }
    fn job(id: i64, completed: i64, conclusion: Option<&str>) -> Value {
        json!({"id":id,"status":"completed","conclusion":conclusion,"completed_at":iso8601::format_millis(completed)})
    }
    fn jobs(count: usize, completed: i64) -> Vec<Value> {
        (1..=count)
            .map(|id| job(id as i64, completed, Some("failure")))
            .collect()
    }

    #[test]
    fn all_conclusions_and_completion_states_map_through_the_real_poll() {
        for conclusion in [
            None,
            Some("failure"),
            Some("timed_out"),
            Some("success"),
            Some("neutral"),
            Some("cancelled"),
            Some("skipped"),
            Some("stale"),
            Some("action_required"),
            Some("startup_failure"),
            Some("future_vendor_conclusion"),
        ] {
            for status in ["completed", "in_progress"] {
                let f = Fixture::new();
                let r = run(1, 1, f.now, status, conclusion);
                let mut j = job(5, f.now, conclusion);
                j["status"] = json!(status);
                f.add(r, vec![j], true);
                let expected = usize::from(status == "completed" && conclusion.is_some()) * 2;
                assert_eq!(f.poll_checked(0), expected, "{status} {conclusion:?}");
                assert_eq!(f.events().len(), expected);
                if expected != 0 {
                    let markers = f.markers();
                    let expected_job = if matches!(conclusion, Some("failure" | "timed_out")) {
                        crate::event_key::GITHUB_CI_JOB_FAILED
                    } else {
                        crate::event_key::GITHUB_CI_JOB_COMPLETED
                    };
                    assert!(markers.iter().any(|m| m.event_name == expected_job));
                    assert!(markers.iter().any(|m| m.event_name == RUN_EVENT));
                    for marker in markers {
                        assert_eq!(marker.headers.conclusion.as_deref(), conclusion);
                    }
                }
            }
        }
    }

    #[test]
    fn early_and_late_jobs_publish_without_a_time_watermark_and_startup_has_one_notice() {
        for startup in [false, true] {
            let f = Fixture::new();
            if startup {
                f.add(
                    run(1, 1, f.now, "completed", Some("startup_failure")),
                    vec![],
                    true,
                );
                assert_eq!(f.poll_checked(0), 1);
                assert_eq!(f.markers()[0].event_name, RUN_EVENT);
                continue;
            }
            f.add(
                run(1, 1, f.now, "in_progress", None),
                vec![job(1, f.now, Some("failure")), job(2, f.now, None)],
                true,
            );
            assert_eq!(
                f.poll_checked(0),
                1,
                "early failed job publishes before the run"
            );
            f.add(
                run(1, 1, f.now, "completed", Some("failure")),
                vec![
                    job(1, f.now, Some("failure")),
                    job(2, f.now - 60_000, Some("failure")),
                ],
                false,
            );
            assert_eq!(
                f.poll_checked(1),
                2,
                "different job id with earlier completion still publishes"
            );
            assert!(f.cursor()["open"].as_object().unwrap().is_empty());
            for tick in 2..=3 {
                assert_eq!(f.poll_checked(tick), 0);
            }
            assert_eq!(
                f.requests()
                    .iter()
                    .filter(|r| r.action == JOBS_READ)
                    .count(),
                2
            );
            assert_eq!(
                f.events()
                    .iter()
                    .map(|(k, _, _)| k.as_str())
                    .collect::<Vec<_>>(),
                vec!["ci_job", "ci_job", "ci_run"]
            );
        }
    }

    #[test]
    fn discovery_outage_reruns_and_open_attempt_overlap_survive_restart() {
        for scenario in ["outage", "rerun", "overlap"] {
            let f = Fixture::new();
            let created = f.now - 20 * 60_000;
            let first = run(1, 1, created, "completed", Some("success"));
            let second = run(1, 2, created, "in_progress", None);
            f.set_cursor(json!({"scanned_through_ms":f.now-30*60_000,"open":{},"pinned":{}}));
            match scenario {
                "outage" => f.add(
                    first.clone(),
                    vec![job(1, created + 5 * 60_000, Some("success"))],
                    true,
                ),
                "rerun" => f.add(second.clone(), vec![job(2, f.now, Some("failure"))], true),
                _ => {
                    f.add(first.clone(), vec![job(1, f.now, Some("success"))], false);
                    f.open(&[first]);
                    f.add(second.clone(), vec![job(2, f.now, Some("failure"))], true);
                }
            }
            assert_eq!(
                f.poll_checked(0),
                if scenario == "outage" {
                    2
                } else if scenario == "overlap" {
                    3
                } else {
                    1
                }
            );
            if scenario != "outage" {
                f.add(
                    run(1, 2, created, "completed", Some("failure")),
                    vec![job(2, f.now, Some("failure"))],
                    false,
                );
                assert_eq!(f.poll_checked(1), 1);
                assert_eq!(
                    f.events()
                        .iter()
                        .filter(|(k, b, _)| k == "ci_job" && b["run"]["run_attempt"] == 2)
                        .count(),
                    1
                );
            }
            assert!(f.requests()[0].args["created"]
                .as_str()
                .unwrap()
                .starts_with(">="));
            if scenario == "outage" {
                assert_eq!(
                    f.requests()[0].args["created"],
                    format!(">={}", iso8601::format_millis(f.now - 40 * 60_000))
                );
            }
        }
    }

    #[test]
    fn discovery_page_cap_and_outage_gaps_are_independent_and_atomic() {
        for (count, outage) in [(200, false), (201, false), (201, true)] {
            let f = Fixture::new();
            let scanned = if outage {
                f.now - 8 * 24 * 3_600_000
            } else {
                f.now - 300_000
            };
            f.set_cursor(json!({"scanned_through_ms":scanned,"pinned":{},"open":{}}));
            for id in 1..=count {
                // All runs are recent. When there are more than 100, they
                // overflow the single page of recently created runs a poll
                // reads. The rotating rescan page will pick up the overflow on
                // later polls, but this poll must still record a
                // `ci_runs_page_cap` coverage gap for the interval the first
                // page could not cover.
                f.add(run(id, 1, f.now - id * 1000, "waiting", None), vec![], true);
            }
            assert_eq!(f.poll_checked(0), 0);
            assert!(f.requests().len() <= 8);
            let gaps = f.gaps();
            assert_eq!(gaps.len(), usize::from(count > 100) + usize::from(outage));
            if count > 100 {
                let g = gaps
                    .iter()
                    .find(|g| g["reason"] == "ci_runs_page_cap")
                    .unwrap();
                assert_eq!(g["from_ms"], scanned - 600_000);
                assert_eq!(g["to_ms"], f.now - 100_000);
            }
            if outage {
                let g = gaps
                    .iter()
                    .find(|g| g["reason"] == "ci_runs_outage")
                    .unwrap();
                assert_eq!(g["from_ms"], scanned);
                assert_eq!(g["to_ms"], f.now - AGE_FLOOR_MS);
            }
            assert_eq!(f.cursor()["scanned_through_ms"], f.now);
        }
    }

    #[test]
    fn idle_and_already_marked_runs_only_discover_and_completed_attempt_reads_jobs_once() {
        for scenario in ["idle", "complete", "replacement"] {
            let f = Fixture::new();
            if scenario != "idle" {
                f.add(
                    run(1, 1, f.now, "completed", Some("failure")),
                    vec![job(1, f.now, Some("failure"))],
                    true,
                );
            }
            for tick in 0..3 {
                assert_eq!(
                    f.poll_checked(tick),
                    if tick == 0 && scenario != "idle" {
                        2
                    } else {
                        0
                    }
                );
            }
            assert_eq!(
                f.requests()
                    .iter()
                    .filter(|r| r.action == JOBS_READ)
                    .count(),
                usize::from(scenario != "idle")
            );
            if scenario == "replacement" {
                let replacement = f
                    .store
                    .subscribe_with_cursor_state(
                        PRINCIPAL,
                        CONNECTION,
                        "list_workflow_runs",
                        300,
                        &json!({}),
                        &json!({"owner":"OWNER","repo":"Repo"}),
                    )
                    .unwrap()
                    .unwrap();
                let before = f.requests().len();
                assert_eq!(
                    TestPoller::new(f.engine.clone()).poll_ci_runs_at(
                        PRINCIPAL,
                        &replacement,
                        f.now + 900_000
                    ),
                    PollCycle::Completed {
                        inserted: 0,
                        duplicates: 0
                    }
                );
                assert_eq!(
                    f.requests().len() - before,
                    2,
                    "marker owned by the predecessor avoids all progress reads"
                );
            }
        }
    }

    #[test]
    fn least_recently_checked_progress_rotates_mixed_sizes_and_bursts_after_restart() {
        for scenario in ["newest", "mixed", "burst"] {
            let f = Fixture::new();
            match scenario {
                "newest" => {
                    let mut waiting = Vec::new();
                    for id in 1..=6 {
                        let r = run(id, 1, f.now, "waiting", None);
                        waiting.push(r.clone());
                        f.add(r, vec![job(id, f.now, None)], false);
                    }
                    f.open(&waiting);
                    f.add(
                        run(7, 1, f.now, "completed", Some("failure")),
                        vec![job(7, f.now, Some("failure"))],
                        true,
                    );
                    assert_eq!(
                        f.poll_checked(0),
                        2,
                        "never checked completion ranks ahead of waiting attempts"
                    );
                    assert_eq!(f.requests()[2].args["run_id"], 7);
                }
                "mixed" => {
                    let a = run(1, 1, f.now, "waiting", None);
                    let b = run(2, 1, f.now, "completed", Some("failure"));
                    f.open(&[a.clone(), b.clone()]);
                    f.add(a, vec![job(900, f.now, None)], false);
                    f.add(b, jobs(500, f.now), false);
                    assert_eq!(f.poll_checked(0), 0);
                    assert_eq!(
                        f.cursor()["open"]["2:1"]["last_checked_ms"],
                        f.now,
                        "skip stamps start time only"
                    );
                    assert_eq!(
                        f.cursor()["open"]["1:1"]["last_checked_ms"],
                        f.now + 1,
                        "fully checked waiting attempt ranks behind skip"
                    );
                    assert_eq!(
                        f.poll_checked(1),
                        501,
                        "five-page attempt is served whole after restart"
                    );
                    assert_eq!(
                        f.requests()
                            .iter()
                            .skip(5)
                            .find(|r| r.action == RUN_READ)
                            .unwrap()
                            .args["run_id"],
                        2
                    );
                    assert_eq!(f.cursor()["open"].as_object().unwrap().len(), 1);
                }
                _ => {
                    for id in 1..=6 {
                        f.add(
                            run(id, 1, f.now, "completed", Some("failure")),
                            jobs(250, f.now)
                                .into_iter()
                                .map(|mut j| {
                                    j["id"] = json!(id * 1000 + j["id"].as_i64().unwrap());
                                    j
                                })
                                .collect(),
                            true,
                        );
                    }
                    for tick in 0..6 {
                        f.poll_checked(tick);
                    }
                    assert_eq!(
                        f.events().len(),
                        6 * 251,
                        "every completion survives capped burst polls and restarts"
                    );
                    assert!(f.cursor()["open"].as_object().unwrap().is_empty());
                }
            }
            let cursor = f.cursor();
            assert_eq!(cursor.as_object().unwrap().len(), 6);
            for entry in cursor["open"].as_object().unwrap().values() {
                assert_eq!(entry.as_object().unwrap().len(), 3);
            }
        }
    }

    #[test]
    fn full_progress_budget_and_queue_ties_are_deterministic_after_restart() {
        for scenario in ["two_discovery_pages", "queue_ties"] {
            let f = Fixture::new();
            if scenario == "two_discovery_pages" {
                f.add(
                    run(999, 1, f.now, "completed", Some("failure")),
                    jobs(500, f.now),
                    true,
                );
                for id in 1..=200 {
                    f.add(
                        run(id, 1, f.now - AGE_FLOOR_MS - 1, "waiting", None),
                        vec![],
                        true,
                    );
                }
                assert_eq!(
                    f.poll_checked(0),
                    501,
                    "first attempt fits the full five-page progress budget"
                );
                assert_eq!(f.requests().len(), 8);
                assert_eq!(
                    f.requests()
                        .iter()
                        .filter(|r| r.action == "list_workflow_runs")
                        .count(),
                    2
                );
                assert_eq!(
                    f.requests()
                        .iter()
                        .filter(|r| r.action == JOBS_READ)
                        .count(),
                    5
                );
                assert_eq!(f.poll_checked(1), 0);
                assert!(f.cursor()["open"].as_object().unwrap().is_empty());
            } else {
                let runs = [
                    run(2, 1, f.now, "waiting", None),
                    run(10, 1, f.now, "waiting", None),
                    run(1, 1, f.now - 1, "waiting", None),
                ];
                f.open(&runs);
                let mut cursor = f.cursor();
                for entry in cursor["open"].as_object_mut().unwrap().values_mut() {
                    entry["last_checked_ms"] = json!(1);
                }
                f.set_cursor(cursor);
                for r in runs {
                    f.add(r, vec![], false);
                }
                for tick in 0..2 {
                    let before = f.requests().len();
                    assert_eq!(f.poll_checked(tick), 0);
                    let requests = f.requests();
                    let ids = requests[before..]
                        .iter()
                        .filter(|r| r.action == RUN_READ)
                        .map(|r| r.args["run_id"].as_i64().unwrap())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        ids,
                        vec![1, 10, 2],
                        "ties break by created_at then string key, not discovery order"
                    );
                }
            }
        }
    }

    #[test]
    fn oversized_attempts_never_publish_jobs_or_block_other_attempts() {
        for terminal in [false, true] {
            let f = Fixture::new();
            f.add(
                run(
                    1,
                    1,
                    f.now,
                    if terminal { "completed" } else { "waiting" },
                    if terminal { Some("failure") } else { None },
                ),
                jobs(501, f.now),
                true,
            );
            f.add(
                run(2, 1, f.now, "completed", Some("failure")),
                vec![job(900, f.now, Some("failure"))],
                true,
            );
            assert_eq!(f.poll_checked(0), if terminal { 3 } else { 2 });
            assert_eq!(
                f.events().iter().filter(|(k, _, _)| k == "ci_job").count(),
                1
            );
            assert_eq!(
                f.events().iter().find(|(k, _, _)| k == "ci_job").unwrap().1["id"],
                900
            );
            assert_eq!(
                f.requests()
                    .iter()
                    .filter(|r| r.action == JOBS_READ && r.args["run_id"] == 1)
                    .count(),
                1
            );
            if !terminal {
                assert_eq!(f.gaps().len(), 0);
                f.add(
                    run(1, 1, f.now, "completed", Some("failure")),
                    jobs(501, f.now),
                    false,
                );
                assert_eq!(f.poll_checked(1), 1);
            }
            let gap = &f.gaps()[0];
            assert_eq!(gap["reason"], "ci_attempt_too_large");
            assert_eq!(gap["from_ms"], f.now);
            assert_eq!(gap["to_ms"], f.now + 60_000);
            assert!(f.cursor()["open"].as_object().unwrap().is_empty());
        }
    }

    #[test]
    fn vanished_and_expired_attempts_are_removed_without_vendor_failure_and_other_reads_continue() {
        for action in [RUN_READ, JOBS_READ, "jobs_later", "expired"] {
            let f = Fixture::new();
            let before = TestPoller::ci_metrics();
            f.add(
                run(
                    1,
                    1,
                    if action == "expired" {
                        f.now - AGE_FLOOR_MS - 1
                    } else {
                        f.now
                    },
                    "waiting",
                    None,
                ),
                if action == "jobs_later" {
                    jobs(101, f.now)
                } else {
                    vec![]
                },
                true,
            );
            f.add(
                run(2, 1, f.now, "completed", Some("failure")),
                vec![job(2, f.now, Some("failure"))],
                true,
            );
            if action == "expired" {
                f.open(&[run(1, 1, f.now - AGE_FLOOR_MS - 1, "waiting", None)]);
            }
            if action != "expired" {
                f.fail(
                    if action == "jobs_later" {
                        JOBS_READ
                    } else {
                        action
                    },
                    1,
                    1,
                    if action == "jobs_later" { 2 } else { 1 },
                    "http_404",
                );
            }
            assert_eq!(f.poll_checked(0), 2);
            assert!(f.cursor()["open"].as_object().unwrap().is_empty());
            assert_eq!(f.watch().status, "active");
            assert_eq!(f.watch().consecutive_vendor_failures, 0);
            let counter = if action == "expired" {
                "runs_expired"
            } else {
                "runs_vanished"
            };
            if action == "expired" {
                assert!(
                    TestPoller::ci_metrics()[counter].as_u64().unwrap()
                        > before[counter].as_u64().unwrap()
                );
            } else {
                assert_eq!(
                    TestPoller::ci_metrics()[counter].as_u64().unwrap(),
                    before[counter].as_u64().unwrap() + 1
                );
            }
        }
    }

    #[test]
    fn any_later_read_failure_commits_no_partial_state_and_restart_delivers_every_completion() {
        for action in ["list_workflow_runs", RUN_READ, JOBS_READ] {
            let f = Fixture::new();
            f.add(
                run(1, 1, f.now, "completed", Some("failure")),
                vec![job(501, f.now, Some("failure"))],
                true,
            );
            f.add(
                run(2, 1, f.now, "completed", Some("failure")),
                jobs(101, f.now),
                true,
            );
            let page = if action == JOBS_READ { 2 } else { 1 };
            f.fail(
                action,
                if action == "list_workflow_runs" { 0 } else { 2 },
                if action == "list_workflow_runs" { 0 } else { 1 },
                page,
                "http_503",
            );
            let before = f.cursor();
            assert!(matches!(f.poll(0), PollCycle::VendorFailed { .. }));
            assert_eq!(
                f.cursor(),
                before,
                "failed cycle leaves cursor and pins unchanged"
            );
            assert!(f.events().is_empty());
            assert!(f.gaps().is_empty());
            assert!(f.markers().is_empty());
            assert_eq!(f.watch().consecutive_vendor_failures, 1);
            assert!(f.store.repo_id_cache("owner/repo").unwrap().is_none());
            f.script.lock().unwrap().failures.clear();
            assert_eq!(f.poll_checked(1), 104);
            assert_eq!(f.watch().consecutive_vendor_failures, 0);
        }
    }

    #[test]
    fn age_floor_refuses_old_jobs_and_runs_but_not_distinct_recent_late_failures() {
        let f = Fixture::new();
        let mut r = run(1, 1, f.now, "completed", Some("failure"));
        r["updated_at"] = json!(iso8601::format_millis(f.now - AGE_FLOOR_MS - 1));
        f.add(
            r,
            vec![
                job(1, f.now - AGE_FLOOR_MS - 1, Some("failure")),
                job(2, f.now - AGE_FLOOR_MS, Some("failure")),
            ],
            true,
        );
        assert_eq!(f.poll_checked(0), 1);
        assert_eq!(f.events()[0].1["id"], 2);
        assert_eq!(f.events()[0].2, f.now - AGE_FLOOR_MS);
        assert!(f.cursor()["open"].as_object().unwrap().is_empty());
    }

    #[test]
    fn admission_defers_without_dispatch_attempt_stamp_or_vendor_failure() {
        let f = Fixture::new();
        f.sql(&format!(
            "INSERT INTO github_actions_quota WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<306) SELECT 'full-'||x, {}, CASE WHEN x<=299 THEN 8 ELSE 1 END FROM n",
            f.now
        ));
        let before = f.watch();
        let count = TestPoller::ci_metrics()["ci_polls_deferred"]
            .as_u64()
            .unwrap();
        assert!(matches!(f.poll(0), PollCycle::Deferred { .. }));
        assert!(f.requests().is_empty());
        let after = f.watch();
        assert_eq!(after.cursor_state, before.cursor_state);
        assert_eq!(after.last_polled_at_ms, before.last_polled_at_ms);
        assert_eq!(after.consecutive_vendor_failures, 0);
        assert!(
            TestPoller::ci_metrics()["ci_polls_deferred"]
                .as_u64()
                .unwrap()
                > count
        );
    }

    #[test]
    fn hand_made_pins_and_every_page_authorization_are_audited_and_schema_drift_suspends() {
        for action in [RUN_READ, JOBS_READ] {
            let f = Fixture::new();
            assert_eq!(
                TestPoller::new(f.engine.clone()).poll_once(PRINCIPAL, &f.watch.subscription_id),
                PollCycle::Completed {
                    inserted: 0,
                    duplicates: 0
                }
            );
            assert_eq!(f.cursor()["pinned"][action], format!("pin-{action}"));
            f.add(
                run(1, 1, f.now, "completed", Some("failure")),
                jobs(101, f.now),
                true,
            );
            f.sql(&format!(
                "UPDATE catalog_actions SET schema_hash='drifted' WHERE name='{action}'"
            ));
            let before = f.requests().len();
            assert!(
                matches!(f.poll(1),PollCycle::Suspended { reason } if reason.contains("schema"))
            );
            assert_eq!(f.watch().consecutive_vendor_failures, 0);
            assert_eq!(f.watch().status, "suspended");
            assert!(f.events().is_empty());
            assert_eq!(
                f.requests().len() - before,
                if action == RUN_READ { 2 } else { 3 },
                "pinned mismatch is refused before dispatch"
            );
        }
        let f = Fixture::new();
        f.add(
            run(1, 1, f.now, "completed", Some("success")),
            jobs(201, f.now),
            true,
        );
        assert_eq!(f.poll_checked(0), 202);
        let audit = f.store.list_audit(PRINCIPAL).unwrap();
        let rows = audit
            .iter()
            .filter(|r| r.outcome.is_some())
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            f.requests().len(),
            "every page has its own dispatch audit row"
        );
        assert!(rows
            .iter()
            .all(|r| r.actor == format!("trigger:{}", f.watch.subscription_id)));
        assert_eq!(
            rows.iter()
                .filter(|r| r.action.as_deref() == Some(JOBS_READ))
                .count(),
            3
        );
    }

    /// Revoking permission to list jobs suspends the subscription only when a
    /// poll needs a jobs page. A locked credential vault on a later jobs page
    /// instead makes the cycle inconclusive: commit no events or cursor changes
    /// and do not increase consecutive vendor failures. Local credential errors
    /// must not trigger the polling stop that requires operator recovery.
    /// After the vault recovers, the next poll inserts all 102 fixture events.
    #[test]
    fn revoked_jobs_selector_is_checked_only_when_used_and_transient_denial_is_inconclusive() {
        for transient in [false, true] {
            let f = Fixture::new();
            if transient {
                f.script.lock().unwrap().deny_after_first_jobs = true;
            } else {
                f.sql("UPDATE grants SET action_selectors='[\"list_workflow_runs\",\"get_workflow_run\"]' WHERE grant_id='ci-poll'");
                assert_eq!(f.poll_checked(0), 0, "idle cycle needs no jobs authority");
                assert_eq!(f.watch().status, "active");
            }
            f.add(
                run(1, 1, f.now, "completed", Some("failure")),
                jobs(101, f.now),
                true,
            );
            let before = f.cursor();
            let result = f.poll(1);
            assert!(f.events().is_empty());
            assert!(f.markers().is_empty());
            if transient {
                assert_eq!(
                    result,
                    PollCycle::Inconclusive {
                        code: "credential_vault_locked".into()
                    }
                );
                assert_eq!(f.watch().status, "active");
                assert_eq!(f.watch().consecutive_vendor_failures, 0);
                assert_eq!(f.cursor(), before);
                f.script.lock().unwrap().deny_after_first_jobs = false;
                f.credentials
                    .set_success(HANDLE, b"ci-token".to_vec(), None, 1);
                assert_eq!(f.poll_checked(2), 102);
            } else {
                assert!(matches!(result, PollCycle::Suspended { .. }));
                assert_eq!(f.watch().consecutive_vendor_failures, 0);
            }
        }
    }

    #[test]
    fn bodies_headers_and_atomic_absent_only_cache_seed_follow_the_run_metadata() {
        for cached in [None, Some(202)] {
            let f = Fixture::new();
            if let Some(id) = cached {
                f.sql(&format!(
                    "INSERT INTO github_repo_id_cache VALUES ('owner/repo',{id},1,2)"
                ));
            }
            f.sql("UPDATE trigger_subscriptions SET project_id='project-ci',project_source='hand'");
            f.add(
                run(1, 2, f.now, "completed", Some("failure")),
                vec![job(5, f.now, Some("failure"))],
                true,
            );
            assert_eq!(f.poll_checked(0), 2);
            let cache = f.store.repo_id_cache("OWNER/Repo").unwrap().unwrap();
            assert_eq!(cache.repo_id, Some(cached.unwrap_or(101)));
            if cached.is_some() {
                assert_eq!(cache.last_attempt_at_ms, 1);
                assert_eq!(cache.resolved_at_ms, Some(2));
            } else {
                assert!(cache.last_attempt_at_ms >= f.now && cache.last_attempt_at_ms <= now_ms());
                assert_eq!(cache.resolved_at_ms, Some(cache.last_attempt_at_ms));
            }
            let markers = f.markers();
            for m in &markers {
                assert_eq!(m.headers.repo, "owner/repo");
                assert_eq!(m.headers.project.as_deref(), Some("project-ci"));
                assert_eq!(m.headers.branch.as_deref(), Some("feature"));
                assert_eq!(m.headers.pr.as_deref(), Some("42"));
                assert_eq!(m.headers.conclusion.as_deref(), Some("failure"));
                assert_eq!(m.repo_id, 101);
            }
            let body: Value = serde_json::from_str(
                &markers
                    .iter()
                    .find(|m| m.event_name == crate::event_key::GITHUB_CI_JOB_FAILED)
                    .unwrap()
                    .body,
            )
            .unwrap();
            assert_eq!(
                body["run"],
                json!({"run_id":1,"run_attempt":2,"head_branch":"feature","pull_requests":[{"number":42}],"event":"pull_request","repository_id":101})
            );
        }
        for prs in [json!([]), json!([{"number":1},{"number":2}])] {
            let f = Fixture::new();
            let mut r = run(1, 1, f.now, "completed", Some("success"));
            r["pull_requests"] = prs;
            f.add(r, vec![], true);
            assert_eq!(f.poll_checked(0), 1);
            assert_eq!(f.markers()[0].headers.pr, None);
        }
        let f = Fixture::new();
        // Failing after inserting the marker and its seed must roll back both.
        f.sql("CREATE TRIGGER reject_ci_gap BEFORE INSERT ON trigger_events WHEN NEW.kind='gap' BEGIN SELECT RAISE(ABORT,'reject gap'); END");
        f.add(
            run(1, 1, f.now, "completed", Some("failure")),
            jobs(501, f.now),
            true,
        );
        assert!(matches!(f.poll(0), PollCycle::StoreFailed { .. }));
        assert!(f.events().is_empty());
        assert!(f.markers().is_empty());
        assert!(f.store.repo_id_cache("owner/repo").unwrap().is_none());
        assert_eq!(f.cursor(), json!({}));
    }

    /// Treat a local refusal or unknown CI read outcome as inconclusive. Keep
    /// the subscription active without advancing its cursor or increasing its
    /// consecutive vendor-failure count. These outcomes must not trigger the
    /// polling stop that requires operator recovery. After clearing each
    /// injected failure, the next poll inserts both fixture events.
    #[test]
    fn local_refusal_and_unknown_outcome_are_inconclusive_and_never_feed_the_breaker() {
        for (code, expected) in [
            ("local_not_sent", "transport_transient"),
            ("local_outcome_unknown", "outcome_unknown"),
        ] {
            for action in ["list_workflow_runs", RUN_READ, JOBS_READ] {
                let f = Fixture::new();
                f.add(
                    run(1, 1, f.now, "completed", Some("failure")),
                    vec![job(501, f.now, Some("failure"))],
                    true,
                );
                let (id, attempt) = if action == "list_workflow_runs" {
                    (0, 0)
                } else {
                    (1, 1)
                };
                f.fail(action, id, attempt, 1, code);
                let before = f.cursor();
                assert_eq!(
                    f.poll(0),
                    PollCycle::Inconclusive {
                        code: expected.into()
                    },
                    "{code} on {action}"
                );
                assert_eq!(
                    f.watch().consecutive_vendor_failures,
                    0,
                    "{code} on {action} must not count as the vendor's failure"
                );
                assert_eq!(f.watch().status, "active");
                assert_eq!(f.cursor(), before);
                assert!(f.events().is_empty());
                f.script.lock().unwrap().failures.clear();
                assert_eq!(f.poll_checked(1), 2, "{code} on {action}");
            }
        }
    }

    /// Suspend a subscription with an unreadable cursor before any vendor read
    /// and reserve no requests for it. CI subscriptions share a request limit
    /// over the preceding hour, and reservations never receive refunds.
    /// Reserving for a subscription that cannot poll would reduce the allowance
    /// available to other subscriptions.
    #[test]
    fn a_watch_refused_before_reading_reserves_no_quota() {
        let f = Fixture::new();
        f.set_cursor(json!({"unexpected": true}));
        assert_eq!(
            f.poll(0),
            PollCycle::Suspended {
                reason: "cursor_state_unusable".into()
            }
        );
        let reserved: i64 = f
            .conn()
            .query_row(
                "SELECT COALESCE(SUM(requests), 0) FROM github_actions_quota",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reserved, 0, "a suspended watch spent shared CI quota");
        assert!(f.requests().is_empty());
    }

    /// Account for each completed run or job in the poll metrics as either an
    /// inserted event or a dropped item. Here one run and one job have activity
    /// timestamps before the oldest allowed time; one job produces a new event.
    ///
    /// Run only this test in a child process because the counters accumulate
    /// across the process lifetime. Other tests must not affect these counts.
    #[test]
    fn a_ci_cycle_balances_the_poll_ledger() {
        const TEST: &str = "poller::ci_runs::tests::a_ci_cycle_balances_the_poll_ledger";
        const CHILD: &str = "PLEXUS_CI_LEDGER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = crate::test_http::bounded::child_output(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(CHILD, "1"),
                std::time::Duration::from_secs(60),
                "CI ledger test child",
            )
            .expect("run child");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "CI ledger child failed: {stdout} {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let f = Fixture::new();
        let mut r = run(1, 1, f.now, "completed", Some("failure"));
        r["updated_at"] = json!(iso8601::format_millis(f.now - AGE_FLOOR_MS - 1));
        f.add(
            r,
            vec![
                job(1, f.now - AGE_FLOOR_MS - 1, Some("failure")),
                job(2, f.now, Some("failure")),
            ],
            true,
        );
        assert_eq!(f.poll_checked(0), 1);
        assert_eq!(
            crate::poller::poll_accounting_metrics(),
            json!({
                "itemsExamined": 3,
                "eventsInserted": 1,
                "identityViolations": 0,
                "droppedByReason": {
                    "olderThanWatermark": 2,
                    "initialBaseline": 0,
                    "unchangedObservation": 0,
                    "unchangedBoundaryReplay": 0,
                    "alreadyDelivered": 0
                },
                "lateRowsBySubscription": {},
                "credentialNeedsRepairByConnection": {}
            })
        );
    }
}
