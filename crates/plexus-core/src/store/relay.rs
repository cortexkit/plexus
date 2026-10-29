//! Durable webhook cursors and atomic admission to the polling event outbox.
use super::*;
use crate::actor_attribution::ActorUnknownCode;
use crate::poller::iso8601::parse_to_millis;
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Default)]
struct MarkerLog {
    last: Option<Instant>,
    markers: usize,
    watches: usize,
}
impl MarkerLog {
    fn record(&mut self, watches: usize, now: Instant) -> Option<(usize, usize)> {
        if watches == 0 {
            return None;
        }
        self.markers += 1;
        self.watches += watches;
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(60))
        {
            return None;
        }
        self.last = Some(now);
        Some((
            std::mem::take(&mut self.markers),
            std::mem::take(&mut self.watches),
        ))
    }
}
static MARKER_LOG: std::sync::Mutex<MarkerLog> = std::sync::Mutex::new(MarkerLog {
    last: None,
    markers: 0,
    watches: 0,
});
fn log_marker_due(reason: &str, watches: usize) {
    // Count committed watch marks, including repeats; suppressed markers join the next line.
    let mut log = MARKER_LOG.lock().unwrap();
    if let Some((markers, watches)) = log.record(watches, Instant::now()) {
        diag!(info relay: "relay markers made watches due: latest_reason={reason} markers={markers} watch_marks={watches}");
    }
}

pub const MAX_SEQ: u64 = 9_007_199_254_740_991;

/// Most run attempts remembered from `workflow_run` webhooks. A job webhook
/// normally follows its run's `requested` webhook within minutes, so this
/// holds far more than the attempts in flight at once.
const CI_RUN_CACHE_CAPACITY: usize = 10_000;
/// Oldest remembered run attempt, by relay receipt time: 24 hours.
const CI_RUN_CACHE_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// (lowercase repository full name, run id, run attempt)
type CiRunKey = (String, i64, i64);

/// The actor, triggering actor, event and fork status of recent workflow run
/// attempts, taken from `workflow_run` webhooks. A `workflow_job` webhook
/// carries none of these values, so its v2 envelope takes them from here.
/// A job whose run attempt is not remembered gets nulls. The cache lives in
/// memory only and is bounded by count and by receipt age; the oldest entry
/// is evicted first.
#[derive(Default)]
pub struct CiRunCache {
    inner: std::sync::Mutex<CiRunCacheEntries>,
}

#[derive(Default)]
struct CiRunCacheEntries {
    /// Values, the receipt time they were stored at, and their insertion number.
    entries:
        std::collections::HashMap<CiRunKey, (crate::event_envelope::CiRunAttribution, i64, u64)>,
    /// Keys by insertion number, oldest first.
    order: std::collections::BTreeMap<u64, CiRunKey>,
    next: u64,
}

fn ci_run_key(repo: &str, run_id: Option<&Value>, attempt: Option<&Value>) -> Option<CiRunKey> {
    Some((
        repo.to_ascii_lowercase(),
        run_id?.as_i64().filter(|id| *id > 0)?,
        attempt?.as_i64().filter(|attempt| *attempt > 0)?,
    ))
}

impl CiRunCache {
    /// Remember the run values of any `workflow_run` webhook, whatever its
    /// action. Storing does not admit the webhook as an event.
    fn remember(&self, event: &Event, received: i64) {
        let Some((repo, _)) = repository(&event.body) else {
            return;
        };
        let run = &event.body["workflow_run"];
        let Some(key) = ci_run_key(&repo, run.get("id"), run.get("run_attempt")) else {
            return;
        };
        let attribution = crate::event_envelope::CiRunAttribution::from_run(run);
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let cache = &mut *guard;
        if let Some((_, _, old)) = cache.entries.remove(&key) {
            cache.order.remove(&old);
        }
        let number = cache.next;
        cache.next += 1;
        cache
            .entries
            .insert(key.clone(), (attribution, received, number));
        cache.order.insert(number, key);
        let oldest_allowed = received.saturating_sub(CI_RUN_CACHE_MAX_AGE_MS);
        while let Some((&number, key)) = cache.order.first_key_value() {
            let expired = cache
                .entries
                .get(key)
                .is_none_or(|(_, stored, _)| *stored < oldest_allowed);
            if cache.entries.len() <= CI_RUN_CACHE_CAPACITY && !expired {
                break;
            }
            let key = key.clone();
            cache.order.remove(&number);
            cache.entries.remove(&key);
        }
    }

    /// The remembered values for a `workflow_job` object's run attempt, or
    /// `None` when that attempt was not seen or was seen too long ago.
    fn for_job(
        &self,
        repo: &str,
        job: &Value,
        received: i64,
    ) -> Option<crate::event_envelope::CiRunAttribution> {
        let key = ci_run_key(repo, job.get("run_id"), job.get("run_attempt"))?;
        let cache = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        cache
            .entries
            .get(&key)
            .filter(|(_, stored, _)| *stored >= received.saturating_sub(CI_RUN_CACHE_MAX_AGE_MS))
            .map(|(attribution, _, _)| attribution.clone())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .entries
            .len()
    }
}

#[derive(Deserialize)]
pub struct Hello {
    pub v: u64,
    pub source: String,
    pub stream_id: String,
    pub next_seq: u64,
    pub oldest_seq: u64,
    pub last_acked_seq: u64,
}

#[derive(Deserialize)]
pub struct Event {
    pub seq: u64,
    pub delivery_id: String,
    pub event: String,
    pub action: Option<String>,
    pub installation_id: i64,
    pub received_at: String,
    pub stub: Option<Stub>,
    pub body: Value,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Stub {
    Oversized,
    RateLimited,
    Overflow,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cursor {
    pub stream_id: String,
    pub committed_seq: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageReset {
    StreamChanged,
    SequenceReset,
    Gap,
}
impl CoverageReset {
    pub fn name(self) -> &'static str {
        match self {
            Self::StreamChanged => "stream_changed",
            Self::SequenceReset => "sequence_reset",
            Self::Gap => "gap",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DropReason {
    UnwatchedRepository,
    RepositoryIdentityChanged,
    InvalidPayload,
    UnsupportedEvent,
    AlreadyDelivered,
    PrCommentReread,
}

/// Admission result after a relay frame's store transaction commits.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Stored,
    Dropped(DropReason),
    /// A cursor replay or reconciliation marker, not an admitted or dropped event.
    CursorOnly,
}
impl DropReason {
    fn counter(&self) -> &'static str {
        match self {
            Self::UnwatchedRepository => "relay_drop_unwatched_repository",
            Self::RepositoryIdentityChanged => "relay_drop_repository_identity_changed",
            Self::InvalidPayload => "relay_drop_invalid_payload",
            Self::UnsupportedEvent => "relay_drop_unsupported_event",
            Self::AlreadyDelivered => "relay_drop_already_delivered",
            Self::PrCommentReread => "relay_drop_pr_comment_reread",
        }
    }
}

fn protocol_error() -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName("invalid relay protocol".into())
}
fn cursor(conn: &rusqlite::Connection, source: &str) -> rusqlite::Result<Option<Cursor>> {
    conn.query_row(
        "SELECT stream_id, committed_seq FROM relay_cursor WHERE source=?1",
        [source],
        |row| {
            Ok(Cursor {
                stream_id: row.get(0)?,
                committed_seq: row.get(1)?,
            })
        },
    )
    .optional()
}

// Only schedules existing watches: the scheduler still owns authorization and quota admission.
fn reconcile(
    conn: &rusqlite::Connection,
    repository: Option<(&str, Option<i64>)>,
) -> rusqlite::Result<usize> {
    reconcile_backstop(conn, repository, true)
}

fn reconcile_backstop(
    conn: &rusqlite::Connection,
    repository: Option<(&str, Option<i64>)>,
    include_releases: bool,
) -> rusqlite::Result<usize> {
    if let Some((repo, Some(id))) = repository {
        let recorded: Option<i64> = conn
            .query_row(
                "SELECT repo_id FROM github_repo_id_cache WHERE repo=lower(?1)",
                [repo],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if recorded.is_some_and(|recorded| recorded != id) {
            return Ok(0);
        }
    }
    conn.execute("UPDATE trigger_subscriptions SET last_polled_at_ms=NULL
        WHERE status='active' AND action IN ('list_issues','list_pull_requests','get_latest_release','list_releases','list_workflow_runs')
        AND (?2 OR action NOT IN ('get_latest_release','list_releases'))
        AND (?1 IS NULL OR lower(json_extract(fixed_args,'$.owner') || '/' || json_extract(fixed_args,'$.repo'))=lower(?1))
        AND EXISTS (SELECT 1 FROM connections c WHERE c.principal=trigger_subscriptions.principal
            AND c.connection_id=trigger_subscriptions.connection_id AND c.app_key IN ('github','github_actions'))",
        rusqlite::params![repository.map(|(name, _)| name), include_releases])
}

fn reread(conn: &rusqlite::Connection, event: &Event) -> rusqlite::Result<usize> {
    let repo = repository(&event.body);
    reconcile(
        conn,
        repo.as_ref().map(|(name, id)| (name.as_str(), Some(*id))),
    )
}

impl PlexusStore {
    /// Reuse relay reconciliation after a lost connection. Releases are not
    /// covered by the relay App, so their polling schedule is left alone.
    pub fn relay_disconnected(&self) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| reconcile_backstop(conn, None, false).map(|_| ()))
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn relay_cursor(&self, source: &str) -> Result<Option<Cursor>, StoreError> {
        self.inner.with_read(|conn| cursor(conn, source))
    }

    pub fn relay_hello(
        &self,
        source: &str,
        hello: &Hello,
    ) -> Result<Option<CoverageReset>, StoreError> {
        if hello.source != source
            || hello.v != 1
            || hello.stream_id.is_empty()
            || hello.next_seq == 0
            || hello.next_seq > MAX_SEQ
            || hello.oldest_seq == 0
            || hello.oldest_seq > hello.next_seq
            || hello.last_acked_seq > MAX_SEQ
            || hello.last_acked_seq >= hello.next_seq
        {
            return Err(StoreError::Backend("invalid relay hello".into()));
        }
        let mut watches = 0;
        let reset = self.inner.with_conn_fenced(|conn| {
            let mut reset = None;
            let old = cursor(conn, source)?;
            let changed = old.as_ref().is_some_and(|old| old.stream_id != hello.stream_id);
            let mut committed = old.as_ref().filter(|_| !changed).map_or(0, |c| c.committed_seq);
            if changed {
                reset = Some(CoverageReset::StreamChanged);
                diag!(warn relay: "relay {source} stream changed; full reconcile queued");
                watches += reconcile(conn, None)?;
            }
            let floor = hello.oldest_seq - 1;
            // On the same stream the relay will next send `next_seq`, so a
            // cursor at or past it means the relay's sequence went backwards
            // (its state was lost or restored). Every event it now sends would
            // be discarded as already committed, so restart from what it still
            // holds and reconcile everything, as for a changed stream.
            if !changed && committed >= hello.next_seq {
                reset = Some(CoverageReset::SequenceReset);
                diag!(warn relay: "relay {source} sequence went back from committed {committed} to next {}; full reconcile queued", hello.next_seq);
                watches += reconcile(conn, None)?;
                committed = floor.max(hello.last_acked_seq.min(hello.next_seq - 1));
            }
            if committed < floor || committed < hello.last_acked_seq {
                reset = reset.or(Some(CoverageReset::Gap));
                diag!(warn relay: "relay {source} gap {}..{}; full reconcile queued", committed + 1, floor.max(hello.last_acked_seq));
                watches += reconcile(conn, None)?;
                committed = floor.max(hello.last_acked_seq);
            }
            conn.execute("INSERT INTO relay_cursor(source,stream_id,committed_seq) VALUES (?1,?2,?3)
                ON CONFLICT(source) DO UPDATE SET stream_id=excluded.stream_id,committed_seq=excluded.committed_seq",
                (source, &hello.stream_id, committed))?;
            Ok(reset)
        })?;
        if let Some(reset) = reset {
            log_marker_due(reset.name(), watches);
        }
        Ok(reset)
    }

    /// The cursor, drop ledger, reconcile queue and event/outbox insert commit together.
    pub fn commit_relay_event(
        &self,
        source: &str,
        stream: &str,
        event: &Event,
    ) -> Result<(), StoreError> {
        self.commit_relay_event_with_outcome(source, stream, event)
            .map(|_| ())
    }

    /// Report admission only after the cursor and event transaction has committed.
    pub fn commit_relay_event_with_outcome(
        &self,
        source: &str,
        stream: &str,
        event: &Event,
    ) -> Result<CommitOutcome, StoreError> {
        let received = parse_to_millis(&event.received_at)
            .ok_or_else(|| StoreError::Backend("invalid relay receipt time".into()))?;
        if event.seq == 0
            || event.received_at.len() != 24
            || event.received_at.as_bytes().get(10) != Some(&b'T')
            || event.received_at.as_bytes().get(19) != Some(&b'.')
            || !event.received_at.ends_with('Z')
            || event.seq > MAX_SEQ
            || event.delivery_id.is_empty()
            || !event.body.is_object()
        {
            return Err(StoreError::Backend("invalid relay event".into()));
        }
        let mut inserted = false;
        let mut outcome = CommitOutcome::CursorOnly;
        let mut committed_new = false;
        let mut due_watches = 0;
        let mut marker_reason = "pr_comment_reread";
        self.inner.with_conn_fenced(|conn| {
            let current = cursor(conn, source)?.ok_or_else(protocol_error)?;
            if current.stream_id != stream { return Err(protocol_error()); }
            if event.seq <= current.committed_seq { return Ok(()); }
            if event.seq != current.committed_seq + 1 { return Err(protocol_error()); }
            committed_new = true;
            match event.stub {
                Some(Stub::Oversized) => { marker_reason = "oversized"; due_watches += reread(conn, event)?; }
                Some(Stub::RateLimited) => { marker_reason = "rate_limited"; due_watches += reread(conn, event)?; }
                Some(Stub::Overflow) => {
                    diag!(warn relay: "relay overflow gap at seq={} installation={}; full reconcile queued", event.seq, event.installation_id);
                    // Relay installations are not agent bot Apps; without an authoritative mapping, reconcile all watches.
                    marker_reason = "overflow";
                    due_watches += reconcile(conn, None)?;
                }
                None if event.event == "cortexkit_installation_bound" => {
                    marker_reason = "installation_bound";
                    match event.body.get("repositories") {
                        Some(Value::Null) => due_watches += reconcile(conn, None)?,
                        Some(Value::Array(repos)) => for repo in repos {
                            if let Some((name, id)) = repository_item(repo) { due_watches += reconcile(conn, Some((&name, Some(id))))?; }
                        },
                        _ => return Err(protocol_error()),
                    }
                }
                None => {
                    if let Err(reason) = admit(conn, event, received, &self.ci_runs, &mut due_watches)? {
                        event_outbox::increment(conn, reason.counter(), 1)?;
                        // Malformed payloads need immediate visibility; identity changes already emit a storage warning.
                        if matches!(reason, DropReason::InvalidPayload) {
                            diag!(info relay: "relay event dropped reason={:?} seq={} event={} action={:?}", reason, event.seq, event.event, event.action);
                        } else {
                            diag!(debug relay: "relay event dropped reason={:?} seq={} event={} action={:?}", reason, event.seq, event.event, event.action);
                        }
                        outcome = CommitOutcome::Dropped(reason);
                    } else {
                        inserted = true;
                        outcome = CommitOutcome::Stored;
                    }
                }
            }
            conn.execute("UPDATE relay_cursor SET committed_seq=?1 WHERE source=?2 AND stream_id=?3", (event.seq, source, stream))?;
            Ok(())
        })?;
        log_marker_due(marker_reason, due_watches);
        if committed_new && event.stub.is_none() && event.event == "workflow_run" {
            self.ci_runs.remember(event, received);
        }
        if inserted {
            self.outbox_ready.notify_one();
        }
        Ok(outcome)
    }
}

fn repository_item(repo: &Value) -> Option<(String, i64)> {
    let name = repo.get("full_name")?.as_str()?;
    if name.trim().is_empty() {
        return None;
    }
    Some((
        name.to_owned(),
        repo.get("id")?.as_i64().filter(|id| *id > 0)?,
    ))
}
fn repository(body: &Value) -> Option<(String, i64)> {
    repository_item(body.get("repository")?)
}

struct Watch {
    principal: String,
    connection: String,
    subscription: String,
    project: Option<String>,
}
fn watch(conn: &rusqlite::Connection, repo: &str, action: &str) -> rusqlite::Result<Option<Watch>> {
    // A paused poller can still receive webhooks on its existing CI or release
    // watch. Reuse ownership's rule so stale or retired watches stay excluded.
    let exists = if matches!(action, "list_workflow_runs" | "get_latest_release") {
        super::repository_ownership_store::WATCH_EXISTS_SQL
    } else {
        "s.status='active'"
    };
    conn.query_row(&format!("SELECT s.principal,s.connection_id,s.subscription_id,s.project_id
        FROM trigger_subscriptions s JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id
        WHERE {exists} AND c.status='active' AND c.app_key IN ('github','github_actions') AND s.action=?2
        AND lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo'))=lower(?1)
        ORDER BY s.subscription_id LIMIT 1"), (repo, action), |r| Ok(Watch {
            principal:r.get(0)?, connection:r.get(1)?, subscription:r.get(2)?, project:r.get(3)? })).optional()
}

fn paired_watches(conn: &Connection, repo: &str, action: &str) -> rusqlite::Result<Vec<Watch>> {
    let counterpart = if action == "list_issues" {
        "list_pull_requests"
    } else {
        "list_issues"
    };
    conn.prepare("SELECT s.principal,s.connection_id,s.subscription_id,s.project_id
        FROM trigger_subscriptions s JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id
        WHERE s.status='active' AND c.status='active' AND c.app_key='github' AND s.action=?2
        AND lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo'))=lower(?1)
        AND EXISTS (SELECT 1 FROM trigger_subscriptions p JOIN connections pc
            ON pc.principal=p.principal AND pc.connection_id=p.connection_id
            WHERE p.principal=s.principal AND p.project_id IS s.project_id AND p.status='active'
            AND pc.status='active' AND pc.app_key='github' AND p.action=?3
            AND lower(json_extract(p.fixed_args,'$.owner') || '/' || json_extract(p.fixed_args,'$.repo'))=lower(?1))
        ORDER BY s.subscription_id")?
        .query_map((repo, action, counterpart), |r| Ok(Watch {
            principal:r.get(0)?, connection:r.get(1)?, subscription:r.get(2)?, project:r.get(3)? }))?.collect()
}

type EventShape = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

fn event_shape(event: &Event) -> Result<EventShape, DropReason> {
    use crate::event_key::*;
    Ok(match event.event.as_str() {
        "issues" | "issue_comment" => (
            GITHUB_ISSUE_CHANGED,
            "issue",
            "issue",
            "list_issues",
            "updated_at",
        ),
        "pull_request" if event.action.as_deref() == Some("dequeued") => (
            GITHUB_PR_DEQUEUED,
            "pull_request",
            "pull_request",
            "list_pull_requests",
            "updated_at",
        ),
        "pull_request" | "pull_request_review" | "pull_request_review_comment" => (
            GITHUB_PR_CHANGED,
            "pull_request",
            "pull_request",
            "list_pull_requests",
            "updated_at",
        ),
        "release" if event.action.as_deref() == Some("published") => (
            GITHUB_RELEASE_PUBLISHED,
            "release",
            "release",
            "get_latest_release",
            "published_at",
        ),
        "workflow_job"
            if event
                .body
                .pointer("/workflow_job/status")
                .and_then(Value::as_str)
                == Some("completed") =>
        {
            let failed = matches!(
                event
                    .body
                    .pointer("/workflow_job/conclusion")
                    .and_then(Value::as_str),
                Some("failure" | "timed_out")
            );
            (
                if failed {
                    GITHUB_CI_JOB_FAILED
                } else {
                    GITHUB_CI_JOB_COMPLETED
                },
                "ci_job",
                "workflow_job",
                "list_workflow_runs",
                "completed_at",
            )
        }
        "workflow_run"
            if event
                .body
                .pointer("/workflow_run/status")
                .and_then(Value::as_str)
                == Some("completed") =>
        {
            (
                GITHUB_CI_RUN_COMPLETED,
                "ci_run",
                "workflow_run",
                "list_workflow_runs",
                "updated_at",
            )
        }
        _ => return Err(DropReason::UnsupportedEvent),
    })
}

fn relay_headers(repo: &str, project: Option<String>, kind: &str, payload: &Value) -> EventHeaders {
    let prs = payload.get("pull_requests").and_then(Value::as_array);
    EventHeaders {
        repo: repo.into(),
        project,
        pr: if matches!(
            kind,
            crate::event_key::GITHUB_PR_CHANGED | crate::event_key::GITHUB_PR_DEQUEUED
        ) {
            payload.get("number").map(Value::to_string)
        } else {
            prs.filter(|prs| prs.len() == 1)
                .and_then(|prs| prs[0].get("number"))
                .map(Value::to_string)
        },
        branch: payload
            .get("head_branch")
            .and_then(Value::as_str)
            .map(str::to_owned),
        conclusion: payload
            .get("conclusion")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn relay_project(
    conn: &Connection,
    repo: &str,
    target: &Watch,
    action: &str,
) -> rusqlite::Result<Option<String>> {
    if matches!(action, "list_issues" | "list_pull_requests") {
        return Ok(target.project.clone());
    }
    // CI and release watches inherit the repository's issue-watch annotation,
    // but another principal's annotation must not replace their own routing.
    let issue_project = conn.query_row("SELECT s.project_id FROM trigger_subscriptions s
        JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id
        WHERE s.principal=?2 AND s.status='active' AND s.action='list_issues'
        AND c.status='active' AND c.app_key='github'
        AND lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo'))=lower(?1)
        ORDER BY s.subscription_id LIMIT 1", (repo, &target.principal), |row| row.get::<_,Option<String>>(0)).optional()?;
    Ok(issue_project.unwrap_or_else(|| target.project.clone()))
}

fn admit(
    conn: &rusqlite::Connection,
    event: &Event,
    received: i64,
    ci_runs: &CiRunCache,
    due_watches: &mut usize,
) -> rusqlite::Result<Result<(), DropReason>> {
    let Some((repo, repo_id)) = repository(&event.body) else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    let watched: bool = conn.query_row("SELECT EXISTS (SELECT 1 FROM trigger_subscriptions s
        JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id
        WHERE s.status <> 'retired' AND c.status='active' AND c.app_key IN ('github','github_actions')
        AND lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo'))=lower(?1))",
        [&repo], |row| row.get(0))?;
    if !watched {
        return Ok(Err(DropReason::UnwatchedRepository));
    }
    let recorded: Option<i64> = conn
        .query_row(
            "SELECT repo_id FROM github_repo_id_cache WHERE repo=lower(?1)",
            [&repo],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    if recorded.is_some_and(|old| old != repo_id) {
        event_outbox::record_repo_id_resolution_on_conn(conn, &repo, Some(repo_id), received)?;
        return Ok(Err(DropReason::RepositoryIdentityChanged));
    }
    if event.event == "issue_comment" && event.body["issue"].get("pull_request").is_some() {
        // A PR conversation comment contains an issue timestamp, not the PR's
        // canonical timestamp. Let the PR poll publish and enrich the change
        // instead of emitting a second event under an issue key.
        let queued = conn.execute("UPDATE trigger_subscriptions SET last_polled_at_ms=NULL
            WHERE status='active' AND action='list_pull_requests'
            AND lower(json_extract(fixed_args,'$.owner') || '/' || json_extract(fixed_args,'$.repo'))=lower(?1)
            AND EXISTS (SELECT 1 FROM connections c WHERE c.principal=trigger_subscriptions.principal
                AND c.connection_id=trigger_subscriptions.connection_id AND c.status='active'
                AND c.app_key IN ('github','github_actions'))", [&repo])?;
        *due_watches += queued;
        return Ok(Err(if queued > 0 {
            DropReason::PrCommentReread
        } else {
            DropReason::UnwatchedRepository
        }));
    }
    let (kind, item_kind, item_field, action, timestamp_field) = match event_shape(event) {
        Ok(shape) => shape,
        Err(reason) => return Ok(Err(reason)),
    };
    let Some(payload) = event.body.get(item_field).filter(|v| v.is_object()) else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    let dequeued = kind == crate::event_key::GITHUB_PR_DEQUEUED;
    let activity = if dequeued {
        received
    } else if let Some(activity) = payload
        .get(timestamp_field)
        .and_then(Value::as_str)
        .and_then(parse_to_millis)
    {
        activity
    } else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    let fields = json!({"repo_id":repo_id,"number":payload.get("number"),"updated_at":payload.get("updated_at"),
        "release_id":payload.get("id"),"job_id":payload.get("id"),"run_id":payload.get("id"),
        "run_attempt":payload.get("run_attempt"),"conclusion":payload.get("conclusion"),
        "delivery_id":event.delivery_id});
    let Ok(key) = crate::event_key::derive_event_key(kind, &fields) else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    let dequeue_body;
    let payload = if dequeued {
        if !payload["number"].is_u64()
            || !payload["head"]["ref"].is_string()
            || !payload["head"]["sha"].is_string()
            || !event.body["reason"].is_string()
            || !event.body["sender"]["login"].is_string()
        {
            return Ok(Err(DropReason::InvalidPayload));
        }
        dequeue_body = json!({"repo":repo.to_ascii_lowercase(),"number":payload["number"],
            "head_ref":payload["head"]["ref"],"head_sha":payload["head"]["sha"],
            "reason":event.body["reason"],"sender":event.body["sender"]["login"]});
        &dequeue_body
    } else {
        payload
    };
    // Pair within one principal and project; independent first-row lookups can
    // combine unrelated owners. Fanout creates visibility rows, not extra notices.
    let targets = if matches!(action, "list_issues" | "list_pull_requests") {
        paired_watches(conn, &repo, action)?
    } else {
        watch(conn, &repo, action)?.into_iter().collect()
    };
    if targets.is_empty() {
        return Ok(Err(DropReason::UnwatchedRepository));
    }
    let change = (kind == crate::event_key::GITHUB_ISSUE_CHANGED).then(|| {
        if payload.get("created_at") == payload.get("updated_at") {
            "opened"
        } else {
            "updated"
        }
    });
    let headers = relay_headers(&repo, targets[0].project.clone(), kind, payload);
    let identity = KeyedEventIdentity {
        event_key: &key,
        event_name: kind,
        repo_id,
        change,
        headers: &headers,
    };
    let actor = if matches!(kind, "github_issue_changed" | "github_pr_changed") {
        match event
            .body
            .pointer("/sender/login")
            .and_then(Value::as_str)
            .filter(|login| !login.is_empty() && !login.chars().any(char::is_whitespace))
        {
            // Store the login exactly as GitHub sends it. A GitHub App's account
            // login ends in "[bot]" (for example "magic-alfonso[bot]"), which is
            // also how the poller stores comment authors and how Prefrontal names
            // an agent's bot when it decides whether an event is the agent's own
            // echo. Stripping or adding the suffix would stop that match.
            Some(login) => ActorAttribution::Known(vec![login.to_owned()]),
            None => ActorAttribution::Unknown {
                code: ActorUnknownCode::UnrecognizedResponseShape,
            },
        }
    } else {
        ActorAttribution::NotEnriched
    };
    // Dequeues use delivery identity because queue transitions need not update
    // the PR timestamp. Changed-item webhooks share polling's identity, so a change seen both ways is one
    // stored event with one row in the publishing outbox. The copy that commits
    // first keeps its body and its actors. The event key is (repository id, item
    // number, updated_at to the second), so two different changes to one item in
    // the same second share a key: the second is treated as a duplicate and its
    // sender is lost. Polling behaves the same way, because a duplicate insert
    // never rewrites a stored row.
    let mut inserted_any = false;
    let mut delivery_id = Some(event.delivery_id.as_str());
    for target in &targets {
        let headers = EventHeaders {
            project: relay_project(conn, &repo, target, action)?,
            ..headers.clone()
        };
        let identity = KeyedEventIdentity {
            headers: &headers,
            ..identity
        };
        let inserted = insert_keyed_event_row(
            conn,
            &target.principal,
            &target.connection,
            &target.subscription,
            &KeyedPollEventInput {
                event: PollEventInput {
                    vendor_event_id: &event.delivery_id,
                    payload,
                    observed_at_ms: received,
                    item_kind: Some(item_kind),
                    activity_at_ms: Some(activity),
                    actor: &actor,
                },
                identity: Some(identity),
                delivery_id: delivery_id.take(),
                envelope_context: crate::event_envelope::EnvelopeContext {
                    source: crate::event_envelope::EnvelopeSource::Webhook(event.action.clone()),
                    comment: event.body.get("comment").cloned(),
                    ci_run: (item_kind == "ci_job")
                        .then(|| ci_runs.for_job(&repo, payload, received))
                        .flatten(),
                },
            },
        )?;
        inserted_any |= !matches!(inserted, TriggerEventInsertOutcome::Duplicate { .. });
    }
    inserted_any |= insert_review_notice(conn, event, &repo, repo_id, received, &targets)?;
    // Failed poll resolutions leave a cache row with a null id. Seed that row too,
    // so a polled copy can derive the same key; never overwrite a known identity.
    conn.execute("INSERT INTO github_repo_id_cache(repo,repo_id,last_attempt_at_ms,resolved_at_ms) VALUES (lower(?1),?2,?3,?3)
        ON CONFLICT(repo) DO UPDATE SET repo_id=excluded.repo_id,
            last_attempt_at_ms=excluded.last_attempt_at_ms,resolved_at_ms=excluded.resolved_at_ms
        WHERE github_repo_id_cache.repo_id IS NULL", (&repo, repo_id, received))?;
    Ok(if !inserted_any {
        Err(DropReason::AlreadyDelivered)
    } else {
        Ok(())
    })
}

fn insert_review_notice(
    conn: &Connection,
    event: &Event,
    repo: &str,
    repo_id: i64,
    received: i64,
    targets: &[Watch],
) -> rusqlite::Result<bool> {
    use crate::event_key::*;
    let (kind, item, id_field, timestamp) = match event.event.as_str() {
        "pull_request_review" if event.action.as_deref() == Some("submitted") => (
            GITHUB_PR_REVIEW_SUBMITTED,
            "review",
            "review_id",
            "submitted_at",
        ),
        "pull_request_review_comment" if event.action.as_deref() == Some("created") => (
            GITHUB_PR_REVIEW_COMMENT_CREATED,
            "comment",
            "comment_id",
            "created_at",
        ),
        _ => return Ok(false),
    };
    let fields = json!({"repo_id": repo_id, (id_field): event.body[item]["id"]});
    let Ok(key) = derive_event_key(kind, &fields) else {
        return Ok(false);
    };
    let payload = crate::review_body::notice(kind, &key, repo, &event.body);
    let activity = event.body[item][timestamp]
        .as_str()
        .and_then(parse_to_millis);
    let mut inserted = false;
    for target in targets {
        let headers = EventHeaders {
            repo: repo.to_owned(),
            project: target.project.clone(),
            pr: payload["pr"].as_u64().map(|pr| pr.to_string()),
            ..Default::default()
        };
        // The item-change row already owns the delivery id. The supplemental
        // notice deduplicates by its semantic key, including across deliveries.
        let outcome = insert_keyed_event_row(
            conn,
            &target.principal,
            &target.connection,
            &target.subscription,
            &KeyedPollEventInput {
                event: PollEventInput {
                    vendor_event_id: &key,
                    payload: &payload,
                    observed_at_ms: received,
                    item_kind: Some(item),
                    activity_at_ms: activity,
                    actor: &ActorAttribution::NotEnriched,
                },
                identity: Some(KeyedEventIdentity {
                    event_key: &key,
                    event_name: kind,
                    repo_id,
                    change: None,
                    headers: &headers,
                }),
                delivery_id: None,
                envelope_context: Default::default(),
            },
        )?;
        inserted |= !matches!(outcome, TriggerEventInsertOutcome::Duplicate { .. });
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    mod dequeue_tests {
        include!("relay_dequeue_tests.rs");
    }
    use super::*;

    #[test]
    fn marker_due_logging_is_limited_to_once_per_minute_and_counts_suppressed_marks() {
        let mut log = MarkerLog::default();
        let now = Instant::now();
        assert_eq!(log.record(0, now), None);
        assert_eq!(log.record(2, now), Some((1, 2)));
        assert_eq!(
            log.record(3, now + Duration::from_secs(59)),
            None,
            "marker logs must be limited to once per minute"
        );
        assert_eq!(log.record(4, now + Duration::from_secs(60)), Some((2, 7)));
        assert_eq!(log.record(1, now + Duration::from_secs(61)), None);
        assert_eq!(log.record(5, now + Duration::from_secs(120)), Some((2, 6)));
    }

    #[test]
    fn ci_and_release_inherit_only_their_principals_issue_project() {
        let store = ci_relay_store();
        for principal in ["direct", "other"] {
            store
                .insert_connection(principal, "issues", "github", "active", &json!({}))
                .unwrap();
        }
        store.inner.with_conn_fenced(|conn| {
            for (id,principal,action,project) in [
                ("0-other","other","list_issues",Some("other-project")),
                ("9-own","direct","list_issues",Some("own-project")),
                ("release","direct","get_latest_release",None),
            ] {
                conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args,project_id,project_source)
                    VALUES (?1,?2,'issues',?3,300,'scalar_diff','hash','active',0,'{\"owner\":\"cortexkit\",\"repo\":\"aft\"}',?4,?5)",
                    rusqlite::params![id,principal,action,project,project.map(|_| "hand")])?;
            }
            Ok(())
        }).unwrap();
        let run = ci_webhook(
            1,
            "completed",
            "workflow_run",
            capture("webhook_ci_run"),
            "2030-10-08T09:00:00.000Z",
        );
        store.commit_relay_event("github", "stream", &run).unwrap();
        let release: Event = serde_json::from_value(json!({"seq":2,"delivery_id":"release-own","event":"release","action":"published","installation_id":42,
            "received_at":"2030-10-08T09:00:00.000Z","stub":null,"body":{"repository":{"id":183627762,"full_name":"cortexkit/aft"},"release":{"id":7,"published_at":"2030-10-08T09:00:00Z"}}})).unwrap();
        // The release must carry the same numeric repository identity as the run.
        let mut release = release;
        release.body["repository"]["id"] = run.body["repository"]["id"].clone();
        store
            .commit_relay_event("github", "stream", &release)
            .unwrap();
        let events = store.drain_event_outbox(10).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.headers.project.as_deref() == Some("own-project")),
            "CI/release routing inherits only the target principal's issue annotation"
        );
    }

    #[tokio::test]
    async fn paired_relay_fanout_keeps_one_canonical_notice_and_wake() {
        let store = ci_relay_store();
        for principal in ["alpha", "beta", "lonely"] {
            store
                .insert_connection(principal, "github", "github", "active", &json!({}))
                .unwrap();
        }
        store.inner.with_conn_fenced(|conn| {
            for (id,principal,action,project) in [
                ("a-issue","alpha","list_issues","a"),
                ("a-issue-extra","alpha","list_issues","a"),
                ("z-pr","alpha","list_pull_requests","a"),
                ("z-issue","beta","list_issues","b"),
                ("a-pr","beta","list_pull_requests","b"),
                ("unpaired","lonely","list_issues","a"),
            ] {
                conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms,fixed_args,project_id,project_source)
                    VALUES (?1,?2,'github',?3,300,'ordered_timestamp','hash','active',0,'{\"owner\":\"org\",\"repo\":\"repo\"}',?4,'hand')",
                    (id,principal,action,project))?;
            }
            Ok(())
        }).unwrap();
        let mut event: Event = serde_json::from_value(json!({
            "seq":1,"delivery_id":"issue-1","event":"issues","action":"edited","installation_id":42,
            "received_at":"2030-10-08T09:00:00.000Z","stub":null,
            "body":{"repository":{"id":101,"full_name":"org/repo"},"sender":{"login":"octocat"},
                "issue":{"number":7,"created_at":"2030-10-07T09:00:00Z","updated_at":"2030-10-08T09:00:00Z"}}
        })).unwrap();
        store
            .commit_relay_event("github", "stream", &event)
            .unwrap();
        assert_eq!(
            stored_count(&store, "trigger_events"),
            3,
            "every valid target gets visibility, never a mixed-principal pair"
        );
        assert_eq!(
            stored_count(&store, "event_outbox"),
            1,
            "fanout must not duplicate the notice that wakes an agent"
        );
        let canonical = store.drain_event_outbox(10).unwrap();
        assert_eq!(canonical.len(), 1);
        tokio::time::timeout(std::time::Duration::from_secs(1), store.outbox_committed())
            .await
            .unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            store.outbox_committed()
        )
        .await
        .is_err());
        event.seq = 2;
        event.delivery_id = "issue-replay".into();
        store
            .commit_relay_event("github", "stream", &event)
            .unwrap();
        assert_eq!(
            store.drain_event_outbox(10).unwrap(),
            canonical,
            "fanout/replay must not rewrite first-writer bytes"
        );
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            store.outbox_committed()
        )
        .await
        .is_err());
    }

    #[test]
    fn unwatched_relay_repositories_do_not_change_cached_identity() {
        let store = ci_relay_store();
        store
            .record_repo_id_resolution("org/away", Some(10), 1)
            .unwrap();
        let event: Event = serde_json::from_value(json!({
            "seq":1,"delivery_id":"away","event":"issues","action":"edited","installation_id":42,
            "received_at":"2030-10-08T09:00:00.000Z","stub":null,
            "body":{"repository":{"id":20,"full_name":"org/away"}}
        }))
        .unwrap();
        store
            .commit_relay_event("github", "stream", &event)
            .unwrap();
        let health = store.event_outbox_health().unwrap();
        assert_eq!(
            health.relay_drops.get("relay_drop_unwatched_repository"),
            Some(&1)
        );
        assert_eq!(health.repository_identity_changed, 0);
        assert_eq!(
            store.repo_id_cache("org/away").unwrap().unwrap().repo_id,
            Some(10)
        );
    }

    #[test]
    fn failed_relay_commit_does_not_seed_run_cache() {
        let store = ci_relay_store();
        let event = ci_webhook(
            1,
            "completed",
            "workflow_run",
            capture("webhook_ci_run"),
            "2030-10-08T09:00:00.000Z",
        );
        store.inner.with_conn_fenced(|conn| conn.execute_batch(
            "CREATE TRIGGER reject_cursor BEFORE UPDATE ON relay_cursor BEGIN SELECT RAISE(ABORT,'no commit'); END;")).unwrap();
        assert!(store
            .commit_relay_event("github", "stream", &event)
            .is_err());
        assert_eq!(
            store.ci_runs.len(),
            0,
            "cache must reflect successful commits only"
        );
        assert_eq!(
            store.relay_cursor("github").unwrap().unwrap().committed_seq,
            0
        );
        store
            .inner
            .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER reject_cursor"))
            .unwrap();
        store
            .commit_relay_event("github", "stream", &event)
            .unwrap();
        assert_eq!(store.ci_runs.len(), 1);
    }

    fn hello(stream: &str, next_seq: u64, oldest_seq: u64, last_acked_seq: u64) -> Hello {
        Hello {
            v: 1,
            source: "github".into(),
            stream_id: stream.into(),
            next_seq,
            oldest_seq,
            last_acked_seq,
        }
    }

    /// A relay whose sequence went backwards on the same stream restarts the
    /// cursor from what it still holds, instead of keeping a cursor ahead of
    /// every event it will send and discarding them all as already committed.
    #[test]
    fn a_relay_sequence_that_goes_backwards_resets_the_cursor() {
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_id("relay-rewind"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        store
            .relay_hello("github", &hello("stream", 11, 1, 0))
            .unwrap();
        store
            .inner
            .with_conn_fenced(|conn| conn.execute("UPDATE relay_cursor SET committed_seq = 10", []))
            .unwrap();
        // Control: the same stream continuing forward keeps the cursor.
        store
            .relay_hello("github", &hello("stream", 11, 1, 10))
            .unwrap();
        assert_eq!(
            store.relay_cursor("github").unwrap().unwrap().committed_seq,
            10
        );

        store
            .relay_hello("github", &hello("stream", 5, 3, 0))
            .unwrap();
        assert_eq!(
            store.relay_cursor("github").unwrap().unwrap(),
            Cursor {
                stream_id: "stream".into(),
                committed_seq: 2
            },
            "the cursor restarts below the oldest event the relay still holds"
        );
    }
    /// A repository watched only for releases receives its release webhook:
    /// only issue and pull request events need the issue and pull request
    /// watch pair.
    #[tokio::test]
    async fn a_release_only_watch_receives_its_release_webhook() {
        // Run SQLite on a blocking thread and check the saved wake only after
        // commit completes. File-backed commits have taken about three seconds
        // in parallel suites; ten seconds allows several store operations even
        // at that latency, without charging their time to notification delivery.
        let commit_wait = std::time::Duration::from_secs(10);
        let wake_wait = std::time::Duration::from_secs(3);
        let inserted = tokio::task::spawn_blocking(|| {
            let store = PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: new_id("relay-release-only"),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: ":memory:".into(),
                },
            })
            .unwrap();
            store
                .insert_connection("direct", "conn-1", "github", "active", &json!({}))
                .unwrap();
            store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute_batch(
                    "INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id,
                        action, cadence_s, cursor_kind, schema_hash, status, created_at_ms, fixed_args)
                     VALUES ('release-watch', 'direct', 'conn-1', 'get_latest_release', 300,
                        'scalar_diff', 'hash-release', 'active', 1,
                        '{\"owner\":\"org\",\"repo\":\"repo\"}')",
                )
            })
            .unwrap();
            store
                .relay_hello("github", &hello("stream", 2, 1, 0))
                .unwrap();
            let time = "2030-10-08T09:00:00.000Z";
            let event: Event = serde_json::from_value(json!({
                "seq": 1, "delivery_id": "release-1", "event": "release", "action": "published",
                "installation_id": 42, "received_at": time, "stub": null,
                "body": {"repository": {"id": 101, "full_name": "org/repo"},
                         "release": {"id": 7, "published_at": time, "updated_at": time}}
            }))
            .unwrap();
            store
                .commit_relay_event("github", "stream", &event)
                .unwrap();
            let stored: Vec<String> = store
                .inner
                .with_conn(|conn| {
                    conn.prepare("SELECT subscription_id FROM trigger_events")?
                        .query_map([], |row| row.get(0))?
                        .collect()
                })
                .unwrap();
            assert_eq!(
                stored,
                vec!["release-watch".to_string()],
                "a release-only watch must receive its release webhook"
            );
            (store, event)
        });
        let (store, event) = tokio::time::timeout(commit_wait, inserted)
            .await
            .expect("relay insert must finish within the durable-work budget")
            .unwrap();
        tokio::time::timeout(wake_wait, store.outbox_committed())
            .await
            .expect("committed relay outbox row must wake the publisher");
        let store = tokio::time::timeout(
            commit_wait,
            tokio::task::spawn_blocking(move || {
                store
                    .commit_relay_event("github", "stream", &event)
                    .unwrap();
                store
            }),
        )
        .await
        .expect("relay replay must finish within the durable-work budget")
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                store.outbox_committed()
            )
            .await
            .is_err(),
            "relay replay must not wake an idle drain"
        );
    }

    fn capture(name: &str) -> Value {
        serde_json::from_str(match name {
            "webhook_ci_run" => {
                include_str!("../../tests/fixtures/event-envelope-v2/webhook_ci_run.json")
            }
            "webhook_ci_job" => {
                include_str!("../../tests/fixtures/event-envelope-v2/webhook_ci_job.json")
            }
            "poll_ci_run" => {
                include_str!("../../tests/fixtures/event-envelope-v2/poll_ci_run.json")
            }
            "poll_ci_job" => {
                include_str!("../../tests/fixtures/event-envelope-v2/poll_ci_job.json")
            }
            _ => panic!("unknown capture {name}"),
        })
        .unwrap()
    }

    /// A relay delivery wrapping a captured run or job object, with the
    /// repository wrapper GitHub sends alongside it.
    fn ci_webhook(seq: u64, action: &str, field: &str, item: Value, received_at: &str) -> Event {
        let repo = if field == "workflow_run" {
            item["repository"]["full_name"].clone()
        } else {
            json!("cortexkit/aft")
        };
        let mut body = json!({"repository":{"id":101,"full_name":repo},
            "sender":{"login":"octo-lantern","type":"User"}});
        body[field] = item;
        Event {
            seq,
            delivery_id: format!("ci-{seq}"),
            event: field.into(),
            action: Some(action.into()),
            installation_id: 42,
            received_at: received_at.into(),
            stub: None,
            body,
        }
    }

    fn ci_relay_store() -> PlexusStore {
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_id("relay-ci-run-cache"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        store
            .insert_connection("direct", "conn-1", "github_actions", "active", &json!({}))
            .unwrap();
        store
            .inner
            .with_conn_fenced(|conn| {
                for repo in ["aft", "magic-context"] {
                    conn.execute(
                        "INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id,
                            action, cadence_s, cursor_kind, schema_hash, status, created_at_ms, fixed_args)
                         VALUES (?1, 'direct', 'conn-1', 'list_workflow_runs', 300, 'ci_runs',
                            'hash', 'active', 1, ?2)",
                        (
                            format!("ci-{repo}"),
                            json!({"owner":"cortexkit","repo":repo}).to_string(),
                        ),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        store
            .relay_hello("github", &hello("stream", 1, 1, 0))
            .unwrap();
        store
    }

    fn stored_count(store: &PlexusStore, table: &str) -> i64 {
        store
            .inner
            .with_read(|conn| {
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
            })
            .unwrap()
    }

    fn envelope_for(store: &PlexusStore, delivery_id: &str) -> Value {
        let stored: String = store
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT o.envelope_v2 FROM event_outbox o
                     JOIN trigger_events e ON e.event_id = o.event_id WHERE e.delivery_id = ?1",
                    [delivery_id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        serde_json::from_str(&stored).unwrap()
    }

    fn run_fields(envelope: &Value) -> Value {
        json!([
            envelope["actor"],
            envelope["triggering_actor"],
            envelope["event"],
            envelope["head_repo_is_fork"]
        ])
    }

    #[test]
    fn ci_run_webhook_carries_workflow_identity_or_explicit_nulls() {
        for has_identity in [true, false] {
            let store = ci_relay_store();
            let mut run = capture("webhook_ci_run");
            if has_identity {
                run["workflow_id"] = json!(123456789);
                run["path"] = json!(".github/workflows/ci.yml");
            } else {
                for field in ["workflow_id", "path"] {
                    run.as_object_mut().unwrap().remove(field);
                }
            }
            store
                .commit_relay_event(
                    "github",
                    "stream",
                    &ci_webhook(
                        1,
                        "completed",
                        "workflow_run",
                        run,
                        "2030-10-08T09:00:00.000Z",
                    ),
                )
                .unwrap();
            let envelope = envelope_for(&store, "ci-1");
            assert_eq!(envelope["kind"], "ci_run");
            let (workflow_id, workflow_path) = if has_identity {
                (json!(123456789), json!(".github/workflows/ci.yml"))
            } else {
                (Value::Null, Value::Null)
            };
            assert_eq!(envelope.get("workflow_id"), Some(&workflow_id));
            assert_eq!(envelope.get("workflow_path"), Some(&workflow_path));
        }
    }

    /// `workflow_run` webhooks that are not completed publish nothing, but the
    /// relay remembers their run values. A later job webhook for the same run
    /// attempt carries them in its v2 envelope; a job for an unseen run gets
    /// nulls. Covers a push run, a re-run by someone other than the pusher,
    /// and a pull request from a fork.
    #[test]
    fn a_job_webhook_takes_run_values_from_earlier_run_webhooks_that_publish_nothing() {
        let store = ci_relay_store();
        let time = "2030-10-08T09:00:00.000Z";
        let mut push_run = capture("webhook_ci_run");
        push_run["id"] = json!(38098639025_i64);
        push_run["run_attempt"] = json!(1);
        push_run["status"] = json!("queued");
        push_run["conclusion"] = Value::Null;
        let mut rerun = push_run.clone();
        rerun["run_attempt"] = json!(2);
        rerun["triggering_actor"]["login"] = json!("ualtinok");
        let mut in_progress = push_run.clone();
        in_progress["status"] = json!("in_progress");
        // The fork pull-request run that the captured polled job belongs to.
        let mut fork_run = capture("poll_ci_run");
        fork_run["id"] = json!(38083735257_i64);
        fork_run["status"] = json!("queued");
        fork_run["conclusion"] = Value::Null;
        let runs = [
            ("requested", push_run),
            ("in_progress", in_progress),
            ("requested", rerun),
            ("requested", fork_run),
        ];
        for (seq, (action, run)) in (1..).zip(runs) {
            store
                .commit_relay_event(
                    "github",
                    "stream",
                    &ci_webhook(seq, action, "workflow_run", run, time),
                )
                .unwrap();
        }
        assert_eq!(
            (
                stored_count(&store, "trigger_events"),
                stored_count(&store, "event_outbox")
            ),
            (0, 0),
            "run webhooks that are not completed must publish nothing"
        );
        assert_eq!(store.ci_runs.len(), 3, "one entry per run attempt");

        let job = capture("webhook_ci_job");
        let mut rerun_job = job.clone();
        rerun_job["id"] = json!(114349743681_i64);
        rerun_job["run_attempt"] = json!(2);
        let mut fork_job = capture("poll_ci_job");
        fork_job.as_object_mut().unwrap().remove("run");
        let mut uncached_job = job.clone();
        uncached_job["id"] = json!(114349743682_i64);
        uncached_job["run_id"] = json!(38098639026_i64);
        let mut fork_job_event = ci_webhook(8, "completed", "workflow_job", fork_job, time);
        fork_job_event.body["repository"]["full_name"] = json!("CortexKit/Magic-Context");
        for event in [
            ci_webhook(5, "completed", "workflow_job", job, time),
            ci_webhook(6, "completed", "workflow_job", rerun_job, time),
            ci_webhook(7, "completed", "workflow_job", uncached_job, time),
            fork_job_event,
        ] {
            store
                .commit_relay_event("github", "stream", &event)
                .unwrap();
        }
        const CACHED: &str = "a job webhook must carry its cached run's values";
        assert_eq!(
            run_fields(&envelope_for(&store, "ci-5")),
            json!(["octo-lantern", "octo-lantern", "push", false]),
            "{CACHED}"
        );
        assert_eq!(
            run_fields(&envelope_for(&store, "ci-6")),
            json!(["octo-lantern", "ualtinok", "push", false]),
            "{CACHED}: a re-run keeps the pusher as actor"
        );
        assert_eq!(
            run_fields(&envelope_for(&store, "ci-8")),
            json!([
                "octo-checks[bot]",
                "octo-checks[bot]",
                "pull_request_target",
                true
            ]),
            "{CACHED}: the repository name matches whatever its case"
        );
        let uncached = envelope_for(&store, "ci-7");
        assert_eq!(
            run_fields(&uncached),
            json!([null, null, null, null]),
            "a job whose run was not seen carries nulls"
        );
        for field in ["actor", "triggering_actor", "event", "head_repo_is_fork"] {
            assert!(uncached.get(field).is_some(), "{field} must be present");
        }
    }

    #[test]
    fn the_run_cache_is_bounded_by_count_and_by_a_day_of_receipt_age() {
        let run = |id: i64| Event {
            seq: 1,
            delivery_id: "run".into(),
            event: "workflow_run".into(),
            action: Some("requested".into()),
            installation_id: 42,
            received_at: "2030-10-08T09:00:00.000Z".into(),
            stub: None,
            body: json!({"repository":{"id":101,"full_name":"CortexKit/AFT"},
                "workflow_run":{"id":id,"run_attempt":1,"actor":{"login":"octo-lantern"}}}),
        };
        let job = |id: i64| json!({"run_id":id,"run_attempt":1});
        let start = 1_000_000_000;
        let cache = CiRunCache::default();
        for id in 1..=CI_RUN_CACHE_CAPACITY as i64 + 1 {
            cache.remember(&run(id), start);
        }
        assert_eq!(cache.len(), CI_RUN_CACHE_CAPACITY);
        assert_eq!(
            cache.for_job("cortexkit/aft", &job(1), start),
            None,
            "the oldest entry is evicted first"
        );
        assert_eq!(
            cache
                .for_job("cortexkit/aft", &job(2), start)
                .and_then(|run| run.actor),
            Some("octo-lantern".into()),
            "the repository key ignores ASCII case"
        );

        let cache = CiRunCache::default();
        cache.remember(&run(1), start);
        let last_valid = start + CI_RUN_CACHE_MAX_AGE_MS;
        assert!(cache
            .for_job("cortexkit/aft", &job(1), last_valid)
            .is_some());
        assert!(cache
            .for_job("cortexkit/aft", &job(1), last_valid + 1)
            .is_none());
        cache.remember(&run(2), last_valid + 1);
        assert_eq!(cache.len(), 1, "storing prunes entries older than a day");
    }

    #[test]
    fn migration_46_forward_rollback_and_reforward_preserve_cursor_and_prior_writes() {
        let scratch = crate::test_scratch::Scratch::database("relay-migration");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "relay-migration".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = open_sqlite(&descriptor).unwrap();
        let prior = &MIGRATIONS[..23];
        assert_eq!(inner.migrate("plexus", prior).unwrap().recorded, 45);
        const INSERT: &str =
            "INSERT INTO audit_journal(ts,principal,actor,acting_principal,decision,reason_code)
            VALUES (1,'direct','direct','direct','allow','prior_binary')";
        inner
            .with_conn_fenced(|conn| conn.execute_batch(INSERT))
            .unwrap();
        let forward = inner.migrate("plexus", &MIGRATIONS[..24]).unwrap();
        assert_eq!((forward.applied, forward.recorded), (1, 46));
        inner
            .with_conn_fenced(|conn| {
                conn.execute_batch("INSERT INTO relay_cursor VALUES ('github','stream',3)")
            })
            .unwrap();
        let rollback = inner.migrate("plexus", prior).unwrap();
        assert!(
            rollback.store_ahead(),
            "prior binary must serve the ahead store"
        );
        assert_eq!(rollback.applied, 0);
        inner
            .with_conn_fenced(|conn| conn.execute_batch(INSERT))
            .unwrap();
        assert_eq!(
            inner.migrate("plexus", &MIGRATIONS[..24]).unwrap().applied,
            0
        );
        inner
            .with_conn(|conn| {
                assert_eq!(
                    cursor(conn, "github")?.unwrap(),
                    Cursor {
                        stream_id: "stream".into(),
                        committed_seq: 3
                    }
                );
                assert_eq!(
                    conn.query_row(
                        "SELECT count(*) FROM audit_journal WHERE reason_code='prior_binary'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )?,
                    2
                );
                Ok(())
            })
            .unwrap();
    }
}
