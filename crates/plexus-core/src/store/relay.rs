//! Durable webhook cursors and atomic admission to the polling event outbox.
use super::*;
use crate::actor_attribution::ActorUnknownCode;
use crate::poller::iso8601::parse_to_millis;
use serde::Deserialize;
use serde_json::json;

pub const MAX_SEQ: u64 = 9_007_199_254_740_991;

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

#[derive(Debug, PartialEq, Eq)]
pub enum DropReason {
    UnwatchedRepository,
    RepositoryIdentityChanged,
    InvalidPayload,
    UnsupportedEvent,
    AlreadyDelivered,
    PrCommentReread,
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
) -> rusqlite::Result<()> {
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
            return Ok(());
        }
    }
    conn.execute("UPDATE trigger_subscriptions SET last_polled_at_ms=NULL
        WHERE status='active' AND action IN ('list_issues','list_pull_requests','get_latest_release','list_releases','list_workflow_runs')
        AND (?1 IS NULL OR lower(json_extract(fixed_args,'$.owner') || '/' || json_extract(fixed_args,'$.repo'))=lower(?1))
        AND EXISTS (SELECT 1 FROM connections c WHERE c.principal=trigger_subscriptions.principal
            AND c.connection_id=trigger_subscriptions.connection_id AND c.app_key IN ('github','github_actions'))",
        [repository.map(|(name, _)| name)])?;
    Ok(())
}

fn reread(conn: &rusqlite::Connection, event: &Event) -> rusqlite::Result<()> {
    let repo = repository(&event.body);
    diag!(info relay: "relay reread queued installation={}", event.installation_id);
    reconcile(
        conn,
        repo.as_ref().map(|(name, id)| (name.as_str(), Some(*id))),
    )
}

impl PlexusStore {
    #[cfg(any(test, feature = "test-support"))]
    pub fn relay_cursor(&self, source: &str) -> Result<Option<Cursor>, StoreError> {
        self.inner.with_read(|conn| cursor(conn, source))
    }

    pub fn relay_hello(&self, source: &str, hello: &Hello) -> Result<(), StoreError> {
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
        self.inner.with_conn_fenced(|conn| {
            let old = cursor(conn, source)?;
            let changed = old.as_ref().is_some_and(|old| old.stream_id != hello.stream_id);
            let mut committed = old.as_ref().filter(|_| !changed).map_or(0, |c| c.committed_seq);
            if changed {
                diag!(warn relay: "relay {source} stream changed; full reconcile queued");
                reconcile(conn, None)?;
            }
            let floor = hello.oldest_seq - 1;
            // On the same stream the relay will next send `next_seq`, so a
            // cursor at or past it means the relay's sequence went backwards
            // (its state was lost or restored). Every event it now sends would
            // be discarded as already committed, so restart from what it still
            // holds and reconcile everything, as for a changed stream.
            if !changed && committed >= hello.next_seq {
                diag!(warn relay: "relay {source} sequence went back from committed {committed} to next {}; full reconcile queued", hello.next_seq);
                reconcile(conn, None)?;
                committed = floor.max(hello.last_acked_seq.min(hello.next_seq - 1));
            }
            if committed < floor || committed < hello.last_acked_seq {
                diag!(warn relay: "relay {source} gap {}..{}; full reconcile queued", committed + 1, floor.max(hello.last_acked_seq));
                reconcile(conn, None)?;
                committed = floor.max(hello.last_acked_seq);
            }
            conn.execute("INSERT INTO relay_cursor(source,stream_id,committed_seq) VALUES (?1,?2,?3)
                ON CONFLICT(source) DO UPDATE SET stream_id=excluded.stream_id,committed_seq=excluded.committed_seq",
                (source, &hello.stream_id, committed))?;
            Ok(())
        })
    }

    /// The cursor, drop ledger, reconcile queue and event/outbox insert commit together.
    pub fn commit_relay_event(
        &self,
        source: &str,
        stream: &str,
        event: &Event,
    ) -> Result<(), StoreError> {
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
        self.inner.with_conn_fenced(|conn| {
            let current = cursor(conn, source)?.ok_or_else(protocol_error)?;
            if current.stream_id != stream { return Err(protocol_error()); }
            if event.seq <= current.committed_seq { return Ok(()); }
            if event.seq != current.committed_seq + 1 { return Err(protocol_error()); }
            match event.stub {
                Some(Stub::Oversized) => reread(conn, event)?,
                Some(Stub::RateLimited) => reread(conn, event)?,
                Some(Stub::Overflow) => {
                    diag!(warn relay: "relay overflow gap at seq={} installation={}; full reconcile queued", event.seq, event.installation_id);
                    // Relay installations are not agent bot Apps; without an authoritative mapping, reconcile all watches.
                    reconcile(conn, None)?;
                }
                None if event.event == "cortexkit_installation_bound" => {
                    diag!(info relay: "relay installation bound reconcile queued installation={}", event.installation_id);
                    match event.body.get("repositories") {
                        Some(Value::Null) => reconcile(conn, None)?,
                        Some(Value::Array(repos)) => for repo in repos {
                            if let Some((name, id)) = repository_item(repo) { reconcile(conn, Some((&name, Some(id))))?; }
                        },
                        _ => return Err(protocol_error()),
                    }
                }
                None => {
                    if let Err(reason) = admit(conn, event, received)? {
                        conn.execute("INSERT INTO event_outbox_counters(name,value) VALUES (?1,1)
                            ON CONFLICT(name) DO UPDATE SET value=value+1", [reason.counter()])?;
                        diag!(info relay: "relay event dropped reason={:?} seq={} event={} action={:?}", reason, event.seq, event.event, event.action);
                    } else {
                        inserted = true;
                    }
                }
            }
            conn.execute("UPDATE relay_cursor SET committed_seq=?1 WHERE source=?2 AND stream_id=?3", (event.seq, source, stream))?;
            Ok(())
        })?;
        if inserted {
            self.outbox_ready.notify_one();
        }
        Ok(())
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

fn admit(
    conn: &rusqlite::Connection,
    event: &Event,
    received: i64,
) -> rusqlite::Result<Result<(), DropReason>> {
    let Some((repo, repo_id)) = repository(&event.body) else {
        return Ok(Err(DropReason::InvalidPayload));
    };
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
        return Ok(Err(if queued > 0 {
            DropReason::PrCommentReread
        } else {
            DropReason::UnwatchedRepository
        }));
    }
    // An issue or pull request event belongs to the repository's issue and
    // pull request watch pair. A release or CI event needs only the watch for
    // its own action, so a repository watched for releases or CI alone still
    // receives its webhooks.
    let pair = if matches!(
        event.event.as_str(),
        "release" | "workflow_job" | "workflow_run"
    ) {
        None
    } else {
        let (Some(issue), Some(pr)) = (
            watch(conn, &repo, "list_issues")?,
            watch(conn, &repo, "list_pull_requests")?,
        ) else {
            return Ok(Err(DropReason::UnwatchedRepository));
        };
        if issue.project != pr.project {
            return Ok(Err(DropReason::UnwatchedRepository));
        }
        Some((issue, pr))
    };
    let (kind, item_kind, item_field, action, timestamp_field) = match event.event.as_str() {
        "issues" | "issue_comment" => (
            crate::event_key::GITHUB_ISSUE_CHANGED,
            "issue",
            "issue",
            "list_issues",
            "updated_at",
        ),
        "pull_request" | "pull_request_review" | "pull_request_review_comment" => (
            crate::event_key::GITHUB_PR_CHANGED,
            "pull_request",
            "pull_request",
            "list_pull_requests",
            "updated_at",
        ),
        "release" if event.action.as_deref() == Some("published") => (
            crate::event_key::GITHUB_RELEASE_PUBLISHED,
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
                    crate::event_key::GITHUB_CI_JOB_FAILED
                } else {
                    crate::event_key::GITHUB_CI_JOB_COMPLETED
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
                crate::event_key::GITHUB_CI_RUN_COMPLETED,
                "ci_run",
                "workflow_run",
                "list_workflow_runs",
                "updated_at",
            )
        }
        _ => return Ok(Err(DropReason::UnsupportedEvent)),
    };
    let Some(payload) = event.body.get(item_field).filter(|v| v.is_object()) else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    let Some(activity) = payload
        .get(timestamp_field)
        .and_then(Value::as_str)
        .and_then(parse_to_millis)
    else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    let fields = json!({"repo_id":repo_id,"number":payload.get("number"),"updated_at":payload.get("updated_at"),
        "release_id":payload.get("id"),"job_id":payload.get("id"),"run_id":payload.get("id"),
        "run_attempt":payload.get("run_attempt"),"conclusion":payload.get("conclusion")});
    let Ok(key) = crate::event_key::derive_event_key(kind, &fields) else {
        return Ok(Err(DropReason::InvalidPayload));
    };
    // The repository's project comes from its issue watch when it has one,
    // which is where the operator or repository ownership stamps it; a
    // repository watched for releases or CI alone takes the project of the
    // watch the event lands on.
    let issue_project = match &pair {
        Some((issue, _)) => Some(issue.project.clone()),
        None => watch(conn, &repo, "list_issues")?.map(|issue| issue.project),
    };
    let target = match (action, pair) {
        ("list_issues", Some((issue, _))) => issue,
        ("list_pull_requests", Some((_, pr))) => pr,
        _ => match watch(conn, &repo, action)? {
            Some(target) => target,
            None => return Ok(Err(DropReason::UnwatchedRepository)),
        },
    };
    let project = issue_project.unwrap_or_else(|| target.project.clone());
    let change = (kind == crate::event_key::GITHUB_ISSUE_CHANGED).then(|| {
        if payload.get("created_at") == payload.get("updated_at") {
            "opened"
        } else {
            "updated"
        }
    });
    let prs = payload.get("pull_requests").and_then(Value::as_array);
    let headers = EventHeaders {
        repo: repo.clone(),
        project,
        pr: if kind == crate::event_key::GITHUB_PR_CHANGED {
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
    };
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
    // Webhooks use the same insert as polling, so a change seen both ways is one
    // stored event with one row in the publishing outbox. The copy that commits
    // first keeps its body and its actors. The event key is (repository id, item
    // number, updated_at to the second), so two different changes to one item in
    // the same second share a key: the second is treated as a duplicate and its
    // sender is lost. Polling behaves the same way, because a duplicate insert
    // never rewrites a stored row.
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
            delivery_id: Some(&event.delivery_id),
            envelope_context: crate::event_envelope::EnvelopeContext {
                source: crate::event_envelope::EnvelopeSource::Webhook(event.action.clone()),
                comment: event.body.get("comment").cloned(),
            },
        },
    )?;
    // Failed poll resolutions leave a cache row with a null id. Seed that row too,
    // so a polled copy can derive the same key; never overwrite a known identity.
    conn.execute("INSERT INTO github_repo_id_cache(repo,repo_id,last_attempt_at_ms,resolved_at_ms) VALUES (lower(?1),?2,?3,?3)
        ON CONFLICT(repo) DO UPDATE SET repo_id=excluded.repo_id,
            last_attempt_at_ms=excluded.last_attempt_at_ms,resolved_at_ms=excluded.resolved_at_ms
        WHERE github_repo_id_cache.repo_id IS NULL", (&repo, repo_id, received))?;
    Ok(
        if matches!(inserted, TriggerEventInsertOutcome::Duplicate { .. }) {
            Err(DropReason::AlreadyDelivered)
        } else {
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
