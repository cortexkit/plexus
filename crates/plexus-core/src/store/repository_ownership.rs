use super::*;
use crate::repository_ownership::RepositoryWatch;
use std::collections::BTreeMap;

use super::event_outbox::{effective_ci_ceiling, CI_CYCLE_REQUESTS};

// Operational and safety suspensions still own their watch; recreating them would
// bypass the pause and discard its cursor. Only stale repository identity or
// stored schema hashes that disagree with the approved catalog need a fresh watch.
// `schema_changed` awaits catalog review; `repin_reviewed_action` updates its
// schema hash and reactivates the existing subscription after approval.
// Keep unknown or absent reasons conservatively, and never count retired rows.
pub(super) const WATCH_EXISTS_SQL: &str = "(s.status = 'active' OR (s.status = 'suspended'
    AND COALESCE(s.suspended_reason, '') NOT IN ('repository_identity_changed', 'catalog_schema_mismatch')))";

impl PlexusStore {
    /// Resolve a repository's project from watch rows populated by entorhinal's
    /// project registry. Operator-set project labels are annotations, not proof
    /// that a workspace owns the repository, so they cannot grant access.
    /// Retired rows preserve obsolete ownership; suspended rows still describe
    /// the repository's current watches and must continue to participate.
    pub fn entorhinal_repository_project(
        &self,
        repository: &str,
    ) -> Result<Option<String>, StoreError> {
        let Ok((owner, repo)) = crate::github::resolver::split_repository(repository) else {
            return Ok(None);
        };
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT DISTINCT s.project_id
                FROM trigger_subscriptions s JOIN connections c
                ON c.principal=s.principal AND c.connection_id=s.connection_id
                WHERE c.app_key IN ('github','github_actions','github_rest')
                AND s.status <> 'retired'
                AND s.project_source = 'entorhinal' AND s.project_id IS NOT NULL
                AND lower(json_extract(s.fixed_args,'$.owner'))=lower(?1)
                AND lower(json_extract(s.fixed_args,'$.repo'))=lower(?2)",
            )?;
            let projects = statement
                .query_map([owner, repo], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if projects.len() == 1 {
                projects.into_iter().next()
            } else {
                None
            })
        })
    }

    /// Retain the history of obsolete automatic watches without leaving them
    /// resumable. Wait for a complete active replacement trio, including CI;
    /// operational pauses and manually managed release watches are not replaced.
    pub(crate) fn retire_replaced_repository_watches(&self) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            atomic(conn, || {
                let mut statement = conn.prepare(
                    "WITH eligible AS (
                        SELECT s.*, lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo')) AS repo_name
                        FROM trigger_subscriptions s JOIN connections c
                        ON c.principal=s.principal AND c.connection_id=s.connection_id
                        WHERE s.principal='direct' AND c.status='active' AND (
                            (s.connection_id='conn-github' AND c.app_key='github' AND s.action='list_issues') OR
                            (s.connection_id='conn-github-prs' AND c.app_key='github' AND s.action='list_pull_requests') OR
                            (s.connection_id='conn-github-actions' AND c.app_key='github_actions' AND s.action='list_workflow_runs'))
                    ), replaced AS (
                        SELECT repo_name FROM eligible WHERE status='active'
                        GROUP BY repo_name HAVING count(DISTINCT action)=3
                    )
                    SELECT subscription_id FROM eligible WHERE status='suspended'
                    AND suspended_reason='repository_identity_changed'
                    AND repo_name IN (SELECT repo_name FROM replaced)",
                )?;
                let ids = statement.query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for id in &ids {
                    conn.execute("UPDATE trigger_subscriptions SET status='retired', generation=generation+1
                        WHERE principal='direct' AND subscription_id=?1", [id])?;
                    ownership_audit(conn, "direct", id, "retire",
                        &serde_json::json!({"reason":"repository_identity_changed","replacement":"active_trio"}).to_string())?;
                }
                Ok(ids.len())
            })
        })
    }

    pub(crate) fn repository_is_bot_bound(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<bool, StoreError> {
        self.inner
            .with_read(|conn| bot_bound_on_conn(conn, owner, repo))
    }

    pub(crate) fn repository_watches(&self) -> Result<Vec<RepositoryWatch>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT s.principal, s.subscription_id, s.fixed_args, s.project_id, s.project_source, s.action
                 FROM trigger_subscriptions s JOIN connections c
                 ON c.principal = s.principal AND c.connection_id = s.connection_id
                 WHERE {WATCH_EXISTS_SQL} AND c.app_key = 'github'
                 AND s.action IN ('list_issues','list_pull_requests','get_latest_release','list_releases')
                 ORDER BY s.subscription_id"))?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, String>(5)?))
            })?.collect::<Result<Vec<_>, _>>()?;
            Ok(rows.into_iter().filter_map(|(principal, id, args, project_id, source, action)| {
                let args: Value = serde_json::from_str(&args).ok()?;
                Some(RepositoryWatch { principal, id, action, owner: args.get("owner")?.as_str()?.into(),
                    repo: args.get("repo")?.as_str()?.into(), project_id, source })
            }).collect())
        })
    }

    pub(crate) fn ci_repository_watches(&self) -> Result<Vec<RepositoryWatch>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT s.principal, s.subscription_id, s.fixed_args, s.project_id, s.project_source
                 FROM trigger_subscriptions s JOIN connections c
                 ON c.principal = s.principal AND c.connection_id = s.connection_id
                 WHERE {WATCH_EXISTS_SQL} AND c.app_key = 'github_actions'
                 AND s.action = 'list_workflow_runs' ORDER BY s.subscription_id",
            ))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows
                .into_iter()
                .filter_map(|(principal, id, args, project_id, source)| {
                    let args: Value = serde_json::from_str(&args).ok()?;
                    Some(RepositoryWatch {
                        principal,
                        id,
                        action: "list_workflow_runs".into(),
                        owner: args.get("owner")?.as_str()?.into(),
                        repo: args.get("repo")?.as_str()?.into(),
                        project_id,
                        source,
                    })
                })
                .collect())
        })
    }

    // None reports unavailable CI prerequisites without affecting issue/PR creation.
    pub(crate) fn create_ci_repository_watch(
        &self,
        issue: &RepositoryWatch,
        now: i64,
    ) -> Result<Option<usize>, StoreError> {
        let args = serde_json::json!({"owner":issue.owner,"repo":issue.repo});
        let plan = self.prepare_subscription(
            "direct",
            "conn-github-actions",
            "list_workflow_runs",
            300,
            &serde_json::json!({}),
            &args,
            true,
        )?;
        let Ok(plan) = plan else { return Ok(None) };
        if plan.cursor_kind != "ci_runs" {
            return Ok(None);
        }
        self.inner.with_conn_fenced(|conn| {
            atomic(conn, || insert_ci_repository_watch(conn, issue, &plan, now))
        })
    }

    pub(crate) fn reconcile_ci_cadence(&self) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            atomic(conn, || {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM trigger_subscriptions WHERE status='active' AND cursor_kind='ci_runs'",
                    [], |row| row.get(0),
                )?;
                // CI quota admission reserves requests for repository lookups.
                // Schedule only whole eight-request cycles within the remaining
                // trailing-hour budget, rounding the interval upward.
                let cycles_per_hour=effective_ci_ceiling(conn)? / CI_CYCLE_REQUESTS;
                let cadence=if cycles_per_hour == 0 { i64::MAX } else {
                    (count.saturating_mul(3600).saturating_add(cycles_per_hour-1) / cycles_per_hour).max(300)
                };
                let mut statement = conn.prepare(
                    "SELECT principal, subscription_id, cadence_s FROM trigger_subscriptions
                     WHERE status='active' AND cursor_kind='ci_runs' AND cadence_s != ?1",
                )?;
                let rows = statement.query_map([cadence], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
                })?.collect::<rusqlite::Result<Vec<_>>>()?;
                for (principal, id, old) in &rows {
                    conn.execute(
                        "UPDATE trigger_subscriptions SET cadence_s=?1 WHERE principal=?2 AND subscription_id=?3",
                        rusqlite::params![cadence, principal, id],
                    )?;
                    ownership_audit(conn, principal, id, "set_cadence",
                        &serde_json::json!({"oldCadence":old,"cadence":cadence,"activeCiWatches":count}).to_string())?;
                }
                Ok(rows.len())
            })
        })
    }

    pub(crate) fn reconcile_watch_project(
        &self,
        watch: &RepositoryWatch,
        project: Option<&str>,
        source: Option<&str>,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            atomic(conn, || {
                let changed = conn.execute(
                    "UPDATE trigger_subscriptions SET project_id = ?1, project_source = ?2
                 WHERE principal = ?3 AND subscription_id = ?4 AND status = 'active'
                 AND project_id IS ?5 AND project_source IS ?6
                 AND (project_id IS NOT ?1 OR project_source IS NOT ?2)",
                    rusqlite::params![
                        project,
                        source,
                        watch.principal,
                        watch.id,
                        watch.project_id,
                        watch.source
                    ],
                )?;
                if changed > 0 {
                    ownership_audit(
                        conn,
                        &watch.principal,
                        &watch.id,
                        "set_project",
                        &serde_json::json!({"oldProject":watch.project_id,"oldSource":watch.source,
                        "project":project,"source":source})
                        .to_string(),
                    )?;
                }
                Ok(changed > 0)
            })
        })
    }

    pub(crate) fn create_repository_watches(
        &self,
        owner: &str,
        repo: &str,
        project: &str,
        now: i64,
    ) -> Result<usize, StoreError> {
        let existing = self.repository_watches()?;
        let has = |action: &str| {
            existing.iter().any(|watch| {
                watch.owner.eq_ignore_ascii_case(owner)
                    && watch.repo.eq_ignore_ascii_case(repo)
                    && watch.action == action
            })
        };
        let missing_issue = !has("list_issues");
        let missing_pr = !has("list_pull_requests");
        if !missing_issue && !missing_pr {
            return Ok(0);
        }
        let args = serde_json::json!({"owner":owner,"repo":repo});
        // Seed now so GitHub's server-side `since` filter excludes old history.
        // The ordered-timestamp cursor subtracts its replay window (initially
        // 60 seconds), so recent activity within that overlap can still emit;
        // subsequent polls deduplicate repeated payloads in storage.
        let seed = serde_json::json!({"watermark_ms":now});
        let mut plans = Vec::new();
        for (connection, action, kind, actor_connection, actor_action, methods, missing) in [
            (
                "conn-github",
                "list_issues",
                "ordered_timestamp",
                "conn-github-comments",
                "issue_read",
                vec!["get_comments".to_string()],
                missing_issue,
            ),
            (
                "conn-github-prs",
                "list_pull_requests",
                "sorted_head",
                "conn-github-pr-comments",
                "pull_request_read",
                vec![
                    "get_comments".to_string(),
                    "get_review_comments".to_string(),
                ],
                missing_pr,
            ),
        ] {
            // Validate both issue/PR polls and their comment-read connections,
            // even if only one watch is missing. A broken prerequisite must not
            // create a partial pair or prevent identifying who changed an item.
            let ready = self
                .connection("direct", actor_connection)?
                .is_some_and(|c| c.status == "active")
                && self
                    .catalog_action("direct", actor_connection, actor_action)?
                    .is_some_and(|a| a.status == "active" && a.risk == "read")
                && self
                    .matching_grant(
                        "direct",
                        actor_connection,
                        "direct",
                        actor_action,
                        crate::governance::AUTHORITY_POLL,
                        now,
                        None,
                    )?
                    .is_some_and(|g| g.authorizes(actor_action, now));
            let plan =
                self.prepare_subscription("direct", connection, action, 300, &seed, &args, true)?;
            let Ok(mut plan) = plan else {
                eprintln!(warn scheduler: "automatic watches skipped for {owner}/{repo}: {connection}/{action} refused: {plan:?}");
                return Ok(0);
            };
            if !ready
                || plan.cursor_kind != kind
                || self
                    .connection("direct", connection)?
                    .is_none_or(|c| c.app_key != "github")
            {
                eprintln!(warn scheduler: "automatic watches skipped for {owner}/{repo}: inactive/missing actor source or unexpected poll shape");
                return Ok(0);
            }
            plan.actor_source = Some(ActorSource {
                connection_id: actor_connection.into(),
                action: actor_action.into(),
                methods,
            });
            if missing {
                plans.push(plan);
            }
        }
        self.inner.with_conn_fenced(|conn| {
            atomic(conn, || {
                // An operator can unbind while the pair is being validated.
                // Recheck the local opt-in in the same transaction as insertion.
                if !bot_bound_on_conn(conn, owner, repo)? {
                    return Ok(0);
                }
                let mut created = 0;
                for plan in &plans {
                    // Recheck in the insertion transaction so a concurrent pass cannot
                    // duplicate an active or operationally suspended watch.
                    let exists: bool = conn.query_row(
                        &format!(
                            "SELECT EXISTS(SELECT 1 FROM trigger_subscriptions s JOIN connections c
                     ON c.principal=s.principal AND c.connection_id=s.connection_id
                     WHERE {WATCH_EXISTS_SQL} AND c.app_key='github' AND s.action=?1
                     AND lower(json_extract(s.fixed_args,'$.owner'))=lower(?2)
                     AND lower(json_extract(s.fixed_args,'$.repo'))=lower(?3))"
                        ),
                        rusqlite::params![plan.action, owner, repo],
                        |r| r.get(0),
                    )?;
                    if exists {
                        continue;
                    }
                    conn.execute(
                        "INSERT INTO trigger_subscriptions
                     (subscription_id, principal, connection_id, action, cadence_s, cursor_kind,
                      cursor_state, fixed_args, schema_hash, status, generation, created_at_ms,
                      project_id, project_source, actor_source_json)
                     VALUES (?1,'direct',?2,?3,300,?4,?5,?6,?7,'active',0,?8,?9,'entorhinal',?10)",
                        rusqlite::params![
                            plan.subscription_id,
                            plan.connection_id,
                            plan.action,
                            plan.cursor_kind,
                            plan.cursor_state.to_string(),
                            plan.fixed_args.to_string(),
                            plan.schema_hash,
                            now,
                            project,
                            serde_json::to_string(&plan.actor_source).unwrap()
                        ],
                    )?;
                    ownership_audit(
                        conn,
                        "direct",
                        &plan.subscription_id,
                        "subscribe",
                        &serde_json::json!({"owner":owner,"repo":repo,"project":project,
                        "connection":plan.connection_id,"action":plan.action})
                        .to_string(),
                    )?;
                    created += 1;
                }
                Ok(created)
            })
        })
    }
}

fn insert_ci_repository_watch(
    conn: &rusqlite::Connection,
    issue: &RepositoryWatch,
    plan: &TriggerSubscription,
    now: i64,
) -> rusqlite::Result<Option<usize>> {
    // Existence and the issue stamp are read in the insertion transaction: a
    // second reconcile cannot race a prepared plan into a duplicate CI watch.
    let exists: bool = conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM trigger_subscriptions s JOIN connections c
         ON c.principal=s.principal AND c.connection_id=s.connection_id
         WHERE {WATCH_EXISTS_SQL} AND c.app_key='github_actions' AND s.action='list_workflow_runs'
         AND lower(json_extract(s.fixed_args,'$.owner'))=lower(?1)
         AND lower(json_extract(s.fixed_args,'$.repo'))=lower(?2))"
        ),
        rusqlite::params![issue.owner, issue.repo],
        |row| row.get(0),
    )?;
    if exists {
        return Ok(Some(0));
    }
    let stamp = conn
        .query_row(
            "SELECT s.project_id, s.project_source FROM trigger_subscriptions s JOIN connections c
         ON c.principal=s.principal AND c.connection_id=s.connection_id
         WHERE s.principal=?1 AND s.subscription_id=?2 AND s.status='active'
         AND c.app_key='github' AND s.action='list_issues'
         AND EXISTS(SELECT 1 FROM trigger_subscriptions p JOIN connections pc
         ON pc.principal=p.principal AND pc.connection_id=p.connection_id
         WHERE p.status='active' AND pc.app_key='github' AND p.action='list_pull_requests'
         AND lower(json_extract(p.fixed_args,'$.owner'))=lower(?3)
         AND lower(json_extract(p.fixed_args,'$.repo'))=lower(?4))",
            rusqlite::params![issue.principal, issue.id, issue.owner, issue.repo],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?;
    let Some((project, source)) = stamp else {
        return Ok(Some(0));
    };
    let Some(hashes) = ci_action_hashes(conn, now_ms())? else {
        return Ok(None);
    };
    // Preparation validates fixed arguments against the discovery schema. If it
    // changed meanwhile, leave creation to a new pass with a freshly prepared plan.
    if hashes["list_workflow_runs"] != plan.schema_hash {
        return Ok(None);
    }
    let seed = serde_json::json!({"scanned_through_ms":now,"open":{},"pinned":{
        "get_workflow_run":hashes["get_workflow_run"],
        "list_jobs_for_workflow_run_attempt":hashes["list_jobs_for_workflow_run_attempt"]}});
    conn.execute(
        "INSERT INTO trigger_subscriptions
         (subscription_id, principal, connection_id, action, cadence_s, cursor_kind,
          cursor_state, fixed_args, schema_hash, status, generation, created_at_ms, project_id, project_source)
         VALUES (?1,'direct','conn-github-actions','list_workflow_runs',300,'ci_runs',?2,?3,?4,'active',0,?5,?6,?7)",
        rusqlite::params![plan.subscription_id, seed.to_string(), plan.fixed_args.to_string(),
            plan.schema_hash, now, project, source],
    )?;
    ownership_audit(conn, "direct", &plan.subscription_id, "subscribe",
        &serde_json::json!({"owner":issue.owner,"repo":issue.repo,"project":project,"source":source,
            "connection":"conn-github-actions","action":"list_workflow_runs"}).to_string())?;
    Ok(Some(1))
}

// Check the live connection, catalog and all four poll selectors together. A
// resolver may return an expired grant or one selecting another action to explain
// a denial; only a live grant naming the requested action permits creation.
fn ci_action_hashes(
    conn: &rusqlite::Connection,
    now: i64,
) -> rusqlite::Result<Option<BTreeMap<String, String>>> {
    let active: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM connections WHERE principal='direct'
         AND connection_id='conn-github-actions' AND app_key='github_actions' AND status='active')",
        [],
        |row| row.get(0),
    )?;
    if !active {
        return Ok(None);
    }
    let mut statement = conn.prepare(
        "SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
         action_selectors, authority_kind, expires_at, generation FROM grants
         WHERE principal='direct' AND connection_id='conn-github-actions'
         AND authority_kind=?1 AND grantee_principal='direct'",
    )?;
    let grants = statement
        .query_map([crate::governance::AUTHORITY_POLL], |row| {
            map_grant_row(row, now)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut hashes = BTreeMap::new();
    for action in [
        "list_workflow_runs",
        "get_workflow_run",
        "list_jobs_for_workflow_run_attempt",
        "get_repository",
    ] {
        if !grant_candidate(&grants, action, now, None).is_some_and(|g| g.authorizes(action, now)) {
            return Ok(None);
        }
        let hash = conn.query_row(
            "SELECT schema_hash FROM catalog_actions WHERE principal='direct'
             AND connection_id='conn-github-actions' AND name=?1 AND status='active' AND risk='read'",
            [action], |row| row.get::<_, String>(0),
        ).optional()?;
        let Some(hash) = hash else { return Ok(None) };
        hashes.insert(action.into(), hash);
    }
    Ok(Some(hashes))
}

// Keep the metadata write and its audit inseparable, including a pair of new
// watches. A savepoint also works inside an existing transaction.
fn atomic<T>(
    conn: &rusqlite::Connection,
    f: impl FnOnce() -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    conn.execute_batch("SAVEPOINT repository_ownership")?;
    match f() {
        Ok(value) => {
            conn.execute_batch("RELEASE repository_ownership")?;
            Ok(value)
        }
        Err(error) => {
            conn.execute_batch("ROLLBACK TO repository_ownership; RELEASE repository_ownership")?;
            Err(error)
        }
    }
}

fn ownership_audit(
    conn: &rusqlite::Connection,
    principal: &str,
    id: &str,
    action: &str,
    detail: &str,
) -> rusqlite::Result<()> {
    conn.execute("INSERT INTO audit_journal
        (ts,principal,actor,acting_principal,action,decision,reason_code,gate,args_redaction_summary,outcome)
        VALUES (?1,?2,'plexus',?2,?3,'allow','repository_ownership','entorhinal_reconcile',?4,'recorded')",
        rusqlite::params![now_ms(), principal, action, format!("subscription {id}: {detail}")])?;
    Ok(())
}

fn bot_bound_on_conn(
    conn: &rusqlite::Connection,
    owner: &str,
    repo: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM github_repo_binding WHERE lower(repository) = lower(?1))",
        [format!("{owner}/{repo}")],
        |row| row.get(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository_ownership::{reconcile, RemoteResolution, RepositoryRegistry};
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use serde_json::json;
    use std::sync::Mutex;

    const CI: &str = "conn-github-actions";
    const ACTIONS: [&str; 4] = [
        "list_workflow_runs",
        "get_workflow_run",
        "list_jobs_for_workflow_run_attempt",
        "get_repository",
    ];

    struct Registry {
        resolution: Mutex<RemoteResolution>,
        owned: bool,
    }
    impl Registry {
        fn hand() -> Self {
            Self {
                resolution: Mutex::new(RemoteResolution::Ambiguous),
                owned: false,
            }
        }
        fn owned() -> Self {
            Self {
                resolution: Mutex::new(RemoteResolution::Found("P".into())),
                owned: true,
            }
        }
    }
    impl RepositoryRegistry for Registry {
        fn resolve_remote(&self, _: &str, _: &str) -> RemoteResolution {
            self.resolution.lock().unwrap().clone()
        }
        fn enumerate(&self) -> Option<Value> {
            Some(if self.owned {
                json!({"projects":[{"projectId":"P","rootRecords":[{"remotes":[
                    {"owner":"owner","repo":"repo","owned":true}]}]}]})
            } else {
                json!({"projects":[]})
            })
        }
    }

    fn fixture(ci: bool) -> PlexusStore {
        fixture_at(ci, ":memory:")
    }

    fn fixture_at(ci: bool, path: &str) -> PlexusStore {
        static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: format!(
                "ci-ownership-{}",
                ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite { path: path.into() },
        })
        .unwrap();
        for source in [
            include_str!("../../../../catalog/github.jsonc"),
            include_str!("../../../../catalog/github_actions.jsonc"),
        ] {
            let source = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let manifest =
                crate::manifest::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
            store.upsert_manifest(CATALOG_PRINCIPAL, &manifest).unwrap();
        }
        for (connection, action) in [
            ("conn-github", "list_issues"),
            ("conn-github-prs", "list_pull_requests"),
            ("conn-github-comments", "issue_read"),
            ("conn-github-pr-comments", "pull_request_read"),
        ] {
            store
                .insert_connection("direct", connection, "github", "active", &json!({}))
                .unwrap();
            store
                .seed_catalog_from_manifest("direct", connection, "github")
                .unwrap();
            store.upsert_catalog_action(&CatalogActionInput {
                connection_id: connection.into(), principal: "direct".into(), name: action.into(), title: None,
                schema: json!({"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}},"required":["owner","repo"]}),
                schema_hash: format!("hash-{action}"), risk: "read".into(), severity: "S2".into(), ask_first: false,
                status: "active".into(), quarantine_reason: None, reconciliation: None,
            }).unwrap();
            grant(&store, connection, &["*"], None);
        }
        store.upsert_catalog_action(&CatalogActionInput {
            connection_id: "conn-github".into(), principal: "direct".into(), name: "get_latest_release".into(), title: None,
            schema: json!({"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}},"required":["owner","repo"]}),
            schema_hash: "hash-release".into(), risk: "read".into(), severity: "S2".into(), ask_first: false,
            status: "active".into(), quarantine_reason: None, reconciliation: None,
        }).unwrap();
        if ci {
            store
                .insert_connection("direct", CI, "github_actions", "active", &json!({}))
                .unwrap();
            store
                .seed_catalog_from_manifest("direct", CI, "github_actions")
                .unwrap();
            grant(&store, CI, &ACTIONS, None);
        }
        store
    }
    fn grant(store: &PlexusStore, connection: &str, selectors: &[&str], expires_at: Option<i64>) {
        store
            .insert_grant(&GrantInput {
                grant_id: format!("poll-{connection}"),
                principal: "direct".into(),
                connection_id: connection.into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "read".into(),
                action_selectors: selectors.iter().map(|s| (*s).into()).collect(),
                authority_kind: crate::governance::AUTHORITY_POLL.into(),
                expires_at,
            })
            .unwrap();
    }
    fn watch(
        store: &PlexusStore,
        connection: &str,
        action: &str,
        owner: &str,
        repo: &str,
        cadence: i64,
    ) -> TriggerSubscription {
        store
            .subscribe_with_cursor_state(
                "direct",
                connection,
                action,
                cadence,
                &json!({}),
                &json!({"owner":owner,"repo":repo}),
            )
            .unwrap()
            .unwrap()
    }
    fn pair(store: &PlexusStore) -> RepositoryWatch {
        let issue = watch(store, "conn-github", "list_issues", "Owner", "Repo", 300);
        watch(
            store,
            "conn-github-prs",
            "list_pull_requests",
            "OWNER",
            "repo",
            300,
        );
        store
            .set_subscription_project("direct", &issue.subscription_id, Some("hand-project"))
            .unwrap();
        store
            .repository_watches()
            .unwrap()
            .into_iter()
            .find(|w| w.id == issue.subscription_id)
            .unwrap()
    }
    fn ci(store: &PlexusStore) -> TriggerSubscription {
        let watches = store.ci_repository_watches().unwrap();
        assert_eq!(watches.len(), 1);
        store
            .subscription("direct", &watches[0].id)
            .unwrap()
            .unwrap()
    }
    fn audits(store: &PlexusStore, action: &str) -> Vec<AuditRow> {
        store
            .list_audit("direct")
            .unwrap()
            .into_iter()
            .filter(|r| {
                r.reason_code == "repository_ownership" && r.action.as_deref() == Some(action)
            })
            .collect()
    }
    fn bind(store: &PlexusStore) {
        store
            .insert_connection("direct", "bot", "github_rest", "pending", &json!({}))
            .unwrap();
        store
            .put_github_handle(&crate::storage::github_store::GithubHandle {
                app_handle_id: "handle".into(),
                agent_id: "agent".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:test".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "bot".into(),
            })
            .unwrap();
        store.bind_github_repo("owner/repo", "handle").unwrap();
    }

    fn all_watch_ids(store: &PlexusStore, action: &str) -> Vec<String> {
        store
            .inner
            .with_conn(|conn| {
                let mut query = conn.prepare(
                    "SELECT subscription_id FROM trigger_subscriptions
                 WHERE action=?1 AND lower(json_extract(fixed_args,'$.owner'))='owner'
                 AND lower(json_extract(fixed_args,'$.repo'))='repo' ORDER BY subscription_id",
                )?;
                let ids = query
                    .query_map([action], |row| row.get(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(ids)
            })
            .unwrap()
    }

    fn stored_cursor(store: &PlexusStore, id: &str) -> String {
        store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT cursor_state FROM trigger_subscriptions WHERE subscription_id=?1",
                    [id],
                    |row| row.get(0),
                )
            })
            .unwrap()
    }

    fn assert_operational_watch_survives_reconcile_and_resume(
        store: &PlexusStore,
        registry: &Registry,
        watch: &TriggerSubscription,
        cursor: Value,
    ) {
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                "UPDATE trigger_subscriptions SET cursor_state=?1, consecutive_vendor_failures=5
                 WHERE subscription_id=?2",
                rusqlite::params![cursor.to_string(), watch.subscription_id],
            )?;
                Ok(())
            })
            .unwrap();
        store
            .suspend(
                "direct",
                &watch.subscription_id,
                CIRCUIT_BREAKER_SUSPENSION_REASON,
            )
            .unwrap();
        let cursor_bytes = stored_cursor(store, &watch.subscription_id);
        let suspended = store
            .subscription("direct", &watch.subscription_id)
            .unwrap()
            .unwrap();
        for now in [3_601_000, 7_201_000] {
            assert_eq!(
                reconcile(store, registry, now).unwrap().created,
                0,
                "operational suspension must not mint a replacement"
            );
            // Count all stored rows, not WATCH_EXISTS_SQL's filtered matches: a
            // hidden suspended original beside a new active copy is still a duplicate.
            assert_eq!(
                all_watch_ids(store, &watch.action),
                std::slice::from_ref(&watch.subscription_id)
            );
            let row = store
                .subscription("direct", &watch.subscription_id)
                .unwrap()
                .unwrap();
            assert_eq!(row.status, "suspended");
            assert_eq!(
                row.suspended_reason.as_deref(),
                Some(CIRCUIT_BREAKER_SUSPENSION_REASON)
            );
            assert_eq!(row.generation, suspended.generation);
            assert_eq!(row.cadence_s, suspended.cadence_s);
            assert_eq!(row.cursor_state, cursor);
            assert_eq!(stored_cursor(store, &watch.subscription_id), cursor_bytes);
        }
        let resumed = store
            .resume("direct", &watch.subscription_id)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.status, "active");
        assert_eq!(resumed.suspended_reason, None);
        assert_eq!(resumed.consecutive_vendor_failures, 0);
        assert_eq!(resumed.cursor_state, cursor);
        assert_eq!(reconcile(store, registry, 10_801_000).unwrap().created, 0);
        assert_eq!(
            all_watch_ids(store, &watch.action),
            std::slice::from_ref(&watch.subscription_id)
        );
        assert_eq!(stored_cursor(store, &watch.subscription_id), cursor_bytes);
    }

    #[test]
    fn ci_reconcile_keeps_circuit_breaker_watch_across_passes_and_resume() {
        let store = fixture(true);
        bind(&store);
        let registry = Registry::owned();
        assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 3);
        let watch = ci(&store);
        let mut cursor = watch.cursor_state.clone();
        cursor["scanned_through_ms"] = json!(123);
        cursor["open"] = json!({"42":{"attempt":2}});
        assert_operational_watch_survives_reconcile_and_resume(&store, &registry, &watch, cursor);
    }

    #[test]
    fn issue_pr_reconcile_keeps_circuit_breaker_watch_across_passes_and_resume() {
        for action in ["list_issues", "list_pull_requests"] {
            let store = fixture(true);
            bind(&store);
            let registry = Registry::owned();
            assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 3);
            let id = all_watch_ids(&store, action).pop().unwrap();
            let watch = store.subscription("direct", &id).unwrap().unwrap();
            assert_operational_watch_survives_reconcile_and_resume(
                &store,
                &registry,
                &watch,
                json!({"watermark_ms":123}),
            );
        }
    }

    #[test]
    fn reconcile_keeps_schema_changed_watch_for_operator_review() {
        for action in ["list_issues", "list_pull_requests", "list_workflow_runs"] {
            let store = fixture(true);
            bind(&store);
            let registry = Registry::owned();
            assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 3);
            let id = all_watch_ids(&store, action).pop().unwrap();
            let cursor_bytes = stored_cursor(&store, &id);
            store.suspend("direct", &id, "schema_changed").unwrap();
            for now in [3_601_000, 7_201_000] {
                assert_eq!(reconcile(&store, &registry, now).unwrap().created, 0);
                assert_eq!(all_watch_ids(&store, action), std::slice::from_ref(&id));
                let row = store.subscription("direct", &id).unwrap().unwrap();
                assert_eq!(row.status, "suspended");
                assert_eq!(row.suspended_reason.as_deref(), Some("schema_changed"));
                assert_eq!(stored_cursor(&store, &id), cursor_bytes);
            }
        }
    }

    #[test]
    fn reconcile_replaces_retired_watches() {
        for action in ["list_issues", "list_pull_requests", "list_workflow_runs"] {
            let store = fixture(true);
            bind(&store);
            let registry = Registry::owned();
            assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 3);
            let old = all_watch_ids(&store, action).pop().unwrap();
            store
                .inner
                .with_conn_fenced(|conn| {
                    conn.execute(
                        "UPDATE trigger_subscriptions SET status='retired', suspended_reason=?1
                         WHERE subscription_id=?2",
                        rusqlite::params![CIRCUIT_BREAKER_SUSPENSION_REASON, old],
                    )?;
                    Ok(())
                })
                .unwrap();
            assert_eq!(reconcile(&store, &registry, 2000).unwrap().created, 1);
            let ids = all_watch_ids(&store, action);
            assert_eq!(ids.len(), 2);
            let fresh = ids.iter().find(|id| **id != old).unwrap();
            assert_eq!(
                store.subscription("direct", fresh).unwrap().unwrap().status,
                "active"
            );
            assert_eq!(
                store.subscription("direct", &old).unwrap().unwrap().status,
                "retired"
            );
            assert_eq!(reconcile(&store, &registry, 3000).unwrap().created, 0);
        }
    }

    #[test]
    fn ci_reconcile_includes_hand_pairs_and_copies_stamp_idempotently() {
        let store = fixture(true);
        let issue = pair(&store);
        let registry = Registry::hand();
        assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 1);
        let first = ci(&store);
        assert_eq!(first.principal, "direct");
        assert_eq!(first.connection_id, CI);
        assert_eq!(first.cursor_kind, "ci_runs");
        assert_eq!(first.project_id, issue.project_id);
        assert_eq!(
            store.ci_repository_watches().unwrap()[0].source.as_deref(),
            Some("hand")
        );
        assert_eq!(first.cursor_state["scanned_through_ms"], 1000);
        assert_eq!(first.cursor_state["open"], json!({}));
        for action in &ACTIONS[1..3] {
            assert_eq!(
                first.cursor_state["pinned"][action],
                store
                    .catalog_action("direct", CI, action)
                    .unwrap()
                    .unwrap()
                    .schema_hash
            );
        }
        assert_eq!(reconcile(&store, &registry, 2000).unwrap().created, 0);
        assert_eq!(ci(&store).subscription_id, first.subscription_id);
        assert_eq!(audits(&store, "subscribe").len(), 1);
        assert_eq!(audits(&store, "set_project").len(), 0);
    }

    #[test]
    fn ci_reconcile_tracks_registry_moves_and_clears_project() {
        let store = fixture(true);
        pair(&store);
        let registry = Registry::owned();
        reconcile(&store, &registry, 1000).unwrap();
        let first = ci(&store);
        assert_eq!(first.project_id.as_deref(), Some("P"));
        for target in [RemoteResolution::Found("Q".into()), RemoteResolution::None] {
            *registry.resolution.lock().unwrap() = target.clone();
            reconcile(&store, &registry, 2000).unwrap();
            let watch = ci(&store);
            let expected = match target {
                RemoteResolution::Found(ref p) => Some(p.as_str()),
                _ => None,
            };
            assert_eq!(watch.project_id.as_deref(), expected);
            assert_eq!(
                store.ci_repository_watches().unwrap()[0].source.as_deref(),
                expected.map(|_| "entorhinal")
            );
            assert_eq!(watch.cursor_state, first.cursor_state);
            assert_eq!(watch.generation, first.generation);
        }
        let rows = audits(&store, "set_project");
        assert_eq!(
            rows.iter()
                .filter(|r| r
                    .args_redaction_summary
                    .as_deref()
                    .unwrap()
                    .contains(&first.subscription_id))
                .count(),
            2
        );
        assert_eq!(reconcile(&store, &registry, 3000).unwrap().changed, 0);
    }

    #[test]
    fn ci_existing_hand_watch_stamp_follows_issue_without_creation_prerequisites() {
        let store = fixture(true);
        let issue = pair(&store);
        let hand = watch(&store, CI, "list_workflow_runs", "owner", "repo", 60);
        let pr = store
            .repository_watches()
            .unwrap()
            .into_iter()
            .find(|w| w.action == "list_pull_requests")
            .unwrap();
        store
            .suspend("direct", &pr.id, "schema_hash_changed")
            .unwrap();
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE connections SET status='pending' WHERE connection_id=?1",
                    [CI],
                )?;
                conn.execute(
                    "UPDATE grants SET expires_at=1 WHERE connection_id=?1",
                    [CI],
                )?;
                Ok(())
            })
            .unwrap();
        let registry = Registry::hand();
        for project in [Some("P"), Some("Q"), None] {
            store
                .set_subscription_project("direct", &issue.id, project)
                .unwrap();
            assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 0);
            let row = ci(&store);
            assert_eq!(row.subscription_id, hand.subscription_id);
            assert_eq!(row.project_id.as_deref(), project);
            assert_eq!(
                store.ci_repository_watches().unwrap()[0].source.as_deref(),
                project.map(|_| "hand")
            );
            assert_eq!(row.cadence_s, 300);
        }
        assert_eq!(audits(&store, "set_project").len(), 3);
    }

    #[test]
    fn ci_creation_requires_active_connection_and_each_live_poll_selector() {
        for case in [
            "absent",
            "inactive",
            "list_workflow_runs",
            "get_workflow_run",
            "list_jobs_for_workflow_run_attempt",
            "get_repository",
            "expired",
            "interactive",
            "other_grantee",
        ] {
            let store = fixture(case != "absent");
            bind(&store);
            let registry = Registry::owned();
            if case != "absent" {
                store.inner.with_conn_fenced(|conn| {
                    match case {
                        "inactive" => { conn.execute("UPDATE connections SET status='pending' WHERE connection_id=?1", [CI])?; }
                        "expired" => { conn.execute("UPDATE grants SET expires_at=1 WHERE connection_id=?1", [CI])?; }
                        "interactive" => { conn.execute("UPDATE grants SET authority_kind='invoke' WHERE connection_id=?1", [CI])?; }
                        "other_grantee" => { conn.execute("UPDATE grants SET grantee_principal='other' WHERE connection_id=?1", [CI])?; }
                        missing => {
                            let selectors: Vec<_> = ACTIONS.iter().filter(|a| **a != missing).collect();
                            conn.execute("UPDATE grants SET action_selectors=?1 WHERE connection_id=?2", (serde_json::to_string(&selectors).unwrap(), CI))?;
                        }
                    }
                    Ok(())
                }).unwrap();
            }
            let report = reconcile(&store, &registry, now_ms()).unwrap();
            assert!(report.ci_connection_absent, "{case}");
            assert_eq!(
                report.created, 2,
                "issue/PR creation must not wait for CI: {case}"
            );
            assert_eq!(store.repository_watches().unwrap().len(), 2);
            assert!(store.ci_repository_watches().unwrap().is_empty(), "{case}");
        }
    }

    #[test]
    fn ci_reconcile_requires_both_active_issue_and_pr_watches() {
        for missing in ["list_issues", "list_pull_requests"] {
            let store = fixture(true);
            let issue = pair(&store);
            let victim = store
                .repository_watches()
                .unwrap()
                .into_iter()
                .find(|w| w.action == missing)
                .unwrap();
            store
                .suspend("direct", &victim.id, "schema_hash_changed")
                .unwrap();
            assert_eq!(
                reconcile(&store, &Registry::hand(), 1000).unwrap().created,
                0
            );
            assert!(store.ci_repository_watches().unwrap().is_empty());
            assert_eq!(
                store.create_ci_repository_watch(&issue, 1000).unwrap(),
                Some(0)
            );
        }
    }

    #[test]
    fn ci_reconcile_replaces_identity_suspended_bot_pair_and_ci_but_not_release() {
        let store = fixture(true);
        bind(&store);
        let registry = Registry::owned();
        assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 3);
        let release = watch(
            &store,
            "conn-github",
            "get_latest_release",
            "owner",
            "repo",
            300,
        );
        let old_pair = store.repository_watches().unwrap();
        let old_ci = ci(&store);
        store.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE trigger_subscriptions SET cursor_state='{\"watermark_ms\":123}' WHERE cursor_kind IN ('ordered_timestamp','sorted_head')", [])?;
            conn.execute("UPDATE trigger_subscriptions SET cursor_state='{\"scanned_through_ms\":123,\"open\":{\"old\":{}},\"pinned\":{}}' WHERE cursor_kind='ci_runs'", [])?;
            Ok(())
        }).unwrap();
        store
            .record_repo_id_resolution("owner/repo", Some(101), 1000)
            .unwrap();
        assert_eq!(
            store
                .record_repo_id_resolution("OWNER/Repo", Some(202), 2000)
                .unwrap(),
            crate::storage::event_outbox::RepoIdUpdate::IdentityChanged {
                old_repo_id: 101,
                new_repo_id: 202,
                suspended: 4
            }
        );
        assert_eq!(reconcile(&store, &registry, 3000).unwrap().created, 3);
        let fresh = store.repository_watches().unwrap();
        assert_eq!(fresh.len(), 2);
        for watch in &fresh {
            assert!(old_pair.iter().all(|old| old.id != watch.id));
            let row = store.subscription("direct", &watch.id).unwrap().unwrap();
            assert_eq!(row.cursor_state, json!({"watermark_ms":3000}));
            assert!(row.last_polled_at_ms.is_none());
            assert_eq!(row.generation, 0);
        }
        let replacement = ci(&store);
        assert_ne!(replacement.subscription_id, old_ci.subscription_id);
        assert_eq!(replacement.cursor_state["scanned_through_ms"], 3000);
        assert_eq!(replacement.cursor_state["open"], json!({}));
        for id in old_pair
            .iter()
            .filter(|w| w.action != "get_latest_release")
            .map(|w| w.id.as_str())
            .chain([old_ci.subscription_id.as_str()])
        {
            let row = store.subscription("direct", id).unwrap().unwrap();
            assert_eq!(row.status, "retired");
            assert_eq!(
                row.suspended_reason.as_deref(),
                Some("repository_identity_changed")
            );
        }
        let release = store
            .subscription("direct", &release.subscription_id)
            .unwrap()
            .unwrap();
        assert_eq!(release.status, "suspended");
        assert_eq!(
            release.suspended_reason.as_deref(),
            Some("repository_identity_changed")
        );
    }

    fn webhook(seq: u64, repo_id: i64) -> super::super::relay::Event {
        super::super::relay::Event {
            seq,
            delivery_id: format!("delivery-{seq}"),
            event: "issues".into(),
            action: Some("opened".into()),
            installation_id: 1,
            received_at: "2026-10-14T16:00:00.000Z".into(),
            stub: None,
            body: json!({"repository":{"full_name":"OWNER/Repo","id":repo_id},
                "issue":{"number":seq,"created_at":"2026-10-14T16:00:00Z",
                    "updated_at":"2026-10-14T16:00:00Z"},"sender":{"login":"alice"}}),
        }
    }

    fn start_relay(store: &PlexusStore) {
        store
            .relay_hello(
                "github",
                &super::super::relay::Hello {
                    v: 1,
                    source: "github".into(),
                    stream_id: "stream".into(),
                    next_seq: 1,
                    oldest_seq: 1,
                    last_acked_seq: 0,
                },
            )
            .unwrap();
    }

    fn identity_counter(store: &PlexusStore, name: &str) -> i64 {
        store
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT COALESCE((SELECT value FROM event_outbox_counters WHERE name=?1),0)",
                    [name],
                    |row| row.get(0),
                )
            })
            .unwrap()
    }

    #[test]
    fn webhook_identity_change_survives_ownership_and_later_delivery() {
        let scratch = crate::test_scratch::Scratch::database("identity-ownership");
        let path = scratch.path().to_str().unwrap();
        let store = fixture_at(true, path);
        bind(&store);
        let registry = Registry::owned();
        assert_eq!(reconcile(&store, &registry, 1000).unwrap().created, 3);
        store
            .record_repo_id_resolution("owner/repo", Some(101), 1000)
            .unwrap();
        start_relay(&store);
        store
            .commit_relay_event("github", "stream", &webhook(1, 202))
            .unwrap();
        // A second connection observes committed state, not pending writes on the relay's connection.
        let reader = rusqlite::Connection::open(path).unwrap();
        let id: i64 = reader
            .query_row(
                "SELECT repo_id FROM github_repo_id_cache WHERE repo='owner/repo'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let suspended: i64 = reader.query_row("SELECT count(*) FROM trigger_subscriptions WHERE status='suspended' AND suspended_reason='repository_identity_changed' AND generation=1", [], |r| r.get(0)).unwrap();
        assert_eq!(suspended, 3, "cache and suspension must commit together");
        assert_eq!(reconcile(&store, &registry, 3000).unwrap().created, 3);
        let mut issue = webhook(2, 202);
        store
            .commit_relay_event("github", "stream", &issue)
            .unwrap();
        let active: i64 = reader
            .query_row(
                "SELECT count(*) FROM trigger_subscriptions WHERE status='active'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((id, active), (202, 3),
            "identity change must commit the new id and keep replacements active after the next webhook");
        issue.seq = 3;
        issue.delivery_id = "pr".into();
        issue.event = "pull_request".into();
        issue.body["pull_request"] = issue.body["issue"].clone();
        store
            .commit_relay_event("github", "stream", &issue)
            .unwrap();
        issue.seq = 4;
        issue.delivery_id = "ci".into();
        issue.event = "workflow_run".into();
        issue.body["workflow_run"] = json!({"id":55,"run_attempt":1,"status":"completed",
            "conclusion":"success","updated_at":"2026-10-14T16:00:00Z"});
        store
            .commit_relay_event("github", "stream", &issue)
            .unwrap();
        assert_eq!(
            store.drain_event_outbox(10).unwrap().len(),
            3,
            "later issue, PR and CI webhooks must be admitted to the outbox"
        );
        assert_eq!(
            store
                .record_repo_id_resolution("owner/repo", Some(202), 5000)
                .unwrap(),
            super::super::event_outbox::RepoIdUpdate::Resolved
        );
        assert_eq!(identity_counter(&store, "repository_identity_changed"), 1);
        assert_eq!(
            identity_counter(&store, "relay_drop_repository_identity_changed"),
            1
        );
        assert_eq!(reconcile(&store, &registry, 6000).unwrap().created, 0);
        for watch in store
            .repository_watches()
            .unwrap()
            .into_iter()
            .chain(store.ci_repository_watches().unwrap())
        {
            assert_eq!(
                store
                    .subscription("direct", &watch.id)
                    .unwrap()
                    .unwrap()
                    .status,
                "active",
                "fresh watches must survive same-id webhooks and poll resolution"
            );
        }
        let total: i64 = reader
            .query_row("SELECT count(*) FROM trigger_subscriptions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(total, 6, "later ownership passes must not pile up watches");
    }

    #[test]
    fn relay_identity_change_rolls_back_cache_and_suspension_on_commit_failure() {
        let store = fixture(true);
        bind(&store);
        reconcile(&store, &Registry::owned(), 1000).unwrap();
        store
            .record_repo_id_resolution("owner/repo", Some(101), 1000)
            .unwrap();
        start_relay(&store);
        store.inner.with_conn_fenced(|conn| conn.execute_batch(
            "CREATE TRIGGER fail_cursor BEFORE UPDATE ON relay_cursor BEGIN SELECT RAISE(ABORT,'injected cursor failure'); END;"
        )).unwrap();
        assert!(store
            .commit_relay_event("github", "stream", &webhook(1, 202))
            .is_err());
        assert_eq!(
            store.repo_id_cache("owner/repo").unwrap().unwrap().repo_id,
            Some(101)
        );
        assert_eq!(identity_counter(&store, "repository_identity_changed"), 0);
        assert_eq!(
            store.relay_cursor("github").unwrap().unwrap().committed_seq,
            0
        );
        assert_eq!(store.repository_watches().unwrap().len(), 2);
        assert_eq!(store.ci_repository_watches().unwrap().len(), 1);
        store
            .inner
            .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER fail_cursor"))
            .unwrap();
        store
            .commit_relay_event("github", "stream", &webhook(1, 202))
            .unwrap();
        assert_eq!(identity_counter(&store, "repository_identity_changed"), 1);
    }

    #[test]
    fn identity_retirement_waits_for_trio_and_preserves_readable_events() {
        use super::super::event_outbox::{EventLookupOutcome, EventReader};
        let store = fixture(true);
        bind(&store);
        let registry = Registry::owned();
        reconcile(&store, &registry, 1000).unwrap();
        store
            .record_repo_id_resolution("owner/repo", Some(101), 1000)
            .unwrap();
        start_relay(&store);
        store
            .commit_relay_event("github", "stream", &webhook(1, 101))
            .unwrap();
        let retained = store.drain_event_outbox(10).unwrap().remove(0);
        store
            .commit_relay_event("github", "stream", &webhook(2, 202))
            .unwrap();
        store
            .create_repository_watches("owner", "repo", "P", 3000)
            .unwrap();
        assert_eq!(
            store.retire_replaced_repository_watches().unwrap(),
            0,
            "identity retirement must wait for an active replacement trio"
        );
        let issue = store
            .repository_watches()
            .unwrap()
            .into_iter()
            .find(|w| w.action == "list_issues")
            .unwrap();
        assert_eq!(
            store.create_ci_repository_watch(&issue, 3000).unwrap(),
            Some(1)
        );
        store.inner.with_conn_fenced(|conn| conn.execute_batch(
            "CREATE TRIGGER fail_retire BEFORE INSERT ON audit_journal WHEN NEW.action='retire' BEGIN SELECT RAISE(ABORT,'injected retirement audit failure'); END;"
        )).unwrap();
        assert!(
            store.retire_replaced_repository_watches().is_err(),
            "retirement must fail when its audit cannot commit"
        );
        assert_eq!(audits(&store, "retire").len(), 0);
        store
            .inner
            .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER fail_retire"))
            .unwrap();
        assert_eq!(
            reconcile(&store, &registry, 4000).unwrap().changed,
            3,
            "replaced identity-suspended watches must be retired without deletion"
        );
        assert_eq!(store.retire_replaced_repository_watches().unwrap(), 0);
        assert_eq!(audits(&store, "retire").len(), 3);
        assert_eq!(
            store
                .subscription("direct", &retained.subscription_id)
                .unwrap()
                .unwrap()
                .status,
            "retired"
        );
        assert_eq!(
            store
                .event_by_key(
                    &retained.event_key,
                    EventReader::Agent { agent_id: "agent" },
                    4000
                )
                .unwrap(),
            EventLookupOutcome::Found(Box::new(retained)),
            "retired watch events must remain readable through the stored repo name"
        );
    }

    #[test]
    fn ci_reconcile_replaces_schema_suspended_watch_with_current_pins() {
        let store = fixture(true);
        pair(&store);
        let registry = Registry::hand();
        reconcile(&store, &registry, 1000).unwrap();
        let old = ci(&store);
        store.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE catalog_actions SET schema_hash='new-jobs-hash' WHERE connection_id=?1 AND name='list_jobs_for_workflow_run_attempt'", [CI])?;
            Ok(())
        }).unwrap();
        store
            .suspend("direct", &old.subscription_id, "catalog_schema_mismatch")
            .unwrap();
        assert_eq!(reconcile(&store, &registry, 2000).unwrap().created, 1);
        let replacement = ci(&store);
        assert_ne!(replacement.subscription_id, old.subscription_id);
        assert_eq!(
            replacement.cursor_state["pinned"]["list_jobs_for_workflow_run_attempt"],
            "new-jobs-hash"
        );
        assert_eq!(replacement.cursor_state["scanned_through_ms"], 2000);
        assert_eq!(replacement.cursor_state["open"], json!({}));
        let retained = store
            .subscription("direct", &old.subscription_id)
            .unwrap()
            .unwrap();
        assert_eq!(retained.status, "suspended");
        assert_eq!(retained.cursor_state, old.cursor_state);
        assert_eq!(reconcile(&store, &registry, 3000).unwrap().created, 0);
    }

    #[test]
    fn ci_cadence_counts_hand_made_watches_and_suspended_rows_are_excluded() {
        let store = fixture(true);
        let watches: Vec<_> = (0..30)
            .map(|n| {
                watch(
                    &store,
                    CI,
                    "list_workflow_runs",
                    "owner",
                    &format!("repo-{n}"),
                    60,
                )
            })
            .collect();
        let registry = Registry::hand();
        assert_eq!(reconcile(&store, &registry, 1000).unwrap().changed, 30);
        for watch in &watches {
            assert_eq!(
                store
                    .subscription("direct", &watch.subscription_id)
                    .unwrap()
                    .unwrap()
                    .cadence_s,
                // Thirty repository lookups leave 570 requests: 71 complete cycles.
                1522
            );
        }
        assert_eq!(audits(&store, "set_cadence").len(), 30);
        for watch in &watches[..10] {
            store
                .suspend("direct", &watch.subscription_id, "test")
                .unwrap();
        }
        assert_eq!(reconcile(&store, &registry, 2000).unwrap().changed, 20);
        for (n, watch) in watches.iter().enumerate() {
            assert_eq!(
                store
                    .subscription("direct", &watch.subscription_id)
                    .unwrap()
                    .unwrap()
                    .cadence_s,
                if n < 10 { 1522 } else { 1000 }
            );
        }
        assert_eq!(audits(&store, "set_cadence").len(), 50);
        assert_eq!(reconcile(&store, &registry, 3000).unwrap().changed, 0);
        assert_eq!(audits(&store, "set_cadence").len(), 50);
    }

    #[test]
    fn ci_cadence_rolls_back_when_audit_fails() {
        let store = fixture(true);
        let watch = watch(&store, CI, "list_workflow_runs", "owner", "repo", 60);
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER reject_cadence_audit BEFORE INSERT ON audit_journal
             WHEN NEW.action='set_cadence' BEGIN SELECT RAISE(ABORT, 'audit refused'); END;",
                )
            })
            .unwrap();
        assert!(reconcile(&store, &Registry::hand(), 1000).is_err());
        assert_eq!(
            store
                .subscription("direct", &watch.subscription_id)
                .unwrap()
                .unwrap()
                .cadence_s,
            60
        );
        assert!(audits(&store, "set_cadence").is_empty());
    }

    #[test]
    fn ci_creation_rechecks_existence_after_preparation() {
        let store = fixture(true);
        let issue = pair(&store);
        let plan = store
            .prepare_subscription(
                "direct",
                CI,
                "list_workflow_runs",
                300,
                &json!({}),
                &json!({"owner":"owner","repo":"repo"}),
                true,
            )
            .unwrap()
            .unwrap();
        let hand = watch(&store, CI, "list_workflow_runs", "OWNER", "REPO", 300);
        let created = store
            .inner
            .with_conn_fenced(|conn| {
                atomic(conn, || {
                    insert_ci_repository_watch(conn, &issue, &plan, 1000)
                })
            })
            .unwrap();
        assert_eq!(created, Some(0));
        assert_eq!(ci(&store).subscription_id, hand.subscription_id);
        assert!(audits(&store, "subscribe").is_empty());
    }

    #[test]
    fn ci_creation_rechecks_authority_and_copies_current_stamp_in_transaction() {
        let store = fixture(true);
        let issue = pair(&store);
        let plan = store
            .prepare_subscription(
                "direct",
                CI,
                "list_workflow_runs",
                300,
                &json!({}),
                &json!({"owner":"owner","repo":"repo"}),
                true,
            )
            .unwrap()
            .unwrap();
        store
            .set_subscription_project("direct", &issue.id, Some("changed-after-preparation"))
            .unwrap();
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE grants SET expires_at=1 WHERE connection_id=?1",
                    [CI],
                )?;
                atomic(conn, || {
                    insert_ci_repository_watch(conn, &issue, &plan, 1000)
                })
            })
            .map(|created| assert_eq!(created, None))
            .unwrap();
        assert!(store.ci_repository_watches().unwrap().is_empty());
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE grants SET expires_at=NULL WHERE connection_id=?1",
                    [CI],
                )?;
                atomic(conn, || {
                    insert_ci_repository_watch(conn, &issue, &plan, 1000)
                })
            })
            .map(|created| assert_eq!(created, Some(1)))
            .unwrap();
        assert_eq!(
            ci(&store).project_id.as_deref(),
            Some("changed-after-preparation")
        );
    }
}
