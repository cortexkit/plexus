//! Keep GitHub watches and their project labels aligned with repository
//! ownership reported by the entorhinal project registry.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use cortexkit_store::StoreError;
use serde_json::{json, Value};

use crate::github_identity::PrefrontalRoutePeer;
use crate::storage::PlexusStore;

pub const RECONCILE_INTERVAL_MS: i64 = 3_600_000;
pub const OWNERSHIP_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteResolution {
    Found(String),
    None,
    Ambiguous,
    Unavailable,
}

/// Ownership replies determine project labels; they do not grant permission
/// to call external services.
pub trait RepositoryRegistry: Send + Sync {
    fn resolve_remote(&self, owner: &str, repo: &str) -> RemoteResolution;
    fn enumerate(&self) -> Option<Value>;
}

/// Entorhinal uses management requests with `method` and `params`, and wraps
/// read replies (including their incarnation) in `result`.
pub struct EntorhinalRepositoryRegistry {
    peer: Arc<dyn PrefrontalRoutePeer>,
}
impl EntorhinalRepositoryRegistry {
    pub fn new(peer: Arc<dyn PrefrontalRoutePeer>) -> Self {
        Self { peer }
    }
}
impl RepositoryRegistry for EntorhinalRepositoryRegistry {
    fn resolve_remote(&self, owner: &str, repo: &str) -> RemoteResolution {
        let Ok(reply) = self
            .peer
            .call("resolve_remote", json!({"owner":owner,"repo":repo}))
        else {
            return RemoteResolution::Unavailable;
        };
        let Some(reply) = reply.get("result") else {
            return RemoteResolution::Unavailable;
        };
        match reply.get("status").and_then(Value::as_str) {
            Some("found") => reply
                .get("projectId")
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .map(|id| RemoteResolution::Found(id.into()))
                .unwrap_or(RemoteResolution::Unavailable),
            Some("none") => RemoteResolution::None,
            Some("ambiguous") => RemoteResolution::Ambiguous,
            _ => RemoteResolution::Unavailable,
        }
    }
    fn enumerate(&self) -> Option<Value> {
        self.peer
            .call("enumerate", json!({}))
            .ok()?
            .get("result")
            .cloned()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RepositoryWatch {
    pub principal: String,
    pub id: String,
    pub action: String,
    pub owner: String,
    pub repo: String,
    pub project_id: Option<String>,
    pub source: Option<String>,
}

#[derive(Default, Debug)]
pub struct OwnershipReport {
    pub changed: usize,
    pub created: usize,
    pub unanswered: bool,
    /// The repository whose ownership request went unanswered, if the pass
    /// stopped at one. The next pass starts just after it.
    pub stopped_at: Option<(String, String)>,
    pub unconfirmed_hand: Vec<String>,
    /// Watches whose project label was set by hand (`project_source = 'hand'`)
    /// that the reconciliation pass this report describes did not ask about,
    /// because it stopped early at an unanswered repository.
    pub deferred_hand: Vec<String>,
    pub unbound_owned_remotes: Vec<String>,
    pub ci_connection_absent: bool,
}

/// Records when the last reconciliation started, so the once-a-second scheduler
/// tick runs it at most once per `RECONCILE_INTERVAL_MS` (one hour). A pass that
/// stops because entorhinal did not answer is not retried on the next tick; the
/// remainder waits for the next interval, which starts after the repository
/// that went unanswered (see [`OwnershipResume`]).
#[derive(Default)]
pub struct OwnershipThrottle(Mutex<Option<i64>>);
impl OwnershipThrottle {
    pub fn due(&self, now_ms: i64) -> bool {
        let mut last = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_some_and(|last| now_ms.saturating_sub(last) < RECONCILE_INTERVAL_MS) {
            return false;
        }
        *last = Some(now_ms);
        true
    }
}

/// Where the next reconciliation starts, after one stopped at an unanswered
/// request.
///
/// A pass stops at the first unanswered request because each one has already
/// waited out the call timeout, and asking every remaining repository would
/// hold the scheduler for that long per repository. Stopping alone, though,
/// let a repository whose request always goes unanswered block every one
/// after it in the fixed order, forever. Resuming just after it puts it last
/// in the next pass, so every other repository is asked first.
#[derive(Default)]
pub struct OwnershipResume(Mutex<Option<(String, String)>>);

/// Order `items` (sorted by key) to start just after `after`, wrapping round,
/// so the item at `after` itself comes last.
fn resume_order<V>(items: &mut [((String, String), V)], after: Option<&(String, String)>) {
    if let Some(after) = after {
        let start = items.partition_point(|(key, _)| key <= after);
        items.rotate_left(start);
    }
}

pub fn reconcile(
    store: &PlexusStore,
    registry: &dyn RepositoryRegistry,
    now_ms: i64,
) -> Result<OwnershipReport, StoreError> {
    reconcile_from(store, registry, now_ms, None)
}

/// [`reconcile`], asking about repositories in order starting just after
/// `resume_after` (the repository a previous pass stopped at).
pub fn reconcile_from(
    store: &PlexusStore,
    registry: &dyn RepositoryRegistry,
    now_ms: i64,
    resume_after: Option<&(String, String)>,
) -> Result<OwnershipReport, StoreError> {
    let watches = store.repository_watches()?;
    let mut report = OwnershipReport::default();
    let mut hand: BTreeSet<String> = watches
        .iter()
        .filter(|w| w.source.as_deref() == Some("hand"))
        .map(|w| w.id.clone())
        .collect();
    let mut repos: BTreeMap<(String, String), Vec<&RepositoryWatch>> = BTreeMap::new();
    for watch in &watches {
        repos
            .entry((
                watch.owner.to_ascii_lowercase(),
                watch.repo.to_ascii_lowercase(),
            ))
            .or_default()
            .push(watch);
    }
    let mut repos: Vec<_> = repos.into_iter().collect();
    resume_order(&mut repos, resume_after);
    for ((owner, repo), watches) in repos {
        let resolution = registry.resolve_remote(&owner, &repo);
        if resolution == RemoteResolution::Unavailable {
            report.unanswered = true;
            report.stopped_at = Some((owner, repo));
            break;
        }
        for watch in watches {
            if hand.remove(&watch.id)
                && matches!(
                    resolution,
                    RemoteResolution::None | RemoteResolution::Ambiguous
                )
            {
                report.unconfirmed_hand.push(watch.id.clone());
            }
            let target = match &resolution {
                RemoteResolution::Found(project) => Some(Some(project.as_str())),
                RemoteResolution::None if watch.source.as_deref() == Some("entorhinal") => {
                    Some(None)
                }
                _ => None,
            };
            if let Some(target) = target {
                report.changed +=
                    store.reconcile_watch_project(watch, target, target.map(|_| "entorhinal"))?
                        as usize;
            }
        }
    }
    report.unconfirmed_hand.sort();
    report.deferred_hand = hand.into_iter().collect();
    if !report.unanswered {
        match registry
            .enumerate()
            .and_then(|reply| owned_repositories(&reply))
        {
            Some(remotes) => {
                let mut remotes: Vec<_> = remotes.into_iter().collect();
                resume_order(&mut remotes, resume_after);
                for ((owner, repo), projects) in remotes {
                    // A registered clone can own its origin without belonging
                    // to an agent. Only an operator's local bot binding opts a
                    // repository into automatic issue and PR watches.
                    if !store.repository_is_bot_bound(&owner, &repo)? {
                        report.unbound_owned_remotes.push(format!("{owner}/{repo}"));
                        continue;
                    }
                    // Two projects claiming the same remote must not mint competing
                    // watches. Confirm sole ownership with resolve_remote before
                    // creating anything from the enumeration snapshot.
                    if projects.len() != 1 {
                        continue;
                    }
                    match registry.resolve_remote(&owner, &repo) {
                        RemoteResolution::Found(project) if projects.contains(&project) => {
                            report.created +=
                                store.create_repository_watches(&owner, &repo, &project, now_ms)?;
                        }
                        RemoteResolution::Unavailable => {
                            report.unanswered = true;
                            report.stopped_at = Some((owner, repo));
                            break;
                        }
                        _ => {}
                    }
                }
            }
            None => report.unanswered = true,
        }
    }
    // Reload after the registry pass so newly created pairs and changed stamps
    // are visible. Hand-made pairs do not need a bot binding to acquire CI.
    let watches = store.repository_watches()?;
    let ci_watches = store.ci_repository_watches()?;
    let mut pairs = BTreeMap::<_, Vec<&RepositoryWatch>>::new();
    for watch in &watches {
        pairs
            .entry((
                watch.owner.to_ascii_lowercase(),
                watch.repo.to_ascii_lowercase(),
            ))
            .or_default()
            .push(watch);
    }
    for ((owner, repo), watches) in pairs {
        let Some(issue) = watches.iter().find(|w| w.action == "list_issues") else {
            continue;
        };
        let existing: Vec<_> = ci_watches
            .iter()
            .filter(|w| w.owner.eq_ignore_ascii_case(&owner) && w.repo.eq_ignore_ascii_case(&repo))
            .collect();
        if existing.is_empty() {
            if !watches.iter().any(|w| w.action == "list_pull_requests") {
                continue;
            }
            match store.create_ci_repository_watch(issue, now_ms)? {
                Some(created) => report.created += created,
                None => report.ci_connection_absent = true,
            }
        } else {
            for watch in existing {
                report.changed += store.reconcile_watch_project(
                    watch,
                    issue.project_id.as_deref(),
                    issue.source.as_deref(),
                )? as usize;
            }
        }
    }
    report.changed += store.reconcile_ci_cadence()?;
    report.changed += store.retire_replaced_repository_watches()?;
    Ok(report)
}

fn owned_repositories(reply: &Value) -> Option<BTreeMap<(String, String), BTreeSet<String>>> {
    let mut owned = BTreeMap::<_, BTreeSet<String>>::new();
    for project in reply.get("projects")?.as_array()? {
        let Some(id) = project
            .get("projectId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let Some(roots) = project.get("rootRecords").and_then(Value::as_array) else {
            continue;
        };
        for root in roots {
            let Some(remotes) = root.get("remotes").and_then(Value::as_array) else {
                continue;
            };
            for remote in remotes {
                if remote.get("owned").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let Some(owner) = remote
                    .get("owner")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                else {
                    continue;
                };
                let Some(repo) = remote
                    .get("repo")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                else {
                    continue;
                };
                owned
                    .entry((owner.to_ascii_lowercase(), repo.to_ascii_lowercase()))
                    .or_default()
                    .insert(id.into());
            }
        }
    }
    Some(owned)
}

pub fn run_and_report(
    store: &PlexusStore,
    registry: &dyn RepositoryRegistry,
    now_ms: i64,
    resume: &OwnershipResume,
) {
    let mut resume_after = resume
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match reconcile_from(store, registry, now_ms, resume_after.as_ref()) {
        Ok(report) => {
            *resume_after = report.stopped_at.clone();
            eprintln!(info scheduler: "repository ownership: {} changed, {} created; unconfirmed hand-set watches: {:?}; unanswered or deferred hand-set watches: {:?}; owned remotes without bot bindings: {:?}", report.changed, report.created, report.unconfirmed_hand, report.deferred_hand, report.unbound_owned_remotes);
            if report.unanswered {
                eprintln!(warn scheduler: "repository ownership stopped at unanswered entorhinal call; remainder deferred to next hour");
            }
            if report.ci_connection_absent {
                eprintln!(warn scheduler: "ci_connection_absent: CI watches skipped; conn-github-actions or its direct poll authority is unavailable");
            }
        }
        Err(error) => {
            eprintln!(warn scheduler: "repository ownership reconciliation failed: {error}")
        }
    }
}

#[cfg(test)]
#[path = "repository_ownership_tests.rs"]
mod tests;

#[cfg(test)]
mod resume_tests {
    use super::*;
    use crate::governance::AUTHORITY_POLL;
    use crate::storage::{CatalogActionInput, GrantInput};
    use crate::Ceiling;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    /// Answers every repository except the ones it is told never to answer.
    #[derive(Default)]
    struct Registry {
        unanswered: BTreeSet<(String, String)>,
        calls: Mutex<Vec<(String, String)>>,
    }
    impl RepositoryRegistry for Registry {
        fn resolve_remote(&self, owner: &str, repo: &str) -> RemoteResolution {
            let key = (owner.to_string(), repo.to_string());
            self.calls.lock().unwrap().push(key.clone());
            if self.unanswered.contains(&key) {
                RemoteResolution::Unavailable
            } else {
                RemoteResolution::Found(format!("project-{repo}"))
            }
        }
        fn enumerate(&self) -> Option<Value> {
            Some(json!({"projects": []}))
        }
    }

    /// A store with issue watches on `owner/a`, `owner/b` and `owner/c`.
    fn store_with_watches() -> PlexusStore {
        static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: format!(
                "ownership-resume-{}",
                ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        let source = include_str!("../../../catalog/github.jsonc")
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
            .insert_connection("direct", "conn-github", "github", "pending", &json!({}))
            .unwrap();
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "conn-github".into(),
                principal: "direct".into(),
                name: "list_issues".into(),
                title: None,
                schema: json!({"type":"object","properties":{
                    "owner":{"type":"string"},"repo":{"type":"string"},"since":{"type":"string"},
                    "orderBy":{"type":"string"},"direction":{"type":"string"},
                    "perPage":{"type":"integer"},"after":{"type":"string"}},
                    "required":["owner","repo"]}),
                schema_hash: "hash-list_issues".into(),
                risk: "read".into(),
                severity: "S2".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        let ticket = store
            .create_binding_ticket_bounded(
                "direct",
                "conn-github",
                "credential_reference",
                b"test:conn-github",
                &Ceiling::unrestricted_for_tests(),
            )
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        store
            .insert_grant(&GrantInput {
                grant_id: "poll-conn-github".into(),
                principal: "direct".into(),
                connection_id: "conn-github".into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["*".into()],
                authority_kind: AUTHORITY_POLL.into(),
                expires_at: None,
            })
            .unwrap();
        for repo in ["a", "b", "c"] {
            store
                .subscribe_with_cursor_state(
                    "direct",
                    "conn-github",
                    "list_issues",
                    300,
                    &json!({}),
                    &json!({"owner": "owner", "repo": repo}),
                )
                .unwrap()
                .unwrap();
        }
        store
    }

    fn projects(store: &PlexusStore) -> BTreeMap<String, Option<String>> {
        store
            .repository_watches()
            .unwrap()
            .into_iter()
            .map(|watch| (watch.repo, watch.project_id))
            .collect()
    }

    /// A repository whose ownership request always goes unanswered must not
    /// starve the ones after it in name order: the next pass starts just after
    /// it, so every
    /// other repository is asked first and it is asked last. Each pass still
    /// stops at its first unanswered request.
    #[test]
    fn a_pass_resumes_after_the_repository_it_stopped_at() {
        let store = store_with_watches();
        let registry = Registry {
            unanswered: [("owner".to_string(), "a".to_string())].into(),
            ..Default::default()
        };
        let resume = OwnershipResume::default();
        let key = |repo: &str| ("owner".to_string(), repo.to_string());

        run_and_report(&store, &registry, 1_000, &resume);
        assert_eq!(*registry.calls.lock().unwrap(), [key("a")]);
        assert_eq!(*resume.0.lock().unwrap(), Some(key("a")));

        run_and_report(&store, &registry, 2_000, &resume);
        assert_eq!(
            *registry.calls.lock().unwrap(),
            [key("a"), key("b"), key("c"), key("a")],
            "the second pass must ask every other repository before the stuck one"
        );
        let projects = projects(&store);
        assert_eq!(projects["b"].as_deref(), Some("project-b"));
        assert_eq!(projects["c"].as_deref(), Some("project-c"));
        assert_eq!(projects["a"], None);

        // Once every request is answered the pass completes and the next one
        // starts from the beginning again.
        let answered = Registry::default();
        run_and_report(&store, &answered, 3_000, &resume);
        assert_eq!(*resume.0.lock().unwrap(), None);
        assert_eq!(
            *answered.calls.lock().unwrap(),
            [key("b"), key("c"), key("a")]
        );
    }
}
