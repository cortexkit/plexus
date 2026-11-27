//! Read and check the signed policy, and reconcile eligible GitHub agents when enabled.

use crate::{blocking_section, ModuleState};
use plexus_core::credentials::{CkcredRoutePeer, CkcredWatch};
use plexus_core::diag;
use plexus_core::github::agent_policy::{
    check_github, read_active, ActivePolicy, ApplyPlan, CheckedGitHub, PolicyRollout, ReadFailure,
    WatchNotice,
};
use plexus_core::manifest::AppManifest;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

mod tokens;
pub(crate) use tokens::configure_tokens;

pub(crate) const BACKSTOP_INTERVAL: Duration = Duration::from_secs(15 * 60);
const WATCH_RETRY: Duration = Duration::from_secs(30);
const GITHUB_CATALOG: &str = "github_rest";
const HEALTH_PLAN_MAX_BYTES: usize = 16 * 1024;

#[derive(Default)]
pub(crate) struct Wakes {
    pub(crate) read: Notify,
    pub(crate) catalog: Notify,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Observation {
    Absent,
    None,
    Loaded,
    #[default]
    Unreadable,
}

struct Checked {
    active: Arc<ActivePolicy>,
    github: CheckedGitHub,
    catalog: Arc<AppManifest>,
    logged_unserved: BTreeSet<String>,
}

impl Checked {
    fn new(active: ActivePolicy, catalog: Arc<AppManifest>) -> Self {
        let github = check_github(&active.policy, &catalog.actions_baseline);
        let mut checked = Self {
            active: Arc::new(active),
            github,
            catalog,
            logged_unserved: BTreeSet::new(),
        };
        checked.log_unserved();
        checked
    }

    fn check_new_catalog(&mut self, catalog: &Arc<AppManifest>) {
        // cached_manifest checks the stored content hash on every call and
        // reuses the Arc while the hash is unchanged.
        if !Arc::ptr_eq(&self.catalog, catalog) {
            self.github = check_github(&self.active.policy, &catalog.actions_baseline);
            self.catalog = Arc::clone(catalog);
            self.log_unserved();
        }
    }

    fn log_unserved(&mut self) {
        let version = self.active.policy.version;
        for unserved in &self.github.unserved {
            if self.logged_unserved.insert(unserved.name.clone()) {
                diag!(warn governance: "agent policy version {version} does not serve {:?}: {}", unserved.name, unserved.reason);
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct Snapshot {
    observation: Observation,
    checked: Option<Checked>,
    catalog_unreadable: bool,
    logged_absence: bool,
    last_reply_was_none: bool,
    last_rollout: Option<PolicyRollout>,
    current_reply: bool,
    apply: Option<Value>,
    apply_failed: bool,
    logged_conflicts: BTreeSet<String>,
    token_legs: tokens::LegCounts,
    broad_suffix_legs: tokens::SuffixLegCounts,
    pub(crate) imports: ImportStatus,
}

#[derive(Default, Serialize)]
pub(crate) struct ImportStatus {
    pub(crate) imported: Vec<String>,
    pub(crate) pending: Vec<ImportIssue>,
    pub(crate) conflicts: Vec<ImportIssue>,
}

#[derive(Serialize)]
pub(crate) struct ImportIssue {
    pub(crate) slug: String,
    pub(crate) reason: &'static str,
}

impl Snapshot {
    pub(crate) fn status(&self) -> Value {
        let checked = self.checked.as_ref();
        let state = if self.catalog_unreadable {
            Observation::Unreadable
        } else {
            self.observation
        };
        json!({
            "state": state,
            "version": checked.map(|c| c.active.policy.version),
            "policy_sha256": checked.map(|c| &c.active.policy_sha256),
            "served": checked.map_or(&[][..], |c| c.github.served.as_slice()),
            "unserved": checked.map_or(&[][..], |c| c.github.unserved.as_slice()),
            "apply": self.apply.clone().unwrap_or_else(empty_apply_status),
            "imports": self.imports,
            "token_legs": self.token_legs,
            "broad_suffix_legs": self.broad_suffix_legs.templates,
            "broad_suffix_legs_overflow": self.broad_suffix_legs.overflow,
        })
    }

    fn observe(
        &mut self,
        reply: Result<Option<ActivePolicy>, ReadFailure>,
        catalog: Option<&Arc<AppManifest>>,
    ) {
        self.observe_vault(reply, catalog);
        // The catalog can change even when the vault returns older policy data
        // or no readable reply. Recheck only the retained version in that case.
        self.observe_catalog(catalog);
    }

    fn observe_vault(
        &mut self,
        reply: Result<Option<ActivePolicy>, ReadFailure>,
        catalog: Option<&Arc<AppManifest>>,
    ) {
        self.current_reply = false;
        let previously_none =
            std::mem::replace(&mut self.last_reply_was_none, matches!(reply, Ok(None)));
        match reply {
            Err(ReadFailure::Unsupported) => {
                if !self.logged_absence {
                    diag!(info governance: "vault does not serve agent policy");
                    self.logged_absence = true;
                }
                self.observation = Observation::Absent;
            }
            Err(ReadFailure::Unreadable) => self.unreadable(),
            Ok(None) => {
                if let Some(checked) = &self.checked {
                    if !previously_none {
                        let version = checked.active.policy.version;
                        diag!(warn governance: "vault reports no active policy; keeping version {version}");
                    }
                } else {
                    self.observation = Observation::None;
                }
            }
            Ok(Some(active)) => {
                let version = active.policy.version;
                if let Some(checked) = &self.checked {
                    let previous = &checked.active;
                    if version < previous.policy.version {
                        return;
                    }
                    if version == previous.policy.version {
                        if active.policy_sha256 == previous.policy_sha256
                            && active.manifest_version == previous.manifest_version
                        {
                            self.observe_rollout(&active);
                            self.observation = Observation::Loaded;
                            self.current_reply = true;
                        } else {
                            self.unreadable();
                        }
                        return;
                    }
                }
                if let Some(catalog) = catalog {
                    self.observe_rollout(&active);
                    self.checked = Some(Checked::new(active, Arc::clone(catalog)));
                    self.observation = Observation::Loaded;
                    self.current_reply = true;
                } else {
                    // The catalog must be readable before a version becomes
                    // retained state. Read policy.active again after recovery.
                    self.observation = Observation::Unreadable;
                }
            }
        }
    }

    fn observe_rollout(&mut self, active: &ActivePolicy) {
        let previous = std::mem::replace(&mut self.last_rollout, active.rollout);
        if active.rollout == previous {
            return;
        }
        if let Some(newest) = active.rollout {
            diag!(info governance: "policy rollout in progress: active manifest {} policy {}, newest manifest {} policy {}",
                active.manifest_version, active.policy.version, newest.manifest_version, newest.policy_version);
        } else {
            diag!(info governance: "policy rollout cleared");
        }
    }

    /// Returns whether the store recovered and a fresh vault read is due.
    fn observe_catalog(&mut self, catalog: Option<&Arc<AppManifest>>) -> bool {
        let was_unreadable = std::mem::replace(&mut self.catalog_unreadable, catalog.is_none());
        if let Some(catalog) = catalog {
            if let Some(checked) = &mut self.checked {
                checked.check_new_catalog(catalog);
            }
            was_unreadable
        } else {
            if !was_unreadable {
                diag!(warn governance: "stored GitHub catalog is unreadable; keeping the last agent policy check, if any");
            }
            false
        }
    }

    fn unreadable(&mut self) {
        if self.observation != Observation::Unreadable {
            diag!(warn governance: "vault policy read failed; keeping the last checked policy, if any");
        }
        self.observation = Observation::Unreadable;
    }

    fn plan_input(&self) -> Option<(Arc<ActivePolicy>, CheckedGitHub)> {
        self.checked
            .as_ref()
            .map(|checked| (Arc::clone(&checked.active), checked.github.clone()))
    }
}

pub(crate) fn preview(state: &ModuleState) -> Result<ApplyPlan, Value> {
    let checked = state
        .health
        .agent_policy
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .plan_input();
    state
        .store()
        .github_policy_preview(
            checked
                .as_ref()
                .map(|(active, github)| (active.as_ref(), github)),
        )
        .map_err(|error| {
            crate::wire::store_failure(
                "agent policy preview",
                "the agent policy plan could not be read",
                &error,
            )
        })
}

pub(crate) fn set_enabled(state: &ModuleState, enabled: bool) -> Value {
    if enabled {
        if let Some(refusal) = state.runtime.connector_home.refusal() {
            return refusal;
        }
    }
    match state.store().set_github_policy_apply(enabled) {
        Ok(()) => {
            update_apply(state, false);
            state.health.agent_policy_wake.notify_one();
            json!({"result":{"enabled":enabled}})
        }
        Err(error) => crate::wire::store_failure(
            "agent policy switch",
            "the agent policy switch could not be stored",
            &error,
        ),
    }
}

fn update_apply(state: &ModuleState, apply: bool) {
    let (checked, current) = {
        let snapshot = state
            .health
            .agent_policy
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (
            snapshot.plan_input(),
            snapshot.current_reply && !snapshot.catalog_unreadable,
        )
    };
    let checked = checked
        .as_ref()
        .map(|(active, github)| (active.as_ref(), github));
    let plan = state.store().github_policy_preview(checked);
    let mut failed = None;
    let mut attempted = false;
    let plan = match plan {
        Ok(mut plan) => {
            if let Some(checked) = checked.filter(|_| {
                apply
                    && current
                    && plan.enabled
                    && plan.has_eligible_agents()
                    && state.runtime.connector_home.held()
            }) {
                attempted = true;
                match state
                    .store()
                    .apply_github_policy(checked, || state.runtime.connector_home.held())
                {
                    Ok(remaining) => plan = remaining,
                    Err(error) => failed = Some(error),
                }
            }
            Some(plan)
        }
        Err(error) => {
            failed = Some(error);
            None
        }
    };
    let mut snapshot = state
        .health
        .agent_policy
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(plan) = plan {
        if failed.is_none() && (attempted || !plan.enabled || !plan.has_eligible_agents()) {
            snapshot.apply_failed = false;
        }
        let conflicts: BTreeSet<_> = plan
            .agents
            .iter()
            .flat_map(|agent| {
                agent.conflicts.iter().map(|conflict| {
                    format!(
                        "version {:?} agent {:?}: {:?}",
                        plan.version, agent.agent, conflict
                    )
                })
            })
            .collect();
        for conflict in conflicts.difference(&snapshot.logged_conflicts) {
            diag!(warn governance: "agent policy conflict: {conflict}");
        }
        snapshot.logged_conflicts = conflicts;
        snapshot.apply = Some(health_plan(&plan));
    }
    if let Some(error) = failed {
        if !snapshot.apply_failed {
            diag!(warn governance: "could not reconcile agent policy: {error}");
        }
        snapshot.apply_failed = true;
    }
    if snapshot.apply_failed {
        snapshot.apply.get_or_insert_with(empty_apply_status)["error"] = json!("store_failure");
    }
}

fn empty_apply_status() -> Value {
    json!({"enabled": false, "applied_version": null,
        "plan": {"agents": [], "unchanged_agents": 0}})
}

fn health_plan(plan: &ApplyPlan) -> Value {
    let mut agents = Vec::new();
    let mut remaining = HEALTH_PLAN_MAX_BYTES;
    let mut omitted = 0;
    for row in plan.agents.iter().filter(|row| row.changed()) {
        let entry = json!({
            "agent": row.agent, "handle": row.handle, "add_selectors": row.add_selectors,
            "remove_selectors": row.remove_selectors, "add_repos": row.add_repos,
            "remove_repos": row.remove_repos, "revoke_grant_ids": row.revoke_grant_ids,
            "held": row.held, "conflicts": row.conflicts,
        });
        let bytes = entry.to_string().len() + 1;
        if let Some(left) = remaining.checked_sub(bytes) {
            agents.push(entry);
            remaining = left;
        } else {
            omitted += 1;
        }
    }
    let mut status = json!({
        "enabled": plan.enabled, "applied_version": plan.applied_version,
        "plan": {"agents": agents, "unchanged_agents": plan.unchanged_agents},
    });
    if omitted != 0 {
        status["plan"]["omitted_agents"] = json!(omitted);
    }
    if !plan.module_layer.is_empty() {
        status["plan"]["module_layer"] = json!(plan.module_layer);
    }
    status
}

fn read_catalog(state: &ModuleState) -> Option<Arc<AppManifest>> {
    state.store().cached_manifest(GITHUB_CATALOG).ok()
}

fn refresh(state: &ModuleState, peer: &dyn CkcredRoutePeer) -> bool {
    if !state.runtime.connector_home.held() {
        return false;
    }
    let reply = read_active(peer);
    let supported = !matches!(reply, Err(ReadFailure::Unsupported));
    if state.runtime.connector_home.held() {
        let catalog = read_catalog(state);
        if state.runtime.connector_home.held() {
            state
                .health
                .agent_policy
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .observe(reply, catalog.as_ref());
            update_apply(state, true);
        }
    }
    supported
}

fn recheck_catalog(state: &ModuleState) -> bool {
    if !state.runtime.connector_home.held() {
        return false;
    }
    let catalog = read_catalog(state);
    state.runtime.connector_home.held()
        && state
            .health
            .agent_policy
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe_catalog(catalog.as_ref())
}

pub(crate) fn spawn(
    state: Arc<ModuleState>,
    stop: mpsc::Receiver<()>,
    wakes: Arc<Wakes>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(state, stop, wakes))
}

async fn run(state: Arc<ModuleState>, mut stop: mpsc::Receiver<()>, wakes: Arc<Wakes>) {
    blocking_section(|| update_apply(&state, false));
    let Some(peer) = state.runtime.vault_peer.as_deref() else {
        return;
    };
    let mut claim = state.runtime.connector_home.decisions();
    let mut watch: Option<CkcredWatch> = None;
    let mut next_watch_attempt = Instant::now();
    let mut was_home = false;
    let mut subscribe = false;

    loop {
        if !state.runtime.connector_home.held() {
            watch = None;
            was_home = false;
            tokio::select! {
                _ = stop.recv() => return,
                _ = wakes.read.notified() => {},
                _ = wakes.catalog.notified() => {},
                _ = state.health.agent_policy_wake.notified() => blocking_section(|| update_apply(&state, false)),
                changed = claim.changed() => if changed.is_err() { return; },
            }
            continue;
        }
        if !was_home {
            subscribe = blocking_section(|| refresh(&state, peer));
            was_home = true;
            next_watch_attempt = Instant::now();
        }
        tokio::select! {
            biased;
            _ = stop.recv() => return,
            changed = claim.changed() => if changed.is_err() { return; },
            _ = wakes.read.notified() => {
                subscribe = blocking_section(|| refresh(&state, peer));
                if !subscribe { watch = None; }
            },
            _ = wakes.catalog.notified() => {
                if blocking_section(|| recheck_catalog(&state)) {
                    wakes.read.notify_one();
                } else { blocking_section(|| update_apply(&state, true)); }
            },
            _ = state.health.agent_policy_wake.notified() => {
                blocking_section(|| update_apply(&state, true));
            },
            event = async {
                match watch.as_mut() {
                    Some(watch) => watch.events.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event.map(WatchNotice::decode) {
                    Some(Ok(_)) => {
                        // The notice is a wakeup, not a policy source. Re-read
                        // even on the opening snapshot or a repeated version.
                        subscribe = blocking_section(|| refresh(&state, peer));
                        if !subscribe { watch = None; }
                    }
                    Some(Err(ReadFailure::Unsupported)) => {
                        // Keep polling policy.active at the backstop in case
                        // this vault can read before it can serve the watch.
                        watch = None;
                        subscribe = false;
                    }
                    Some(Err(ReadFailure::Unreadable)) | None => watch = None,
                }
            },
            _ = tokio::time::sleep_until(next_watch_attempt), if subscribe && watch.is_none() => {
                next_watch_attempt = Instant::now() + WATCH_RETRY;
                if state.runtime.connector_home.held() {
                    watch = blocking_section(|| peer.watch_policy()).ok();
                }
            },
        }
    }
}

#[cfg(test)]
mod tests;
