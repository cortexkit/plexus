//! Read and check the signed policy without changing grants or bindings.

use crate::{blocking_section, ModuleState};
use plexus_core::credentials::{CkcredRoutePeer, CkcredWatch};
use plexus_core::diag;
use plexus_core::github::agent_policy::{
    check_github, read_active, ActivePolicy, CheckedGitHub, ReadFailure, WatchNotice,
};
use plexus_core::manifest::AppManifest;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

pub(crate) const BACKSTOP_INTERVAL: Duration = Duration::from_secs(15 * 60);
const WATCH_RETRY: Duration = Duration::from_secs(30);
const GITHUB_CATALOG: &str = "github_rest";

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
    active: ActivePolicy,
    github: CheckedGitHub,
    catalog: Arc<AppManifest>,
    logged_unserved: BTreeSet<String>,
}

impl Checked {
    fn new(active: ActivePolicy, catalog: Arc<AppManifest>) -> Self {
        let github = check_github(&active.policy, &catalog.actions_baseline);
        let mut checked = Self {
            active,
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
                            self.observation = Observation::Loaded;
                        } else {
                            self.unreadable();
                        }
                        return;
                    }
                }
                if let Some(catalog) = catalog {
                    self.checked = Some(Checked::new(active, Arc::clone(catalog)));
                    self.observation = Observation::Loaded;
                } else {
                    // The catalog must be readable before a version becomes
                    // retained state. Read policy.active again after recovery.
                    self.observation = Observation::Unreadable;
                }
            }
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
                }
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
