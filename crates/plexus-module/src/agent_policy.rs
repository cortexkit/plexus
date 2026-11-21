//! Read and check the signed policy without changing grants or bindings.

use crate::{blocking_section, ModuleState};
use plexus_core::credentials::{CkcredRoutePeer, CkcredWatch};
use plexus_core::diag;
use plexus_core::github::agent_policy::{
    check_github, read_active, ActivePolicy, CheckedGitHub, ReadFailure, WatchNotice,
};
use plexus_core::manifest::{ActionBaseline, AppManifest};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

pub(crate) const BACKSTOP_INTERVAL: Duration = Duration::from_secs(15 * 60);
const WATCH_RETRY: Duration = Duration::from_secs(30);

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
}

#[derive(Default)]
pub(crate) struct Snapshot {
    observation: Observation,
    checked: Option<Checked>,
    logged_absence: bool,
    last_reply_was_none: bool,
}

impl Snapshot {
    pub(crate) fn status(&self) -> Value {
        let checked = self.checked.as_ref();
        json!({
            "state": self.observation,
            "version": checked.map(|c| c.active.policy.version),
            "policy_sha256": checked.map(|c| &c.active.policy_sha256),
            "served": checked.map_or(&[][..], |c| c.github.served.as_slice()),
            "unserved": checked.map_or(&[][..], |c| c.github.unserved.as_slice()),
        })
    }

    fn observe(
        &mut self,
        reply: Result<Option<ActivePolicy>, ReadFailure>,
        catalog: &[ActionBaseline],
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
                let github = check_github(&active.policy, catalog);
                for unserved in &github.unserved {
                    diag!(warn governance: "agent policy version {version} does not serve {:?}: {}", unserved.name, unserved.reason);
                }
                self.checked = Some(Checked { active, github });
                self.observation = Observation::Loaded;
            }
        }
    }

    fn unreadable(&mut self) {
        if self.observation != Observation::Unreadable {
            diag!(warn governance: "vault policy read failed; keeping the last checked policy, if any");
        }
        self.observation = Observation::Unreadable;
    }
}

fn refresh(state: &ModuleState, peer: &dyn CkcredRoutePeer, catalog: &[ActionBaseline]) -> bool {
    if !state.runtime.connector_home.held() {
        return false;
    }
    let reply = read_active(peer);
    let supported = !matches!(reply, Err(ReadFailure::Unsupported));
    if state.runtime.connector_home.held() {
        state
            .health
            .agent_policy
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(reply, catalog);
    }
    supported
}

fn checked_catalog() -> Result<AppManifest, String> {
    let source = include_str!("../../../catalog/github_rest.jsonc");
    let json = subc_jsonc::jsonc_to_json(source).map_err(|err| err.to_string())?;
    serde_json::from_str(&json).map_err(|err| err.to_string())
}

pub(crate) fn spawn(
    state: Arc<ModuleState>,
    stop: mpsc::Receiver<()>,
    backstop: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(state, stop, backstop))
}

async fn run(state: Arc<ModuleState>, mut stop: mpsc::Receiver<()>, backstop: Arc<Notify>) {
    let Some(peer) = state.runtime.vault_peer.as_deref() else {
        return;
    };
    let Ok(catalog) = checked_catalog() else {
        diag!(error governance: "shipped GitHub catalog could not be read for the policy load check");
        return;
    };
    let actions = &catalog.actions_baseline;
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
                _ = backstop.notified() => {},
                changed = claim.changed() => if changed.is_err() { return; },
            }
            continue;
        }
        if !was_home {
            subscribe = blocking_section(|| refresh(&state, peer, actions));
            was_home = true;
            next_watch_attempt = Instant::now();
        }
        tokio::select! {
            biased;
            _ = stop.recv() => return,
            changed = claim.changed() => if changed.is_err() { return; },
            _ = backstop.notified() => {
                subscribe = blocking_section(|| refresh(&state, peer, actions));
                if !subscribe { watch = None; }
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
                        subscribe = blocking_section(|| refresh(&state, peer, actions));
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
