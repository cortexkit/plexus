use super::Snapshot;
use crate::{composition::ModuleRuntime, health::HealthState};
use plexus_core::credentials::{CkcredRoutePeer, PolicyTokenFailure};
use plexus_core::github::credential::{
    GithubPolicyTokens, UNRESOLVABLE_AUTH_REQUIRED, UNRESOLVABLE_PERMANENT, UNRESOLVABLE_TRANSIENT,
};
use plexus_core::{PlexusStore, ResolvedCredential};
use serde::Serialize;
use std::sync::{Arc, MutexGuard};

#[derive(Default, Serialize)]
pub(super) struct LegCounts {
    narrowed: u64,
    broad: u64,
}

pub(crate) fn configure_tokens(runtime: &mut ModuleRuntime, health: &Arc<HealthState>) {
    runtime.engine.set_github_policy_tokens(Arc::new(Tokens {
        peer: runtime.vault_peer.clone(),
        store: Arc::clone(&runtime.store),
        health: Arc::clone(health),
    }));
}

struct Tokens {
    peer: Option<Arc<dyn CkcredRoutePeer>>,
    store: Arc<PlexusStore>,
    health: Arc<HealthState>,
}

impl Tokens {
    fn snapshot(&self) -> MutexGuard<'_, Snapshot> {
        self.health
            .agent_policy
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }
}

impl GithubPolicyTokens for Tokens {
    fn prepare(
        &self,
        agent: &str,
        identity: &str,
        kind: &str,
        repository: &str,
    ) -> Result<Option<ResolvedCredential>, &'static str> {
        let active = {
            let snapshot = self.snapshot();
            let Some(checked) = snapshot
                .checked
                .as_ref()
                .filter(|c| c.github.serves_kind(kind))
            else {
                return Ok(None);
            };
            Arc::clone(&checked.active)
        };
        let version = active.policy.version;
        let applied = || {
            self.store
                .github_policy_applied_version(agent, version, &active.policy_sha256)
                .map_err(|_| UNRESOLVABLE_TRANSIENT)
        };
        if !applied()? {
            return Ok(None);
        }
        let resource = if kind == "node_repository" {
            "binding"
        } else {
            repository
        };
        use PolicyTokenFailure::*;
        let peer = self.peer.as_ref().ok_or(UNRESOLVABLE_TRANSIENT)?;
        match peer.policy_token(identity, kind, resource, version) {
            Ok(token) => {
                // Minting may wait on GitHub. Do not use its answer if the
                // checked policy or the applied row moved during that wait.
                let current = self.snapshot().checked.as_ref().is_some_and(|c| {
                    c.active.policy_sha256 == active.policy_sha256 && c.github.serves_kind(kind)
                });
                if !current
                    || !applied()?
                    || token
                        .expires_at_ms
                        .is_none_or(|expiry| expiry <= plexus_core::now_ms())
                {
                    return Err(UNRESOLVABLE_TRANSIENT);
                }
                Ok(Some(token))
            }
            Err(Unsupported) => Ok(None),
            Err(VersionNotActive) => {
                self.health.agent_policy_wakes.read.notify_one();
                Err(UNRESOLVABLE_TRANSIENT)
            }
            Err(Unavailable) => Err(UNRESOLVABLE_TRANSIENT),
            Err(AuthRequired) => Err(UNRESOLVABLE_AUTH_REQUIRED),
            Err(
                NotFound | NotInstalled | ApprovalRequired | ApprovalPolicyChanged | InvalidReply,
            ) => Err(UNRESOLVABLE_PERMANENT),
        }
    }

    fn record_leg(&self, narrowed: bool) {
        let mut snapshot = self.snapshot();
        let counts = &mut snapshot.token_legs;
        let count = if narrowed {
            &mut counts.narrowed
        } else {
            &mut counts.broad
        };
        *count = count.saturating_add(1);
    }
}
