use super::{ActivePolicy, Snapshot};
use crate::{composition::ModuleRuntime, health::HealthState};
use plexus_core::credentials::{CkcredRoutePeer, PolicyTokenFailure};
use plexus_core::diag;
use plexus_core::github::agent_policy::{repo_get_suffix_template, SuffixMatch};
use plexus_core::github::credential::{
    BroadSuffix, GithubPolicyTokens, RepoGetToken, UNRESOLVABLE_AUTH_REQUIRED,
    UNRESOLVABLE_PERMANENT, UNRESOLVABLE_TRANSIENT,
};
use plexus_core::{PlexusStore, ResolvedCredential};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, MutexGuard, Once};

const MAX_SUFFIX_TEMPLATES: usize = 32;
static WARN_AMBIGUOUS_SUFFIX: Once = Once::new();

#[derive(Default, Serialize)]
pub(super) struct LegCounts {
    narrowed: u64,
    broad: u64,
}

#[derive(Default)]
pub(super) struct SuffixLegCounts {
    pub(super) templates: BTreeMap<String, TemplateCount>,
    pub(super) overflow: u64,
}

#[derive(Default, Serialize)]
#[serde(transparent)]
pub(super) struct TemplateCount {
    count: u64,
    #[serde(skip)]
    logged_unmatched: bool,
}

impl SuffixLegCounts {
    fn record(&mut self, template: &str, unmatched: bool) -> bool {
        let count = if let Some(count) = self.templates.get_mut(template) {
            count
        } else if self.templates.len() < MAX_SUFFIX_TEMPLATES {
            self.templates.entry(template.into()).or_default()
        } else {
            self.overflow = self.overflow.saturating_add(1);
            return false;
        };
        count.count = count.count.saturating_add(1);
        unmatched && !std::mem::replace(&mut count.logged_unmatched, true)
    }
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

    fn prepare_selected(
        &self,
        agent: &str,
        identity: &str,
        kind: &str,
        repository: &str,
        active: &ActivePolicy,
    ) -> Result<Option<ResolvedCredential>, &'static str> {
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
}

impl GithubPolicyTokens for Tokens {
    fn prepare(
        &self,
        agent: &str,
        identity: &str,
        kind: &str,
        repository: &str,
    ) -> Result<Option<ResolvedCredential>, &'static str> {
        let active = self
            .snapshot()
            .checked
            .as_ref()
            .filter(|checked| checked.github.serves_kind(kind))
            .map(|checked| Arc::clone(&checked.active));
        let Some(active) = active else {
            return Ok(None);
        };
        self.prepare_selected(agent, identity, kind, repository, &active)
    }

    fn prepare_repo_get_suffix(
        &self,
        agent: &str,
        identity: &str,
        repository: &str,
        args: &Value,
    ) -> Result<RepoGetToken, &'static str> {
        let (active, catalog, kind, unmatched) = {
            let snapshot = self.snapshot();
            let Some(checked) = &snapshot.checked else {
                drop(snapshot);
                let catalog = self.store.cached_manifest(super::GITHUB_CATALOG).ok();
                return Ok(RepoGetToken::Broad(BroadSuffix {
                    template: repo_get_suffix_template(
                        catalog.as_ref().map_or(&[], |c| &c.actions_baseline),
                        None,
                        args,
                    ),
                    unmatched: true,
                }));
            };
            let (kind, unmatched) = match checked
                .active
                .policy
                .match_repo_get_suffix(repository, args)
            {
                SuffixMatch::Unique(kind) => (
                    checked.github.serves_kind(kind).then(|| kind.to_owned()),
                    false,
                ),
                SuffixMatch::None => (None, true),
                SuffixMatch::Ambiguous => {
                    WARN_AMBIGUOUS_SUFFIX.call_once(|| diag!(warn governance: "multiple agent policy kinds match a GitHub repo.get suffix; using the scoped installation token"));
                    (None, false)
                }
            };
            (
                Arc::clone(&checked.active),
                Arc::clone(&checked.catalog),
                kind,
                unmatched,
            )
        };
        // Use the exact policy that selected the kind, not a fresh snapshot.
        if let Some(kind) = kind {
            if let Some(token) =
                self.prepare_selected(agent, identity, &kind, repository, &active)?
            {
                return Ok(RepoGetToken::Narrowed(token));
            }
        }
        Ok(RepoGetToken::Broad(BroadSuffix {
            template: repo_get_suffix_template(
                &catalog.actions_baseline,
                Some(&active.policy),
                args,
            ),
            unmatched,
        }))
    }

    fn record_leg(&self, narrowed: bool, broad_suffix: Option<BroadSuffix>) {
        let mut snapshot = self.snapshot();
        let counts = &mut snapshot.token_legs;
        let count = if narrowed {
            &mut counts.narrowed
        } else {
            &mut counts.broad
        };
        *count = count.saturating_add(1);
        if let Some(BroadSuffix {
            template,
            unmatched,
        }) = broad_suffix
        {
            let log = snapshot.broad_suffix_legs.record(&template, unmatched);
            drop(snapshot);
            if log {
                diag!(info governance: "unmatched GitHub repo.get suffix: {template}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_telemetry_counts_overflow_without_forgetting_tracked_templates() {
        let mut counts = SuffixLegCounts::default();
        assert!(!counts.record("issues/{}", false));
        assert!(counts.record("issues/{}", true));
        assert!(!counts.record("issues/{}", true));
        for index in 1..32 {
            assert!(counts.record(&"{}/".repeat(index), true));
        }
        assert!(!counts.record("commits/{}", true));
        assert!(!counts.record("issues/{}", true));
        assert!(!counts.record("commits/{}", true));
        assert_eq!(counts.templates.len(), 32);
        assert_eq!(counts.overflow, 2);
        assert_eq!(counts.templates["issues/{}"].count, 4);
    }
}
