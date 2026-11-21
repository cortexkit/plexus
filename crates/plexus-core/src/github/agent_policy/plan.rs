//! Compute the GitHub policy diff without reading or changing the store.

use super::{model::Class, ActivePolicy, CheckedGitHub};
use crate::github::{
    canonical_repository, control::invoke_selectors, facade::effects::primary_action,
};
use crate::storage::github_store::GithubHandle;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const GITHUB_APP: &str = "github_app:";

#[derive(Default)]
pub(crate) struct StoreView {
    pub enabled: bool,
    pub applied: BTreeMap<String, Applied>,
    pub handles: Vec<GithubHandle>,
    pub bindings: BTreeMap<String, String>,
    pub grants: Vec<StoredGrant>,
    pub policies: BTreeMap<(String, String, String), StoredPolicy>,
}

pub(crate) struct Applied {
    pub version: i64,
    pub sha256: String,
    pub manifest_version: i64,
    pub grant_ids: Vec<String>,
}

pub(crate) struct StoredGrant {
    pub principal: String,
    pub connection: String,
    pub id: String,
    pub agent: String,
    pub selectors: BTreeSet<String>,
    pub expires_at: Option<i64>,
    pub generation: i64,
}

pub(crate) struct StoredPolicy {
    pub id: String,
    pub effect: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApplyPlan {
    pub enabled: bool,
    pub applied_version: Option<i64>,
    pub version: Option<i64>,
    /// GitHub reads the policy allows that no bot write runs as a lookup first
    /// (for example `github.repo.get` or `github.actions.job_log`). Plexus
    /// authorizes those reads by the calling module's grant alone, so they get
    /// no agent selector here; they are listed so a preview shows they were
    /// kept on the module grants, not dropped.
    pub module_layer: Vec<String>,
    pub agents: Vec<AgentChange>,
    pub unchanged_agents: usize,
}

impl ApplyPlan {
    pub fn has_eligible_agents(&self) -> bool {
        self.agents.iter().any(|row| row.target.is_some())
    }
}

#[derive(Debug, Serialize)]
pub struct AgentChange {
    pub agent: String,
    pub handle: Option<String>,
    pub add_selectors: Vec<String>,
    pub remove_selectors: Vec<String>,
    pub add_repos: Vec<String>,
    pub remove_repos: Vec<String>,
    pub revoke_grant_ids: Vec<String>,
    pub held: Option<&'static str>,
    pub conflicts: Vec<PolicyConflict>,
    pub derived_grant: Option<DerivedGrant>,
    pub allow_policies: Vec<String>,
    #[serde(skip)]
    pub(crate) target: Option<Target>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PolicyConflict {
    pub reason: &'static str,
    pub resource: Option<String>,
    pub handle: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DerivedGrant {
    pub(crate) id: String,
    pub(crate) selectors: BTreeSet<String>,
    pub(crate) insert: bool,
}

#[derive(Debug)]
pub(crate) struct Target {
    pub principal: String,
    pub connection: String,
    pub revoke: Vec<(String, String)>,
    pub next_grant_generation: Option<i64>,
}

impl AgentChange {
    pub fn changed(&self) -> bool {
        self.held.is_some()
            || !self.conflicts.is_empty()
            || !self.add_selectors.is_empty()
            || !self.remove_selectors.is_empty()
            || !self.add_repos.is_empty()
            || !self.remove_repos.is_empty()
            || !self.revoke_grant_ids.is_empty()
            || !self.allow_policies.is_empty()
            || self
                .derived_grant
                .as_ref()
                .is_some_and(|grant| grant.insert)
    }
}

pub(crate) fn derive(
    checked: Option<(&ActivePolicy, &CheckedGitHub)>,
    store: &StoreView,
    now: i64,
) -> ApplyPlan {
    let mut plan = ApplyPlan {
        enabled: store.enabled,
        applied_version: store.applied.values().map(|row| row.version).max(),
        version: checked.map(|(active, _)| active.policy.version),
        module_layer: Vec::new(),
        agents: Vec::new(),
        unchanged_agents: 0,
    };
    let Some((active, checked)) = checked else {
        return plan;
    };
    let version = active.policy.version;
    let Some(rules) = &active.policy.rule_sets.github else {
        return plan;
    };
    let selectors: BTreeSet<_> = invoke_selectors(
        checked
            .served
            .iter()
            .filter_map(|action| primary_action(action)),
    )
    .into_iter()
    .filter(|action| checked.served_kinds.contains(*action))
    .map(str::to_owned)
    .collect();
    let writes: Vec<_> = selectors
        .iter()
        .filter(|name| !name.starts_with("github."))
        .collect();
    plan.module_layer = rules
        .kinds
        .iter()
        .filter(|kind| {
            kind.class == Class::Read
                && checked.served_kinds.contains(&kind.kind)
                && !selectors.contains(&kind.kind)
        })
        .map(|kind| kind.kind.clone())
        .collect();
    plan.module_layer.sort_unstable();

    let mut agents = BTreeMap::<_, Vec<_>>::new();
    let mut identities = BTreeMap::<_, BTreeSet<_>>::new();
    let mut resources = BTreeMap::<_, BTreeSet<_>>::new();
    for binding in &active.policy.bindings {
        agents.entry(&binding.agent).or_default().push(binding);
        identities
            .entry(&binding.identity)
            .or_default()
            .insert(&binding.agent);
        for resource in &binding.resources {
            resources
                .entry(canonical_repository(resource))
                .or_default()
                .insert(&binding.agent);
        }
    }
    let older = plan
        .applied_version
        .is_some_and(|applied| version < applied);
    let changed_bytes = store.applied.values().any(|row| {
        row.version == version
            && (row.sha256 != active.policy_sha256
                || row.manifest_version != active.manifest_version)
    });
    for (agent, bindings) in agents {
        let previous = store.applied.get(agent);
        if older || previous.is_some_and(|row| version <= row.version) {
            plan.unchanged_agents += 1;
            continue;
        }
        let mut row = AgentChange {
            agent: agent.clone(),
            handle: None,
            add_selectors: Vec::new(),
            remove_selectors: Vec::new(),
            add_repos: Vec::new(),
            remove_repos: Vec::new(),
            revoke_grant_ids: Vec::new(),
            held: None,
            conflicts: Vec::new(),
            derived_grant: None,
            allow_policies: Vec::new(),
            target: None,
        };
        let binding = bindings[0];
        let handle = store
            .handles
            .iter()
            .find(|handle| handle.credential_reference == binding.identity);
        row.handle = handle.map(|handle| handle.app_handle_id.clone());
        let mut conflict = |reason, resource, handle| {
            row.conflicts.push(PolicyConflict {
                reason,
                resource,
                handle,
            })
        };
        if changed_bytes {
            conflict("policy_version_content_changed", None, None);
        }
        if agent.is_empty()
            || binding
                .identity
                .strip_prefix(GITHUB_APP)
                .is_none_or(str::is_empty)
        {
            conflict("invalid_binding_identity", None, None);
        }
        if bindings.len() != 1 || identities[&binding.identity].len() != 1 {
            conflict("duplicate_policy_binding", None, None);
        }
        if let Some(handle) = handle.filter(|handle| handle.agent_id != *agent) {
            conflict(
                "handle_belongs_to_another_agent",
                None,
                Some(handle.app_handle_id.clone()),
            );
        }
        let desired: BTreeSet<_> = binding
            .resources
            .iter()
            .map(|repo| canonical_repository(repo))
            .collect();
        let owners: BTreeSet<_> = desired
            .iter()
            .filter_map(|repo| repo.split_once('/').map(|(owner, _)| owner))
            .collect();
        if owners.len() > 1 {
            conflict("binding_owner_mismatch", None, row.handle.clone());
        }
        for repo in &desired {
            if crate::github::resolver::split_repository(repo).is_err() {
                conflict("invalid_repository", Some(repo.clone()), None);
            } else if resources[repo].len() != 1 {
                conflict("duplicate_policy_repository", Some(repo.clone()), None);
            }
            if let Some(other) = store
                .bindings
                .get(repo)
                .filter(|id| Some(*id) != row.handle.as_ref())
            {
                conflict(
                    "repository_bound_to_another_handle",
                    Some(repo.clone()),
                    Some(other.clone()),
                );
            }
        }
        let enabled = handle.filter(|handle| handle.status == "enabled");
        if enabled.is_none() {
            row.held = Some(if handle.is_some() {
                "handle_disabled"
            } else {
                "handle_not_imported"
            });
        }
        if let Some(handle) = enabled.filter(|_| row.conflicts.is_empty()) {
            plan_agent(
                &mut row,
                store,
                handle,
                desired,
                &Wanted {
                    selectors: &selectors,
                    writes: &writes,
                    version,
                    now,
                },
            );
        }
        if !row.changed() {
            plan.unchanged_agents += 1;
        }
        plan.agents.push(row);
    }
    plan
}

struct Wanted<'a> {
    selectors: &'a BTreeSet<String>,
    writes: &'a [&'a String],
    version: i64,
    now: i64,
}

fn plan_agent(
    row: &mut AgentChange,
    store: &StoreView,
    handle: &GithubHandle,
    desired: BTreeSet<String>,
    wanted: &Wanted<'_>,
) {
    let current: BTreeSet<_> = store
        .bindings
        .iter()
        .filter(|(_, bound)| *bound == &handle.app_handle_id)
        .map(|(repo, _)| repo.clone())
        .collect();
    row.add_repos = desired.difference(&current).cloned().collect();
    row.remove_repos = current.difference(&desired).cloned().collect();
    let applies_here = |grant: &StoredGrant| {
        grant.principal == handle.connection_principal && grant.connection == handle.connection_id
    };
    let current_agent = store.grants.iter().filter(|grant| grant.agent == row.agent);
    let previous_ids = store
        .applied
        .get(&row.agent)
        .map(|record| &record.grant_ids);
    let was_derived = |grant: &StoredGrant| previous_ids.is_some_and(|ids| ids.contains(&grant.id));
    let is_hand = |grant: &StoredGrant| {
        grant.id.starts_with("github-import:") || grant.id.starts_with("github-grant:")
    };
    row.allow_policies = wanted
        .writes
        .iter()
        .filter(|action| {
            store
                .policies
                .get(&(
                    row.agent.clone(),
                    handle.connection_id.clone(),
                    (*action).to_string(),
                ))
                .is_none_or(|policy| policy.effect != "allow" || policy.expires_at.is_some())
        })
        .map(|action| (*action).clone())
        .collect();
    let keep = current_agent.clone().find(|grant| {
        was_derived(grant)
            && applies_here(grant)
            && grant.expires_at.is_none()
            && grant.selectors == *wanted.selectors
            && row.allow_policies.is_empty()
    });
    let revoke: BTreeSet<_> = current_agent
        .clone()
        .filter(|grant| {
            !keep.is_some_and(|keep| keep.id == grant.id && keep.principal == grant.principal)
                && (was_derived(grant) || (applies_here(grant) && is_hand(grant)))
        })
        .map(|grant| (grant.principal.clone(), grant.id.clone()))
        .collect();
    row.revoke_grant_ids = revoke.iter().map(|(_, id)| id.clone()).collect();
    row.revoke_grant_ids.sort_unstable();
    let live_grants = current_agent
        .filter(|grant| applies_here(grant) && grant.expires_at.is_none_or(|at| at > wanted.now));
    let before: BTreeSet<_> = live_grants
        .clone()
        .flat_map(|grant| grant.selectors.iter().cloned())
        .collect();
    let mut after = wanted.selectors.clone();
    after.extend(
        live_grants
            .filter(|grant| !revoke.contains(&(grant.principal.clone(), grant.id.clone())))
            .flat_map(|grant| grant.selectors.iter().cloned()),
    );
    row.add_selectors = after.difference(&before).cloned().collect();
    row.remove_selectors = before.difference(&after).cloned().collect();
    if !wanted.selectors.is_empty() {
        row.derived_grant = Some(DerivedGrant {
            id: keep.map(|grant| grant.id.clone()).unwrap_or_else(|| {
                format!(
                    "policy:github:{}:{}:v{}",
                    row.agent, handle.connection_id, wanted.version
                )
            }),
            selectors: wanted.selectors.clone(),
            insert: keep.is_none(),
        });
    }
    row.target = Some(Target {
        principal: handle.connection_principal.clone(),
        connection: handle.connection_id.clone(),
        // A planned bot write records the highest authorizing agent-grant
        // generation and checks it again before dispatch. Invalidate that
        // receipt even if the replacement grant differs only by id.
        next_grant_generation: store
            .grants
            .iter()
            .filter(|grant| revoke.contains(&(grant.principal.clone(), grant.id.clone())))
            .map(|grant| grant.generation)
            .max()
            .unwrap_or_default()
            .checked_add(1),
        revoke: revoke.into_iter().collect(),
    });
}
