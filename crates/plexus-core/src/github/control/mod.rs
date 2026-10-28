//! Operator-controlled GitHub handle import and read-only installation proof.
//! The inventory is an operator-supplied snapshot of existing agent authority;
//! repository reachability is instead established with each App's own vault token.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::github::credential::HandleCredentialProvider;
use crate::github::facade::effects;
use crate::github::pagination::{self, ListRead, WalkError};
use crate::storage::github_store::{
    GithubHandle, GithubImportRow, GithubImportedGrant, GithubImportedPolicy,
};
use crate::storage::PlexusStore;

const WRITES: &[&str] = &[
    "add_issue_comment",
    "add_pr_review",
    "add_reaction",
    "create_issue",
    "create_pull_request",
    "edit_issue",
    "update_issue_comment",
    "close_issue",
    "reopen_issue",
    "mark_pull_request_ready",
    "convert_pull_request_to_draft",
    "enqueue_pull_request",
    "dequeue_pull_request",
    "edit_pull_request",
    "reply_to_review_comment",
    "resolve_review_thread",
    "unresolve_review_thread",
    "create_pull_request_stack",
    "add_to_pull_request_stack",
    "unstack_pull_requests",
];
const READS: &[&str] = &[
    "github.issue.get",
    "github.issue_comment.get",
    "github.issue_comments.list",
    "github.issue.search",
    "github.pull_request.get",
    "github.pull_request.queue_state.get",
    "github.pr.review_threads",
];
/// The reviewed reads a scheduled poll may be granted on a handle connection:
/// the import's module reads plus the issue timeline, which actor enrichment
/// reads when an event's comment window names nobody.
const POLL_READS: &[&str] = &[
    "github.issue.get",
    "github.issue_comment.get",
    "github.issue_comments.list",
    "github.issue_timeline.list",
    "github.issue.search",
];
/// The read actions each imported handle grants the prefrontal module.
const PREFRONTAL_READS: &[&str] = crate::github::reads::BOT_ACTIONS;
/// The only writes each imported handle grants the prefrontal module. This
/// carries over the invoke grant on `add_reaction` that prefrontal-core holds
/// today on every per-project GitHub connection, which it uses for the eyes
/// reaction that marks an issue or pull request as seen. The agent's own
/// grant on the handle must still cover each request.
const PREFRONTAL_WRITES: &[&str] = &["add_reaction"];

/// Every action selector on prefrontal-core's module grant for one handle.
pub(crate) fn prefrontal_selectors() -> Vec<String> {
    PREFRONTAL_READS
        .iter()
        .chain(PREFRONTAL_WRITES)
        .map(|action| (*action).to_owned())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub version: String,
    pub handles: Vec<InventoryHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryHandle {
    pub app_handle_id: String,
    pub agent_id: String,
    pub app_id: i64,
    pub installation_id: Option<i64>,
    pub credential_id: String,
    pub status: String,
    pub grants: Vec<AgentPermission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPermission {
    pub action: String,
    pub repository: String,
    pub provenance: String,
    pub policy: String,
}

/// The credential generation an imported handle row starts at. The import's
/// installation read uses the same generation, so the token it caches is the
/// one dispatch asks for once the row exists.
const IMPORTED_CREDENTIAL_GENERATION: i64 = 0;

/// No token is retained: the vault-supplied installation token is handed only
/// to the read-only repository lister and cannot be supplied by the caller.
pub trait InstallationReader {
    fn repositories_page(
        &self,
        token: &crate::credentials::ResolvedCredential,
        page: usize,
        per_page: usize,
    ) -> Result<Value, String>;
}

pub struct GithubApiReader {
    client: reqwest::blocking::Client,
}

impl Default for GithubApiReader {
    fn default() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                // Drop idle keep-alive connections well before a server's own
                // keep-alive timeout could close them; see
                // `http_support::POOLED_CONNECTION_IDLE_LIMIT`, which the MCP
                // and REST transports use too.
                .pool_idle_timeout(crate::http_support::POOLED_CONNECTION_IDLE_LIMIT)
                .build()
                .expect("static GitHub client settings"),
        }
    }
}

impl InstallationReader for GithubApiReader {
    fn repositories_page(
        &self,
        token: &crate::credentials::ResolvedCredential,
        page: usize,
        per_page: usize,
    ) -> Result<Value, String> {
        // GitHub REST: https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation
        // GET /installation/repositories accepts an installation access token and page/per_page.
        let bearer = std::str::from_utf8(token.payload()).map_err(|_| "credential_invalid")?;
        let response = self
            .client
            .get("https://api.github.com/installation/repositories")
            .query(&[("page", page), ("per_page", per_page)])
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "plexus-github-control")
            .bearer_auth(bearer)
            .send()
            .map_err(|_| "installation_read_failed")?;
        if !response.status().is_success() {
            return Err(format!(
                "installation_read_failed{{status: {}}}",
                response.status().as_u16()
            ));
        }
        response
            .json()
            .map_err(|_| "installation_response_invalid".into())
    }
}

/// Every repository the handle's installation token can read. `generation`
/// must be the handle row's own credential generation: the credential provider
/// caches tokens per handle generation. An import of an existing handle uses
/// its live generation rather than the initial generation of new imports.
fn resolve_repositories(
    provider: &dyn HandleCredentialProvider,
    reader: &dyn InstallationReader,
    handle: &InventoryHandle,
    generation: i64,
    now: i64,
) -> Result<Vec<String>, String> {
    let credential = provider
        .prepare(&handle.app_handle_id, generation, &handle.credential_id)
        .map_err(|code| {
            if let Some(fields) = code.strip_suffix('}') {
                // The code already carries brace detail (its failure class);
                // add the credential id as one more field in the same braces.
                format!("{fields}, credential_id: {}}}", handle.credential_id)
            } else {
                format!("{code}{{credential_id: {}}}", handle.credential_id)
            }
        })?;
    let started = std::time::Instant::now();
    let completed = pagination::walk(
        ListRead::InstallationRepositories,
        now,
        || now.saturating_add(started.elapsed().as_millis().min(i64::MAX as u128) as i64),
        |page| {
            reader
                .repositories_page(&credential, page.page, page.per_page)
                .map_err(|_| WalkError::ReadFailed)
        },
    )
    .map_err(|error| format!("installation_repositories_{error:?}"))?;
    let mut repositories = BTreeSet::new();
    for item in completed.items() {
        let name = item
            .get("full_name")
            .and_then(Value::as_str)
            .ok_or("installation_response_invalid")?;
        if crate::github::resolver::split_repository(name).is_err() {
            return Err("installation_response_invalid".into());
        }
        if !repositories.insert(crate::github::canonical_repository(name)) {
            return Err("installation_response_invalid".into());
        }
    }
    Ok(repositories.into_iter().collect())
}

fn validate(inventory: &Inventory) -> Result<(), String> {
    if inventory.version != "github-grant-import.v1" {
        return Err("inventory_version_invalid".into());
    }
    let mut agents = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for row in &inventory.handles {
        if row.app_handle_id.is_empty()
            || row.agent_id.is_empty()
            || row.app_id <= 0
            || row.credential_id != crate::github::credential::app_reference(&row.app_handle_id)
            || !matches!(row.status.as_str(), "enabled" | "disabled")
            || !agents.insert(&row.agent_id)
            || !ids.insert(&row.app_handle_id)
            || !credentials.insert(&row.credential_id)
        {
            return Err("inventory_handle_invalid".into());
        }
        let mut pairs = BTreeSet::new();
        for grant in &row.grants {
            if grant.provenance.is_empty()
                || !matches!(grant.policy.as_str(), "allow" | "block")
                || !WRITES.contains(&grant.action.as_str())
                    && !READS.contains(&grant.action.as_str())
                || !pairs.insert((&grant.action, &grant.repository))
                || crate::github::resolver::split_repository(&grant.repository).is_err()
            {
                return Err("inventory_grant_invalid".into());
            }
        }
    }
    Ok(())
}

/// The agent's grant rows and their dry-run matrix: every allowed inventory
/// row, plus the closure of the allowed writes under
/// [`effects::implied_by_write`], on the same repository.
///
/// The inventory states abilities; the facade authorizes every read and leg a
/// request dispatches against the agent's grant for that exact action, so the
/// import mints those too. An implied action is minted once per repository,
/// named after the first write (in name order) that implies it, and its matrix
/// row lists every allowed write that implies it. A `block` row withholds only
/// its own action: what a blocked write would imply is minted only when an
/// allowed write implies it as well. A `block` row naming an action that an
/// allowed write implies contradicts that write, and the inventory is refused
/// rather than guessing which of the two the operator meant.
fn agent_grants(item: &InventoryHandle) -> Result<(Vec<GithubImportedGrant>, Vec<Value>), String> {
    let explicit: BTreeSet<(&str, &str)> = item
        .grants
        .iter()
        .filter(|row| row.policy == "allow")
        .map(|row| (row.action.as_str(), row.repository.as_str()))
        .collect();
    // (implied action, repository) -> the allowed writes implying it there.
    let mut implied: BTreeMap<(&'static str, &str), BTreeSet<&str>> = BTreeMap::new();
    for row in item.grants.iter().filter(|row| row.policy == "allow") {
        for action in effects::implied_by_write(&row.action, WRITES) {
            implied
                .entry((action, row.repository.as_str()))
                .or_default()
                .insert(row.action.as_str());
        }
    }
    for row in item.grants.iter().filter(|row| row.policy == "block") {
        if let Some(writes) = implied.get(&(row.action.as_str(), row.repository.as_str())) {
            return Err(format!(
                "inventory_block_contradicts_implied{{action: {}, repository: {}, implied_by: {}}}",
                row.action,
                row.repository,
                writes.iter().copied().collect::<Vec<_>>().join(",")
            ));
        }
    }
    let mut grants: Vec<GithubImportedGrant> = item
        .grants
        .iter()
        .filter(|grant| grant.policy == "allow")
        .map(|grant| GithubImportedGrant {
            action: grant.action.clone(),
            repository: grant.repository.clone(),
            provenance: grant.provenance.clone(),
        })
        .collect();
    let mut matrix: Vec<Value> = item
        .grants
        .iter()
        .map(|row| json!({"action":row.action,"repository":row.repository,"policy":row.policy,"provenance":row.provenance,"implied":false}))
        .collect();
    for ((action, repository), writes) in implied {
        // An inventory row that grants the action outright already covers it.
        if explicit.contains(&(action, repository)) {
            continue;
        }
        let first = writes.iter().next().expect("an implied action has a write");
        let provenance = format!("implied-by-{first}");
        matrix.push(
            json!({"action":action,"repository":repository,"policy":"allow",
            "provenance":provenance,"implied":true,"implied_by":writes}),
        );
        grants.push(GithubImportedGrant {
            action: action.to_owned(),
            repository: repository.to_owned(),
            provenance,
        });
    }
    // Grants have action scope, not repository scope; the matrix keeps the
    // repository evidence while storage needs only one grant for each action.
    let mut actions = BTreeSet::new();
    grants.retain(|grant| actions.insert(grant.action.clone()));
    Ok((grants, matrix))
}

/// The policies that let an imported agent's grants take effect.
///
/// Governance composes the module effect (or, with no module policy, the
/// catalog default, which is ask_first for every write) with the agent effect,
/// taking the stricter of block > ask_first > allow. An agent allow alone
/// therefore cannot lift the default, so every granted write, including its
/// implied mutation legs, gets a module allow. Reads default to allow and get
/// no module policy.
///
/// Each inventory row gets an agent policy with its own effect. Implied legs of
/// an allowed write get an agent allow. Legs that only a blocked write implies
/// get an agent block, so the block covers what the blocked write would have
/// dispatched without withdrawing anything an allowed write still needs.
fn policies(item: &InventoryHandle, grants: &[GithubImportedGrant]) -> Vec<GithubImportedPolicy> {
    let is_write = |action: &str| !action.starts_with("github.");
    let granted: BTreeSet<&str> = grants.iter().map(|grant| grant.action.as_str()).collect();
    let mut agent: BTreeMap<&str, &str> = BTreeMap::new();
    for row in &item.grants {
        agent.insert(row.action.as_str(), row.policy.as_str());
    }
    for action in granted.iter().filter(|action| is_write(action)) {
        agent.entry(action).or_insert("allow");
    }
    for row in item.grants.iter().filter(|row| row.policy == "block") {
        for action in effects::implied_by_write(&row.action, WRITES) {
            if is_write(action) && !granted.contains(action) {
                agent.entry(action).or_insert("block");
            }
        }
    }
    let module = granted
        .iter()
        .filter(|action| is_write(action))
        .map(|action| GithubImportedPolicy {
            agent: false,
            action: (*action).to_owned(),
            effect: "allow".into(),
        });
    module
        .chain(
            agent
                .into_iter()
                .map(|(action, effect)| GithubImportedPolicy {
                    agent: true,
                    action: action.to_owned(),
                    effect: effect.to_owned(),
                }),
        )
        .collect()
}

/// The connection id an import mints for a handle. Spelled once so the
/// import itself, the onboarding preview, and the runtime transport
/// registration after an applied import cannot drift apart: a registration
/// that names any other id would miss the committed connection.
pub fn handle_connection_id(app_handle_id: &str) -> String {
    format!("github-handle-{app_handle_id}")
}

/// Import is a single-use operation. All network reads precede the SQLite
/// transaction; neither an unlisted repository nor a failed read can activate a row.
pub fn import(
    store: &PlexusStore,
    principal: &str,
    inventory: &Inventory,
    provider: &dyn HandleCredentialProvider,
    reader: &dyn InstallationReader,
    now: i64,
    dry_run: bool,
) -> Result<Value, String> {
    import_with(store, principal, inventory, dry_run, |item, generation| {
        resolve_repositories(provider, reader, item, generation, now)
    })
}

/// The repositories one handle's installation lists, read with the handle's
/// own token exactly as [`import`] reads them before importing it: at the
/// stored handle's credential generation, or the initial one for a handle not
/// imported yet. [`import_listed`], [`probe_listed`] and [`bind_listed`] take
/// this listing, so one read can serve an import, a probe and a bind.
pub fn installation_repositories(
    store: &PlexusStore,
    handle: &InventoryHandle,
    provider: &dyn HandleCredentialProvider,
    reader: &dyn InstallationReader,
    now: i64,
) -> Result<Vec<String>, String> {
    resolve_repositories(
        provider,
        reader,
        handle,
        handle_generation(store, handle)?,
        now,
    )
}

/// The credential generation an installation read for `handle` uses.
fn handle_generation(store: &PlexusStore, handle: &InventoryHandle) -> Result<i64, String> {
    Ok(store
        .github_handle_and_bindings(&handle.app_handle_id)
        .map_err(|_| "store_failure")?
        .map_or(IMPORTED_CREDENTIAL_GENERATION, |(handle, _)| {
            handle.credential_generation
        }))
}

/// [`import`] with each handle's installation listing already read (see
/// [`installation_repositories`]), keyed by app handle id. A handle without a
/// listing is refused with `installation_not_listed`.
pub fn import_listed(
    store: &PlexusStore,
    principal: &str,
    inventory: &Inventory,
    listings: &BTreeMap<String, Vec<String>>,
    dry_run: bool,
) -> Result<Value, String> {
    import_with(store, principal, inventory, dry_run, |item, _| {
        listings
            .get(&item.app_handle_id)
            .cloned()
            .ok_or_else(|| "installation_not_listed".to_string())
    })
}

/// The import itself, with `list` supplying each handle's installation
/// repositories given the handle and its credential generation.
fn import_with(
    store: &PlexusStore,
    principal: &str,
    inventory: &Inventory,
    dry_run: bool,
    mut list: impl FnMut(&InventoryHandle, i64) -> Result<Vec<String>, String>,
) -> Result<Value, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    // Repository names are compared, bound and reported in canonical form.
    let mut inventory = inventory.clone();
    for row in &mut inventory.handles {
        for grant in &mut row.grants {
            grant.repository = crate::github::canonical_repository(&grant.repository);
        }
    }
    let inventory = &inventory;
    validate(inventory)?;
    let mut rows = Vec::new();
    let mut matrix = BTreeMap::new();
    let mut module_grants = Vec::new();
    let mut policy_plan = BTreeMap::new();
    for item in &inventory.handles {
        let generation = handle_generation(store, item)?;
        let repositories = list(item, generation)?;
        let reachable: BTreeSet<_> = repositories.iter().map(String::as_str).collect();
        for permission in &item.grants {
            if !reachable.contains(permission.repository.as_str()) {
                return Err(format!(
                    "repository_unreachable{{repository: {}}}",
                    permission.repository
                ));
            }
        }
        let bound: BTreeSet<String> = item
            .grants
            .iter()
            .map(|row| row.repository.clone())
            .collect();
        // Existing grants have no repository selector. Refuse partial matrices
        // instead of silently extending one permitted action to another bound repo.
        for action in item
            .grants
            .iter()
            .filter(|row| row.policy == "allow")
            .map(|row| &row.action)
        {
            if bound.iter().any(|repo| {
                !item.grants.iter().any(|grant| {
                    &grant.action == action && &grant.repository == repo && grant.policy == "allow"
                })
            }) {
                return Err("inventory_repository_scope_unrepresentable".into());
            }
        }
        let (grants, agent_matrix) = agent_grants(item)?;
        let policies = policies(item, &grants);
        policy_plan.insert(
            item.agent_id.clone(),
            policies
                .iter()
                .map(|policy| {
                    json!({"level": if policy.agent {"agent"} else {"module"},
                    "action":policy.action,"effect":policy.effect})
                })
                .collect::<Vec<_>>(),
        );
        let mut aft: BTreeSet<String> = grants.iter().map(|row| row.action.clone()).collect();
        aft.extend(READS.iter().map(|action| (*action).to_owned()));
        aft.extend(
            crate::github::reads::bot::GRANT_ACTIONS
                .iter()
                .map(|action| (*action).to_owned()),
        );
        let connection_id = handle_connection_id(&item.app_handle_id);
        module_grants.push(json!({"connection_id":connection_id,"grantee_principal":crate::github::AFT_PRINCIPAL,"action_selectors":aft}));
        module_grants.push(json!({"connection_id":connection_id,"grantee_principal":crate::github::PREFRONTAL_PRINCIPAL,"action_selectors":prefrontal_selectors()}));
        matrix.insert(item.agent_id.clone(), agent_matrix);
        rows.push(GithubImportRow {
            handle: GithubHandle {
                app_handle_id: item.app_handle_id.clone(),
                agent_id: item.agent_id.clone(),
                app_id: item.app_id,
                installation_id: item.installation_id,
                credential_reference: item.credential_id.clone(),
                credential_generation: IMPORTED_CREDENTIAL_GENERATION,
                status: item.status.clone(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id,
            },
            repositories: bound.into_iter().collect(),
            grants,
            module_actions: aft.into_iter().collect(),
            policies,
        });
    }
    let plan = json!({"agents":matrix,"module_grants":module_grants,"policies":policy_plan});
    store
        .import_github_handles_checked(&rows, dry_run)
        .map_err(|error| format!("import_failed: {error}"))??;
    Ok(plan)
}

/// Grant scheduled-poll authority for reviewed reads on one already-imported
/// handle (the poll form of `github.handle.grant`).
///
/// Only reads are grantable: a write is refused by name, because a timer must
/// never carry authority to change anything. The grantee is the handle
/// connection's own principal, which owns the subscriptions a poll runs for.
/// The connection's ceiling widens by exactly the listed reads, in the same
/// transaction that mints the grant. `dry_run` returns the plan and writes
/// nothing.
pub fn grant_poll(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    actions: &[String],
    dry_run: bool,
) -> Result<Value, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    if app_handle_id.is_empty() {
        return Err("app_handle_id_required".into());
    }
    if actions.is_empty() {
        return Err("actions_required".into());
    }
    if let Some(action) = actions
        .iter()
        .find(|action| WRITES.contains(&action.as_str()))
    {
        return Err(format!("poll_write_refused{{action: {action}}}"));
    }
    if let Some(action) = actions
        .iter()
        .find(|action| !POLL_READS.contains(&action.as_str()))
    {
        return Err(format!("action_not_grantable{{action: {action}}}"));
    }
    let listed: BTreeSet<&str> = actions.iter().map(String::as_str).collect();
    let request = crate::storage::github_store::GithubHandlePollGrant {
        app_handle_id: app_handle_id.to_owned(),
        actions: listed.iter().map(|action| (*action).to_owned()).collect(),
        dry_run,
    };
    store
        .grant_github_handle_poll(&request)
        .map_err(|error| format!("grant_failed: {error}"))?
}

/// Upgrade module authority for bot reads without changing write grants or policies.
pub fn grant_read(
    store: &PlexusStore,
    principal: &str,
    request: &crate::storage::github_store::GithubHandleReadGrant,
) -> Result<Value, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    store
        .grant_github_handle_read(request)
        .map_err(|error| format!("grant_failed: {error}"))?
}

/// Add write abilities to one already-imported handle without re-importing it.
///
/// Each action must be one of the import's grantable writes, and it is
/// expanded with the same [`effects::implied_by_write`] closure the import
/// uses, so the new authority covers every read and leg its requests dispatch.
/// The handle connection's ceiling widens by exactly that expanded set; the
/// agent and `module` grants and the `effect` policies follow the import's
/// shape. Policies cover every write in the expanded set, as the import's do,
/// so an implied mutation leg is governed by the same effect as the write that
/// dispatches it.
///
/// `dry_run` returns the plan and writes nothing.
pub fn grant(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    actions: &[String],
    module: &str,
    effect: &str,
    dry_run: bool,
) -> Result<Value, String> {
    let request = grant_request(principal, app_handle_id, actions, module, effect, dry_run)?;
    store
        .grant_github_handle(&request)
        .map_err(|error| format!("grant_failed: {error}"))?
}

/// Upgrade all enabled handles with the same explicit write intent. The store
/// validates the reviewed facade actions and applies every plan atomically.
pub fn grant_all(
    store: &PlexusStore,
    principal: &str,
    actions: &[String],
    module: &str,
    effect: &str,
    dry_run: bool,
) -> Result<Value, String> {
    let request = grant_request(
        principal,
        "all enabled handles",
        actions,
        module,
        effect,
        dry_run,
    )?;
    store
        .grant_all_github_handles(&request)
        .map_err(|error| format!("grant_failed: {error}"))?
}

fn grant_request(
    principal: &str,
    app_handle_id: &str,
    actions: &[String],
    module: &str,
    effect: &str,
    dry_run: bool,
) -> Result<crate::storage::github_store::GithubHandleGrant, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    if app_handle_id.is_empty() {
        return Err("app_handle_id_required".into());
    }
    if actions.is_empty() {
        return Err("actions_required".into());
    }
    if let Some(action) = actions
        .iter()
        .find(|action| !WRITES.contains(&action.as_str()))
    {
        return Err(format!("action_not_grantable{{action: {action}}}"));
    }
    // The carrying module must be one supervised module, named outright: a
    // wildcard grantee would hand the abilities to every module at once.
    if module
        .strip_prefix("reserved:")
        .is_none_or(|id| id.is_empty() || id.contains('*'))
    {
        return Err(format!("module_invalid{{module: {module}}}"));
    }
    if !matches!(effect, "allow" | "ask_first" | "block") {
        return Err(format!("effect_invalid{{effect: {effect}}}"));
    }
    let listed: BTreeSet<&str> = actions.iter().map(String::as_str).collect();
    let mut expanded: BTreeSet<&str> = listed.clone();
    for action in &listed {
        expanded.extend(effects::implied_by_write(action, WRITES));
    }
    Ok(crate::storage::github_store::GithubHandleGrant {
        app_handle_id: app_handle_id.to_owned(),
        module: module.to_owned(),
        actions: listed.iter().map(|action| (*action).to_owned()).collect(),
        expanded: expanded.iter().map(|action| (*action).to_owned()).collect(),
        policy_actions: expanded
            .iter()
            .filter(|action| !action.starts_with("github."))
            .map(|action| (*action).to_owned())
            .collect(),
        effect: effect.to_owned(),
        dry_run,
    })
}

pub fn bindings_read(
    store: &PlexusStore,
    principal: &str,
    connection_id: &str,
) -> Result<Value, crate::governance::Denial> {
    let refusal = store
        .github_module_grant_refusal(connection_id, principal)
        .map_err(|_| crate::governance::Denial::StoreFailure)?;
    if let Some(cause) = refusal {
        return Err(crate::governance::Denial::GrantRefusal(
            crate::grant_refusal::GrantRefusal::new(
                crate::grant_refusal::GrantTarget::new(
                    crate::grant_refusal::Layer::Module,
                    principal,
                    "github",
                    Some(connection_id),
                    "bindings.read",
                ),
                cause,
            ),
        ));
    }
    store
        .read_github_bindings_for_connection(connection_id, principal)
        .map_err(|_| crate::governance::Denial::StoreFailure)
}

pub fn bindings_read_for_agent(
    store: &PlexusStore,
    principal: &str,
    agent_id: &str,
) -> Result<Value, crate::governance::Denial> {
    store
        .read_github_bindings_for_agent(agent_id, principal)
        .map_err(|_| crate::governance::Denial::StoreFailure)
}

/// A stored handle in the shape [`resolve_repositories`] reads, so the probe
/// and the bind list the installation exactly as the import does: with the
/// handle's own credential.
fn installation_item(handle: GithubHandle) -> InventoryHandle {
    InventoryHandle {
        app_handle_id: handle.app_handle_id,
        agent_id: handle.agent_id,
        app_id: handle.app_id,
        installation_id: handle.installation_id,
        credential_id: handle.credential_reference,
        status: handle.status,
        grants: Vec::new(),
    }
}

/// Bind more repositories to one imported handle.
///
/// Each repository must be `owner/name`, share the handle's owner, not be
/// bound to a different handle, and be listed by the handle's own installation
/// (read with its token, as the import and the probe read it). The installation
/// is listed before the store transaction opens; every repository is then
/// checked and bound inside that one transaction, so a refusal on any of them
/// leaves none bound. Agent grants carry no repository, so the new binding is
/// what extends the handle's writes to the repository.
///
/// `dry_run` returns the plan and writes nothing.
#[allow(clippy::too_many_arguments)]
pub fn bind(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    repositories: &[String],
    provider: &dyn HandleCredentialProvider,
    reader: &dyn InstallationReader,
    now: i64,
    dry_run: bool,
) -> Result<Value, String> {
    bind_with(
        store,
        principal,
        app_handle_id,
        repositories,
        dry_run,
        |handle| {
            let generation = handle.credential_generation;
            resolve_repositories(
                provider,
                reader,
                &installation_item(handle),
                generation,
                now,
            )
        },
    )
}

/// [`bind`] with the handle's installation listing already read (see
/// [`installation_repositories`]).
pub fn bind_listed(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    repositories: &[String],
    installation: &[String],
    dry_run: bool,
) -> Result<Value, String> {
    bind_with(
        store,
        principal,
        app_handle_id,
        repositories,
        dry_run,
        |_| Ok(installation.to_vec()),
    )
}

/// The bind itself, with `list` supplying the stored handle's installation
/// repositories.
fn bind_with(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    repositories: &[String],
    dry_run: bool,
    list: impl FnOnce(GithubHandle) -> Result<Vec<String>, String>,
) -> Result<Value, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    if app_handle_id.is_empty() {
        return Err("app_handle_id_required".into());
    }
    if repositories.is_empty() {
        return Err("repositories_required".into());
    }
    let mut listed: Vec<String> = Vec::new();
    for repository in repositories {
        if crate::github::resolver::split_repository(repository).is_err() {
            return Err(format!("repository_invalid{{repository: {repository}}}"));
        }
        let repository = crate::github::canonical_repository(repository);
        if !listed.contains(&repository) {
            listed.push(repository);
        }
    }
    // Refuse an unknown or disabled handle before spending a vendor read on
    // it; the store checks both again inside its transaction.
    let (handle, _) = store
        .github_handle_and_bindings(app_handle_id)
        .map_err(|_| "store_failure")?
        .ok_or("agent_handle_unknown")?;
    if handle.status != "enabled" {
        return Err(format!(
            "agent_handle_disabled{{app_handle_id: {app_handle_id}}}"
        ));
    }
    let installation = list(handle)?;
    store
        .bind_github_handle_repos(&crate::storage::github_store::GithubHandleBind {
            app_handle_id: app_handle_id.to_owned(),
            repositories: listed,
            installation,
            dry_run,
        })
        .map_err(|error| format!("bind_failed: {error}"))?
}

/// Check a bind that will run right after `handle` is imported, before the
/// handle exists: the checks [`bind`] makes, against the repositories the
/// import binds (`imported`) and the installation listing already read. The
/// result has the shape of a bind preview: `add` and `already_bound`.
pub fn bind_after_import_preview(
    store: &PlexusStore,
    handle: &InventoryHandle,
    imported: &[String],
    repositories: &[String],
    installation: &[String],
) -> Result<Value, String> {
    if repositories.is_empty() {
        return Err("repositories_required".into());
    }
    let installation: BTreeSet<String> = installation
        .iter()
        .map(|name| crate::github::canonical_repository(name))
        .collect();
    let imported: BTreeSet<String> = imported
        .iter()
        .map(|name| crate::github::canonical_repository(name))
        .collect();
    let owner_of = |name: &str| name.split_once('/').map(|(owner, _)| owner.to_owned());
    let mut listed: Vec<String> = Vec::new();
    for repository in repositories {
        if crate::github::resolver::split_repository(repository).is_err() {
            return Err(format!("repository_invalid{{repository: {repository}}}"));
        }
        let repository = crate::github::canonical_repository(repository);
        if !listed.contains(&repository) {
            listed.push(repository);
        }
    }
    // The bind takes the owner of the handle's first bound repository, or of
    // the first listed one when the handle has none.
    let owner = imported
        .iter()
        .next()
        .or(listed.first())
        .and_then(|name| owner_of(name));
    let mut add = Vec::new();
    let mut already_bound = Vec::new();
    for repository in listed {
        if owner_of(&repository) != owner {
            return Err(format!(
                "binding_owner_mismatch{{repository: {repository}, owner: {}}}",
                owner.as_deref().unwrap_or("")
            ));
        }
        if imported.contains(&repository) {
            already_bound.push(repository);
            continue;
        }
        if let Some((_, connection)) = store
            .github_handle_connection_for_repo(&repository)
            .map_err(|_| "store_failure")?
        {
            return Err(format!(
                "repository_bound_elsewhere{{repository: {repository}, connection_id: {connection}}}"
            ));
        }
        if !installation.contains(&repository) {
            return Err(format!(
                "repository_not_in_installation{{repository: {repository}}}"
            ));
        }
        add.push(repository);
    }
    Ok(json!({
        "app_handle_id": handle.app_handle_id,
        "dry_run": true,
        "add": add,
        "already_bound": already_bound,
    }))
}

/// Unbinding narrows authority and requires no credential or additional
/// proof of authorization beyond the direct operator principal.
/// Grants and policies remain attached to the handle.
pub fn unbind(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    repository: &str,
    request_id: &str,
    dry_run: bool,
) -> Result<Value, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    if app_handle_id.is_empty() {
        return Err("app_handle_id_required".into());
    }
    if crate::github::resolver::split_repository(repository).is_err() {
        return Err(format!("repository_invalid{{repository: {repository}}}"));
    }
    store
        .unbind_github_handle_repo(principal, app_handle_id, repository, request_id, dry_run)
        .map_err(|error| format!("unbind_failed: {error}"))?
}

pub fn probe(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    provider: &dyn HandleCredentialProvider,
    reader: &dyn InstallationReader,
    now: i64,
) -> Result<Value, String> {
    probe_with(store, principal, app_handle_id, now, |handle| {
        let generation = handle.credential_generation;
        resolve_repositories(
            provider,
            reader,
            &installation_item(handle),
            generation,
            now,
        )
    })
}

/// [`probe`] with the handle's installation listing already read (see
/// [`installation_repositories`]).
pub fn probe_listed(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    installation: &[String],
    now: i64,
) -> Result<Value, String> {
    probe_with(store, principal, app_handle_id, now, |_| {
        Ok(installation.to_vec())
    })
}

/// The probe itself, with `list` supplying the stored handle's installation
/// repositories.
fn probe_with(
    store: &PlexusStore,
    principal: &str,
    app_handle_id: &str,
    now: i64,
    list: impl FnOnce(GithubHandle) -> Result<Vec<String>, String>,
) -> Result<Value, String> {
    if principal != "direct" {
        return Err("operator_authority_required".into());
    }
    let binding_generation = store
        .github_repo_binding_generation()
        .map_err(|_| "store_failure")?;
    let (handle, bound) = store
        .github_handle_and_bindings(app_handle_id)
        .map_err(|_| "store_failure")?
        .ok_or("agent_handle_unknown")?;
    let generation = handle.credential_generation;
    let reachable = list(handle)?;
    let available: BTreeSet<_> = reachable.iter().map(String::as_str).collect();
    for repository in &bound {
        if !available.contains(repository.as_str()) {
            store
                .prove_github_handle(app_handle_id, generation, binding_generation, None)
                .map_err(|_| "store_failure")?;
            return Err(format!(
                "repository_unreachable{{repository: {repository}}}"
            ));
        }
    }
    if !store
        .prove_github_handle(app_handle_id, generation, binding_generation, Some(now))
        .map_err(|_| "store_failure")?
    {
        return Err("store_failure".into());
    }
    Ok(json!({"app_handle_id":app_handle_id,"repositories":bound,"proven_at":now}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn implied(write: &str) -> Vec<&'static str> {
        effects::implied_by_write(write, WRITES)
            .into_iter()
            .collect()
    }

    #[test]
    fn each_grantable_write_implies_exactly_its_reads_and_legs() {
        for write in ["enqueue_pull_request", "dequeue_pull_request"] {
            assert_eq!(
                effects::implied_by_write(write, WRITES),
                BTreeSet::from(["github.pull_request.queue_state.get"]),
                "{write}"
            );
        }
        assert_eq!(implied("add_issue_comment"), Vec::<&str>::new());
        assert_eq!(implied("add_pr_review"), Vec::<&str>::new());
        assert_eq!(implied("add_reaction"), Vec::<&str>::new());
        assert_eq!(implied("create_issue"), Vec::<&str>::new());
        assert_eq!(implied("create_pull_request"), Vec::<&str>::new());
        assert_eq!(
            implied("update_issue_comment"),
            ["github.issue_comment.get", "github.issue_comments.list"]
        );
        assert_eq!(
            implied("edit_issue"),
            [
                "add_issue_assignees",
                "add_issue_labels",
                "github.issue.get",
                "remove_issue_assignees",
                "remove_issue_label"
            ]
        );
        // A close carrying a comment also dispatches add_issue_comment, but
        // that is its own grantable ability and is never implied.
        assert_eq!(implied("close_issue"), Vec::<&str>::new());
        assert_eq!(implied("reopen_issue"), Vec::<&str>::new());
    }

    #[test]
    fn no_grantable_write_is_implied_by_another() {
        for write in WRITES {
            for other in WRITES {
                assert!(
                    !effects::implied_by_write(other, WRITES).contains(write),
                    "{other} implies {write}"
                );
            }
        }
    }

    /// Every action a request kind dispatches is either the kind's own write,
    /// another grantable write, or implied by the kind's write, so an agent
    /// granted the right writes is never refused a read or leg.
    #[test]
    fn every_request_kind_is_covered_by_its_write_and_the_grantable_writes() {
        for kind in effects::REQUEST_KINDS {
            let write = effects::primary_action(kind).unwrap();
            assert!(WRITES.contains(&write), "{kind}: {write} is not grantable");
            let covered = effects::implied_by_write(write, WRITES);
            for read in effects::reads_for_kind(kind).unwrap() {
                assert!(covered.contains(read), "{kind}: read {read} not implied");
            }
        }
    }

    fn handle(rows: &[(&str, &str)]) -> InventoryHandle {
        InventoryHandle {
            app_handle_id: "app".into(),
            agent_id: "agent".into(),
            app_id: 1,
            installation_id: None,
            credential_id: "github_app:app".into(),
            status: "enabled".into(),
            grants: rows
                .iter()
                .map(|(action, policy)| AgentPermission {
                    action: (*action).into(),
                    repository: "org/repo".into(),
                    provenance: format!("row-{action}"),
                    policy: (*policy).into(),
                })
                .collect(),
        }
    }

    fn granted(rows: &[(&str, &str)]) -> Vec<String> {
        let mut actions: Vec<String> = agent_grants(&handle(rows))
            .unwrap()
            .0
            .into_iter()
            .map(|grant| grant.action)
            .collect();
        actions.sort();
        actions
    }

    #[test]
    fn a_blocked_write_withholds_what_only_it_implies() {
        assert_eq!(
            granted(&[("close_issue", "block"), ("add_reaction", "allow")]),
            ["add_reaction"]
        );
    }

    #[test]
    fn a_blocked_write_keeps_what_another_allowed_write_implies() {
        assert_eq!(
            granted(&[("close_issue", "block"), ("edit_issue", "allow")]),
            [
                "add_issue_assignees",
                "add_issue_labels",
                "edit_issue",
                "github.issue.get",
                "remove_issue_assignees",
                "remove_issue_label"
            ]
        );
    }

    #[test]
    fn a_block_on_an_action_an_allowed_write_implies_is_refused() {
        assert_eq!(
            agent_grants(&handle(&[
                ("github.issue.get", "block"),
                ("close_issue", "allow"),
                ("edit_issue", "allow"),
            ]))
            .unwrap_err(),
            "inventory_block_contradicts_implied{action: github.issue.get, repository: org/repo, implied_by: edit_issue}"
        );
    }

    #[test]
    fn dry_run_matrix_marks_implied_rows_and_the_writes_implying_them() {
        let (grants, matrix) = agent_grants(&handle(&[("update_issue_comment", "allow")])).unwrap();
        assert_eq!(
            matrix,
            vec![
                json!({"action":"update_issue_comment","repository":"org/repo","policy":"allow",
                    "provenance":"row-update_issue_comment","implied":false}),
                json!({"action":"github.issue_comment.get","repository":"org/repo","policy":"allow",
                    "provenance":"implied-by-update_issue_comment","implied":true,
                    "implied_by":["update_issue_comment"]}),
                json!({"action":"github.issue_comments.list","repository":"org/repo","policy":"allow",
                    "provenance":"implied-by-update_issue_comment","implied":true,
                    "implied_by":["update_issue_comment"]}),
            ]
        );
        assert_eq!(grants.len(), 3);
    }

    fn policy_rows(rows: &[(&str, &str)]) -> Vec<(bool, String, String)> {
        let item = handle(rows);
        let (grants, _) = agent_grants(&item).unwrap();
        policies(&item, &grants)
            .into_iter()
            .map(|policy| (policy.agent, policy.action, policy.effect))
            .collect()
    }

    #[test]
    fn a_blocked_write_and_the_legs_only_it_implies_get_agent_blocks() {
        let row = |agent: bool, action: &str, effect: &str| (agent, action.into(), effect.into());
        assert_eq!(
            policy_rows(&[("edit_issue", "block"), ("add_reaction", "allow")]),
            vec![
                row(false, "add_reaction", "allow"),
                row(true, "add_issue_assignees", "block"),
                row(true, "add_issue_labels", "block"),
                row(true, "add_reaction", "allow"),
                row(true, "edit_issue", "block"),
                row(true, "remove_issue_assignees", "block"),
                row(true, "remove_issue_label", "block"),
            ]
        );
        // Reads never get policies here: github.issue.get stays granted to
        // reopen and is left to its allow default.
        assert_eq!(
            policy_rows(&[("close_issue", "block"), ("reopen_issue", "allow")]),
            vec![
                row(false, "reopen_issue", "allow"),
                row(true, "close_issue", "block"),
                row(true, "reopen_issue", "allow"),
            ]
        );
    }

    #[test]
    fn an_explicit_row_is_not_duplicated_by_an_implied_one() {
        let (grants, matrix) = agent_grants(&handle(&[
            ("close_issue", "allow"),
            ("github.issue.get", "allow"),
        ]))
        .unwrap();
        assert_eq!(grants.len(), 2);
        assert!(matrix.iter().all(|row| row["implied"] == false));
    }
}
