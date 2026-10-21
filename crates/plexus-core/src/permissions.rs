//! `permissions/v1`: the per-agent GitHub bot grants plexus holds, shaped as
//! rows on the operator's permissions page, and their revocation.
//!
//! Only agent-layer grants are listed. Module-layer grants (the carrier
//! ceilings held for aft, prefrontal-core, basal, broca and direct) and
//! policies (allow, ask_first, block) are not standing grants the operator
//! gave an agent, so they stay off the page.
//!
//! The page shows capabilities, not grant rows. An agent's grants on one bot
//! connection fold into at most three rows, the same for every bot and
//! independent of when each grant was minted:
//!
//! | `scope` token | Grants in the row |
//! |---|---|
//! | `github_bot_speak` | every selector except `create_issue` and `create_pull_request`: comment, edit comment, review, react, edit, close, reopen, assignees, labels, and the reads they depend on |
//! | `github_bot_open_issues` | `create_issue` |
//! | `github_bot_open_pull_requests` | `create_pull_request` |
//!
//! These three tokens are plexus's whole `scope` vocabulary. A selector plexus
//! does not know yet lands in the speak row. A row exists only while at least
//! one of its grants is live.
//!
//! A grant whose selectors span more than one row (`*`, or a list naming
//! `create_issue` beside a comment action) is in every row it touches.
//! Revoking any of those rows removes the whole grant: one grant row cannot
//! be split, and leaving it live would keep authority the operator asked to
//! end.

use std::collections::BTreeMap;

use cortexkit_store::StoreError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::storage::permissions_store::LiveAgentGrant;
use crate::storage::{AuditRecord, PlexusStore};

/// The capability a module declares to serve `permissions.list` and
/// `permissions.revoke`.
pub const CAPABILITY: &str = "permissions/v1";
pub const LIST_METHOD: &str = "permissions.list";
pub const REVOKE_METHOD: &str = "permissions.revoke";
/// The module id rows carry, so the page can address a revoke back here.
const MODULE: &str = "plexus";

/// The selectors with a row of their own. Every other selector is speech.
const CREATE_ISSUE: &str = "create_issue";
const CREATE_PULL_REQUEST: &str = "create_pull_request";

/// One of the three rows a bot connection can have for an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Speak,
    OpenIssues,
    OpenPullRequests,
}

impl Capability {
    pub const ALL: [Capability; 3] = [
        Capability::Speak,
        Capability::OpenIssues,
        Capability::OpenPullRequests,
    ];

    /// The row's `scope` token.
    pub fn scope(self) -> &'static str {
        match self {
            Capability::Speak => "github_bot_speak",
            Capability::OpenIssues => "github_bot_open_issues",
            Capability::OpenPullRequests => "github_bot_open_pull_requests",
        }
    }

    /// The rows one selector puts its grant in. `*` names every action, so
    /// it is in all three.
    fn of_selector(selector: &str) -> &'static [Capability] {
        match selector {
            "*" => &Capability::ALL,
            CREATE_ISSUE => &[Capability::OpenIssues],
            CREATE_PULL_REQUEST => &[Capability::OpenPullRequests],
            _ => &[Capability::Speak],
        }
    }

    /// The rows a grant is in. A grant with no selectors authorizes nothing,
    /// but it is still live authority on record, so it is shown (and can be
    /// revoked) with speech rather than hidden.
    fn of_grant(selectors: &[String]) -> Vec<Capability> {
        let mut rows: Vec<Capability> = selectors
            .iter()
            .flat_map(|selector| Capability::of_selector(selector).iter().copied())
            .collect();
        if rows.is_empty() {
            rows.push(Capability::Speak);
        }
        rows.sort();
        rows.dedup();
        rows
    }
}

/// The opaque row id: a hash of the agent, the connection and the
/// capability. It is derived, not stored, so the same row has the same id on
/// every list for as long as any of its grants is live, however many of its
/// grants come and go.
pub fn row_id(agent_id: &str, connection_id: &str, capability: Capability) -> String {
    // Not `jcs::sha256_hex`: the parts are hashed length-prefixed as a stream,
    // and the id keeps only the first 24 hex characters.
    let mut hasher = Sha256::new();
    for part in [CAPABILITY, agent_id, connection_id, capability.scope()] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("plx_{}", &hex::encode(hasher.finalize())[..24])
}

/// A grant held by a row, as the store keys it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HeldGrant {
    pub principal: String,
    pub grant_id: String,
}

/// One row on the permissions page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRow {
    pub id: String,
    pub agent_id: String,
    pub connection_id: String,
    pub capability: Capability,
    pub bot_login: Option<String>,
    pub repositories: Vec<String>,
    /// The newest `created_at_ms` among the row's grants.
    pub granted_at_ms: i64,
    /// The last expiry among the row's grants; `None` if any never expires.
    pub expires_at_ms: Option<i64>,
    pub grants: Vec<HeldGrant>,
}

/// Fold live agent grants into page rows, sorted by agent, connection and
/// capability so the list is byte-stable between reads.
pub fn rows(grants: &[LiveAgentGrant]) -> Vec<PermissionRow> {
    let mut rows: BTreeMap<(String, String, Capability), PermissionRow> = BTreeMap::new();
    for grant in grants {
        for capability in Capability::of_grant(&grant.action_selectors) {
            let key = (
                grant.agent_id.clone(),
                grant.connection_id.clone(),
                capability,
            );
            let row = rows.entry(key).or_insert_with(|| PermissionRow {
                id: row_id(&grant.agent_id, &grant.connection_id, capability),
                agent_id: grant.agent_id.clone(),
                connection_id: grant.connection_id.clone(),
                capability,
                bot_login: None,
                repositories: Vec::new(),
                granted_at_ms: grant.created_at_ms,
                expires_at_ms: grant.expires_at,
                grants: Vec::new(),
            });
            if row.bot_login.is_none() {
                row.bot_login.clone_from(&grant.bot_login);
                row.repositories.clone_from(&grant.repositories);
            }
            row.granted_at_ms = row.granted_at_ms.max(grant.created_at_ms);
            row.expires_at_ms = match (row.expires_at_ms, grant.expires_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
            row.grants.push(HeldGrant {
                principal: grant.principal.clone(),
                grant_id: grant.grant_id.clone(),
            });
        }
    }
    rows.into_values().collect()
}

/// "a", "a and b", "a, b and c".
fn joined(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

impl PermissionRow {
    fn login(&self) -> &str {
        // Agent grants are minted only on GitHub App handle connections. A
        // handle removed while its grants stay live has no login left to show.
        self.bot_login.as_deref().unwrap_or("an unknown GitHub bot")
    }

    /// What the row covers, for display.
    fn subject_label(&self) -> String {
        let login = self.login();
        match self.capability {
            Capability::Speak if self.repositories.is_empty() => format!("Speak as {login}"),
            Capability::Speak => format!("Speak as {login} on {}", joined(&self.repositories)),
            Capability::OpenIssues => format!("Open issues as {login}"),
            Capability::OpenPullRequests => format!("Open pull requests as {login}"),
        }
    }

    /// One plain sentence that tells the operator what the row lets the agent
    /// do.
    fn scope_label(&self) -> String {
        let login = self.login();
        let what = match self.capability {
            Capability::Speak => {
                "can comment, review, react, edit, close and reopen issues and pull requests"
            }
            Capability::OpenIssues => "can open new issues",
            Capability::OpenPullRequests => "can open new pull requests",
        };
        if self.repositories.is_empty() {
            format!("{login} {what}. No repository is bound to it now.")
        } else {
            format!("{login} {what} on {}.", joined(&self.repositories))
        }
    }

    /// The row as `permissions.list` sends it.
    pub fn to_wire(&self) -> Value {
        let mut row = json!({
            "id": self.id,
            "agent_id": self.agent_id,
            "holder": {"kind": "agent", "agent_id": self.agent_id},
            "module": MODULE,
            "subject_label": self.subject_label(),
            "scope": self.capability.scope(),
            "scope_label": self.scope_label(),
            "granted_at_ms": self.granted_at_ms,
        });
        if let Some(expires_at_ms) = self.expires_at_ms {
            row["expires_at_ms"] = json!(expires_at_ms);
        }
        row
    }
}

/// The permissions-page rows built from the agent-layer grants that are live
/// at `now`, optionally for one agent only. A live grant is one still in
/// `grants` (not revoked) whose expiry, if it has one, is after `now`.
pub fn list(
    store: &PlexusStore,
    agent_id: Option<&str>,
    now: i64,
) -> Result<Vec<PermissionRow>, StoreError> {
    Ok(rows(&store.live_agent_grants(agent_id, now)?))
}

/// What `permissions.revoke` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// At least one live grant of the row was revoked; these are the ones.
    Revoked(Vec<HeldGrant>),
    /// The row has no live grants: an unknown id, a row already revoked, or
    /// one whose grants all expired.
    NotFound,
}

/// Revoke every live grant of the row `id`, and nothing else.
///
/// Each grant goes through [`PlexusStore::revoke_grant`], the path the admin
/// `revoke-grant` takes: the revocation is appended to the journal and
/// fsynced, then one fenced transaction snapshots the row into
/// `grant_revocations` and deletes it. A database restored from before the
/// revoke replays the journal on open, so the grant stays revoked.
///
/// Grants are revoked one at a time. A crash or store error part way leaves
/// every grant before it fully revoked and every grant after it untouched;
/// the row is still listed under the same id, because the id depends only on
/// the agent, the connection and the capability, so a retry finds the rest
/// and finishes. A grant journaled but not yet deleted is removed by the
/// replay on the next open. Each revoked grant gets an audit row; a failed
/// audit append is logged and does not undo the revocation.
pub fn revoke(
    store: &PlexusStore,
    caller: &str,
    id: &str,
    now: i64,
) -> Result<RevokeOutcome, StoreError> {
    let Some(row) = list(store, None, now)?.into_iter().find(|row| row.id == id) else {
        return Ok(RevokeOutcome::NotFound);
    };
    let mut revoked = Vec::new();
    for grant in &row.grants {
        // `revoke_grant` returns false when the grant is no longer in
        // `grants`: a concurrent revoke (another `permissions.revoke`, the
        // admin `revoke-grant` or the agent-retirement sweep) removed it
        // after `list` read it. Nothing is left to revoke or record.
        if store.revoke_grant_as(&grant.principal, &grant.grant_id, caller)? {
            if let Err(error) = store.append_audit(&AuditRecord::permissions_revocation(
                caller,
                &grant.principal,
                &row.agent_id,
                &row.connection_id,
                &grant.grant_id,
                &row.id,
            )) {
                eprintln!(error governance: "audit append failed: permissions.revoke principal={:?} grant_id={:?}: {error}", grant.principal, grant.grant_id);
            }
            revoked.push(grant.clone());
        }
    }
    Ok(if revoked.is_empty() {
        RevokeOutcome::NotFound
    } else {
        RevokeOutcome::Revoked(revoked)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::GrantInput;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    #[test]
    #[ignore = "explicit audit timing measurement"]
    fn permission_list_and_revoke_at_542_grants() {
        let scratch = crate::test_scratch::Scratch::database("permissions-audit-timing");
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "permissions-audit-timing".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        for index in 0..32 {
            let handle = format!("handle-{index}");
            store
                .insert_connection(
                    "direct",
                    &format!("conn-{index}"),
                    "github",
                    "active",
                    &serde_json::json!({"required": [], "write_enabling": []}),
                )
                .unwrap();
            store
                .put_github_handle(&crate::storage::github_store::GithubHandle {
                    app_handle_id: handle.clone(),
                    agent_id: format!("agent-{index}"),
                    app_id: index,
                    installation_id: None,
                    credential_reference: format!("github_app:bot-{index}"),
                    credential_generation: 1,
                    status: "enabled".into(),
                    proven_at: None,
                    connection_principal: "direct".into(),
                    connection_id: format!("conn-{index}"),
                })
                .unwrap();
            store
                .bind_github_repo(&format!("owner/repo-{index}"), &handle)
                .unwrap();
        }
        for index in 0..542 {
            store
                .insert_agent_grant_for_test(
                    &GrantInput {
                        grant_id: format!("g-{index}"),
                        principal: "direct".into(),
                        connection_id: format!("conn-{}", index % 32),
                        grantee_principal: "direct".into(),
                        risk_ceiling: "write".into(),
                        action_selectors: vec!["add_comment".into()],
                        authority_kind: "invoke".into(),
                        expires_at: None,
                    },
                    &format!("agent-{}", index % 32),
                )
                .unwrap();
        }
        let start = std::time::Instant::now();
        let listed = list(&store, None, crate::storage::now_ms()).unwrap();
        let list_us = start.elapsed().as_micros();
        assert_eq!(listed.len(), 32);
        assert_eq!(
            listed.iter().map(|row| row.grants.len()).sum::<usize>(),
            542
        );
        let start = std::time::Instant::now();
        let revoked = revoke(&store, "direct", &listed[0].id, crate::storage::now_ms()).unwrap();
        let revoke_us = start.elapsed().as_micros();
        let RevokeOutcome::Revoked(revoked) = revoked else {
            panic!("no grants revoked")
        };
        println!("542 grants / 32 handles / 32 repositories: list={list_us} us, revoke={} grants={revoke_us} us", revoked.len());
    }

    #[test]
    fn a_capability_keeps_its_last_expiry_after_an_earlier_grant_expires() {
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "permission-expiry".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        for (id, expiry) in [("early", Some(10)), ("late", Some(20))] {
            store
                .insert_agent_grant_for_test(
                    &GrantInput {
                        grant_id: id.into(),
                        principal: "direct".into(),
                        connection_id: "conn".into(),
                        grantee_principal: "direct".into(),
                        risk_ceiling: "write".into(),
                        action_selectors: vec!["add_comment".into()],
                        authority_kind: "invoke".into(),
                        expires_at: expiry,
                    },
                    "agent-a",
                )
                .unwrap();
        }
        let before = list(&store, None, 1).unwrap();
        assert_eq!(
            before[0].expires_at_ms,
            Some(20),
            "row expires before capability ends"
        );
        let after = list(&store, None, 11).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, before[0].id);
        assert_eq!(after[0].expires_at_ms, Some(20));
        store
            .insert_agent_grant_for_test(
                &GrantInput {
                    grant_id: "always".into(),
                    principal: "direct".into(),
                    connection_id: "conn".into(),
                    grantee_principal: "direct".into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec!["add_comment".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                },
                "agent-a",
            )
            .unwrap();
        assert_eq!(list(&store, None, 11).unwrap()[0].expires_at_ms, None);
        assert_eq!(list(&store, None, 21).unwrap()[0].expires_at_ms, None);
    }
}
