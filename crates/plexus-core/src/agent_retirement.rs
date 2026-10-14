//! Revoke the grants of agents that prefrontal has retired.
//!
//! Agent grants are keyed on prefrontal's agent id, and nothing else in plexus
//! learns when prefrontal retires an agent. A bot write needs an authorized
//! delegating session stamp, but unreachable grants are still authority on
//! record: a reused id or a stamping bug could exercise them again. This sweep
//! removes them.
//!
//! The sweep only ever narrows authority, and only on a definite answer. A
//! retired verdict revokes; a live agent, an unknown id, an unreachable
//! registry, or an unrecognised reply leaves every row as it was. An unknown id
//! is prefrontal saying the id never existed, which is not the same claim as a
//! retirement, and an error is no claim at all.
//!
//! GitHub handles and their repository bindings are left alone. A handle owned
//! by a retired agent is reported so an operator can rebind its repositories to
//! a new agent; disabling it automatically would take repositories offline on
//! the strength of a registry reply.

use crate::agent_registry::{AgentLookup, AgentRegistry};
use crate::storage::{AuditRecord, PlexusStore};
use cortexkit_store::StoreError;

/// How often the scheduler runs the sweep. Retirement is rare and the rows it
/// removes are already unreachable, so an hour of lag costs nothing while
/// keeping registry traffic to one round per agent per hour.
pub const AGENT_RETIREMENT_SWEEP_INTERVAL_MS: i64 = 60 * 60 * 1000;

/// Reason recorded on the audit row of every grant this sweep revokes.
pub const AGENT_RETIRED_REASON: &str = "agent_retired";

/// What one sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetirementSweep {
    /// Agents the registry reported retired, in the order they were resolved.
    pub agents_gone: Vec<String>,
    /// Grant rows removed across all retired agents.
    pub grants_revoked: usize,
    /// Agents left untouched because the registry could not give an answer.
    pub agents_unresolved: usize,
    /// The agent whose lookup went unanswered, if the sweep stopped at one.
    /// The next sweep starts just after it.
    pub stopped_at: Option<String>,
    /// Grants of retired agents whose revocation failed in the store; they are
    /// still live and the next sweep retries them.
    pub revocation_failures: usize,
}

/// Where the next sweep starts, after one stopped at an unanswered lookup.
///
/// Stopping at the first unanswered lookup bounds how long an unreachable
/// registry holds the scheduler. On its own it also let an agent whose lookup
/// always goes unanswered shield every agent after it in id order, forever.
/// Resuming just after it puts it last in the next sweep, so every other agent
/// is asked first.
#[derive(Debug, Default)]
pub struct SweepResume(std::sync::Mutex<Option<String>>);

/// Resolve every agent that holds a grant and revoke all grants of each agent
/// the registry reports retired, in agent id order.
pub fn sweep_retired_agents(
    store: &PlexusStore,
    registry: &dyn AgentRegistry,
) -> Result<RetirementSweep, StoreError> {
    sweep_retired_agents_from(store, registry, None)
}

/// [`sweep_retired_agents`], starting just after `resume_after` (the agent a
/// previous sweep stopped at) and wrapping round to it last.
///
/// Revocation goes through [`PlexusStore::revoke_grant`], the same path an
/// operator's revoke takes: the journal line is appended before the fenced
/// transaction snapshots the row into `grant_revocations` and deletes it. Each
/// revoked grant then gets its own audit row. A failure on one grant is logged
/// and counted rather than aborting, so one bad row cannot shield the rest.
pub fn sweep_retired_agents_from(
    store: &PlexusStore,
    registry: &dyn AgentRegistry,
    resume_after: Option<&str>,
) -> Result<RetirementSweep, StoreError> {
    let mut sweep = RetirementSweep::default();
    let mut agents = store.agents_holding_grants()?;
    agents.sort();
    if let Some(after) = resume_after {
        let start = agents.partition_point(|agent| agent.as_str() <= after);
        agents.rotate_left(start);
    }
    for (index, agent_id) in agents.iter().enumerate() {
        match registry.lookup(agent_id) {
            AgentLookup::Retired => {
                revoke_agent(store, agent_id, &mut sweep)?;
                sweep.agents_gone.push(agent_id.clone());
            }
            AgentLookup::Known | AgentLookup::Unknown => {}
            AgentLookup::Unavailable => {
                // The sweep runs inline in the scheduler pass, and a lookup
                // that goes unanswered has already waited out the route call's
                // full timeout (30 s by default). Asking every remaining agent
                // would hold polling for that long per agent, so stop at the
                // first unanswered lookup and leave the rest to the next sweep.
                sweep.agents_unresolved += agents.len() - index;
                sweep.stopped_at = Some(agent_id.clone());
                break;
            }
        }
    }
    Ok(sweep)
}

fn revoke_agent(
    store: &PlexusStore,
    agent_id: &str,
    sweep: &mut RetirementSweep,
) -> Result<(), StoreError> {
    for grant in store.grants_held_by_agent(agent_id)? {
        match store.revoke_grant_as(&grant.principal, &grant.grant_id, "plexus") {
            // False means the row vanished between the read and the revoke,
            // which leaves nothing to record.
            Ok(false) => {}
            Ok(true) => {
                sweep.grants_revoked += 1;
                if let Err(error) = store.append_audit(&AuditRecord::agent_retired_revocation(
                    &grant.principal,
                    agent_id,
                    &grant.connection_id,
                    &grant.grant_id,
                )) {
                    eprintln!(error governance: "audit append failed: agent_retired revoke_grant principal={:?} grant_id={:?}: {error}", grant.principal, grant.grant_id);
                }
            }
            Err(error) => {
                sweep.revocation_failures += 1;
                eprintln!(error governance: "retired agent {agent_id:?}: revoking grant {:?} failed: {error}", grant.grant_id);
            }
        }
    }
    Ok(())
}

/// Run one sweep and write its diagnostics. Never fails: like the scheduler's
/// other housekeeping, a problem here is logged and polling carries on.
pub fn run_and_report(store: &PlexusStore, registry: &dyn AgentRegistry, resume: &SweepResume) {
    let mut resume_after = resume
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let sweep = match sweep_retired_agents_from(store, registry, resume_after.as_deref()) {
        Ok(sweep) => sweep,
        Err(error) => {
            eprintln!(warn governance: "agent retirement sweep failed: {error}");
            return;
        }
    };
    *resume_after = sweep.stopped_at.clone();
    drop(resume_after);
    if sweep.agents_unresolved > 0 {
        eprintln!(warn governance: "agent retirement sweep skipped {} agent(s): registry gave no answer", sweep.agents_unresolved);
    }
    if sweep.grants_revoked > 0 {
        eprintln!(info governance: "agent retirement sweep: {} agent(s) gone, {} grant(s) revoked", sweep.agents_gone.len(), sweep.grants_revoked);
    }
    for agent_id in &sweep.agents_gone {
        match store.github_handles_for_agent(agent_id) {
            Ok(handles) => {
                for handle in handles {
                    eprintln!(info governance: "github handle {} belongs to retired agent {agent_id:?} (status {}); rebind repositories {:?} to a new agent", handle.app_handle_id, handle.status, handle.repositories);
                }
            }
            Err(error) => {
                eprintln!(warn governance: "agent retirement sweep could not read handles of {agent_id:?}: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_registry::StubAgentRegistry;
    use crate::storage::github_store::GithubHandle;
    use crate::storage::GrantInput;
    use crate::test_scratch::Scratch;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use std::path::{Path, PathBuf};

    struct ReplyRegistry(serde_json::Value);
    impl AgentRegistry for ReplyRegistry {
        fn lookup(&self, _: &str) -> AgentLookup {
            crate::agent_registry::resolve_agent_lookup_reply(&self.0)
        }
    }

    #[test]
    fn a_null_agent_with_a_deleted_gone_reply_preserves_grants() {
        let (_scratch, store) = file_store("registry-both-present-null");
        grant(&store, "direct", "conn", "g-agent", "agent-a");
        let reply = serde_json::json!({"agent":null,"gone":{"reason":"deleted","at":1}});
        let sweep = sweep_retired_agents(&store, &ReplyRegistry(reply)).unwrap();
        assert_eq!(
            sweep.grants_revoked, 0,
            "both-present reply must not revoke grants even when agent is null"
        );
        assert_eq!(store.grants_held_by_agent("agent-a").unwrap().len(), 1);
    }

    #[test]
    fn only_well_formed_producer_retirement_replies_revoke_grants() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/agent-registry/replies.json"
        ))
        .unwrap();
        let mut cases = Vec::new();
        for pointer in ["/cases/2/reply", "/cases/3/reply", "/cases/4/reply"] {
            cases.push((
                fixture
                    .pointer(pointer)
                    .expect("producer reply path")
                    .clone(),
                pointer != "/cases/2/reply",
            ));
        }
        // The paired fixture replies are the deleted and merged answers above as
        // the agent registry (the Prefrontal module) now sends them, with
        // top-level `incarnation` and `generation` fields added. Those fields
        // do not change how retirement is read: `gone.reason` still decides it,
        // so both replies must still revoke the agent's grants.
        for pointer in ["/pairs/2/reply", "/pairs/3/reply"] {
            cases.push((
                fixture
                    .pointer(pointer)
                    .expect("producer pair reply path")
                    .clone(),
                true,
            ));
        }
        for malformed in [
            serde_json::json!({"gone": null}),
            serde_json::json!({"gone": "deleted"}),
            serde_json::json!({"gone": []}),
            serde_json::json!({"gone": {"reason": "other", "at": 1}}),
            serde_json::json!({"gone": {"reason": "deleted"}}),
            serde_json::json!({"gone": {"reason": "deleted", "at": -1}}),
            serde_json::json!({"gone": {"reason": "deleted", "at": 1.5}}),
            serde_json::json!({"gone": {"reason": "merged", "at": 1}}),
            serde_json::json!({"agent": {}, "gone": {"reason": "deleted", "at": 1}}),
            serde_json::json!({}),
        ] {
            cases.push((malformed, false));
        }
        for (reply, retired) in cases {
            let (_scratch, store) = file_store("registry-wire-sweep");
            grant(&store, "direct", "conn", "g-agent", "agent-a");
            let sweep = sweep_retired_agents(&store, &ReplyRegistry(reply.clone())).unwrap();
            assert_eq!(sweep.grants_revoked, usize::from(retired), "{reply}");
            assert_eq!(
                store.grants_held_by_agent("agent-a").unwrap().len(),
                usize::from(!retired),
                "{reply}"
            );
        }
    }

    /// A file-backed store, because the revocation journal only exists beside
    /// a database file.
    fn file_store(label: &str) -> (Scratch, PlexusStore) {
        let scratch = Scratch::database(label);
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: label.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        };
        let store = PlexusStore::open(&descriptor).expect("open store");
        (scratch, store)
    }

    fn journal_path(scratch: &Scratch) -> PathBuf {
        scratch.path().with_file_name(crate::grant_journal::NAME)
    }

    fn grant(store: &PlexusStore, principal: &str, connection: &str, id: &str, agent: &str) {
        store
            .insert_agent_grant_for_test(
                &GrantInput {
                    grant_id: id.into(),
                    principal: principal.into(),
                    connection_id: connection.into(),
                    grantee_principal: crate::github::AFT_PRINCIPAL.into(),
                    risk_ceiling: "write".into(),
                    action_selectors: vec!["github.issue.comment".into()],
                    authority_kind: crate::governance::AUTHORITY_INVOKE.into(),
                    expires_at: None,
                },
                agent,
            )
            .expect("insert agent grant");
    }

    fn retirement_audit_rows(
        store: &PlexusStore,
        principal: &str,
    ) -> Vec<crate::storage::AuditRow> {
        store
            .list_audit(principal)
            .expect("list audit")
            .into_iter()
            .filter(|row| row.reason_code == AGENT_RETIRED_REASON)
            .collect()
    }

    /// Every file in the store's directory, by name, with its bytes.
    ///
    /// SQLite's `-shm` file is left out: it is the write-ahead log's shared
    /// memory index, and a plain read records its read position there, so it
    /// changes on any query. The database, its log, and the revocation journal
    /// are what hold data.
    fn directory_bytes(directory: &Path) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(directory)
            .expect("read store directory")
            .filter(|entry| {
                !entry
                    .as_ref()
                    .is_ok_and(|entry| entry.file_name().to_string_lossy().ends_with("-shm"))
            })
            .map(|entry| {
                let entry = entry.expect("directory entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).expect("read store file"),
                )
            })
            .collect();
        files.sort();
        files
    }

    /// Names of the files that were added, removed, or rewritten between two
    /// [`directory_bytes`] readings, so a failure names the file, not a byte dump.
    fn changed_files(before: &[(String, Vec<u8>)], after: &[(String, Vec<u8>)]) -> Vec<String> {
        let mut names: Vec<String> = before
            .iter()
            .chain(after)
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
            .into_iter()
            .filter(|name| {
                let find = |files: &[(String, Vec<u8>)]| {
                    files
                        .iter()
                        .find(|(file, _)| file == name)
                        .map(|(_, bytes)| bytes.clone())
                };
                find(before) != find(after)
            })
            .collect()
    }

    #[test]
    fn a_retired_agent_loses_every_grant_through_the_journalled_revocation_path() {
        let (scratch, store) = file_store("agent-retirement-gone");
        grant(
            &store,
            "direct",
            "github-handle-a",
            "grant-gone-1",
            "agent-gone",
        );
        grant(
            &store,
            "direct",
            "github-handle-b",
            "grant-gone-2",
            "agent-gone",
        );
        grant(
            &store,
            "other",
            "github-handle-c",
            "grant-gone-3",
            "agent-gone",
        );
        grant(
            &store,
            "direct",
            "github-handle-a",
            "grant-live",
            "agent-live",
        );
        store
            .put_github_handle(&GithubHandle {
                app_handle_id: "handle-gone".into(),
                agent_id: "agent-gone".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:gone".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "github-handle-a".into(),
            })
            .expect("handle");
        let registry = StubAgentRegistry::with_default_response(AgentLookup::Known);
        registry.set_response("agent-gone", AgentLookup::Retired);

        let sweep = sweep_retired_agents(&store, &registry).expect("sweep");

        assert_eq!(sweep.agents_gone, vec!["agent-gone".to_string()]);
        assert_eq!(sweep.grants_revoked, 3);
        assert!(
            store.grants_held_by_agent("agent-gone").unwrap().is_empty(),
            "a retired agent kept a grant row"
        );
        assert_eq!(
            store.grants_held_by_agent("agent-live").unwrap().len(),
            1,
            "a live agent's grant was touched"
        );
        // The snapshot: each revoked grant reappears as a revoked record.
        for (principal, connection, id) in [
            ("direct", "github-handle-a", "grant-gone-1"),
            ("direct", "github-handle-b", "grant-gone-2"),
            ("other", "github-handle-c", "grant-gone-3"),
        ] {
            let record = store
                .list_grants(principal, connection)
                .unwrap()
                .into_iter()
                .find(|record| record.grant_id == id)
                .unwrap_or_else(|| panic!("no grant_revocations snapshot for {id}"));
            assert!(
                record.revoked_at_ms.is_some(),
                "{id} was not snapshotted as revoked"
            );
        }
        let live = store
            .list_grants("direct", "github-handle-a")
            .unwrap()
            .into_iter()
            .find(|record| record.grant_id == "grant-live")
            .expect("live grant");
        assert!(
            live.revoked_at_ms.is_none(),
            "the live agent's grant was revoked"
        );
        // The journal: one line per revoked grant, and none for the live one.
        let mut journalled: Vec<String> = crate::grant_journal::read(&journal_path(&scratch))
            .expect("read journal")
            .into_iter()
            .map(|entry| entry.grant_id)
            .collect();
        journalled.sort();
        assert_eq!(journalled, ["grant-gone-1", "grant-gone-2", "grant-gone-3"]);
        // The audit: one row per grant, attributed to the retired agent.
        let direct = retirement_audit_rows(&store, "direct");
        assert_eq!(direct.len(), 2, "{direct:?}");
        assert_eq!(retirement_audit_rows(&store, "other").len(), 1);
        assert!(direct
            .iter()
            .all(|row| row.agent_id.as_deref() == Some("agent-gone")));
        // The handle stays exactly as it was.
        let handles = store.github_handles_for_agent("agent-gone").unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].status, "enabled");
    }

    #[test]
    fn an_unavailable_registry_or_an_unknown_agent_changes_nothing() {
        let (scratch, store) = file_store("agent-retirement-no-answer");
        grant(
            &store,
            "direct",
            "conn",
            "grant-unavailable",
            "agent-unavailable",
        );
        // Named to sort before the unavailable agent: the sweep resolves
        // agents in id order and stops at the first unanswered lookup, so this
        // one has to come first to be resolved at all.
        grant(
            &store,
            "direct",
            "conn",
            "grant-unknown",
            "agent-answered-unknown",
        );
        let registry = StubAgentRegistry::with_default_response(AgentLookup::Known);
        registry.set_response("agent-unavailable", AgentLookup::Unavailable);
        registry.set_response("agent-answered-unknown", AgentLookup::Unknown);
        let before = directory_bytes(scratch.owned_directory());

        let sweep = sweep_retired_agents(&store, &registry).expect("sweep");

        assert_eq!(
            registry.requests(),
            ["agent-answered-unknown", "agent-unavailable"],
            "both agents must have been resolved for this to prove anything"
        );
        // The byte comparison comes before the counters, so a sweep that
        // wrongly revokes is caught by what it did to the store, not only by
        // what it reported.
        let after = directory_bytes(scratch.owned_directory());
        assert_eq!(
            changed_files(&before, &after),
            Vec::<String>::new(),
            "the store changed without a retired verdict"
        );
        assert_eq!(sweep.agents_unresolved, 1);
        assert_eq!(sweep.grants_revoked, 0);
        assert!(sweep.agents_gone.is_empty());
        assert_eq!(store.agents_holding_grants().unwrap().len(), 2);
    }

    /// An unresponsive registry costs the scheduler one call timeout per sweep,
    /// not one per agent: the sweep stops at the first unanswered lookup, asks
    /// no one else, and revokes nothing, even for an agent that is retired.
    #[test]
    fn the_sweep_stops_at_the_first_unanswered_lookup() {
        let (_scratch, store) = file_store("agent-retirement-stop");
        grant(&store, "direct", "conn", "grant-a", "agent-a-unavailable");
        grant(&store, "direct", "conn", "grant-b", "agent-b-retired");
        grant(&store, "direct", "conn", "grant-c", "agent-c-known");
        let registry = StubAgentRegistry::with_default_response(AgentLookup::Known);
        registry.set_response("agent-a-unavailable", AgentLookup::Unavailable);
        registry.set_response("agent-b-retired", AgentLookup::Retired);

        let sweep = sweep_retired_agents(&store, &registry).expect("sweep");

        assert_eq!(
            registry.requests(),
            ["agent-a-unavailable"],
            "the sweep asked the registry again after an unanswered lookup"
        );
        assert_eq!(sweep.agents_unresolved, 3);
        assert_eq!(sweep.grants_revoked, 0);
        assert_eq!(
            store.grants_held_by_agent("agent-b-retired").unwrap().len(),
            1,
            "a grant was revoked in a sweep that stopped before reaching it"
        );
    }

    /// An agent whose lookup always goes unanswered must not shield the agents
    /// after it in id order: the next sweep starts just after it, so every
    /// other agent is asked first and it is asked last. Each sweep still stops
    /// at its first unanswered lookup.
    #[test]
    fn the_next_sweep_resumes_after_the_agent_it_stopped_at() {
        let (_scratch, store) = file_store("agent-retirement-resume");
        grant(&store, "direct", "conn", "grant-a", "agent-a-unavailable");
        grant(&store, "direct", "conn", "grant-b", "agent-b-retired");
        grant(&store, "direct", "conn", "grant-c", "agent-c-known");
        let registry = StubAgentRegistry::with_default_response(AgentLookup::Known);
        registry.set_response("agent-a-unavailable", AgentLookup::Unavailable);
        registry.set_response("agent-b-retired", AgentLookup::Retired);
        let resume = SweepResume::default();

        run_and_report(&store, &registry, &resume);
        assert_eq!(registry.requests(), ["agent-a-unavailable"]);
        run_and_report(&store, &registry, &resume);

        assert_eq!(
            registry.requests(),
            [
                "agent-a-unavailable",
                "agent-b-retired",
                "agent-c-known",
                "agent-a-unavailable"
            ],
            "the second sweep must ask every other agent before the stuck one"
        );
        assert!(
            store
                .grants_held_by_agent("agent-b-retired")
                .unwrap()
                .is_empty(),
            "the retired agent behind the stuck one was never revoked"
        );
        let sweep =
            sweep_retired_agents_from(&store, &registry, Some("agent-a-unavailable")).unwrap();
        assert_eq!(sweep.stopped_at.as_deref(), Some("agent-a-unavailable"));
        assert_eq!(sweep.agents_unresolved, 1);
    }
}
