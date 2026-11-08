use super::*;
use crate::storage::GrantInput;
use crate::test_scratch::Scratch;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

const NOW: i64 = 1_790_000_000_000;

struct Fixture {
    store: PlexusStore,
    scratch: Scratch,
}

impl Fixture {
    fn new() -> Self {
        let scratch = Scratch::database("module-search-permissions");
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "module-search-permissions".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        Self { store, scratch }
    }

    fn connection(&self, owner: &str, id: &str, app: &str, status: &str) {
        self.store
            .insert_connection(
                owner,
                id,
                app,
                status,
                &json!({"required":[],"optional":[],"write_enabling":[]}),
            )
            .unwrap();
    }

    fn grant(&self, id: &str, owner: &str, connection: &str, caller: &str) -> GrantInput {
        let grant = GrantInput {
            grant_id: id.into(),
            principal: owner.into(),
            connection_id: connection.into(),
            grantee_principal: caller.into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["*".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        };
        self.store.insert_grant(&grant).unwrap();
        grant
    }

    fn stamp(&self, id: &str, created: i64, expiry: Option<i64>) {
        assert_eq!(
            rusqlite::Connection::open(self.scratch.path())
                .unwrap()
                .execute(
                    "UPDATE grants SET created_at_ms = ?2, expires_at = ?3 WHERE grant_id = ?1",
                    rusqlite::params![id, created, expiry]
                )
                .unwrap(),
            1
        );
    }

    fn listed(&self, now: i64) -> Vec<Value> {
        list(&self.store, None, now)
            .unwrap()
            .iter()
            .map(ListedRow::to_wire)
            .collect()
    }
}

#[test]
fn search_grants_fold_per_module_and_capability_with_stable_ids() {
    let f = Fixture::new();
    for (owner, id, app) in [
        ("direct", "exa", "exa_rest"),
        ("direct", "tavily", "tavily_rest"),
        ("reserved:owner", "exa", "exa_rest"),
        ("direct", "grep", crate::code_search::BACKEND),
    ] {
        f.connection(owner, id, app, "active");
        let grant_id = format!("{owner}-{id}");
        f.grant(&grant_id, owner, id, "reserved:broca");
        f.stamp(
            &grant_id,
            if id == "tavily" { 9_000 } else { 1_000 },
            if id == "exa" { Some(NOW + 100) } else { None },
        );
    }
    let before = f.listed(NOW);
    assert_eq!(
        before,
        vec![
            json!({
                "id": module_row_id("broca", SearchCapability::Web),
                "holder": {"kind":"module", "module_id":"broca"},
                "module":"plexus", "subject_label":"Web search", "scope":"web_search",
                "scope_label":"Can search the web.", "granted_at_ms":9_000,
            }),
            json!({
                "id": module_row_id("broca", SearchCapability::Code),
                "holder": {"kind":"module", "module_id":"broca"},
                "module":"plexus", "subject_label":"Code search", "scope":"code_search",
                "scope_label":"Can search public code on GitHub.", "granted_at_ms":1_000,
            }),
        ]
    );
    assert_eq!(list(&f.store, None, NOW).unwrap()[0].grants().len(), 3);
    assert_ne!(before[0]["id"], before[1]["id"]);
    assert_ne!(
        before[0]["id"],
        row_id("module", "broca", Capability::Speak)
    );
    assert!(f.store.revoke_grant("direct", "direct-exa").unwrap());
    assert_eq!(
        f.listed(NOW),
        before,
        "provider churn must not change the row id or shape"
    );
    let later = f.listed(NOW + 100);
    assert_eq!(
        later, before,
        "expired folded grants must not change a still-live row's id"
    );
}

#[test]
fn search_connections_use_the_provider_table_and_shared_live_status_rule() {
    let f = Fixture::new();
    let apps = crate::web_search::providers::PROVIDER_NAMES
        .iter()
        .map(|provider| provider.app_key)
        .chain([crate::code_search::BACKEND]);
    for (index, app) in apps.enumerate() {
        for status in [
            "active",
            "degraded",
            "auth_required",
            "pending",
            "disabled",
            "revoked",
        ] {
            let id = format!("conn-{index}-{status}");
            let module = format!("module-{index}-{status}");
            f.connection("direct", &id, app, status);
            f.grant(&id, "direct", &id, &format!("reserved:{module}"));
            let rows = f.listed(NOW);
            let found = rows.iter().any(|row| row["holder"]["module_id"] == module);
            assert_eq!(
                found,
                matches!(status, "active" | "degraded" | "auth_required"),
                "{app}/{status}: {rows:?}"
            );
        }
    }
}

#[test]
fn bot_carriers_direct_wildcards_agents_and_other_authorities_are_not_module_rows() {
    let f = Fixture::new();
    for (id, app) in [
        ("github-handle-bot", "github"),
        ("tavily-mcp", "tavily"),
        ("firecrawl-mcp", "firecrawl"),
        ("other", "other"),
    ] {
        f.connection("direct", id, app, "active");
        for module in ["aft", "basal", "prefrontal-core", "broca"] {
            f.grant(
                &format!("{id}-{module}"),
                "direct",
                id,
                &format!("reserved:{module}"),
            );
        }
    }
    f.connection("direct", "exa", "exa_rest", "active");
    for caller in ["direct", "*", "enrolled:plugin", "reserved:"] {
        f.grant(caller, "direct", "exa", caller);
    }
    let mut noninvoke = f.grant("noninvoke", "direct", "exa", "reserved:noninvoke");
    f.store.revoke_grant("direct", "noninvoke").unwrap();
    noninvoke.grant_id = "poll".into();
    noninvoke.authority_kind = "poll".into();
    f.store.insert_grant(&noninvoke).unwrap();
    let mut agent = noninvoke;
    agent.grant_id = "agent-grant".into();
    agent.authority_kind = "invoke".into();
    agent.grantee_principal = "reserved:broca".into();
    f.store
        .insert_agent_grant_for_test(&agent, "agent-a")
        .unwrap();
    let rows = f.listed(NOW);
    assert_eq!(
        rows.len(),
        3,
        "only the agent's wildcard bot-style rows are listed: {rows:?}"
    );
    assert!(rows.iter().all(|row| row["holder"]["kind"] == "agent"));
}

#[test]
fn agent_filtered_list_omits_module_rows() {
    let f = Fixture::new();
    f.connection("direct", "exa", "exa_rest", "active");
    let mut grant = f.grant("module", "direct", "exa", "reserved:broca");
    grant.grant_id = "agent".into();
    grant.action_selectors = vec!["search".into()];
    f.store
        .insert_agent_grant_for_test(&grant, "agent-a")
        .unwrap();
    assert_eq!(f.listed(NOW).len(), 2);
    let filtered = list(&f.store, Some("agent-a"), NOW).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(
        filtered[0].to_wire()["holder"],
        json!({"kind":"agent","agent_id":"agent-a"})
    );
    assert!(list(&f.store, Some("missing"), NOW).unwrap().is_empty());
}

#[test]
fn expired_and_revoked_module_search_grants_produce_no_row() {
    let f = Fixture::new();
    f.connection("direct", "exa", "exa_rest", "active");
    f.grant("expires", "direct", "exa", "reserved:broca");
    f.stamp("expires", 1_000, Some(NOW));
    f.grant("revoked", "direct", "exa", "reserved:broca");
    f.store.revoke_grant("direct", "revoked").unwrap();
    let before = f.listed(NOW - 1);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0]["expires_at_ms"], NOW);
    assert!(f.listed(NOW).is_empty());
    assert_eq!(
        revoke(&f.store, "direct", before[0]["id"].as_str().unwrap(), NOW).unwrap(),
        RevokeOutcome::NotFound
    );
}

#[test]
fn folded_module_row_expires_with_its_last_grant() {
    let f = Fixture::new();
    for (id, app, expiry) in [
        ("exa", "exa_rest", NOW + 10),
        ("tavily", "tavily_rest", NOW + 20),
    ] {
        f.connection("direct", id, app, "active");
        f.grant(id, "direct", id, "reserved:broca");
        f.stamp(id, 1_000, Some(expiry));
    }
    let before = f.listed(NOW);
    assert_eq!(before[0]["expires_at_ms"], NOW + 20);
    assert_eq!(f.listed(NOW + 10), before);
    assert!(f.listed(NOW + 20).is_empty());
}

#[test]
fn revoke_removes_every_folded_module_grant_with_snapshots_and_audit() {
    let f = Fixture::new();
    for (owner, connection, app) in [
        ("direct", "exa", "exa_rest"),
        ("direct", "tavily", "tavily_rest"),
        ("reserved:owner", "exa", "exa_rest"),
        ("direct", "grep", crate::code_search::BACKEND),
        ("direct", "github-handle-bot", "github"),
    ] {
        f.connection(owner, connection, app, "active");
        f.grant(
            &format!("{owner}-{connection}"),
            owner,
            connection,
            "reserved:broca",
        );
    }
    f.grant("other-module", "direct", "exa", "reserved:aft");
    let id = module_row_id("broca", SearchCapability::Web);
    let listed = list(&f.store, None, NOW).unwrap();
    let held = listed
        .iter()
        .find(|row| row.id() == id)
        .unwrap()
        .grants()
        .to_vec();
    assert_eq!(held.len(), 3);
    assert_eq!(
        revoke(&f.store, "reserved:cingulate", &id, NOW).unwrap(),
        RevokeOutcome::Revoked(held.clone())
    );
    assert_eq!(
        revoke(&f.store, "reserved:cingulate", &id, NOW).unwrap(),
        RevokeOutcome::NotFound
    );
    let db = rusqlite::Connection::open(f.scratch.path()).unwrap();
    for grant in &held {
        let remaining = f
            .store
            .list_grants(&grant.principal, &grant.connection_id)
            .unwrap();
        let snapshot = remaining
            .iter()
            .find(|row| row.grant_id == grant.grant_id)
            .unwrap();
        assert_eq!(snapshot.state, "revoked");
        assert_eq!(snapshot.revoked_by.as_deref(), Some("reserved:cingulate"));
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM grant_revocations WHERE principal = ?1 AND grant_id = ?2",
                [&grant.principal, &grant.grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let audits = f.store.list_audit(&grant.principal).unwrap();
        let audit = audits
            .iter()
            .find(|row| {
                row.reason_code == "permissions_revoke"
                    && row
                        .args_redaction_summary
                        .as_deref()
                        .is_some_and(|summary| summary.contains(&grant.grant_id))
            })
            .unwrap();
        assert_eq!(audit.acting_principal, "reserved:cingulate");
        assert_eq!(audit.agent_id, None);
        assert_eq!(
            audit.connection_id.as_deref(),
            Some(grant.connection_id.as_str())
        );
    }
    let live: i64 = db
        .query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        live, 3,
        "code search, bot carrier and other module grants remain live"
    );
    let after = f.listed(NOW);
    assert_eq!(after.len(), 2);
    assert!(after
        .iter()
        .any(|row| row["id"] == module_row_id("broca", SearchCapability::Code)));
    assert!(after
        .iter()
        .any(|row| row["id"] == module_row_id("aft", SearchCapability::Web)));
    assert_eq!(
        revoke(
            &f.store,
            "direct",
            &module_row_id("broca", SearchCapability::Code),
            NOW
        )
        .unwrap(),
        RevokeOutcome::Revoked(vec![HeldGrant {
            principal: "direct".into(),
            connection_id: "grep".into(),
            grant_id: "direct-grep".into()
        }])
    );
}
