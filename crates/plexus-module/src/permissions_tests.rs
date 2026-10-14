//! `permissions.list` and `permissions.revoke` through the route, as cingulate
//! calls them: row grouping, the agent filter, expiry, revoke exactness and
//! idempotence, restore survival, admission, and the reply shapes of the
//! contract's provider vectors. Vectors are the example request and reply
//! files the permissions/v1 contract publishes; the provider ones are copied
//! into `crates/plexus-module/tests/fixtures/permissions-v1/`.
use super::*;
use plexus_core::permissions::{row_id, Capability};
use plexus_core::storage::github_store::{
    GithubHandle, GithubImportRow, GithubImportedGrant, GithubImportedPolicy,
};
use plexus_core::{MockTransport, CATALOG_PRINCIPAL};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use subc_protocol::{
    scope::{ScopeAttributes, ScopeKind, ScopeStamp},
    BindIdentity, RouteTarget,
};

const ALL_AGENT: &str = "agent-all";
const ALL_CONNECTION: &str = "github-handle-all-bot";
const SPEAK_AGENT: &str = "agent-speak";
const SPEAK_CONNECTION: &str = "github-handle-speak-bot";

/// The fourteen speech selectors. A selector is an action name stored in a
/// grant's `action_selectors`, naming one action the grant allows. These are
/// comment, edit comment, review, react, edit, close, reopen, assignees,
/// labels and the reads they depend on.
const SPEAK_ACTIONS: [&str; 14] = [
    "add_issue_comment",
    "update_issue_comment",
    "add_pr_review",
    "add_reaction",
    "edit_issue",
    "close_issue",
    "reopen_issue",
    "add_issue_assignees",
    "add_issue_labels",
    "github.issue.get",
    "github.issue_comment.get",
    "github.issue_comments.list",
    "remove_issue_assignees",
    "remove_issue_label",
];

/// The refusal every caller other than cingulate and `direct` gets, as the
/// permissions/v1 test vector `provider-revoke-refused-agent.json` (in
/// `crates/plexus-module/tests/fixtures/permissions-v1/`) pins it.
const REFUSED_AGENT: &str =
    include_str!("../tests/fixtures/permissions-v1/provider-revoke-refused-agent.json");

fn all_actions() -> Vec<&'static str> {
    let mut actions = SPEAK_ACTIONS.to_vec();
    actions.extend(["create_issue", "create_pull_request"]);
    actions
}

fn descriptor(path: &Path) -> StorageDescriptor {
    StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "permissions".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    }
}

fn import_row(slug: &str, agent: &str, repositories: &[&str], actions: &[&str]) -> GithubImportRow {
    GithubImportRow {
        handle: GithubHandle {
            app_handle_id: slug.into(),
            agent_id: agent.into(),
            app_id: 1,
            installation_id: None,
            credential_reference: format!("github_app:{slug}"),
            credential_generation: 0,
            status: "enabled".into(),
            proven_at: None,
            connection_principal: "direct".into(),
            connection_id: format!("github-handle-{slug}"),
        },
        repositories: repositories.iter().map(|repo| repo.to_string()).collect(),
        grants: actions
            .iter()
            .map(|action| GithubImportedGrant {
                action: action.to_string(),
                repository: repositories[0].into(),
                provenance: "test".into(),
            })
            .collect(),
        module_actions: actions.iter().map(|action| action.to_string()).collect(),
        // One agent-level and one module-level policy, so the tests can show
        // that neither becomes a row.
        policies: vec![
            GithubImportedPolicy {
                agent: true,
                action: "add_issue_comment".into(),
                effect: "allow".into(),
            },
            GithubImportedPolicy {
                agent: false,
                action: "add_issue_comment".into(),
                effect: "ask_first".into(),
            },
        ],
    }
}

/// A file-backed store, because the revocation journal exists only beside a
/// database file. `agent-all` holds sixteen grants on the bot `all-bot`,
/// bound to `cortexkit/magic-context`: the fourteen speech selectors plus
/// `create_issue` and `create_pull_request`. `agent-speak` holds only the
/// fourteen speech grants, on the bot `speak-bot` bound to `o/a` and `o/b`.
/// The import also writes each connection's module-layer grants (grants with
/// no agent id, held by a carrier module such as aft for every agent it
/// carries) and one agent-level and one module-level policy per connection.
struct Fixture {
    state: Arc<ModuleState>,
    store: Arc<PlexusStore>,
    transport: Arc<MockTransport>,
    scratch: Scratch,
}

fn state_for(store: Arc<PlexusStore>) -> (Arc<ModuleState>, Arc<MockTransport>) {
    let transport = Arc::new(MockTransport::default());
    let runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
        store,
        Arc::new(StubCredentialSource::default()),
        transport.clone(),
    );
    (
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        }),
        transport,
    )
}

fn fixture() -> Fixture {
    let scratch = Scratch::database("permissions");
    let store = Arc::new(PlexusStore::open(&descriptor(&scratch)).unwrap());
    store
        .upsert_manifest(
            CATALOG_PRINCIPAL,
            &super::github_read_frame_tests::github_manifest(),
        )
        .unwrap();
    store
        .import_github_handles(&[
            import_row(
                "all-bot",
                ALL_AGENT,
                &["cortexkit/magic-context"],
                &all_actions(),
            ),
            import_row("speak-bot", SPEAK_AGENT, &["o/a", "o/b"], &SPEAK_ACTIONS),
        ])
        .unwrap();
    let (state, transport) = state_for(store.clone());
    Fixture {
        state,
        store,
        transport,
        scratch,
    }
}

fn sql(scratch: &Scratch) -> rusqlite::Connection {
    rusqlite::Connection::open(scratch.path()).unwrap()
}

fn count(scratch: &Scratch, query: &str) -> i64 {
    sql(scratch).query_row(query, [], |row| row.get(0)).unwrap()
}

/// `(principal, grant_id)` of the agent's grant for one action.
fn grant_of(scratch: &Scratch, agent: &str, action: &str) -> (String, String) {
    sql(scratch)
        .query_row(
            "SELECT principal, grant_id FROM grants
             WHERE agent_id = ?1 AND action_selectors = json_array(?2)",
            [agent, action],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn set_grant(scratch: &Scratch, agent: &str, action: &str, column: &str, value: i64) {
    let changed = sql(scratch)
        .execute(
            &format!(
                "UPDATE grants SET {column} = ?3
                 WHERE agent_id = ?1 AND action_selectors = json_array(?2)"
            ),
            rusqlite::params![agent, action, value],
        )
        .unwrap();
    assert_eq!(changed, 1, "{agent} must hold exactly one {action} grant");
}

fn reserved(id: &str) -> Principal {
    Principal::Reserved {
        module_id: id.into(),
    }
}

fn stamp(mode: &CallMode) -> Option<ScopeStamp> {
    let attributes = match mode {
        CallMode::Codemode => ScopeAttributes::new().with_run_id(Some("run-1".into())),
        CallMode::Flow => ScopeAttributes::new().with_flow_id(Some("flow-1".into())),
        _ => return None,
    };
    Some(
        ScopeStamp::new(reserved("prefrontal-core"), "scope-1", 1, ScopeKind::Worker)
            .with_attributes(
                attributes
                    .with_agent_id(Some(ALL_AGENT.into()))
                    .with_delegates(true),
            )
            .with_owner_authorized(true),
    )
}

/// Bind a route as `principal` and send one request body on it.
async fn route_call(
    state: &Arc<ModuleState>,
    principal: Principal,
    mode: CallMode,
    body: Value,
) -> Value {
    let routes = Arc::new(RouteBindings::new());
    let bind = Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&ModuleControlRequest::RouteBind {
            route_channel: 17,
            epoch: 3,
            target: RouteTarget::ToolProvider {
                module_id: DEFAULT_MODULE_ID.into(),
            },
            identity: BindIdentity::new("/tmp", "permissions-test", "session"),
            principal: Some(principal.clone()),
            scope: stamp(&mode),
            call_mode: Some(mode),
            role_versions: None,
            consumer_capabilities: None,
            admission_facts: None,
        })
        .unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_control_request(bind, &writer, state, &routes)
        .await
        .unwrap();
    let ack = recv_within(responses.recv(), Duration::from_secs(5), "route.bind reply").await;
    assert_eq!(
        ack.header.ty,
        FrameType::Response,
        "{principal:?} must bind: {}",
        String::from_utf8_lossy(&ack.body)
    );
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        17,
        3,
        2,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_tool_request(frame, &writer, state, &routes)
        .await
        .unwrap();
    let reply = recv_within(responses.recv(), Duration::from_secs(5), "route reply").await;
    serde_json::from_slice(&reply.body).unwrap()
}

async fn list(state: &Arc<ModuleState>, params: Value) -> Value {
    let reply = route_call(
        state,
        reserved("cingulate"),
        CallMode::Classic,
        json!({"method": "permissions.list", "params": params}),
    )
    .await;
    assert!(reply.get("error").is_none(), "list must succeed: {reply}");
    reply["result"]["grants"].clone()
}

async fn revoke(state: &Arc<ModuleState>, id: &str) -> Value {
    route_call(
        state,
        reserved("cingulate"),
        CallMode::Classic,
        json!({"method": "permissions.revoke", "params": {"id": id}}),
    )
    .await
}

/// The listed row of `agent` with `scope`, if there is one.
fn row<'a>(rows: &'a Value, agent: &str, scope: &str) -> Option<&'a Value> {
    rows.as_array()
        .unwrap()
        .iter()
        .find(|row| row["agent_id"] == agent && row["scope"] == scope)
}

fn scopes_of(rows: &Value, agent: &str) -> Vec<String> {
    rows.as_array()
        .unwrap()
        .iter()
        .filter(|row| row["agent_id"] == agent)
        .map(|row| row["scope"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_fold_into_three_rows_for_a_full_bot_and_one_for_a_speak_only_bot() {
    let f = fixture();
    // Mint times differ per grant: the rows must not split by them.
    for action in all_actions() {
        set_grant(&f.scratch, ALL_AGENT, action, "created_at_ms", 1_000);
    }
    set_grant(
        &f.scratch,
        ALL_AGENT,
        "add_reaction",
        "created_at_ms",
        9_000,
    );
    set_grant(
        &f.scratch,
        ALL_AGENT,
        "create_issue",
        "created_at_ms",
        5_000,
    );
    let rows = list(&f.state, json!({})).await;
    assert_eq!(
        scopes_of(&rows, ALL_AGENT),
        [
            "github_bot_speak",
            "github_bot_open_issues",
            "github_bot_open_pull_requests"
        ],
        "an agent holding all sixteen grants gets exactly three rows: {rows}"
    );
    assert_eq!(
        scopes_of(&rows, SPEAK_AGENT),
        ["github_bot_speak"],
        "an agent holding only speech grants gets one row: {rows}"
    );
    let speak = row(&rows, ALL_AGENT, "github_bot_speak").unwrap();
    assert_eq!(
        speak,
        &json!({
            "id": row_id(ALL_AGENT, ALL_CONNECTION, Capability::Speak),
            "agent_id": ALL_AGENT,
            "holder": {"kind": "agent", "agent_id": ALL_AGENT},
            "module": "plexus",
            "subject_label": "Speak as all-bot[bot] on cortexkit/magic-context",
            "scope": "github_bot_speak",
            "scope_label": "all-bot[bot] can comment, review, react, edit, close and reopen issues and pull requests on cortexkit/magic-context.",
            "granted_at_ms": 9_000,
        }),
        "granted_at_ms is the newest mint among the row's grants"
    );
    let issues = row(&rows, ALL_AGENT, "github_bot_open_issues").unwrap();
    assert_eq!(issues["subject_label"], "Open issues as all-bot[bot]");
    assert_eq!(
        issues["scope_label"],
        "all-bot[bot] can open new issues on cortexkit/magic-context."
    );
    assert_eq!(issues["granted_at_ms"], 5_000);
    let pulls = row(&rows, ALL_AGENT, "github_bot_open_pull_requests").unwrap();
    assert_eq!(pulls["subject_label"], "Open pull requests as all-bot[bot]");
    assert_eq!(pulls["granted_at_ms"], 1_000);
    let other = row(&rows, SPEAK_AGENT, "github_bot_speak").unwrap();
    assert_eq!(
        other["subject_label"],
        "Speak as speak-bot[bot] on o/a and o/b"
    );
    assert_eq!(
        other["id"],
        row_id(SPEAK_AGENT, SPEAK_CONNECTION, Capability::Speak)
    );
}

/// Module-layer grants (grants with no agent id: the ceilings a carrier
/// module such as aft holds for every agent it carries) and policies are not
/// standing grants an operator gave an agent, so they never become rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_grants_and_policies_are_not_listed() {
    let f = fixture();
    assert!(
        count(
            &f.scratch,
            "SELECT COUNT(*) FROM grants WHERE agent_id IS NULL"
        ) >= 4,
        "the import must have written module-layer grants for both connections"
    );
    assert!(count(&f.scratch, "SELECT COUNT(*) FROM policies") >= 4);
    let rows = list(&f.state, json!({})).await;
    let agents: BTreeSet<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["agent_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        (agents, rows.as_array().unwrap().len()),
        (BTreeSet::from([ALL_AGENT, SPEAK_AGENT]), 4),
        "module-layer grants and policies must stay off the permissions page: {rows}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_filter_lists_one_agent_and_row_ids_are_stable() {
    let f = fixture();
    let all = list(&f.state, json!({})).await;
    assert_eq!(
        list(&f.state, json!({})).await,
        all,
        "a second read is identical"
    );
    let only = list(&f.state, json!({"agent_id": SPEAK_AGENT})).await;
    assert_eq!(
        only,
        json!([row(&all, SPEAK_AGENT, "github_bot_speak").unwrap()])
    );
    assert_eq!(
        list(&f.state, json!({"agent_id": "agent-nobody"})).await,
        json!([])
    );
    // A speech grant leaving the row does not change the row's id.
    let (principal, grant_id) = grant_of(&f.scratch, ALL_AGENT, "add_reaction");
    assert!(f.store.revoke_grant(&principal, &grant_id).unwrap());
    let after = list(&f.state, json!({"agent_id": ALL_AGENT})).await;
    assert_eq!(
        row(&after, ALL_AGENT, "github_bot_speak").unwrap()["id"],
        row(&all, ALL_AGENT, "github_bot_speak").unwrap()["id"]
    );
    for bad in [
        json!({"agent_id": ""}),
        json!({"agent_id": 7}),
        json!({"agent": "x"}),
    ] {
        let reply = route_call(
            &f.state,
            reserved("cingulate"),
            CallMode::Classic,
            json!({"method": "permissions.list", "params": bad}),
        )
        .await;
        assert_eq!(reply["error"]["code"], "invalid_request", "{bad}: {reply}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_grants_are_unlisted_and_a_row_expires_with_its_last_grant() {
    let f = fixture();
    let issues_id = row_id(ALL_AGENT, ALL_CONNECTION, Capability::OpenIssues);
    let now = plexus_core::storage::now_ms();
    set_grant(&f.scratch, ALL_AGENT, "create_issue", "expires_at", now - 1);
    set_grant(
        &f.scratch,
        ALL_AGENT,
        "create_pull_request",
        "expires_at",
        now + 3_600_000,
    );
    set_grant(
        &f.scratch,
        ALL_AGENT,
        "add_reaction",
        "expires_at",
        now + 7_200_000,
    );
    set_grant(
        &f.scratch,
        ALL_AGENT,
        "close_issue",
        "expires_at",
        now + 3_600_001,
    );
    let rows = list(&f.state, json!({})).await;
    assert!(
        row(&rows, ALL_AGENT, "github_bot_open_issues").is_none(),
        "a row whose only grant expired is gone: {rows}"
    );
    assert_eq!(
        row(&rows, ALL_AGENT, "github_bot_open_pull_requests").unwrap()["expires_at_ms"],
        now + 3_600_000
    );
    // The permissions page contract (`permissions/v1`, defined in the
    // cingulate repository's docs/contracts/permissions-v1.md) lists a
    // capability row only while one of its grants is live. The row's
    // `expires_at_ms` is the latest expiry among those grants, and is left
    // out when any of them never expires. Both speak rows below still hold
    // speech grants without an expiry, so neither carries `expires_at_ms`,
    // even though `agent-all`'s `add_reaction` and `close_issue` grants now
    // expire.
    assert!(row(&rows, ALL_AGENT, "github_bot_speak")
        .unwrap()
        .get("expires_at_ms")
        .is_none());
    assert!(row(&rows, SPEAK_AGENT, "github_bot_speak")
        .unwrap()
        .get("expires_at_ms")
        .is_none());
    assert_eq!(
        revoke(&f.state, &issues_id).await,
        json!({"result": {"outcome": "not_found"}}),
        "an expired row answers not_found, like an unknown one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_removes_exactly_the_rows_live_grants() {
    let f = fixture();
    let before = list(&f.state, json!({})).await;
    let total = count(&f.scratch, "SELECT COUNT(*) FROM grants");
    let pulls = row_id(ALL_AGENT, ALL_CONNECTION, Capability::OpenPullRequests);
    let (principal, grant_id) = grant_of(&f.scratch, ALL_AGENT, "create_pull_request");
    assert_eq!(
        revoke(&f.state, &pulls).await,
        json!({"result": {"outcome": "revoked"}})
    );
    assert_eq!(
        count(&f.scratch, "SELECT COUNT(*) FROM grants"),
        total - 1,
        "revoking open_pull_requests must remove its one grant and nothing else"
    );
    let gone: i64 = sql(&f.scratch)
        .query_row(
            "SELECT COUNT(*) FROM grants WHERE principal = ?1 AND grant_id = ?2",
            [&principal, &grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(gone, 0);
    let after = list(&f.state, json!({})).await;
    let mut expected = before.as_array().unwrap().clone();
    expected.retain(|row| row["id"] != pulls);
    assert_eq!(
        after,
        Value::Array(expected),
        "speak and open_issues, and the other agent's row, must be untouched"
    );
    let snapshot: i64 = sql(&f.scratch)
        .query_row(
            "SELECT COUNT(*) FROM grant_revocations WHERE principal = ?1 AND grant_id = ?2",
            [&principal, &grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        snapshot, 1,
        "the revoke keeps its grant_revocations snapshot"
    );
    let audit: Vec<_> = f
        .store
        .list_audit(&principal)
        .unwrap()
        .into_iter()
        .filter(|row| row.reason_code == "permissions_revoke")
        .collect();
    assert_eq!(audit.len(), 1, "one audit row per revoked grant: {audit:?}");
    assert_eq!(audit[0].acting_principal, "reserved:cingulate");
    assert_eq!(audit[0].agent_id.as_deref(), Some(ALL_AGENT));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeat_or_unknown_revoke_answers_not_found() {
    let f = fixture();
    let speak = row_id(ALL_AGENT, ALL_CONNECTION, Capability::Speak);
    assert_eq!(
        revoke(&f.state, &speak).await,
        json!({"result": {"outcome": "revoked"}})
    );
    assert_eq!(
        revoke(&f.state, &speak).await,
        json!({"result": {"outcome": "not_found"}}),
        "revoking is idempotent"
    );
    assert_eq!(
        revoke(&f.state, "plx_unknown").await,
        json!({"result": {"outcome": "not_found"}})
    );
    let rows = list(&f.state, json!({})).await;
    assert_eq!(
        scopes_of(&rows, ALL_AGENT),
        ["github_bot_open_issues", "github_bot_open_pull_requests"]
    );
    for params in [
        json!({}),
        json!({"id": ""}),
        json!({"id": speak, "module": "plexus"}),
    ] {
        let reply = route_call(
            &f.state,
            reserved("cingulate"),
            CallMode::Classic,
            json!({"method": "permissions.revoke", "params": params}),
        )
        .await;
        assert_eq!(
            reply["error"]["code"], "invalid_request",
            "{params}: {reply}"
        );
    }
}

/// Drop every handle on the store, then open it again from its file, as a
/// restart does. The journal is replayed on open.
fn reopen(f: Fixture) -> Fixture {
    let Fixture {
        state,
        store,
        transport: _,
        scratch,
    } = f;
    drop(state);
    drop(store);
    let store = Arc::new(PlexusStore::open(&descriptor(&scratch)).unwrap());
    let (state, transport) = state_for(store.clone());
    Fixture {
        state,
        store,
        transport,
        scratch,
    }
}

fn journal(scratch: &Scratch) -> PathBuf {
    scratch.path().with_file_name("grant-revocations.jsonl")
}

fn live_speak_grants(scratch: &Scratch, agent: &str) -> i64 {
    sql(scratch)
        .query_row(
            "SELECT COUNT(*) FROM grants WHERE agent_id = ?1
             AND action_selectors NOT IN ('[\"create_issue\"]', '[\"create_pull_request\"]')",
            [agent],
            |row| row.get(0),
        )
        .unwrap()
}

/// The revoke is journaled before the database changes, so restoring the
/// database from a backup taken before the revoke does not bring the grants
/// back: the journal beside it is replayed when the store opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_database_keeps_the_revoked_row_revoked() {
    let f = fixture();
    let backup = Scratch::database("permissions-backup");
    sql(&f.scratch)
        .execute("VACUUM INTO ?1", [backup.path().to_string_lossy()])
        .unwrap();
    let speak = row_id(ALL_AGENT, ALL_CONNECTION, Capability::Speak);
    assert_eq!(
        revoke(&f.state, &speak).await,
        json!({"result": {"outcome": "revoked"}})
    );
    let Fixture {
        state,
        store,
        transport: _,
        scratch,
    } = f;
    drop(state);
    drop(store);
    // Restore: the database file is replaced by the backup; its siblings,
    // the journal among them, stay.
    for sibling in ["store.db-wal", "store.db-shm"] {
        let _ = std::fs::remove_file(scratch.path().with_file_name(sibling));
    }
    std::fs::copy(backup.path(), scratch.path()).unwrap();
    assert_eq!(
        live_speak_grants(&scratch, ALL_AGENT),
        14,
        "the restored file holds the speech grants again"
    );
    let store = Arc::new(PlexusStore::open(&descriptor(&scratch)).unwrap());
    let (state, _transport) = state_for(store);
    assert_eq!(
        live_speak_grants(&scratch, ALL_AGENT),
        0,
        "a restore must not bring revoked grants back"
    );
    let rows = list(&state, json!({})).await;
    assert_eq!(
        scopes_of(&rows, ALL_AGENT),
        ["github_bot_open_issues", "github_bot_open_pull_requests"],
        "a restore must not bring the revoked row back: {rows}"
    );
    let journal_lines = std::fs::read_to_string(journal(&scratch)).unwrap();
    assert_eq!(
        journal_lines.lines().count(),
        14,
        "one journal line per grant"
    );
}

/// A row's grants are revoked one at a time. Interrupt the revoke at both
/// points a crash can hit: after one grant was fully revoked, and after the
/// next grant's journal line was written but before the database delete.
/// The row keeps its id, the restart's replay finishes the journaled grant,
/// and a retry revokes the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_revoke_converges_on_retry() {
    let f = fixture();
    let speak = row_id(ALL_AGENT, ALL_CONNECTION, Capability::Speak);
    let (principal, first) = grant_of(&f.scratch, ALL_AGENT, "add_issue_comment");
    assert!(f.store.revoke_grant(&principal, &first).unwrap());
    let (_, second) = grant_of(&f.scratch, ALL_AGENT, "add_reaction");
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(journal(&f.scratch))
            .unwrap();
        writeln!(
            file,
            "{}",
            json!({"principal": principal, "grant_id": second, "revoked_at_ms": 1})
        )
        .unwrap();
    }
    assert_eq!(live_speak_grants(&f.scratch, ALL_AGENT), 13);
    let f = reopen(f);
    assert_eq!(
        live_speak_grants(&f.scratch, ALL_AGENT),
        12,
        "the journaled grant is revoked by the replay on open"
    );
    let rows = list(&f.state, json!({})).await;
    assert_eq!(
        row(&rows, ALL_AGENT, "github_bot_speak").unwrap()["id"],
        speak,
        "a partly revoked row keeps its id"
    );
    assert_eq!(
        revoke(&f.state, &speak).await,
        json!({"result": {"outcome": "revoked"}})
    );
    assert_eq!(live_speak_grants(&f.scratch, ALL_AGENT), 0);
    assert_eq!(
        count(
            &f.scratch,
            "SELECT COUNT(*) FROM grant_revocations GROUP BY grant_id ORDER BY 1 DESC LIMIT 1"
        ),
        1,
        "every grant is revoked once"
    );
    assert_eq!(
        scopes_of(&list(&f.state, json!({})).await, ALL_AGENT),
        ["github_bot_open_issues", "github_bot_open_pull_requests"]
    );
}

/// Only cingulate and the local operator's direct route are admitted, and
/// only on a classic route. A route's call mode, which the daemon derives
/// from the route's scope when the route is bound, says what kind of work the
/// route carries: classic for an ordinary session, flow for an automation
/// Basal runs (a scope with a flow id), codemode for calls made from inside a
/// code run (a scope with a run id). A flow or a codemode run is an agent's
/// work even when its principal would be admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_cingulate_and_direct_are_admitted() {
    let f = fixture();
    let refusal = serde_json::from_str::<Value>(REFUSED_AGENT).unwrap()["error"].clone();
    let speak = row_id(ALL_AGENT, ALL_CONNECTION, Capability::Speak);
    let total = count(&f.scratch, "SELECT COUNT(*) FROM grants");
    for (principal, mode) in [
        (reserved("aft"), CallMode::Classic),
        (reserved("prefrontal-core"), CallMode::Classic),
        (reserved("broca"), CallMode::Classic),
        (reserved("basal"), CallMode::Flow),
        (reserved("cingulate"), CallMode::Flow),
        (reserved("cingulate"), CallMode::Codemode),
        (Principal::Direct, CallMode::Codemode),
    ] {
        for body in [
            json!({"method": "permissions.list", "params": {}}),
            json!({"method": "permissions.revoke", "params": {"id": speak}}),
        ] {
            let reply = route_call(&f.state, principal.clone(), mode.clone(), body).await;
            assert_eq!(
                reply,
                json!({"error": refusal}),
                "{principal:?} in {mode:?} must be refused with permissions_operator_required"
            );
        }
    }
    assert_eq!(
        count(&f.scratch, "SELECT COUNT(*) FROM grants"),
        total,
        "a refused revoke must revoke nothing"
    );
    for principal in [reserved("cingulate"), Principal::Direct] {
        let reply = route_call(
            &f.state,
            principal.clone(),
            CallMode::Classic,
            json!({"method": "permissions.list", "params": {}}),
        )
        .await;
        assert_eq!(
            reply["result"]["grants"].as_array().map(Vec::len),
            Some(4),
            "{principal:?} must be admitted: {reply}"
        );
    }
    let reply = route_call(
        &f.state,
        Principal::Direct,
        CallMode::Classic,
        json!({"method": "permissions.revoke", "params": {"id": speak}}),
    )
    .await;
    assert_eq!(reply, json!({"result": {"outcome": "revoked"}}));
}

/// Binding gives cingulate no tool authority: it holds no grants, so a
/// facade call is refused before anything reaches the vendor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cingulate_binds_but_holds_no_tool_authority() {
    let f = fixture();
    let reply = route_call(
        &f.state,
        reserved("cingulate"),
        CallMode::Classic,
        json!({"name": "invoke", "arguments": {"op": "call", "connection": ALL_CONNECTION,
            "action": "github.issue.get", "args": {"owner": "cortexkit", "repo": "magic-context", "issue_number": 1}}}),
    )
    .await;
    assert!(
        reply.get("error").is_some() || reply["isError"] == true,
        "cingulate must not invoke: {reply}"
    );
    assert!(
        f.transport.requests().is_empty(),
        "nothing may reach the vendor"
    );
}

const VECTORS: [(&str, &str); 8] = [
    (
        "provider-list",
        include_str!("../tests/fixtures/permissions-v1/provider-list.json"),
    ),
    (
        "provider-list-after-upgrade",
        include_str!("../tests/fixtures/permissions-v1/provider-list-after-upgrade.json"),
    ),
    (
        "provider-list-after-expiry",
        include_str!("../tests/fixtures/permissions-v1/provider-list-after-expiry.json"),
    ),
    (
        "provider-revoke-revoked",
        include_str!("../tests/fixtures/permissions-v1/provider-revoke-revoked.json"),
    ),
    (
        "provider-revoke-stopping",
        include_str!("../tests/fixtures/permissions-v1/provider-revoke-stopping.json"),
    ),
    (
        "provider-revoke-not-found",
        include_str!("../tests/fixtures/permissions-v1/provider-revoke-not-found.json"),
    ),
    (
        "provider-revoke-expired",
        include_str!("../tests/fixtures/permissions-v1/provider-revoke-expired.json"),
    ),
    ("provider-revoke-refused-agent", REFUSED_AGENT),
];

fn vector(name: &str) -> Value {
    let (_, text) = VECTORS.iter().find(|(case, _)| *case == name).unwrap();
    serde_json::from_str(text).unwrap()
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Every field the provider vectors' rows use (the `provider-list*.json`
/// files in `crates/plexus-module/tests/fixtures/permissions-v1/`), with its
/// JSON type, and the agent holder's exact field set.
fn vector_row_fields() -> (BTreeMap<String, &'static str>, BTreeSet<String>) {
    let mut fields = BTreeMap::new();
    let mut agent_holder = BTreeSet::new();
    for case in [
        "provider-list",
        "provider-list-after-upgrade",
        "provider-list-after-expiry",
    ] {
        let case = vector(case);
        assert_eq!(case["route"]["principal"], "reserved:cingulate");
        for row in case["reply"]["grants"].as_array().unwrap() {
            for (field, value) in row.as_object().unwrap() {
                let previous = fields.insert(field.clone(), kind(value));
                assert!(previous.is_none_or(|previous| previous == kind(value)));
            }
            if row["holder"]["kind"] == "agent" {
                agent_holder = row["holder"].as_object().unwrap().keys().cloned().collect();
            }
        }
    }
    (fields, agent_holder)
}

/// Plexus's rows use only the contract's fields, with the vectors' types, and
/// carry every field the contract requires. The vectors' rows are
/// Cerebellum's (Cerebellum is another module that provides permissions/v1,
/// for its grants to use desktop apps and sites in the agent browser), so
/// values are not compared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_replies_have_the_vector_shape() {
    let f = fixture();
    let now = plexus_core::storage::now_ms();
    set_grant(
        &f.scratch,
        ALL_AGENT,
        "create_issue",
        "expires_at",
        now + 3_600_000,
    );
    let reply = route_call(
        &f.state,
        reserved("cingulate"),
        CallMode::Classic,
        json!({"method": "permissions.list", "params": vector("provider-list")["request"]}),
    )
    .await;
    let result = reply["result"].as_object().unwrap();
    assert_eq!(
        result.keys().collect::<Vec<_>>(),
        vector("provider-list")["reply"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>()
    );
    let (fields, agent_holder) = vector_row_fields();
    let required = [
        "id",
        "agent_id",
        "holder",
        "module",
        "subject_label",
        "scope",
        "scope_label",
        "granted_at_ms",
    ];
    let rows = result["grants"].as_array().unwrap();
    assert!(rows.iter().any(|row| row.get("expires_at_ms").is_some()));
    for row in rows {
        let row = row.as_object().unwrap();
        for field in required {
            assert!(row.contains_key(field), "{field} missing: {row:?}");
        }
        for (field, value) in row {
            assert_eq!(
                fields.get(field).copied(),
                Some(kind(value)),
                "{field} is not a vector field of that type"
            );
        }
        assert!(!row.contains_key("group") && !row.contains_key("card_ref"));
        let holder: BTreeSet<String> = row["holder"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(holder, agent_holder);
        assert_eq!(row["holder"]["kind"], "agent");
        assert_eq!(row["holder"]["agent_id"], row["agent_id"]);
    }
}

/// Revoke answers use the outcome values of the `provider-revoke-*.json`
/// vectors and never `stopping`: plexus checks grants again before every
/// dispatch and every bot write, so there is no running work for a revoke to
/// stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_replies_have_the_vector_shape() {
    let f = fixture();
    let speak = row_id(ALL_AGENT, ALL_CONNECTION, Capability::Speak);
    let revoked = revoke(&f.state, &speak).await;
    assert_eq!(
        revoked["result"],
        vector("provider-revoke-revoked")["reply"]
    );
    assert_eq!(
        revoked["result"].get("stopping"),
        None,
        "plexus never answers stopping"
    );
    assert_eq!(
        vector("provider-revoke-stopping")["reply"]["outcome"],
        "revoked"
    );
    assert_eq!(
        revoke(&f.state, &speak).await["result"],
        vector("provider-revoke-expired")["reply"]
    );
    let unknown = vector("provider-revoke-not-found");
    let reply = route_call(
        &f.state,
        reserved("cingulate"),
        CallMode::Classic,
        json!({"method": "permissions.revoke", "params": unknown["request"]}),
    )
    .await;
    assert_eq!(reply["result"], unknown["reply"]);
    let refused = vector("provider-revoke-refused-agent");
    let reply = route_call(
        &f.state,
        reserved("aft"),
        CallMode::Classic,
        json!({"method": "permissions.revoke", "params": refused["request"]}),
    )
    .await;
    assert_eq!(reply, json!({"error": refused["error"]}));
}

/// The copied vectors in `crates/plexus-module/tests/fixtures/permissions-v1/`
/// are byte for byte the files cingulate's checksum list (`SHA256SUMS`)
/// names. Only the provider cases and the README are copied; the list also
/// names cingulate's aggregator cases, which are absent here.
#[test]
fn copied_vectors_match_their_checksums() {
    use sha2::{Digest, Sha256};
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/permissions-v1");
    let sums = std::fs::read_to_string(directory.join("SHA256SUMS")).unwrap();
    let mut checked = 0;
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        if !(name.starts_with("provider-") || name == "README.md") {
            continue;
        }
        let bytes = std::fs::read(directory.join(name)).unwrap();
        assert_eq!(
            hex_lower(&Sha256::digest(&bytes)),
            sum,
            "{name} differs from cingulate's"
        );
        checked += 1;
    }
    assert_eq!(
        checked, 25,
        "8 provider cases of 3 files each, and the README"
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
