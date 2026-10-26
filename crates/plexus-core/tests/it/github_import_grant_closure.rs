//! An agent imported with a set of writes can make every request those writes
//! name, end to end: the real import mints the agent's grants into a real
//! store, and each request runs the real facade and governance path against a
//! recording transport.
use crate::scope_support::{delegating_scope, LiveScopeReader};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::control::{
    self, AgentPermission, InstallationReader, Inventory, InventoryHandle,
};
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::github::facade::bot_request_scoped;
use plexus_core::governance::GovernanceEngine;
use plexus_core::scope::CallScope;
use plexus_core::storage::github_store::GithubGovernanceSeams;
use plexus_core::transport::{MockResponse, MockTransport};
use plexus_core::{ingest_value, PlexusStore, CATALOG_PRINCIPAL};
use serde_json::{json, Value};
use std::sync::Arc;

/// The writes the first real inventory grants every agent, plus reopen.
const INVENTORY_WRITES: &[&str] = &[
    "add_issue_comment",
    "update_issue_comment",
    "add_pr_review",
    "add_reaction",
    "edit_issue",
    "close_issue",
    "reopen_issue",
];

/// Supplies the vault token for both the import's repository listing and the
/// facade's dispatch; neither is inspected by this test.
struct Token;
impl HandleCredentialProvider for Token {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        Ok(ResolvedCredential::new(
            reference.as_bytes().to_vec(),
            None,
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

/// The installation can reach exactly the one repository the agent is bound to.
struct Repositories;
impl InstallationReader for Repositories {
    fn repositories_page(
        &self,
        _: &ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        Ok(json!({"repositories":[{"full_name":"org/repo"}]}))
    }
}

// Parse the shipped reviewed JSONC, as the control-surface tests do, so the
// imported connection is seeded from the real catalog.
fn github_manifest() -> plexus_core::IngestedManifest {
    let source = include_str!(concat!("../", "../../../catalog/github_rest.jsonc"));
    let clean = subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
    ingest_value(serde_json::from_str(&clean).unwrap()).unwrap()
}

/// The handle belongs to the agent identified by the fixture's route stamp.
fn inventory(writes: &[&str]) -> Inventory {
    Inventory {
        version: "github-grant-import.v1".into(),
        handles: vec![InventoryHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            app_id: 42,
            installation_id: None,
            credential_id: "github_app:app-fixture".into(),
            status: "enabled".into(),
            grants: writes
                .iter()
                .map(|action| AgentPermission {
                    action: (*action).into(),
                    repository: "org/repo".into(),
                    provenance: format!("inventory-{action}"),
                    policy: "allow".into(),
                })
                .collect(),
        }],
    }
}

// Fields drop in declaration order: the scratch guard is last so the store
// and engine close before it removes their directory.
struct Imported {
    store: Arc<PlexusStore>,
    engine: GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>,
    transport: Arc<MockTransport>,
    scope: CallScope,
    _scratch: plexus_core::test_scratch::Scratch,
}

/// Imports `writes` for the fixture agent through the real import, proves the
/// handle with the real probe, and wires the facade exactly as the module does.
fn imported(label: &str, writes: &[&str]) -> Imported {
    imported_from(label, &inventory(writes))
}

fn imported_from(label: &str, inventory: &Inventory) -> Imported {
    imported_with(label, inventory, &Repositories)
}

#[test]
fn poll_regrant_survives_restart_while_restored_issuance_stays_revoked() {
    let label = "poll-grant-replay";
    let fixture = imported(label, &["add_reaction"]);
    let grant = plexus_core::storage::github_store::GithubHandlePollGrant {
        app_handle_id: "app-fixture".into(),
        actions: vec!["github.issue.get".into()],
        dry_run: false,
    };
    let mint = |store: &PlexusStore| store.grant_github_handle_poll(&grant).unwrap().unwrap();
    let first = mint(&fixture.store);
    let old = first["grants"][0]["grant_id"].as_str().unwrap().to_owned();
    assert_eq!(mint(&fixture.store)["grants"][0]["op"], "unchanged");
    let backup = fixture._scratch.path().with_file_name("before-revoke.db");
    rusqlite::Connection::open(fixture._scratch.path())
        .unwrap()
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    assert!(fixture.store.revoke_grant("direct", &old).unwrap());
    let second = mint(&fixture.store);
    let new = second["grants"][0]["grant_id"].as_str().unwrap().to_owned();
    let Imported {
        _scratch: scratch,
        store,
        engine,
        ..
    } = fixture;
    drop(engine);
    drop(store);
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: label.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).unwrap();
    assert!(store
        .list_grants("direct", "github-handle-app-fixture")
        .unwrap()
        .iter()
        .any(|row| row.grant_id == new && row.revoked_at_ms.is_none()));
    assert_ne!(old, new, "a regrant must not reuse a journaled issuance id");
    drop(store);
    std::fs::copy(&backup, scratch.path()).unwrap();
    let restored = PlexusStore::open(&descriptor).unwrap();
    assert!(restored
        .list_grants("direct", "github-handle-app-fixture")
        .unwrap()
        .iter()
        .all(|row| row.grant_id != old || row.revoked_at_ms.is_some()));
}

#[test]
fn a_second_single_use_import_refuses_without_duplicate_grants() {
    let fixture = imported("single-use-import", &["add_reaction"]);
    let before = fixture
        .store
        .list_grants("direct", "github-handle-app-fixture")
        .unwrap();
    assert!(control::import(
        &fixture.store,
        "direct",
        &inventory(&["add_reaction"]),
        &Token,
        &Repositories,
        0,
        false
    )
    .is_err());
    assert_eq!(
        fixture
            .store
            .list_grants("direct", "github-handle-app-fixture")
            .unwrap(),
        before
    );
}

/// As [`imported_from`], with the import's installation listing supplied by
/// `reader`, for inventories that bind more than the one fixture repository.
fn imported_with(label: &str, inventory: &Inventory, reader: &dyn InstallationReader) -> Imported {
    let scratch = plexus_core::test_scratch::Scratch::database(label);
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: label.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
        .unwrap();
    control::import(&store, "direct", inventory, &Token, reader, 0, false).unwrap();
    control::probe(&store, "direct", "app-fixture", &Token, reader, 1).unwrap();
    let scope = delegating_scope("agent-fixture");
    let transport = Arc::new(MockTransport::default());
    // Ownership reads answer as the bot the fixture handle speaks for.
    let bot = json!({"login":"app-fixture[bot]","type":"Bot"});
    transport.set_response_for_method(
        "github.issue.get",
        "",
        MockResponse::Success(json!({"number":42,"user":bot})),
    );
    transport.set_response_for_method(
        "github.issue_comment.get",
        "",
        MockResponse::Success(json!({"id":123,"user":bot})),
    );
    transport.set_response_for_method(
        "github.issue_comments.list",
        "",
        MockResponse::Success(json!([
            {"id":5,"user":{"login":"someone","type":"User"}},
            {"id":123,"user":bot}
        ])),
    );
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    Imported {
        _scratch: scratch,
        store,
        engine,
        transport,
        scope,
    }
}

/// A recorded shim request, pointed at the agent's bound repository.
fn wire(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/gh_shim_wire/requests/{name}.request.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut request: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    request["repository"] = json!("org/repo");
    request
}

/// Runs one request for an agent imported with [`INVENTORY_WRITES`] (or
/// `writes`), asserts it completed, and returns every transport call it made.
fn drive_with(label: &str, writes: &[&str], request: Value) -> Vec<(String, Value)> {
    let (reply, calls) = send(&imported(label, writes), label, request);
    assert_eq!(reply["result"]["status"], "completed", "{label}: {reply}");
    calls
}

/// Sends one bot request as AFT and returns the reply and every transport call.
fn send(fixture: &Imported, label: &str, request: Value) -> (Value, Vec<(String, Value)>) {
    let now = plexus_core::now_ms();
    let reply = bot_request_scoped(
        &fixture.store,
        &fixture.engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&fixture.scope),
        &request,
        &format!("{label}-nonce"),
        &format!("{label}-id"),
        "worker",
        now,
    );
    let calls = fixture
        .transport
        .requests()
        .into_iter()
        .map(|request| (request.action, request.args))
        .collect();
    (reply, calls)
}

fn drive(label: &str, request: Value) -> Vec<(String, Value)> {
    drive_with(label, INVENTORY_WRITES, request)
}

fn actions(calls: &[(String, Value)]) -> Vec<&str> {
    calls.iter().map(|(action, _)| action.as_str()).collect()
}

#[test]
fn imported_agent_completes_issue_comment() {
    let calls = drive("closure-comment", wire("v1-issue-comment"));
    assert_eq!(actions(&calls), ["add_issue_comment"]);
    assert_eq!(calls[0].1["issue_number"], 42);
    assert_eq!(calls[0].1["body"], "A governed issue comment.");
}

#[test]
fn imported_agent_completes_pr_comment() {
    let calls = drive("closure-pr-comment", wire("v1-pr-comment"));
    assert_eq!(actions(&calls), ["add_issue_comment"]);
    assert_eq!(calls[0].1["issue_number"], 7);
}

#[test]
fn imported_agent_completes_edit_last() {
    let calls = drive("closure-edit-last", wire("v10-issue-comment-edit-last"));
    assert_eq!(
        actions(&calls),
        [
            "github.issue_comments.list",
            "github.issue_comment.get",
            "update_issue_comment"
        ]
    );
    assert_eq!(calls[2].1["comment_id"], 123);
    assert_eq!(
        calls[2].1["body"],
        "Replacement text for the bot's last comment."
    );
}

#[test]
fn imported_agent_completes_comment_patch() {
    let calls = drive("closure-comment-patch", wire("v14-api-patch-issue-comment"));
    assert_eq!(
        actions(&calls),
        ["github.issue_comment.get", "update_issue_comment"]
    );
    assert_eq!(calls[1].1["comment_id"], 123);
    assert_eq!(calls[1].1["body"], "Edited comment text.");
}

#[test]
fn imported_agent_completes_pr_review() {
    let calls = drive("closure-pr-review", wire("v1-pr-review"));
    assert_eq!(actions(&calls), ["add_pr_review"]);
    assert_eq!(calls[0].1["pull_number"], 7);
    assert!(calls[0].1.get("issue_number").is_none());
    assert_eq!(calls[0].1["event"], "COMMENT");
    assert_eq!(calls[0].1["body"], "A governed review comment.");
}

#[test]
fn imported_agent_completes_each_v22_write_with_only_its_implied_reads() {
    let bot = json!({"login":"app-fixture[bot]", "type":"Bot"});
    let stack = json!({"url":"https://api.github.com/repos/org/repo/stacks/3", "number":3,
        "pull_requests":[{"number":7,"user":bot,"base":{"repo":{"url":"https://api.github.com/repos/org/repo"}}}]});
    for (action, wire_action, target, body, read, read_value, response) in [
        (
            "edit_pull_request",
            "pr edit",
            json!({"number":"7"}),
            json!({"title":"T"}),
            Some("github.pull_request.get"),
            json!({"number":7,"user":bot}),
            json!({"number":7}),
        ),
        (
            "reply_to_review_comment",
            "api:POST:/repos/*/*/pulls/*/comments/*/replies",
            json!({"number":"7","comment_id":"99"}),
            json!({"body":"B"}),
            None,
            Value::Null,
            json!({"id":100}),
        ),
        (
            "resolve_review_thread",
            "graphql resolvereviewthread",
            json!({"thread_id":"PRRT_7"}),
            json!({}),
            Some("github.review_thread.get"),
            json!({"data":{"node":{"id":"PRRT_7","pullRequest":{"repository":{"nameWithOwner":"org/repo"}}}}}),
            json!({"data":{"resolveReviewThread":{"thread":{"id":"PRRT_7","isResolved":true}}}}),
        ),
        (
            "unresolve_review_thread",
            "graphql unresolvereviewthread",
            json!({"thread_id":"PRRT_7"}),
            json!({}),
            Some("github.review_thread.get"),
            json!({"data":{"node":{"id":"PRRT_7","pullRequest":{"repository":{"nameWithOwner":"org/repo"}}}}}),
            json!({"data":{"unresolveReviewThread":{"thread":{"id":"PRRT_7","isResolved":false}}}}),
        ),
        (
            "create_pull_request_stack",
            "api:POST:/repos/*/*/stacks",
            json!({}),
            json!({"pull_requests":[7]}),
            Some("github.pull_request.get"),
            json!({"number":7,"user":bot}),
            stack.clone(),
        ),
        (
            "add_to_pull_request_stack",
            "api:POST:/repos/*/*/stacks/*/add",
            json!({"stack_number":"3"}),
            json!({"pull_requests":[7]}),
            Some("github.pull_request.get"),
            json!({"number":7,"user":bot}),
            stack.clone(),
        ),
        (
            "unstack_pull_requests",
            "api:POST:/repos/*/*/stacks/*/unstack",
            json!({"stack_number":"3"}),
            json!({}),
            Some("github.stack.get"),
            stack.clone(),
            Value::Null,
        ),
    ] {
        let fixture = imported("v22-import", &[action]);
        if let Some(read) = read {
            fixture
                .transport
                .set_response_for_method(read, "", MockResponse::Success(read_value));
        }
        fixture
            .transport
            .set_response_for_method(action, "", MockResponse::Success(response));
        let mut request = json!({"action":wire_action,"repository":"org/repo","manifest_version":22,"target":target,"body":body});
        if wire_action == "pr edit" {
            request["author_scope"] = json!("own");
        }
        let (reply, calls) = send(&fixture, "v22-import", request);
        assert_eq!(reply["result"]["status"], "completed", "{action}: {reply}");
        let expected: Vec<_> = read.into_iter().chain(std::iter::once(action)).collect();
        assert_eq!(actions(&calls), expected, "{action}");
    }
}

#[test]
fn imported_agent_completes_reaction() {
    let calls = drive("closure-reaction", wire("v1-issue-reaction"));
    assert_eq!(actions(&calls), ["add_reaction"]);
    assert_eq!(calls[0].1["content"], "+1");
}

#[test]
fn imported_agent_completes_own_issue_edit_with_title_labels_and_assignees() {
    let mut request = wire("v14-issue-edit-title-body");
    request["body"] = json!({
        "title":"A retitled issue",
        "add_labels":["triaged"],
        "remove_labels":["needs-triage"],
        "add_assignees":["octocat"],
        "remove_assignees":["hubot"]
    });
    let calls = drive("closure-issue-edit", request);
    assert_eq!(
        actions(&calls),
        [
            "github.issue.get",
            "edit_issue",
            "add_issue_labels",
            "remove_issue_label",
            "add_issue_assignees",
            "remove_issue_assignees"
        ]
    );
    assert_eq!(calls[1].1["title"], "A retitled issue");
    assert_eq!(calls[2].1["labels"], json!(["triaged"]));
    assert_eq!(calls[3].1["label"], "needs-triage");
    assert_eq!(calls[4].1["assignees"], json!(["octocat"]));
    assert_eq!(calls[5].1["assignees"], json!(["hubot"]));
}

#[test]
fn imported_agent_completes_close_with_comment() {
    let calls = drive("closure-close-comment", wire("v12-issue-close"));
    assert_eq!(actions(&calls), ["add_issue_comment", "close_issue"]);
    assert_eq!(calls[0].1["body"], "Closing as not planned.");
    assert_eq!(calls[1].1["state"], "closed");
    assert_eq!(calls[1].1["state_reason"], "not_planned");
    assert!(calls[1].1.get("comment").is_none());
}

#[test]
fn imported_agent_completes_close_without_comment() {
    let mut request = wire("v12-issue-close");
    request.as_object_mut().unwrap().remove("comment");
    let calls = drive("closure-close", request);
    assert_eq!(actions(&calls), ["close_issue"]);
    assert_eq!(calls[0].1["state"], "closed");
}

#[test]
fn imported_agent_completes_reopen() {
    let mut request = wire("v12-issue-reopen");
    request.as_object_mut().unwrap().remove("comment");
    let calls = drive("closure-reopen", request);
    assert_eq!(actions(&calls), ["reopen_issue"]);
    assert_eq!(calls[0].1["state"], "open");
}

#[test]
fn imported_agent_completes_reopen_with_comment() {
    let calls = drive("closure-reopen-comment", wire("v12-issue-reopen"));
    assert_eq!(actions(&calls), ["add_issue_comment", "reopen_issue"]);
    assert_eq!(calls[0].1["issue_number"], 42);
    assert_eq!(calls[0].1["body"], "Reopening for another pass.");
    assert_eq!(calls[1].1["state"], "open");
    assert!(calls[1].1.get("comment").is_none());
}

#[test]
fn imported_agent_reacts_with_any_github_reaction() {
    // The recorded shim request reacts +1, not the seen-marker's eyes.
    for (index, reaction) in [
        "+1", "-1", "laugh", "confused", "heart", "hooray", "rocket", "eyes",
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = wire("v1-issue-reaction");
        request["body"]["reaction"] = json!(reaction);
        let calls = drive(&format!("closure-reaction-{index}"), request);
        assert_eq!(actions(&calls), ["add_reaction"]);
        assert_eq!(calls[0].1["content"], reaction);
    }
}

#[test]
fn unknown_reaction_refuses_before_any_vendor_call() {
    let fixture = imported("closure-reaction-unknown", INVENTORY_WRITES);
    let mut request = wire("v1-issue-reaction");
    request["body"]["reaction"] = json!("thumbs");
    let (reply, calls) = send(&fixture, "closure-reaction-unknown", request);
    assert_eq!(
        reply["result"]["refusal_code"], "request_field_forbidden{field: reaction}",
        "{reply}"
    );
    assert!(calls.is_empty());
}

#[test]
fn issue_edit_carrying_state_or_milestone_refuses_before_any_vendor_call() {
    let fixture = imported("closure-edit-forbidden", INVENTORY_WRITES);
    for (field, value) in [("state", json!("closed")), ("milestone", json!(3))] {
        let mut request = wire("v14-issue-edit-title-body");
        request["body"][field] = value;
        let (reply, calls) = send(&fixture, &format!("closure-edit-{field}"), request);
        assert_eq!(
            reply["result"]["refusal_code"],
            format!("request_field_forbidden{{field: {field}}}"),
            "{reply}"
        );
        assert!(calls.is_empty(), "{field}");
    }
}

/// Each agent grant row the import wrote for the fixture agent, as
/// (action, grant id), sorted by action.
fn agent_grants(store: &PlexusStore) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = store
        .list_grants("direct", "github-handle-app-fixture")
        .unwrap()
        .into_iter()
        .filter(|row| row.grant_id.contains(":agent:"))
        .map(|row| {
            assert_eq!(row.action_selectors.len(), 1, "{}", row.grant_id);
            (row.action_selectors[0].clone(), row.grant_id)
        })
        .collect();
    rows.sort();
    rows
}

#[test]
fn reaction_only_agent_gets_no_read_or_other_write() {
    let fixture = imported("closure-reaction-only", &["add_reaction"]);
    let grants = agent_grants(&fixture.store);
    assert_eq!(
        grants
            .iter()
            .map(|(action, _)| action.as_str())
            .collect::<Vec<_>>(),
        ["add_reaction"]
    );
}

#[test]
fn implied_rows_are_named_after_the_write_that_implies_them() {
    let fixture = imported("closure-implied-ids", INVENTORY_WRITES);
    let grants = agent_grants(&fixture.store);
    let actions: Vec<&str> = grants.iter().map(|(action, _)| action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "add_issue_assignees",
            "add_issue_comment",
            "add_issue_labels",
            "add_pr_review",
            "add_reaction",
            "close_issue",
            "edit_issue",
            "github.issue.get",
            "github.issue_comment.get",
            "github.issue_comments.list",
            "remove_issue_assignees",
            "remove_issue_label",
            "reopen_issue",
            "update_issue_comment",
        ]
    );
    let id = |action: &str| {
        grants
            .iter()
            .find(|(name, _)| name == action)
            .map(|(_, id)| id.clone())
            .unwrap()
    };
    // Only issue edits need the issue ownership read.
    assert!(id("github.issue.get").ends_with(":implied-by-edit_issue"));
    assert!(id("add_issue_labels").ends_with(":implied-by-edit_issue"));
    assert!(id("github.issue_comments.list").ends_with(":implied-by-update_issue_comment"));
    assert!(id("edit_issue").ends_with(":inventory-edit_issue"));
}

#[test]
fn create_issue_stays_grantable_but_is_implied_by_no_write() {
    let fixture = imported("closure-no-create", INVENTORY_WRITES);
    assert!(agent_grants(&fixture.store)
        .iter()
        .all(|(action, _)| action != "create_issue"));
    let calls = drive_with(
        "closure-create",
        &["create_issue"],
        wire("v14-issue-create"),
    );
    assert_eq!(actions(&calls), ["create_issue"]);
}

#[test]
fn pr_review_without_a_posting_event_refuses_before_any_vendor_call() {
    let fixture = imported("closure-review-event", INVENTORY_WRITES);
    for (index, event) in [json!("PENDING"), json!(null), json!(7)]
        .into_iter()
        .enumerate()
    {
        let mut request = wire("v1-pr-review");
        request["body"]["event"] = event;
        let (reply, calls) = send(&fixture, &format!("closure-review-event-{index}"), request);
        assert_eq!(
            reply["result"]["refusal_code"], "request_field_forbidden{field: event}",
            "{reply}"
        );
        assert!(calls.is_empty());
    }
}

/// Prefrontal's reads go through the grant the import mints to prefrontal's
/// real route principal.
#[test]
fn prefrontal_reads_through_an_imported_handle() {
    let fixture = imported("closure-prefrontal-read", INVENTORY_WRITES);
    // `since` is not an argument of the issue read, so it is dropped rather
    // than sent, and the routing `repository` never reaches the vendor.
    let issue = plexus_core::github::reads::read(
        &fixture.engine,
        plexus_core::github::PREFRONTAL_PRINCIPAL,
        "github.issue.get",
        &json!("org/repo"),
        &json!({"issue_number":42, "since":"2026-01-01T00:00:00Z"}),
    )
    .unwrap_or_else(|error| panic!("prefrontal read refused: {error:?}"));
    assert_eq!(issue["number"], 42);
    let calls = fixture.transport.requests();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].action, "github.issue.get");
    assert_eq!(
        calls[0].args,
        json!({"owner":"org","repo":"repo","issue_number":42})
    );
}

/// An imported handle connection's catalog rows pin each action's reviewed
/// `http.args_schema`, not an open placeholder, so governance can refuse an
/// argument the schema does not declare from the first call.
#[test]
fn imported_handle_rows_pin_the_reviewed_argument_schema() {
    let fixture = imported("closure-seeded-schema", INVENTORY_WRITES);
    let manifest = github_manifest().manifest;
    let rows = fixture
        .store
        .list_catalog_actions_all("direct", "github-handle-app-fixture")
        .unwrap();
    assert_eq!(rows.len(), manifest.actions_baseline.len());
    for row in rows {
        let declared = manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == row.name)
            .and_then(|action| action.http.as_ref())
            .unwrap_or_else(|| panic!("{} is a declared REST action", row.name));
        assert_eq!(row.schema, declared.args_schema, "{}", row.name);
        assert_eq!(
            row.schema_hash,
            plexus_core::jcs::jcs_sha256(&declared.args_schema).unwrap(),
            "{}",
            row.name
        );
    }
}

#[test]
fn imported_block_on_close_refuses_instead_of_parking() {
    let mut blocked = inventory(INVENTORY_WRITES);
    for row in &mut blocked.handles[0].grants {
        if row.action == "close_issue" {
            row.policy = "block".into();
        }
    }
    let fixture = imported_from("closure-block-close", &blocked);
    let mut request = wire("v12-issue-close");
    request.as_object_mut().unwrap().remove("comment");
    let (reply, calls) = send(&fixture, "closure-block-close", request);
    // A blocked write is left out of the handle's module grant as well as
    // getting an agent block policy, so the facade refuses at its grant check,
    // before policy composition could park the request for approval.
    assert_eq!(reply["result"]["status"], "refused", "{reply}");
    assert_eq!(
        reply["result"]["refusal_code"], "module_grant_absent",
        "{reply}"
    );
    assert!(calls.is_empty());
    // Blocking close does not block the independent reopen action.
    let mut reopen = wire("v12-issue-reopen");
    reopen.as_object_mut().unwrap().remove("comment");
    let (reply, calls) = send(&fixture, "closure-block-reopen", reopen);
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(actions(&calls), ["reopen_issue"]);
}

#[test]
fn import_writes_module_allows_for_writes_and_agent_policies_per_row() {
    let fixture = imported("closure-policies", &["edit_issue", "add_reaction"]);
    let effects = |principal: &str| {
        let mut rows: Vec<(String, String)> = fixture
            .store
            .list_policies(principal, Some("github-handle-app-fixture"))
            .unwrap()
            .into_iter()
            .map(|row| (row.action_selector, row.effect))
            .collect();
        rows.sort();
        rows
    };
    let allow = |actions: &[&str]| {
        actions
            .iter()
            .map(|action| ((*action).to_owned(), "allow".to_owned()))
            .collect::<Vec<_>>()
    };
    let writes = allow(&[
        "add_issue_assignees",
        "add_issue_labels",
        "add_reaction",
        "edit_issue",
        "remove_issue_assignees",
        "remove_issue_label",
    ]);
    // Reads default to allow and get no module policy.
    assert_eq!(effects("direct"), writes);
    assert_eq!(effects("agent-fixture"), writes);
}

/// The comment a reopen carries is the agent's own add_issue_comment ability,
/// never implied by reopen_issue, exactly as for a close.
#[test]
fn reopen_comment_needs_the_agents_comment_grant() {
    let fixture = imported("closure-reopen-no-comment-grant", &["reopen_issue"]);
    let (reply, calls) = send(
        &fixture,
        "closure-reopen-no-comment-grant",
        wire("v12-issue-reopen"),
    );
    assert_eq!(reply["result"]["status"], "refused", "{reply}");
    assert!(calls.is_empty());
}

/// Runs `github.handle.grant` as the operator on the fixture handle.
fn handle_grant(
    store: &PlexusStore,
    principal: &str,
    handle: &str,
    actions: &[&str],
    dry_run: bool,
) -> Result<Value, String> {
    let actions: Vec<String> = actions.iter().map(|action| (*action).to_owned()).collect();
    control::grant(
        store,
        principal,
        handle,
        &actions,
        plexus_core::github::AFT_PRINCIPAL,
        "allow",
        dry_run,
    )
}

/// Every row of the tables a handle grant may write, read through a separate
/// connection so the comparison does not go through the store under test.
fn authority_tables(fixture: &Imported) -> Vec<Vec<String>> {
    let conn = rusqlite::Connection::open(fixture._scratch.path()).unwrap();
    [
        "SELECT principal||'|'||connection_id||'|'||ceiling_risk||'|'||ceiling_selectors||'|'||generation FROM connections ORDER BY 1",
        "SELECT grant_id||'|'||grantee_principal||'|'||IFNULL(agent_id,'-')||'|'||action_selectors||'|'||generation FROM grants ORDER BY 1",
        "SELECT policy_id||'|'||principal||'|'||action_selector||'|'||effect||'|'||generation FROM policies ORDER BY 1",
    ]
    .iter()
    .map(|query| {
        let mut statement = conn.prepare(query).unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    })
    .collect()
}

fn ceiling(store: &PlexusStore) -> Vec<String> {
    store
        .connection_ceiling("direct", "github-handle-app-fixture")
        .unwrap()
        .unwrap()
        .action_selectors
}

/// The property the grant exists for: an agent imported without create_issue
/// is refused an issue create, and after the operator grants create_issue the
/// same request completes through the real facade path.
#[test]
fn handle_grant_lets_an_imported_agent_create_issues() {
    let fixture = imported("grant-e2e", INVENTORY_WRITES);
    let (reply, calls) = send(&fixture, "grant-e2e-before", wire("v14-issue-create"));
    assert_eq!(reply["result"]["status"], "refused", "{reply}");
    assert!(calls.is_empty());

    handle_grant(
        &fixture.store,
        "direct",
        "app-fixture",
        &["create_issue"],
        false,
    )
    .expect("the grant mints inside the widened ceiling");
    let (reply, calls) = send(&fixture, "grant-e2e-after", wire("v14-issue-create"));
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(actions(&calls), ["create_issue"]);

    // The rows follow the import's shape: one agent row, the carrying module's
    // grant extended in place, and an allow at both policy levels.
    let agent_rows: Vec<String> = agent_grants(&fixture.store)
        .into_iter()
        .filter(|(action, _)| action == "create_issue")
        .map(|(_, id)| id)
        .collect();
    assert_eq!(agent_rows.len(), 1, "{agent_rows:?}");
    let aft = fixture
        .store
        .list_grants("direct", "github-handle-app-fixture")
        .unwrap()
        .into_iter()
        .find(|row| row.grant_id == "github-import:app-fixture:aft")
        .unwrap();
    assert!(aft.action_selectors.contains(&"create_issue".to_owned()));
    assert_eq!(aft.generation, 1);
    for owner in ["direct", "agent-fixture"] {
        let effect = fixture
            .store
            .list_policies(owner, Some("github-handle-app-fixture"))
            .unwrap()
            .into_iter()
            .find(|row| row.action_selector == "create_issue")
            .map(|row| row.effect);
        assert_eq!(effect.as_deref(), Some("allow"), "{owner}");
    }
}

/// A pull request request in the shim's nested shape, for the bound repository.
fn pr_create() -> Value {
    json!({"action":"pr create","target":{},"repository":"org/repo","body":{
        "title":"Add the thing","body":"Opened by the bot.","base":"main","head":"feature"}})
}

/// A bot imported before pull requests existed gains them through
/// handle-grant alone: refused first, then the same request completes as one
/// create_pull_request call, with no pre-dispatch read before it.
#[test]
fn handle_grant_lets_an_imported_agent_open_pull_requests() {
    let fixture = imported("grant-pr", INVENTORY_WRITES);
    assert!(agent_grants(&fixture.store)
        .iter()
        .all(|(action, _)| action != "create_pull_request"));
    let (reply, calls) = send(&fixture, "grant-pr-before", pr_create());
    assert_eq!(reply["result"]["status"], "refused", "{reply}");
    assert!(calls.is_empty());

    let plan = handle_grant(
        &fixture.store,
        "direct",
        "app-fixture",
        &["create_pull_request"],
        false,
    )
    .expect("create_pull_request is grantable");
    assert_eq!(plan["ceiling_additions"], json!(["create_pull_request"]));
    let (reply, calls) = send(&fixture, "grant-pr-after", pr_create());
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(actions(&calls), ["create_pull_request"]);
    assert_eq!(calls[0].1["head"], "feature");
    assert_eq!(calls[0].1["base"], "main");
}

#[test]
fn handle_grant_dry_run_writes_nothing_and_returns_the_plan() {
    let fixture = imported("grant-dry-run", INVENTORY_WRITES);
    let before = authority_tables(&fixture);
    let plan = handle_grant(
        &fixture.store,
        "direct",
        "app-fixture",
        &["create_issue"],
        true,
    )
    .unwrap();
    assert_eq!(authority_tables(&fixture), before);
    assert_eq!(plan["ceiling_additions"], json!(["create_issue"]));
    assert_eq!(plan["dry_run"], true);
    let grants = plan["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 2, "{plan}");
    assert_eq!(grants[0]["level"], "agent");
    assert_eq!(grants[0]["action"], "create_issue");
    assert_eq!(grants[1]["level"], "module");
    assert_eq!(grants[1]["op"], "extend");
    assert_eq!(grants[1]["grant_id"], "github-import:app-fixture:aft");
    assert_eq!(
        plan["policies"],
        json!([
            {"level":"module","action":"create_issue","effect":"allow","op":"insert"},
            {"level":"agent","action":"create_issue","effect":"allow","op":"insert"},
        ])
    );
}

#[test]
fn handle_grant_refuses_by_name_and_writes_nothing() {
    let fixture = imported("grant-refusals", INVENTORY_WRITES);
    let before = authority_tables(&fixture);
    for (principal, handle, actions, code) in [
        (
            "direct",
            "app-fixture",
            &["delete_repository"][..],
            "action_not_grantable{action: delete_repository}",
        ),
        // A read is implied by writes, never granted on its own.
        (
            "direct",
            "app-fixture",
            &["create_issue", "github.issue.get"][..],
            "action_not_grantable{action: github.issue.get}",
        ),
        (
            "direct",
            "app-unknown",
            &["create_issue"][..],
            "agent_handle_unknown",
        ),
        (
            plexus_core::github::AFT_PRINCIPAL,
            "app-fixture",
            &["create_issue"][..],
            "operator_authority_required",
        ),
        ("direct", "app-fixture", &[][..], "actions_required"),
    ] {
        assert_eq!(
            handle_grant(&fixture.store, principal, handle, actions, false).unwrap_err(),
            code
        );
        assert_eq!(authority_tables(&fixture), before, "{code}");
    }
    let wildcard = control::grant(
        &fixture.store,
        "direct",
        "app-fixture",
        &["create_issue".to_owned()],
        "*",
        "allow",
        false,
    );
    assert_eq!(wildcard.unwrap_err(), "module_invalid{module: *}");
    assert_eq!(authority_tables(&fixture), before);
}

#[test]
fn handle_grant_refuses_a_disabled_handle() {
    let mut disabled = inventory(INVENTORY_WRITES);
    disabled.handles[0].status = "disabled".into();
    let fixture = imported_from("grant-disabled", &disabled);
    let before = authority_tables(&fixture);
    assert_eq!(
        handle_grant(
            &fixture.store,
            "direct",
            "app-fixture",
            &["create_issue"],
            false
        )
        .unwrap_err(),
        "agent_handle_disabled{app_handle_id: app-fixture}"
    );
    assert_eq!(authority_tables(&fixture), before);
}

/// The ceiling widens by the granted writes and what they imply, and by
/// nothing else.
#[test]
fn handle_grant_widens_the_ceiling_by_exactly_the_expanded_set() {
    let fixture = imported("grant-narrow", INVENTORY_WRITES);
    let before = ceiling(&fixture.store);
    handle_grant(
        &fixture.store,
        "direct",
        "app-fixture",
        &["create_issue"],
        false,
    )
    .unwrap();
    let mut expected = before.clone();
    expected.push("create_issue".into());
    assert_eq!(ceiling(&fixture.store), expected);

    // A write with implied legs adds the legs the ceiling lacks; the issue
    // read every import already carries is not added twice.
    let fixture = imported("grant-narrow-legs", &["add_reaction"]);
    let before = ceiling(&fixture.store);
    assert!(before.contains(&"github.issue.get".to_owned()));
    handle_grant(
        &fixture.store,
        "direct",
        "app-fixture",
        &["edit_issue"],
        false,
    )
    .unwrap();
    let mut expected = before.clone();
    expected.extend(
        [
            "add_issue_assignees",
            "add_issue_labels",
            "edit_issue",
            "remove_issue_assignees",
            "remove_issue_label",
        ]
        .map(String::from),
    );
    assert_eq!(ceiling(&fixture.store), expected);
    // The legs are governed too, so the request they carry is not parked.
    let calls = {
        let mut request = wire("v14-issue-edit-title-body");
        request["body"] = json!({"title":"Retitled","add_labels":["triaged"]});
        let (reply, calls) = send(&fixture, "grant-narrow-legs-edit", request);
        assert_eq!(reply["result"]["status"], "completed", "{reply}");
        calls
    };
    assert_eq!(
        actions(&calls),
        ["github.issue.get", "edit_issue", "add_issue_labels"]
    );
}

/// A recording installation: lists exactly `repositories`, and keeps the
/// credential payload each page was read with so a test can tell whose token
/// listed it.
struct Installation {
    repositories: Vec<&'static str>,
    tokens: std::sync::Mutex<Vec<String>>,
}

impl Installation {
    fn listing(repositories: &[&'static str]) -> Self {
        Self {
            repositories: repositories.to_vec(),
            tokens: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn tokens(&self) -> Vec<String> {
        self.tokens.lock().unwrap().clone()
    }
}

impl InstallationReader for Installation {
    fn repositories_page(
        &self,
        token: &ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        self.tokens
            .lock()
            .unwrap()
            .push(String::from_utf8(token.payload().to_vec()).unwrap());
        let listed: Vec<Value> = self
            .repositories
            .iter()
            .map(|name| json!({"full_name": name}))
            .collect();
        Ok(json!({ "repositories": listed }))
    }
}

/// Runs `github.handle.bind` for `repositories` against `installation`.
fn handle_bind(
    store: &PlexusStore,
    principal: &str,
    handle: &str,
    repositories: &[&str],
    installation: &Installation,
    dry_run: bool,
) -> Result<Value, String> {
    let repositories: Vec<String> = repositories.iter().map(|name| (*name).to_owned()).collect();
    control::bind(
        store,
        principal,
        handle,
        &repositories,
        &Token,
        installation,
        2,
        dry_run,
    )
}

/// Every row a bind may write: the bindings, the global binding generation,
/// and the connections whose write filters follow the bindings. Read through a
/// separate connection so the comparison does not go through the store under
/// test.
fn binding_tables(fixture: &Imported) -> Vec<Vec<String>> {
    let conn = rusqlite::Connection::open(fixture._scratch.path()).unwrap();
    [
        "SELECT repository||'|'||app_handle_id FROM github_repo_binding ORDER BY 1",
        "SELECT CAST(generation AS TEXT) FROM github_repo_binding_generation",
        "SELECT principal||'|'||connection_id||'|'||resource_filters||'|'||generation FROM connections ORDER BY 1",
    ]
    .iter()
    .map(|query| {
        let mut statement = conn.prepare(query).unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    })
    .collect()
}

fn bound(fixture: &Imported) -> Vec<String> {
    binding_tables(fixture).swap_remove(0)
}

/// The fixture handle bound to org/repo, plus a second handle (app-other)
/// already bound to org/taken, so a bind can meet another handle's binding.
fn two_handles(label: &str) -> Imported {
    let mut inventory = inventory(INVENTORY_WRITES);
    inventory.handles.push(InventoryHandle {
        app_handle_id: "app-other".into(),
        agent_id: "agent-other".into(),
        app_id: 43,
        installation_id: None,
        credential_id: "github_app:app-other".into(),
        status: "enabled".into(),
        grants: vec![AgentPermission {
            action: "add_issue_comment".into(),
            repository: "org/taken".into(),
            provenance: "inventory-add_issue_comment".into(),
            policy: "allow".into(),
        }],
    });
    imported_with(
        label,
        &inventory,
        &Installation::listing(&["org/repo", "org/taken"]),
    )
}

/// The installation every bind test lists: the fixture's own repository, two
/// more of its owner's, one bound to the other handle, and one of another owner.
const WIDE: &[&str] = &[
    "org/repo",
    "org/second",
    "org/third",
    "org/taken",
    "other/elsewhere",
];

/// The property the bind exists for: an agent imported with one repository is
/// refused a comment on a second, and once the operator binds the second one
/// (which the handle's installation lists) the same request completes, under
/// an advanced binding generation.
#[test]
fn handle_bind_lets_an_imported_agent_write_to_another_repository() {
    let fixture = imported("bind-e2e", INVENTORY_WRITES);
    let mut request = wire("v1-issue-comment");
    request["repository"] = json!("org/second");
    let (reply, calls) = send(&fixture, "bind-e2e-before", request.clone());
    assert_eq!(reply["result"]["status"], "refused", "{reply}");
    assert_eq!(
        reply["result"]["refusal_code"], "repository_unbound",
        "{reply}"
    );
    assert!(calls.is_empty());
    let before = reply["repo_binding_generation"].as_i64().unwrap();

    let installation = Installation::listing(WIDE);
    let plan = handle_bind(
        &fixture.store,
        "direct",
        "app-fixture",
        &["org/second"],
        &installation,
        false,
    )
    .expect("the bind applies");
    // The installation was listed with the handle's own credential.
    assert_eq!(installation.tokens(), ["github_app:app-fixture"]);
    assert_eq!(plan["add"], json!(["org/second"]));
    assert_eq!(plan["dry_run"], false);
    assert_eq!(plan["repo_binding_generation"]["delta"], 1, "{plan}");
    assert_eq!(
        bound(&fixture),
        ["org/repo|app-fixture", "org/second|app-fixture"]
    );

    let (reply, calls) = send(&fixture, "bind-e2e-after", request);
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(actions(&calls), ["add_issue_comment"]);
    let after = reply["repo_binding_generation"].as_i64().unwrap();
    assert!(after > before, "{before} -> {after}");
    assert_eq!(after, plan["repo_binding_generation"]["after"]);
}

/// Each refusal is named and leaves the bindings, the generation and every
/// connection filter exactly as they were.
#[test]
fn handle_bind_refuses_by_name_and_writes_nothing() {
    let fixture = two_handles("bind-refusals");
    let installation = Installation::listing(WIDE);
    let before = binding_tables(&fixture);
    let authority = authority_tables(&fixture);
    for (principal, handle, repositories, code) in [
        (
            "direct",
            "app-fixture",
            &["org/taken"][..],
            "repository_bound_elsewhere{repository: org/taken, app_handle_id: app-other}",
        ),
        (
            "direct",
            "app-fixture",
            &["org/outside"][..],
            "repository_not_in_installation{repository: org/outside}",
        ),
        (
            "direct",
            "app-fixture",
            &["other/elsewhere"][..],
            "binding_owner_mismatch{repository: other/elsewhere, owner: org}",
        ),
        (
            "direct",
            "app-unknown",
            &["org/second"][..],
            "agent_handle_unknown",
        ),
        (
            plexus_core::github::AFT_PRINCIPAL,
            "app-fixture",
            &["org/second"][..],
            "operator_authority_required",
        ),
        (
            "direct",
            "app-fixture",
            &["not-a-repository"][..],
            "repository_invalid{repository: not-a-repository}",
        ),
        (
            "direct",
            "app-fixture",
            &["org/a/b"][..],
            "repository_invalid{repository: org/a/b}",
        ),
        ("direct", "app-fixture", &[][..], "repositories_required"),
    ] {
        assert_eq!(
            handle_bind(
                &fixture.store,
                principal,
                handle,
                repositories,
                &installation,
                false
            )
            .unwrap_err(),
            code
        );
        assert_eq!(binding_tables(&fixture), before, "{code}");
        assert_eq!(authority_tables(&fixture), authority, "{code}");
    }
}

#[test]
fn handle_bind_refuses_a_disabled_handle() {
    let mut disabled = inventory(INVENTORY_WRITES);
    disabled.handles[0].status = "disabled".into();
    let fixture = imported_from("bind-disabled", &disabled);
    let before = binding_tables(&fixture);
    assert_eq!(
        handle_bind(
            &fixture.store,
            "direct",
            "app-fixture",
            &["org/second"],
            &Installation::listing(WIDE),
            false
        )
        .unwrap_err(),
        "agent_handle_disabled{app_handle_id: app-fixture}"
    );
    assert_eq!(binding_tables(&fixture), before);
}

/// A refusal on a later repository leaves the earlier ones unbound: the whole
/// list is bound in one transaction or not at all.
#[test]
fn handle_bind_is_all_or_nothing() {
    let fixture = two_handles("bind-atomic");
    let installation = Installation::listing(WIDE);
    let before = binding_tables(&fixture);
    for (repositories, code) in [
        (
            &["org/second", "org/third", "org/outside"][..],
            "repository_not_in_installation{repository: org/outside}",
        ),
        (
            &["org/second", "org/taken"][..],
            "repository_bound_elsewhere{repository: org/taken, app_handle_id: app-other}",
        ),
    ] {
        assert_eq!(
            handle_bind(
                &fixture.store,
                "direct",
                "app-fixture",
                repositories,
                &installation,
                false
            )
            .unwrap_err(),
            code
        );
        assert_eq!(binding_tables(&fixture), before, "{code}");
    }
    assert_eq!(
        bound(&fixture),
        ["org/repo|app-fixture", "org/taken|app-other"]
    );
}

/// A dry run returns the plan (what it would add, what is already bound, the
/// generation delta) and writes nothing.
#[test]
fn handle_bind_dry_run_writes_nothing_and_returns_the_plan() {
    let fixture = imported("bind-dry-run", INVENTORY_WRITES);
    let before = binding_tables(&fixture);
    let generation: i64 = before[1][0].parse().unwrap();
    let plan = handle_bind(
        &fixture.store,
        "direct",
        "app-fixture",
        &["org/repo", "org/second", "org/third", "org/second"],
        &Installation::listing(WIDE),
        true,
    )
    .unwrap();
    assert_eq!(binding_tables(&fixture), before);
    assert_eq!(
        plan,
        json!({
            "app_handle_id": "app-fixture",
            "connection_id": "github-handle-app-fixture",
            "dry_run": true,
            "add": ["org/second", "org/third"],
            "already_bound": ["org/repo"],
            "repo_binding_generation": {"before": generation, "after": generation + 2, "delta": 2},
        })
    );
}

#[test]
fn handle_unbind_preview_writes_nothing() {
    let fixture = imported("unbind-preview", INVENTORY_WRITES);
    let before = snapshot(&fixture);
    let plan = control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "org/repo",
        "preview",
        true,
    )
    .unwrap();
    assert_eq!(plan["remove"], json!(["org/repo"]));
    assert_eq!(plan["last_repository"], true);
    assert_eq!(plan["remaining_repositories"], 0);
    assert_eq!(snapshot(&fixture), before);
}

#[test]
fn handle_unbind_apply_deletes_and_bumps_generation() {
    let fixture = imported("unbind-apply", INVENTORY_WRITES);
    let plan = control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "org/repo",
        "apply",
        false,
    )
    .unwrap();
    assert!(bound(&fixture).is_empty());
    assert_eq!(plan["repo_binding_generation"]["delta"], 1);
    let conn = rusqlite::Connection::open(fixture._scratch.path()).unwrap();
    let row: (String, String, String) = conn.query_row("SELECT principal,app_handle_id,args_redaction_summary FROM audit_journal WHERE action='github.handle.unbind'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(
        row,
        (
            "direct".into(),
            "app-fixture".into(),
            json!({"repository":"org/repo"}).to_string()
        )
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_journal WHERE action='github.handle.unbind'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

/// GitHub owner and repository names are case-insensitive, and plexus holds
/// them in one canonical lowercase form: a bind in any case stores the
/// lowercase name (even when the installation lists it in the owner's
/// chosen case), a request in any case finds that binding and is sent in the
/// canonical form the connection's write filter names, and an unbind in any
/// case removes it.
#[test]
fn repository_names_bind_route_and_unbind_in_any_case() {
    let fixture = imported("repository-case", INVENTORY_WRITES);
    handle_bind(
        &fixture.store,
        "direct",
        "app-fixture",
        &["Org/Second"],
        &Installation::listing(&["Org/Repo", "ORG/SECOND"]),
        false,
    )
    .unwrap();
    assert_eq!(
        bound(&fixture),
        ["org/repo|app-fixture", "org/second|app-fixture"]
    );
    let mut request = wire("v1-issue-comment");
    request["repository"] = json!("Org/SECOND");
    let (reply, calls) = send(&fixture, "repository-case", request);
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(actions(&calls), ["add_issue_comment"]);
    assert_eq!(calls[0].1["owner"], "org");
    assert_eq!(calls[0].1["repo"], "second");
    assert!(fixture
        .store
        .github_handle_connection_for_repo("ORG/Repo")
        .unwrap()
        .is_some());
    control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "ORG/second",
        "unbind-case",
        false,
    )
    .unwrap();
    assert_eq!(bound(&fixture), ["org/repo|app-fixture"]);
}

/// The handle connection's owner/repo write filter names exactly the
/// repositories bound to the handle after every binding change: a bind adds
/// the repository, and an unbind takes it out again, down to an empty list
/// when the last one goes.
#[test]
fn handle_write_filter_follows_bind_and_unbind() {
    let fixture = imported("unbind-filter", INVENTORY_WRITES);
    let filter_repos = || -> Value {
        let conn = rusqlite::Connection::open(fixture._scratch.path()).unwrap();
        let filters: String = conn
            .query_row(
                "SELECT resource_filters FROM connections WHERE connection_id='github-handle-app-fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str::<Value>(&filters).unwrap()["values"]["repo"].clone()
    };
    assert_eq!(filter_repos(), json!(["repo"]));
    handle_bind(
        &fixture.store,
        "direct",
        "app-fixture",
        &["org/second"],
        &Installation::listing(WIDE),
        false,
    )
    .unwrap();
    assert_eq!(filter_repos(), json!(["repo", "second"]));
    control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "org/second",
        "unbind-second",
        false,
    )
    .unwrap();
    assert_eq!(
        filter_repos(),
        json!(["repo"]),
        "an unbound repository stayed in the write filter"
    );
    control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "org/repo",
        "unbind-last",
        false,
    )
    .unwrap();
    assert_eq!(
        filter_repos(),
        json!([]),
        "an unbound repository stayed in the write filter"
    );
}

#[test]
fn handle_unbind_refuses_wrong_handle() {
    let fixture = two_handles("unbind-refusal");
    let before = snapshot(&fixture);
    for (handle, repo, code) in [
        ("app-fixture", "org/taken", "repo_not_bound_to_handle"),
        ("app-fixture", "org/missing", "repo_not_bound_to_handle"),
        ("missing", "org/repo", "agent_handle_unknown"),
    ] {
        let error =
            control::unbind(&fixture.store, "direct", handle, repo, "refusal", false).unwrap_err();
        assert!(error.starts_with(code), "{error}");
    }
    assert_eq!(snapshot(&fixture), before);
    assert_eq!(
        control::unbind(
            &fixture.store,
            "module:other",
            "app-fixture",
            "org/repo",
            "denied",
            false
        )
        .unwrap_err(),
        "operator_authority_required"
    );
}

#[test]
fn handle_unbind_completed_write_replays() {
    let fixture = imported("unbind-replay", INVENTORY_WRITES);
    let request = wire("v1-issue-comment");
    let (first, calls) = send(&fixture, "unbind-replay", request.clone());
    assert_eq!(first["result"]["status"], "completed", "{first}");
    assert_eq!(actions(&calls), ["add_issue_comment"]);
    control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "org/repo",
        "apply",
        false,
    )
    .unwrap();
    let (replay, replay_calls) = send(&fixture, "unbind-replay", request);
    assert_eq!(replay["result"]["status"], "completed", "{replay}");
    assert_eq!(replay_calls, calls);
}

fn snapshot(fixture: &Imported) -> Vec<Vec<String>> {
    let mut tables = binding_tables(fixture);
    let conn = rusqlite::Connection::open(fixture._scratch.path()).unwrap();
    for table in ["audit_journal", "grants", "policies"] {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let width = stmt.column_count();
        tables.push(
            stmt.query_map([], |row| {
                Ok((0..width)
                    .map(|i| format!("{:?}", row.get_ref(i).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        );
    }
    tables
}

#[test]
fn import_refuses_repository_bound_elsewhere_in_preview_and_apply() {
    let fixture = imported("import-conflict", INVENTORY_WRITES);
    let mut candidate = inventory(INVENTORY_WRITES);
    candidate.handles[0].app_handle_id = "new-bot".into();
    candidate.handles[0].agent_id = "new-agent".into();
    candidate.handles[0].credential_id = "github_app:new-bot".into();
    let before = snapshot(&fixture);
    for dry_run in [true, false] {
        let error = control::import(
            &fixture.store,
            "direct",
            &candidate,
            &Token,
            &Repositories,
            2,
            dry_run,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "repository_bound_elsewhere{repository: org/repo, app_handle_id: app-fixture}"
        );
        assert_eq!(snapshot(&fixture), before);
    }
}

#[test]
fn handle_unbind_audit_failure_rolls_back_deletion() {
    let fixture = imported("unbind-audit-rollback", INVENTORY_WRITES);
    let conn = rusqlite::Connection::open(fixture._scratch.path()).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_unbind_audit BEFORE INSERT ON audit_journal WHEN NEW.action='github.handle.unbind' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;").unwrap();
    let before = snapshot(&fixture);
    assert!(control::unbind(
        &fixture.store,
        "direct",
        "app-fixture",
        "org/repo",
        "apply",
        false
    )
    .unwrap_err()
    .starts_with("unbind_failed:"));
    assert_eq!(snapshot(&fixture), before);
}

#[test]
fn import_refuses_conflicting_planned_handles_in_preview_and_apply() {
    let fixture = imported("import-planned-conflict", INVENTORY_WRITES);
    let mut candidate = inventory(INVENTORY_WRITES);
    let mut second = inventory(INVENTORY_WRITES).handles.remove(0);
    candidate.handles[0].app_handle_id = "first-bot".into();
    candidate.handles[0].agent_id = "first-agent".into();
    candidate.handles[0].credential_id = "github_app:first-bot".into();
    second.app_handle_id = "second-bot".into();
    second.agent_id = "second-agent".into();
    second.credential_id = "github_app:second-bot".into();
    candidate.handles.push(second);
    for handle in &mut candidate.handles {
        for grant in &mut handle.grants {
            grant.repository = "org/second".into();
        }
    }
    let installation = Installation::listing(&["org/second"]);
    let before = snapshot(&fixture);
    for dry_run in [true, false] {
        let error = control::import(
            &fixture.store,
            "direct",
            &candidate,
            &Token,
            &installation,
            2,
            dry_run,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "repository_bound_elsewhere{repository: org/second, app_handle_id: first-bot}"
        );
        assert_eq!(snapshot(&fixture), before);
        for id in ["first-bot", "second-bot"] {
            assert!(fixture
                .store
                .github_handle_and_bindings(id)
                .unwrap()
                .is_none());
        }
    }
}
