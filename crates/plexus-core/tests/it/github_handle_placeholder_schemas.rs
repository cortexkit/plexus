//! GitHub handle catalog rows that still hold the open placeholder schema move
//! to the reviewed manifest's `http.args_schema` when the boot pass runs, and
//! nothing else moves.
//!
//! Handle connections imported before the seeder read `http.args_schema` kept
//! the placeholder on every row, and governance treats a schema without
//! `properties` as open, so the undeclared-argument check refused nothing on
//! any bot action. Each test imports a real handle from the shipped manifest,
//! then rewrites its rows back to the placeholder the way the old seeder left
//! them.
use crate::scope_support::{delegating_scope, LiveScopeReader};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::control::{
    self, AgentPermission, InstallationReader, Inventory, InventoryHandle,
};
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::github::facade::bot_request_scoped;
use plexus_core::github::AFT_PRINCIPAL;
use plexus_core::governance::{Denial, GovernanceEngine};
use plexus_core::scope::CallScope;
use plexus_core::storage::github_store::GithubGovernanceSeams;
use plexus_core::transport::{MockResponse, MockTransport};
use plexus_core::{ingest_value, PlexusStore, CATALOG_PRINCIPAL};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::Arc;

const AGENT: &str = "agent-fixture";
const HANDLE: &str = "app-fixture";
const PRINCIPAL: &str = "direct";
const CONNECTION: &str = "github-handle-app-fixture";
/// The placeholder as the store holds it: serialized with sorted keys.
const PLACEHOLDER: &str = r#"{"additionalProperties":true,"type":"object"}"#;

/// Every write an import accepts. The label and assignee writes an issue edit
/// sends are implied by `edit_issue`, so the import grants them without being
/// asked.
const WRITES: [&str; 11] = [
    "add_issue_comment",
    "update_issue_comment",
    "add_pr_review",
    "add_reaction",
    "create_issue",
    "create_pull_request",
    "close_issue",
    "reopen_issue",
    "edit_issue",
    "mark_pull_request_ready",
    "convert_pull_request_to_draft",
];

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
struct Installation;
impl InstallationReader for Installation {
    fn repositories_page(
        &self,
        _: &ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        Ok(json!({"repositories":[{"full_name":"org/repo"}]}))
    }
}

/// The shipped reviewed GitHub REST manifest, parsed from its JSONC source.
fn github_manifest() -> plexus_core::IngestedManifest {
    let source = include_str!(concat!("../", "../../../catalog/github_rest.jsonc"));
    let mut clean = String::new();
    let mut chars = source.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if quoted {
            clean.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            clean.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    clean.push(next);
                    break;
                }
            }
        } else {
            clean.push(ch);
        }
    }
    ingest_value(serde_json::from_str(&clean).unwrap()).unwrap()
}

/// The reviewed argument schema the shipped manifest declares for `action`.
fn reviewed_schema(action: &str) -> Value {
    github_manifest()
        .manifest
        .actions_baseline
        .iter()
        .find(|declared| declared.name == action)
        .and_then(|declared| declared.http.as_ref())
        .unwrap_or_else(|| panic!("{action} is a declared REST action"))
        .args_schema
        .clone()
}

type Engine = GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>;

/// One stored catalog row: (schema_json, schema_hash, status, generation).
type Row = (String, String, String, i64);

struct Fixture {
    _scratch: plexus_core::test_scratch::Scratch,
    store: Arc<PlexusStore>,
    engine: Engine,
    transport: Arc<MockTransport>,
    scope: CallScope,
    path: std::path::PathBuf,
}

impl Fixture {
    /// Import a handle whose agent holds every bot write on org/repo, prove
    /// it, then put every catalog row back on the placeholder.
    fn new(label: &str) -> Self {
        let scratch = plexus_core::test_scratch::Scratch::database(label);
        let path = scratch.path().to_path_buf();
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: label.into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
            .unwrap();
        let inventory = Inventory {
            version: "github-grant-import.v1".into(),
            handles: vec![InventoryHandle {
                app_handle_id: HANDLE.into(),
                agent_id: AGENT.into(),
                app_id: 1,
                installation_id: None,
                credential_id: "github_app:app-fixture".into(),
                status: "enabled".into(),
                grants: WRITES
                    .iter()
                    .map(|action| AgentPermission {
                        action: (*action).into(),
                        repository: "org/repo".into(),
                        provenance: format!("today-{action}"),
                        policy: "allow".into(),
                    })
                    .collect(),
            }],
        };
        control::import(
            &store,
            PRINCIPAL,
            &inventory,
            &Token,
            &Installation,
            0,
            false,
        )
        .unwrap();
        control::probe(&store, PRINCIPAL, HANDLE, &Token, &Installation, 1).unwrap();
        let placeholder_hash = plexus_core::jcs::jcs_sha256(&json!({
            "type": "object",
            "additionalProperties": true
        }))
        .unwrap();
        let rewound = Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE catalog_actions SET schema_json = ?1, schema_hash = ?2
                 WHERE principal = ?3 AND connection_id = ?4",
                params![PLACEHOLDER, placeholder_hash, PRINCIPAL, CONNECTION],
            )
            .unwrap();
        assert_eq!(
            rewound,
            github_manifest().manifest.actions_baseline.len(),
            "every declared action has a row on the handle"
        );
        let scope = delegating_scope("agent-fixture");
        let transport = Arc::new(MockTransport::default());
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                plexus_core::credentials::StubCredentialSource::with_default_success(
                    b"unused".to_vec(),
                ),
            ),
            transport.clone(),
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
        Self {
            _scratch: scratch,
            store,
            engine,
            transport,
            scope,
            path,
        }
    }

    fn db(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }

    fn row(&self, action: &str) -> Row {
        self.db()
            .query_row(
                "SELECT schema_json, schema_hash, status, generation FROM catalog_actions
                 WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
                params![PRINCIPAL, CONNECTION, action],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    }

    fn rows(&self) -> Vec<(String, Row)> {
        let db = self.db();
        let mut statement = db
            .prepare(
                "SELECT name, schema_json, schema_hash, status, generation FROM catalog_actions
                 WHERE principal = ?1 AND connection_id = ?2 ORDER BY name",
            )
            .unwrap();
        statement
            .query_map(params![PRINCIPAL, CONNECTION], |row| {
                Ok((
                    row.get(0)?,
                    (row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?),
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn set(&self, action: &str, assignments: &str) {
        let changed = self
            .db()
            .execute(
                &format!(
                    "UPDATE catalog_actions SET {assignments}
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                params![PRINCIPAL, CONNECTION, action],
            )
            .unwrap();
        assert_eq!(changed, 1, "{action}");
    }

    fn call(&self, request: &Value, nonce: &str) -> Value {
        let mut request = request.clone();
        request["repository"] = json!("org/repo");
        bot_request_scoped(
            &self.store,
            &self.engine,
            AFT_PRINCIPAL,
            Some(&self.scope),
            &request,
            nonce,
            nonce,
            "worker",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
        )
    }

    /// Ask governance for a read carrying one argument no reviewed schema
    /// declares. Sent as a poll, pinned to the row's current schema hash: an
    /// ordinary invoke on a handle connection must first name a bound
    /// repository in a `repository` argument, which a poll does not.
    fn undeclared_read(&self) -> Result<(), Denial> {
        let action = "github.issue.get";
        let request = self
            .engine
            .poll_authorization_request(
                PRINCIPAL,
                CONNECTION,
                action,
                json!({"owner":"org","repo":"repo","issue_number":42,"unreviewed":true}),
                "subscription-fixture",
                self.row(action).1,
            )
            .unwrap();
        self.engine.authorize(request).map(|_| ())
    }
}

fn bot_user() -> Value {
    json!({"login":"app-fixture[bot]","type":"Bot","id":9,"node_id":"BOT_9"})
}

fn issue_body(number: u64, id: u64, state: &str, state_reason: Value) -> Value {
    json!({"id":id,"node_id":format!("I_{id}"),"number":number,
        "html_url":format!("https://github.com/org/repo/issues/{number}"),
        "url":format!("https://api.github.com/repos/org/repo/issues/{number}"),
        "title":"example","body":"issue text","state":state,"state_reason":state_reason,
        "user":bot_user(),"labels":[]})
}

fn comment_body(id: u64, text: &str) -> Value {
    json!({"id":id,"node_id":format!("IC_{id}"),
        "html_url":format!("https://github.com/org/repo/issues/42#issuecomment-{id}"),
        "url":format!("https://api.github.com/repos/org/repo/issues/comments/{id}"),
        "body":text,"user":bot_user()})
}

/// GitHub REST answers for every read and write the facade sends.
fn github_bodies(transport: &MockTransport) {
    let open = || issue_body(42, 4200, "open", Value::Null);
    for (action, body) in [
        (
            "github.issue_comments.list",
            json!([comment_body(101, "earlier")]),
        ),
        ("github.issue_comment.get", comment_body(101, "earlier")),
        ("github.issue.get", open()),
        ("add_issue_comment", comment_body(501, "hello")),
        ("update_issue_comment", comment_body(101, "edited")),
        (
            "add_pr_review",
            json!({"id":601,"node_id":"PRR_601",
                "html_url":"https://github.com/org/repo/pull/42#pullrequestreview-601",
                "body":"looks good","state":"COMMENTED","user":bot_user()}),
        ),
        (
            "add_reaction",
            json!({"id":701,"node_id":"REA_701","content":"eyes","user":bot_user()}),
        ),
        ("create_issue", issue_body(43, 4300, "open", Value::Null)),
        (
            "create_pull_request",
            json!({"id":9112,"node_id":"PR_12","number":12,
                "html_url":"https://github.com/org/repo/pull/12",
                "url":"https://api.github.com/repos/org/repo/pulls/12",
                "title":"example","state":"open","draft":true,"user":bot_user()}),
        ),
        (
            "close_issue",
            issue_body(42, 4200, "closed", json!("completed")),
        ),
        ("reopen_issue", open()),
        ("edit_issue", open()),
        (
            "add_issue_labels",
            json!([{"id":1,"node_id":"LA_1","name":"triaged","color":"ededed"}]),
        ),
        ("remove_issue_label", json!([])),
        ("add_issue_assignees", open()),
        ("remove_issue_assignees", open()),
    ] {
        transport.set_response_for_method(action, "", MockResponse::Success(body));
    }
}

/// One request of every bot request kind, each carrying every field its kind
/// accepts, and the writes it must reach.
fn every_request_kind() -> Vec<(&'static str, Value, Vec<&'static str>)> {
    vec![
        (
            "pr-ready",
            json!({"verb":"pr ready","number":"7","undo":false}),
            vec!["mark_pull_request_ready"],
        ),
        (
            "pr-draft",
            json!({"verb":"pr ready","number":"7","undo":true}),
            vec!["convert_pull_request_to_draft"],
        ),
        (
            "comment",
            json!({"action":"issue comment","target":{"number":"42"},"body":{"body":"hello"}}),
            vec!["add_issue_comment"],
        ),
        (
            "edit-last",
            json!({"action":"pr comment","edit_last":true,"target":{"number":"42"},
                "body":{"body":"replacement"}}),
            vec!["update_issue_comment"],
        ),
        (
            "comment-edit",
            json!({"action":"api:PATCH:/repos/*/*/issues/comments/*",
                "target":{"comment_id":"101"},"body":{"body":"edited"}}),
            vec!["update_issue_comment"],
        ),
        (
            "pr-review",
            json!({"action":"pr review","target":{"number":"42"},
                "body":{"body":"looks good","event":"COMMENT"}}),
            vec!["add_pr_review"],
        ),
        (
            "reaction",
            json!({"action":"issue reaction","target":{"number":"42"},"body":{"reaction":"eyes"}}),
            vec!["add_reaction"],
        ),
        (
            "issue-create",
            json!({"action":"issue create","body":{"title":"example","body":"text","labels":["bug"]}}),
            vec!["create_issue"],
        ),
        (
            "pr-create",
            json!({"action":"pr create","target":{},"body":{"title":"Add the thing",
                "body":"Opened by the bot.","base":"main","head":"feature","draft":true}}),
            vec!["create_pull_request"],
        ),
        (
            "close",
            json!({"verb":"issue close","number":"42","comment":"done","reason":"not_planned"}),
            vec!["add_issue_comment", "close_issue"],
        ),
        (
            "reopen",
            json!({"verb":"issue reopen","number":"42","comment":"again"}),
            vec!["add_issue_comment", "reopen_issue"],
        ),
        (
            "issue-edit",
            json!({"action":"issue edit","target":{"number":"42"},"body":{
                "title":"renamed","body":"text","labels":["a"],"assignees":["octocat"],
                "add_labels":["triaged"],"remove_labels":["needs-triage"],
                "add_assignees":["octocat"],"remove_assignees":["hubot"]}}),
            vec![
                "edit_issue",
                "add_issue_labels",
                "remove_issue_label",
                "add_issue_assignees",
                "remove_issue_assignees",
            ],
        ),
    ]
}

#[test]
fn placeholder_rows_take_the_reviewed_schema_and_every_bot_request_kind_still_dispatches() {
    let f = Fixture::new("handle-pin-reviewed");
    // Before the pass, the open placeholder lets an undeclared argument
    // through the argument check.
    assert!(
        !matches!(f.undeclared_read(), Err(Denial::ArgumentUndeclared { .. })),
        "the placeholder declares nothing, so nothing is refused as undeclared"
    );

    let report = f.store.pin_handle_placeholder_schemas().unwrap();
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    let rows = f.rows();
    assert_eq!(report.pinned.len(), rows.len(), "{report:?}");
    for (action, (schema_json, schema_hash, status, generation)) in &rows {
        let reviewed = reviewed_schema(action);
        let stored: Value = serde_json::from_str(schema_json).unwrap();
        assert_eq!(stored, reviewed, "{action}");
        assert_eq!(
            *schema_hash,
            plexus_core::jcs::jcs_sha256(&reviewed).unwrap(),
            "{action}"
        );
        assert_eq!(status, "active", "{action}: the move never quarantines");
        assert_eq!(*generation, 2, "{action}: the schema change bumps once");
        let pin = report
            .pinned
            .iter()
            .find(|pin| pin.action == *action)
            .unwrap();
        assert_eq!(
            (pin.principal.as_str(), pin.connection_id.as_str()),
            (PRINCIPAL, CONNECTION)
        );
        assert_eq!(pin.schema_hash, *schema_hash, "{action}");
    }

    // The check now covers the handle: the same undeclared argument is refused.
    match f.undeclared_read() {
        Err(Denial::ArgumentUndeclared { field }) => assert_eq!(field, "unreviewed"),
        other => panic!("expected an undeclared-argument refusal, got {other:?}"),
    }

    // Every bot request kind still completes against the pinned schemas,
    // because each leg sends only what its action declares.
    github_bodies(&f.transport);
    for (label, request, writes) in every_request_kind() {
        if request["verb"] == "pr ready" {
            let undo = request["undo"].as_bool().unwrap();
            f.transport.set_response_for_method(
                "github.pull_request.get",
                "",
                MockResponse::Success(json!({
                    "user":{"login":"app-fixture[bot]","type":"Bot"},"draft":!undo,
                    "node_id":"PR_7","html_url":"https://github.com/org/repo/pull/7","number":7
                })),
            );
            let (action, mutation) = if undo {
                ("convert_pull_request_to_draft", "convertPullRequestToDraft")
            } else {
                ("mark_pull_request_ready", "markPullRequestReadyForReview")
            };
            f.transport.set_response_for_method(
                action,
                "",
                MockResponse::Success(json!({"data":{mutation:{"pullRequest":{
                    "url":"https://github.com/org/repo/pull/7","number":7,"isDraft":undo
                }}}})),
            );
        }
        let before = f.transport.requests().len();
        let reply = f.call(&request, label);
        assert_eq!(reply["result"]["status"], "completed", "{label}: {reply}");
        let sent: Vec<String> = f.transport.requests()[before..]
            .iter()
            .map(|request| request.action.clone())
            .collect();
        for write in writes {
            assert!(
                sent.iter().any(|action| action == write),
                "{label}: {write} was not sent, sent {sent:?}"
            );
        }
    }
}

#[test]
fn a_row_holding_any_other_schema_is_left_exactly_as_it_is() {
    let f = Fixture::new("handle-pin-real-schema");
    let pinned = json!({"type":"object","properties":{"body":{"type":"string"}}});
    f.set(
        "add_issue_comment",
        &format!("schema_json = '{pinned}', schema_hash = 'reviewer-pin'"),
    );
    // Accepts any argument like the placeholder does, but is not the exact
    // placeholder, so it must not move.
    f.set(
        "add_reaction",
        r#"schema_json = '{"type":"object","additionalProperties":true,"properties":{}}',
           schema_hash = 'near-placeholder'"#,
    );
    let comment = f.row("add_issue_comment");
    let reaction = f.row("add_reaction");

    let report = f.store.pin_handle_placeholder_schemas().unwrap();

    assert_eq!(f.row("add_issue_comment"), comment);
    assert_eq!(f.row("add_reaction"), reaction);
    assert!(report
        .pinned
        .iter()
        .all(|pin| pin.action != "add_issue_comment" && pin.action != "add_reaction"));
    // The rest of the handle's rows still moved.
    assert_eq!(report.pinned.len(), f.rows().len() - 2, "{report:?}");
}

#[test]
fn a_quarantined_placeholder_row_is_left_for_its_reviewer() {
    let f = Fixture::new("handle-pin-quarantined");
    f.set(
        "close_issue",
        "status = 'quarantined', quarantine_reason = 'schema_changed_requires_review'",
    );
    let quarantined = f.row("close_issue");
    assert_eq!(quarantined.0, PLACEHOLDER);

    let report = f.store.pin_handle_placeholder_schemas().unwrap();

    assert_eq!(f.row("close_issue"), quarantined);
    assert!(report.pinned.iter().all(|pin| pin.action != "close_issue"));
    assert_eq!(report.pinned.len(), f.rows().len() - 1, "{report:?}");
}

#[test]
fn a_second_pass_moves_nothing() {
    let f = Fixture::new("handle-pin-idempotent");
    let first = f.store.pin_handle_placeholder_schemas().unwrap();
    assert!(!first.pinned.is_empty());
    let after_first = f.rows();

    let second = f.store.pin_handle_placeholder_schemas().unwrap();

    assert_eq!(second, Default::default());
    assert_eq!(f.rows(), after_first, "no schema, hash or generation moved");
}

#[test]
fn an_action_the_reviewed_manifest_does_not_declare_keeps_the_placeholder_as_a_gap() {
    let f = Fixture::new("handle-pin-gap");
    let db = f.db();
    db.execute(
        "INSERT INTO catalog_actions (connection_id, principal, name, schema_json, schema_hash,
            risk, severity, status, first_seen_at_ms, last_seen_at_ms, ask_first)
         VALUES (?1, ?2, 'github.withdrawn.action', ?3, 'placeholder', 'read', 'S1',
            'active', 1, 1, 0)",
        params![CONNECTION, PRINCIPAL, PLACEHOLDER],
    )
    .unwrap();
    let before = f.row("github.withdrawn.action");

    let report = f.store.pin_handle_placeholder_schemas().unwrap();

    assert_eq!(f.row("github.withdrawn.action"), before);
    assert_eq!(report.gaps.len(), 1, "{report:?}");
    assert_eq!(report.gaps[0].action, "github.withdrawn.action");
    assert_eq!(report.gaps[0].connection_id, CONNECTION);
    assert_eq!(report.gaps[0].reason, "action not in the reviewed manifest");
}

#[test]
fn a_revoked_handle_connection_is_skipped() {
    let f = Fixture::new("handle-pin-revoked");
    assert!(f.store.revoke_connection(PRINCIPAL, CONNECTION).unwrap());
    let before = f.rows();

    let report = f.store.pin_handle_placeholder_schemas().unwrap();

    assert_eq!(report, Default::default());
    assert_eq!(f.rows(), before);
}

/// Moving a row off the placeholder changes its schema hash, so a watch pinned
/// to the placeholder hash is suspended for review exactly as a catalog
/// refresh suspends one on any schema change.
#[test]
fn a_watch_pinned_to_the_placeholder_is_suspended_when_its_row_moves() {
    let f = Fixture::new("handle-pin-suspends");
    let placeholder_hash = f.row("github.issue.get").1;
    f.db()
        .execute(
            "INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action,
                cadence_s, cursor_kind, schema_hash, status, created_at_ms)
             VALUES ('watch-placeholder', ?1, ?2, 'github.issue.get', 60, 'snapshot_diff', ?3,
                'active', 1)",
            params![PRINCIPAL, CONNECTION, placeholder_hash],
        )
        .unwrap();

    let report = f.store.pin_handle_placeholder_schemas().unwrap();

    assert!(report
        .pinned
        .iter()
        .any(|pinned| pinned.action == "github.issue.get"));
    let (status, reason): (String, Option<String>) = f
        .db()
        .query_row(
            "SELECT status, suspended_reason FROM trigger_subscriptions
             WHERE subscription_id = 'watch-placeholder'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (status.as_str(), reason.as_deref()),
        ("suspended", Some("schema_changed")),
        "a watch pinned to the placeholder must be suspended"
    );
}
