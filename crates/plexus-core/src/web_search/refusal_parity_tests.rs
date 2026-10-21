//! Every outcome path of web_search (compatibility mode) and code_search,
//! pinned as the exact error body the agent receives and the exact search
//! audit row written. The two tools share their governance checks, so this
//! table is what shows a change to the shared code alters a tool's reply or
//! audit row only where intended.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::code_search::{CodeSearchService, ACTION as CODE_ACTION, BACKEND as CODE_BACKEND};
use crate::governance::GovernanceEngine;
use crate::scope::CallScope;
use crate::storage::{CatalogActionInput, GrantInput, PlexusStore, CATALOG_PRINCIPAL};
use crate::test_scratch::Scratch;
use crate::web_search::{ExaRestBackend, WebSearchService};
use crate::{MockResponse, MockTransport, StubCredentialSource};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

const NOW: i64 = 1_790_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tool {
    Web,
    Code,
}

impl Tool {
    fn connection(self) -> &'static str {
        match self {
            Self::Web => "exa",
            Self::Code => "grep",
        }
    }
    fn app_key(self) -> &'static str {
        match self {
            Self::Web => "exa_rest",
            Self::Code => CODE_BACKEND,
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::Web => "search",
            Self::Code => CODE_ACTION,
        }
    }
    fn gate(self) -> &'static str {
        match self {
            Self::Web => "web_search",
            Self::Code => "code_search",
        }
    }
    fn vendor_reply(self) -> Value {
        match self {
            Self::Web => json!({"results": [
                {"url": "https://a.example/", "title": "A", "text": "first"},
                {"url": "https://b.example/", "title": "B", "text": "second"},
            ]}),
            Self::Code => {
                let sse = include_str!("../../tests/fixtures/grep_app/search.sse");
                let data = sse
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .unwrap();
                serde_json::from_str::<Value>(data).unwrap()["result"].clone()
            }
        }
    }
}

struct Fixture {
    store: Arc<PlexusStore>,
    transport: Arc<MockTransport>,
    engine: GovernanceEngine<StubCredentialSource, MockTransport>,
    web: WebSearchService,
    code: CodeSearchService,
    path: Scratch,
}

fn add_connection(store: &PlexusStore, id: &str, app_key: &str, action: &str) {
    store
        .insert_connection(
            "direct",
            id,
            app_key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", id, b"test:search")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: id.into(),
            name: action.into(),
            title: None,
            schema: schema.clone(),
            schema_hash: crate::jcs_sha256(&schema).unwrap(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_grant(&GrantInput {
            principal: "direct".into(),
            connection_id: id.into(),
            grant_id: format!("{id}-direct"),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![action.into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

impl Fixture {
    fn new(name: &str) -> Self {
        let path = Scratch::database(name);
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: name.into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let source = include_str!("../../../../catalog/grep_app.jsonc");
        let manifest = crate::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
        )
        .unwrap();
        store.upsert_manifest(CATALOG_PRINCIPAL, &manifest).unwrap();
        add_connection(
            &store,
            Tool::Web.connection(),
            Tool::Web.app_key(),
            Tool::Web.action(),
        );
        add_connection(
            &store,
            Tool::Code.connection(),
            Tool::Code.app_key(),
            Tool::Code.action(),
        );
        let transport = Arc::new(MockTransport::default());
        Self {
            engine: GovernanceEngine::new(
                store.clone(),
                Arc::new(StubCredentialSource::with_default_success(
                    b"test-credential".to_vec(),
                )),
                transport.clone(),
            ),
            store,
            transport,
            web: WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW)),
            code: CodeSearchService::with_clock(Arc::new(|| NOW)),
            path,
        }
    }

    /// The tool's reply as the agent receives it (the error body, or a
    /// summary of a successful response) and the search audit row it wrote.
    fn call(
        &self,
        tool: Tool,
        caller: &str,
        arguments: &Value,
        scope: Option<&CallScope>,
    ) -> (String, String) {
        let arguments: &Map<String, Value> = arguments.as_object().unwrap();
        let reply = match tool {
            Tool::Web => match self
                .web
                .search_scoped(&self.engine, caller, arguments, scope, None)
            {
                Ok(response) => format!(
                    "ok backend={} cached={} results={}",
                    response.backend,
                    response.cached,
                    response.results.len()
                ),
                Err(refusal) => refusal.to_wire().to_string(),
            },
            Tool::Code => {
                match self
                    .code
                    .search_scoped(&self.engine, caller, arguments, scope, None)
                {
                    Ok(response) => format!(
                        "ok matches={} truncated={}",
                        response.matches.len(),
                        response.truncated
                    ),
                    Err(refusal) => refusal.to_wire().to_string(),
                }
            }
        };
        (reply, self.last_audit_row(tool))
    }

    fn last_audit_row(&self, tool: Tool) -> String {
        let db = rusqlite::Connection::open(self.path.path()).unwrap();
        db.query_row(
            "SELECT principal, actor, connection_id, app_key, action, risk, severity,
                    decision, reason_code, outcome, args_redaction_summary, query_text,
                    result_count, response_class, request_id IS NOT NULL
             FROM audit_journal WHERE gate = ?1 ORDER BY journal_id DESC LIMIT 1",
            [tool.gate()],
            |row| {
                let text = |index: usize| -> rusqlite::Result<String> {
                    Ok(row
                        .get::<_, Option<String>>(index)?
                        .unwrap_or_else(|| "-".into()))
                };
                Ok([
                    text(0)?,
                    text(1)?,
                    text(2)?,
                    text(3)?,
                    text(4)?,
                    text(5)?,
                    text(6)?,
                    text(7)?,
                    text(8)?,
                    text(9)?,
                    text(10)?,
                    text(11)?,
                    row.get::<_, Option<i64>>(12)?
                        .map_or_else(|| "-".into(), |count| count.to_string()),
                    text(13)?,
                    if row.get::<_, bool>(14)? {
                        "request_id".into()
                    } else {
                        "-".into()
                    },
                ]
                .join(" | "))
            },
        )
        .unwrap()
    }
}

fn flow_scope() -> CallScope {
    CallScope {
        owner: "reserved:stranger".into(),
        scope_ref: "flow-1".into(),
        scope_epoch: 1,
        kind: Some("worker".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: Some("flow-1".into()),
        delegates: true,
        owner_authorized: true,
    }
}

/// Run one named path for one tool on a fresh store and return
/// `name | reply` and `name | audit row` lines.
fn run_case(name: &str, tool: Tool) -> Option<[String; 2]> {
    let mut fixture = Fixture::new(&format!("parity-{name}-{tool:?}"));
    fixture
        .transport
        .set_response(MockResponse::Success(tool.vendor_reply()));
    let store = fixture.store.clone();
    let (connection, action) = (tool.connection(), tool.action());
    let query = json!({"query": "pub fn with_capacity"});
    let mut caller = "direct";
    let mut arguments = query.clone();
    let mut scope = None;
    match name {
        "dispatched" => {}
        "cache_hit" => {
            if tool == Tool::Code {
                return None;
            }
            fixture.call(tool, caller, &arguments, None);
        }
        "invalid_query" => arguments = json!({"query": ""}),
        "code_lookup" => {
            if tool == Tool::Code {
                return None;
            }
            arguments = json!({"query": "site:github.com/owner/repo/blob/main/lib.rs"});
        }
        "not_granted" => caller = "reserved:stranger",
        "flow_not_granted" => {
            caller = "reserved:stranger";
            scope = Some(flow_scope());
        }
        "ambiguous" => add_connection(&store, "second", tool.app_key(), action),
        "ask_first" => {
            store
                .set_policy("direct", connection, action, "ask_first", None)
                .unwrap();
        }
        "block" => {
            store
                .set_policy("direct", connection, action, "block", None)
                .unwrap();
        }
        "quarantined" => {
            store
                .quarantine_action("direct", connection, action, "operator review")
                .unwrap();
        }
        "quarantined_ask_first" => {
            store
                .quarantine_action("direct", connection, action, "operator review")
                .unwrap();
            store
                .set_policy("direct", connection, action, "ask_first", None)
                .unwrap();
        }
        "connection_unusable" => {
            store
                .set_connection_health(
                    "direct",
                    connection,
                    "degraded",
                    &json!({"healthy_enough": false}),
                )
                .unwrap();
        }
        "quarantined_unusable" => {
            store
                .quarantine_action("direct", connection, action, "operator review")
                .unwrap();
            store
                .set_connection_health(
                    "direct",
                    connection,
                    "degraded",
                    &json!({"healthy_enough": false}),
                )
                .unwrap();
        }
        "connection_unusable_ask_first" => {
            store
                .set_connection_health(
                    "direct",
                    connection,
                    "degraded",
                    &json!({"healthy_enough": false}),
                )
                .unwrap();
            store
                .set_policy("direct", connection, action, "ask_first", None)
                .unwrap();
        }
        "rate_limited" => {
            store
                .set_web_search_limits(
                    match tool {
                        Tool::Web => "exa",
                        Tool::Code => CODE_BACKEND,
                    },
                    crate::storage::web_search_store::WebSearchLimits {
                        per_caller_per_minute: 1,
                        per_backend_per_minute: 10,
                    },
                )
                .unwrap();
            fixture.call(tool, caller, &json!({"query": "first search"}), None);
        }
        "vendor_throttled" => fixture.transport.set_response(MockResponse::Throttled {
            retry_after_ms: Some(12_000),
            message: "slow down".into(),
        }),
        "vendor_throttled_no_delay" => fixture.transport.set_response(MockResponse::Throttled {
            retry_after_ms: None,
            message: "slow down".into(),
        }),
        "vendor_failed" => fixture.transport.set_response(MockResponse::VendorError {
            code: "vendor_bad".into(),
            message: "sensitive vendor body".into(),
        }),
        "outcome_unknown" => fixture.transport.set_response(MockResponse::OutcomeUnknown),
        "transient_not_sent" => fixture
            .transport
            .set_response(MockResponse::TransientNotSent {
                message: "connection refused".into(),
            }),
        "reply_unreadable" => fixture
            .transport
            .set_response(MockResponse::Success(json!({"unexpected": true}))),
        "home_not_held" => {
            fixture.engine = fixture
                .engine
                .with_connector_home_guard(Arc::new(|| Some("not-held".into())));
        }
        "store_failure" => {
            let db = rusqlite::Connection::open(fixture.path.path()).unwrap();
            db.execute("DROP TABLE policies", []).unwrap();
        }
        other => panic!("unknown case {other}"),
    }
    let (reply, audit) = fixture.call(tool, caller, &arguments, scope.as_ref());
    Some([
        format!("{name} {tool:?} reply | {reply}"),
        format!("{name} {tool:?} audit | {audit}"),
    ])
}

const CASES: &[&str] = &[
    "dispatched",
    "cache_hit",
    "invalid_query",
    "code_lookup",
    "not_granted",
    "flow_not_granted",
    "ambiguous",
    "ask_first",
    "block",
    "quarantined",
    "quarantined_ask_first",
    "connection_unusable",
    "quarantined_unusable",
    "connection_unusable_ask_first",
    "rate_limited",
    "vendor_throttled",
    "vendor_throttled_no_delay",
    "vendor_failed",
    "outcome_unknown",
    "transient_not_sent",
    "reply_unreadable",
    "home_not_held",
    "store_failure",
];

fn actual_table() -> Vec<String> {
    let mut lines = Vec::new();
    for name in CASES {
        for tool in [Tool::Web, Tool::Code] {
            if let Some(pair) = run_case(name, tool) {
                lines.extend(pair);
            }
        }
    }
    lines
}

/// Each line is `case tool reply|audit | ...`. Audit columns: principal,
/// actor, connection_id, app_key, action, risk, severity, decision,
/// reason_code, outcome, args_redaction_summary, query_text, result_count,
/// response_class, and whether request_id is set.
const EXPECTED: &str = include_str!("refusal_parity_expected.txt");

#[test]
fn every_search_path_replies_and_audits_exactly_as_pinned() {
    let actual = actual_table();
    if std::env::var_os("PLEXUS_PRINT_SEARCH_PARITY").is_some() {
        println!(
            "BEGIN PARITY TABLE\n{}\nEND PARITY TABLE",
            actual.join("\n")
        );
    }
    let expected = EXPECTED.lines().collect::<Vec<_>>();
    let mismatches = actual
        .iter()
        .zip(
            expected
                .iter()
                .copied()
                .chain(std::iter::repeat("<missing>")),
        )
        .filter(|(actual, expected)| actual.as_str() != *expected)
        .map(|(actual, expected)| format!("expected: {expected}\n  actual: {actual}"))
        .collect::<Vec<_>>();
    assert!(
        mismatches.is_empty() && actual.len() == expected.len(),
        "a search path's reply or audit row changed ({} of {} lines differ, {} expected lines):\n{}",
        mismatches.len(),
        actual.len(),
        expected.len(),
        mismatches.join("\n")
    );
}
