//! Per-connector fixture description for the conformance runner.

use std::path::PathBuf;

use serde_json::{json, Value};

use crate::stub_server::StubTool;

/// Where the transport should send vendor traffic.
#[derive(Debug, Clone)]
pub enum TransportTarget {
    /// Start an in-process MCP stub presenting `expected_actions`.
    InProcessStub,
    /// Start an in-process REST stub answering the routes the manifest declares.
    InProcessRestStub,
    /// Use the reviewed manifest URL (real vendor). Requires an operator handle.
    ManifestEndpoint,
    /// Explicit endpoint override (tests / local stubs).
    Endpoint(String),
}

/// How the harness exercises connector write behavior: none (read-only),
/// ask-first approve-then-dispatch, or S3 decision-plane escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePath {
    /// No write action (read-only vendors). Ask-first write is an honest SKIP.
    None,
    /// S2 ask-first: create action_request → approve → dispatch.
    AskFirst,
    /// Floor-S3: invoke yields NeedsDecisionPlane (unconfigured decision plane).
    S3Escalation,
}

/// One connector fixture the runner can execute.
#[derive(Debug, Clone)]
pub struct ConnectorFixture {
    pub name: String,
    pub manifest_path: PathBuf,
    pub stub_payload: Vec<u8>,
    pub transport_target: TransportTarget,
    pub expected_actions: Vec<String>,
    pub read_action: String,
    /// Args for the allowed-read step (and other read-shaped probes).
    pub read_args: Value,
    pub write_action: Option<String>,
    pub write_path: WritePath,
    pub principal: String,
    pub canary_handle: Vec<u8>,
    /// Resource filters applied to the connection at create time.
    pub resource_filters: Value,
    /// When set, the write action requires these args for resource-filter pass.
    pub write_args: Value,
    /// Args that should fail the resource-filter gate.
    pub denied_resource_args: Value,
    /// Action used for the resource-filter denial probe (defaults to write_action
    /// when present; read-only fixtures set this explicitly, e.g. list_events).
    pub resource_filter_action: Option<String>,
}

type FixtureRegistration = (&'static str, fn() -> ConnectorFixture, fn(&str) -> StubTool);

macro_rules! fixture_registry {
    ($($name:literal => $constructor:ident, $stub:ident);+ $(;)?) => {
        const FIXTURE_NAMES: &[&str] = &[$($name),+];
        const FIXTURE_REGISTRY: &[FixtureRegistration] = &[$(($name, ConnectorFixture::$constructor, $stub)),+];
    };
}

fixture_registry! {
    "stub" => stub, default_stub_tool;
    "exa" => exa, exa_stub_tool;
    "linear" => linear, linear_stub_tool;
    "sentry" => sentry, sentry_stub_tool;
    "notion" => notion, notion_stub_tool;
    "gcal" => gcal, gcal_stub_tool;
    "github" => github, github_stub_tool;
    "tavily" => tavily, default_stub_tool;
    "context7" => context7, default_stub_tool;
    "firecrawl" => firecrawl, default_stub_tool;
    "huggingface" => huggingface, default_stub_tool;
    "deepwiki" => deepwiki, default_stub_tool;
    "restdemo" => restdemo, default_stub_tool;
    "exa_rest" => exa_rest, default_stub_tool;
    "supabase" => supabase, default_stub_tool;
    "neon" => neon, default_stub_tool;
    "posthog_rest" => posthog_rest, default_stub_tool;
    "resend" => resend, default_stub_tool;
    "browserbase" => browserbase, default_stub_tool;
}

fn default_stub_tool(name: &str) -> StubTool {
    StubTool::simple(name)
}

impl ConnectorFixture {
    fn defaults() -> Self {
        Self {
            name: String::new(),
            manifest_path: PathBuf::new(),
            stub_payload: Vec::new(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: Vec::new(),
            read_action: String::new(),
            read_args: json!({}),
            write_action: None,
            write_path: WritePath::None,
            principal: "direct".into(),
            canary_handle: Vec::new(),
            resource_filters: json!({}),
            write_args: json!({}),
            denied_resource_args: json!({}),
            resource_filter_action: None,
        }
    }

    /// Synthetic full-surface fixture used for CI end-to-end green.
    pub fn stub() -> Self {
        let manifest_path = PathBuf::from("fixtures/stub.jsonc");
        Self {
            name: "stub".to_string(),
            manifest_path,
            stub_payload: b"stub-vendor-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "read_item".to_string(),
                "write_item".to_string(),
                "quarantine_candidate".to_string(),
            ],
            read_action: "read_item".to_string(),
            read_args: json!({"q": "conformance"}),
            write_action: Some("write_item".to_string()),
            write_path: WritePath::AskFirst,
            canary_handle: b"test:CANARY-HANDLE-STUB-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["team"],
                "optional": [],
                "write_enabling": ["team"],
                "values": { "team": ["core", "platform"] }
            }),
            write_args: json!({"team": "core", "title": "conformance-write"}),
            denied_resource_args: json!({"team": "forbidden", "title": "nope"}),
            ..Self::defaults()
        }
    }

    /// Real Exa catalog against an in-process stub presenting Exa's action set.
    pub fn exa() -> Self {
        let manifest_path = PathBuf::from("catalog/exa.jsonc");
        Self {
            name: "exa".to_string(),
            manifest_path,
            stub_payload: b"exa-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            // Live-verified names from https://mcp.exa.ai/mcp tools/list.
            expected_actions: vec!["web_search_exa".to_string(), "web_fetch_exa".to_string()],
            read_action: "web_search_exa".to_string(),
            read_args: json!({"query": "conformance test", "numResults": 1}),
            canary_handle: b"test:CANARY-HANDLE-EXA-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": ["domain_allowlist"],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Real Linear catalog against an in-process stub presenting Linear's declared actions.
    pub fn linear() -> Self {
        let manifest_path = PathBuf::from("catalog/linear.jsonc");
        Self {
            name: "linear".to_string(),
            manifest_path,
            stub_payload: b"linear-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "search_issues".to_string(),
                "get_issue".to_string(),
                "create_issue".to_string(),
                "comment_issue".to_string(),
                "update_issue_status".to_string(),
            ],
            read_action: "search_issues".to_string(),
            read_args: json!({"q": "conformance"}),
            write_action: Some("create_issue".to_string()),
            write_path: WritePath::AskFirst,
            canary_handle: b"test:CANARY-HANDLE-LINEAR-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["workspace", "team"],
                "optional": ["project", "label", "cycle", "status"],
                "write_enabling": ["team"],
                "values": {
                    "workspace": ["acme"],
                    "team": ["core", "platform"]
                }
            }),
            write_args: json!({
                "workspace": "acme",
                "team": "core",
                "title": "conformance-create-issue"
            }),
            denied_resource_args: json!({
                "workspace": "acme",
                "team": "forbidden",
                "title": "nope"
            }),
            ..Self::defaults()
        }
    }

    /// Real Sentry catalog against an in-process stub presenting Sentry's declared actions.
    pub fn sentry() -> Self {
        let manifest_path = PathBuf::from("catalog/sentry.jsonc");
        Self {
            name: "sentry".to_string(),
            manifest_path,
            stub_payload: b"sentry-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "search_issues".to_string(),
                "get_issue".to_string(),
                "get_event".to_string(),
                "comment_issue".to_string(),
                "assign_issue".to_string(),
                "resolve_issue".to_string(),
            ],
            read_action: "search_issues".to_string(),
            read_args: json!({"q": "conformance"}),
            write_action: Some("comment_issue".to_string()),
            write_path: WritePath::AskFirst,
            canary_handle: b"test:CANARY-HANDLE-SENTRY-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["org", "project"],
                "optional": ["environment", "status"],
                "write_enabling": ["project"],
                "values": {
                    "org": ["acme"],
                    "project": ["api", "web"]
                }
            }),
            write_args: json!({
                "org": "acme",
                "project": "api",
                "issue": "PROJ-1",
                "body": "conformance comment"
            }),
            denied_resource_args: json!({
                "org": "acme",
                "project": "forbidden",
                "issue": "PROJ-1",
                "body": "nope"
            }),
            ..Self::defaults()
        }
    }

    /// Notion catalog (tier S3 floor): writes escalate to NeedsDecisionPlane.
    pub fn notion() -> Self {
        let manifest_path = PathBuf::from("catalog/notion.jsonc");
        Self {
            name: "notion".to_string(),
            manifest_path,
            stub_payload: b"notion-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "search".to_string(),
                "query_database".to_string(),
                "read_page".to_string(),
                "create_page".to_string(),
                "append_block".to_string(),
            ],
            read_action: "search".to_string(),
            read_args: json!({
                "workspace": "acme",
                "q": "conformance"
            }),
            write_action: Some("create_page".to_string()),
            write_path: WritePath::S3Escalation,
            canary_handle: b"test:CANARY-HANDLE-NOTION-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["workspace"],
                "optional": ["page_allowlist", "database_allowlist", "property_filter"],
                "write_enabling": ["parent_allowlist"],
                "values": {
                    "workspace": ["acme"],
                    "parent_allowlist": ["drafts", "inbox"]
                }
            }),
            write_args: json!({
                "workspace": "acme",
                "parent_allowlist": "drafts",
                "title": "conformance-create-page"
            }),
            // S3 severity runs before the resource gate, so write-path resource
            // denials are not reachable; denied_calls skips the resource probe
            // for S3Escalation fixtures.
            denied_resource_args: json!({
                "workspace": "acme",
                "parent_allowlist": "forbidden",
                "title": "nope"
            }),
            ..Self::defaults()
        }
    }

    /// Google Calendar catalog: read-only fixture plus calendar allowlist denial probe.
    pub fn gcal() -> Self {
        let manifest_path = PathBuf::from("catalog/gcal.jsonc");
        Self {
            name: "gcal".to_string(),
            manifest_path,
            stub_payload: b"gcal-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "list_calendars".to_string(),
                "list_events".to_string(),
                "get_availability".to_string(),
            ],
            read_action: "list_calendars".to_string(),
            read_args: json!({
                "calendar_allowlist": "primary"
            }),
            canary_handle: b"test:CANARY-HANDLE-GCAL-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["calendar_allowlist"],
                "optional": ["time_window", "attendee_domain"],
                "write_enabling": [],
                "values": {
                    "calendar_allowlist": ["primary", "work"]
                }
            }),
            denied_resource_args: json!({
                "calendar_allowlist": "forbidden"
            }),
            resource_filter_action: Some("list_events".to_string()),
            ..Self::defaults()
        }
    }

    /// GitHub catalog: read-only /readonly variant with owner/repo filters.
    pub fn github() -> Self {
        let manifest_path = PathBuf::from("catalog/github.jsonc");
        Self {
            name: "github".to_string(),
            manifest_path,
            stub_payload: b"github-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            // Tool names from the GitHub MCP server default-readonly toolset
            // (https://github.com/github/github-mcp-server).
            expected_actions: vec![
                "get_me".to_string(),
                "get_team_members".to_string(),
                "get_teams".to_string(),
                "search_repositories".to_string(),
                "get_file_contents".to_string(),
                "search_code".to_string(),
                "search_commits".to_string(),
                "get_commit".to_string(),
                "list_branches".to_string(),
                "list_commits".to_string(),
                "list_releases".to_string(),
                "get_latest_release".to_string(),
                "get_release_by_tag".to_string(),
                "get_tag".to_string(),
                "list_tags".to_string(),
                "list_repository_collaborators".to_string(),
                "list_issues".to_string(),
                "search_issues".to_string(),
                "issue_read".to_string(),
                "get_label".to_string(),
                "list_issue_fields".to_string(),
                "list_issue_types".to_string(),
                "list_pull_requests".to_string(),
                "pull_request_read".to_string(),
                "search_pull_requests".to_string(),
                "search_users".to_string(),
                "run_secret_scanning".to_string(),
            ],
            read_action: "search_repositories".to_string(),
            read_args: json!({"q": "conformance"}),
            canary_handle: b"test:CANARY-HANDLE-GITHUB-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": ["owner", "repo"],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Tavily catalog: read-only web search and extraction.
    pub fn tavily() -> Self {
        let manifest_path = PathBuf::from("catalog/tavily.jsonc");
        Self {
            name: "tavily".to_string(),
            manifest_path,
            stub_payload: b"tavily-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec!["tavily_search".to_string(), "tavily_extract".to_string()],
            read_action: "tavily_search".to_string(),
            read_args: json!({"query": "conformance test"}),
            canary_handle: b"test:CANARY-HANDLE-TAVILY-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": [],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Context7 catalog: read-only library documentation lookup.
    pub fn context7() -> Self {
        let manifest_path = PathBuf::from("catalog/context7.jsonc");
        Self {
            name: "context7".to_string(),
            manifest_path,
            stub_payload: b"context7-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec!["resolve-library-id".to_string(), "query-docs".to_string()],
            read_action: "resolve-library-id".to_string(),
            read_args: json!({"library": "react"}),
            canary_handle: b"test:CANARY-HANDLE-CONTEXT7-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": [],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Firecrawl catalog: scrape, search, and document parsing — all read.
    ///
    /// These names come from the live server's own tool list. The fixture once
    /// expected `scrape`/`search`/`map`/`crawl`/`extract`/`agent`/
    /// `interact`, none of which the vendor serves any more, and it passed the
    /// whole time: the stub transport presents whatever the fixture declares,
    /// so a fixture and a manifest that agree with each other are green even
    /// when both are wrong about the vendor. Only `--live` against the real
    /// endpoint can tell them apart, which is why catalog drift is invisible
    /// until someone connects in production.
    ///
    /// There is no write vector because the vendor withdrew every mutating
    /// tool; the browser-driving `agent` and `interact` are gone. Ask-first and
    /// write-enabling coverage lives in the fixtures whose vendors actually
    /// serve writes (browserbase, notion), so nothing is lost by this fixture
    /// declining to invent one.
    pub fn firecrawl() -> Self {
        let manifest_path = PathBuf::from("catalog/firecrawl.jsonc");
        Self {
            name: "firecrawl".to_string(),
            manifest_path,
            stub_payload: b"firecrawl-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "firecrawl_scrape".to_string(),
                "firecrawl_search".to_string(),
                "firecrawl_parse".to_string(),
            ],
            read_action: "firecrawl_scrape".to_string(),
            read_args: json!({"url": "https://example.com"}),
            canary_handle: b"test:CANARY-HANDLE-FIRECRAWL-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": [],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Hugging Face catalog: read-only model/dataset/space search and repo reads.
    pub fn huggingface() -> Self {
        let manifest_path = PathBuf::from("catalog/huggingface.jsonc");
        Self {
            name: "huggingface".to_string(),
            manifest_path,
            stub_payload: b"huggingface-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            // Tool names confirmed from https://github.com/huggingface/hf-mcp-server
            // (ALL_BUILTIN_TOOL_IDS in tool-ids.ts), read-shaped subset only.
            expected_actions: vec![
                "model_search".to_string(),
                "model_details".to_string(),
                "dataset_search".to_string(),
                "dataset_details".to_string(),
                "space_search".to_string(),
                "space_info".to_string(),
                "space_files".to_string(),
                "paper_search".to_string(),
                "hub_repo_search".to_string(),
                "hub_repo_details".to_string(),
                "hf_fs".to_string(),
                "hf_doc_search".to_string(),
                "hf_doc_fetch".to_string(),
            ],
            read_action: "model_search".to_string(),
            read_args: json!({"query": "conformance test"}),
            canary_handle: b"test:CANARY-HANDLE-HUGGINGFACE-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": [],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Synthetic REST fixture: a hand-written `rest_api` manifest exercised
    /// against an in-process REST stub. Covers a GET with a path parameter, a
    /// POST with a JSON body, and an ask-first gated write.
    pub fn restdemo() -> Self {
        let manifest_path = PathBuf::from("fixtures/restdemo.jsonc");
        Self {
            name: "restdemo".to_string(),
            manifest_path,
            stub_payload: b"restdemo-vendor-token".to_vec(),
            transport_target: TransportTarget::InProcessRestStub,
            expected_actions: vec![
                "get_issue".to_string(),
                "create_issue".to_string(),
                "delete_issue".to_string(),
            ],
            read_action: "get_issue".to_string(),
            read_args: json!({"issue_id": "issue-1", "team": "core"}),
            write_action: Some("create_issue".to_string()),
            write_path: WritePath::AskFirst,
            canary_handle: b"test:CANARY-HANDLE-RESTDEMO-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["team"],
                "optional": [],
                "write_enabling": ["team"],
                "values": { "team": ["core", "platform"] }
            }),
            write_args: json!({"team": "core", "title": "conformance-write"}),
            denied_resource_args: json!({"team": "forbidden", "title": "nope"}),
            ..Self::defaults()
        }
    }

    /// DeepWiki: the credential-free vendor. Its manifest declares
    /// `auth.mode = none`, so the fixture exercises the enrollment path that
    /// has no handle to place — the one that was unreachable while the connect
    /// path demanded a credential unconditionally.
    pub fn deepwiki() -> Self {
        let manifest_path = PathBuf::from("catalog/deepwiki.jsonc");
        Self {
            name: "deepwiki".to_string(),
            manifest_path,
            stub_payload: b"deepwiki-unused-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "read_wiki_structure".to_string(),
                "read_wiki_contents".to_string(),
                "ask_question".to_string(),
            ],
            read_action: "ask_question".to_string(),
            read_args: json!({"repo_allowlist": "cortexkit/plexus", "question": "conformance"}),
            canary_handle: b"test:CANARY-HANDLE-DEEPWIKI-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": ["repo_allowlist"],
                "write_enabling": [],
                "values": {
                    "repo_allowlist": ["cortexkit/plexus", "cortexkit/subconscious"]
                }
            }),
            denied_resource_args: json!({"repo_allowlist": "forbidden/repo"}),
            resource_filter_action: Some("ask_question".to_string()),
            ..Self::defaults()
        }
    }

    /// Exa over REST: the live proof for the rest_api transport.
    ///
    /// Same vendor and same credential as the `exa` fixture, which reaches Exa
    /// over MCP. Running both against the real endpoint isolates transport
    /// behaviour from vendor behaviour, and gives the REST path an acceptance
    /// proof against a real third-party API rather than only the in-process
    /// stub — every stub-only proof in this codebase has so far missed
    /// something that first contact with a real vendor found.
    ///
    /// Defaults to the in-process REST stub so it runs on every gate; a live
    /// run supplies --live with an operator handle, which switches the target
    /// to the manifest endpoint.
    pub fn exa_rest() -> Self {
        let manifest_path = PathBuf::from("catalog/exa_rest.jsonc");
        Self {
            name: "exa_rest".to_string(),
            manifest_path,
            stub_payload: b"exa-rest-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessRestStub,
            expected_actions: vec![
                "search".to_string(),
                "get_contents".to_string(),
                "find_similar".to_string(),
            ],
            read_action: "search".to_string(),
            read_args: json!({"query": "CortexKit connectors plane", "numResults": 1}),
            canary_handle: b"test:CANARY-HANDLE-EXA-REST-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": [],
                "write_enabling": []
            }),
            ..Self::defaults()
        }
    }

    /// Supabase catalog fixture covering write operations that can execute arbitrary SQL or Edge Functions.
    pub fn supabase() -> Self {
        let manifest_path = PathBuf::from("catalog/supabase.jsonc");
        Self {
            name: "supabase".to_string(),
            manifest_path,
            stub_payload: b"supabase-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "list_tables".to_string(),
                "list_extensions".to_string(),
                "list_migrations".to_string(),
                "execute_sql".to_string(),
                "get_logs".to_string(),
                "get_advisors".to_string(),
                "get_project_url".to_string(),
                "get_publishable_keys".to_string(),
                "generate_typescript_types".to_string(),
                "list_edge_functions".to_string(),
                "get_edge_function".to_string(),
                "search_docs".to_string(),
                "list_projects".to_string(),
                "get_project".to_string(),
                "apply_migration".to_string(),
                "deploy_edge_function".to_string(),
            ],
            read_action: "list_tables".to_string(),
            read_args: json!({
                "project_id": "project-conformance",
                "q": "conformance"
            }),
            write_action: Some("deploy_edge_function".to_string()),
            write_path: WritePath::S3Escalation,
            canary_handle: b"test:CANARY-HANDLE-SUPABASE-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["project_id"],
                "optional": ["organization_id", "branch_id"],
                "write_enabling": ["project_id"],
                "values": { "project_id": ["project-conformance"] }
            }),
            write_args: json!({
                "project_id": "project-conformance",
                "function_slug": "conformance-probe"
            }),
            denied_resource_args: json!({
                "project_id": "forbidden-project",
                "function_slug": "denied-probe"
            }),
            ..Self::defaults()
        }
    }

    /// Neon catalog preview fixture for write operations that can execute arbitrary SQL.
    pub fn neon() -> Self {
        let manifest_path = PathBuf::from("catalog/neon.jsonc");
        Self {
            name: "neon".to_string(),
            manifest_path,
            stub_payload: b"neon-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "list_projects".to_string(),
                "describe_project".to_string(),
                "describe_branch".to_string(),
                "list_branch_computes".to_string(),
                "get_database_tables".to_string(),
                "describe_table_schema".to_string(),
                "run_sql".to_string(),
                "compare_database_schema".to_string(),
                "list_slow_queries".to_string(),
                "explain_sql_statement".to_string(),
                "get_connection_string".to_string(),
                "search".to_string(),
                "fetch".to_string(),
                "create_branch".to_string(),
                "prepare_database_migration".to_string(),
                "complete_database_migration".to_string(),
            ],
            read_action: "list_projects".to_string(),
            read_args: json!({
                "project_id": "project-conformance",
                "branch_id": "branch-conformance"
            }),
            write_action: Some("create_branch".to_string()),
            write_path: WritePath::S3Escalation,
            canary_handle: b"test:CANARY-HANDLE-NEON-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["project_id"],
                "optional": ["branch_id"],
                "write_enabling": ["project_id", "branch_id"],
                "values": {
                    "project_id": ["project-conformance"],
                    "branch_id": ["branch-conformance"]
                }
            }),
            write_args: json!({
                "project_id": "project-conformance",
                "branch_id": "branch-conformance",
                "branch_name": "conformance-probe"
            }),
            denied_resource_args: json!({
                "project_id": "project-conformance",
                "branch_id": "forbidden-branch",
                "branch_name": "denied-probe"
            }),
            ..Self::defaults()
        }
    }

    /// Read-only PostHog REST catalog fixture. The project ID is supplied as a
    /// connection value allowlist so its per-project scope is asserted on read
    /// calls, where required filters alone do not gate execution.
    pub fn posthog_rest() -> Self {
        let manifest_path = PathBuf::from("catalog/posthog_rest.jsonc");
        Self {
            name: "posthog_rest".to_string(),
            manifest_path,
            stub_payload: b"posthog-rest-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessRestStub,
            expected_actions: vec![
                "error_tracking_issues_list".to_string(),
                "error_tracking_issue_get".to_string(),
                "feature_flags_list".to_string(),
                "feature_flag_get".to_string(),
                "experiments_list".to_string(),
                "experiment_get".to_string(),
                "insights_list".to_string(),
                "insight_get".to_string(),
                "events_list".to_string(),
                "event_get".to_string(),
            ],
            read_action: "feature_flags_list".to_string(),
            read_args: json!({
                "project_id": "project-conformance",
                "limit": 1
            }),
            canary_handle: b"test:CANARY-HANDLE-POSTHOG-REST-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": ["project_id"],
                "optional": [],
                "write_enabling": [],
                "values": { "project_id": ["project-conformance"] }
            }),
            denied_resource_args: json!({"project_id": "forbidden-project"}),
            resource_filter_action: Some("feature_flags_list".to_string()),
            ..Self::defaults()
        }
    }

    /// Resend catalog fixture for an irreversible broadcast send that cannot be undone after execution.
    pub fn resend() -> Self {
        let manifest_path = PathBuf::from("catalog/resend.jsonc");
        Self {
            name: "resend".to_string(),
            manifest_path,
            stub_payload: b"resend-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "list-emails".to_string(),
                "get-email".to_string(),
                "send-email".to_string(),
                "cancel-email".to_string(),
                "list-contacts".to_string(),
                "get-contact".to_string(),
                "create-contact".to_string(),
                "update-contact".to_string(),
                "remove-contact".to_string(),
                "list-domains".to_string(),
                "get-domain".to_string(),
                "create-domain".to_string(),
                "verify-domain".to_string(),
                "list-broadcasts".to_string(),
                "get-broadcast".to_string(),
                "create-broadcast".to_string(),
                "update-broadcast".to_string(),
                "send-broadcast".to_string(),
                "remove-broadcast".to_string(),
            ],
            read_action: "list-emails".to_string(),
            read_args: json!({ "from_domain": "example.com" }),
            write_action: Some("create-broadcast".to_string()),
            write_path: WritePath::S3Escalation,
            canary_handle: b"test:CANARY-HANDLE-RESEND-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": ["from_domain"],
                "write_enabling": ["from_domain"],
                "values": { "from_domain": ["example.com"] }
            }),
            write_args: json!({
                "from_domain": "example.com",
                "subject": "Conformance broadcast"
            }),
            denied_resource_args: json!({
                "from_domain": "forbidden.example",
                "subject": "Denied broadcast"
            }),
            ..Self::defaults()
        }
    }

    /// Browserbase catalog fixture where browser actions that cause side effects require user confirmation before execution.
    pub fn browserbase() -> Self {
        let manifest_path = PathBuf::from("catalog/browserbase.jsonc");
        Self {
            name: "browserbase".to_string(),
            manifest_path,
            stub_payload: b"browserbase-stub-token".to_vec(),
            transport_target: TransportTarget::InProcessStub,
            expected_actions: vec![
                "start".to_string(),
                "end".to_string(),
                "navigate".to_string(),
                "act".to_string(),
                "observe".to_string(),
                "extract".to_string(),
            ],
            read_action: "navigate".to_string(),
            read_args: json!({
                "url": "https://example.com",
                "domain_allowlist": "example.com"
            }),
            write_action: Some("act".to_string()),
            write_path: WritePath::AskFirst,
            canary_handle: b"test:CANARY-HANDLE-BROWSERBASE-CONFORMANCE".to_vec(),
            resource_filters: json!({
                "required": [],
                "optional": ["domain_allowlist"],
                "write_enabling": ["domain_allowlist"],
                "values": { "domain_allowlist": ["example.com"] }
            }),
            write_args: json!({
                "domain_allowlist": "example.com",
                "action": "click #conformance"
            }),
            denied_resource_args: json!({
                "domain_allowlist": "forbidden.example",
                "url": "https://forbidden.example"
            }),
            resource_filter_action: Some("navigate".to_string()),
            ..Self::defaults()
        }
    }

    pub fn by_name(name: &str) -> Result<Self, String> {
        FIXTURE_REGISTRY
            .iter()
            .find(|(registered, _, _)| *registered == name)
            .map(|(_, constructor, _)| constructor())
            .ok_or_else(|| {
                format!(
                    "unknown fixture '{name}' (known: {})",
                    FIXTURE_NAMES.join(", ")
                )
            })
    }

    /// Known fixture names for CLI list/help and integration loops.
    pub fn known_names() -> &'static [&'static str] {
        FIXTURE_NAMES
    }

    pub fn stub_tools(&self) -> Vec<StubTool> {
        let factory = FIXTURE_REGISTRY
            .iter()
            .find(|(name, _, _)| *name == self.name)
            .map(|(_, _, factory)| *factory)
            .unwrap_or(default_stub_tool);
        self.expected_actions
            .iter()
            .map(|name| factory(name))
            .map(|tool| self.declaring_sent_arguments(tool))
            .collect()
    }

    pub fn validate_stub_arguments(&self) -> Result<(), String> {
        for tool in self
            .stub_tools()
            .into_iter()
            .filter(|tool| !tool.inferred_schema)
        {
            let arguments = [
                (Some(self.read_action.as_str()), &self.read_args),
                (self.write_action.as_deref(), &self.write_args),
                (
                    self.resource_filter_action
                        .as_deref()
                        .or(self.write_action.as_deref()),
                    &self.denied_resource_args,
                ),
            ];
            for (_, args) in arguments
                .into_iter()
                .filter(|(name, _)| *name == Some(tool.name.as_str()))
            {
                let extras = args
                    .as_object()
                    .into_iter()
                    .flat_map(|args| args.keys())
                    .filter(|key| tool.input_schema["properties"].get(*key).is_none())
                    .collect::<Vec<_>>();
                if !extras.is_empty() {
                    return Err(format!(
                        "fixture {} sends undeclared arguments {extras:?} to {}",
                        self.name, tool.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Synthetic tools infer their properties from the fixture. Vendor-modelled
    /// schemas stay unchanged so misspelled arguments fail before dispatch.
    fn declaring_sent_arguments(&self, mut tool: StubTool) -> StubTool {
        if !tool.inferred_schema {
            return tool;
        }
        let name = tool.name.as_str();
        let mut sent = Vec::new();
        if name == self.read_action {
            sent.push(&self.read_args);
        }
        if self.write_action.as_deref() == Some(name) {
            sent.push(&self.write_args);
            sent.push(&self.denied_resource_args);
        }
        if self.resource_filter_action.as_deref() == Some(name) {
            sent.push(&self.denied_resource_args);
        }
        let keys: Vec<String> = sent
            .into_iter()
            .filter_map(Value::as_object)
            .flat_map(|args| args.keys().cloned())
            .collect();
        if let Some(properties) = tool.input_schema["properties"].as_object_mut() {
            for key in keys {
                properties.entry(key).or_insert_with(|| json!({}));
            }
        }
        tool
    }

    pub fn load_manifest_source(&self) -> Result<String, String> {
        let embedded = match self.manifest_path.to_str().unwrap_or("") {
            "fixtures/stub.jsonc" => Some(include_str!("../fixtures/stub.jsonc")),
            "fixtures/restdemo.jsonc" => Some(include_str!("../fixtures/restdemo.jsonc")),
            "catalog/exa.jsonc" => Some(include_str!("../../../catalog/exa.jsonc")),
            "catalog/linear.jsonc" => Some(include_str!("../../../catalog/linear.jsonc")),
            "catalog/sentry.jsonc" => Some(include_str!("../../../catalog/sentry.jsonc")),
            "catalog/notion.jsonc" => Some(include_str!("../../../catalog/notion.jsonc")),
            "catalog/gcal.jsonc" => Some(include_str!("../../../catalog/gcal.jsonc")),
            "catalog/github.jsonc" => Some(include_str!("../../../catalog/github.jsonc")),
            "catalog/tavily.jsonc" => Some(include_str!("../../../catalog/tavily.jsonc")),
            "catalog/context7.jsonc" => Some(include_str!("../../../catalog/context7.jsonc")),
            "catalog/firecrawl.jsonc" => Some(include_str!("../../../catalog/firecrawl.jsonc")),
            "catalog/huggingface.jsonc" => Some(include_str!("../../../catalog/huggingface.jsonc")),
            "catalog/deepwiki.jsonc" => Some(include_str!("../../../catalog/deepwiki.jsonc")),
            "catalog/exa_rest.jsonc" => Some(include_str!("../../../catalog/exa_rest.jsonc")),
            "catalog/supabase.jsonc" => Some(include_str!("../../../catalog/supabase.jsonc")),
            "catalog/neon.jsonc" => Some(include_str!("../../../catalog/neon.jsonc")),
            "catalog/posthog_rest.jsonc" => {
                Some(include_str!("../../../catalog/posthog_rest.jsonc"))
            }
            "catalog/resend.jsonc" => Some(include_str!("../../../catalog/resend.jsonc")),
            "catalog/browserbase.jsonc" => Some(include_str!("../../../catalog/browserbase.jsonc")),
            _ => None,
        };
        if let Some(source) = embedded {
            return Ok(source.to_owned());
        }
        std::fs::read_to_string(&self.manifest_path)
            .map_err(|error| format!("read fixture manifest: {error}"))
    }
}

/// Exa's MCP tools with the argument names https://mcp.exa.ai/mcp declares
/// for them, so the fixture's read arguments are ones the discovered schema
/// declares, as they are against the live server.
fn exa_stub_tool(name: &str) -> StubTool {
    let schema = match name {
        "web_search_exa" => json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "numResults": {"type": "number"},
                "objective": {"type": "string"}
            },
            "required": ["query"],
            "additionalProperties": false
        }),
        "web_fetch_exa" => json!({
            "type": "object",
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "maxCharacters": {"type": "number"}
            },
            "required": ["urls"],
            "additionalProperties": false
        }),
        _ => return StubTool::simple(name),
    };
    StubTool::new(name, schema)
}

fn linear_stub_tool(name: &str) -> StubTool {
    let schema = match name {
        "search_issues" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "team": {"type": "string"},
                "project": {"type": "string"},
                "label": {"type": "string"},
                "status": {"type": "string"},
                "q": {"type": "string"}
            }
        }),
        "get_issue" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "team": {"type": "string"},
                "issue_id": {"type": "string"}
            },
            "required": ["issue_id"]
        }),
        "create_issue" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "team": {"type": "string"},
                "title": {"type": "string"},
                "project": {"type": "string"},
                "label": {"type": "string"}
            },
            "required": ["workspace", "team", "title"]
        }),
        "comment_issue" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "team": {"type": "string"},
                "issue_id": {"type": "string"},
                "body": {"type": "string"}
            },
            "required": ["issue_id", "body"]
        }),
        "update_issue_status" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "team": {"type": "string"},
                "issue_id": {"type": "string"},
                "status": {"type": "string"}
            },
            "required": ["issue_id", "status"]
        }),
        _ => json!({"type": "object", "properties": {}}),
    };
    StubTool::new(name.to_string(), schema)
}

fn sentry_stub_tool(name: &str) -> StubTool {
    let schema = match name {
        "search_issues" => json!({
            "type": "object",
            "properties": {
                "org": {"type": "string"},
                "project": {"type": "string"},
                "environment": {"type": "string"},
                "status": {"type": "string"},
                "q": {"type": "string"}
            }
        }),
        "get_issue" => json!({
            "type": "object",
            "properties": {
                "org": {"type": "string"},
                "project": {"type": "string"},
                "issue_id": {"type": "string"}
            },
            "required": ["issue_id"]
        }),
        "get_event" => json!({
            "type": "object",
            "properties": {
                "org": {"type": "string"},
                "project": {"type": "string"},
                "event_id": {"type": "string"}
            },
            "required": ["event_id"]
        }),
        "comment_issue" => json!({
            "type": "object",
            "properties": {
                "org": {"type": "string"},
                "project": {"type": "string"},
                "issue": {"type": "string"},
                "body": {"type": "string"}
            },
            "required": ["org", "project", "issue", "body"]
        }),
        "assign_issue" => json!({
            "type": "object",
            "properties": {
                "org": {"type": "string"},
                "project": {"type": "string"},
                "issue": {"type": "string"},
                "assignee": {"type": "string"}
            },
            "required": ["org", "project", "issue", "assignee"]
        }),
        "resolve_issue" => json!({
            "type": "object",
            "properties": {
                "org": {"type": "string"},
                "project": {"type": "string"},
                "issue": {"type": "string"}
            },
            "required": ["org", "project", "issue"]
        }),
        _ => json!({"type": "object", "properties": {}}),
    };
    StubTool::new(name.to_string(), schema)
}

fn notion_stub_tool(name: &str) -> StubTool {
    let schema = match name {
        "search" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "q": {"type": "string"},
                "page_allowlist": {"type": "string"},
                "database_allowlist": {"type": "string"}
            }
        }),
        "query_database" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "database_allowlist": {"type": "string"},
                "property_filter": {"type": "string"}
            },
            "required": ["workspace"]
        }),
        "read_page" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "page_allowlist": {"type": "string"},
                "page_id": {"type": "string"}
            },
            "required": ["page_id"]
        }),
        "create_page" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "parent_allowlist": {"type": "string"},
                "title": {"type": "string"}
            },
            "required": ["workspace", "parent_allowlist", "title"]
        }),
        "append_block" => json!({
            "type": "object",
            "properties": {
                "workspace": {"type": "string"},
                "page_allowlist": {"type": "string"},
                "page_id": {"type": "string"},
                "body": {"type": "string"}
            },
            "required": ["page_id", "body"]
        }),
        _ => json!({"type": "object", "properties": {}}),
    };
    StubTool::new(name.to_string(), schema)
}

fn gcal_stub_tool(name: &str) -> StubTool {
    let schema = match name {
        "list_calendars" => json!({
            "type": "object",
            "properties": {
                "calendar_allowlist": {"type": "string"}
            }
        }),
        "list_events" => json!({
            "type": "object",
            "properties": {
                "calendar_allowlist": {"type": "string"},
                "time_window": {"type": "string"},
                "attendee_domain": {"type": "string"}
            },
            "required": ["calendar_allowlist"]
        }),
        "get_availability" => json!({
            "type": "object",
            "properties": {
                "calendar_allowlist": {"type": "string"},
                "time_window": {"type": "string"}
            },
            "required": ["calendar_allowlist"]
        }),
        _ => json!({"type": "object", "properties": {}}),
    };
    StubTool::new(name.to_string(), schema)
}

fn github_stub_tool(name: &str) -> StubTool {
    let schema = match name {
        "get_me" => json!({
            "type": "object",
            "properties": {}
        }),
        "get_team_members" | "get_teams" => json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"}
            }
        }),
        "search_repositories"
        | "search_code"
        | "search_commits"
        | "search_issues"
        | "search_users"
        | "search_pull_requests" => json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "q": {"type": "string"}
            }
        }),
        "get_file_contents"
        | "get_commit"
        | "list_branches"
        | "list_commits"
        | "list_releases"
        | "list_tags"
        | "list_repository_collaborators" => json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"}
            },
            "required": ["owner", "repo"]
        }),
        "get_latest_release" | "get_release_by_tag" | "get_tag" => json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"}
            },
            "required": ["owner", "repo"]
        }),
        "list_issues" | "issue_read" | "get_label" | "list_issue_fields" | "list_issue_types" => {
            json!({
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"}
                },
                "required": ["owner", "repo"]
            })
        }
        "list_pull_requests" | "pull_request_read" => json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"}
            },
            "required": ["owner", "repo"]
        }),
        _ => json!({"type": "object", "properties": {}}),
    };
    StubTool::new(name.to_string(), schema)
}
