#[test]
fn provenance_declines_a_dirty_build_and_names_a_missing_git() {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let provenance = |commit: &str| {
        serde_json::to_value(
            subc_protocol::manifest::build_provenance_from_source(
                super::build_git_sha_source(commit),
                None,
                None,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let clean = provenance(sha);
    assert_eq!(clean["build_git_sha"], sha);
    assert!(clean.get("build_git_sha_absence_reason").is_none());
    let dirty = provenance(&format!("{sha}-dirty"));
    assert!(dirty.get("build_git_sha").is_none(), "{dirty}");
    assert_eq!(dirty["build_git_sha_absence_reason"], "declined_dirty");
    let missing = provenance("unavailable");
    assert!(missing.get("build_git_sha").is_none(), "{missing}");
    assert_eq!(missing["build_git_sha_absence_reason"], "no_git_dir");
}

#[test]
fn regression_dirty_marker_checks_only_watched_compiled_inputs() {
    let scratch = plexus_core::test_scratch::Scratch::directory("build-dirty-inputs");
    let git = |args: &[&str]| {
        let mut command = std::process::Command::new("git");
        command.current_dir(scratch.path()).args(args);
        let output = crate::bounded::child_output(
            &mut command,
            std::time::Duration::from_secs(10),
            "fixture git",
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    std::fs::create_dir(scratch.join("crates")).unwrap();
    std::fs::write(scratch.join("crates/lib.rs"), "compiled").unwrap();
    std::fs::write(scratch.join("Cargo.toml"), "manifest").unwrap();
    std::fs::write(scratch.join("Cargo.lock"), "lock").unwrap();
    git(&["add", "."]);
    git(&[
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture",
    ]);
    std::fs::write(scratch.join("notes.md"), "not compiled").unwrap();
    let dirty = || {
        let output = crate::bounded::child_output(
            &mut super::build_support::dirty_command(scratch.path()),
            std::time::Duration::from_secs(10),
            "compiled input status",
        )
        .unwrap();
        assert!(output.status.success());
        !output.stdout.is_empty()
    };
    assert!(!dirty());
    std::fs::write(scratch.join("crates/lib.rs"), "edited").unwrap();
    assert!(dirty());
}

#[test]
fn regression_dirty_command_cannot_refresh_the_watched_index() {
    let command = super::build_support::dirty_command(std::path::Path::new("."));
    assert!(command.get_envs().any(
        |(key, value)| key == "GIT_OPTIONAL_LOCKS" && value == Some(std::ffi::OsStr::new("0"))
    ));
}
#[test]
fn regression_github_and_connection_schemas_admit_handler_fields() {
    let github = tool(
        GITHUB_TOOL,
        "",
        ExecutionMode::Unfenceable,
        &["bot_request", "bindings.read"],
    );
    let connections = tool(
        CONNECTIONS_TOOL,
        "",
        ExecutionMode::Mutating,
        &["configure"],
    );
    // This tool request posts an eyes reaction, matching the existing
    // scoped bot-write handler test.
    let aft = json!({"op":"bot_request","request_nonce":"module-nonce",
            "request":{"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}}});
    let reaction = json!({"op":"bot_request","request_nonce":"reaction", "connection_id":"github-bot",
            "request":{"action":"issue reaction","repository":"org/repo","target":{"number":42},"body":{"reaction":"eyes"}}});
    for call in [
        aft,
        reaction,
        json!({"op":"bindings.read", "connection_id":"github-bot"}),
    ] {
        assert_object_schema_accepts(&github.schema, &call);
    }
    assert_object_schema_accepts(
        &connections.schema,
        &json!({"op":"configure", "connection":"github-bot", "resource_filters":{"repositories":["org/repo"]}}),
    );
}

fn assert_object_schema_accepts(schema: &serde_json::Value, call: &serde_json::Value) {
    assert_eq!(schema["type"], "object");
    for required in schema["required"].as_array().unwrap() {
        assert!(call.get(required.as_str().unwrap()).is_some());
    }
    for (key, value) in call.as_object().unwrap() {
        let property = schema["properties"].get(key);
        assert!(
            property.is_some() || schema["additionalProperties"] != false,
            "field {key} refused by {schema}"
        );
        let Some(property) = property else { continue };
        match property.get("type").and_then(serde_json::Value::as_str) {
            Some("string") => assert!(value.is_string()),
            Some("object") => assert!(value.is_object()),
            None => {}
            other => panic!("unsupported test schema type {other:?}"),
        }
        if let Some(choices) = property.get("enum") {
            assert!(choices.as_array().unwrap().contains(value));
        }
    }
}
use super::*;
use std::collections::BTreeSet;
use subc_protocol::manifest::{ExecutionMode, ProviderRole};

/// The provenance reports exactly the launch-nonce source it was given,
/// on the wire as `fd` / `env`, and leaves the field out when there is none.
#[test]
fn provenance_reports_the_launch_nonce_source_it_is_given() {
    for (source, wire) in [
        (Some(LaunchNonceSource::Fd), Some("fd")),
        (Some(LaunchNonceSource::Env), Some("env")),
        (None, None),
    ] {
        let manifest = build_with_launch_nonce_source("plexus", source.clone());
        let provenance = manifest.provenance.as_ref().expect("provenance declared");
        assert_eq!(provenance.launch_nonce_source, source);
        provenance.validate().expect("provenance stays canonical");
        let encoded = serde_json::to_value(&manifest).expect("manifest serializes");
        assert_eq!(
            encoded["provenance"]["launch_nonce_source"].as_str(),
            wire,
            "{encoded}"
        );
    }
    assert_eq!(
        build("plexus")
            .provenance
            .expect("provenance declared")
            .launch_nonce_source,
        None
    );
}

/// The manifest claims no trust tier and declares no bindings.
///
/// Asserting ABSENCE rather than a value is the point. The daemon reads
/// neither field on any path, and this module previously sent a first-party
/// tier and a storage binding it never consumed — the storage descriptor
/// arrives from the daemon's central policy, not from anything a module says
/// about itself. A re-added field would be a claim no reader can check, so
/// the test that keeps it out has to fail on its PRESENCE.
///
/// Mutation-proved: restoring either `.trust_tier(Some(..))` or a
/// `.bindings(Some(..))` call reddens the matching assertion.
#[test]
fn the_manifest_claims_no_trust_tier_and_declares_no_bindings() {
    let manifest = build("plexus");
    assert!(
        manifest.trust_tier.is_none(),
        "a tier nothing reads must not be asserted: {:?}",
        manifest.trust_tier
    );
    assert!(
        manifest.bindings.is_none(),
        "a binding this module does not consume must not be declared"
    );
    let wire = serde_json::to_value(&manifest).expect("manifest serializes");
    assert!(
        wire.get("trust_tier").is_none() && wire.get("bindings").is_none(),
        "neither field may reach the wire: {wire}"
    );
}

#[test]
fn manifest_advertises_flow_scopes_v1() {
    let manifest = build("plexus");
    let wire = serde_json::to_value(&manifest).unwrap();
    assert!(wire["capabilities"]["provides"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "flow-scopes/v1"));
}

/// Without scope-on-behalf-of/v1 in the manifest's provided capabilities,
/// the daemon never stamps a worker scope's on_behalf_of_agent on a bind to
/// plexus, and every worker GitHub bot read would be refused for naming no
/// agent.
#[test]
fn manifest_advertises_scope_on_behalf_of_v1() {
    let wire = serde_json::to_value(build("plexus")).unwrap();
    assert!(wire["capabilities"]["provides"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "scope-on-behalf-of/v1"));
}

/// Cingulate calls a permissions/v1 provider only when the module catalog
/// shows both the capability and the two operations on its management
/// surface; a provider missing either is reported unsupported and never
/// called.
#[test]
fn manifest_advertises_permissions_v1() {
    let wire = serde_json::to_value(build("plexus")).unwrap();
    assert!(wire["capabilities"]["provides"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "permissions/v1"));
    let manifest = build("plexus");
    let operations: Vec<_> = manifest
        .provides
        .iter()
        .filter_map(|role| match role {
            ProviderRole::ManagementSurface { operations, .. } => Some(operations),
            _ => None,
        })
        .flatten()
        .map(|operation| (operation.name.as_str(), operation.kind.clone()))
        .collect();
    assert!(
        operations.contains(&(
            plexus_core::permissions::LIST_METHOD,
            ManagementOperationKind::Query
        )),
        "cingulate needs permissions.list declared as a query"
    );
    assert!(
        operations.contains(&(
            plexus_core::permissions::REVOKE_METHOD,
            ManagementOperationKind::Mutate
        )),
        "cingulate needs permissions.revoke declared"
    );
}

#[test]
fn manifest_advertises_tool_provider_v1() {
    let wire = serde_json::to_value(build("plexus")).unwrap();
    assert!(wire["capabilities"]["provides"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "tool-provider/v1"));
}

#[test]
fn manifest_events_match_published_names_and_notice_headers() {
    let manifest = build("plexus");
    let declared = manifest.events.as_ref().expect("events are declared");
    let declared_names = declared
        .iter()
        .map(|event| event.name.as_str())
        .collect::<BTreeSet<_>>();
    let published_names = plexus_core::event_key::PUBLISHED_EVENTS
        .iter()
        .map(|event| event.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(declared_names, published_names);

    let event_headers = plexus_core::EventHeaders {
        repo: "owner/repo".to_string(),
        project: Some("project-id".to_string()),
        pr: Some("12".to_string()),
        branch: Some("main".to_string()),
        conclusion: Some("success".to_string()),
    };
    for published in plexus_core::event_key::PUBLISHED_EVENTS {
        for version in published.versions().iter().copied().map(u32::from) {
            let declaration = declared
                .iter()
                .find(|event| event.name == published.name && event.version == version)
                .expect("published event is declared");
            assert_eq!(declaration.version, version, "{}", published.name);
            assert_eq!(
                declaration.headers.contains(&"event_key".to_owned()),
                version == 2
            );
            let declared_headers = declaration
                .headers
                .iter()
                .filter(|name| name.as_str() != "event_key")
                .cloned()
                .collect::<BTreeSet<_>>();
            let notice_headers = crate::bus::notice_headers(published.name, &event_headers)
                .expect("published event");
            let emitted_headers = notice_headers
                .keys()
                .filter(|name| name.as_str() != "kind")
                .cloned()
                .collect::<BTreeSet<_>>();
            assert_eq!(
                declared_headers, emitted_headers,
                "header labels for {} must match its notices",
                published.name
            );
        }
    }
}

#[test]
fn manifest_event_declarations_pass_subc_protocol_validation() {
    let wire = serde_json::to_value(build("plexus")).expect("manifest serializes");
    subc_protocol::manifest::validate_hello_event_declarations(&wire)
        .expect("subc-protocol accepts the declared events");
}

#[test]
fn manifest_events_pin_the_serialized_wire_json() {
    let events = build("plexus").events.expect("events are declared");
    assert_eq!(events.len(), 14);
    let v1: Vec<_> = events.iter().filter(|event| event.version == 1).collect();
    let v2: Vec<_> = events.iter().filter(|event| event.version == 2).collect();
    assert_eq!(v1.len(), 8);
    assert_eq!(v2.len(), 6);
    for (one, two) in v1.iter().zip(&v2) {
        let mut expected = serde_json::to_value(one).unwrap();
        expected["version"] = json!(2);
        expected["headers"]
            .as_array_mut()
            .unwrap()
            .push(json!("event_key"));
        assert_eq!(serde_json::to_value(two).unwrap(), expected);
    }
    assert_eq!(
        serde_json::to_string(&v1).expect("events serialize"),
        r#"[{"name":"github_issue_changed","version":1,"headers":["repo","project"],"summary":"An issue changed in a watched GitHub repository."},{"name":"github_pr_changed","version":1,"headers":["repo","project","pr"],"summary":"A pull request changed in a watched GitHub repository."},{"name":"github_release_published","version":1,"headers":["repo","project"],"summary":"A release was published in a watched GitHub repository."},{"name":"github_ci_job_failed","version":1,"headers":["repo","project","pr","branch","conclusion"],"summary":"A GitHub Actions job failed in a watched repository."},{"name":"github_ci_job_completed","version":1,"headers":["repo","project","pr","branch","conclusion"],"summary":"A GitHub Actions job completed in a watched repository."},{"name":"github_ci_run_completed","version":1,"headers":["repo","project","pr","branch","conclusion"],"summary":"A GitHub Actions workflow run completed in a watched repository."},{"name":"github_pr_review_submitted","version":1,"headers":["repo","project","pr"],"summary":"A review was submitted on a watched GitHub pull request."},{"name":"github_pr_review_comment_created","version":1,"headers":["repo","project","pr"],"summary":"A review comment was created on a watched GitHub pull request."}]"#
    );
}

#[test]
fn manifest_advertises_eleven_tools_including_read_facades_and_search() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            CONNECTIONS_TOOL,
            CATALOG_TOOL,
            INVOKE_TOOL,
            REQUESTS_TOOL,
            GITHUB_TOOL,
            GITHUB_READ_TOOL,
            GITHUB_REACT_TOOL,
            EVENTS_GET_TOOL,
            EVENTS_TOOL,
            WEB_SEARCH_TOOL,
            CODE_SEARCH_TOOL,
        ]
    );
    assert_eq!(tools[1].execution_mode, ExecutionMode::Pure);
    assert_eq!(tools[2].execution_mode, ExecutionMode::Unfenceable);
    assert_eq!(
        tools[4].schema["properties"]["op"]["enum"],
        json!(["bot_request", "bindings.read"]),
        "the github facade only advertises bot requests and binding reads"
    );
    assert_eq!(tools[9].execution_mode, ExecutionMode::Pure);
    assert_eq!(
        tools[9].schema["required"],
        json!(["query"]),
        "web_search takes flat arguments with only the query required"
    );
    let events_schema = &tools[8].schema;
    assert!(
        events_schema["properties"]["op"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("get")),
        "events schema must include get in op enum"
    );
    assert_eq!(
        events_schema["properties"]["event_key"]["type"], "string",
        "events schema must declare event_key string"
    );
    assert_eq!(
        events_schema["properties"]["event_name"]["type"], "string",
        "events schema must declare event_name string"
    );
    assert_eq!(
        events_schema["additionalProperties"], false,
        "events schema must enforce additionalProperties: false"
    );
}

/// Every `events` op the facade serves is in the advertised `op` enum.
/// The schema is closed (`additionalProperties: false`), so a schema-
/// validating caller, such as a model's tool call, cannot send an op or
/// field the enum and properties leave out, however well the handler
/// serves it. The served ops are read from the handler's own match arms,
/// so a new op added there without the schema fails here.
#[test]
fn every_served_events_op_and_its_fields_are_advertised() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    let schema = &tools
        .iter()
        .find(|tool| tool.name == EVENTS_TOOL)
        .expect("events is advertised")
        .schema;
    let advertised: Vec<&str> = schema["properties"]["op"]["enum"]
        .as_array()
        .expect("op enum")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let marker = "(manifest::EVENTS_TOOL, Some(\"";
    let served: Vec<&str> = include_str!("lib.rs")
        .split(marker)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert!(
        served.len() >= 10,
        "the handler scan found only {served:?}; the match-arm shape changed"
    );
    for op in &served {
        assert!(
            advertised.contains(op),
            "events op {op} is served but missing from the advertised enum {advertised:?}"
        );
    }
    // The schema must declare every field set_deliver_to reads: both
    // spellings of the subscription id, and deliver_to, whose null value
    // clears the target.
    for field in ["subscription_id", "subscription", "deliver_to"] {
        assert!(
            schema["properties"].get(field).is_some(),
            "set_deliver_to reads {field}, which the closed schema must declare"
        );
    }
    assert_eq!(
        schema["properties"]["deliver_to"]["type"],
        json!(["string", "null"]),
        "deliver_to takes an agent id, or null to clear"
    );
}

#[test]
fn events_get_manifest_is_pure_with_an_exact_closed_schema() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    let get = tools
        .iter()
        .find(|tool| tool.name == EVENTS_GET_TOOL)
        .expect("events_get is advertised");
    assert_eq!(
        get.execution_mode,
        ExecutionMode::Pure,
        "events_get must advertise the exact read-only execution mode"
    );
    assert_eq!(
        get.schema,
        json!({
            "type": "object",
            "properties": {
                "event_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "event_name": {"type": "string"},
                "version": {"type": "integer", "enum": [1, 2]}
            },
            "required": ["event_key", "event_name"],
            "additionalProperties": false
        })
    );
    assert_eq!(
        tools
            .iter()
            .find(|tool| tool.name == EVENTS_TOOL)
            .unwrap()
            .execution_mode,
        ExecutionMode::Mutating
    );
}

#[test]
fn code_search_schema_and_description_are_pinned() {
    let tool = code_search_tool();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/code_search/schema.json")).unwrap();
    let description: String = serde_json::from_str(include_str!(
        "../tests/fixtures/code_search/description.json"
    ))
    .unwrap();
    assert_eq!(tool.schema, schema);
    assert_eq!(tool.description, Some(description));
    assert_eq!(CODE_SEARCH_CAPABILITY, "plexus:code.search/v1");
}

#[test]
fn code_search_manifest_is_pure() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("tool provider required");
    };
    assert_eq!(
        tools
            .iter()
            .find(|t| t.name == CODE_SEARCH_TOOL)
            .unwrap()
            .execution_mode,
        ExecutionMode::Pure,
        "code_search must advertise the retry-safe Pure execution mode"
    );
}

#[test]
fn advertised_code_search_schema_matches_parser_acceptance() {
    use plexus_core::code_search::CodeSearchQuery;
    let schema = code_search_tool().schema;
    let properties = &schema["properties"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["query"]));
    assert_eq!(properties["query"]["type"], "string");
    assert_eq!(properties["query"]["minLength"], 1);
    assert_eq!(properties["query"]["maxLength"], 500);
    assert!(properties["query"].get("pattern").is_none());
    for length in 1..=500 {
        for query in ["x".repeat(length), "é".repeat(length)] {
            let args = json!({"query":query});
            let parsed = CodeSearchQuery::parse(args.as_object().unwrap()).unwrap();
            assert_eq!(parsed.vendor_args()["query"], args["query"]);
        }
    }
    for field in [
        "regex",
        "match_case",
        "whole_words",
        "repo",
        "path",
        "language",
    ] {
        let kind = match field {
            "repo" | "path" => "string",
            "language" => "array",
            _ => "boolean",
        };
        assert_eq!(properties[field]["type"], json!([kind, "null"]));
        let mut args = json!({"query":"x"});
        args[field] = serde_json::Value::Null;
        let null = CodeSearchQuery::parse(args.as_object().unwrap())
            .unwrap()
            .vendor_args();
        let absent = CodeSearchQuery::parse(json!({"query":"x"}).as_object().unwrap())
            .unwrap()
            .vendor_args();
        assert_eq!(null, absent, "{field}: null is absent");
    }
    for field in ["repo", "path", "language"] {
        let limit = if field == "language" {
            &properties[field]["items"]["maxLength"]
        } else {
            &properties[field]["maxLength"]
        };
        assert_eq!(*limit, 500);
        let mut args = json!({"query":"x"});
        args[field] = if field == "language" {
            json!(["é".repeat(500)])
        } else {
            json!("é".repeat(500))
        };
        assert!(CodeSearchQuery::parse(args.as_object().unwrap()).is_ok());
        args[field] = if field == "language" {
            json!(["é".repeat(501)])
        } else {
            json!("é".repeat(501))
        };
        let refusal = CodeSearchQuery::parse(args.as_object().unwrap())
            .err()
            .unwrap()
            .to_wire();
        assert_eq!(refusal["error"]["field"], field);
    }
    assert_eq!(properties["language"]["maxItems"], 10);
    assert_eq!(properties["language"]["items"]["type"], "string");
    for args in [
        json!({"query":"x","language":[null]}),
        json!({"query":"x","language":vec!["Rust";11]}),
    ] {
        let refusal = CodeSearchQuery::parse(args.as_object().unwrap())
            .err()
            .unwrap()
            .to_wire();
        assert_eq!(refusal["error"]["field"], "language");
    }
    let trimmed =
        CodeSearchQuery::parse(json!({"query":"  needle\t"}).as_object().unwrap()).unwrap();
    assert_eq!(trimmed.vendor_args()["query"], "needle");
    let blank = CodeSearchQuery::parse(json!({"query":" \t\n"}).as_object().unwrap())
        .err()
        .unwrap()
        .to_wire();
    assert_eq!(blank["error"]["code"], "invalid_query");
    assert_eq!(blank["error"]["field"], "query");
}

fn advertised_web_search() -> Tool {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    tools
        .iter()
        .find(|tool| tool.name == WEB_SEARCH_TOOL)
        .expect("web_search is advertised")
        .clone()
}

#[test]
fn web_search_description_matches_core_fixture() {
    let expected: String = serde_json::from_str(include_str!(
        "../tests/fixtures/core-web-search/description.json"
    ))
    .unwrap();
    assert_eq!(
        advertised_web_search().description,
        Some(expected),
        "web_search description must match the pinned core contract"
    );
}

#[test]
fn web_search_schema_matches_core_fixture_without_agent_assertion() {
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/core-web-search/schema.json"
    ))
    .unwrap();
    let schema = advertised_web_search().schema;
    assert_eq!(
        schema, expected,
        "web_search schema must match the pinned core contract without agent_assertion"
    );
    assert!(schema["properties"].get("agent_assertion").is_none());
}

#[test]
fn all_tool_schemas_exclude_retired_identity_tokens() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("tool-provider role required");
    };
    for tool in tools {
        for field in ["assertion", "agent_assertion"] {
            assert!(
                tool.schema["properties"].get(field).is_none(),
                "{} must not advertise {field}",
                tool.name
            );
        }
        assert_eq!(
            tool.schema["additionalProperties"], false,
            "{} keeps a closed argument schema",
            tool.name
        );
    }
}

#[test]
fn web_search_manifest_is_pure() {
    assert_eq!(
        advertised_web_search().execution_mode,
        ExecutionMode::Pure,
        "web_search must advertise the retry-safe Pure execution mode"
    );
}

#[test]
fn web_search_definition_jcs_digest_matches_core_contract() {
    let tool = advertised_web_search();
    let definition = json!({
        "name": tool.name,
        "description": tool.description,
        "schema": tool.schema
    });
    use sha2::{Digest, Sha256};
    let bytes = plexus_core::jcs::canonicalize(&definition).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    println!("web_search definition RFC 8785 SHA-256: {digest}");
    assert_eq!(
        digest, "d67303ec0087bf41c3abd834f02c9b22ea3d9143e936de4b6e156c7a57e25a58",
        "web_search model-facing definition digest must remain byte-identical"
    );
}

#[test]
fn github_read_manifest_is_pure_with_a_closed_action_schema() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    let read = tools
        .iter()
        .find(|tool| tool.name == "github_read")
        .unwrap();
    let wire = serde_json::to_value(read).unwrap();
    assert_eq!(
        wire["execution_mode"], "pure",
        "github_read must advertise the exact read-only execution mode"
    );
    assert_eq!(read.execution_mode, ExecutionMode::Pure);
    assert_eq!(
        read.schema,
        json!({
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": [
                    "github.issue.get", "github.issue_comments.list", "github.issue.search", "github.pr.review_threads", "github.actions.job_log", "github.actions.artifact_file", "github.actions.run.superseded",
                    "github.repo.get", "github.search.code", "github.search.issues"
                ]},
                "repository": {"oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]},
                "args": {"type": "object", "properties": {
                "pr": {"type": "integer", "minimum": 1, "maximum": 2147483647},
                    "job_id": {"type": "integer", "minimum": 1},
                    "run_id": {"type": "integer", "minimum": 1},
                    "artifact": {"type": "string", "minLength": 1},
                    "path": {"type": "string"},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 262144, "default": 65536},
                    "query": {"type": "object", "additionalProperties": {"type": "string"}},
                    "accept": {"type": "string", "enum": [
                        "application/vnd.github+json", "application/vnd.github.raw+json",
                        "application/vnd.github.diff", "application/vnd.github.patch"
                    ]},
                    "q": {"type": "string"},
                    "page": {"type": "integer", "minimum": 1},
                    "per_page": {"type": "integer", "minimum": 1, "maximum": 100},
                    "offset": {"type": "integer", "minimum": 0},
                    "length": {"type": "integer", "minimum": 1, "maximum": 1048576}
                }}
            },
            "required": ["action", "repository", "args"],
            "additionalProperties": false
        })
    );
}

/// github_react posts on GitHub, so it must never be advertised as Pure: a
/// Pure tool may be retried freely, and only the request_nonce receipt
/// makes a repeated reaction safe. Its schema is closed at every level.
#[test]
fn github_react_manifest_is_mutating_with_a_closed_schema() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    let react = tools
        .iter()
        .find(|tool| tool.name == "github_react")
        .unwrap();
    let wire = serde_json::to_value(react).unwrap();
    assert_eq!(
        wire["execution_mode"], "mutating",
        "github_react must advertise the Mutating execution mode"
    );
    assert_eq!(react.execution_mode, ExecutionMode::Mutating);
    assert!(react
        .description
        .as_deref()
        .is_some_and(|text| text.contains("own bot")));
    assert_eq!(
        react.schema,
        json!({
            "type": "object",
            "properties": {
                "repository": {"type": "string", "minLength": 1, "description": "owner/name"},
                "kind": {"type": "string", "enum": ["issue", "pr"]},
                "target": {
                    "type": "object",
                    "properties": {"number": {"type": "integer", "minimum": 1}},
                    "required": ["number"],
                    "additionalProperties": false
                },
                "reaction": {"type": "string", "enum": [
                    "+1", "-1", "laugh", "confused", "heart", "hooray", "rocket", "eyes"
                ]},
                "request_nonce": {"type": "string", "minLength": 1}
            },
            "required": ["repository", "kind", "target", "reaction", "request_nonce"],
            "additionalProperties": false
        })
    );
}

/// The privileged ceremony must never appear on the tool surface: anything
/// advertised there is reachable by an agent through the MCP gateway. This
/// fails if a future change moves or copies an admin op into the facade.
#[test]
fn privileged_ops_are_absent_from_the_tool_surface() {
    let manifest = build("plexus");
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("plexus must expose a ToolProvider role");
    };
    for tool in tools {
        assert!(
            !tool.name.contains("admin"),
            "privileged op leaked onto the tool surface: {}",
            tool.name
        );
        let rendered = tool.schema.to_string();
        for privileged in [
            "issue_ticket",
            "grant",
            "revoke_grant",
            "set_policy",
            "list_policies",
            "remove_policy",
            "review_action",
            "repin_action",
            "delete_connection",
            "set_web_search_limit",
            "set_web_search_order",
            "set_web_search_allowance",
            "handle.import",
            "handle.probe",
            "handle.grant",
            "handle.bind",
        ] {
            assert!(
                !rendered.contains(privileged),
                "tool {} advertises privileged operation {privileged}",
                tool.name
            );
        }
    }
}

#[test]
fn manifest_exposes_the_privileged_ops_on_a_management_surface() {
    let manifest = build("plexus");
    let ProviderRole::ManagementSurface { operations, .. } = &manifest.provides[1] else {
        panic!("plexus must expose a ManagementSurface role");
    };
    assert_eq!(
        operations
            .iter()
            .map(|operation| operation.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            crate::grants_would_ask::METHOD,
            plexus_core::permissions::LIST_METHOD,
            plexus_core::permissions::REVOKE_METHOD,
            ADMIN_RECIPIENTS_ADD_OP,
            ADMIN_RECIPIENTS_REMOVE_OP,
            ADMIN_RECIPIENTS_LIST_OP,
            GITHUB_IMPORT_OP,
            GITHUB_PROBE_OP,
            GITHUB_GRANT_OP,
            GITHUB_BIND_OP,
            GITHUB_UNBIND_OP,
            ADMIN_ISSUE_TICKET_OP,
            ADMIN_GRANT_OP,
            ADMIN_WIDEN_CEILING_OP,
            ADMIN_REVOKE_GRANT_OP,
            ADMIN_LIST_GRANTS_OP,
            ADMIN_SET_POLICY_OP,
            ADMIN_LIST_POLICIES_OP,
            ADMIN_REMOVE_POLICY_OP,
            ADMIN_REVIEW_ACTION_OP,
            ADMIN_REPIN_ACTION_OP,
            ADMIN_DELETE_CONNECTION_OP,
            ADMIN_REBIND_CREDENTIAL_OP,
            ADMIN_SET_WEB_SEARCH_LIMIT_OP,
            ADMIN_SET_WEB_SEARCH_ORDER_OP,
            ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP,
            ADMIN_ADD_WEB_SEARCH_PROVIDER_OP,
            crate::connector_home::STATUS_OP,
            crate::relay::STATUS_OP,
        ]
    );
}
