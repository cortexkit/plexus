use super::*;
use serde_json::json;

use crate::test_logging as diagnostic_logging;

#[test]
fn catalog_matches_every_advertised_definition() {
    let manifest = manifest::build("plexus");
    let advertised: Vec<_> = manifest
        .provides
        .iter()
        .flat_map(|role| match role {
            ProviderRole::ToolProvider { tools, .. } => tools.iter().collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect();
    let tools = catalog_tools(&advertised_tools());
    assert_eq!(tools.len(), 12);
    assert_eq!(tools.len(), advertised.len());
    for (tool, definition) in tools.iter().zip(advertised) {
        assert_eq!(tool.name, definition.name);
        assert_eq!(tool.description, definition.description);
        assert_eq!(tool.input_schema, definition.schema);
        assert_eq!(
            tool.schema_digest,
            schema_digest(&definition.schema).unwrap()
        );
        cortexkit_role_tool_provider::catalog::check_flat_schema(&tool.input_schema).unwrap();
    }
    assert!(tools.iter().all(|tool| !tool.name.contains('.')));
}

#[test]
fn catalog_schemas_portable() {
    use std::collections::BTreeSet;

    // No single preset serves every tool. Lint the complete definitions before
    // preset selection so tools omitted from the presets are checked too.
    let definitions = advertised_tools();
    let tools = catalog_tools(&definitions);
    let declared: BTreeSet<_> = definitions.iter().map(|tool| tool.name.as_str()).collect();
    let linted: BTreeSet<_> = tools.iter().map(|tool| tool.name.as_str()).collect();
    assert!(
        !declared.is_empty(),
        "the declared tool list must not be empty"
    );
    assert_eq!(
        linted, declared,
        "lint every declared tool, not a filtered subset"
    );
    assert_eq!(tools.len(), linted.len(), "tool names must be unique");

    let findings: Vec<_> = tools
        .iter()
        .flat_map(|tool| {
            cortexkit_role_tool_provider::lint_input_schema(&tool.input_schema)
                .into_iter()
                .map(move |lint| format!("{} input_schema {lint}", tool.name))
        })
        .collect();
    assert!(findings.is_empty(), "{}", findings.join("; "));
}

#[test]
fn only_search_tools_opt_into_tool_result_v1() {
    for tool in catalog_tools(&advertised_tools()) {
        let expected = if matches!(tool.name.as_str(), "web_search" | "code_search") {
            Some(cortexkit_role_tool_provider::result::ResultFormat::ToolResultV1)
        } else {
            None
        };
        assert_eq!(
            tool.result_format, expected,
            "result format for {}",
            tool.name
        );
        // Pin the wire name too: model-facing clients render content parts
        // only when a tool's catalog entry says exactly `tool-result/v1`, and
        // show any other value, including the retired `content/v1`, as plain
        // JSON.
        if expected.is_some() {
            assert_eq!(
                serde_json::to_value(&tool.result_format).unwrap(),
                "tool-result/v1",
                "search tools must declare tool-result/v1: {}",
                tool.name
            );
        }
        assert_eq!(tool.semantics, if expected.is_some() { 2 } else { 1 });
    }
}

#[test]
fn catalog_modes_match_every_tool_contract() {
    for tool in &catalog_tools(&advertised_tools()) {
        check_modes(tool).unwrap();
        assert_eq!(
            serves_call_mode(tool, &CallMode::Classic),
            tool.name != manifest::GITHUB_WATCH_TOOL
        );
        assert_eq!(
            serves_call_mode(tool, &CallMode::Codemode),
            matches!(
                tool.name.as_str(),
                "web_search" | "code_search" | "github_read" | "events_get" | "catalog"
            ),
            "catalog codemode promise must match the tool contract: {}",
            tool.name
        );
        assert_eq!(
            serves_call_mode(tool, &CallMode::Flow),
            !matches!(tool.name.as_str(), "connections" | "requests" | "events")
        );
        assert!(!serves_call_mode(tool, &CallMode::Unknown("future".into())));
    }
}

/// The served catalog marks github_react, and no other tool, with
/// `emits_events: false`, and the served digest covers that member.
#[test]
fn catalog_emits_events_is_false_on_github_react_only() {
    let all_tools = wire_tools(&catalog_tools(&advertised_tools()));
    let tools = all_tools.as_array().unwrap();
    assert_eq!(tools.len(), 12);
    for tool in tools {
        if tool["name"] == "github_react" {
            assert_eq!(
                tool.get("emits_events"),
                Some(&json!(false)),
                "github_react must promise emits_events: false"
            );
        } else {
            assert_eq!(
                tool.get("emits_events"),
                None,
                "only github_react carries emits_events: {}",
                tool["name"]
            );
        }
    }
    let wire = reply(
        ops::TOOL_CATALOG,
        json!({"preset": "flow"}).as_object().unwrap(),
    )
    .unwrap();
    assert_eq!(wire["tools"][4]["emits_events"], false);
    let mut content = wire.clone();
    content.as_object_mut().unwrap().remove("catalog_digest");
    assert_eq!(
        wire["catalog_digest"],
        plexus_core::jcs_sha256(&content).unwrap(),
        "the catalog digest must cover the served emits_events member"
    );
}

#[test]
fn catalog_capability_table_matches_every_advertised_tool() {
    let expected: &[(&str, &[&str])] = &[
        ("connections", &["plexus:connections/v1"]),
        ("catalog", &["plexus:catalog.read/v1"]),
        ("invoke", &["plexus:connector.invoke/v1"]),
        ("requests", &["plexus:approval.requests/v1"]),
        ("github", &["plexus:github.facade/v1"]),
        ("github_read", &["github.read/v1", "plexus:github.read/v1"]),
        ("github_react", &["plexus:github.react/v1"]),
        ("github_watch", &["plexus:github.watch/v1"]),
        ("events_get", &["plexus:events.get/v1"]),
        ("events", &["plexus:events/v1"]),
        ("web_search", &["plexus:web.search/v1", "web.search/v1"]),
        (
            "code_search",
            &["code.search.public/v1", "plexus:code.search/v1"],
        ),
    ];
    assert_eq!(
        TOOL_CAPABILITIES, expected,
        "capability table must name truthful tags"
    );
    let tools = catalog_tools(&advertised_tools());
    assert_eq!(tools.len(), expected.len());
    for tool in &tools {
        let (_, tags) = expected
            .iter()
            .find(|(name, _)| *name == tool.name)
            .unwrap();
        assert_eq!(
            tool.capabilities, *tags,
            "wrong capability tags for {}",
            tool.name
        );
        assert!(tool.capabilities.windows(2).all(|pair| pair[0] < pair[1]));
        for tag in &tool.capabilities {
            assert!(tag.is_ascii());
            cortexkit_role_tool_provider::check_capability_tag(tag).unwrap();
        }
    }
    for (name, _) in TOOL_CAPABILITIES {
        assert_eq!(
            tools.iter().filter(|tool| tool.name == *name).count(),
            1,
            "capability table must name each advertised tool exactly once"
        );
    }
}

fn fetch(
    params: Value,
    composition: Option<Value>,
    preset: Option<&str>,
) -> Result<CatalogAnswer, ErrorBody> {
    let mut arguments = json!({"params": params});
    if let Some(composition) = composition {
        arguments["composition"] = composition;
    }
    if let Some(preset) = preset {
        arguments["preset"] = json!(preset);
    }
    reply(ops::TOOL_CATALOG, arguments.as_object().unwrap())
        .map(|wire| serde_json::from_value(wire).unwrap())
}

fn names(answer: &CatalogAnswer) -> Vec<&str> {
    answer.tools.iter().map(|tool| tool.name.as_str()).collect()
}

#[tokio::test]
async fn tool_catalog_route_ignores_capabilities_without_a_preset() {
    use subc_protocol::{FrameType, Principal};

    for capabilities in [
        json!(["code.search.public/v1", "web.search/v1"]),
        json!(["plexus:unserved/v1"]),
        json!(["web.search/v1", "code.search.public/v1"]),
        json!(["web.search/v1", "web.search/v1"]),
        json!([4]),
        json!("web.search/v1"),
        json!(null),
        json!([]),
    ] {
        let frame = send_metadata(
            Principal::Reserved {
                module_id: "prefrontal".to_owned(),
            },
            ops::TOOL_CATALOG,
            json!({"params": {"capabilities": capabilities}}),
        )
        .await;
        assert_eq!(frame.header.ty, FrameType::Response, "{capabilities}");
        let answer: CatalogAnswer = serde_json::from_slice(&frame.body).unwrap();
        assert!(answer.tools.is_empty(), "{capabilities}");
        assert_eq!(answer.presets, ["head", "worker", "reader", "flow"]);
    }
}

#[tokio::test]
async fn tool_catalog_route_uses_preset_despite_capabilities() {
    use subc_protocol::{FrameType, Principal};

    let expected = send_metadata(
        Principal::Direct,
        ops::TOOL_CATALOG,
        json!({"preset": "reader"}),
    )
    .await;
    assert_eq!(expected.header.ty, FrameType::Response);
    let answer: CatalogAnswer = serde_json::from_slice(&expected.body).unwrap();
    assert_eq!(names(&answer), ["code_search"]);

    for capabilities in [json!(["web.search/v1"]), json!([]), json!(false)] {
        let frame = send_metadata(
            Principal::Direct,
            ops::TOOL_CATALOG,
            json!({"preset": "reader", "params": {"capabilities": capabilities}}),
        )
        .await;
        assert_eq!(frame.header.ty, FrameType::Response, "{capabilities}");
        assert_eq!(frame.body, expected.body, "{capabilities}");
    }
}

#[tokio::test]
async fn role_describe_route_retains_tool_tags_without_advertising_filter() {
    use subc_protocol::{FrameType, Principal};

    let frame = send_metadata(Principal::Direct, ops::ROLE_DESCRIBE, json!({})).await;
    assert_eq!(frame.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(body["tool_capabilities"], json!(tool_capability_union()));
    assert_eq!(body["capabilities"], json!(["plexus:github.read.bulk/v1"]));
    cortexkit_role_tool_provider::describe::check_describe(&body).unwrap();
}

#[test]
fn catalog_plan_without_a_preset_answers_no_tools() {
    let answer = fetch(json!({}), Some(json!({"providers": "opaque"})), None).unwrap();
    assert!(answer.tools.is_empty());
    assert_eq!(answer.presets, ["head", "worker", "reader", "flow"]);
    cortexkit_role_tool_provider::catalog::check_presets(&answer, None).unwrap();
}

#[test]
fn catalog_search_presets_return_only_search_tools() {
    for preset in ["head", "worker"] {
        let answer = fetch(json!({}), None, Some(preset)).unwrap();
        assert_eq!(
            names(&answer),
            [WEB_SEARCH_TOOL, CODE_SEARCH_TOOL],
            "{preset}"
        );
        cortexkit_role_tool_provider::catalog::check_presets(&answer, Some(preset)).unwrap();
    }
    // Read-only lanes get code search alone.
    let answer = fetch(json!({}), None, Some("reader")).unwrap();
    assert_eq!(names(&answer), [CODE_SEARCH_TOOL]);
    cortexkit_role_tool_provider::catalog::check_presets(&answer, Some("reader")).unwrap();
}

#[tokio::test]
async fn catalog_flow_preset_returns_flow_tools_with_unchanged_metadata() {
    let frame = send_request(
        subc_protocol::Principal::Direct,
        json!({"name": ops::TOOL_CATALOG, "preset": "flow", "arguments": {"preset": "flow"}}),
    )
    .await;
    assert_eq!(frame.header.ty, subc_protocol::FrameType::Response);
    let wire: Value = serde_json::from_slice(&frame.body).unwrap();
    let answer: CatalogAnswer = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        names(&answer),
        [
            "catalog",
            "invoke",
            "github",
            "github_read",
            "github_react",
            "github_watch",
            "events_get",
            WEB_SEARCH_TOOL,
            CODE_SEARCH_TOOL,
        ]
    );
    cortexkit_role_tool_provider::catalog::check_presets(&answer, Some("flow")).unwrap();
    let full = wire_tools(&catalog_tools(&advertised_tools()));
    let flow_tools: Vec<_> = full
        .as_array()
        .unwrap()
        .iter()
        .filter(|tool| {
            tool["modes"]
                .as_array()
                .is_some_and(|modes| modes.iter().any(|mode| mode == "flow"))
        })
        .collect();
    assert_eq!(wire["tools"], json!(flow_tools));
    assert_eq!(wire["tools"][4]["emits_events"], false);
}

#[test]
fn catalog_refuses_unknown_preset_with_or_without_capabilities() {
    for params in [json!({}), json!({"capabilities": ["web.search/v1"]})] {
        let error = fetch(params, None, Some("unknown")).unwrap_err();
        assert_eq!(
            error.code,
            cortexkit_role_tool_provider::errors::INVALID_REQUEST
        );
        assert_eq!(error.detail.unwrap()["field"], "preset");
    }
}

#[tokio::test]
async fn catalog_preset_wire_vectors_match_reply() {
    use std::fmt::Write as _;

    let vectors: &[(&str, Option<&str>, &[u8])] = &[
        (
            "flow.reply.json",
            Some("flow"),
            include_bytes!("../tests/fixtures/tool-catalog-presets/flow.reply.json"),
        ),
        (
            "head.reply.json",
            Some("head"),
            include_bytes!("../tests/fixtures/tool-catalog-presets/head.reply.json"),
        ),
        (
            "no-preset.reply.json",
            None,
            include_bytes!("../tests/fixtures/tool-catalog-presets/no-preset.reply.json"),
        ),
        (
            "reader.reply.json",
            Some("reader"),
            include_bytes!("../tests/fixtures/tool-catalog-presets/reader.reply.json"),
        ),
        (
            "worker.reply.json",
            Some("worker"),
            include_bytes!("../tests/fixtures/tool-catalog-presets/worker.reply.json"),
        ),
    ];
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tool-catalog-presets");
    let regenerate =
        std::env::var("PLEXUS_REGENERATE_CATALOG_PRESET_FIXTURES").as_deref() == Ok("1");
    let mut sums = String::new();
    for &(filename, preset, expected) in vectors {
        let arguments = preset.map_or_else(|| json!({}), |preset| json!({"preset": preset}));
        let frame = send_metadata(
            subc_protocol::Principal::Direct,
            ops::TOOL_CATALOG,
            arguments,
        )
        .await;
        assert_eq!(
            frame.header.ty,
            subc_protocol::FrameType::Response,
            "{filename}"
        );
        let actual = &frame.body[..];
        assert!(
            actual.len() < 65_536,
            "{filename} exceeds the catalog size limit"
        );
        writeln!(sums, "{}  {filename}", plexus_core::jcs::sha256_hex(actual)).unwrap();
        if regenerate {
            std::fs::write(directory.join(filename), actual).unwrap();
        } else {
            assert!(
                actual == expected,
                "committed reply bytes for {filename} must equal the response body"
            );
        }
    }
    if regenerate {
        std::fs::write(directory.join("SHA256SUMS"), sums).unwrap();
    } else {
        assert_eq!(
            sums,
            include_str!("../tests/fixtures/tool-catalog-presets/SHA256SUMS")
        );
    }
}

#[test]
fn catalog_preflight_matches_plan_selection() {
    for params in [
        json!({}),
        json!({"capabilities": []}),
        json!({"capabilities": ["plexus:github.read/v1"]}),
        json!({"capabilities": ["code.search.public/v1", "web.search/v1"]}),
    ] {
        let preflight = fetch(params.clone(), None, Some("head")).unwrap();
        let plan = fetch(params, Some(json!({"providers": []})), Some("head")).unwrap();
        assert_eq!(
            preflight.tools, plan.tools,
            "preflight and plan fetch must select identical tools"
        );
    }
}

#[test]
fn catalog_core_wire_vectors_match_reply() {
    type Vector<'a> = (&'a str, &'a [u8], &'a [u8], &'a [&'a str]);
    let vectors: &[Vector<'_>] = &[
        (
            "preflight-reader-search",
            include_bytes!("../tests/fixtures/tool-catalog/preflight-reader-search.request.json"),
            include_bytes!("../tests/fixtures/tool-catalog/preflight-reader-search.reply.json"),
            &[CODE_SEARCH_TOOL],
        ),
        (
            "preflight-worker-search",
            include_bytes!("../tests/fixtures/tool-catalog/preflight-worker-search.request.json"),
            include_bytes!("../tests/fixtures/tool-catalog/preflight-worker-search.reply.json"),
            &[WEB_SEARCH_TOOL, CODE_SEARCH_TOOL],
        ),
        (
            "plan-reader-search",
            include_bytes!("../tests/fixtures/tool-catalog/plan-reader-search.request.json"),
            include_bytes!("../tests/fixtures/tool-catalog/plan-reader-search.reply.json"),
            &[CODE_SEARCH_TOOL],
        ),
        (
            "preflight-github",
            include_bytes!("../tests/fixtures/tool-catalog/preflight-github.request.json"),
            include_bytes!("../tests/fixtures/tool-catalog/preflight-github.reply.json"),
            &[CODE_SEARCH_TOOL],
        ),
        (
            "preflight-unknown-capability",
            include_bytes!(
                "../tests/fixtures/tool-catalog/preflight-unknown-capability.request.json"
            ),
            include_bytes!(
                "../tests/fixtures/tool-catalog/preflight-unknown-capability.reply.json"
            ),
            &[CODE_SEARCH_TOOL],
        ),
        (
            "preflight-github-read",
            include_bytes!("../tests/fixtures/tool-catalog/preflight-github-read.request.json"),
            include_bytes!("../tests/fixtures/tool-catalog/preflight-github-read.reply.json"),
            &[CODE_SEARCH_TOOL],
        ),
    ];

    for (name, request_bytes, reply_bytes, expected_tools) in vectors {
        let request: Value = serde_json::from_slice(request_bytes).unwrap();
        let actual = reply(ops::TOOL_CATALOG, request.as_object().unwrap()).unwrap();
        let decoded: CatalogAnswer = serde_json::from_value(actual.clone()).unwrap();
        assert_eq!(names(&decoded), *expected_tools, "{name}");
        assert!(decoded.presets.is_empty(), "{name}");
        let actual_bytes = serde_json::to_vec(&actual).unwrap();
        if std::env::var("PLEXUS_REGENERATE_CATALOG_FIXTURES").as_deref() == Ok("1") {
            if actual_bytes.as_slice() != *reply_bytes {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/tool-catalog")
                    .join(format!("{name}.reply.json"));
                std::fs::write(&path, &actual_bytes).unwrap();
                println!("updated {}", path.display());
            }
            continue;
        }
        assert_eq!(
            actual_bytes.as_slice(),
            *reply_bytes,
            "committed reply bytes for {name} must equal reply()"
        );
    }
}

#[test]
fn catalog_composition_is_opaque_and_does_not_select_definitions() {
    let params = json!({"capabilities": ["plexus:code.search/v1", "plexus:web.search/v1"]});
    let definitions = fetch(params.clone(), Some(json!({})), Some("head")).unwrap();
    assert_eq!(names(&definitions), [WEB_SEARCH_TOOL, CODE_SEARCH_TOOL]);
    for composition in [
        json!({"providers": [{"provider": "plexus", "tools": [{"name": "unknown", "capabilities": ["wrong"]}]}]}),
        json!({"providers": [{"provider": "plexus", "tools": []}]}),
        json!({"providers": [{"provider": "another-id", "tools": [{"name": "github"}]}]}),
        json!({"providers": "not an array", "scope": "irrelevant", "agent": "irrelevant"}),
    ] {
        let answer = fetch(params.clone(), Some(composition.clone()), Some("head")).unwrap();
        assert_eq!(answer.tools, definitions.tools);
        assert_eq!(answer.generation, definitions.generation);
        assert_eq!(
            answer.composition_digest.unwrap(),
            cortexkit_role_tool_provider::catalog::composition_digest(&composition).unwrap()
        );
    }
}

#[test]
fn catalog_broca_head_fixture_uses_preset_and_hashes_opaque_composition() {
    let plan: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/fetch-plan-v1/broca-head-plexus-direct.json"
    ))
    .unwrap();
    assert_eq!(
        cortexkit_role_tool_provider::catalog::composition_digest(&plan).unwrap(),
        include_str!("../tests/fixtures/fetch-plan-v1/broca-head-plexus-direct.sha256")
    );
    let item = plan["tool_items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["provider"] == "plexus")
        .unwrap();
    let composition = plan["composition"].clone();
    // The fixture's Plexus tool item has empty params, so the head preset offers
    // only search, regardless of the tools listed in the opaque composition.
    let original = fetch(
        item["params"].clone(),
        Some(composition.clone()),
        item["preset"].as_str(),
    )
    .unwrap();
    assert_eq!(names(&original), [WEB_SEARCH_TOOL, CODE_SEARCH_TOOL]);
    let answer = fetch(
        json!({"capabilities": ["plexus:github.facade/v1", "plexus:web.search/v1"]}),
        Some(composition),
        item["preset"].as_str(),
    )
    .unwrap();
    assert_eq!(answer, original);
    assert_eq!(
        answer.composition_digest.unwrap(),
        plan["composition_digest"]
    );
}

#[test]
fn catalog_generation_is_full_set_and_digest_covers_preset_answer() {
    let discovery = fetch(json!({}), None, None).unwrap();
    let preset = fetch(json!({}), None, Some("reader")).unwrap();
    assert_eq!(names(&preset), ["code_search"]);
    assert_eq!(preset.generation, discovery.generation);
    assert_ne!(preset.catalog_digest, discovery.catalog_digest);
    let mut content = serde_json::to_value(&preset).unwrap();
    content.as_object_mut().unwrap().remove("catalog_digest");
    assert_eq!(
        preset.catalog_digest,
        plexus_core::jcs_sha256(&content).unwrap()
    );
    content["tools"] = serde_json::to_value(&discovery.tools).unwrap();
    assert_ne!(
        preset.catalog_digest,
        plexus_core::jcs_sha256(&content).unwrap()
    );
}

#[test]
fn catalog_generation_is_stable_and_tracks_descriptions() {
    let request = serde_json::from_value(json!({"preset": "reader"})).unwrap();
    let definitions = advertised_tools();
    let first = catalog(&request, &definitions).unwrap();
    let second = catalog(&request, &advertised_tools()).unwrap();
    assert_eq!(first, second);
    let mut changed = definitions.clone();
    let unselected = changed
        .iter_mut()
        .find(|tool| tool.name == "connections")
        .unwrap();
    unselected.description = Some("Changed unselected facade description".to_owned());
    let changed = catalog(&request, &changed).unwrap();
    assert_ne!(
        first.generation, changed.generation,
        "generation must cover descriptions outside the selected preset"
    );
    assert_ne!(first.catalog_digest, changed.catalog_digest);
    assert_eq!(first.tools[0].schema_digest, changed.tools[0].schema_digest);
    let mut changed = definitions;
    let selected = changed
        .iter_mut()
        .find(|tool| tool.name == CODE_SEARCH_TOOL)
        .unwrap();
    selected.schema["description"] = json!("Changed schema description");
    let changed = catalog(&request, &changed).unwrap();
    assert_ne!(first.generation, changed.generation);
    assert_ne!(first.catalog_digest, changed.catalog_digest);
    assert_eq!(first.tools[0].schema_digest, changed.tools[0].schema_digest);
}

#[test]
fn catalog_digest_only_matches_full_answer_and_hashes_composition() {
    let composition = json!({"secret": "opaque composition data", "nested": [1, 2]});
    let full = reply(
        ops::TOOL_CATALOG,
        json!({"composition": composition, "preset": "reader"})
            .as_object()
            .unwrap(),
    )
    .unwrap();
    let digest = reply(
            ops::TOOL_CATALOG,
            json!({"composition": composition, "preset": "reader", "params": {"capabilities": ["plexus:web.search/v1"]}, "digest_only": true})
                .as_object()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(full["tools"].as_array().unwrap().len(), 1);
    assert_eq!(full["tools"][0]["name"], CODE_SEARCH_TOOL);
    assert_eq!(digest.as_object().unwrap().len(), 2);
    assert_eq!(digest["generation"], full["generation"]);
    assert_eq!(digest["catalog_digest"], full["catalog_digest"]);
    assert_eq!(
        full["composition_digest"],
        cortexkit_role_tool_provider::catalog::composition_digest(&composition).unwrap()
    );
    let other = reply(
        ops::TOOL_CATALOG,
        json!({"composition": {"nested": [2, 1]}, "preset": "reader"})
            .as_object()
            .unwrap(),
    )
    .unwrap();
    assert_ne!(other["catalog_digest"], full["catalog_digest"]);
    assert_eq!(other["generation"], full["generation"]);
}

#[test]
fn catalog_digest_only_matches_full_preset_or_discovery_answer() {
    for preset in [
        None,
        Some("head"),
        Some("worker"),
        Some("reader"),
        Some("flow"),
    ] {
        let mut arguments = preset.map_or_else(|| json!({}), |preset| json!({"preset": preset}));
        let mut full = reply(ops::TOOL_CATALOG, arguments.as_object().unwrap()).unwrap();
        let catalog_digest = full
            .as_object_mut()
            .unwrap()
            .remove("catalog_digest")
            .unwrap();
        assert_eq!(
            catalog_digest,
            plexus_core::jcs_sha256(&full).unwrap(),
            "{preset:?}"
        );

        arguments["digest_only"] = json!(true);
        let digest = reply(ops::TOOL_CATALOG, arguments.as_object().unwrap()).unwrap();
        assert_eq!(
            digest,
            json!({"generation": full["generation"], "catalog_digest": catalog_digest}),
            "{preset:?}"
        );
    }
}

async fn send_metadata(
    principal: subc_protocol::Principal,
    name: &str,
    arguments: Value,
) -> subc_protocol::Frame {
    send_request(principal, json!({"name": name, "arguments": arguments})).await
}

async fn send_request(principal: subc_protocol::Principal, request: Value) -> subc_protocol::Frame {
    use std::sync::Arc;
    use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
    let scratch = plexus_core::test_scratch::Scratch::database("tool-provider-route");
    let store = Arc::new(
        plexus_core::PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".to_owned(),
            storage_namespace: "test".to_owned(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    // No connections or grants: metadata must not acquire connector authority.
    let runtime = crate::runtime_for_test(store);
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        41,
        1,
        7,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = tokio::sync::mpsc::channel(1);
    crate::handle_tool_request_for_test(frame, &writer, runtime, principal)
        .await
        .unwrap();
    let response = crate::bounded::recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "catalog response",
    )
    .await;
    assert_eq!(response.header.channel, 41);
    assert_eq!(response.header.epoch, 1);
    assert_eq!(response.header.corr, 7);
    assert!(
        responses.try_recv().is_err(),
        "metadata must send exactly one terminal frame"
    );
    response
}

#[tokio::test]
async fn tool_catalog_route_serves_metadata_without_grants() {
    use subc_protocol::{FrameType, Principal};
    let expected = reply(ops::TOOL_CATALOG, &Map::new()).unwrap();
    for principal in [
        Principal::Direct,
        Principal::Reserved {
            module_id: "aft".to_owned(),
        },
        Principal::Reserved {
            module_id: "prefrontal".to_owned(),
        },
    ] {
        let frame = send_metadata(principal, ops::TOOL_CATALOG, json!({})).await;
        assert_eq!(frame.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(
            body, expected,
            "role answer must be served directly, not wrapped as an MCP result"
        );
        let decoded: CatalogAnswer = serde_json::from_value(body).unwrap();
        assert!(
            decoded.tools.is_empty(),
            "preflight without a preset must select no tools"
        );
    }
    let frame = send_metadata(
        Principal::Direct,
        ops::TOOL_CATALOG,
        json!({"composition": {"secret": "opaque"}, "digest_only": true}),
    )
    .await;
    assert_eq!(frame.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(body["generation"], expected["generation"]);
}

/// Consumers discover providers by the complete set of tool tags in `role.describe`.
#[test]
fn role_describe_lists_every_catalog_tool_tag() {
    let describe = reply(ops::ROLE_DESCRIBE, &Map::new()).unwrap();
    let listed: Vec<String> =
        serde_json::from_value(describe["tool_capabilities"].clone()).unwrap();
    assert!(
        listed
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes()),
        "tool_capabilities must be sorted bytewise with no repeats: {listed:?}"
    );
    let mut served: Vec<String> = catalog_tools(&advertised_tools())
        .into_iter()
        .flat_map(|tool| tool.capabilities)
        .collect();
    served.sort_unstable();
    served.dedup();
    assert_eq!(
        listed, served,
        "tool_capabilities must equal the union of catalog tool tags"
    );
}

#[tokio::test]
async fn tool_catalog_route_refuses_unknown_or_unsupported_fields() {
    for (arguments, field) in [
        (json!({"unknown": true}), "unknown"),
        (json!({"params": {"unknown": true}}), "params.unknown"),
        (json!({"preset": "unknown"}), "preset"),
        (json!({"system_text": {"preset": "unknown"}}), "system_text"),
        (json!({"composition": []}), "arguments"),
        (json!({"digest_only": "true"}), "arguments"),
    ] {
        let frame = send_metadata(
            subc_protocol::Principal::Direct,
            ops::TOOL_CATALOG,
            arguments,
        )
        .await;
        assert_eq!(frame.header.ty, subc_protocol::FrameType::Error);
        let error: ErrorBody = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.detail.unwrap()["field"], field);
    }
}

#[tokio::test]
async fn role_describe_route_lists_required_ops_and_is_cacheable() {
    let first = send_metadata(
        subc_protocol::Principal::Direct,
        ops::ROLE_DESCRIBE,
        json!({}),
    )
    .await;
    let second = send_metadata(
        subc_protocol::Principal::Direct,
        ops::ROLE_DESCRIBE,
        json!({}),
    )
    .await;
    assert_eq!(first.header.ty, subc_protocol::FrameType::Response);
    assert_eq!(first.body, second.body);
    let body = serde_json::from_slice(&first.body).unwrap();
    let description = cortexkit_role_tool_provider::describe::check_describe(&body).unwrap();
    assert!(description.major("tool-provider/v1").unwrap().holds_calls());
    assert!(description
        .major("tool-provider/v1")
        .unwrap()
        .ops
        .iter()
        .any(|op| op == plexus_core::github::reads::bot::BULK_METHOD));
}

fn frozen_catalog_request(preset: &str) -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/fetch-plan-v1/plexus-worker-catalog-request.json"
    ))
    .unwrap();
    let mut arguments = fixture["worker-tool-and-text"]["request"].clone();
    arguments["preset"] = json!(preset);
    json!({"name": ops::TOOL_CATALOG, "preset": preset, "arguments": arguments})
}

#[tokio::test]
async fn frozen_catalog_presets_return_their_search_tools() {
    for (preset, tools) in [
        ("worker", &[WEB_SEARCH_TOOL, CODE_SEARCH_TOOL][..]),
        ("reader", &[CODE_SEARCH_TOOL][..]),
        ("head", &[WEB_SEARCH_TOOL, CODE_SEARCH_TOOL][..]),
    ] {
        let frame = send_request(
            subc_protocol::Principal::Direct,
            frozen_catalog_request(preset),
        )
        .await;
        assert_eq!(
            frame.header.ty,
            subc_protocol::FrameType::Response,
            "{preset}: {:?}",
            frame.body
        );
        let answer: CatalogAnswer = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(names(&answer), tools, "{preset}");
    }
}

#[tokio::test]
async fn frozen_catalog_preset_must_match_argument_preset() {
    for argument in [json!("reader"), Value::Null, json!(17)] {
        let mut request = frozen_catalog_request("worker");
        request["arguments"]["preset"] = argument;
        let frame = send_request(subc_protocol::Principal::Direct, request).await;
        assert_eq!(frame.header.ty, subc_protocol::FrameType::Error);
        let error: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(error["code"], "invalid_request");
        assert_eq!(error["field"], "preset");
        assert_eq!(
            error["message"],
            "top-level preset must equal arguments.preset"
        );
    }
}

#[tokio::test]
async fn frozen_preset_preserves_search_refusals_and_role_description() {
    for name in [WEB_SEARCH_TOOL, CODE_SEARCH_TOOL, ops::ROLE_DESCRIBE] {
        let arguments = if name == ops::ROLE_DESCRIBE {
            json!({})
        } else {
            json!({"query": "rust"})
        };
        let request = json!({"name": name, "arguments": arguments});
        let plain = send_request(subc_protocol::Principal::Direct, request.clone()).await;
        let mut frozen_request = request;
        frozen_request["preset"] = json!("worker");
        let frozen = send_request(subc_protocol::Principal::Direct, frozen_request).await;
        assert_eq!(frozen.header.ty, plain.header.ty, "{name}");
        assert_eq!(frozen.body, plain.body, "{name}");
        let body: Value = serde_json::from_slice(&plain.body).unwrap();
        if name == ops::ROLE_DESCRIBE {
            assert_eq!(plain.header.ty, subc_protocol::FrameType::Response);
            cortexkit_role_tool_provider::describe::check_describe(&body).unwrap();
        } else {
            let code = body["error"]["code"]
                .as_str()
                .or_else(|| body["errorCode"].as_str());
            assert!(code.is_some(), "ungranted search must refuse: {body}");
            assert_ne!(
                code,
                Some("invalid_request"),
                "search must reach authority checks: {body}"
            );
        }
    }
}

/// Replays the exact requests Broca, the model runner, sends when a coding
/// worker's session includes plexus's search tools: the tool-catalog fetch
/// and a later web_search call (fixtures/broca-frames/README.md). Both carry
/// a top-level preset name. Plexus once refused that field, which stopped
/// every worker launch whose plan included plexus. These are the bytes Broca
/// really sends, not a request rebuilt from reading its source.
#[tokio::test]
async fn broca_worker_frames_are_served() {
    let catalog: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/broca-frames/catalog-fetch.json"
    ))
    .unwrap();
    let frame = send_request(subc_protocol::Principal::Direct, catalog).await;
    assert_eq!(
        frame.header.ty,
        subc_protocol::FrameType::Response,
        "Broca's catalog fetch must be answered: {}",
        String::from_utf8_lossy(&frame.body)
    );
    let answer: CatalogAnswer = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(names(&answer), ["web_search", "code_search"]);

    let call: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/broca-frames/web-search-call.json"
    ))
    .unwrap();
    let mut plain = call.clone();
    let plain_object = plain.as_object_mut().unwrap();
    plain_object.remove("preset");
    plain_object.remove("tool_call_id");
    let with_preset = send_request(subc_protocol::Principal::Direct, call).await;
    let without = send_request(subc_protocol::Principal::Direct, plain).await;
    assert_eq!(
        (with_preset.header.ty, &with_preset.body),
        (without.header.ty, &without.body),
        "Broca's frozen preset and tool_call_id must not change a search call's answer"
    );
}

#[tokio::test]
async fn provider_refusals_warn_once_without_request_values() {
    const TEST: &str = "tool_provider::tests::provider_refusals_warn_once_without_request_values";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        let output = crate::bounded::child_output(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("PLEXUS_LOG_STDERR_CHILD", "1"),
            std::time::Duration::from_secs(30),
            "provider refusal warning child",
        )
        .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains("tool call refused: op="))
            .collect();
        assert_eq!(
            lines.len(),
            6,
            "each refusal must warn exactly once: {stderr}"
        );
        for secret in [
            "composition-secret",
            "argument-secret",
            "parameter-secret",
            "malformed.secret",
            "capability-secret",
            "serde-secret",
            "object-secret",
        ] {
            assert!(
                !stderr.contains(secret),
                "request values must not be logged ({secret}): {stderr}"
            );
        }
        let messages = [
            "unknown catalog argument",
            "role.describe takes no arguments",
            "unknown or malformed plexus preset",
            "unknown or malformed plexus preset",
            "malformed catalog arguments (values redacted)",
            "unknown or malformed plexus preset",
        ];
        for (line, expected_message) in lines.iter().zip(messages) {
            assert!(
                line.contains(&format!("message={expected_message} argument_keys=")),
                "{line}"
            );
            let message = &line[line.find("tool call refused:").unwrap()..];
            diagnostic_logging::assert_diagnostic(
                line,
                cortexkit_log::ParsedLevel::Warn,
                "plexus.wire",
                message,
            );
            for field in [
                "caller=direct",
                "code=invalid_request",
                "message=",
                "argument_keys=",
                "params_keys=",
            ] {
                assert!(line.contains(field), "missing {field}: {line}");
            }
        }
        assert!(lines[0].contains("op=tool.catalog"));
        assert!(lines[0].contains("composition") && lines[0].contains("capabilities"));
        assert!(lines[1].contains("op=role.describe"));
        assert!(lines[2].contains("op=web_search") && lines[2].contains("preset=mason"));
        assert!(lines[3..].iter().all(|line| !line.contains(" preset=")));
        return;
    }
    diagnostic_logging::init_child();
    for request in [
        json!({"name": ops::TOOL_CATALOG, "preset":"worker", "arguments":{
                "preset":"worker", "unknown":"argument-secret",
                "params":{"capabilities":"parameter-secret"},
                "composition":{"anything":"composition-secret"}}}),
        json!({"name": ops::ROLE_DESCRIBE, "preset":"reader", "arguments":{"unknown":"argument-secret"}}),
        json!({"name": WEB_SEARCH_TOOL, "preset":"mason", "arguments":{}}),
        json!({"name": WEB_SEARCH_TOOL, "preset":"malformed.secret", "arguments":{}}),
        json!({"name": ops::TOOL_CATALOG, "arguments":{"digest_only":"serde-secret"}}),
        json!({"name": ops::ROLE_DESCRIBE, "preset":{"secret":"object-secret"}, "arguments":{}}),
    ] {
        let frame = send_request(subc_protocol::Principal::Direct, request).await;
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        let error = body.get("error").unwrap_or(&body);
        assert_eq!(error["code"], "invalid_request");
    }
    let frame = send_metadata(
        subc_protocol::Principal::Direct,
        ops::TOOL_CATALOG,
        json!({"params":{"capabilities":["capability-secret"]}}),
    )
    .await;
    assert_eq!(frame.header.ty, subc_protocol::FrameType::Response);
}
