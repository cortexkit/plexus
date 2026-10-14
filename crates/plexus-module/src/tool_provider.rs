//! Read-only tool-provider role metadata, derived from the advertised facade.

use cortexkit_role_tool_provider::{
    catalog::{
        check_modes, schema_digest, serves_call_mode, CatalogAnswer, CatalogRequest, CatalogTool,
    },
    describe::{Major, RoleDescribe},
    errors::invalid_request,
    ops, PROVIDES,
};
use serde_json::{Map, Value};
use subc_protocol::{
    call_mode::CallMode,
    manifest::{ProviderRole, Tool},
    ErrorBody,
};

use crate::manifest::{self, CODE_SEARCH_CAPABILITY, CODE_SEARCH_TOOL, WEB_SEARCH_TOOL};

// Tags describe the tool's contract, not the caller's authority. Keep the
// mapping explicit so grants can select tools without knowing their names.
const TOOL_CAPABILITIES: &[(&str, &[&str])] = &[
    ("connections", &["plexus:connections/v1"]),
    ("catalog", &["plexus:catalog.read/v1"]),
    ("invoke", &["plexus:connector.invoke/v1"]),
    ("requests", &["plexus:approval.requests/v1"]),
    ("github", &["plexus:github.facade/v1"]),
    ("github_read", &["github.read/v1", "plexus:github.read/v1"]),
    ("events_get", &["plexus:events.get/v1"]),
    ("events", &["plexus:events/v1"]),
    (WEB_SEARCH_TOOL, &["plexus:web.search/v1", "web.search/v1"]),
    (
        CODE_SEARCH_TOOL,
        &["code.search.public/v1", CODE_SEARCH_CAPABILITY],
    ),
];

fn modes_for(name: &str) -> Vec<CallMode> {
    match name {
        WEB_SEARCH_TOOL
        | CODE_SEARCH_TOOL
        | "github_read"
        | "events_get"
        | "catalog"
        | ops::TOOL_CATALOG
        | ops::ROLE_DESCRIBE
        | ops::TOOL_WITHDRAW => {
            vec![CallMode::Classic, CallMode::Codemode, CallMode::Flow]
        }
        "github" | "invoke" => vec![CallMode::Classic, CallMode::Flow],
        _ => vec![CallMode::Classic],
    }
}

pub(crate) fn mode_refusal(name: &str, mode: &CallMode) -> Option<ErrorBody> {
    // Use the same declaration for admission and catalog publication. Role
    // operations are not facade catalog entries, but still reject unknown modes.
    let tool = CatalogTool::new(name, "", 1, Value::Null).with_modes(modes_for(name));
    if serves_call_mode(&tool, mode) {
        None
    } else {
        Some(
            ErrorBody::new(
                cortexkit_role_tool_provider::errors::CALL_MODE_UNSUPPORTED,
                "plexus does not serve this tool in the route's call mode",
            )
            .with_detail(serde_json::json!({"tool": name, "mode": mode})),
        )
    }
}

pub(crate) fn is_metadata_op(name: &str) -> bool {
    matches!(name, ops::TOOL_CATALOG | ops::ROLE_DESCRIBE)
}

fn advertised_tools() -> Vec<Tool> {
    manifest::build(crate::DEFAULT_MODULE_ID)
        .provides
        .into_iter()
        .flat_map(|role| match role {
            ProviderRole::ToolProvider { tools, .. } => tools,
            _ => Vec::new(),
        })
        .collect()
}

fn catalog_tools(definitions: &[Tool]) -> Vec<CatalogTool> {
    definitions
        .iter()
        .map(|definition| {
            let mut capabilities: Vec<_> = TOOL_CAPABILITIES
                .iter()
                .find(|(name, _)| *name == definition.name)
                .expect("every advertised tool has capability tags")
                .1
                .iter()
                .map(|tag| (*tag).to_owned())
                .collect();
            capabilities.sort_unstable();
            capabilities.dedup();
            for tag in &capabilities {
                cortexkit_role_tool_provider::check_capability_tag(tag)
                    .expect("facade capability tags are valid");
            }
            // Semantics starts at 1; bump it when behavior changes without a
            // structural schema change so consumers can detect stale call pins.
            let search_content =
                matches!(definition.name.as_str(), WEB_SEARCH_TOOL | CODE_SEARCH_TOOL);
            let mut tool = CatalogTool::new(
                &definition.name,
                schema_digest(&definition.schema).expect("facade schemas are JCS-compatible"),
                if search_content { 2 } else { 1 },
                definition.schema.clone(),
            )
            .with_capabilities(capabilities)
            .with_modes(modes_for(&definition.name));
            check_modes(&tool).expect("facade call modes are valid");
            if search_content {
                tool = tool.with_result_format(
                    cortexkit_role_tool_provider::result::ResultFormat::ContentV1,
                );
            }
            tool.description = definition.description.clone();
            tool
        })
        .collect()
}

fn generation(tools: &[CatalogTool]) -> String {
    // Hash full definitions, not structural schema digests: descriptions and
    // capability promises are catalog content even when call pins stay valid.
    let definitions = serde_json::to_value(tools).expect("catalog tools serialize");
    plexus_core::jcs_sha256(&definitions).expect("facade definitions are JCS-compatible")
}

fn tools_for(
    preset: Option<&str>,
    params: &Map<String, Value>,
) -> Result<Vec<&'static str>, ErrorBody> {
    if preset.is_some_and(|preset| !matches!(preset, "head" | "worker" | "reader")) {
        return Err(invalid_request("preset", "unknown plexus catalog preset"));
    }
    if let Some(field) = params.keys().find(|field| field.as_str() != "capabilities") {
        return Err(invalid_request(
            &format!("params.{field}"),
            "unknown plexus catalog parameter",
        ));
    }
    let Some(capabilities) = params.get("capabilities") else {
        return Ok(Vec::new());
    };
    let capabilities = capabilities.as_array().ok_or_else(|| {
        invalid_request(
            "params.capabilities",
            "capabilities must be an array of tags",
        )
    })?;
    let tags: Vec<_> = capabilities
        .iter()
        .enumerate()
        .map(|(index, tag)| {
            tag.as_str().ok_or_else(|| {
                invalid_request(
                    &format!("params.capabilities[{index}]"),
                    "capability tag must be a string",
                )
            })
        })
        .collect::<Result<_, _>>()?;
    if tags.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_request(
            "params.capabilities",
            "capability tags must be sorted bytewise with no repeats",
        ));
    }
    for (index, tag) in tags.iter().enumerate() {
        if !TOOL_CAPABILITIES.iter().any(|(_, own)| own.contains(tag)) {
            return Err(invalid_request(
                &format!("params.capabilities[{index}]"),
                format!("plexus serves no capability {tag}"),
            )
            .with_detail(serde_json::json!({
                "field": format!("params.capabilities[{index}]"),
                "capability": tag,
            })));
        }
    }
    Ok(TOOL_CAPABILITIES
        .iter()
        .filter(|(_, own)| own.iter().any(|tag| tags.contains(tag)))
        .map(|(name, _)| *name)
        .collect())
}

#[cfg(test)]
fn catalog(request: &CatalogRequest, definitions: &[Tool]) -> Result<CatalogAnswer, ErrorBody> {
    let tools = catalog_tools(definitions);
    let digest = generation(&tools);
    catalog_answer(request, tools, digest)
}

fn cached_catalog(request: &CatalogRequest) -> Result<CatalogAnswer, ErrorBody> {
    static DEFINITIONS: std::sync::OnceLock<(Vec<CatalogTool>, String)> =
        std::sync::OnceLock::new();
    let (tools, digest) = DEFINITIONS.get_or_init(|| {
        let tools = catalog_tools(&advertised_tools());
        let digest = generation(&tools);
        (tools, digest)
    });
    catalog_answer(request, tools.clone(), digest.clone())
}

fn catalog_answer(
    request: &CatalogRequest,
    tools: Vec<CatalogTool>,
    generation: String,
) -> Result<CatalogAnswer, ErrorBody> {
    let selected = tools_for(request.preset.as_deref(), &request.params)?;
    // Generation identifies the full advertised definitions, independent of
    // the plan's capability selection; catalog_digest covers the actual answer.
    let tools = if request.composition.is_some() {
        tools
            .into_iter()
            .filter(|tool| selected.contains(&tool.name.as_str()))
            .collect()
    } else {
        tools
    };
    let mut answer = CatalogAnswer::new(generation, "").with_tools(tools);
    if let Some(composition) = &request.composition {
        answer.composition_digest = Some(
            cortexkit_role_tool_provider::catalog::composition_digest(&Value::Object(
                composition.clone(),
            ))
            .expect("decoded composition is JCS-compatible"),
        );
    }
    // A digest cannot include itself. Hash the full answer before shortening a
    // digest-only reply, so both fetch modes report exactly the same digest.
    let mut content = serde_json::to_value(&answer).expect("catalog answer serializes");
    content.as_object_mut().unwrap().remove("catalog_digest");
    answer.catalog_digest =
        plexus_core::jcs_sha256(&content).expect("catalog content is JCS-compatible");
    Ok(answer)
}

pub(crate) fn reply(name: &str, arguments: &Map<String, Value>) -> Result<Value, ErrorBody> {
    if name == ops::ROLE_DESCRIBE {
        if let Some(field) = arguments.keys().next() {
            return Err(invalid_request(field, "role.describe takes no arguments"));
        }
        return Ok(serde_json::to_value(RoleDescribe {
            majors: vec![Major {
                version: PROVIDES.to_owned(),
                ops: vec![
                    ops::ROLE_DESCRIBE.to_owned(),
                    ops::TOOL_CATALOG.to_owned(),
                    ops::TOOL_WITHDRAW.to_owned(),
                ],
                stability: "alpha".to_owned(),
            }],
            implementation_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: Vec::new(),
        })
        .expect("role description serializes"));
    }
    // The wire type permits additive members; this provider refuses axes it
    // cannot implement rather than silently returning the default catalog.
    if let Some(field) = arguments.keys().find(|field| {
        !matches!(
            field.as_str(),
            "params" | "preset" | "composition" | "system_text" | "digest_only"
        )
    }) {
        return Err(invalid_request(field, "unknown catalog argument"));
    }
    let request: CatalogRequest = serde_json::from_value(Value::Object(arguments.clone()))
        .map_err(|error| invalid_request("arguments", error.to_string()))?;
    if request.system_text.is_some() {
        return Err(invalid_request(
            "system_text",
            "plexus serves no system text",
        ));
    }
    let answer = cached_catalog(&request)?;
    let mut wire = serde_json::to_value(answer).expect("catalog answer serializes");
    if request.digest_only == Some(true) {
        // CatalogAnswer decodes omitted tools but serializes an empty list;
        // the role's digest-only wire shape contains only these two members.
        wire.as_object_mut()
            .unwrap()
            .retain(|key, _| matches!(key.as_str(), "generation" | "catalog_digest"));
    }
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let answer: CatalogAnswer =
            serde_json::from_value(reply(ops::TOOL_CATALOG, &Map::new()).unwrap()).unwrap();
        assert_eq!(answer.tools.len(), 10);
        assert_eq!(answer.tools.len(), advertised.len());
        for (tool, definition) in answer.tools.iter().zip(advertised) {
            assert_eq!(tool.name, definition.name);
            assert_eq!(tool.description, definition.description);
            assert_eq!(tool.input_schema, definition.schema);
            assert_eq!(
                tool.schema_digest,
                schema_digest(&definition.schema).unwrap()
            );
            cortexkit_role_tool_provider::catalog::check_flat_schema(&tool.input_schema).unwrap();
        }
        assert!(answer.tools.iter().all(|tool| !tool.name.contains('.')));
    }

    #[test]
    fn only_search_tools_opt_into_content_v1() {
        let answer = catalog(&CatalogRequest::default(), &advertised_tools()).unwrap();
        for tool in &answer.tools {
            let expected = if matches!(tool.name.as_str(), "web_search" | "code_search") {
                Some(cortexkit_role_tool_provider::result::ResultFormat::ContentV1)
            } else {
                None
            };
            assert_eq!(
                tool.result_format, expected,
                "result format for {}",
                tool.name
            );
            assert_eq!(tool.semantics, if expected.is_some() { 2 } else { 1 });
        }
    }

    #[test]
    fn catalog_modes_match_every_tool_contract() {
        let answer = catalog(&CatalogRequest::default(), &advertised_tools()).unwrap();
        for tool in &answer.tools {
            check_modes(tool).unwrap();
            assert!(serves_call_mode(tool, &CallMode::Classic));
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

    #[test]
    fn catalog_code_search_has_its_capability() {
        let answer = catalog(&CatalogRequest::default(), &advertised_tools()).unwrap();
        let tool = answer
            .tools
            .iter()
            .find(|tool| tool.name == "code_search")
            .unwrap();
        assert_eq!(
            tool.capabilities,
            ["code.search.public/v1", "plexus:code.search/v1"],
            "code_search capability must be published"
        );
        for tag in &tool.capabilities {
            cortexkit_role_tool_provider::check_capability_tag(tag).unwrap();
        }
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
        let answer = catalog(&CatalogRequest::default(), &advertised_tools()).unwrap();
        assert_eq!(answer.tools.len(), expected.len());
        for tool in &answer.tools {
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
                answer
                    .tools
                    .iter()
                    .filter(|tool| tool.name == *name)
                    .count(),
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

    #[test]
    fn catalog_reader_capabilities_select_only_search_in_manifest_order() {
        for tags in [
            json!(["plexus:code.search/v1", "plexus:web.search/v1"]),
            json!(["code.search.public/v1", "web.search/v1"]),
        ] {
            for preset in [None, Some("head"), Some("worker"), Some("reader")] {
                let answer = fetch(json!({"capabilities": tags}),
                Some(json!({"providers": [{"provider": "another-id", "tools": [{"name": "invoke"}]}]})),
                preset).unwrap();
                assert_eq!(
                    names(&answer),
                    ["web_search", "code_search"],
                    "reader capabilities must select only search tools in manifest order"
                );
                assert_eq!(
                    answer.tools[0].capabilities,
                    ["plexus:web.search/v1", "web.search/v1"]
                );
                assert_eq!(
                    answer.tools[1].capabilities,
                    ["code.search.public/v1", "plexus:code.search/v1"]
                );
            }
        }
    }

    #[test]
    fn catalog_github_capabilities_select_only_the_named_facade() {
        for (tag, name) in [
            ("github.read/v1", "github_read"),
            ("plexus:github.read/v1", "github_read"),
            ("plexus:github.facade/v1", "github"),
        ] {
            let answer = fetch(
                json!({"capabilities": [tag]}),
                Some(json!({})),
                Some("reader"),
            )
            .unwrap();
            assert_eq!(names(&answer), [name]);
            let expected = if name == "github_read" {
                vec!["github.read/v1", "plexus:github.read/v1"]
            } else {
                vec!["plexus:github.facade/v1"]
            };
            assert_eq!(answer.tools[0].capabilities, expected);
        }
    }

    #[test]
    fn catalog_refuses_unserved_capability_by_name() {
        for tag in ["plexus:unserved/v1", "code.search/v1"] {
            let error = fetch(
                json!({"capabilities": [tag]}),
                Some(json!({})),
                Some("reader"),
            )
            .unwrap_err();
            assert_eq!(
                error.code,
                cortexkit_role_tool_provider::errors::INVALID_REQUEST
            );
            assert!(error.message.contains(tag));
            let detail = error.detail.unwrap();
            assert_eq!(detail["field"], "params.capabilities[0]");
            assert_eq!(detail["capability"], tag);
        }
    }

    #[test]
    fn catalog_refuses_malformed_or_noncanonical_capability_lists() {
        for (capabilities, field) in [
            (
                json!(["plexus:web.search/v1", "plexus:code.search/v1"]),
                "params.capabilities",
            ),
            (
                json!(["plexus:web.search/v1", "plexus:web.search/v1"]),
                "params.capabilities",
            ),
            (json!(["plexus:web.search/v1", 4]), "params.capabilities[1]"),
            (json!("plexus:web.search/v1"), "params.capabilities"),
            (json!(null), "params.capabilities"),
        ] {
            let error =
                fetch(json!({"capabilities": capabilities}), Some(json!({})), None).unwrap_err();
            assert_eq!(
                error.code,
                cortexkit_role_tool_provider::errors::INVALID_REQUEST
            );
            assert_eq!(error.detail.unwrap()["field"], field);
        }
    }

    #[test]
    fn catalog_plan_without_capabilities_answers_no_tools() {
        for params in [json!({}), json!({"capabilities": []})] {
            let answer =
                fetch(params, Some(json!({"providers": "opaque"})), Some("reader")).unwrap();
            assert!(
                answer.tools.is_empty(),
                "plan fetch without capabilities must answer no tools"
            );
        }
    }

    #[test]
    fn catalog_preflight_ignores_capability_selection() {
        for params in [
            json!({}),
            json!({"capabilities": []}),
            json!({"capabilities": ["plexus:github.read/v1"]}),
        ] {
            let answer = fetch(params, None, Some("head")).unwrap();
            assert_eq!(answer.tools.len(), 10);
            assert_eq!(answer.tools, catalog_tools(&advertised_tools()));
        }
    }

    #[test]
    fn catalog_composition_is_opaque_and_does_not_select_definitions() {
        let params = json!({"capabilities": ["plexus:code.search/v1", "plexus:web.search/v1"]});
        let definitions = fetch(params.clone(), Some(json!({})), None).unwrap();
        for composition in [
            json!({"providers": [{"provider": "plexus", "tools": [{"name": "unknown", "capabilities": ["wrong"]}]}]}),
            json!({"providers": [{"provider": "plexus", "tools": []}]}),
            json!({"providers": [{"provider": "another-id", "tools": [{"name": "github"}]}]}),
            json!({"providers": "not an array", "scope": "irrelevant", "agent": "irrelevant"}),
        ] {
            let answer = fetch(params.clone(), Some(composition.clone()), None).unwrap();
            assert_eq!(answer.tools, definitions.tools);
            assert_eq!(answer.generation, definitions.generation);
            assert_eq!(
                answer.composition_digest.unwrap(),
                cortexkit_role_tool_provider::catalog::composition_digest(&composition).unwrap()
            );
        }
    }

    #[test]
    fn catalog_broca_head_fixture_selects_names_and_tags_from_params() {
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
        // The shared vector predates capability selection and has empty params.
        // A plan fetch with those original params must not expose any tools.
        let original = fetch(
            item["params"].clone(),
            Some(composition.clone()),
            item["preset"].as_str(),
        )
        .unwrap();
        assert!(original.tools.is_empty());
        let answer = fetch(
            json!({"capabilities": ["plexus:github.facade/v1", "plexus:web.search/v1"]}),
            Some(composition),
            item["preset"].as_str(),
        )
        .unwrap();
        assert_eq!(names(&answer), ["github", "web_search"]);
        assert_eq!(
            answer.composition_digest.unwrap(),
            plan["composition_digest"]
        );
        let entry = plan["composition"]["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["provider"] == "plexus")
            .unwrap();
        for (tool, planned) in answer.tools.iter().zip(entry["tools"].as_array().unwrap()) {
            assert_eq!(tool.name, planned["name"]);
            let mut expected = planned["capabilities"].as_array().unwrap().clone();
            if tool.name == "web_search" {
                expected.push(json!("web.search/v1"));
            }
            assert_eq!(
                serde_json::to_value(&tool.capabilities).unwrap(),
                json!(expected)
            );
        }
    }

    #[test]
    fn catalog_generation_is_full_set_and_digest_covers_filtered_answer() {
        let full = fetch(json!({}), None, None).unwrap();
        let filtered = fetch(
            json!({"capabilities": ["plexus:code.search/v1"]}),
            Some(json!({})),
            Some("reader"),
        )
        .unwrap();
        assert_eq!(names(&filtered), ["code_search"]);
        assert_eq!(filtered.generation, full.generation);
        assert_ne!(filtered.catalog_digest, full.catalog_digest);
        let mut content = serde_json::to_value(&filtered).unwrap();
        content.as_object_mut().unwrap().remove("catalog_digest");
        assert_eq!(
            filtered.catalog_digest,
            plexus_core::jcs_sha256(&content).unwrap()
        );
        content["tools"] = serde_json::to_value(&full.tools).unwrap();
        assert_ne!(
            filtered.catalog_digest,
            plexus_core::jcs_sha256(&content).unwrap()
        );
    }

    #[test]
    fn catalog_generation_is_stable_and_tracks_descriptions() {
        let definitions = advertised_tools();
        let first = catalog(&CatalogRequest::default(), &definitions).unwrap();
        let second = catalog(&CatalogRequest::default(), &advertised_tools()).unwrap();
        assert_eq!(first, second);
        let mut changed = definitions.clone();
        changed[0].description = Some("Changed facade description".to_owned());
        let changed = catalog(&CatalogRequest::default(), &changed).unwrap();
        assert_ne!(
            first.generation, changed.generation,
            "generation must cover descriptions"
        );
        assert_ne!(first.catalog_digest, changed.catalog_digest);
        assert_eq!(first.tools[0].schema_digest, changed.tools[0].schema_digest);
        let mut changed = definitions;
        changed[0].schema["description"] = json!("Changed schema description");
        let changed = catalog(&CatalogRequest::default(), &changed).unwrap();
        assert_ne!(first.generation, changed.generation);
        assert_eq!(first.tools[0].schema_digest, changed.tools[0].schema_digest);
    }

    #[test]
    fn catalog_digest_only_matches_full_answer_and_hashes_composition() {
        let composition = json!({"secret": "opaque composition data", "nested": [1, 2]});
        let full = reply(
            ops::TOOL_CATALOG,
            json!({"composition": composition, "params": {"capabilities": ["plexus:web.search/v1"]}}).as_object().unwrap(),
        )
        .unwrap();
        let digest = reply(
            ops::TOOL_CATALOG,
            json!({"composition": composition, "params": {"capabilities": ["plexus:web.search/v1"]}, "digest_only": true})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(full["tools"].as_array().unwrap().len(), 1);
        assert_eq!(full["tools"][0]["name"], "web_search");
        assert_eq!(digest.as_object().unwrap().len(), 2);
        assert_eq!(digest["generation"], full["generation"]);
        assert_eq!(digest["catalog_digest"], full["catalog_digest"]);
        assert_eq!(
            full["composition_digest"],
            cortexkit_role_tool_provider::catalog::composition_digest(&composition).unwrap()
        );
        let other = reply(
            ops::TOOL_CATALOG,
            json!({"composition": {"nested": [2, 1]}, "params": {"capabilities": ["plexus:web.search/v1"]}})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert_ne!(other["catalog_digest"], full["catalog_digest"]);
        assert_eq!(other["generation"], full["generation"]);
    }

    async fn send_metadata(
        principal: subc_protocol::Principal,
        name: &str,
        arguments: Value,
    ) -> subc_protocol::Frame {
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
            serde_json::to_vec(&json!({"name": name, "arguments": arguments})).unwrap(),
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
                module_id: "prefrontal-core".to_owned(),
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
            assert_eq!(decoded.tools.len(), 10);
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
        let frame = send_metadata(
            Principal::Direct,
            ops::TOOL_CATALOG,
            json!({"preset": "reader", "params": {"capabilities": ["plexus:code.search/v1", "plexus:web.search/v1"]}, "composition": {"providers": []}}),
        ).await;
        assert_eq!(frame.header.ty, FrameType::Response);
        let answer: CatalogAnswer = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(names(&answer), ["web_search", "code_search"]);
    }

    #[tokio::test]
    async fn tool_catalog_route_refuses_unknown_or_unsupported_fields() {
        for (arguments, field) in [
            (json!({"unknown": true}), "unknown"),
            (json!({"params": {"unknown": true}}), "params.unknown"),
            (json!({"preset": "unknown"}), "preset"),
            (json!({"system_text": {"preset": "unknown"}}), "system_text"),
            (json!({"composition": []}), "arguments"),
            (
                json!({"params": {"capabilities": ["plexus:unserved/v1"]}}),
                "params.capabilities[0]",
            ),
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
    }
}
