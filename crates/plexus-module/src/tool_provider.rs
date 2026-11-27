//! Read-only tool-provider role metadata, derived from the advertised facade.

use cortexkit_role_tool_provider::{
    catalog::{
        check_modes, schema_digest, serves_call_mode, CatalogAnswer, CatalogRequest, CatalogTool,
    },
    describe::{Major, RoleDescribe},
    ops, PROVIDES,
};
use serde_json::{Map, Value};
use subc_protocol::{
    call_mode::CallMode,
    manifest::{ProviderRole, Tool},
    ErrorBody,
};

use crate::manifest::{self, CODE_SEARCH_CAPABILITY, CODE_SEARCH_TOOL, WEB_SEARCH_TOOL};
use plexus_core::text::refusal_echo;

fn invalid_request(field: &str, message: impl Into<String>) -> ErrorBody {
    cortexkit_role_tool_provider::errors::invalid_request(
        &refusal_echo(field),
        refusal_echo(&message.into()).into_owned(),
    )
}

const PRESETS: [&str; 4] = ["head", "worker", "reader", "flow"];

// Tags describe the tool's contract, not the caller's authority. Keep the
// mapping explicit so consumers can discover providers by capability.
const TOOL_CAPABILITIES: &[(&str, &[&str])] = &[
    ("connections", &["plexus:connections/v1"]),
    ("catalog", &["plexus:catalog.read/v1"]),
    ("invoke", &["plexus:connector.invoke/v1"]),
    ("requests", &["plexus:approval.requests/v1"]),
    ("github", &["plexus:github.facade/v1"]),
    ("github_read", &["github.read/v1", "plexus:github.read/v1"]),
    ("github_react", &["plexus:github.react/v1"]),
    (manifest::GITHUB_WATCH_TOOL, &["plexus:github.watch/v1"]),
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
        manifest::GITHUB_WATCH_TOOL => vec![CallMode::Flow],
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
        // github_react posts as the bot of the agent named in the caller's
        // session scope. A codemode run's scope only attributes the call to an
        // agent and never lets it act as that agent, so like github and
        // invoke it is not served in codemode.
        "github" | "github_react" | "invoke" => vec![CallMode::Classic, CallMode::Flow],
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

/// Every capability tag any plexus tool carries, sorted bytewise with no
/// repeats: the `tool_capabilities` list `role.describe` reports.
fn tool_capability_union() -> Vec<String> {
    let mut tags: Vec<String> = TOOL_CAPABILITIES
        .iter()
        .flat_map(|(_, tags)| tags.iter().map(|tag| (*tag).to_owned()))
        .collect();
    tags.sort_unstable();
    tags.dedup();
    tags
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
                    cortexkit_role_tool_provider::result::ResultFormat::ToolResultV1,
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
    let definitions = wire_tools(tools);
    plexus_core::jcs_sha256(&definitions).expect("facade definitions are JCS-compatible")
}

/// The `emits_events` member of a tool's catalog entry, when it has one.
///
/// `false` promises that no call to the tool, whatever its arguments, makes
/// plexus emit a bus event, either directly or by relaying an upstream
/// notification the call caused. Absent means plexus makes no promise either
/// way.
fn emits_events(name: &str) -> Option<bool> {
    match name {
        // github_react only adds a reaction, through the bot request path,
        // which writes receipts and audit rows but no event. The two ways a
        // reaction could come back as a plexus event are both closed:
        // - polling: adding a reaction does not change an issue's
        //   `updated_at` (measured on six issues), and the issue and pull
        //   request event keys include `updated_at`, so no poll sees a new
        //   change;
        // - the webhook relay admits no reaction webhook types.
        // If either stops holding, this promise must be withdrawn.
        manifest::GITHUB_REACT_TOOL => Some(false),
        _ => None,
    }
}

/// Catalog tools as plexus serves them: the pinned role crate's encoding,
/// plus `emits_events` on the tools that declare it (see [`emits_events`]).
/// Generation, catalog digest and the reply all use this encoding, so the
/// digests cover exactly what is served.
fn wire_tools(tools: &[CatalogTool]) -> Value {
    let mut wire = serde_json::to_value(tools).expect("catalog tools serialize");
    for tool in wire
        .as_array_mut()
        .expect("catalog tools serialize as a list")
    {
        let fields = tool.as_object_mut().expect("a catalog tool is an object");
        let name = fields
            .get("name")
            .and_then(Value::as_str)
            .expect("a catalog tool has a name");
        if let Some(emits) = emits_events(name) {
            fields.insert("emits_events".to_owned(), Value::Bool(emits));
        }
    }
    wire
}

pub(crate) fn serves_preset(preset: &str) -> bool {
    PRESETS.contains(&preset)
}

fn tools_for(
    preset: Option<&str>,
    params: &Map<String, Value>,
    mut tools: Vec<CatalogTool>,
) -> Result<Vec<CatalogTool>, ErrorBody> {
    if preset.is_some_and(|preset| !serves_preset(preset)) {
        return Err(invalid_request("preset", "unknown plexus catalog preset"));
    }
    // Older callers may still send capabilities. Ignore the member regardless
    // of its value, but keep refusing other unsupported parameters.
    if let Some(field) = params.keys().find(|field| field.as_str() != "capabilities") {
        return Err(invalid_request(
            &format!("params.{field}"),
            "unknown plexus catalog parameter",
        ));
    }
    tools.retain(|tool| match preset {
        Some("head" | "worker") => {
            matches!(tool.name.as_str(), WEB_SEARCH_TOOL | CODE_SEARCH_TOOL)
        }
        // Read-only lanes get code search alone; a lane that also needs web
        // search asks for `worker`.
        Some("reader") => tool.name == CODE_SEARCH_TOOL,
        Some("flow") => serves_call_mode(tool, &CallMode::Flow),
        // A request without a preset is for discovery, not tool selection.
        _ => false,
    });
    Ok(tools)
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
    // Generation identifies the full advertised definitions, independent of
    // tool selection; catalog_digest covers the actual answer.
    let tools = tools_for(request.preset.as_deref(), &request.params, tools)?;
    let mut answer = CatalogAnswer::new(generation, "").with_tools(tools);
    if request.preset.is_none() {
        answer = answer.with_presets(PRESETS);
    }
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
    content["tools"] = wire_tools(&answer.tools);
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
        let describe = RoleDescribe::new(
            vec![Major {
                version: PROVIDES.to_owned(),
                ops: vec![
                    ops::ROLE_DESCRIBE.to_owned(),
                    ops::TOOL_CATALOG.to_owned(),
                    ops::TOOL_WITHDRAW.to_owned(),
                    plexus_core::github::reads::bot::BULK_METHOD.to_owned(),
                ],
                stability: "alpha".to_owned(),
            }],
            env!("CARGO_PKG_VERSION"),
        )
        .with_capabilities(vec!["plexus:github.read.bulk/v1".to_owned()])
        .with_tool_capabilities(tool_capability_union());
        return Ok(serde_json::to_value(describe).expect("role description serializes"));
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
    let tools = wire_tools(&answer.tools);
    let mut wire = serde_json::to_value(answer).expect("catalog answer serializes");
    wire["tools"] = tools;
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
#[path = "tool_provider_tests.rs"]
mod tests;
