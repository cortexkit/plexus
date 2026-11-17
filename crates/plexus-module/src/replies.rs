//! Shared reply shaping, refusals, content rendering and wire-send helpers.

use super::*;

/// Mark a reply whose effect already happened but whose audit row could not be
/// written. The effect stands, so the caller still gets the real reply rather
/// than an error that would read as "nothing happened"; the warning and the
/// log line say the journal is missing this row.
pub(super) fn warn_audit_failed(response: &mut Value, what: &str, error: &dyn std::fmt::Display) {
    eprintln!(error governance: "audit append failed after {what} took effect: {error}");
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "warning".into(),
            json!({
                "code": "audit_append_failed",
                "message": format!("{what} took effect, but its audit row could not be written; the module log names the cause"),
            }),
        );
    }
}

/// Run synchronous connector work that may touch the vendor transport.
///
/// The MCP transport is built on a blocking HTTP client, which owns an internal
/// runtime. Executing that on an async worker is illegal: tokio panics with
/// "cannot drop a runtime in a context where blocking is not allowed" when the
/// client's runtime is released, which kills the module mid-request and closes
/// the route under the caller. `block_in_place` moves the current task off the
/// async worker for the duration, making the blocking work — and the drops it
/// performs — legal.
///
/// `block_in_place` exists only on the multi-threaded runtime and panics on a
/// current-thread one, so there (and outside any runtime) the work runs
/// directly: a current-thread runtime has no other worker to hand the async
/// tasks to, so running inline is the only option it offers.
pub(super) fn blocking_section<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => work(),
    }
}

pub(super) fn retired_identity_field(
    arguments: &serde_json::Map<String, Value>,
) -> Option<&'static str> {
    ["assertion", "agent_assertion"]
        .into_iter()
        .find(|field| arguments.contains_key(*field))
}

pub(super) fn retired_identity_refusal(field: &str) -> Value {
    json!({"error":{"code":"argument_undeclared", "field":field,
        "message":format!("argument_undeclared{{field: {field}}}"), "transmission":"not_sent"}})
}

/// The arguments map checked exactly as `secret_input::contains_secret_input`
/// checks a JSON object, without first cloning the map into a `Value`.
pub(super) fn map_contains_secret_input(value: &serde_json::Map<String, Value>) -> bool {
    value
        .iter()
        .any(|(key, child)| plexus_core::secret_input::contains_secret_entry(key, child))
}

pub(super) const CONSENT_PENDING_TEXT: &str = "Waiting for the user to approve <service> <action>. The request has gone to them. End your turn now; you will be resumed with the answer, and then you should run this same call again.";

pub(super) fn denial_response(denial: &plexus_core::Denial) -> Value {
    if matches!(
        denial,
        plexus_core::Denial::FederatedPairingEnded
            | plexus_core::Denial::FederatedLivenessUnavailable
    ) {
        return json!({"error": {"code": denial.reason_code(), "message": denial.reason_code(),
            "retryable": matches!(denial, plexus_core::Denial::FederatedLivenessUnavailable),
            "transmission": "not_sent"}});
    }
    if let plexus_core::Denial::AccessPending {
        elicitation_id,
        service,
        action,
    } = denial
    {
        let text = CONSENT_PENDING_TEXT
            .replace("<service>", &plexus_core::text::refusal_echo(service))
            .replace("<action>", &plexus_core::text::refusal_echo(action));
        return json!({"error": {"code": "access_pending", "message": text, "elicitation_id": elicitation_id}});
    }
    if let plexus_core::Denial::ConsentRefused {
        code,
        elicitation_id,
    } = denial
    {
        return json!({"error": {"code": code, "message": code, "elicitation_id": elicitation_id}});
    }
    if let plexus_core::Denial::ConnectorHomeNotHeld { state } = denial {
        if state.pointer("/error/code").and_then(Value::as_str) == Some("request_deadline_exceeded")
        {
            return state.clone();
        }
        return json!({"error":{"code":"connector_home_not_held", "message":format!("connector home not held: {state}"),"connectorHome":state,"transmission":"not_sent"}});
    }
    let mut response = json!({
        "error": {
            "code": denial.reason_code(),
            "terminal": denial.terminal(),
            "message": "governance denied the connector operation"
        }
    });
    if matches!(denial, plexus_core::Denial::NeedsDecisionPlane(_)) {
        response["error"]["message"] =
            json!("S3/S4 execution is not active: no production decision plane is configured.");
    }
    if let plexus_core::Denial::GrantRefusal(refusal) = denial {
        response["error"]["detail"] = json!(refusal.detail());
    }
    // Include the ID of the request waiting for approval in the error response
    // so the caller can identify it without searching a list of requests.
    if let plexus_core::Denial::ActionRequestCreated { request_id } = denial {
        response["error"]["request_id"] = json!(request_id);
    }
    // Name the refused argument so the caller can drop it. Only the name is
    // echoed, never the argument's value.
    if let plexus_core::Denial::ArgumentUndeclared { field } = denial {
        response["error"]["field"] = json!(plexus_core::text::refusal_echo(field));
    }
    if let plexus_core::Denial::ConsentUnavailable { action } = denial {
        let action = plexus_core::text::refusal_echo(action);
        response["error"]["action"] = json!(action);
        response["error"]["message"] = json!(format!(
            "consent_unavailable for action '{action}': no admissible session or consent route is available"
        ));
        response["error"]["transmission"] = json!("not_sent");
    }
    if let plexus_core::Denial::RecipientArgumentInvalid { pointer } = denial {
        response["error"]["pointer"] = json!(pointer);
    }
    if let plexus_core::Denial::ApprovalPreviewTooLong {
        action,
        length,
        limit,
    } = denial
    {
        let action = plexus_core::text::refusal_echo(action);
        response["error"]["action"] = json!(action);
        response["error"]["message"] = json!(format!("approval_preview_too_long for action '{action}': {length} bytes exceeds {limit} byte frame-body limit"));
        response["error"]["length"] = json!(length);
        response["error"]["limit"] = json!(limit);
    }
    response
}

pub(super) fn dispatch_response(outcome: DispatchOutcome) -> Value {
    #[cfg(test)]
    let outcome = remaining_tool_guard_tests::stable_dispatch_identity(outcome);
    let (transmission, result, message) = match outcome.outcome {
        TransportOutcome::Completed { response } => ("completed", response, None),
        TransportOutcome::VendorFailed { code, message } => {
            ("failed", Some(json!({"code": code})), Some(message))
        }
        TransportOutcome::OutcomeUnknown => (
            "outcome_unknown",
            None,
            Some("vendor outcome is unresolved".to_string()),
        ),
        TransportOutcome::NotSent { code, message } => {
            ("not_sent", Some(json!({"code": code})), Some(message))
        }
    };
    let mut body = json!({
        "result": {
            "reservation_id": outcome.reservation_id,
            "transmission": transmission,
            "retryability": match outcome.retryability {
                plexus_core::Retryability::Terminal => "terminal",
                plexus_core::Retryability::AutoRetryable => "autoretryable",
                plexus_core::Retryability::Throttle => "throttle",
            },
            "response": result
        }
    });
    if let Some(reconciliation) = outcome.reconciliation {
        body["result"]["reconciliation"] = json!(reconciliation);
    }
    if let Some(message) = message {
        body["result"]["message"] = Value::String(message);
    }
    body
}

/// Report EVERY missing required field, not the first one found.
///
/// A validator holds all of its failed conditions at the moment it refuses, so
/// disclosing one throws away information it already computed. The cost lands
/// on the caller: an error that reveals one problem at a time costs a round
/// trip per discovery, and the second failure is indistinguishable from the
/// first, so the caller cannot tell whether their correction made progress.
/// That matters most for callers with no access to this source, which is every
/// agent reaching the module through the facade.
///
/// Returns `None` when nothing is missing.
pub(super) fn missing_string_fields(
    arguments: &serde_json::Map<String, Value>,
    required: &[&str],
) -> Option<Vec<String>> {
    let missing: Vec<String> = required
        .iter()
        .filter(|field| {
            arguments
                .get(**field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        .map(|field| (*field).to_string())
        .collect();
    (!missing.is_empty()).then_some(missing)
}

pub(super) async fn send_tool_response(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    channel: u16,
    epoch: u32,
    correlation: u64,
    body: Value,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let frame = Frame::build_with_version(
        version,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        correlation,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, frame).await
}

pub(super) async fn send_tool_error(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    channel: u16,
    epoch: u32,
    correlation: u64,
    code: &str,
    message: &str,
) -> Result<(), ModuleError> {
    // These are fixed ingress/worker refusals, not rendered tool or program
    // results. Keep their old bytes while measuring their final legacy body.
    let reply = with_event_get_retryable(tool_error(code, message));
    let reply = if remaining_tool_guard::ENABLED {
        remaining_tool_guard::guard(None, reply.clone(), reply)
    } else {
        reply
    };
    send_tool_response(writer, version, channel, epoch, correlation, reply).await
}

/// The route error body `{"error": {"code", "message"}}`.
pub(super) fn tool_error(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

pub(super) fn is_event_get_call(object: &serde_json::Map<String, Value>) -> bool {
    object.get("name").and_then(Value::as_str) == Some(manifest::EVENTS_GET_TOOL)
        || (object.get("name").and_then(Value::as_str) == Some(manifest::EVENTS_TOOL)
            && object
                .get("arguments")
                .and_then(|arguments| arguments.get("op"))
                .and_then(Value::as_str)
                == Some("get"))
}

/// Event consumers retain events on transient failures, but drop terminal refusals.
/// Decorate the complete reply, rather than individual gates, so new refusals
/// always carry a boolean. Ingress errors share this helper because they can
/// precede decoding the tool name; their retry policy is the same for every tool.
pub(super) fn with_event_get_retryable(mut reply: Value) -> Value {
    if let Some(error) = reply.get_mut("error").and_then(Value::as_object_mut) {
        let retryable = matches!(
            error.get("code").and_then(Value::as_str),
            Some(
                "flow_audience_unavailable"
                    | "store_failure"
                    | "resource_exhausted"
                    | "route_not_bound"
                    | "request_deadline_exceeded"
                    | "internal_error"
            )
        );
        error.entry("retryable").or_insert(json!(retryable));
    }
    reply
}

/// Whether this tool call is a GitHub bot write: the `github` tool's
/// `bot_request` op, or `github_react`, which runs through the same receipt
/// path. Only those refusals carry `retry_same_nonce`; other tools never
/// claim a nonce receipt, so the field would be meaningless on them.
pub(super) fn is_bot_request_call(object: &serde_json::Map<String, Value>) -> bool {
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    if name == manifest::GITHUB_REACT_TOOL {
        return true;
    }
    if name != manifest::GITHUB_TOOL {
        return false;
    }
    object
        .get("arguments")
        .and_then(Value::as_object)
        .and_then(|arguments| arguments.get("op"))
        .and_then(Value::as_str)
        .is_some_and(|op| op == "bot_request")
}

/// Mark a top-level `{"error": ...}` refusal of a bot write as safe to
/// retry with the same nonce. Module gates run before the facade claims any
/// receipt, so no receipt is held and resending the identical request is safe.
pub(super) fn with_bot_retry_flag(mut reply: Value) -> Value {
    if let Some(error) = reply.get_mut("error") {
        if error.is_object() && error.get("retry_same_nonce").is_none() {
            error["retry_same_nonce"] = json!(true);
        }
    }
    reply
}

pub(super) fn diagnostic_label(value: &str) -> String {
    let (kept, cut) = plexus_core::text::prefix_within_chars(value, 128);
    let mut label: String = kept.chars().flat_map(char::escape_default).collect();
    if cut {
        label.push_str("...");
    }
    label
}

// On routes that negotiated tool-result/v1, web search replies drop the legacy
// result/error members. Enabled once core's web search readers read
// structuredContent/isError/errorCode (core 0493ea5e25); set it back to false
// if a negotiated consumer turns out to read only the legacy members.
pub(super) const CORE_WEB_SEARCH_TOOL_RESULT_V1_READER_READY: bool = true;

pub(super) fn with_call_tool_result_with_repo(
    tool: Option<&str>,
    reply: Value,
    code_search_repo: Option<&str>,
    reads_tool_result_v1: bool,
) -> Value {
    with_call_tool_result_for_route(
        tool,
        reply,
        code_search_repo,
        reads_tool_result_v1,
        CORE_WEB_SEARCH_TOOL_RESULT_V1_READER_READY,
    )
}

/// Full envelopes remain JSON text for relays. Large events/catalog listings
/// keep their full legacy result but summarize text and omit structuredContent.
/// Other tools keep the MCP fields and legacy facade envelope they already serve.
///
/// Model-facing callers, such as Broca routing a model's tool call here, read
/// only `content[].text`, `structuredContent` and `isError`; relays that
/// decode the reply themselves, such as prefrontal's web search relay and
/// AFT's gh-shim relay, read `result`/`error`. Web search keeps these members
/// for Prefrontal's relay until Core's reader is ready, then omits them only on
/// negotiated routes; code search has no legacy-envelope consumer.
/// A success adds `content`, `isError: false` and `structuredContent` (a copy
/// of `result`, when it is a JSON object, as MCP requires). For web search the
/// text is a readable listing, and code search renders its parsed matches.
/// For other tools the text is the WHOLE facade
/// reply as JSON, not just `result`, because relays that predate these fields
/// (AFT's gh-shim `facade_reply`) unwrap a JSON text block as the complete
/// reply and then read `result.status` and `repo_binding_generation` from it.
/// A refusal adds `content` and `isError: true`. Web search retains Prefrontal's
/// web search relay wording so moving providers does not change model text.
/// For other tools, typed grant refusals carry
/// the full envelope as JSON text so restoration clients can read detail;
/// other refusals retain the code, message, retry delay and field in one line.
///
/// What may be disclosed does not change: the text is rendered only from the
/// `result` or `error` value already in this reply, never from anything wider
/// such as a vendor error body the handler kept out of it.
///
/// Management-surface replies (`{method, params}`) do not pass through here;
/// the operator's admin client reads them as they are.
pub(super) fn with_call_tool_result_for_route(
    tool: Option<&str>,
    mut reply: Value,
    code_search_repo: Option<&str>,
    reads_tool_result_v1: bool,
    core_web_search_reader_ready: bool,
) -> Value {
    let pure_web_search = tool == Some(manifest::WEB_SEARCH_TOOL)
        && core_web_search_reader_ready
        && reads_tool_result_v1;
    if reply["error"]["code"] == "access_pending" && !pure_web_search {
        let text = reply["error"]["message"].as_str().unwrap_or_default();
        return json!({
            "content": text_content(text.to_string()),
            "isError": true,
            "structuredContent": {"success": false, "code": "access_pending", "message": text, "text": text, "elicitation_id": reply["error"]["elicitation_id"]}
        });
    }
    if let Some(tool @ (manifest::WEB_SEARCH_TOOL | manifest::CODE_SEARCH_TOOL)) = tool {
        let format = if pure_web_search {
            reply_guard::EffectiveFormat::ToolResultV1
        } else {
            reply_guard::EffectiveFormat::Legacy
        };
        return search_content_result(tool, reply, code_search_repo, format);
    }
    let listing = matches!(tool, Some(manifest::EVENTS_TOOL | manifest::CATALOG_TOOL))
        && ["events", "actions", "apps"]
            .into_iter()
            .any(|key| reply["result"][key].is_array());
    let bounded_listing = listing && !json_fits(&reply, 64 * 1024);
    let text = if let Some(error) = reply.get("error") {
        if error.get("detail").is_some() {
            pretty_json(&reply)
        } else {
            refusal_text(error)
        }
    } else if bounded_listing {
        json!({"result":{"summary":"Listing is large; read result for full data or request an events page.",
            "next_after":reply["result"]["next_after"]}}).to_string()
    } else {
        pretty_json(&reply)
    };
    let Some(fields) = reply.as_object_mut() else {
        return reply;
    };
    if fields.contains_key("error") {
        fields.insert("content".to_string(), text_content(text));
        fields.insert("isError".to_string(), Value::Bool(true));
    } else if let Some(result) = fields.get("result") {
        let structured = (!bounded_listing && result.is_object()).then(|| result.clone());
        fields.insert("content".to_string(), text_content(text));
        fields.insert("isError".to_string(), Value::Bool(false));
        if let Some(structured) = structured {
            fields.insert("structuredContent".to_string(), structured);
        }
    }
    reply
}

fn json_fits(value: &Value, limit: usize) -> bool {
    struct BoundedSize(usize);
    impl std::io::Write for BoundedSize {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other("JSON size limit"));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(BoundedSize(limit), value).is_ok()
}

pub(super) fn search_content_result(
    tool: &str,
    mut legacy: Value,
    code_search_repo: Option<&str>,
    format: reply_guard::EffectiveFormat,
) -> Value {
    use cortexkit_role_tool_provider::result::{validate, ContentPart, ToolResult};
    let pure_web_search = tool == manifest::WEB_SEARCH_TOOL
        && matches!(format, reply_guard::EffectiveFormat::ToolResultV1);
    let mut result = if let Some(error) = legacy.get("error") {
        let text = if tool == manifest::WEB_SEARCH_TOOL {
            web_search_refusal_text(error)
        } else if error.get("detail").is_some() {
            pretty_json(&legacy)
        } else {
            refusal_text(error)
        };
        let code = if tool == manifest::WEB_SEARCH_TOOL {
            web_search_text_field(error, "code").unwrap_or("unknown")
        } else {
            error.get("code").and_then(Value::as_str).unwrap_or("error")
        };
        let mut result = ToolResult::new(vec![ContentPart::text(text)]).with_error(code);
        if pure_web_search {
            if let Some(error) = error.as_object() {
                result = result.with_structured_content(error.clone());
            }
        }
        result
    } else {
        let mut parsed = legacy.get("result").cloned().unwrap_or(Value::Null);
        let text = if tool == manifest::WEB_SEARCH_TOOL {
            let (text, shown) = web_search_text(&parsed);
            if let Some(results) = parsed.get_mut("results").and_then(Value::as_array_mut) {
                let found = results.len();
                if shown < found {
                    results.truncate(shown);
                    parsed["results_shown"] = json!(shown);
                    parsed["results_found"] = json!(found);
                    parsed["results_omitted"] = json!(found - shown);
                    // Core's web_search relay renders the appended legacy
                    // `result`, not this text, so it must carry the same
                    // shown subset or the head still gets every result.
                    legacy["result"] = parsed.clone();
                }
            }
            text
        } else {
            serde_json::from_value::<plexus_core::code_search::CodeSearchResponse>(parsed.clone())
                .ok()
                .map(|response| {
                    plexus_core::code_search::reply::render_with_repo_filter(
                        &response,
                        code_search_repo,
                    )
                })
                .unwrap_or_else(|| pretty_json(&legacy))
        };
        let mut result = ToolResult::new(vec![ContentPart::text(text)]);
        result.is_error = Some(false);
        if let Some(parsed) = parsed.as_object() {
            result = result.with_structured_content(parsed.clone());
        }
        result
    };
    // Refuse an invalid or oversized result by name rather than sending content
    // that a tool-result/v1 consumer cannot accept, or silently truncating it.
    let mut body = serde_json::to_value(&result).expect("search ToolResult serializes");
    let valid = if pure_web_search {
        format.fits(&body)
    } else {
        validate(&result).is_ok()
    };
    if !valid {
        let message = "plexus could not produce a valid tool-result/v1 result";
        result = ToolResult::new(vec![ContentPart::text(message)]).with_error("invalid_answer");
        legacy = tool_error("invalid_answer", message);
        if pure_web_search {
            result = result.with_structured_content(legacy["error"].as_object().unwrap().clone());
        }
        body = serde_json::to_value(&result).expect("search ToolResult serializes");
    }
    validate(&result).expect("the bounded tool-result/v1 refusal is valid");
    if tool == manifest::WEB_SEARCH_TOOL && !pure_web_search {
        for key in ["result", "error"] {
            if let Some(value) = legacy.get(key) {
                body.as_object_mut()
                    .unwrap()
                    .insert(key.into(), value.clone());
            }
        }
    }
    body
}

/// A `CallToolResult` content list holding one text block.
fn text_content(text: String) -> Value {
    json!([{"type": "text", "text": text}])
}

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// One line naming a refusal: `code: message`, then the retry delay in whole
/// seconds (rounded up) when the error states one, then the refused field
/// when it names one. A model reading only this text can still tell that the
/// call failed, why, and when it may try again.
fn refusal_text(error: &Value) -> String {
    let code = error.get("code").and_then(Value::as_str).unwrap_or("error");
    let mut text = match error.get("message").and_then(Value::as_str) {
        Some(message) => format!("{code}: {message}"),
        None => code.to_string(),
    };
    if let Some(retry_after_ms) = error.get("retry_after_ms").and_then(Value::as_u64) {
        text.push_str(&format!(
            " (retry after {} s)",
            retry_after_ms.div_ceil(1_000)
        ));
    }
    if let Some(field) = error.get("field").and_then(Value::as_str) {
        text.push_str(&format!(" field: {field}"));
    }
    text
}

/// The text a model reads for a web search: a count line, then each result
/// numbered with title, url, publication day and excerpt. Until this moved
/// here, Prefrontal (the agent runtime) authored the web_search tool and
/// rendered this same text from plexus's reply. Ordinary replies stay identical;
/// larger replies stop at a whole result and disclose how many were omitted.
fn web_search_text(result: &Value) -> (String, usize) {
    use cortexkit_role_tool_provider::result::MAX_MODEL_VISIBLE_BYTES;
    let cached = result.get("cached").and_then(Value::as_bool) == Some(true);
    let cached_note = if cached { " (cached)" } else { "" };
    let results = result
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if results.is_empty() {
        return (format!("No web results{cached_note}."), 0);
    }
    let noun = if results.len() == 1 {
        "result"
    } else {
        "results"
    };
    let mut text = format!("{} web {noun}{cached_note}:", results.len());
    // Reserve the longest closing note before accepting a result. Text is the
    // only model-visible part of this ToolResult; structured data is not counted.
    let note = |shown| {
        format!("\n\nShown {shown} of {} results found; the rest were left out to keep the reply under the size limit.", results.len())
    };
    let budget = MAX_MODEL_VISIBLE_BYTES - note(results.len()).len();
    for (index, item) in results.iter().enumerate() {
        let mut entry = format!(
            "\n\n{}. {}",
            index + 1,
            web_search_text_field(item, "title")
                .map(web_search_collapse_whitespace)
                .unwrap_or_else(|| "(untitled)".to_string())
        );
        if let Some(url) = web_search_text_field(item, "url") {
            entry.push_str(&format!("\n   {url}"));
        }
        if let Some(published) = web_search_text_field(item, "published_at") {
            // RFC 3339 timestamps carry precision the model does not need;
            // show only the publication day.
            let day = published.split('T').next().unwrap_or(published);
            entry.push_str(&format!("\n   Published {day}"));
        }
        if let Some(excerpt) = web_search_text_field(item, "excerpt") {
            entry.push_str(&format!("\n   {}", web_search_collapse_whitespace(excerpt)));
        }
        if text.len() + entry.len() > budget {
            text.push_str(&note(index));
            return (text, index);
        }
        text.push_str(&entry);
    }
    (text, results.len())
}

fn web_search_text_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn web_search_collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn web_search_wait_words(retry_after_ms: u64) -> String {
    let seconds = retry_after_ms.div_ceil(1_000).max(1);
    let (minutes, rest) = (seconds / 60, seconds % 60);
    let unit = |count: u64, one: &str| {
        if count == 1 {
            format!("1 {one}")
        } else {
            format!("{count} {one}s")
        }
    };
    match (minutes, rest) {
        (0, _) => unit(rest, "second"),
        (_, 0) => unit(minutes, "minute"),
        _ => format!("{} {}", unit(minutes, "minute"), unit(rest, "second")),
    }
}

fn web_search_refusal_text(error: &Value) -> String {
    let code = web_search_text_field(error, "code").unwrap_or("unknown");
    let message = web_search_text_field(error, "message").unwrap_or("no detail given");
    let backend = web_search_text_field(error, "backend").unwrap_or("the search backend");
    let head = format!("web_search was refused ({code}):");
    match code {
        "rate_limited" => match error.get("retry_after_ms").and_then(Value::as_u64) {
            Some(retry_after_ms) => format!(
                "{head} the web search rate limit is reached. Retry in {} (retry_after_ms {retry_after_ms}).",
                web_search_wait_words(retry_after_ms)
            ),
            None => format!("{head} the web search rate limit is reached. Retry in a minute."),
        },
        "invalid_query" => {
            let field = web_search_text_field(error, "field").unwrap_or("an argument");
            format!("{head} the `{field}` argument is not valid. Correct it and search again.")
        }
        "web_search_code_lookup" => format!("{head} {message}"),
        "web_search_not_granted" => format!(
            "{head} plexus grants no web search backend to the calling module. An operator must grant it; retrying fails the same way until then."
        ),
        "agent_not_granted" => format!(
            "{head} plexus holds no web search grant for this agent. An operator must grant it; retrying fails the same way until then."
        ),
        "backend_unavailable" => {
            format!("{head} {backend} is unavailable right now. Retry in a little while.")
        }
        "backend_quarantined" => format!(
            "{head} {backend} is quarantined pending operator review; retrying fails the same way until an operator clears it."
        ),
        "backend_ambiguous" => format!(
            "{head} more than one plexus connection could serve this search, and plexus will not pick whose account pays. An operator must leave one; retrying fails the same way until then."
        ),
        _ => {
            let retry = if error.get("retryable").and_then(Value::as_bool) == Some(true) {
                " Retry shortly."
            } else {
                ""
            };
            format!("{head} {message}.{retry}")
        }
    }
}

pub(super) async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| ModuleError::Message("egress channel closed".to_string()))
}
