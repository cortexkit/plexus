//! Disabled final-body safety net for facade tools awaiting consumer approval.

use super::{manifest, reply_guard, with_call_tool_result_with_repo, Frame};
use reply_guard::{EffectiveFormat, ExecutionState};
use serde_json::{json, Value};

// Off until the readers of these tools' replies (Basal flows, core's event
// readers, Broca's model-facing tools and the plexus operator client) approve
// the samples in tests/fixtures/reply-too-large-v1/.
pub(super) const ENABLED: bool = false;

pub(super) fn covers(tool: Option<&str>) -> bool {
    matches!(
        tool,
        Some(
            manifest::CONNECTIONS_TOOL
                | manifest::CATALOG_TOOL
                | manifest::REQUESTS_TOOL
                | manifest::EVENTS_TOOL
                | manifest::INVOKE_TOOL
                | manifest::EVENTS_GET_TOOL
                | manifest::WITHDRAW_TOOL
        )
    )
}

pub(super) fn early(frame: &Frame, reply: Value, enabled: bool) -> Value {
    if !enabled {
        return reply;
    }
    let request: Value = serde_json::from_slice(&frame.body).unwrap_or(Value::Null);
    let tool = request.get("name").and_then(Value::as_str);
    if request.get("method").is_none() && covers(tool) {
        guard(tool, reply.clone(), reply)
    } else {
        reply
    }
}

pub(super) fn error_frame(body: Value) -> Value {
    if ENABLED
        && body["message"].as_str().is_some_and(|message| {
            message.len() > cortexkit_role_tool_provider::result::MAX_MODEL_VISIBLE_BYTES
        })
    {
        return json!({"code":"response_too_large", "message":"The request was refused, but its refusal message was too large to return."});
    }
    body
}

pub(super) fn guard(tool: Option<&str>, facade: Value, rendered: Value) -> Value {
    // None of these tools advertises result_format. Route capabilities alone
    // cannot negotiate ToolResultV1, even though the legacy body has MCP fields.
    let format = EffectiveFormat::Legacy;
    if format.fits(&rendered) {
        return rendered;
    }
    if facade.get("error").is_some() {
        return refusal(tool, facade);
    }
    if facade["result"]["transmission"].is_string() {
        let transmission = facade["result"]["transmission"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut fallback = facade;
        fallback["result"]["response"] = json!({"error": {
            "code": "response_too_large",
            "message": "The operation's output was too large to return and was discarded. Do not replay the operation.",
            "output_discarded": true
        }});
        let rendered = render(tool, fallback.clone());
        if format.fits(&rendered) {
            return rendered;
        }
        // Dispatch identity and reconciliation are execution evidence, not
        // output. Bound only the free-form vendor message, never those members.
        if let Some(message) = fallback["result"].get_mut("message") {
            bound_echoes(message);
        }
        let rendered = render(tool, fallback);
        if format.fits(&rendered) {
            return rendered;
        }
        // Never turn an unresolved dispatch into a completed one, even when
        // execution evidence itself cannot be represented in the byte budget.
        return render(
            tool,
            measured_error(
                "The operation's output was too large to return and was discarded. Do not replay the operation.",
                &transmission,
            ),
        );
    }
    let event_read = tool == Some(manifest::EVENTS_GET_TOOL)
        || (tool == Some(manifest::EVENTS_TOOL) && facade["result"]["body"].is_string());
    let mut fallback = completed_fallback();
    if event_read {
        fallback = super::with_event_get_retryable(fallback);
    }
    // Rendered like every other refusal of these tools (content, isError and
    // the legacy error), so a runner reads it as a tool error, not a malformed
    // reply.
    let fallback = render(tool, fallback);
    assert!(format.fits(&fallback));
    fallback
}

fn render(tool: Option<&str>, facade: Value) -> Value {
    with_call_tool_result_with_repo(tool, facade, None, false)
}

fn bound_echoes(value: &mut Value) {
    match value {
        Value::String(text) => *text = plexus_core::text::refusal_echo(text).into_owned(),
        Value::Array(values) => values.iter_mut().for_each(bound_echoes),
        Value::Object(fields) => fields.values_mut().for_each(bound_echoes),
        _ => {}
    }
}

fn refusal(tool: Option<&str>, mut facade: Value) -> Value {
    bound_echoes(&mut facade);
    let pending = facade["error"]["code"] == "access_pending";
    if pending {
        facade["error"]["transmission"] = json!("pending");
    }
    // Keep the original refusal code and operational members (including retry
    // hints). Only free-form detail may be omitted after bounding string echoes.
    let rendered = render_refusal(tool, &facade, pending);
    if EffectiveFormat::Legacy.fits(&rendered) {
        return rendered;
    }
    if facade["error"]
        .as_object_mut()
        .unwrap()
        .remove("detail")
        .is_some()
    {
        facade["error"]["detail_omitted"] = json!(true);
    }
    let rendered = render_refusal(tool, &facade, pending);
    if EffectiveFormat::Legacy.fits(&rendered) {
        return rendered;
    }
    render_refusal(
        tool,
        &measured_error(
            "The refusal was too large to return; the operation remains refused.",
            if pending { "pending" } else { "refused" },
        ),
        pending,
    )
}

fn render_refusal(tool: Option<&str>, facade: &Value, pending: bool) -> Value {
    let mut rendered = render(tool, facade.clone());
    if pending {
        // The ordinary renderer projects access_pending into structuredContent
        // and drops the legacy error, which carries transmission. Keep the
        // pending identity beside the rendered fields.
        rendered["error"] = facade["error"].clone();
    }
    rendered
}

fn measured_error(message: &'static str, transmission: &str) -> Value {
    reply_guard::fallback(
        EffectiveFormat::Legacy,
        message,
        ExecutionState { transmission },
    )
    .expect("fixed refusal fallback fits the legacy byte limit")
}

fn completed_fallback() -> Value {
    let mut fallback = measured_error(
        "The operation completed, but its output was too large to return and was discarded.",
        "completed",
    );
    fallback["error"]["output_discarded"] = json!(true);
    assert!(EffectiveFormat::Legacy.fits(&fallback));
    fallback
}
