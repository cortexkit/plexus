//! Bounds for model-facing GitHub reads, never for `github.read.bulk`.

use cortexkit_role_tool_provider::result::{legacy_model_visible_bytes, MAX_MODEL_VISIBLE_BYTES};
use serde_json::{json, Value};

use super::reply_guard::{self, EffectiveFormat, ExecutionState};

// Tails can discard their oldest bytes after measuring JSON escaping. Ranges
// cannot: transport redaction/ANSI removal changes text byte positions, while
// offset/length count raw bytes for paging. 10000 * 6 = 60000 leaves 5536 bytes
// for the fixed range envelope even for six-byte control escapes. Unusual
// redaction expansion is refused by the final guard, never mapped to a false
// raw offset. The bulk operation retains its separate 1 MiB range limit.
const MAX_TAIL_BYTES: u64 = 60_000;
const MAX_RANGE_BYTES: u64 = 10_000;

pub(super) fn bounded_args(action: &str, mut args: Value, range: bool) -> (Value, Option<u64>) {
    let key = match action {
        "github.actions.job_log" if range => "length",
        "github.actions.job_log" | "github.actions.artifact_file" => "max_bytes",
        _ => return (args, None),
    };
    let Some(fields) = args.as_object_mut() else {
        return (args, None);
    };
    let cap = if range {
        MAX_RANGE_BYTES
    } else {
        MAX_TAIL_BYTES
    };
    let applied = match fields.get(key) {
        None => cap,
        Some(value) => match value.as_u64() {
            Some(bytes) if bytes > 0 => bytes.min(cap),
            // Leave invalid arguments for the existing typed validation.
            _ => return (args, None),
        },
    };
    fields.insert(key.into(), json!(applied));
    (args, (key == "max_bytes").then_some(applied))
}

/// Keep the newest UTF-8 suffix whose complete legacy envelope fits. The
/// transport cap bounds raw bytes, not JSON escaping or redaction expansion.
pub(super) fn shape_tail(action: &str, mut reply: Value) -> Value {
    if !matches!(
        action,
        "github.actions.job_log" | "github.actions.artifact_file"
    ) {
        return reply;
    }
    let (Some(text), Some(max_bytes)) = (
        reply.pointer("/result/text").and_then(Value::as_str),
        reply.pointer("/result/max_bytes").and_then(Value::as_u64),
    ) else {
        return reply;
    };
    let text = text.to_owned();
    let was_truncated = reply["result"]["truncated"] == true;
    let boundary = |mut start: usize| {
        while !text.is_char_boundary(start) {
            start += 1;
        }
        start
    };
    let set_tail = |reply: &mut Value, start: usize| {
        reply["result"]["text"] = json!(&text[start..]);
        reply["result"]["length"] = json!(text.len() - start);
        reply["result"]["truncated"] = json!(was_truncated || start > 0);
    };
    let mut low = boundary(text.len().saturating_sub(max_bytes as usize));
    let mut high = text.len();
    // Removing a prefix only shrinks this envelope, so find the longest
    // fitting suffix without guessing how much its characters will escape.
    while low < high {
        let mut mid = low + (high - low) / 2;
        while !text.is_char_boundary(mid) {
            mid -= 1;
        }
        set_tail(&mut reply, mid);
        if legacy_model_visible_bytes(&reply) <= MAX_MODEL_VISIBLE_BYTES {
            high = mid;
        } else {
            low = boundary(mid + 1);
        }
    }
    set_tail(&mut reply, low);
    reply
}

/// Measure the exact lean legacy body. Keep refusals' execution state rather
/// than implying that a read which was already sent is safe to retry.
pub(super) fn guard(action: &str, reply: Value, _reads_tool_result_v1: bool) -> Value {
    // Bind capabilities are available for a later negotiation change. GitHub
    // reads still use their existing lean legacy body on every route.
    let format = EffectiveFormat::Legacy;
    if format.fits(&reply) {
        return reply;
    }
    let size = format.model_visible_bytes(&reply).expect("legacy body");
    plexus_core::diag!(warn wire:
        "github_read action {} returned {size} model-visible bytes; refusing oversized reply",
        super::diagnostic_label(action)
    );
    let transmission = reply
        .pointer("/error/transmission")
        .or_else(|| reply.pointer("/error/outcome/transmission"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if reply.get("error").is_some() || action == "github.bindings.list" {
                "not_sent"
            } else {
                "sent"
            }
        });
    reply_guard::fallback(
        format,
        "GitHub read reply exceeds the tool's 65536-byte limit and was not returned; narrow the request with a smaller path, per_page, or page",
        ExecutionState { transmission },
    )
    .expect("GitHub read transmission labels and size refusal fit the legacy limit")
}
