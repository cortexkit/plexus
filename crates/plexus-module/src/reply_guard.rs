//! Final-body accounting. Callers choose the negotiated format and supply the
//! actual execution state; this module never infers either from a reply's shape.

use cortexkit_role_tool_provider::result::{
    self, ContentPart, ToolResult, MAX_MODEL_VISIBLE_BYTES, MAX_RESULT_BYTES,
};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug)]
pub(super) enum EffectiveFormat {
    Legacy,
    ToolResultV1,
}

impl EffectiveFormat {
    pub(super) fn model_visible_bytes(self, body: &Value) -> Option<usize> {
        match self {
            Self::Legacy => Some(result::legacy_model_visible_bytes(body)),
            Self::ToolResultV1 => {
                let reply: ToolResult = serde_json::from_value(body.clone()).ok()?;
                result::validate(&reply).ok()?;
                // Decoding ToolResult ignores extension members. Measure the
                // final body too, so extensions cannot evade the transport cap.
                if serde_json::to_vec(body).ok()?.len() >= MAX_RESULT_BYTES {
                    return None;
                }
                Some(result::model_visible_bytes(&reply))
            }
        }
    }

    pub(super) fn fits(self, body: &Value) -> bool {
        self.model_visible_bytes(body)
            .is_some_and(|bytes| bytes <= MAX_MODEL_VISIBLE_BYTES)
    }
}

/// The producer's transmission vocabulary is preserved verbatim, including
/// completed and outcome-unknown writes. Only the producer knows what ran.
#[derive(Clone, Copy, Serialize)]
pub(super) struct ExecutionState<'a> {
    pub(super) transmission: &'a str,
}

#[derive(Serialize)]
struct ResponseTooLarge<'a> {
    code: &'static str,
    message: &'static str,
    #[serde(flatten)]
    execution: ExecutionState<'a>,
}

/// Return only a validated, measured fallback. An unbounded execution label or
/// message is a caller error, not permission to emit another oversized body.
pub(super) fn fallback(
    format: EffectiveFormat,
    message: &'static str,
    execution: ExecutionState<'_>,
) -> Option<Value> {
    let error = ResponseTooLarge {
        code: "response_too_large",
        message,
        execution,
    };
    let facade = json!({"error": error});
    let body = match format {
        EffectiveFormat::Legacy => facade,
        EffectiveFormat::ToolResultV1 => serde_json::to_value(
            ToolResult::new(vec![ContentPart::text(message)])
                .with_error("response_too_large")
                .with_structured_content(facade.as_object()?.clone()),
        )
        .ok()?,
    };
    format.fits(&body).then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusive_boundaries_use_the_explicit_format() {
        for size in [65_535, 65_536, 65_537] {
            let legacy_string = json!("x".repeat(size));
            // {"text":""} has eleven bytes of canonical JSON overhead.
            let legacy_object = json!({"text": "x".repeat(size - 11)});
            let negotiated = json!({"content": [{"type":"text", "text":"x".repeat(size)}]});
            for (format, body) in [
                (EffectiveFormat::Legacy, legacy_string),
                (EffectiveFormat::Legacy, legacy_object),
                (EffectiveFormat::ToolResultV1, negotiated),
            ] {
                assert_eq!(format.model_visible_bytes(&body), Some(size));
                assert_eq!(format.fits(&body), size <= 65_536);
            }
        }
        let looks_negotiated = json!({"content":[{"type":"text","text":"ok"}],
            "structuredContent":{"large":"x".repeat(65_536)}});
        assert!(EffectiveFormat::ToolResultV1.fits(&looks_negotiated));
        assert!(!EffectiveFormat::Legacy.fits(&looks_negotiated));
    }

    #[test]
    fn escaping_and_four_byte_utf8_count_decoded_text_or_canonical_json() {
        let text = "\"\\\n\u{0001}🦀";
        assert_eq!(text.len(), 8);
        assert_eq!(
            EffectiveFormat::Legacy.model_visible_bytes(&json!(text)),
            Some(8)
        );
        assert_eq!(
            EffectiveFormat::Legacy.model_visible_bytes(&json!({"text":text})),
            Some(27)
        );
        let negotiated = json!({"content":[{"type":"text","text":text}]});
        assert_eq!(
            EffectiveFormat::ToolResultV1.model_visible_bytes(&negotiated),
            Some(8)
        );
        let alternate_escapes: Value =
            serde_json::from_str(r#"{"text":"\u0022\u005c\u000a\u0001\ud83e\udd80"}"#).unwrap();
        assert_eq!(alternate_escapes, json!({"text":text}));
        assert_eq!(
            EffectiveFormat::Legacy.model_visible_bytes(&alternate_escapes),
            Some(27)
        );
    }

    #[test]
    fn unknown_content_counts_but_images_and_structured_content_do_not() {
        let body = json!({"content":[
            {"type":"text","text":"🦀"},
            {"type":"future","payload":"\u{0001}"},
            {"type":"image","mimeType":"image/png","data":"AA==","width":1,"height":1,"alt":"ignored"}
        ], "structuredContent":{"ignored":"x".repeat(70_000)}});
        // Unknown part: {"payload":"\u0001","type":"future"} = 36 bytes.
        assert_eq!(
            EffectiveFormat::ToolResultV1.model_visible_bytes(&body),
            Some(40)
        );
    }

    #[test]
    fn negotiated_shape_and_final_serialized_body_are_checked() {
        assert!(!EffectiveFormat::ToolResultV1.fits(&json!({"content":[]})));
        assert!(!EffectiveFormat::ToolResultV1
            .fits(&json!({"content":[{"type":"text","text":"ok"}], "isError":true})));
        let mut body = json!({"content":[{"type":"text","text":"ok"}], "extension":""});
        let overhead = serde_json::to_vec(&body).unwrap().len();
        body["extension"] = json!("x".repeat(MAX_RESULT_BYTES - overhead - 1));
        assert!(EffectiveFormat::ToolResultV1.fits(&body));
        body["extension"] = json!("x".repeat(MAX_RESULT_BYTES - overhead));
        assert!(!EffectiveFormat::ToolResultV1.fits(&body));
    }

    #[test]
    fn fallbacks_fit_and_never_infer_unsent_from_discarded_output() {
        for transmission in ["not_sent", "sent", "completed", "outcome_unknown", "failed"] {
            for format in [EffectiveFormat::Legacy, EffectiveFormat::ToolResultV1] {
                let body = fallback(
                    format,
                    "Output discarded because it was too large.",
                    ExecutionState { transmission },
                )
                .unwrap();
                assert!(format.fits(&body));
                let error = match format {
                    EffectiveFormat::Legacy => &body["error"],
                    EffectiveFormat::ToolResultV1 => {
                        assert_eq!(body["isError"], true);
                        assert_eq!(body["errorCode"], "response_too_large");
                        &body["structuredContent"]["error"]
                    }
                };
                assert_eq!(error["code"], "response_too_large");
                assert_eq!(error["transmission"], transmission);
            }
        }
        assert!(fallback(
            EffectiveFormat::Legacy,
            "Output discarded.",
            ExecutionState {
                transmission: &"x".repeat(65_536)
            }
        )
        .is_none());
    }
}
