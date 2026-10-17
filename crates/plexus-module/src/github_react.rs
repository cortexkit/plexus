//! Arguments of the `github_react` facade tool.
//!
//! `github_react` adds one reaction to an issue or pull request as the acting
//! agent's own bot. It exists so a flow can be given that one effect: Basal
//! grants flows whole tools, and granting the `github` tool would also give
//! every other bot write its `bot_request` operation can reach.
//!
//! This module only checks the tool's closed argument shape and builds the
//! request that the `github` tool's `bot_request` would receive for the same
//! reaction. The facade then sends that request through the one bot request
//! path, `plexus_core::github::facade::bot_request_scoped`, so the gates,
//! grants, receipts, nonce rules, transport and refusals are shared rather
//! than repeated here.

use plexus_core::github::facade::request_map::REACTIONS;
use serde_json::{json, Map, Value};

/// The top-level arguments `github_react` accepts; every one is required.
const FIELDS: &[&str] = &["repository", "kind", "target", "reaction", "request_nonce"];

/// A `github_react` call translated into the `github` tool's bot request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReactionRequest {
    /// The `request` object a `bot_request` call would carry.
    pub(crate) request: Value,
    pub(crate) request_nonce: String,
}

fn refuse(field: &str, message: String) -> Value {
    json!({"error": {
        "code": "invalid_request",
        "field": field,
        "message": message,
        "transmission": "not_sent",
    }})
}

/// Check `github_react`'s arguments and build the bot request they stand for.
///
/// Every key outside the declared shape, at the top level or inside
/// `target`, is refused by name, and so is a missing or ill-typed value. The
/// only actions the result can name are `issue reaction` and `pr reaction`,
/// both of which the bot request map sends as `add_reaction`.
pub(crate) fn reaction_request(arguments: &Map<String, Value>) -> Result<ReactionRequest, Value> {
    if let Some(field) = arguments
        .keys()
        .find(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err(refuse(
            field,
            format!("github_react does not accept the field {field}"),
        ));
    }
    if let Some(field) = FIELDS.iter().find(|field| !arguments.contains_key(**field)) {
        return Err(refuse(field, format!("github_react requires {field}")));
    }
    let repository = arguments["repository"]
        .as_str()
        .filter(|repository| !repository.is_empty())
        .ok_or_else(|| {
            refuse(
                "repository",
                "repository must be a non-empty owner/name string".into(),
            )
        })?;
    let action = match arguments["kind"].as_str() {
        Some("issue") => "issue reaction",
        Some("pr") => "pr reaction",
        _ => return Err(refuse("kind", "kind must be issue or pr".into())),
    };
    let target = arguments["target"]
        .as_object()
        .ok_or_else(|| refuse("target", "target must be an object".into()))?;
    if let Some(field) = target.keys().find(|field| field.as_str() != "number") {
        let field = format!("target.{field}");
        return Err(refuse(
            &field,
            format!("github_react does not accept the field {field}"),
        ));
    }
    let number = target
        .get("number")
        .and_then(Value::as_u64)
        .filter(|number| *number > 0)
        .ok_or_else(|| {
            refuse(
                "target.number",
                "target.number must be a positive integer".into(),
            )
        })?;
    let reaction = arguments["reaction"]
        .as_str()
        .filter(|reaction| REACTIONS.contains(reaction))
        .ok_or_else(|| {
            refuse(
                "reaction",
                format!("reaction must be one of {}", REACTIONS.join(", ")),
            )
        })?;
    let request_nonce = arguments["request_nonce"]
        .as_str()
        .filter(|nonce| !nonce.is_empty())
        .ok_or_else(|| {
            refuse(
                "request_nonce",
                "request_nonce must be a non-empty string".into(),
            )
        })?;
    Ok(ReactionRequest {
        request: json!({
            "action": action,
            "repository": repository,
            "target": {"number": number},
            "body": {"reaction": reaction},
        }),
        request_nonce: request_nonce.to_owned(),
    })
}
