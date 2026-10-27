//! Closed translation from the shim's speech vocabulary to governed catalog actions.
use crate::github::facade::effects;
use crate::github::resolver::{self, RequestKind, ResolvedRepositories};
use serde_json::{Map, Value};

/// The reactions a bot request may place: GitHub's full set, and the same
/// list as add_reaction's `content` enum in catalog/github_rest.jsonc. A test
/// in tests/github_catalog.rs compares the two, so neither can change alone.
pub const REACTIONS: &[&str] = &[
    "+1", "-1", "laugh", "confused", "heart", "hooray", "rocket", "eyes",
];

#[derive(Debug, Clone)]
pub struct MappedRequest {
    pub request_kind: String,
    pub action: &'static str,
    pub reads: &'static [&'static str],
    pub canonical: Value,
    pub fingerprint: String,
    pub approval_id: Option<String>,
    pub args: Value,
}

/// A pull request request arrives in the shim's nested shape,
/// `{"action":"pr create","target":{},"body":{title, body, base, head, draft}}`,
/// and in no other: a top-level field or a string `body` would make `body`
/// mean the pull request text in one shape and the field object in the other.
///
/// The head must name a branch of the bound repository itself. GitHub reads
/// `owner:branch` as a branch in another repository of the fork network, so
/// any `:` refuses here, before a receipt is claimed or GitHub is contacted,
/// whatever the caller's own checks did.
fn check_pr_create(object: &Map<String, Value>) -> Result<(), String> {
    for field in ["title", "head", "base", "draft"] {
        if object.contains_key(field) {
            return Err(format!("request_field_forbidden{{field: {field}}}"));
        }
    }
    let Some(fields) = object.get("body").and_then(Value::as_object) else {
        return Err("request_field_forbidden{field: body}".into());
    };
    let branch = |field: &str| {
        fields
            .get(field)
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("request_field_forbidden{{field: {field}}}"))
    };
    let head = branch("head")?;
    if head.contains(':') {
        return Err("pr_head_cross_repository".into());
    }
    let base = branch("base")?;
    // GitHub would refuse a pull request of a branch into itself anyway; it
    // is refused here so the request never reaches GitHub.
    if head == base {
        return Err("request_field_forbidden{field: head}".into());
    }
    Ok(())
}

fn positive_id(value: Option<&Value>, field: &str) -> Result<u64, String> {
    value
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .filter(|number| *number > 0)
        .ok_or_else(|| format!("request_field_forbidden{{field: {field}}}"))
}

/// The gh shim stamps these envelope fields on every `gh.route` request,
/// whatever its kind. They describe the wire and the caller (wire schema
/// version, signed manifest version, trust rung time, process metadata) and
/// never become GitHub arguments, so the closed-shape kinds accept them
/// alongside their own fields.
const SHIM_ENVELOPE_FIELDS: [&str; 5] = [
    "operation",
    "gh_route_schema",
    "manifest_version",
    "rung_as_of_unix_secs",
    "metadata",
];

/// These nested wire shapes have no caller-supplied transport arguments. Even
/// fields ignored by the transport are refused so a typo cannot appear to work.
fn check_nested(object: &Map<String, Value>, kind: &str) -> Result<(), String> {
    for field in object.keys() {
        if !matches!(field.as_str(), "action" | "repository" | "target" | "body")
            && !SHIM_ENVELOPE_FIELDS.contains(&field.as_str())
            && !(kind == "pr_edit" && field == "author_scope")
        {
            return Err(format!("request_field_forbidden{{field: {field}}}"));
        }
    }
    if kind == "pr_edit" && object.get("author_scope").and_then(Value::as_str) != Some("own") {
        return Err("request_field_forbidden{field: author_scope}".into());
    }
    let target = object
        .get("target")
        .and_then(Value::as_object)
        .ok_or("request_field_forbidden{field: target}")?;
    let fields = object
        .get("body")
        .and_then(Value::as_object)
        .ok_or("request_field_forbidden{field: body}")?;
    let (targets, allowed): (&[&str], &[&str]) = match kind {
        // Changing a PR's base retargets what it merges into, which is not
        // speech, so pr edit admits only title and body.
        "pr_edit" => (&["number"], &["title", "body"]),
        "review_reply" => (&["number", "comment_id"], &["body"]),
        "resolve_thread" | "unresolve_thread" => (&["thread_id"], &[]),
        "stack_create" => (&[], &["pull_requests"]),
        "stack_add" => (&["stack_number"], &["pull_requests"]),
        "stack_unstack" => (&["stack_number"], &[]),
        _ => unreachable!("closed nested request kinds"),
    };
    for field in target.keys() {
        if !targets.contains(&field.as_str()) {
            return Err(format!("request_field_forbidden{{field: {field}}}"));
        }
    }
    for field in targets {
        if *field == "thread_id" {
            if !target
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                return Err(format!("request_field_forbidden{{field: {field}}}"));
            }
        } else {
            positive_id(target.get(*field), field)?;
        }
    }
    for (field, value) in fields {
        if !allowed.contains(&field.as_str()) || (field != "pull_requests" && !value.is_string()) {
            return Err(format!("request_field_forbidden{{field: {field}}}"));
        }
    }
    if kind == "pr_edit" && fields.is_empty() {
        return Err("request_field_forbidden{field: body}".into());
    }
    if kind == "review_reply" && !fields.contains_key("body") {
        return Err("request_field_forbidden{field: body}".into());
    }
    if matches!(kind, "stack_create" | "stack_add") {
        let valid = fields
            .get("pull_requests")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                let mut seen = std::collections::BTreeSet::new();
                !items.is_empty()
                    && items.len() <= 50
                    && items
                        .iter()
                        .all(|item| item.as_u64().is_some_and(|n| n > 0 && seen.insert(n)))
            });
        if !valid {
            return Err("request_field_forbidden{field: pull_requests}".into());
        }
    }
    Ok(())
}

pub fn map(
    request: &Value,
    resolved: &ResolvedRepositories,
    repository: &str,
) -> Result<MappedRequest, String> {
    let object = request.as_object().ok_or("request_kind_unmapped")?;
    for field in [
        "repositories",
        "target_repository",
        "path_repository",
        "full_name",
        "owner",
        "repo",
    ] {
        if object.contains_key(field) {
            return Err(format!("request_field_forbidden{{field: {field}}}"));
        }
    }
    let action = object.get("action").and_then(Value::as_str);
    let verb = object.get("verb").and_then(Value::as_str);
    if verb == Some("pr ready") {
        for field in object.keys() {
            if !matches!(field.as_str(), "verb" | "repository" | "number" | "undo")
                && !SHIM_ENVELOPE_FIELDS.contains(&field.as_str())
            {
                return Err(format!("request_field_forbidden{{field: {field}}}"));
            }
        }
        if object.get("undo").and_then(Value::as_bool).is_none() {
            return Err("request_field_forbidden{field: undo}".into());
        }
        if object.get("number").is_none() {
            return Err("request_field_forbidden{field: number}".into());
        }
    }
    let (kind, allowed_kind) = match (
        action,
        verb,
        object.get("edit_last").and_then(Value::as_bool),
    ) {
        (Some("issue comment" | "pr comment"), _, Some(true)) => {
            ("comment_edit_last", RequestKind::CommentEdit)
        }
        (Some("issue comment" | "pr comment"), _, _) => ("comment", RequestKind::Comment),
        (Some("pr review"), _, _) => ("pr_review", RequestKind::PrReview),
        (Some("issue reaction" | "pr reaction"), _, _) => ("reaction", RequestKind::Reaction),
        (Some("issue create"), _, _) => ("issue_create", RequestKind::IssueCreate),
        (Some("pr create"), _, _) => ("pr_create", RequestKind::PrCreate),
        (Some("issue edit"), _, _) => ("issue_edit", RequestKind::IssueEdit),
        (Some("pr edit"), _, _) => ("pr_edit", RequestKind::PrEdit),
        (Some("api:POST:/repos/*/*/pulls/*/comments/*/replies"), _, _) => {
            ("review_reply", RequestKind::ReviewReply)
        }
        (Some("graphql resolvereviewthread"), _, _) => {
            ("resolve_thread", RequestKind::ReviewThread)
        }
        (Some("graphql unresolvereviewthread"), _, _) => {
            ("unresolve_thread", RequestKind::ReviewThread)
        }
        (Some("api:POST:/repos/*/*/stacks"), _, _) => ("stack_create", RequestKind::StackCreate),
        (Some("api:POST:/repos/*/*/stacks/*/add"), _, _) => ("stack_add", RequestKind::StackAdd),
        (Some("api:POST:/repos/*/*/stacks/*/unstack"), _, _) => {
            ("stack_unstack", RequestKind::StackUnstack)
        }
        (Some("api:PATCH:/repos/*/*/issues/comments/*"), _, _) => {
            ("comment_edit", RequestKind::CommentEdit)
        }
        (_, Some("issue close" | "pr close"), _) => ("close", RequestKind::Close),
        (_, Some("issue reopen" | "pr reopen"), _) => ("reopen", RequestKind::Reopen),
        (_, Some("pr ready"), _) => {
            if object["undo"] == true {
                ("pr_draft", RequestKind::PrReady)
            } else {
                ("pr_ready", RequestKind::PrReady)
            }
        }
        _ => return Err("request_kind_unmapped".into()),
    };
    // The catalog action and pre-dispatch reads come from the effects table so
    // the imported agent grants and this map cannot disagree about a kind.
    let (Some(catalog_action), Some(reads)) =
        (effects::primary_action(kind), effects::reads_for_kind(kind))
    else {
        return Err("request_kind_unmapped".into());
    };
    if kind == "close" || kind == "reopen" {
        if object
            .get("comment")
            .is_some_and(|comment| !comment.is_string())
        {
            return Err("request_field_forbidden{field: comment}".into());
        }
        for field in ["body", "title"] {
            if object.contains_key(field) {
                return Err(format!("request_field_forbidden{{field: {field}}}"));
            }
        }
    }
    if kind == "pr_create" {
        check_pr_create(object)?;
    }
    if matches!(
        kind,
        "pr_edit"
            | "review_reply"
            | "resolve_thread"
            | "unresolve_thread"
            | "stack_create"
            | "stack_add"
            | "stack_unstack"
    ) {
        check_nested(object, kind)?;
    }
    if object.get("body").is_some_and(|body| !body.is_object()) {
        return Err("request_field_forbidden{field: body}".into());
    }
    let mut canonical = object.clone();
    for field in [
        "request_nonce",
        "nonce",
        "approval_id",
        "approved_request_id",
        "rung_as_of_unix_secs",
        "timestamp",
        "created_at",
        "updated_at",
    ] {
        canonical.remove(field);
    }
    let canonical = Value::Object(canonical);
    // Hash sorted JSON with exact decimal integers, not the binary64 numbers
    // required by the JSON Canonicalization Scheme used for grant parity.
    // A distinct prefix refuses replay of older receipts: their hashes cannot
    // prove that a large integer in the original request was unchanged.
    // This is serde_json's own sorted text, not `jcs::canonicalize_exact_integers`:
    // the two order some keys and write some numbers differently, and receipts
    // store this value, so switching would need a new prefix.
    let mut exact = canonical.clone();
    exact.sort_all_objects();
    let fingerprint = format!(
        "exact-json-v1:{}",
        crate::jcs::sha256_hex(exact.to_string().as_bytes())
    );
    let mut body = Map::new();
    if let Some(fields) = object.get("body").and_then(Value::as_object) {
        body.extend(fields.clone());
    }
    for field in ["title", "comment", "reason", "content"] {
        if let Some(value) = object.get(field) {
            body.insert(field.into(), value.clone());
        }
    }
    if let Some(reaction) = body.remove("reaction") {
        body.insert("content".into(), reaction);
    }
    for field in ["issue_number", "pull_number", "comment_id"] {
        if body.contains_key(field) {
            return Err(format!("request_field_forbidden{{field: {field}}}"));
        }
    }
    if kind == "close" {
        body.insert("state".into(), Value::String("closed".into()));
        if let Some(reason) = body.remove("reason") {
            body.insert("state_reason".into(), reason);
        }
    } else if kind == "reopen" {
        body.insert("state".into(), Value::String("open".into()));
    } else if kind == "pr_review" {
        // GitHub files a review with no event as PENDING, a draft only its
        // author can see, so a posted review must name one of the three events.
        if !matches!(
            body.get("event").and_then(Value::as_str),
            Some("COMMENT" | "APPROVE" | "REQUEST_CHANGES")
        ) {
            return Err("request_field_forbidden{field: event}".into());
        }
    } else if kind == "reaction" {
        // Nothing validates the catalog's args_schema at dispatch, and the REST
        // transport sends every argument, so the reaction vocabulary is
        // enforced here, before any vendor call.
        if !body
            .get("content")
            .and_then(Value::as_str)
            .is_some_and(|content| REACTIONS.contains(&content))
        {
            return Err("request_field_forbidden{field: reaction}".into());
        }
    } else if kind == "issue_edit" {
        for field in [
            "labels",
            "assignees",
            "add_labels",
            "remove_labels",
            "add_assignees",
            "remove_assignees",
        ] {
            if body.get(field).is_some_and(|value| {
                !value
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
            }) {
                return Err(format!("request_field_forbidden{{field: {field}}}"));
            }
        }
        // Changing state here would bypass the close and reopen kinds, with
        // their reason and comment rules; milestone is not part of the shim's
        // issue-edit shape or the edit_issue schema.
        for field in ["state", "milestone"] {
            if body.contains_key(field) {
                return Err(format!("request_field_forbidden{{field: {field}}}"));
            }
        }
    }
    if let Some(number) = request
        .pointer("/target/number")
        .or_else(|| object.get("number"))
    {
        let parsed = number
            .as_u64()
            .or_else(|| number.as_str().and_then(|s| s.parse().ok()))
            .ok_or("request_kind_unmapped")?;
        // The review endpoint addresses the pull request as pull_number.
        let field = if matches!(
            kind,
            "pr_review" | "pr_ready" | "pr_draft" | "pr_edit" | "review_reply"
        ) {
            "pull_number"
        } else {
            "issue_number"
        };
        body.insert(field.into(), Value::from(parsed));
    }
    if let Some(id) = request.pointer("/target/comment_id") {
        let parsed = id
            .as_u64()
            .or_else(|| id.as_str().and_then(|s| s.parse().ok()))
            .ok_or("request_kind_unmapped")?;
        body.insert("comment_id".into(), Value::from(parsed));
    }
    if let Some(id) = request.pointer("/target/thread_id") {
        body.insert("thread_id".into(), id.clone());
    }
    if let Some(number) = request.pointer("/target/stack_number") {
        body.insert(
            "stack_number".into(),
            Value::from(positive_id(Some(number), "stack_number")?),
        );
    }
    let args = resolver::mapped_args(resolved, repository, &Value::Object(body), allowed_kind)
        .map_err(|_| "repository_unbound")?;
    Ok(MappedRequest {
        request_kind: kind.into(),
        action: catalog_action,
        reads,
        canonical,
        fingerprint,
        approval_id: request
            .get("approval_id")
            .or_else(|| request.get("approved_request_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Receipts store this fingerprint and a replayed request is matched by
    /// it, so its bytes must not move. The literal is SHA-256 of the sorted
    /// compact JSON text, computed outside plexus.
    #[test]
    fn request_fingerprint_is_pinned_and_differs_from_jcs() {
        let resolved = ResolvedRepositories {
            repositories: vec!["org/repo".into()],
            binding: crate::github::resolver::Binding {
                app_handle_id: "app".into(),
                connection_id: "conn".into(),
            },
        };
        let request = serde_json::json!({
            "action": "issue comment",
            "number": 18_446_744_073_709_551_615_u64,
            "comment": "héllo 😀",
            "metadata": {"\u{E000}": 1, "\u{1F600}": 2.5},
            "request_nonce": "nonce-1",
        });
        let mapped = map(&request, &resolved, "org/repo").unwrap();
        assert_eq!(
            mapped.fingerprint,
            "exact-json-v1:13e467821cea1b4cfe7bad64d15b37c2e4cfb99c20ed5ba262b52dd2fd4ab77c",
            "the stored receipt fingerprint must not move"
        );
        // RFC 8785 orders U+1F600 before U+E000, so the JCS form is other bytes.
        let jcs = crate::jcs::canonicalize_exact_integers(&mapped.canonical).unwrap();
        assert_ne!(
            mapped.fingerprint,
            format!("exact-json-v1:{}", crate::jcs::sha256_hex(&jcs))
        );
    }

    #[test]
    fn request_body_must_be_an_object() {
        let resolved = ResolvedRepositories {
            repositories: vec!["org/repo".into()],
            binding: crate::github::resolver::Binding {
                app_handle_id: "app".into(),
                connection_id: "conn".into(),
            },
        };
        for body in [
            serde_json::json!("text"),
            Value::Null,
            serde_json::json!([]),
        ] {
            let mapped = map(
                &serde_json::json!({"action":"issue create","title":"title","body":body}),
                &resolved,
                "org/repo",
            );
            assert!(
                mapped.is_err(),
                "non-object body must not be silently dropped"
            );
            let error = mapped.unwrap_err();
            assert_eq!(
                error, "request_field_forbidden{field: body}",
                "non-object body must not be silently dropped"
            );
        }
    }
}
