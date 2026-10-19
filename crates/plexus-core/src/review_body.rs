//! Bounded review text shared by webhook notices and review-thread reads.

use serde_json::{json, Value};

pub(crate) fn excerpt(body: Option<&str>) -> (Value, Value) {
    match body {
        Some(body) => {
            let mut chars = body.chars();
            let excerpt: String = chars.by_ref().take(1_500).collect();
            (json!(excerpt), json!(chars.next().is_some()))
        }
        None => (Value::Null, Value::Null),
    }
}

pub(crate) fn notice(kind: &str, key: &str, repo: &str, webhook: &Value) -> Value {
    let review = kind == crate::event_key::GITHUB_PR_REVIEW_SUBMITTED;
    let item = &webhook[if review { "review" } else { "comment" }];
    let text = |pointer| item.pointer(pointer).and_then(Value::as_str);
    let (excerpt, truncated) = excerpt(text("/body"));
    let mut body = json!({
        "event_key": key,
        "kind": if review { "pull_request_review" } else { "pull_request_review_comment" },
        "repo": repo.to_ascii_lowercase(),
        "pr": webhook.pointer("/pull_request/number").and_then(Value::as_u64),
        "head_sha": webhook.pointer("/pull_request/head/sha").and_then(Value::as_str),
        "body_excerpt": excerpt, "body_truncated": truncated,
    });
    let bot = text("/user/type").map(|kind| kind == "Bot");
    if review {
        body["reviewer_login"] = json!(text("/user/login"));
        body["reviewer_is_bot"] = json!(bot);
        body["state"] = json!(text("/state").map(str::to_lowercase));
        body["review_id"] = json!(item["id"].as_u64());
        body["review_url"] = json!(text("/html_url"));
        body["submitted_at"] = json!(text("/submitted_at"));
    } else {
        body["author_login"] = json!(text("/user/login"));
        body["author_is_bot"] = json!(bot);
        for field in ["line", "original_line", "in_reply_to_id"] {
            body[field] = json!(item[field].as_u64());
        }
        for field in ["path", "side", "created_at"] {
            body[field] = json!(item[field].as_str());
        }
        body["comment_id"] = json!(item["id"].as_u64());
        body["review_id"] = json!(item["pull_request_review_id"].as_u64());
        body["comment_url"] = json!(text("/html_url"));
    }
    body
}
