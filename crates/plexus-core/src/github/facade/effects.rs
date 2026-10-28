//! Ordered GitHub mutations and proof that required ownership reads finished
//! before a mutation can be authorized.
use crate::github::facade::request_map::MappedRequest;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipProof {
    kind: String,
    completed: Vec<&'static str>,
}

impl OwnershipProof {
    // Only the code processing GitHub read responses constructs this proof;
    // ordinary invoke callers cannot claim that ownership reads completed.
    pub(crate) fn new(kind: &str, completed: Vec<&'static str>) -> Self {
        Self {
            kind: kind.into(),
            completed,
        }
    }

    pub(crate) fn satisfies(&self, action: &str) -> bool {
        let Some(required) = reads_for_kind(&self.kind) else {
            return false;
        };
        required.iter().all(|read| self.completed.contains(read))
            && effects_for_kind(&self.kind).contains(&action)
    }
}

/// Every request kind the facade routes. The functions below are the single
/// record of what each kind dispatches; the request map, the ownership proof,
/// the dispatch plan and the imported agent grants all read them.
pub const REQUEST_KINDS: &[&str] = &[
    "comment",
    "comment_edit_last",
    "comment_edit",
    "pr_review",
    "reaction",
    "issue_create",
    "issue_edit",
    "pr_create",
    "close",
    "reopen",
    "pr_ready",
    "pr_draft",
    "pr_edit",
    "review_reply",
    "resolve_thread",
    "unresolve_thread",
    "stack_create",
    "stack_add",
    "stack_unstack",
];

/// The catalog action that names a request kind: the write an agent must be
/// granted to make that request at all.
pub fn primary_action(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "comment" => "add_issue_comment",
        "comment_edit_last" | "comment_edit" => "update_issue_comment",
        "pr_review" => "add_pr_review",
        "reaction" => "add_reaction",
        "issue_create" => "create_issue",
        "issue_edit" => "edit_issue",
        "pr_create" => "create_pull_request",
        "close" => "close_issue",
        "reopen" => "reopen_issue",
        "pr_ready" => "mark_pull_request_ready",
        "pr_draft" => "convert_pull_request_to_draft",
        "pr_edit" => "edit_pull_request",
        "review_reply" => "reply_to_review_comment",
        "resolve_thread" => "resolve_review_thread",
        "unresolve_thread" => "unresolve_review_thread",
        "stack_create" => "create_pull_request_stack",
        "stack_add" => "add_to_pull_request_stack",
        "stack_unstack" => "unstack_pull_requests",
        _ => return None,
    })
}

/// Reads that must complete before a request kind may write, in dispatch
/// order. `None` marks a kind the facade does not route.
pub fn reads_for_kind(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "comment_edit_last" => &["github.issue_comments.list", "github.issue_comment.get"],
        "comment_edit" => &["github.issue_comment.get"],
        "issue_edit" => &["github.issue.get"],
        "pr_ready" | "pr_draft" | "pr_edit" | "stack_create" | "stack_add" => {
            &["github.pull_request.get"]
        }
        "resolve_thread" => &["github.review_thread.get", "github.pull_request.get"],
        "unresolve_thread" => &["github.review_thread.get"],
        "stack_unstack" => &["github.stack.get"],
        "comment" | "pr_review" | "reaction" | "issue_create" | "pr_create" | "close"
        | "reopen" | "review_reply" => &[],
        _ => return None,
    })
}

/// Every catalog action a granted `write` lets the facade dispatch on the
/// agent's behalf, excluding the write itself: the reads and extra mutation
/// legs of each request kind that `write` names.
///
/// The facade authorizes each dispatched action against the agent's grant for
/// that exact name, so an agent granted only the write would be refused its
/// own requests. Actions in `grantable` other than `write` are never implied:
/// a close carrying a comment dispatches `add_issue_comment` too, but that
/// ability stays an explicit choice in the inventory.
pub fn implied_by_write(write: &str, grantable: &[&str]) -> BTreeSet<&'static str> {
    REQUEST_KINDS
        .iter()
        .filter(|kind| primary_action(kind) == Some(write))
        .flat_map(|kind| {
            effects_for_kind(kind)
                .iter()
                .chain(reads_for_kind(kind).unwrap_or_default())
                .copied()
        })
        .filter(|action| *action != write && !grantable.contains(action))
        .collect()
}

fn effects_for_kind(kind: &str) -> &'static [&'static str] {
    match kind {
        "comment_edit_last" | "comment_edit" => &["update_issue_comment"],
        "comment" => &["add_issue_comment"],
        "pr_review" => &["add_pr_review"],
        "reaction" => &["add_reaction"],
        "issue_create" => &["create_issue"],
        "pr_create" => &["create_pull_request"],
        "close" => &["add_issue_comment", "close_issue"],
        "reopen" => &["add_issue_comment", "reopen_issue"],
        "pr_ready" => &["mark_pull_request_ready"],
        "pr_draft" => &["convert_pull_request_to_draft"],
        "pr_edit" => &["edit_pull_request"],
        "review_reply" => &["reply_to_review_comment"],
        "resolve_thread" => &["resolve_review_thread"],
        "unresolve_thread" => &["unresolve_review_thread"],
        "stack_create" => &["create_pull_request_stack"],
        "stack_add" => &["add_to_pull_request_stack"],
        "stack_unstack" => &["unstack_pull_requests"],
        "issue_edit" => &[
            "edit_issue",
            "add_issue_labels",
            "remove_issue_label",
            "add_issue_assignees",
            "remove_issue_assignees",
        ],
        _ => &[],
    }
}

pub(super) fn plan(mapped: &MappedRequest) -> Vec<(&'static str, Value)> {
    let args = &mapped.args;
    let mut result = Vec::new();
    match mapped.request_kind.as_str() {
        // A close or reopen carrying a comment posts it first, so the issue
        // explains its change of state; the comment leg needs the agent's own
        // add_issue_comment grant.
        "close" | "reopen" => {
            if let Some(comment) = args.get("comment") {
                let mut comment_args = json!({"owner":args["owner"], "repo":args["repo"], "issue_number":args["issue_number"]});
                comment_args["body"] = comment.clone();
                result.push(("add_issue_comment", comment_args));
            }
            let mut state_args = args.clone();
            state_args
                .as_object_mut()
                .expect("mapped args are an object")
                .remove("comment");
            let state_action = if mapped.request_kind == "close" {
                "close_issue"
            } else {
                "reopen_issue"
            };
            result.push((state_action, state_args));
        }
        "issue_edit" => {
            let fields = args.as_object();
            let base = json!({"owner":args["owner"], "repo":args["repo"], "issue_number":args["issue_number"]});
            let mut edit = base.clone();
            for field in ["title", "body", "labels", "assignees"] {
                if let Some(value) = fields.and_then(|fields| fields.get(field)) {
                    edit[field] = value.clone();
                }
            }
            if edit.as_object().is_some_and(|fields| fields.len() > 3) {
                result.push(("edit_issue", edit));
            }
            if let Some(labels) = fields.and_then(|fields| fields.get("add_labels")) {
                let mut leg = base.clone();
                leg["labels"] = labels.clone();
                result.push(("add_issue_labels", leg));
            }
            if let Some(labels) = fields
                .and_then(|fields| fields.get("remove_labels"))
                .and_then(Value::as_array)
            {
                for label in labels {
                    let mut leg = base.clone();
                    leg["label"] = label.clone();
                    result.push(("remove_issue_label", leg));
                }
            }
            for (field, action) in [
                ("add_assignees", "add_issue_assignees"),
                ("remove_assignees", "remove_issue_assignees"),
            ] {
                if let Some(value) = fields.and_then(|fields| fields.get(field)) {
                    let mut leg = base.clone();
                    leg["assignees"] = value.clone();
                    result.push((action, leg));
                }
            }
        }
        _ => result.push((mapped.action, args.clone())),
    }
    result
}
