use super::model::{
    AgentPolicy, Approval, Class, Kind, Operation, OwnershipCheck, Request, RuleSet,
};
use crate::github::facade::effects::{
    effects_for_kind, optional_effect, reads_for_kind, REQUEST_KINDS,
};
use crate::manifest::{ActionBaseline, HttpMethod, HttpOperation};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CheckedGitHub {
    pub served: Vec<String>,
    pub unserved: Vec<Unserved>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Unserved {
    pub name: String,
    pub reason: &'static str,
}

pub fn check_github(policy: &AgentPolicy, catalog: &[ActionBaseline]) -> CheckedGitHub {
    policy
        .rule_sets
        .github
        .as_ref()
        .map_or_else(CheckedGitHub::default, |rules| {
            check_rule_set(rules, catalog)
        })
}

pub(super) fn check_rule_set(rules: &RuleSet, catalog: &[ActionBaseline]) -> CheckedGitHub {
    let catalog: BTreeMap<_, _> = catalog
        .iter()
        .filter_map(|action| Some((action.name.as_str(), action.http.as_ref()?)))
        .collect();
    let kinds: BTreeMap<_, _> = rules.kinds.iter().map(|k| (k.kind.as_str(), k)).collect();
    let mut checked = CheckedGitHub::default();
    let mut matching_kinds = BTreeSet::new();
    for kind in &rules.kinds {
        match kind_reason(kind, catalog.get(kind.kind.as_str()).copied()) {
            Some(reason) => checked.unserved.push(Unserved {
                name: kind.kind.clone(),
                reason,
            }),
            None => {
                matching_kinds.insert(kind.kind.as_str());
            }
        }
    }
    for action in &rules.actions {
        let reason = check_action(action, &kinds, &matching_kinds);
        if let Some(reason) = reason {
            checked.unserved.push(Unserved {
                name: action.action.clone(),
                reason,
            });
        } else {
            checked.served.push(action.action.clone());
        }
    }
    checked.served.sort_unstable();
    checked.unserved.sort_unstable();
    checked
}

fn kind_reason(kind: &Kind, http: Option<&HttpOperation>) -> Option<&'static str> {
    if kind.class == Class::Denied {
        return Some("policy_kind_denied");
    }
    let Some(http) = http else {
        return Some("policy_kind_not_catalogued");
    };
    if kind.class == Class::Read && kind.approval == Approval::Once {
        return Some("policy_approval_unsupported");
    }
    if kind.requests.is_empty() {
        return Some(if http.path == "/graphql" {
            "policy_graphql_mismatch"
        } else {
            "policy_rest_mismatch"
        });
    }
    for request in &kind.requests {
        match request {
            Request::Rest(rest) => {
                if http.path == "/graphql"
                    || rest.method != method_name(http.method)
                    || !paths_match(&http.path, &rest.path)
                {
                    return Some("policy_rest_mismatch");
                }
            }
            Request::Graphql(graphql) => {
                let root = http
                    .request_constants
                    .as_ref()
                    .and_then(|constants| constants.get("query"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(fixed_query_root);
                if http.path != "/graphql"
                    || http.method != HttpMethod::Post
                    || !root.is_some_and(|(operation, field)| {
                        operation == graphql.operation && graphql.fields == [field]
                    })
                {
                    return Some("policy_graphql_mismatch");
                }
            }
        }
    }
    None
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
    }
}

fn paths_match(catalog: &str, policy: &str) -> bool {
    let (Some(catalog), Some(policy)) = (catalog.strip_prefix('/'), policy.strip_prefix('/'))
    else {
        return false;
    };
    let mut policy = policy.split('/');
    catalog.split('/').all(|segment| {
        let typed = match segment {
            "{owner}" | "{repo}" => segment,
            "{issue_number}" | "{pull_number}" | "{stack_number}" => "{number}",
            "{comment_id}" | "{job_id}" => "{id}",
            "{label}" => "{name}",
            literal if !literal.contains(['{', '}']) => literal,
            _ => return false,
        };
        policy.next() == Some(typed)
    }) && policy.next().is_none()
}

// Only the catalog's fixed documents reach this reader, not arbitrary GraphQL.
// Require one explicit operation with one unaliased root field; anything outside
// that reviewed form (including a second root or an operation directive) fails.
fn fixed_query_root(text: &str) -> Option<(Operation, &str)> {
    fn identifier(text: &str) -> (&str, &str) {
        let text = text.trim_start();
        text.split_at(
            text.find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(text.len()),
        )
    }
    fn skip_group(text: &str, open: char, close: char) -> Option<&str> {
        let mut depth = 0;
        for (index, character) in text.char_indices() {
            if character == open {
                depth += 1;
            } else if character == close {
                depth -= 1;
                if depth == 0 {
                    return Some(text[index + 1..].trim_start());
                }
            }
        }
        None
    }

    // Quotes and comments can contain braces or parentheses without delimiting
    // groups. None of the fixed queries use them.
    if text.contains(['"', '#']) {
        return None;
    }
    let (operation, rest) = identifier(text);
    let operation = match operation {
        "query" => Operation::Query,
        "mutation" => Operation::Mutation,
        _ => return None,
    };
    let mut rest = rest.trim_start();
    if rest.starts_with('(') {
        rest = skip_group(rest, '(', ')')?;
    }
    let (field, rest) = identifier(rest.strip_prefix('{')?);
    if field.is_empty() || field.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut rest = rest.trim_start();
    if rest.starts_with('(') {
        rest = skip_group(rest, '(', ')')?;
    }
    if rest.starts_with('{') {
        rest = skip_group(rest, '{', '}')?;
    }
    (rest.trim_end() == "}").then_some((operation, field))
}

fn check_action(
    action: &super::model::Action,
    kinds: &BTreeMap<&str, &Kind>,
    matching: &BTreeSet<&str>,
) -> Option<&'static str> {
    let name = action.action.as_str();
    if !REQUEST_KINDS.contains(&name) {
        return Some("policy_action_unknown");
    }
    let effects = effects_for_kind(name);
    if action.legs.len() != effects.len()
        || action.legs.iter().zip(effects).any(|(leg, &effect)| {
            leg.kind != effect || leg.optional != optional_effect(name, effect)
        })
    {
        return Some("policy_legs_mismatch");
    }
    if action.legs.iter().any(|leg| {
        kinds
            .get(leg.kind.as_str())
            .is_some_and(|kind| kind.approval == Approval::Once)
    }) {
        return Some("policy_approval_unsupported");
    }
    for leg in &action.legs {
        let leg = leg.kind.as_str();
        if !matching.contains(leg) || kinds[leg].class == Class::Read {
            return Some("policy_leg_unserved");
        }
        if !ownership_matches(name, kinds[leg], kinds, matching) {
            return Some("policy_ownership_mismatch");
        }
    }
    None
}

fn ownership_matches(
    action: &str,
    kind: &Kind,
    kinds: &BTreeMap<&str, &Kind>,
    matching: &BTreeSet<&str>,
) -> bool {
    use OwnershipCheck::*;
    let enforced = match action {
        "comment_edit" => OwnComment,
        "comment_edit_last" => OwnLastComment,
        "issue_edit" => OwnIssue,
        "pr_ready" | "pr_draft" | "pr_edit" | "pr_enqueue" | "pr_dequeue" => OwnPullRequest,
        "stack_create" | "stack_add" => OwnPullRequests,
        "stack_unstack" => OwnStackPullRequests,
        "resolve_thread" => OwnThreadPullRequest,
        "unresolve_thread" => ThreadInRepository,
        _ => return kind.ownership.is_none(),
    };
    let Some(ownership) = &kind.ownership else {
        return false;
    };
    let reads = reads_for_kind(action).unwrap_or_default();
    let expected_reads = match (enforced, ownership.check) {
        // Selecting the App's latest comment also proves the selected comment
        // belongs to the App. The weaker policy check needs only the item read.
        (OwnLastComment, OwnComment) => &reads[1..],
        (actual, floor) if actual == floor => reads,
        _ => return false,
    };
    ownership.reads == expected_reads
        && reads
            .iter()
            .all(|read| matching.contains(read) && kinds[*read].class == Class::Read)
}
