use super::check::check_rule_set;
use super::model::{parse_exact, RuleSet};
use super::wire::decode_active;
use super::*;
use crate::manifest::AppManifest;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SEED: &str = include_str!("../../../tests/fixtures/vault-wire/agent-policy-v1/github.json");
const SEED_SHA256: &str = "aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7";

fn golden(name: &str) -> Value {
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(
                "../../../tests/fixtures/vault-wire/agent-policy-v1/",
                $name,
                ".json"
            ))
        };
    }
    let (json, sha256) = match name {
        "policy.active.none" => (
            fixture!("policy.active.none"),
            "3c0ebdb32b66ece759f5baee3e3dae552da9ce4224747a20b60011a63f87ca59",
        ),
        "policy.active.ready" => (
            fixture!("policy.active.ready"),
            "9aeb3035ac9cb7b5e71cafce723bf29de77a2ff49f4cadc197e800339c27e166",
        ),
        "policy.watch.initial" => (
            fixture!("policy.watch.initial"),
            "b7b4d16d9a8a6905bf91b07177844dad19b90fc599ef20adc717bbf37b07eca6",
        ),
        "policy.watch.changed" => (
            fixture!("policy.watch.changed"),
            "b270cf61622a0ee32a79b8b5f8c43e5f6a18c9855c232568d6ec74ba2ce67e2e",
        ),
        _ => panic!("unknown policy golden {name}"),
    };
    assert_eq!(format!("{:x}", Sha256::digest(json)), sha256, "{name}");
    serde_json::from_str(json).unwrap()
}

fn catalog() -> AppManifest {
    let source = include_str!("../../../../../catalog/github_rest.jsonc");
    serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap()
}

fn signed_document() -> Value {
    let mut rules: Value = serde_json::from_str(SEED).unwrap();
    rules["source"] = json!({"release":"cortexkit-defaults-2026.11","sha256":SEED_SHA256});
    json!({
        "schema":"ck-agent-policy/v1",
        "version":3,
        "issued_at_unix_secs":7,
        "root_key_id":"1234567890abcdef",
        "rule_sets":{"github":rules},
        "bindings":[]
    })
}

fn row<'a>(document: &'a mut Value, collection: &str, key: &str, name: &str) -> &'a mut Value {
    document["rule_sets"]["github"][collection]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row[key] == name)
        .unwrap()
}

fn kind<'a>(document: &'a mut Value, name: &str) -> &'a mut Value {
    row(document, "kinds", "kind", name)
}

fn action<'a>(document: &'a mut Value, name: &str) -> &'a mut Value {
    row(document, "actions", "action", name)
}

fn checked(document: &Value) -> CheckedGitHub {
    let document = AgentPolicy::parse(&document.to_string()).unwrap();
    check_github(&document, &catalog().actions_baseline)
}

fn refused(result: &CheckedGitHub, name: &str, reason: &str) {
    assert!(!result.served.iter().any(|served| served == name));
    assert!(
        result
            .unserved
            .iter()
            .any(|u| u.name == name && u.reason == reason),
        "expected {name} refused as {reason}: {:?}",
        result.unserved
    );
}

#[test]
fn vault_active_and_watch_goldens_decode() {
    assert!(decode_active(golden("policy.active.none"))
        .unwrap()
        .is_none());
    let active = decode_active(golden("policy.active.ready"))
        .unwrap()
        .unwrap();
    assert_eq!(active.policy.version, 1);
    assert_eq!(active.manifest_version, 41);
    assert_eq!(active.policy.bindings[0].identity, "github_app:agent");
    assert_eq!(active.policy.bindings[0].resources, ["org/r"]);
    let initial = WatchNotice::decode(golden("policy.watch.initial")).unwrap();
    let changed = WatchNotice::decode(golden("policy.watch.changed")).unwrap();
    assert_eq!(initial.epoch, "00112233445566778899aabbccddeeff");
    assert_eq!(initial.epoch, changed.epoch);
    assert_eq!(
        (initial.seq, initial.version, initial.policy_sha256),
        (1, None, None)
    );
    assert_eq!(
        (changed.seq, changed.version),
        (2, Some(active.policy.version))
    );
    assert_eq!(
        changed.policy_sha256.as_deref(),
        Some(active.policy_sha256.as_str())
    );
}

#[test]
fn active_rejects_partial_null_or_inconsistent_metadata() {
    let mut reply = golden("policy.active.none");
    reply["result"]["manifest_version"] = json!(41);
    assert_eq!(decode_active(reply).unwrap_err(), ReadFailure::Unreadable);
    let mut reply = golden("policy.active.none");
    reply["result"].as_object_mut().unwrap().remove("version");
    assert_eq!(decode_active(reply).unwrap_err(), ReadFailure::Unreadable);
    let mut reply = golden("policy.active.ready");
    reply["result"]["version"] = json!(2);
    assert_eq!(decode_active(reply).unwrap_err(), ReadFailure::Unreadable);
    let mut reply = golden("policy.active.ready");
    reply["result"]["policy_sha256"] = json!("0".repeat(64));
    assert_eq!(decode_active(reply).unwrap_err(), ReadFailure::Unreadable);
}

#[test]
fn seeded_github_actions_and_unserved_kinds_are_pinned() {
    assert_eq!(format!("{:x}", Sha256::digest(SEED)), SEED_SHA256);
    let rules: RuleSet = parse_exact(SEED).unwrap();
    let result = check_rule_set(&rules, &catalog().actions_baseline);
    assert_eq!(
        result.served,
        [
            "close",
            "comment",
            "comment_edit",
            "comment_edit_last",
            "issue_create",
            "issue_edit",
            "pr_create",
            "pr_dequeue",
            "pr_draft",
            "pr_edit",
            "pr_enqueue",
            "pr_ready",
            "pr_review",
            "reaction",
            "reopen",
            "resolve_thread",
            "review_reply",
            "stack_add",
            "stack_create",
            "stack_unstack",
            "unresolve_thread",
        ]
    );
    assert_eq!(
        result.unserved,
        [Unserved {
            name: "node_repository".into(),
            reason: "policy_kind_not_catalogued"
        }]
    );
    let mut reordered = signed_document();
    for collection in ["kinds", "actions"] {
        reordered["rule_sets"]["github"][collection]
            .as_array_mut()
            .unwrap()
            .reverse();
    }
    assert_eq!(checked(&reordered), result);
}

#[test]
fn a_wrong_rest_path_refuses_the_kind_and_its_actions_by_name() {
    let mut document = signed_document();
    let rest = &mut kind(&mut document, "add_issue_comment")["requests"][0]["rest"];
    rest["path"] = json!("/repos/{owner}/{repo}/issues/{id}/comments");
    let result = checked(&document);
    refused(&result, "add_issue_comment", "policy_rest_mismatch");
    refused(&result, "comment", "policy_leg_unserved");
    assert!(result.served.contains(&"comment_edit".into()));
}

#[test]
fn a_wrong_graphql_root_or_operation_refuses_the_kind_by_name() {
    let mut document = signed_document();
    let graphql = &mut kind(&mut document, "resolve_review_thread")["requests"][0]["graphql"];
    graphql["fields"] = json!(["unresolveReviewThread"]);
    refused(
        &checked(&document),
        "resolve_review_thread",
        "policy_graphql_mismatch",
    );
    let graphql = &mut kind(&mut document, "resolve_review_thread")["requests"][0]["graphql"];
    graphql["fields"] = json!(["resolveReviewThread"]);
    graphql["operation"] = json!("query");
    refused(
        &checked(&document),
        "resolve_review_thread",
        "policy_graphql_mismatch",
    );
    kind(&mut document, "resolve_review_thread")["requests"] = json!([
        {"rest":{"method":"POST","host":"api.github.com","path":"/graphql"}}
    ]);
    refused(
        &checked(&document),
        "resolve_review_thread",
        "policy_rest_mismatch",
    );
}

#[test]
fn wrong_leg_order_or_optionality_refuses_the_action_by_name() {
    let mut document = signed_document();
    let legs = action(&mut document, "close")["legs"]
        .as_array_mut()
        .unwrap();
    legs.swap(0, 1);
    refused(&checked(&document), "close", "policy_legs_mismatch");
    let legs = action(&mut document, "close")["legs"]
        .as_array_mut()
        .unwrap();
    legs.swap(0, 1);
    legs[0]["optional"] = json!(false);
    refused(&checked(&document), "close", "policy_legs_mismatch");
}

#[test]
fn missing_ownership_refuses_both_comment_edits_by_name() {
    let mut document = signed_document();
    kind(&mut document, "update_issue_comment")["ownership"] = Value::Null;
    let result = checked(&document);
    refused(&result, "comment_edit", "policy_ownership_mismatch");
    refused(&result, "comment_edit_last", "policy_ownership_mismatch");
}

#[test]
fn an_optional_once_leg_still_refuses_the_action_by_name() {
    let mut document = signed_document();
    let comment = kind(&mut document, "add_issue_comment");
    comment["approval"] = json!("once");
    comment["consent"] = json!({"fields":["body"]});
    let result = checked(&document);
    refused(&result, "comment", "policy_approval_unsupported");
    refused(&result, "close", "policy_approval_unsupported");
}

#[test]
fn a_once_read_is_unserved_and_cannot_satisfy_an_ownership_check() {
    let mut document = signed_document();
    let issue = kind(&mut document, "github.issue.get");
    issue["approval"] = json!("once");
    issue["consent"] = json!({"fields":["number"]});
    let result = checked(&document);
    refused(&result, "github.issue.get", "policy_approval_unsupported");
    refused(&result, "issue_edit", "policy_ownership_mismatch");
}

#[test]
fn denied_kinds_and_unknown_actions_are_unserved_by_name() {
    let mut document = signed_document();
    let comment = kind(&mut document, "add_issue_comment");
    comment["class"] = json!("denied");
    comment["requests"] = json!([]);
    comment["credential"] = Value::Null;
    action(&mut document, "comment")["action"] = json!("unknown_action");
    let result = checked(&document);
    refused(&result, "add_issue_comment", "policy_kind_denied");
    refused(&result, "unknown_action", "policy_action_unknown");
    refused(&result, "close", "policy_leg_unserved");
}

#[test]
fn an_unknown_policy_field_is_rejected_by_name() {
    let mut document = signed_document();
    kind(&mut document, "add_issue_comment")["requests"][0]["rest"]["new_field"] = json!(true);
    let error = AgentPolicy::parse(&document.to_string())
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field `new_field`"), "{error}");
}

#[test]
fn parser_refuses_noninteger_out_of_range_duplicate_and_oversized_input() {
    let document = signed_document().to_string();
    for number in ["7.0", "7e0", "9007199254740992", "-9007199254740992"] {
        let invalid = document.replace(
            "\"issued_at_unix_secs\":7",
            &format!("\"issued_at_unix_secs\":{number}"),
        );
        assert!(AgentPolicy::parse(&invalid).is_err(), "accepted {number}");
    }
    for number in ["9007199254740991", "-9007199254740991"] {
        let at_limit = document.replace(
            "\"issued_at_unix_secs\":7",
            &format!("\"issued_at_unix_secs\":{number}"),
        );
        assert!(AgentPolicy::parse(&at_limit).is_ok(), "refused {number}");
    }
    let duplicate = document.replace("\"version\":3", "\"version\":1,\"version\":3");
    assert!(AgentPolicy::parse(&duplicate)
        .unwrap_err()
        .to_string()
        .contains("duplicate member"));
    let mut at_limit = document;
    at_limit.push_str(&" ".repeat(MAX_POLICY_BYTES - at_limit.len()));
    assert!(AgentPolicy::parse(&at_limit).is_ok());
    at_limit.push(' ');
    assert!(AgentPolicy::parse(&at_limit)
        .unwrap_err()
        .to_string()
        .contains("1 MiB"));
}

#[test]
fn parser_refuses_positional_objects_and_missing_signed_source() {
    let mut document = signed_document();
    let binding = json!(["github", "agent", "github_app:agent", ["org/r"]]);
    document["bindings"] = json!([binding]);
    assert!(
        AgentPolicy::parse(&document.to_string()).is_err(),
        "accepted a positional binding"
    );
    document["bindings"] = json!([]);
    document["rule_sets"]["github"]
        .as_object_mut()
        .unwrap()
        .remove("source");
    assert!(AgentPolicy::parse(&document.to_string())
        .unwrap_err()
        .to_string()
        .contains("missing field `source`"));
}
