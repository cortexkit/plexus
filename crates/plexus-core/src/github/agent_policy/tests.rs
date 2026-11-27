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

#[test]
fn draft_suffix_kinds_are_served_by_repo_get() {
    let draft = include_str!(
        "../../../tests/fixtures/agent_policy/github-rules-revision-2-kinds.draft.json"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(draft)),
        "394f278e7470b0bab27e4275632673995dbdb5641c89ed12523ac283b5f27486"
    );
    let entries: Vec<Value> = serde_json::from_str(draft).unwrap();
    let mut document = signed_document();
    document["rule_sets"]["github"]["kinds"]
        .as_array_mut()
        .unwrap()
        .extend(entries.iter().cloned());
    let result = checked(&document);
    for entry in entries {
        let name = entry["kind"].as_str().unwrap();
        assert!(result.serves_kind(name), "{name}: {:?}", result.unserved);
    }
    refused(&result, "node_repository", "policy_kind_not_catalogued");
}

#[test]
fn suffix_match_checks_repository_whole_path_and_query() {
    let mut document = signed_document();
    let read = kind(&mut document, "github.issue.get");
    read["requests"][0]["rest"]["query"] = json!({"optional":["page"]});
    let mut overlap = read.clone();
    overlap["kind"] = json!("fixture.other_kind");

    let args = json!({"owner":"Org_EMU", "repo":"Repo.Name", "path":"issues/7",
        "query":{"page":"9"}});
    let policy = AgentPolicy::parse(&document.to_string()).unwrap();
    assert_eq!(
        policy.match_repo_get_suffix("org_emu/repo.name", &args),
        SuffixMatch::Unique("github.issue.get")
    );
    for repository in ["other/repo.name", "org_emu/other"] {
        assert_eq!(
            policy.match_repo_get_suffix(repository, &args),
            SuffixMatch::None
        );
    }
    let mut bad = args.clone();
    bad["query"] = json!({"per_page":"9"});
    assert_eq!(
        policy.match_repo_get_suffix("org_emu/repo.name", &bad),
        SuffixMatch::None
    );
    for path in [
        "issues/7/unmatched",
        "issues/7/",
        "issues//7",
        "issues/%2e%2e/7",
        "issues/7%2Fextra",
        "issues/7%5C",
        "issues/7%00",
    ] {
        bad["query"] = json!({});
        bad["path"] = json!(path);
        assert_eq!(
            policy.match_repo_get_suffix("org_emu/repo.name", &bad),
            SuffixMatch::None,
            "{path}"
        );
    }
    document["rule_sets"]["github"]["kinds"]
        .as_array_mut()
        .unwrap()
        .push(overlap);
    let policy = AgentPolicy::parse(&document.to_string()).unwrap();
    assert_eq!(
        policy.match_repo_get_suffix("org_emu/repo.name", &args),
        SuffixMatch::Ambiguous
    );
}

#[test]
fn suffix_match_uses_decoded_and_bounded_extractor_types() {
    let mut document = signed_document();
    let rest = kind(&mut document, "github.issue.get")["requests"][0]["rest"].clone();
    let distinct = [
        ("number-test", "{number}"),
        ("id-test", "{id}"),
        ("sha-test", "{sha}"),
        ("name-test", "{name}"),
        ("tail-test", "{path*}"),
    ];
    for (route, segment) in distinct {
        let mut request = rest.clone();
        request["path"] = json!(format!("/repos/{{owner}}/{{repo}}/{route}/{segment}"));
        let mut entry = kind(&mut document, "github.issue.get").clone();
        entry["kind"] = json!(route);
        entry["requests"] = json!([{"rest":request}]);
        document["rule_sets"]["github"]["kinds"]
            .as_array_mut()
            .unwrap()
            .push(entry);
    }
    let policy = AgentPolicy::parse(&document.to_string()).unwrap();
    let expect = |route, path: &str, matched| {
        let args = json!({"owner":"org","repo":"repo","path":format!("{route}/{path}")});
        assert_eq!(
            policy.match_repo_get_suffix("org/repo", &args),
            if matched {
                SuffixMatch::Unique(route)
            } else {
                SuffixMatch::None
            },
            "{route}/{path}"
        );
    };
    for (route, value, matched) in [
        ("number-test", "%37", true),
        ("number-test", "2147483647", true),
        ("number-test", "2147483648", false),
        ("number-test", "07", false),
        ("id-test", "9007199254740991", true),
        ("id-test", "9007199254740992", false),
        ("id-test", "0", false),
        ("id-test", "+7", false),
        ("sha-test", "cafef00d", false),
        ("name-test", "release%20notes", true),
        ("name-test", "%C3%A9", true),
        ("name-test", "%FF", false),
        ("name-test", "nested/path", false),
        ("tail-test", "nested/path", true),
        ("tail-test", "", false),
    ] {
        expect(route, value, matched);
    }
    expect("sha-test", &"a".repeat(40), true);
    expect("sha-test", &"a".repeat(64), true);
    expect("sha-test", &"A".repeat(40), false);
    expect("name-test", &"a".repeat(255), true);
    expect("name-test", &"a".repeat(256), false);
    let full_tail = format!("{0}/{0}/{0}/{0}/a", "a".repeat(254));
    assert_eq!(full_tail.len(), 1021);
    expect("tail-test", &format!("{full_tail}aaa"), true);
    expect("tail-test", &format!("{full_tail}aaaa"), false);
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
    assert_eq!(active.rollout, None);
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

// These rollout replies are stand-in inputs until samples from the vault handler arrive.
fn active_reply_with_rollout(golden_name: &str, rollout: Value) -> Value {
    let mut reply = golden(golden_name);
    reply["result"]["rollout"] = rollout;
    reply
}

#[test]
fn active_accepts_rollout_without_replacing_the_active_pair() {
    let baseline = decode_active(golden("policy.active.ready"))
        .unwrap()
        .unwrap();
    let reply = active_reply_with_rollout(
        "policy.active.ready",
        json!({"manifest_version":42,"policy_version":3}),
    );
    let active = decode_active(reply).unwrap().unwrap();
    assert_eq!(active.manifest_version, baseline.manifest_version);
    assert_eq!(active.policy.version, baseline.policy.version);
    assert_eq!(active.policy_sha256, baseline.policy_sha256);
    assert_eq!(active.policy.bindings[0].identity, "github_app:agent");
    assert_eq!(active.policy.bindings[0].resources, ["org/r"]);
    assert_eq!(
        active.rollout,
        Some(PolicyRollout {
            manifest_version: 42,
            policy_version: 3,
        })
    );
}

#[test]
fn active_rejects_malformed_rollout() {
    for (case, rollout) in [
        (
            "unknown field",
            json!({"manifest_version":42,"policy_version":3,"extra":true}),
        ),
        ("missing manifest version", json!({"policy_version":3})),
        ("missing policy version", json!({"manifest_version":42})),
        ("non-object", json!([42, 3])),
        ("null", json!(null)),
        (
            "fractional manifest version",
            json!({"manifest_version":42.5,"policy_version":3}),
        ),
        (
            "fractional policy version",
            json!({"manifest_version":42,"policy_version":3.5}),
        ),
        (
            "string manifest version",
            json!({"manifest_version":"42","policy_version":3}),
        ),
        (
            "string policy version",
            json!({"manifest_version":42,"policy_version":"3"}),
        ),
        (
            "zero manifest version",
            json!({"manifest_version":0,"policy_version":3}),
        ),
        (
            "zero policy version",
            json!({"manifest_version":42,"policy_version":0}),
        ),
        (
            "negative manifest version",
            json!({"manifest_version":-42,"policy_version":3}),
        ),
        (
            "negative policy version",
            json!({"manifest_version":42,"policy_version":-3}),
        ),
        (
            "equal manifest version",
            json!({"manifest_version":41,"policy_version":3}),
        ),
        (
            "older manifest version",
            json!({"manifest_version":40,"policy_version":3}),
        ),
    ] {
        let reply = active_reply_with_rollout("policy.active.ready", rollout);
        assert_eq!(
            decode_active(reply).unwrap_err(),
            ReadFailure::Unreadable,
            "{case}"
        );
    }
}

#[test]
fn active_accepts_rollout_beside_an_all_null_pair_as_no_active_policy() {
    // The vault names a stored newer pair before any pair is ready. Plexus still
    // has no active policy to apply, but the rollout's own values must be valid.
    let reply = active_reply_with_rollout(
        "policy.active.none",
        json!({"manifest_version":42,"policy_version":3}),
    );
    assert!(decode_active(reply).unwrap().is_none());
    for rollout in [
        json!({"manifest_version":0,"policy_version":3}),
        json!({"manifest_version":42,"policy_version":0}),
        json!({"manifest_version":42,"policy_version":3,"extra":true}),
    ] {
        let reply = active_reply_with_rollout("policy.active.none", rollout);
        assert_eq!(decode_active(reply).unwrap_err(), ReadFailure::Unreadable);
    }
}

/// Replies captured from the vault's real `policy.active` handler, vendored
/// byte for byte in `tests/fixtures/vault-wire/agent-policy-handler-v1/`.
#[test]
fn vault_handler_rollout_samples_decode() {
    let ready: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vault-wire/agent-policy-handler-v1/policy.active.ready.json"
    ))
    .unwrap();
    let rollout: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vault-wire/agent-policy-handler-v1/policy.active.rollout.json"
    ))
    .unwrap();
    let unready: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vault-wire/agent-policy-handler-v1/policy.active.rollout-unready.json"
    ))
    .unwrap();
    assert!(decode_active(unready).unwrap().is_none());
    let ready = decode_active(ready).unwrap().unwrap();
    assert_eq!(ready.rollout, None);
    let rolling = decode_active(rollout).unwrap().unwrap();
    assert_eq!(rolling.manifest_version, ready.manifest_version);
    assert_eq!(rolling.policy_sha256, ready.policy_sha256);
    assert_eq!(
        rolling.rollout,
        Some(PolicyRollout {
            manifest_version: 42,
            policy_version: 2,
        })
    );
}

#[test]
fn rollout_does_not_relax_other_vault_reply_shapes() {
    let rollout = json!({"manifest_version":42,"policy_version":3});
    let mut active = active_reply_with_rollout("policy.active.ready", rollout.clone());
    active["result"]["extra"] = json!(true);
    assert_eq!(decode_active(active).unwrap_err(), ReadFailure::Unreadable);
    let mut watch = golden("policy.watch.changed");
    watch["rollout"] = rollout;
    assert_eq!(
        WatchNotice::decode(watch).unwrap_err(),
        ReadFailure::Unreadable
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
