use super::*;
use crate::github::agent_policy::{check_github, AgentPolicy};
use crate::github::control::{self, AgentPermission, Inventory, InventoryHandle};
use crate::test_scratch::Scratch;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const WRITES: &[&str] = &[
    "add_issue_comment",
    "add_pr_review",
    "add_reaction",
    "create_issue",
    "create_pull_request",
    "edit_issue",
    "update_issue_comment",
    "close_issue",
    "reopen_issue",
    "mark_pull_request_ready",
    "convert_pull_request_to_draft",
    "enqueue_pull_request",
    "dequeue_pull_request",
    "edit_pull_request",
    "reply_to_review_comment",
    "resolve_review_thread",
    "unresolve_review_thread",
    "create_pull_request_stack",
    "add_to_pull_request_stack",
    "unstack_pull_requests",
];

fn open(path: &Path) -> PlexusStore {
    PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "policy-apply".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .unwrap()
}

fn catalog() -> crate::IngestedManifest {
    crate::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../catalog/github_rest.jsonc"
            )))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn store(label: &str) -> (Scratch, PlexusStore) {
    let scratch = Scratch::directory(label);
    let store = open(&scratch.join("store.db"));
    store.upsert_manifest("system", &catalog()).unwrap();
    (scratch, store)
}

fn hand_onboard(store: &PlexusStore, agent: &str, handle: &str, repo: &str, writes: &[&str]) {
    let inventory = Inventory {
        version: "github-grant-import.v1".into(),
        handles: vec![InventoryHandle {
            app_handle_id: handle.into(),
            agent_id: agent.into(),
            app_id: 42,
            installation_id: None,
            credential_id: format!("github_app:{handle}"),
            status: "enabled".into(),
            grants: vec![AgentPermission {
                action: "create_issue".into(),
                repository: repo.into(),
                provenance: "operator".into(),
                policy: "allow".into(),
            }],
        }],
    };
    control::import_listed(
        store,
        "direct",
        &inventory,
        &BTreeMap::from([(handle.into(), vec![repo.into()])]),
        false,
    )
    .unwrap();
    control::grant_read(
        store,
        "direct",
        &crate::storage::github_store::GithubHandleReadGrant {
            app_handle_id: Some(handle.into()),
            all_handles: false,
            module: crate::github::AFT_PRINCIPAL.into(),
            actions: crate::github::reads::bot::GRANT_ACTIONS
                .iter()
                .map(|s| (*s).into())
                .collect(),
            dry_run: false,
        },
    )
    .unwrap();
    if !writes.is_empty() {
        control::grant(
            store,
            "direct",
            handle,
            &writes.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
            crate::github::AFT_PRINCIPAL,
            "allow",
            false,
        )
        .unwrap();
    }
}

fn binding(agent: &str, handle: &str, repos: &[&str]) -> Value {
    json!({"service":"github","agent":agent,"identity":format!("github_app:{handle}"),"resources":repos})
}

fn policy(
    version: i64,
    bindings: Vec<Value>,
    only_action: Option<&str>,
) -> (ActivePolicy, CheckedGitHub) {
    let mut seed: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/vault-wire/agent-policy-v1/github.json"
    )))
    .unwrap();
    seed["source"] = json!({"release":"test-seed", "sha256":"aca7b285dce9d1ebff602aae291d0205779a932fc47cf2afd380b3ee5d91f1a7"});
    if let Some(only) = only_action {
        seed["actions"]
            .as_array_mut()
            .unwrap()
            .retain(|action| action["action"] == only);
    }
    let text = json!({"schema":"ck-agent-policy/v1","version":version,"issued_at_unix_secs":1,
        "root_key_id":"56fae12f77164627","rule_sets":{"github":seed},"bindings":bindings})
    .to_string();
    let policy = AgentPolicy::parse(&text).unwrap();
    let checked = check_github(&policy, &catalog().manifest.actions_baseline);
    (
        ActivePolicy {
            policy,
            policy_sha256: format!("{:x}", Sha256::digest(&text)),
            manifest_version: 41,
            rollout: None,
        },
        checked,
    )
}

fn preview(store: &PlexusStore, policy: &(ActivePolicy, CheckedGitHub)) -> ApplyPlan {
    store
        .github_policy_preview(Some((&policy.0, &policy.1)))
        .unwrap()
}

fn apply(store: &PlexusStore, policy: &(ActivePolicy, CheckedGitHub)) -> ApplyPlan {
    store
        .apply_github_policy((&policy.0, &policy.1), || true)
        .unwrap()
}

fn generations(store: &PlexusStore, handle: &str) -> (i64, i64) {
    store.inner.with_read(|conn| conn.query_row(
        "SELECT g.generation,c.generation FROM github_repo_binding_generation g,github_app_handle h
         JOIN connections c ON c.principal=h.connection_principal AND c.connection_id=h.connection_id
         WHERE h.app_handle_id=?1", [handle], |r| Ok((r.get(0)?,r.get(1)?)),
    )).unwrap()
}

fn ids(store: &PlexusStore, agent: &str) -> Vec<String> {
    store
        .grants_held_by_agent(agent)
        .unwrap()
        .into_iter()
        .map(|g| g.grant_id)
        .collect()
}

#[test]
fn checked_seed_moves_only_the_hand_grant_ids() {
    let (_dir, store) = store("seed-plan");
    hand_onboard(&store, "agent-a", "app-a", "org/one", WRITES);
    hand_onboard(
        &store,
        "uncovered",
        "app-other",
        "org/other",
        &["add_issue_comment"],
    );
    let before = ids(&store, "agent-a");
    let other = ids(&store, "uncovered");
    let loaded = policy(1, vec![binding("agent-a", "app-a", &["org/one"])], None);
    assert_eq!(loaded.1.served.len(), 21);
    let plan = preview(&store, &loaded);
    let [row] = plan.agents.as_slice() else {
        panic!("{plan:#?}")
    };
    assert!(!plan.enabled);
    assert_eq!(
        plan.module_layer,
        [
            "github.actions.job.get",
            "github.actions.job_log",
            "github.pr.review_threads",
            "github.pulls.open",
            "github.repo.get",
            "github.search.code",
            "github.search.issues"
        ]
    );
    assert!(row.held.is_none() && row.conflicts.is_empty(), "{row:#?}");
    assert_eq!(row.revoke_grant_ids, before);
    assert!(
        row.add_selectors.is_empty()
            && row.remove_selectors.is_empty()
            && row.add_repos.is_empty()
            && row.remove_repos.is_empty()
            && row.allow_policies.is_empty(),
        "{row:#?}"
    );
    let expected_id = format!(
        "policy:github:agent-a:{}:v1",
        row.target.as_ref().unwrap().connection
    );
    assert_eq!(row.derived_grant.as_ref().unwrap().id, expected_id);
    println!("{}", serde_json::to_string_pretty(&plan).unwrap());
    let generations_before = generations(&store, "app-a");
    assert_eq!(apply(&store, &loaded).applied_version, None);
    store.set_github_policy_apply(true).unwrap();
    assert_eq!(apply(&store, &loaded).applied_version, Some(1));
    assert_eq!(ids(&store, "agent-a"), vec![expected_id]);
    assert_eq!(ids(&store, "uncovered"), other);
    assert_eq!(generations(&store, "app-a"), generations_before);
    assert_eq!(apply(&store, &loaded).unchanged_agents, 1);
    let same_contents = policy(2, vec![binding("agent-a", "app-a", &["org/one"])], None);
    assert_eq!(apply(&store, &same_contents).applied_version, Some(2));
    assert_eq!(
        ids(&store, "agent-a"),
        vec![row.derived_grant.as_ref().unwrap().id.clone()]
    );
    assert_eq!(generations(&store, "app-a"), generations_before);
}

#[test]
fn one_version_applies_eligible_agents_and_revisits_held_and_conflicts() {
    let (_dir, store) = store("pending-policy");
    hand_onboard(&store, "agent-a", "app-a", "org/one", &[]);
    hand_onboard(&store, "agent-b", "app-b", "org/two", &[]);
    hand_onboard(&store, "uncovered", "app-other", "org/conflict", &[]);
    let policy2 = policy(
        2,
        vec![
            binding("agent-c", "app-c", &["org/three"]),
            binding("agent-b", "app-b", &["org/conflict"]),
            binding("agent-a", "app-a", &["org/one"]),
        ],
        Some("issue_create"),
    );
    store.set_github_policy_apply(true).unwrap();
    let applied = apply(&store, &policy2);
    assert_eq!(applied.applied_version, Some(2));
    assert_eq!(applied.unchanged_agents, 1);
    let [conflict, held] = applied.agents.as_slice() else {
        panic!("{applied:#?}")
    };
    assert_eq!(conflict.agent, "agent-b");
    assert_eq!(
        conflict.conflicts,
        [PolicyConflict {
            reason: "repository_bound_to_another_handle",
            resource: Some("org/conflict".into()),
            handle: Some("app-other".into()),
        }]
    );
    assert_eq!(held.agent, "agent-c");
    assert_eq!(held.held, Some("handle_not_imported"));
    assert_eq!(
        store
            .github_handle_for_repo("org/conflict")
            .unwrap()
            .unwrap()
            .agent_id,
        "uncovered"
    );
    assert!(!ids(&store, "agent-b")[0].starts_with("policy:"));
    assert!(!preview(
        &store,
        &policy(1, vec![binding("agent-b", "app-b", &["org/two"])], None)
    )
    .has_eligible_agents());
    assert!(!store
        .github_policy_preview(None)
        .unwrap()
        .has_eligible_agents());
    hand_onboard(&store, "agent-c", "app-c", "org/three", &[]);
    control::unbind(
        &store,
        "direct",
        "app-other",
        "org/conflict",
        "release-old-binding",
        false,
    )
    .unwrap();
    let complete = apply(&store, &policy2);
    assert_eq!(complete.applied_version, Some(2));
    assert_eq!(complete.unchanged_agents, 3);
    assert!(complete.agents.is_empty());
    assert!(ids(&store, "agent-c")[0].starts_with("policy:"));
    assert_eq!(
        store
            .github_handle_for_repo("org/conflict")
            .unwrap()
            .unwrap()
            .agent_id,
        "agent-b"
    );
    assert!(store.github_handle_for_repo("org/two").unwrap().is_none());
}

#[test]
fn a_failed_second_agent_rolls_back_the_entire_sql_apply() {
    let (_dir, store) = store("apply-atomic");
    for (agent, handle, repo) in [
        ("agent-a", "app-a", "org/one"),
        ("agent-b", "app-b", "org/two"),
    ] {
        hand_onboard(&store, agent, handle, repo, &[]);
    }
    store.set_github_policy_apply(true).unwrap();
    let planned = policy(
        1,
        vec![
            binding("agent-a", "app-a", &["org/new"]),
            binding("agent-b", "app-b", &["org/two"]),
        ],
        None,
    );
    let a = ids(&store, "agent-a");
    let b = ids(&store, "agent-b");
    let generations_a = generations(&store, "app-a");
    let generations_b = generations(&store, "app-b");
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_second_policy BEFORE INSERT ON policy_applied
         WHEN NEW.agent='agent-b' BEGIN SELECT RAISE(ABORT,'injected policy failure'); END;",
            )
        })
        .unwrap();
    let error = store
        .apply_github_policy((&planned.0, &planned.1), || true)
        .unwrap_err();
    assert!(
        error.to_string().contains("injected policy failure"),
        "{error}"
    );
    assert_eq!(ids(&store, "agent-a"), a);
    assert_eq!(ids(&store, "agent-b"), b);
    assert_eq!(generations(&store, "app-a"), generations_a);
    assert_eq!(generations(&store, "app-b"), generations_b);
    assert!(store.github_handle_for_repo("org/new").unwrap().is_none());
    assert!(store.github_handle_for_repo("org/one").unwrap().is_some());
    assert_eq!(preview(&store, &planned).applied_version, None);
    store
        .inner
        .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER refuse_second_policy"))
        .unwrap();
    assert_eq!(apply(&store, &planned).applied_version, Some(1));
    let (binding_gen_after, conn_gen_after) = generations(&store, "app-a");
    assert_eq!(
        binding_gen_after,
        generations_a.0 + 2,
        "one add and one remove"
    );
    assert_eq!(
        conn_gen_after,
        generations_a.1 + 1,
        "ceiling and filters share one bump"
    );
    assert_eq!(
        generations(&store, "app-b").1,
        generations_b.1 + 1,
        "ceiling-only bump"
    );
}

#[test]
fn old_snapshots_cannot_revive_hand_grants_or_a_replaced_derived_id() {
    let (dir, store) = store("policy-restore");
    hand_onboard(&store, "agent-a", "app-a", "org/one", WRITES);
    let take_backup = |name| {
        let path = dir.join(name);
        store
            .inner
            .with_conn(|conn| conn.execute("VACUUM INTO ?1", [path.to_str().unwrap()]))
            .unwrap();
        path
    };
    let hand_backup = take_backup("hand.db");
    store.set_github_policy_apply(true).unwrap();
    let loaded = policy(1, vec![binding("agent-a", "app-a", &["org/one"])], None);
    assert_eq!(apply(&store, &loaded).applied_version, Some(1));
    let v1 = ids(&store, "agent-a");
    let derived_backup = take_backup("derived.db");
    let narrowed = policy(
        2,
        vec![binding("agent-a", "app-a", &["org/one"])],
        Some("issue_create"),
    );
    assert_eq!(apply(&store, &narrowed).applied_version, Some(2));
    let v2 = ids(&store, "agent-a");
    assert_ne!(v1, v2);
    assert!(v2[0].ends_with(":v2"));
    drop(store);
    // Each snapshot is a consistent SQLite backup beside the original journal,
    // so opening it exercises the normal restore replay without copying a live DB.
    let restored = open(&hand_backup);
    assert!(ids(&restored, "agent-a").is_empty());
    restored.set_github_policy_apply(true).unwrap();
    let refused = apply(&restored, &loaded);
    assert_eq!(
        refused.agents[0].conflicts[0].reason,
        "derived_grant_id_revoked"
    );
    assert!(ids(&restored, "agent-a").is_empty());
    drop(restored);
    let restored = open(&derived_backup);
    assert!(
        ids(&restored, "agent-a").is_empty(),
        "replaced derived id must remain revoked"
    );
    assert_eq!(apply(&restored, &narrowed).applied_version, Some(2));
    assert_eq!(ids(&restored, "agent-a"), v2);
}
