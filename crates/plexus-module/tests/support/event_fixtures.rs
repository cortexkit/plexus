use plexus_core::{
    storage::event_outbox::{EventHeaders, KeyedEventIdentity, KeyedPollEventInput},
    ActorAttribution, GrantInput, PlexusStore, PollEventInput,
};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn seed_test_events(path: &Path, store: &PlexusStore) -> (String, String) {
    seed_test_events_with_issue_payload(path, store, json!({"id": 1, "title": "bug report"}))
}

pub(super) fn seed_test_events_with_issue_payload(
    path: &Path,
    store: &PlexusStore,
    issue_payload: Value,
) -> (String, String) {
    let conn = rusqlite::Connection::open(path).expect("open test db");
    conn.execute_batch(
            "INSERT INTO connections (connection_id, principal, app_key, status, created_at_ms, updated_at_ms)
             VALUES ('conn-github', 'direct', 'github', 'active', 1, 1),
                    ('conn-github-actions', 'direct', 'github_actions', 'active', 1, 1);
             INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action, cadence_s, cursor_kind, cursor_state, schema_hash, status, created_at_ms)
             VALUES ('issue-sub-1', 'direct', 'conn-github', 'list_issues', 300, 'ordered_timestamp', '{}', 'hash', 'active', 1),
                    ('ci-sub-1', 'direct', 'conn-github-actions', 'list_workflow_runs', 300, 'ci_runs', '{}', 'hash', 'active', 1);
            ",
        )
        .expect("seed connections and subscriptions");

    // Grant core consume authority on conn-github
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-core-consume".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-github".to_string(),
            grantee_principal: "reserved:prefrontal".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["list_issues".to_string()],
            authority_kind: "events_consume".to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("seed core consume grant");

    let issue_sub_id = "issue-sub-1".to_string();
    let ci_sub_id = "ci-sub-1".to_string();

    // Insert issue event
    let issue_key = "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let issue_headers = EventHeaders {
        repo: "owner/repo".to_string(),
        project: Some("project-1".to_string()),
        pr: None,
        branch: None,
        conclusion: None,
    };
    let actor = ActorAttribution::NotEnriched;
    let issue_input = KeyedPollEventInput {
        event: PollEventInput {
            vendor_event_id: "issue-1",
            payload: &issue_payload,
            observed_at_ms: plexus_core::now_ms(),
            item_kind: Some("issue"),
            activity_at_ms: Some(plexus_core::now_ms()),
            actor: &actor,
        },
        identity: Some(KeyedEventIdentity {
            event_key: &issue_key,
            event_name: "github_issue_changed",
            repo_id: 101,
            change: Some("opened"),
            headers: &issue_headers,
        }),
        delivery_id: None,
        envelope_context: Default::default(),
    };
    store
        .commit_keyed_poll_success(
            "direct",
            "conn-github",
            &issue_sub_id,
            &json!({}),
            &[issue_input],
            plexus_core::now_ms(),
            &[],
        )
        .expect("commit issue event");

    // Insert CI event
    let ci_key = "0000000000000000000000000000000000000000000000000000000000000002".to_string();
    let ci_payload = json!({"run_id": 99, "status": "completed"});
    let ci_headers = EventHeaders {
        repo: "owner/repo".to_string(),
        project: Some("project-1".to_string()),
        pr: None,
        branch: Some("main".to_string()),
        conclusion: Some("failure".to_string()),
    };
    let ci_input = KeyedPollEventInput {
        event: PollEventInput {
            vendor_event_id: "run-99",
            payload: &ci_payload,
            observed_at_ms: plexus_core::now_ms(),
            item_kind: Some("ci_run"),
            activity_at_ms: Some(plexus_core::now_ms()),
            actor: &actor,
        },
        identity: Some(KeyedEventIdentity {
            event_key: &ci_key,
            event_name: "github_ci_run_completed",
            repo_id: 101,
            change: None,
            headers: &ci_headers,
        }),
        delivery_id: None,
        envelope_context: Default::default(),
    };
    store
        .commit_keyed_poll_success(
            "direct",
            "conn-github-actions",
            &ci_sub_id,
            &json!({"pinned": {}, "open": {}}),
            &[ci_input],
            plexus_core::now_ms(),
            &[],
        )
        .expect("commit ci event");

    (issue_key, ci_key)
}
