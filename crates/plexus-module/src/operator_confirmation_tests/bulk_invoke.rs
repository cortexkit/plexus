use super::*;

const WRITES: &[&str] = &[
    "edit_pull_request",
    "reply_to_review_comment",
    "resolve_review_thread",
    "unresolve_review_thread",
    "create_pull_request_stack",
    "add_to_pull_request_stack",
    "unstack_pull_requests",
];

struct BulkInstallation;
impl plexus_core::github::control::InstallationReader for BulkInstallation {
    fn repositories_page(
        &self,
        _: &plexus_core::credentials::ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        Ok(
            json!({"repositories":(0..26).map(|i| json!({"full_name":format!("org/repo-{i}")})).collect::<Vec<_>>()}),
        )
    }
}

fn case() -> Case {
    let mut case = Case::new(manifest::GITHUB_IMPORT_OP);
    let handles: Vec<_> = (0..26).map(|i| json!({
        "app_handle_id":format!("app-bulk-{i:02}"), "agent_id":format!("agent-bulk-{i:02}"),
        "app_id":i+1, "installation_id":null, "credential_id":format!("github_app:app-bulk-{i:02}"), "status":"enabled",
        "grants":[{"action":"create_issue","repository":format!("org/repo-{i}"),"provenance":"operator","policy":"allow"}]
    })).collect();
    let inventory =
        serde_json::from_value(json!({"version":"github-grant-import.v1","handles":handles}))
            .unwrap();
    plexus_core::github::control::import(
        case.state.store(),
        "direct",
        &inventory,
        &AnyHandleToken,
        &BulkInstallation,
        plexus_core::now_ms(),
        false,
    )
    .unwrap();
    case.method = manifest::GITHUB_GRANT_OP;
    case.params = json!({"kind":"invoke","all_handles":true,"module":"reserved:aft","effect":"allow","actions":WRITES,"dry_run":false});
    case
}

// Grant IDs contain mint timestamps. Compare the full authority rows while
// ignoring generated IDs and bookkeeping clocks, not expiries or generations.
fn authority(case: &Case) -> Vec<Vec<String>> {
    let db = rusqlite::Connection::open(&case.path).unwrap();
    [
        "connections",
        "grants",
        "policies",
        "catalog_actions",
        "github_repo_binding",
        "github_app_handle",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns: Vec<_> = statement
            .column_names()
            .iter()
            .enumerate()
            .filter_map(|(index, name)| {
                (!matches!(
                    *name,
                    "grant_id"
                        | "policy_id"
                        | "created_at_ms"
                        | "updated_at_ms"
                        | "first_seen_at_ms"
                        | "last_seen_at_ms"
                        | "bound_at_ms"
                        | "proven_at"
                ))
                .then_some(index)
            })
            .collect();
        let mut rows = statement
            .query_map([], |row| {
                Ok(columns
                    .iter()
                    .map(|i| format!("{:?}", row.get_ref(*i).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        rows.sort();
        rows
    })
    .collect()
}

#[tokio::test]
async fn all_handles_seven_writes_match_26_single_handle_applies_with_one_confirmation() {
    let mut bulk = case();
    let single = case();
    assert_eq!(authority(&bulk), authority(&single));
    let before = bulk.snapshot(true);
    bulk.params["dry_run"] = json!(true);
    let preview = ceremony_with_peer(&bulk, Ok(()), false).await;
    assert_eq!(
        preview["result"]["handles"].as_array().unwrap().len(),
        26,
        "{preview}"
    );
    assert_eq!(preview["result"]["actions"].as_array().unwrap().len(), 7);
    assert_eq!(preview["result"]["expanded"].as_array().unwrap().len(), 10);
    for action in [
        "github.pull_request.get",
        "github.review_thread.get",
        "github.stack.get",
    ] {
        assert!(preview["result"]["expanded"]
            .as_array()
            .unwrap()
            .contains(&json!(action)));
    }
    assert_eq!(bulk.snapshot(true), before, "preview wrote durable state");
    bulk.params["dry_run"] = json!(false);
    let applied = ceremony_with_peer(&bulk, Ok(()), true).await;
    assert_eq!(
        applied["result"]["handles"].as_array().unwrap().len(),
        26,
        "{applied}"
    );
    let actions: Vec<_> = WRITES.iter().map(|action| (*action).to_owned()).collect();
    for i in 0..26 {
        plexus_core::github::control::grant(
            single.state.store(),
            "direct",
            &format!("app-bulk-{i:02}"),
            &actions,
            "reserved:aft",
            "allow",
            false,
        )
        .unwrap();
    }
    assert_eq!(
        authority(&bulk),
        authority(&single),
        "bulk authority differs from per-handle applies"
    );
    let db = rusqlite::Connection::open(&bulk.path).unwrap();
    let audits: usize = db.query_row("SELECT count(*) FROM audit_journal WHERE action='github.handle.grant' AND outcome='applied'",[],|row| row.get(0)).unwrap();
    assert_eq!(audits, 26);
    let before = bulk.snapshot(true);
    let repeated = ceremony_with_peer(&bulk, Ok(()), true).await;
    assert!(repeated.get("error").is_none(), "{repeated}");
    assert_eq!(
        bulk.snapshot(true),
        before,
        "rerun changed authority or audit"
    );
}

#[tokio::test]
async fn all_handles_refuses_non_facade_unknown_and_wildcard_actions_before_prompt() {
    let mut case = case();
    for action in ["github.issue.get", "unknown_write", "*"] {
        case.params["actions"] = json!([action]);
        let before = case.snapshot(true);
        let reply = ceremony_with_peer(&case, Ok(()), false).await;
        assert_eq!(
            reply["error"]["code"],
            format!("action_not_grantable{{action: {action}}}"),
            "{reply}"
        );
        assert_eq!(case.snapshot(true), before);
    }
    let mut manifest: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../../catalog/github_rest.jsonc")).unwrap(),
    )
    .unwrap();
    for row in manifest["actions_baseline"].as_array_mut().unwrap() {
        if row["name"] == "edit_pull_request" {
            row["facade_only"] = json!(false);
        }
    }
    case.state
        .store()
        .upsert_manifest("system", &plexus_core::ingest_value(manifest).unwrap())
        .unwrap();
    case.params["actions"] = json!(["edit_pull_request"]);
    let before = case.snapshot(true);
    let reply = ceremony_with_peer(&case, Ok(()), false).await;
    assert_eq!(
        reply["error"]["code"], "reviewed_facade_write_required{action: edit_pull_request}",
        "{reply}"
    );
    assert_eq!(case.snapshot(true), before);
}

#[tokio::test]
async fn all_handles_declined_intent_and_late_audit_failure_change_no_authority() {
    let case = case();
    let before = case.snapshot(false);
    let reply = ceremony_with_peer(&case, Err("operator_declined"), true).await;
    assert_eq!(
        reply["error"]["code"], "operator_confirmation_declined",
        "{reply}"
    );
    assert_eq!(case.snapshot(false), before);
    let db = rusqlite::Connection::open(&case.path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_last_bulk_audit BEFORE INSERT ON audit_journal WHEN NEW.app_handle_id='app-bulk-25' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;").unwrap();
    let before = case.snapshot(true);
    let reply = ceremony_with_peer(&case, Ok(()), true).await;
    assert!(
        reply["error"]["code"]
            .as_str()
            .unwrap()
            .starts_with("grant_failed:"),
        "{reply}"
    );
    assert_eq!(
        case.snapshot(true),
        before,
        "late failure left a partial bulk grant"
    );
}

#[tokio::test]
async fn all_handles_refuses_inactive_catalog_and_does_not_reactivate_or_seed_on_preview() {
    let case = case();
    let db = rusqlite::Connection::open(&case.path).unwrap();
    db.execute("DELETE FROM catalog_actions WHERE connection_id='github-handle-app-bulk-00' AND name='github.stack.get'",[]).unwrap();
    db.execute("UPDATE catalog_actions SET status='quarantined' WHERE connection_id='github-handle-app-bulk-25' AND name='edit_pull_request'",[]).unwrap();
    let before = case.snapshot(true);
    let reply = ceremony_with_peer(&case, Ok(()), false).await;
    assert_eq!(
        reply["error"]["code"],
        "catalog_action_inactive{action: edit_pull_request, status: quarantined}",
        "{reply}"
    );
    assert_eq!(
        case.snapshot(true),
        before,
        "refused preview seeded or reactivated catalog rows"
    );
}

#[tokio::test]
async fn all_handles_preview_selects_enabled_handles_only() {
    let case = case();
    let db = rusqlite::Connection::open(&case.path).unwrap();
    db.execute(
        "UPDATE github_app_handle SET status='disabled' WHERE app_handle_id='app-bulk-25'",
        [],
    )
    .unwrap();
    let mut params = case.params.clone();
    params["dry_run"] = json!(true);
    let before = case.snapshot(true);
    let plan = github_handle_grant(&case.state, "direct", &params);
    assert_eq!(
        plan["result"]["handles"].as_array().unwrap().len(),
        25,
        "{plan}"
    );
    assert!(plan["result"]["handles"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["app_handle_id"] != "app-bulk-25"));
    assert_eq!(case.snapshot(true), before);
}

#[tokio::test]
async fn all_handles_seeds_only_missing_reviewed_actions_after_confirmation() {
    let mut case = case();
    let db = rusqlite::Connection::open(&case.path).unwrap();
    for action in WRITES.iter().copied().chain([
        "github.pull_request.get",
        "github.review_thread.get",
        "github.stack.get",
    ]) {
        db.execute("DELETE FROM catalog_actions WHERE connection_id='github-handle-app-bulk-00' AND name=?1",[action]).unwrap();
    }
    case.params["dry_run"] = json!(true);
    let before = case.snapshot(true);
    let preview = ceremony_with_peer(&case, Ok(()), false).await;
    let additions = &preview["result"]["handles"][0]["catalog_additions"];
    assert_eq!(additions.as_array().unwrap().len(), 10, "{preview}");
    assert_eq!(case.snapshot(true), before);
    case.params["dry_run"] = json!(false);
    let applied = ceremony_with_peer(&case, Ok(()), true).await;
    assert!(applied.get("error").is_none(), "{applied}");
    for action in additions.as_array().unwrap() {
        let row: (String,String) = db.query_row("SELECT status,risk FROM catalog_actions WHERE connection_id='github-handle-app-bulk-00' AND name=?1",
            [action.as_str().unwrap()],|row| Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert_eq!(row.0, "active");
        assert_eq!(
            row.1,
            if action.as_str().unwrap().starts_with("github.") {
                "read"
            } else {
                "write"
            }
        );
    }
}
