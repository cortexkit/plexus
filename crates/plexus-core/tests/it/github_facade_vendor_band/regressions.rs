use super::*;

#[test]
fn completed_label_only_edit_recovers_its_projection_without_another_read() {
    let (scratch, store, engine, transport, scope) = setup(
        "label-finish-replay",
        &[
            ("github.issue.get", "read"),
            ("edit_issue", "write"),
            ("add_issue_labels", "write"),
        ],
    );
    transport.set_response_for_method("github.issue.get", "", MockResponse::Success(json!({
        "id":42,"html_url":"https://github.com/org/repo/issues/42", "user":{"login":"app-fixture[bot]","type":"Bot"},
    })));
    transport.set_response_for_method(
        "add_issue_labels",
        "",
        MockResponse::Success(json!([{"name":"triaged"}])),
    );
    let db = Connection::open(scratch.path()).unwrap();
    db.execute_batch("CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON github_bot_receipt WHEN NEW.state='completed' BEGIN SELECT RAISE(FAIL,'unavailable'); END;").unwrap();
    let request = json!({"action":"issue edit","repository":"org/repo","target":{"number":42},"body":{"add_labels":["triaged"]}});
    let send = || {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "label-finish",
            "request",
            "worker",
            plexus_core::storage::now_ms(),
        )
    };
    let first = send();
    assert_eq!(
        first["result"],
        json!({"status":"completed","result":{"id":42,"url":"https://github.com/org/repo/issues/42"}})
    );
    db.execute_batch("DROP TRIGGER fail_finish; UPDATE github_app_handle SET status='disabled';")
        .unwrap();
    assert_eq!(send()["result"], first["result"]);
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn own_issue_author_login_is_case_insensitive() {
    let (_scratch, store, engine, transport, scope) = setup(
        "login-case",
        &[("github.issue.get", "read"), ("edit_issue", "write")],
    );
    transport.set_response_for_method(
        "github.issue.get",
        "",
        MockResponse::Success(json!({"user":{"login":"APP-FIXTURE[bot]","type":"Bot"}})),
    );
    let reply = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"action":"issue edit","repository":"org/repo","target":{"number":42},"body":{"title":"changed"}}),
        "case",
        "request",
        "worker",
        plexus_core::storage::now_ms(),
    );
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn transient_governance_denial_between_legs_keeps_nonce_retryable() {
    use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
    struct UnhealthyAfterComment {
        inner: Arc<MockTransport>,
        path: std::path::PathBuf,
    }
    impl Transport for UnhealthyAfterComment {
        fn dispatch(
            &self,
            request: TransportRequest,
            credential: &ResolvedCredential,
        ) -> TransportResponse {
            let comment = request.action == "add_issue_comment";
            let result = self.inner.dispatch(request, credential);
            if comment {
                Connection::open(&self.path).unwrap().execute("UPDATE connections SET health_state='{\"healthy_enough\":false}' WHERE connection_id='conn-fixture'",[]).unwrap();
            }
            result
        }
    }
    let (scratch, store, _, inner, scope) = setup(
        "retry-governance",
        &[("add_issue_comment", "write"), ("close_issue", "write")],
    );
    let transport = Arc::new(UnhealthyAfterComment {
        inner: inner.clone(),
        path: scratch.path().into(),
    });
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport,
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let request =
        json!({"verb":"issue close","repository":"org/repo","number":42,"comment":"once"});
    let send = || {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "governance",
            "request",
            "worker",
            plexus_core::storage::now_ms(),
        )
    };
    let first = send();
    assert!(
        first["result"]["refusal_code"]
            .as_str()
            .unwrap()
            .contains("Connection(Unhealthy)"),
        "{first}"
    );
    let row = store
        .github_receipt("agent-fixture", "governance")
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "pending");
    assert_eq!(row.claim_owner, None);
    Connection::open(scratch.path())
        .unwrap()
        .execute(
            "UPDATE connections SET health_state='{}' WHERE connection_id='conn-fixture'",
            [],
        )
        .unwrap();
    assert_eq!(send()["result"]["status"], "completed");
    assert_eq!(
        inner
            .requests()
            .iter()
            .filter(|request| request.action == "add_issue_comment")
            .count(),
        1
    );
}

#[test]
fn receipt_updates_use_transition_time_instead_of_admission_time() {
    let (_scratch, store, engine, _, scope) =
        setup("transition-time", &[("add_reaction", "write")]);
    let before = plexus_core::storage::now_ms();
    let reply = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"action":"issue reaction","repository":"org/repo","target":{"number":42},"body":{"reaction":"eyes"}}),
        "clock",
        "request",
        "worker",
        before - 1000,
    );
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert!(
        store
            .github_receipt("agent-fixture", "clock")
            .unwrap()
            .unwrap()
            .updated_at
            >= before
    );
}

#[test]
fn generation_preflight_failure_is_audited() {
    let (scratch, store, engine, _, scope) = setup("preflight-audit", &[("add_reaction", "write")]);
    let db = Connection::open(scratch.path()).unwrap();
    db.execute_batch(
        "ALTER TABLE github_repo_binding_generation RENAME TO unavailable_generation;",
    )
    .unwrap();
    bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"action":"issue reaction","repository":"org/repo","target":{"number":42},"body":{"reaction":"eyes"}}),
        "audit",
        "preflight-failure",
        "worker",
        plexus_core::storage::now_ms(),
    );
    let count: i64 = db.query_row("SELECT COUNT(*) FROM audit_journal WHERE request_id='preflight-failure' AND reason_code='store_failure'", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn close_does_not_require_an_unused_issue_read() {
    let (_scratch, store, engine, transport, scope) =
        setup("close-without-read", &[("close_issue", "write")]);
    let reply = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"verb":"issue close","repository":"org/repo","number":42}),
        "close",
        "request",
        "worker",
        plexus_core::storage::now_ms(),
    );
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].action, "close_issue");
}

#[test]
fn transient_transport_between_legs_resumes_without_reposting_comment() {
    let (_scratch, store, engine, transport, scope) = setup(
        "retry-not-sent",
        &[
            ("github.issue.get", "read"),
            ("add_issue_comment", "write"),
            ("close_issue", "write"),
        ],
    );
    transport.set_response_for_method(
        "close_issue",
        "",
        MockResponse::TransientNotSent {
            message: "temporary".into(),
        },
    );
    let request =
        json!({"verb":"issue close","repository":"org/repo","number":42,"comment":"once"});
    let send = || {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "retry",
            "request",
            "worker",
            plexus_core::storage::now_ms(),
        )
    };
    let first = send();
    assert_eq!(
        first["result"]["refusal_code"], "transport_not_sent",
        "{first}"
    );
    assert_eq!(
        store
            .github_receipt("agent-fixture", "retry")
            .unwrap()
            .unwrap()
            .claim_owner,
        None
    );
    transport.set_response_for_method(
        "close_issue",
        "",
        MockResponse::Success(json!({"state":"closed"})),
    );
    assert_eq!(send()["result"]["status"], "completed");
    assert_eq!(
        transport
            .requests()
            .iter()
            .filter(|r| r.action == "add_issue_comment")
            .count(),
        1
    );
}

#[test]
fn later_permanent_refusal_reports_durable_legs() {
    let (_scratch, store, engine, transport, scope) = setup(
        "refused-legs",
        &[
            ("github.issue.get", "read"),
            ("add_issue_comment", "write"),
            ("close_issue", "write"),
        ],
    );
    transport.set_response_for_method(
        "close_issue",
        "",
        MockResponse::VendorError {
            code: "http_403".into(),
            message: "forbidden".into(),
        },
    );
    let request =
        json!({"verb":"issue close","repository":"org/repo","number":42,"comment":"once"});
    let send = || {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "refused",
            "request",
            "worker",
            plexus_core::storage::now_ms(),
        )
    };
    let first = send();
    assert_eq!(first["result"]["legs_sent"], json!(["add_issue_comment"]));
    assert_eq!(send()["result"], first["result"]);
}

#[test]
fn ordinary_search_refuses_raw_query_and_builds_bound_query() {
    let (_scratch, _, engine, transport, _) =
        setup("bound-search", &[("github.issue.search", "read")]);
    for field in ["q", "query"] {
        let mut args = json!({"repositories":["org/repo"],"terms":"bug"});
        args[field] = json!("repo:elsewhere/private");
        let denied = engine.authorize(plexus_core::AuthorizationRequest::new(
            plexus_core::github::AFT_PRINCIPAL,
            "conn-fixture",
            "github.issue.search",
            args,
        ));
        assert!(
            matches!(denied, Err(plexus_core::Denial::Resolver(plexus_core::governance::ResolverDenial::RequestFieldForbidden{field: f})) if f == field)
        );
    }
    let reservation = engine
        .authorize(plexus_core::AuthorizationRequest::new(
            plexus_core::github::AFT_PRINCIPAL,
            "conn-fixture",
            "github.issue.search",
            json!({"repositories":["org/repo"],"terms":"bug"}),
        ))
        .unwrap();
    engine.revalidate_and_dispatch(&reservation);
    assert_eq!(transport.requests()[0].args["q"], "bug repo:org/repo");
}

#[test]
fn search_boolean_scope_escape_is_refused_and_counts_are_filtered() {
    let (_scratch, _, engine, transport, _) =
        setup("search-count", &[("github.issue.search", "read")]);
    for terms in [
        "foo OR bar",
        "NOT foo",
        "(repo:other/x)",
        "foo (bar)",
        "-org:other",
    ] {
        assert!(
            matches!(
            plexus_core::github::reads::read_scoped(
                &engine,
                plexus_core::github::AFT_PRINCIPAL,
                "github.issue.search",
                &json!(["org/repo"]),
                &json!({"terms":terms}),
                None
            ), Err(plexus_core::github::reads::ReadError::Denied(plexus_core::Denial::Resolver(plexus_core::governance::ResolverDenial::RequestFieldForbidden {field}))) if field == "query_qualifier"),
            "{terms}"
        );
    }
    transport.set_response(MockResponse::Success(json!({"total_count":900,"incomplete_results":false,
        "items":[{"repository":{"full_name":"org/repo"}},{"repository":{"full_name":"other/private"}}]})));
    let result = plexus_core::github::reads::read_scoped(
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        "github.issue.search",
        &json!(["org/repo"]),
        &json!({"terms":"bug"}),
        None,
    )
    .unwrap();
    assert_eq!(result["total_count"], 1);
    assert_eq!(result["incomplete"], true);
}

#[test]
fn completed_effects_replay_before_disabled_handle_and_live_claim() {
    let (scratch, store, engine, transport, scope) =
        setup("finish-replay", &[("add_reaction", "write")]);
    let db = Connection::open(scratch.path()).unwrap();
    db.execute_batch("CREATE TRIGGER fail_finish BEFORE UPDATE OF state ON github_bot_receipt WHEN NEW.state='completed' BEGIN SELECT RAISE(FAIL,'unavailable'); END;").unwrap();
    transport.set_response(MockResponse::Success(json!({"id":7,"content":"eyes"})));
    let request = json!({"action":"issue reaction","repository":"org/repo","target":{"number":42},"body":{"reaction":"eyes"}});
    let send = || {
        bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            "finish",
            "request",
            "worker",
            plexus_core::storage::now_ms(),
        )
    };
    let first = send();
    assert_eq!(first["result"]["status"], "completed");
    db.execute_batch("DROP TRIGGER fail_finish; UPDATE github_app_handle SET status='disabled';")
        .unwrap();
    assert_eq!(send()["result"], first["result"]);
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn malformed_mutation_fields_never_dispatch() {
    let (_scratch, store, engine, transport, scope) = setup(
        "field-types",
        &[
            ("github.issue.get", "read"),
            ("edit_issue", "write"),
            ("close_issue", "write"),
        ],
    );
    let mut cases = vec![(
        json!({"verb":"issue close","repository":"org/repo","number":42,"comment":null}),
        "comment",
    )];
    for field in [
        "labels",
        "assignees",
        "add_labels",
        "remove_labels",
        "add_assignees",
        "remove_assignees",
    ] {
        let mut request = json!({"action":"issue edit","repository":"org/repo","target":{"number":42},"body":{"title":"title"}});
        request["body"][field] = json!("bug");
        cases.push((request, field));
    }
    for (request, field) in cases {
        let reply = bot_request_scoped(
            &store,
            &engine,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request,
            field,
            "request",
            "worker",
            plexus_core::storage::now_ms(),
        );
        assert_eq!(
            reply["result"]["refusal_code"],
            format!("request_field_forbidden{{field: {field}}}")
        );
    }
    assert!(transport.requests().is_empty());
}

#[test]
fn claim_storage_error_has_stable_sanitized_code() {
    let (scratch, store, engine, _, scope) = setup("claim-failure", &[("add_reaction", "write")]);
    Connection::open(scratch.path()).unwrap().execute_batch("CREATE TRIGGER fail_claim BEFORE INSERT ON github_bot_receipt BEGIN SELECT RAISE(FAIL,'backend secret'); END;").unwrap();
    let reply = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &json!({"action":"issue reaction","repository":"org/repo","target":{"number":42},"body":{"reaction":"eyes"}}),
        "failure",
        "request",
        "worker",
        plexus_core::storage::now_ms(),
    );
    assert_eq!(reply["result"]["refusal_code"], "store_failure");
    assert!(!reply.to_string().contains("backend secret"));
}
