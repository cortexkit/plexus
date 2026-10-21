use super::*;
use crate::storage::{
    web_search_store::WebSearchLimits, CatalogActionInput, GrantInput, PlexusStore,
    CATALOG_PRINCIPAL,
};
use crate::test_scratch::Scratch;
use crate::{MockResponse, MockTransport, StubCredentialSource};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

#[test]
fn store_and_reply_errors_keep_operator_diagnostics() {
    const TEST: &str = "code_search::tests::store_and_reply_errors_keep_operator_diagnostics";
    if std::env::var_os("PLEXUS_SEARCH_DIAGNOSTIC_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        let f = Fixture::new();
        f.grant("direct");
        f.transport.set_response(MockResponse::Success(
            json!({"content":[{"type":"text","text":"invalid"}]}),
        ));
        assert_eq!(
            f.search("direct", None).unwrap_err().to_wire()["error"]["code"],
            "backend_unavailable"
        );
        let sql = rusqlite::Connection::open(&*f.path).unwrap();
        sql.execute("DROP TABLE web_search_limits", []).unwrap();
        assert_eq!(
            f.search("direct", None).unwrap_err().to_wire()["error"]["code"],
            "backend_unavailable"
        );
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[
            ("PLEXUS_SEARCH_DIAGNOSTIC_CHILD", "1"),
            ("PLEXUS_LOG_STDERR_CHILD", "1"),
        ],
        std::time::Duration::from_secs(30),
        "search diagnostics child",
    );
    assert!(output.status.success(), "diagnostic fixture must complete");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("code_search reply unreadable:"),
        "reply error cause must reach operator logs: {stderr}"
    );
    assert!(
        stderr.contains("code_search store lookup failed:") && stderr.contains("web_search_limits"),
        "store error cause must reach operator logs: {stderr}"
    );
}

struct Fixture {
    store: Arc<PlexusStore>,
    transport: Arc<MockTransport>,
    engine: GovernanceEngine<StubCredentialSource, MockTransport>,
    service: CodeSearchService,
    path: Scratch,
}

impl Fixture {
    fn new() -> Self {
        let path = Scratch::database("code-search");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "code-search".into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let source =
            subc_jsonc::jsonc_to_json(include_str!("../../../../catalog/grep_app.jsonc")).unwrap();
        let manifest = crate::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
        store.upsert_manifest(CATALOG_PRINCIPAL, &manifest).unwrap();
        store
            .insert_connection(
                "direct",
                "grep",
                BACKEND,
                "pending",
                &json!({"required":[],"optional":[],"write_enabling":[]}),
            )
            .unwrap();
        let ticket = store
            .create_binding_ticket_with_role("direct", "grep", "none", b"")
            .unwrap();
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .unwrap();
        let schema = json!({"type":"object"});
        store
            .upsert_catalog_action(&CatalogActionInput {
                principal: "direct".into(),
                connection_id: "grep".into(),
                name: ACTION.into(),
                title: None,
                schema: schema.clone(),
                schema_hash: crate::jcs_sha256(&schema).unwrap(),
                risk: "read".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        let transport = Arc::new(MockTransport::default());
        transport.set_response(MockResponse::Success(reply::tests::captured_reply()));
        Self {
            engine: GovernanceEngine::new(
                store.clone(),
                Arc::new(StubCredentialSource::default()),
                transport.clone(),
            ),
            store,
            transport,
            path,
            service: CodeSearchService::with_clock(Arc::new(|| 1_790_000_000_000)),
        }
    }

    fn grant(&self, caller: &str) {
        self.store
            .insert_grant(&GrantInput {
                principal: "direct".into(),
                connection_id: "grep".into(),
                grant_id: format!("grant-{caller}"),
                grantee_principal: caller.into(),
                risk_ceiling: "read".into(),
                action_selectors: vec![ACTION.into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
    }

    fn search(
        &self,
        caller: &str,
        scope: Option<&CallScope>,
    ) -> Result<CodeSearchResponse, CodeSearchRefusal> {
        self.service.search_scoped(
            &self.engine,
            caller,
            json!({"query":"pub fn with_capacity"}).as_object().unwrap(),
            scope,
            None,
        )
    }
}

#[test]
fn quarantined_backend_has_a_specific_refusal() {
    let f = Fixture::new();
    f.grant("direct");
    f.store
        .quarantine_action("direct", "grep", ACTION, "operator review")
        .unwrap();
    assert_eq!(
        f.search("direct", None).unwrap_err().to_wire()["error"]["code"],
        "backend_quarantined",
        "quarantine must have a diagnostic refusal"
    );
}

#[test]
fn ambiguous_backend_has_a_specific_refusal() {
    let f = Fixture::new();
    f.grant("direct");
    f.store
        .insert_connection(
            "direct",
            "second",
            BACKEND,
            "pending",
            &json!({"required":[],"optional":[],"write_enabling":[]}),
        )
        .unwrap();
    let ticket = f
        .store
        .create_binding_ticket_with_role("direct", "second", "none", b"")
        .unwrap();
    f.store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    let row = f
        .store
        .catalog_action("direct", "grep", ACTION)
        .unwrap()
        .unwrap();
    f.store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: "second".into(),
            name: ACTION.into(),
            title: row.title,
            schema: row.schema,
            schema_hash: row.schema_hash,
            risk: row.risk,
            severity: row.severity,
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    f.store
        .insert_grant(&GrantInput {
            principal: "direct".into(),
            connection_id: "second".into(),
            grant_id: "second-grant".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![ACTION.into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    assert_eq!(
        f.search("direct", None).unwrap_err().to_wire()["error"]["code"],
        "backend_ambiguous",
        "ambiguity must have a diagnostic refusal"
    );
    assert!(f.transport.requests().is_empty());
}

#[test]
fn consent_refusal_names_the_unsent_action() {
    let error = CodeSearchRefusal::new(RefusalCode::ConsentUnavailable).to_wire();
    assert_eq!(
        error["error"]["action"], ACTION,
        "consent refusal must name its action"
    );
    assert_eq!(error["error"]["transmission"], "not_sent");
}

#[test]
fn blocked_searches_keep_the_code_search_rate_budget() {
    let f = Fixture::new();
    f.grant("direct");
    f.store
        .set_policy("direct", "grep", ACTION, "block", None)
        .unwrap();
    for _ in 0..200 {
        assert_eq!(
            f.search("direct", None).unwrap_err().to_wire()["error"]["code"],
            "policy_blocked",
            "blocked code searches must not consume quota"
        );
    }
    f.store
        .set_policy("direct", "grep", ACTION, "allow", None)
        .unwrap();
    assert!(f.search("direct", None).is_ok());
}

#[test]
fn grant_refusal_without_dispatch_and_candidate_requires_a_module_grant() {
    let f = Fixture::new();
    assert_eq!(
        f.search("direct", None).unwrap_err().code,
        "code_search_not_granted"
    );
    assert!(f.transport.requests().is_empty());
    // Check candidate selection itself: engine authorization independently checks grants too.
    assert!(
        backing_connection(&f.store, "direct", 1_790_000_000_000).is_err(),
        "candidate selection must require a module grant"
    );
    f.grant("direct");
    assert_eq!(f.search("direct", None).unwrap().matches.len(), 10);
    assert_eq!(f.transport.requests().len(), 1);
    assert_eq!(f.transport.requests()[0].action, ACTION);
}

#[test]
fn per_caller_and_global_limits_refuse_without_dispatch() {
    let f = Fixture::new();
    f.grant("direct");
    f.grant("reserved:reader");
    f.store
        .set_web_search_limits(
            BACKEND,
            WebSearchLimits {
                per_caller_per_minute: 1,
                per_backend_per_minute: 2,
            },
        )
        .unwrap();
    f.search("direct", None).unwrap();
    assert_eq!(
        f.search("direct", None).unwrap_err().code,
        "rate_limited",
        "per-caller limit must refuse"
    );
    f.search("reserved:reader", None).unwrap();
    f.grant("reserved:other");
    assert_eq!(
        f.search("reserved:other", None).unwrap_err().code,
        "rate_limited",
        "global limit must refuse"
    );
    assert_eq!(f.transport.requests().len(), 2);
}

#[test]
fn audit_records_query_count_and_scoped_agent_as_attribution_only() {
    let f = Fixture::new();
    f.grant("reserved:basal");
    let scope = CallScope {
        owner: "reserved:basal".into(),
        scope_ref: "flow-1".into(),
        scope_epoch: 1,
        kind: Some("worker".into()),
        parent: None,
        parent_state: None,
        agent_id: Some("reader-agent".into()),
        flow_id: Some("flow-1".into()),
        delegates: true,
        owner_authorized: true,
    };
    f.search("reserved:basal", Some(&scope)).unwrap();
    let db = rusqlite::Connection::open(f.path.path()).unwrap();
    let row:(String,String,i64,String,String,String) = db.query_row("SELECT actor,query_text,result_count,agent_id,scope_flow_id,reason_code FROM audit_journal WHERE gate = 'code_search'",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
    assert_eq!(
        row,
        (
            "reserved:basal".into(),
            "pub fn with_capacity".into(),
            10,
            "reader-agent".into(),
            "flow-1".into(),
            "code_search_dispatched".into()
        )
    );
    assert_eq!(
        f.transport.requests().len(),
        1,
        "the stamped agent needs no independent grant"
    );
}

#[test]
fn no_match_reply_completes_and_audits_zero_results() {
    let f = Fixture::new();
    f.grant("direct");
    f.transport
        .set_response(MockResponse::Success(reply::tests::captured_empty_reply()));

    let response = f.search("direct", None).unwrap();
    assert!(
        response.matches.is_empty(),
        "an empty vendor reply has no matches"
    );

    let db = rusqlite::Connection::open(f.path.path()).unwrap();
    let row: (String, i64, String) = db
        .query_row(
            "SELECT outcome, result_count, reason_code FROM audit_journal WHERE gate = 'code_search'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        ("completed".into(), 0, "code_search_dispatched".into())
    );
}

#[test]
fn vendor_throttle_uses_retry_after_field_not_message_text_and_audits_reason() {
    let f = Fixture::new();
    for (caller, retry_after_ms, expected_retry_after_ms, message) in [
        ("direct", None, 30_000, "vendor throttled this search"),
        (
            "reserved:reader",
            Some(12_000),
            12_000,
            "the vendor's throttle wording has changed",
        ),
    ] {
        f.grant(caller);
        f.transport.set_response(MockResponse::Throttled {
            retry_after_ms,
            message: message.into(),
        });
        let refusal = f.search(caller, None).unwrap_err();
        assert_eq!(refusal.code, "rate_limited");
        assert_eq!(refusal.retry_after_ms, Some(expected_retry_after_ms));
        assert_eq!(
            refusal.to_wire(),
            json!({"error": {
                "code": "rate_limited",
                "message": "code search rate limit reached; retry after retry_after_ms",
                "retry_after_ms": expected_retry_after_ms
            }})
        );

        let db = rusqlite::Connection::open(f.path.path()).unwrap();
        let row: (String, String, Option<i64>) = db
            .query_row(
                "SELECT outcome, reason_code, result_count FROM audit_journal WHERE gate = 'code_search' AND actor = ?1",
                [caller],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("failed".into(), "rate_limited".into(), None));
    }
}

#[test]
fn backend_diagnostics_are_not_exposed_and_home_gates_dispatch() {
    let mut f = Fixture::new();
    f.grant("direct");
    f.transport.set_response(MockResponse::VendorError {
        code: "vendor_bad".into(),
        message: "sensitive vendor body".into(),
    });
    let refusal = f.search("direct", None).unwrap_err().to_wire();
    assert_eq!(refusal["error"]["code"], "backend_unavailable");
    assert!(!refusal.to_string().contains("sensitive"));
    let previous_requests = f.transport.requests().len();
    f.engine = f
        .engine
        .with_connector_home_guard(Arc::new(|| Some("not-held".into())));
    assert_eq!(
        f.search("direct", None).unwrap_err().code,
        "backend_unavailable"
    );
    assert_eq!(f.transport.requests().len(), previous_requests);
}

/// The global grep.app bucket is shared by every caller, so a caller without
/// a grant must be refused before it is charged. Otherwise ungranted callers
/// could empty it and lock out the granted ones.
#[test]
fn ungranted_callers_cannot_drain_the_global_bucket() {
    let f = Fixture::new();
    f.grant("direct");
    f.store
        .set_web_search_limits(
            BACKEND,
            WebSearchLimits {
                per_caller_per_minute: 1,
                per_backend_per_minute: 1,
            },
        )
        .unwrap();
    for stranger in ["reserved:stranger-a", "reserved:stranger-b"] {
        assert_eq!(
            f.search(stranger, None).unwrap_err().code,
            "code_search_not_granted",
            "an ungranted caller is refused as not granted, never rate limited"
        );
    }
    assert_eq!(
        f.search("direct", None)
            .expect("the granted caller keeps the global budget")
            .matches
            .len(),
        10
    );
    assert_eq!(f.transport.requests().len(), 1);
}

/// A flow is told which grant to restore, in the same typed form every flow
/// refusal uses; a caller outside a flow keeps the tool's closed code.
#[test]
fn flow_without_a_grant_gets_a_typed_grant_refusal() {
    let f = Fixture::new();
    let scope = CallScope {
        owner: "reserved:stranger".into(),
        scope_ref: "flow-1".into(),
        scope_epoch: 1,
        kind: Some("worker".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: Some("flow-1".into()),
        delegates: true,
        owner_authorized: true,
    };
    let wire = f
        .search("reserved:stranger", Some(&scope))
        .unwrap_err()
        .to_wire();
    assert_eq!(
        wire["error"]["code"], "module_grant_absent",
        "a flow must be told which grant to restore: {wire}"
    );
    assert_eq!(wire["error"]["detail"]["action"], ACTION);
    assert_eq!(wire["error"]["detail"]["cause"], "missing");
    assert_eq!(
        f.search("reserved:stranger", None).unwrap_err().code,
        "code_search_not_granted"
    );
    assert!(f.transport.requests().is_empty());
}

/// A quarantine denial from authorization (reachable when the action is
/// quarantined after the preflight read it) maps to the quarantine refusal,
/// as an invoke would report it, not to an unavailable backend.
#[test]
fn quarantine_met_at_authorize_is_backend_quarantined() {
    let denial = crate::governance::Denial::Catalog(crate::governance::CatalogDenial::Quarantined);
    assert_eq!(
        refusal_from(facade::denial_for(&denial, grant_target("direct"))).code,
        "backend_quarantined",
        "a quarantine met at authorize must name the quarantine"
    );
}

/// The search row carries the engine's request id, so a reviewer can join the
/// query to the engine's authorization and dispatch rows for the same call.
#[test]
fn the_search_row_joins_the_engine_rows_by_request_id() {
    let f = Fixture::new();
    f.grant("direct");
    f.search("direct", None).unwrap();
    let db = rusqlite::Connection::open(f.path.path()).unwrap();
    let request_id = |gate: &str| -> Option<String> {
        db.query_row(
            "SELECT request_id FROM audit_journal WHERE gate = ?1",
            [gate],
            |row| row.get(0),
        )
        .unwrap()
    };
    let search = request_id("code_search");
    assert!(search.is_some(), "the search row must carry a request id");
    assert_eq!(
        search,
        request_id("dispatch"),
        "the search row must carry the engine's request id"
    );
}

/// After governance admitted a search, the row says whether the request
/// reached the vendor: a vendor failure is an allowed call that failed, an
/// unresolved send is unknown, and a dispatch that never left is not sent.
#[test]
fn a_dispatched_search_row_states_what_reached_the_vendor() {
    let f = Fixture::new();
    for (caller, response, expected) in [
        (
            "direct",
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "vendor down".into(),
            },
            ("allow", "failed"),
        ),
        (
            "reserved:unknown",
            MockResponse::OutcomeUnknown,
            ("allow", "unknown"),
        ),
        (
            "reserved:unsent",
            MockResponse::TransientNotSent {
                message: "connection refused".into(),
            },
            ("deny", "not_sent"),
        ),
    ] {
        f.grant(caller);
        f.transport.set_response(response);
        assert!(f.search(caller, None).is_err());
        let db = rusqlite::Connection::open(f.path.path()).unwrap();
        let row: (String, String) = db
            .query_row(
                "SELECT decision, outcome FROM audit_journal WHERE gate = 'code_search' AND actor = ?1",
                [caller],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (row.0.as_str(), row.1.as_str()),
            expected,
            "the search row must state what reached the vendor for {caller}"
        );
    }
}

/// The audit row records which repositories, paths and languages a search
/// read and which match options it used, not only the query text.
#[test]
fn the_search_row_records_the_filters() {
    let f = Fixture::new();
    f.grant("direct");
    f.service
        .search_scoped(
            &f.engine,
            "direct",
            json!({"query": "with_capacity", "regex": true, "repo": "rust-lang/rust",
                "path": "library/", "language": ["Rust"]})
            .as_object()
            .unwrap(),
            None,
            None,
        )
        .unwrap();
    let db = rusqlite::Connection::open(f.path.path()).unwrap();
    let summary: String = db
        .query_row(
            "SELECT args_redaction_summary FROM audit_journal WHERE gate = 'code_search'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&summary).unwrap(),
        json!({"filters": {"regex": true, "repo": "rust-lang/rust", "path": "library/",
            "language": ["Rust"]}}),
        "the search row must record the filters"
    );
}

/// A credential pasted into a code search (to check whether it leaked) is
/// sent to the vendor but never stored: the audit row keeps the other words
/// and says a word was redacted. Filters get the same treatment.
#[test]
fn credential_shaped_query_words_are_not_stored() {
    let f = Fixture::new();
    f.grant("direct");
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    f.service
        .search_scoped(
            &f.engine,
            "direct",
            json!({"query": format!("\"{token}\" leaked"), "repo": token})
                .as_object()
                .unwrap(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        f.transport.requests()[0].args["query"],
        format!("\"{token}\" leaked"),
        "the vendor still receives the query as written"
    );
    let db = rusqlite::Connection::open(f.path.path()).unwrap();
    let (query_text, summary): (String, String) = db
        .query_row(
            "SELECT query_text, args_redaction_summary FROM audit_journal WHERE gate = 'code_search'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        query_text, "[redacted] leaked",
        "a credential-shaped query word must not be stored"
    );
    let summary: Value = serde_json::from_str(&summary).unwrap();
    assert_eq!(summary["query_redacted"], true);
    assert_eq!(summary["filters_redacted"], true);
    assert!(
        !db.query_row("SELECT group_concat(coalesce(query_text,'') || coalesce(args_redaction_summary,''), ' ') FROM audit_journal", [], |row| row.get::<_, String>(0))
            .unwrap()
            .contains("ghp_abcdefghij"),
        "no search row may hold the token"
    );
}
