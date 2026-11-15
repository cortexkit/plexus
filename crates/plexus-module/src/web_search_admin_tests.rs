use super::*;
use plexus_core::web_search::providers::PROVIDER_NAMES;

const ORDER: &str = manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP;
const ALLOWANCE: &str = manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP;

async fn command(fixture: &Fixture, op: &str, params: Value) -> Value {
    fixture
        .send(Principal::Direct, json!({"method": op, "params": params}))
        .await
}

fn changes(fixture: &Fixture, action: &str) -> Vec<Value> {
    let db = Connection::open(fixture.path.as_ref() as &Path).unwrap();
    let mut query = db
        .prepare(
            "SELECT args_redaction_summary FROM audit_journal
         WHERE action=?1 AND gate='operator_ceremony' AND principal='direct' AND risk='write'
         ORDER BY journal_id",
        )
        .unwrap();
    query
        .query_map([action], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|row| serde_json::from_str(&row.unwrap()).unwrap())
        .collect()
}

/// Routing now chooses each search's provider, so the order command is
/// refused by name whatever it is asked, and the stored order row is kept
/// untouched for a rollback to read.
#[tokio::test]
async fn order_command_is_retired_by_name_and_leaves_the_stored_order() {
    let fixture = Fixture::new("order-retired");
    fixture
        .store
        .set_web_search_order(&["tavily".into(), "exa".into()])
        .unwrap();
    for params in [
        json!({"providers": ["exa", "tavily"]}),
        json!({"providers": ["exa"], "dry_run": false}),
        json!({"clear": true, "dry_run": false}),
        json!({"providers": "malformed"}),
        json!({}),
    ] {
        let reply = command(&fixture, ORDER, params.clone()).await;
        assert_eq!(code(&reply), "web_search_order_retired", "{params}: {reply}");
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("set_web_search_order") && message.contains("routing"),
            "{reply}"
        );
    }
    assert_eq!(
        fixture.store.web_search_order().unwrap(),
        Some(vec!["tavily".into(), "exa".into()])
    );
    assert!(changes(&fixture, "set_web_search_order").is_empty());
}

#[tokio::test]
async fn allowance_previews_applies_and_clears_only_the_named_provider() {
    let fixture = Fixture::new("allowance-ceremony");
    let dry = command(&fixture, ALLOWANCE, json!({"provider": "exa", "count": 1})).await;
    assert_eq!(
        dry["result"],
        json!({"provider": "exa", "previous": null, "new": 1, "outcome": "would_set", "dry_run": true})
    );
    assert_eq!(fixture.store.web_search_allowance("exa").unwrap(), None);
    assert!(changes(&fixture, "set_web_search_allowance").is_empty());
    for (count, previous) in [(1, Value::Null), (10_000_000, json!(1))] {
        let reply = command(
            &fixture,
            ALLOWANCE,
            json!({"provider": "exa", "count": count, "dry_run": false}),
        )
        .await;
        assert_eq!(reply["result"]["previous"], previous, "{reply}");
        assert_eq!(reply["result"]["new"], count);
        assert_eq!(
            fixture.store.web_search_allowance("exa").unwrap(),
            Some(count)
        );
        if count == 1 {
            // Every search is metered against a set allowance: the first
            // spends it, and the next finds Exa's allowance used up.
            let served = fixture
                .search(Principal::Direct, json!({"query": "stored allowance"}))
                .await;
            assert_eq!(served["result"]["backend"], "exa", "{served}");
            let refused = fixture
                .search(Principal::Direct, json!({"query": "another search"}))
                .await;
            assert_eq!(
                refused["error"]["detail"],
                json!([{"provider": "exa", "reason": "allowance"}]),
                "{refused}"
            );
            assert_eq!(
                fixture
                    .store
                    .web_search_allowance_used("exa", "direct", NOW_MS)
                    .unwrap(),
                1
            );
        }
    }
    let other = command(
        &fixture,
        ALLOWANCE,
        json!({"provider": "tavily", "count": 2, "dry_run": false}),
    )
    .await;
    assert_eq!(other["result"]["outcome"], "set", "{other}");
    let dry_clear = command(
        &fixture,
        ALLOWANCE,
        json!({"provider": "exa", "clear": true}),
    )
    .await;
    assert_eq!(dry_clear["result"]["outcome"], "would_clear");
    assert_eq!(
        fixture.store.web_search_allowance("exa").unwrap(),
        Some(10_000_000)
    );
    assert_eq!(changes(&fixture, "set_web_search_allowance").len(), 3);
    let cleared = command(
        &fixture,
        ALLOWANCE,
        json!({"provider": "exa", "clear": true, "dry_run": false}),
    )
    .await;
    assert_eq!(cleared["result"]["outcome"], "cleared", "{cleared}");
    assert_eq!(fixture.store.web_search_allowance("exa").unwrap(), None);
    assert_eq!(
        fixture.store.web_search_allowance("tavily").unwrap(),
        Some(2)
    );
    assert_eq!(fixture.store.web_search_order().unwrap(), None);
    assert_eq!(
        changes(&fixture, "set_web_search_allowance"),
        vec![
            json!({"provider": "exa", "previous": null, "new": 1}),
            json!({"provider": "exa", "previous": 1, "new": 10_000_000}),
            json!({"provider": "tavily", "previous": null, "new": 2}),
            json!({"provider": "exa", "previous": 10_000_000, "new": null}),
        ]
    );
}

#[tokio::test]
async fn admin_commands_accept_every_table_name_and_reject_unknown_names() {
    let fixture = Fixture::new("admin-names");
    let limit = manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP;
    for provider in PROVIDER_NAMES {
        for (op, params) in [
            (ALLOWANCE, json!({"provider": provider.name, "count": 1})),
            (
                limit,
                json!({"backend": provider.name, "per_caller_per_minute": 3, "per_backend_per_minute": 7}),
            ),
        ] {
            let reply = command(&fixture, op, params.clone()).await;
            assert_eq!(
                reply["result"]["outcome"], "would_set",
                "{op} {params}: {reply}"
            );
            let mut apply = params;
            apply["dry_run"] = json!(false);
            let reply = command(&fixture, op, apply).await;
            assert_eq!(reply["result"]["outcome"], "set", "{op}: {reply}");
        }
        assert_eq!(
            fixture.store.web_search_limits(provider.name).unwrap(),
            Some(WebSearchLimits {
                per_caller_per_minute: 3,
                per_backend_per_minute: 7,
            })
        );
    }
    for unknown in ["", "EXA", "exa_rest", "tavily_rest", "bing", "public"] {
        for dry_run in [true, false] {
            for (op, params) in [
                (
                    ALLOWANCE,
                    json!({"provider": unknown, "count": 1, "dry_run": dry_run}),
                ),
                (
                    ALLOWANCE,
                    json!({"provider": unknown, "clear": true, "dry_run": dry_run}),
                ),
                (
                    limit,
                    json!({"backend": unknown, "per_caller_per_minute": 3, "per_backend_per_minute": 7, "dry_run": dry_run}),
                ),
            ] {
                let reply = command(&fixture, op, params).await;
                assert_eq!(code(&reply), "unknown_backend", "{op}: {reply}");
            }
        }
    }
    assert_eq!(
        changes(&fixture, "set_web_search_allowance").len(),
        PROVIDER_NAMES.len()
    );
    assert_eq!(fixture.store.web_search_limits("bing").unwrap(), None);
}

#[tokio::test]
async fn allowance_rejects_out_of_range_and_noninteger_counts_without_writes() {
    let fixture = Fixture::new("allowance-invalid");
    for dry_run in [true, false] {
        for count in [
            json!(0),
            json!(-1),
            json!(10_000_001),
            json!(u64::MAX),
            json!(1.5),
            json!("2"),
            json!(true),
            Value::Null,
        ] {
            let reply = command(
                &fixture,
                ALLOWANCE,
                json!({"provider": "exa", "count": count, "dry_run": dry_run}),
            )
            .await;
            assert_eq!(code(&reply), "invalid_request", "{reply}");
        }
        let absent = command(
            &fixture,
            ALLOWANCE,
            json!({"provider": "exa", "dry_run": dry_run}),
        )
        .await;
        assert_eq!(code(&absent), "invalid_request");
    }
    assert_eq!(fixture.store.web_search_allowance("exa").unwrap(), None);
    assert!(changes(&fixture, "set_web_search_allowance").is_empty());
}

#[tokio::test]
async fn clear_rejects_names_counts_missing_provider_and_nonboolean_intent() {
    let fixture = Fixture::new("clear-invalid");
    for dry_run in [true, false] {
        for (op, mut params) in [
            (ALLOWANCE, json!({"clear": true})),
            (
                ALLOWANCE,
                json!({"clear": true, "provider": "exa", "count": 2}),
            ),
            (
                ALLOWANCE,
                json!({"clear": true, "provider": "exa", "count": null}),
            ),
            (
                ALLOWANCE,
                json!({"clear": "true", "provider": "exa", "count": 2}),
            ),
        ] {
            params["dry_run"] = json!(dry_run);
            let reply = command(&fixture, op, params).await;
            assert_eq!(code(&reply), "invalid_request", "{op}: {reply}");
        }
    }
    assert!(changes(&fixture, "set_web_search_allowance").is_empty());
}

#[tokio::test]
async fn allowance_requires_direct_management_and_explicit_apply() {
    let fixture = Fixture::new("admin-authority");
    for (op, mut params) in [(ALLOWANCE, json!({"provider": "exa", "count": 2}))] {
        let preview = command(&fixture, op, params.clone()).await;
        assert_eq!(preview["result"]["dry_run"], true, "{preview}");
        for dry_run in [Value::Null, json!("false")] {
            params["dry_run"] = dry_run;
            let reply = command(&fixture, op, params.clone()).await;
            assert_eq!(code(&reply), "invalid_request", "{reply}");
            assert_eq!(
                reply["error"]["message"], "dry_run must be a boolean",
                "{reply}"
            );
        }
        params["dry_run"] = json!(true);
        let preview = command(&fixture, op, params.clone()).await;
        assert_eq!(preview["result"]["dry_run"], true, "{preview}");
        params["dry_run"] = json!(false);
        for principal in [aft(), basal()] {
            let reply = fixture
                .send(principal, json!({"method": op, "params": params}))
                .await;
            assert_eq!(code(&reply), "operator_authority_required", "{reply}");
        }
        let tool = fixture
            .send(Principal::Direct, json!({"name": op, "arguments": params}))
            .await;
        assert!(tool.get("error").is_some(), "{tool}");
    }
    assert_eq!(fixture.store.web_search_allowance("exa").unwrap(), None);
    assert!(changes(&fixture, "set_web_search_allowance").is_empty());
}

/// code_search charges the grep_app row of the limits table, so the limit op
/// must accept it; the allowance op stays web-search only. An
/// applied change reports and audits the row the write itself replaced.
#[tokio::test]
async fn code_search_limits_are_settable_and_report_the_replaced_row() {
    let fixture = Fixture::new("code-search-limit");
    let limit = manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP;
    let backend = plexus_core::code_search::BACKEND;
    let dry = command(
        &fixture,
        limit,
        json!({"backend": backend, "per_caller_per_minute": 3, "per_backend_per_minute": 7}),
    )
    .await;
    assert_eq!(
        dry["result"]["outcome"], "would_set",
        "the code_search backend's limits must be settable: {dry}"
    );
    for (per_caller, per_backend, previous, source) in [
        (
            3,
            7,
            json!({"per_caller_per_minute": 30, "per_backend_per_minute": 120}),
            "default",
        ),
        (
            4,
            9,
            json!({"per_caller_per_minute": 3, "per_backend_per_minute": 7}),
            "set",
        ),
    ] {
        let reply = command(
            &fixture,
            limit,
            json!({"backend": backend, "per_caller_per_minute": per_caller,
                "per_backend_per_minute": per_backend, "dry_run": false}),
        )
        .await;
        assert_eq!(reply["result"]["outcome"], "set", "{reply}");
        assert_eq!(
            (
                &reply["result"]["previous"],
                &reply["result"]["previous_source"]
            ),
            (&previous, &json!(source)),
            "the reply must report the row the write replaced: {reply}"
        );
    }
    assert_eq!(
        fixture.store.web_search_limits(backend).unwrap(),
        Some(WebSearchLimits {
            per_caller_per_minute: 4,
            per_backend_per_minute: 9,
        })
    );
    let db = Connection::open(fixture.path.as_ref() as &Path).unwrap();
    let summary: String = db
        .query_row(
            "SELECT args_redaction_summary FROM audit_journal
             WHERE action='set_web_search_limit' ORDER BY journal_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        summary,
        "backend=grep_app per_caller_per_minute 3 -> 4, per_backend_per_minute 7 -> 9 (previous values were set)"
    );
    for (op, params) in [(ALLOWANCE, json!({"provider": backend, "count": 1}))] {
        let reply = command(&fixture, op, params).await;
        assert_eq!(code(&reply), "unknown_backend", "{op}: {reply}");
    }
}
