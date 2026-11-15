use super::*;

#[test]
fn declarations_are_the_shape_routing_reads() {
    let declarations = role_declarations(&[
        RouteRef::new("tavily", "search"),
        RouteRef::new("exa", "search"),
        RouteRef::new("exa", "search"),
    ]);
    assert_eq!(
        serde_json::to_value(&declarations).unwrap(),
        json!({
            "routing/v1": {"consumers": [
                {"name": "plexus.web_search", "kind": "search", "selectors": ["plexus"]}
            ]},
            "search-provider/v1": {"routes": [
                {"provider": "exa", "model": "search"},
                {"provider": "tavily", "model": "search"}
            ]}
        })
    );
    assert_eq!(
        serde_json::to_value(role_declarations(&[])).unwrap()["search-provider/v1"],
        json!({"routes": []})
    );
}

#[test]
fn table_routes_follow_the_provider_table() {
    assert_eq!(
        table_routes(),
        [
            RouteRef::new("exa", "search"),
            RouteRef::new("tavily", "search"),
            RouteRef::new("brave", "web-search"),
            RouteRef::new("deepseek", "search"),
            RouteRef::new("kimi-for-coding", "search"),
            RouteRef::new("ollama-cloud", "web-search"),
        ]
    );
}

#[test]
fn describe_must_serve_search_selection() {
    let serving = fake::FakeRouter::serving_search_describe();
    assert_eq!(
        read_describe_reply(Ok(json!({"result": serving.clone()}))),
        Ok(DescribeFacts {
            attempt_outcomes: true
        })
    );
    let mut legacy_reports = serving.clone();
    legacy_reports["capabilities"] = json!([
        "select_kind",
        "select_media",
        "select_search",
        "select_eligible_routes"
    ]);
    assert_eq!(
        read_describe_reply(Ok(json!({"result": legacy_reports}))),
        Ok(DescribeFacts {
            attempt_outcomes: false
        })
    );
    for (member, value) in [
        ("kinds", json!(["image"])),
        (
            "capabilities",
            json!(["select_kind", "select_media", "select_eligible_routes"]),
        ),
        (
            "capabilities",
            json!(["select_kind", "select_media", "select_search"]),
        ),
        ("version", json!(2)),
        ("role", json!("tools")),
    ] {
        let mut describe = serving.clone();
        describe[member] = value;
        assert!(
            read_describe_reply(Ok(json!({"result": describe}))).is_err(),
            "{member}"
        );
    }
    assert!(
        read_describe_reply(Ok(serving)).is_err(),
        "a bare answer is not a reply"
    );
}

#[test]
fn reports_pair_each_status_with_its_legacy_outcome() {
    let report = |status| report_params("dec", status, true);
    for (status, name, outcome) in [
        (AttemptStatus::Served, "served", "completed"),
        (AttemptStatus::ServedEmpty, "served_empty", "completed"),
        (AttemptStatus::Quota, "quota", "failed"),
        (AttemptStatus::Credential, "credential", "failed"),
        (AttemptStatus::Unavailable, "unavailable", "failed"),
        (AttemptStatus::Rejected, "rejected", "cancelled"),
        (
            AttemptStatus::Throttled {
                retry_after_ms: None,
            },
            "throttled",
            "failed",
        ),
    ] {
        assert_eq!(
            report(status),
            json!({"decision_id": "dec", "outcome": outcome, "attempt_outcome": {"status": name}})
        );
    }
    assert_eq!(
        report(AttemptStatus::Throttled {
            retry_after_ms: Some(0)
        }),
        json!({"decision_id": "dec", "outcome": "failed",
            "attempt_outcome": {"status": "throttled", "retry_after_ms": 0}})
    );
    assert_eq!(
        report_params("dec", AttemptStatus::Rejected, false),
        json!({"decision_id": "dec", "outcome": "cancelled"})
    );
}

#[test]
fn the_catalog_must_list_exactly_one_verified_routing_provider() {
    let entry = |module: &str, verified: bool, provides: &[&str]| {
        json!({"module_id": module, "nonce_verified": verified,
            "capabilities": {"provides": provides}})
    };
    let routing = entry("striatum", true, &["routing/v1"]);
    assert_eq!(
        routing_provider(&json!([
            entry("plexus", true, &["tool-provider/v1"]),
            routing
        ])),
        Ok("striatum".into())
    );
    assert_eq!(
        routing_provider(&json!([entry("striatum", false, &["routing/v1"])])),
        Err(DiscoveryFailure::None)
    );
    assert_eq!(routing_provider(&json!([])), Err(DiscoveryFailure::None));
    assert_eq!(
        routing_provider(&json!([routing, entry("other", true, &["routing/v1"])])),
        Err(DiscoveryFailure::Ambiguous)
    );
}

#[test]
fn select_replies_name_a_route_or_say_why_not() {
    assert!(matches!(
        read_select_reply(Ok(json!({"result": {"decision_id": "d"}}))),
        SelectOutcome::Unavailable(_)
    ));
    assert!(matches!(
        read_select_reply(Ok(json!({
            "result": {"decision_id": "d", "engine": {"provider": "exa", "model": "search"}},
            "extra": 1
        }))),
        SelectOutcome::Unavailable(_)
    ));
    assert!(matches!(
        read_select_reply(Err(RoutingCallError::Unreachable("down".into()))),
        SelectOutcome::Unavailable(_)
    ));
}
