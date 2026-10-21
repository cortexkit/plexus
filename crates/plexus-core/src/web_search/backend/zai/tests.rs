use super::*;
use crate::manifest::{Risk, TransportKind};
use crate::web_search::query::Recency;

fn query() -> WebSearchQuery {
    WebSearchQuery {
        query: "weather report".into(),
        max_results: 5,
        include_domains: vec![],
        recency: None,
    }
}

fn prepare(schema: Value) -> Result<PreparedSearch, CapabilitySkip> {
    let backend = ZaiMcpBackend::default();
    backend.prepare_reviewed(backend.prepare(&query(), 0).unwrap(), Some(&schema), "zai")
}

#[test]
fn reviewed_query_field_is_preferred_and_declared_count_is_sent() {
    assert_eq!(
        prepare(json!({"properties": {"query": {}, "search_query": {}, "count": {}}}))
            .unwrap()
            .vendor_args,
        json!({"query": "weather report", "count": 5})
    );
}

#[test]
fn reviewed_search_query_variant_is_used_without_argument_retries() {
    assert_eq!(
        prepare(json!({"properties": {"search_query": {}, "count": {}}}))
            .unwrap()
            .vendor_args,
        json!({"search_query": "weather report", "count": 5})
    );
}

#[test]
fn undeclared_count_is_omitted_for_both_query_variants() {
    for field in ["query", "search_query"] {
        let mut schema = json!({"properties": {}});
        schema["properties"][field] = json!({"type": "string"});
        let args = prepare(schema).unwrap().vendor_args;
        assert_eq!(args.as_object().unwrap().len(), 1);
        assert_eq!(args[field], "weather report");
        assert!(args.get("count").is_none());
    }
}

#[test]
fn missing_reviewed_query_fields_skip_and_log_only_once_per_connection() {
    const TEST: &str = "web_search::backend::zai::tests::missing_reviewed_query_fields_skip_and_log_only_once_per_connection";
    if std::env::var_os("PLEXUS_ZAI_LOG_CHILD").is_none() {
        let output = crate::bounded::child_test_output(
            TEST,
            &[
                ("PLEXUS_ZAI_LOG_CHILD", "1"),
                ("PLEXUS_LOG_STDERR_CHILD", "1"),
            ],
            std::time::Duration::from_secs(30),
            "ZAI unsupported schema log child",
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr
                .matches("declares neither query nor search_query")
                .count(),
            2,
            "unsupported schema must log once per connection"
        );
        return;
    }
    use crate::test_logging as logging;
    logging::init_child();
    let backend = ZaiMcpBackend::default();
    for (connection, schema) in [
        ("one", None),
        ("one", Some(json!({"properties":{"count":{}}}))),
        ("two", Some(json!({}))),
    ] {
        let result = backend.prepare_reviewed(
            backend.prepare(&query(), 0).unwrap(),
            schema.as_ref(),
            connection,
        );
        assert_eq!(
            result,
            Err(CapabilitySkip {
                provider: "zai",
                reason: CapabilitySkipReason::Capability,
                failed: CapabilityFailure::Schema,
            })
        );
    }
    assert_eq!(
        *backend.unsupported_connections.lock().unwrap(),
        HashSet::from(["one".into(), "two".into()])
    );
}

#[test]
fn capability_serves_unfiltered_and_skips_domains_or_recency() {
    let backend = ZaiMcpBackend::default();
    assert_eq!(
        backend.prepare(&query(), 0).unwrap().vendor_args,
        json!({"query":"weather report", "count":5})
    );
    let mut search = query();
    search.max_results = 50;
    assert_eq!(backend.prepare(&search, 0).unwrap().query.max_results, 20);
    search.include_domains.push("example.com".into());
    assert_eq!(
        backend.prepare(&search, 0).unwrap_err().failed,
        CapabilityFailure::DomainFilter
    );
    search.include_domains.clear();
    for recency in [Recency::Day, Recency::Week, Recency::Month, Recency::Year] {
        search.recency = Some(recency);
        assert_eq!(
            backend.prepare(&search, 0).unwrap_err().failed,
            CapabilityFailure::Recency
        );
    }
}

#[test]
fn existing_backend_default_hook_preserves_prepared_bytes() {
    let backend = super::super::ExaRestBackend;
    let prepared = backend.prepare(&query(), 0).unwrap();
    let bytes = serde_json::to_vec(&prepared.vendor_args).unwrap();
    let passed = backend
        .prepare_reviewed(prepared.clone(), Some(&json!({"properties": {}})), "exa")
        .unwrap();
    assert_eq!(passed, prepared);
    assert_eq!(serde_json::to_vec(&passed.vendor_args).unwrap(), bytes);
}

#[test]
fn mapping_uses_sources_only_with_link_url_dates_and_bounded_excerpts() {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let reply = crate::mcp_payload::decode_tool_result(fixtures["success"]["result"].clone());
    let backend = ZaiMcpBackend::default();
    let results = backend.map_reply(&reply, 5, 0).unwrap();
    assert_eq!(
        results,
        vec![
            WebSearchResult {
                url: "https://example.com/search".into(),
                title: "Z.AI search".into(),
                excerpt: "Source excerpt.".into(),
                published_at: Some("2026-06-18T00:00:00.000Z".into()),
                fetched_at: "1970-01-01T00:00:00.000Z".into()
            },
            WebSearchResult {
                url: "https://example.org/source".into(),
                title: "Second source".into(),
                excerpt: "Another excerpt.".into(),
                published_at: None,
                fetched_at: "1970-01-01T00:00:00.000Z".into()
            },
        ]
    );
    assert!(!serde_json::to_string(&results)
        .unwrap()
        .contains("ANSWER MUST NOT LEAK"));
    assert_eq!(backend.map_reply(&reply, 1, 0).unwrap().len(), 1);
    assert!(backend.map_reply(&reply, 0, 0).unwrap().is_empty());
    assert_eq!(backend.map_reply(&json!([]), 5, 0), Ok(vec![]));
    assert!(backend
        .map_reply(&json!({"answer":"not results"}), 5, 0)
        .is_err());
    let reply = json!([
        {"title":"no link"}, {"link":" ", "url":""},
        {"link":" ", "url":" https://example.net/ ", "content":"é".repeat(700), "publish_date":"bad date"}
    ]);
    let results = backend.map_reply(&reply, 5, 0).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.net/");
    assert_eq!(results[0].excerpt, "é".repeat(600));
    assert!(results[0].published_at.is_none());
    let many = json!(vec![json!({"link":"https://example.com/"}); 25]);
    assert_eq!(backend.map_reply(&many, 25, 0).unwrap().len(), 20);
}

#[test]
fn shipped_manifest_and_registry_pin_mcp_read_and_vault_binding() {
    let manifest = crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!("../../../../../../catalog/zai.jsonc"))
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
    .manifest;
    assert_eq!(manifest.key, "zai");
    assert_eq!(manifest.transport.kind, TransportKind::McpRemote);
    assert_eq!(
        manifest.transport.url,
        "https://api.z.ai/api/mcp/web_search_prime/mcp"
    );
    assert_eq!(manifest.actions_baseline.len(), 1);
    let action = &manifest.actions_baseline[0];
    assert_eq!(action.name, "web_search_prime");
    assert_eq!(action.risk, Risk::Read);
    assert!(action.idempotency.is_none(), "read-only MCP search is Pure");
    assert_eq!(manifest.credential_bindings.len(), 1);
    let binding = &manifest.credential_bindings[0];
    assert_eq!(
        (
            &*binding.ref_role,
            &*binding.placement,
            &*binding.key,
            &*binding.prefix,
            binding.required
        ),
        ("api_key", "header", "Authorization", "Bearer ", true)
    );
    let provider = crate::web_search::providers::provider_named("zai").unwrap();
    let backend = crate::web_search::registered_backend(provider).unwrap();
    assert_eq!(
        (backend.name(), backend.app_key(), backend.action()),
        ("zai", "zai", "web_search_prime")
    );
    assert_eq!(provider.action, backend.action());
    assert_eq!(
        provider.credential,
        crate::web_search::providers::VaultCredential::Required("apikey:zai")
    );
}
