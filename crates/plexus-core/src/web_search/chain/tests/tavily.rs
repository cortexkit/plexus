//! Tavily's documented replies, sent through the real REST transport built from
//! the shipped `catalog/tavily_rest.jsonc`, and how the chain treats each.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::web_search::backend::TavilyRestBackend;
use std::sync::Mutex;

const CONNECTION: &str = "tavily-rest";

/// Records which vault credential each dispatch asked for, and every
/// authentication failure reported back to the vault.
#[derive(Default)]
struct RecordingVault {
    requested: Mutex<Vec<String>>,
    auth_failures: Mutex<Vec<u16>>,
}

impl CredentialSource for RecordingVault {
    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        self.requested.lock().unwrap().push(id.to_string());
        Ok(ResolvedCredential::new(
            b"test-credential".to_vec(),
            None,
            7,
        ))
    }
    fn report_id_auth_failure(&self, _: &str, status: u16) {
        self.auth_failures.lock().unwrap().push(status);
    }
}

fn shipped_manifest(file: &str) -> crate::manifest::AppManifest {
    let source = match file {
        "tavily_rest.jsonc" => include_str!("../../../../../../catalog/tavily_rest.jsonc"),
        "tavily.jsonc" => include_str!("../../../../../../catalog/tavily.jsonc"),
        _ => unreachable!(),
    };
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

/// Connect `connection` of `app_key` for the `direct` principal, which owns
/// it and is the caller every search in these tests runs as. The connection
/// is bound to the vault credential `credential`, with `action` reviewed under
/// `schema` and an invoke grant for `action` to `direct`.
fn connect(
    store: &PlexusStore,
    connection: &str,
    app_key: &str,
    credential: &[u8],
    action: &str,
    schema: Value,
) {
    store
        .insert_connection(
            "direct",
            connection,
            app_key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", connection, credential)
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: connection.into(),
            name: action.into(),
            title: None,
            schema_hash: crate::jcs_sha256(&schema).unwrap(),
            schema,
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_grant(&GrantInput {
            principal: "direct".into(),
            connection_id: connection.into(),
            grant_id: format!("{connection}-direct"),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![action.into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

fn tavily_service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(TavilyRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request Tavily's attempt sent.
    request: String,
    vault: Arc<RecordingVault>,
    /// The chain fields of the call's `web_search` audit row.
    audit: Option<Value>,
}

impl Recorded {
    fn cooldown(&self) -> Option<i64> {
        self.service
            .chain_cooldowns
            .lock()
            .unwrap()
            .get(CONNECTION)
            .map(|until| until - NOW)
    }
}

/// One search with order `tavily`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["tavily"])
}

/// One search with `order`, which must start with `tavily`. Tavily's attempt is
/// answered by the recorded reply `record`; each later provider's attempt, by
/// an Exa-shaped success. The fake server expects one request per provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    assert_eq!(providers.first(), Some(&"tavily"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/tavily/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let manifest = shipped_manifest("tavily_rest.jsonc");
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-tavily-{record}-{}",
        providers.len()
    ));
    connect(
        fixture.store(),
        CONNECTION,
        "tavily_rest",
        b"apikey:tavily",
        "search",
        manifest.actions_baseline[0]
            .http
            .as_ref()
            .unwrap()
            .args_schema
            .clone(),
    );
    order(&fixture, providers);
    // Complete durable setup first. Admission then follows the server's lifetime,
    // so preparation before dispatch cannot expire its listener.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        providers.len(),
        "tavily",
        std::time::Duration::from_secs(30),
        {
            let requests = requests.clone();
            move |index, received| {
                requests.lock().unwrap().push(received.to_string());
                let (status, headers, body) = if index == 0 {
                    (
                        response["status"].as_u64().unwrap(),
                        response["headers"].as_str().unwrap(),
                        response["body"].as_str().unwrap(),
                    )
                } else {
                    (
                        200,
                        "",
                        r#"{"results":[{"url":"https://example.org","title":"Fallback","text":"Weather"}]}"#,
                    )
                };
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        },
    );
    let mut config = RestConfig::from_manifest(&manifest);
    config.base_url = endpoint;
    let vault = Arc::new(RecordingVault::default());
    let engine = GovernanceEngine::new(
        fixture.store().clone(),
        vault.clone(),
        Arc::new(RestTransport::new(config)),
    );
    let service = tavily_service();
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": "Who is Leo Messi?",
            "max_results": 3,
            "include_domains": ["britannica.com"],
            "recency": "year"
        })
        .as_object()
        .unwrap(),
    );
    if let Err(error) = server.join() {
        panic!(
            "{record}: the search did not reach the recorded endpoint once per provider ({error}): {result:?}"
        );
    }
    let request = requests.lock().unwrap().remove(0);
    let audit = engine
        .store()
        .list_audit("direct")
        .unwrap()
        .into_iter()
        .find(|row| row.gate.as_deref() == Some("web_search"))
        .and_then(|row| row.args_redaction_summary)
        .map(|summary| serde_json::from_str(&summary).unwrap());
    Recorded {
        result,
        service,
        request,
        vault,
        audit,
    }
}

fn assert_moved_on(record: &str, reason: SkipReason, cooldown_ms: i64) -> Recorded {
    let recorded = recorded_search(record);
    let refusal = recorded.result.clone().unwrap_err();
    assert_eq!(
        refusal,
        unavailable(&[("tavily", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("detail\":{\"error") && !wire.contains("Tavily"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    recorded
}

#[test]
fn a_documented_success_is_served_from_a_bearer_post_to_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "tavily");
    assert_eq!(
        response
            .results
            .iter()
            .map(|result| (
                result.url.as_str(),
                result.title.as_str(),
                result.published_at.as_deref()
            ))
            .collect::<Vec<_>>(),
        [(
            "https://www.britannica.com/facts/Lionel-Messi",
            "Lionel Messi Facts | Britannica",
            Some("2025-03-11T17:00:00.000Z")
        )]
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("POST /search HTTP/1.1\r\n"), "{head}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer test-credential")),
        "the key travels as a bearer token: {head}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({
            "query": "Who is Leo Messi?",
            "max_results": 3,
            "include_domains": ["britannica.com"],
            "time_range": "year",
            "include_published_date": true,
            "filter_by_published_date": true
        })
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:tavily"],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn a_documented_empty_reply_is_served_empty() {
    let recorded = recorded_search("empty");
    let response = recorded.result.unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("tavily", 0)
    );
    assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn documented_request_errors_reject_without_a_cooldown() {
    for record in ["bad_request", "validation_failed"] {
        let recorded = recorded_search(record);
        assert_eq!(
            recorded.result,
            Err(WebSearchRefusal::RequestRejected {
                backend: "tavily".into()
            }),
            "{record}"
        );
        assert_eq!(recorded.cooldown(), None, "{record}");
    }
}

#[test]
fn a_documented_unauthorized_reply_cools_the_credential_and_reports_it() {
    let recorded = assert_moved_on("unauthorized", SkipReason::Credential, 60_000);
    assert_eq!(*recorded.vault.auth_failures.lock().unwrap(), [401]);
}

#[test]
fn documented_rate_limits_are_throttled_for_the_retry_after_or_a_minute() {
    assert_moved_on("throttled_retry", SkipReason::Throttled, 60_000);
    assert_moved_on("throttled_short_retry", SkipReason::Throttled, 7_000);
    assert_moved_on("throttled_no_retry", SkipReason::Throttled, 60_000);
}

#[test]
fn documented_plan_and_pay_as_you_go_limits_are_quota_and_fall_through() {
    // Tavily declares 432 and 433 as exhausted statuses, so each is treated
    // like 402: the walk moves to the next provider and Tavily cools down for
    // an hour instead of being retried every minute. Neither is a credential
    // failure, so neither is reported to the vault.
    for record in ["plan_limit", "pay_as_you_go_limit"] {
        let recorded = recorded_walk(record, &["tavily", "exa"]);
        let response = recorded.result.as_ref().unwrap();
        assert_eq!(
            (response.backend.as_str(), response.results.len()),
            ("exa", 1),
            "{record} falls through to the next provider"
        );
        assert_eq!(recorded.cooldown(), Some(3_600_000), "{record} cooldown");
        assert_eq!(
            recorded.audit,
            Some(
                json!({"served_by": "exa", "skipped": [{"provider": "tavily", "reason": "quota"}]})
            ),
            "{record}"
        );
        assert_eq!(
            *recorded.vault.requested.lock().unwrap(),
            ["apikey:tavily", "test:exa"]
        );
        assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());

        assert_moved_on(record, SkipReason::Quota, 3_600_000);
    }
}

#[test]
fn a_server_error_or_a_reply_without_results_is_unavailable() {
    assert_moved_on("server_error", SkipReason::Unavailable, 60_000);
    assert_moved_on("malformed", SkipReason::Unavailable, 60_000);
}

#[test]
fn tavily_mcp_connections_are_not_chain_candidates() {
    let refusal_with_mcp = |with_mcp: bool| {
        let (engine, transport) =
            super::super::super::tests::granted_exa_engine(&format!("chain-tavily-mcp-{with_mcp}"));
        if with_mcp {
            // A live MCP Tavily connection, granted to the caller for both its
            // own tool and an action named like the REST search action.
            connect(
                engine.store(),
                "tavily-mcp",
                "tavily",
                b"apikey:tavily",
                "tavily_search",
                json!({"type": "object"}),
            );
            engine
                .store()
                .insert_grant(&GrantInput {
                    principal: "direct".into(),
                    connection_id: "tavily-mcp".into(),
                    grant_id: "tavily-mcp-search".into(),
                    grantee_principal: "direct".into(),
                    risk_ceiling: "read".into(),
                    action_selectors: vec!["search".into()],
                    authority_kind: "invoke".into(),
                    expires_at: None,
                })
                .unwrap();
        }
        order(&engine, &["tavily"]);
        let refusal = search(&tavily_service(), &engine, "direct").unwrap_err();
        assert!(transport.requests().is_empty(), "nothing is dispatched");
        refusal
    };
    let refusal = refusal_with_mcp(true);
    assert_eq!(refusal.code(), "web_search_not_granted");
    assert_eq!(
        refusal,
        refusal_with_mcp(false),
        "an MCP Tavily connection changes nothing for REST search"
    );
}
