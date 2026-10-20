//! Brave's documented replies, sent through the real REST transport built from
//! the shipped `catalog/brave_rest.jsonc`, and how the chain treats each.

use super::*;
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::rest_api::{RestConfig, RestTransport};
use crate::web_search::backend::BraveRestBackend;
use std::collections::BTreeMap;
use std::sync::Mutex;

const CONNECTION: &str = "brave-rest";

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

fn shipped_manifest() -> crate::manifest::AppManifest {
    let source = include_str!("../../../../../../catalog/brave_rest.jsonc");
    crate::manifest::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap()
    .manifest
}

/// Connect `CONNECTION` of `brave_rest` for the `direct` principal, which owns
/// it and is the caller every search in these tests runs as. The connection is
/// bound to the vault credential `apikey:brave`, with `search` reviewed under
/// the shipped schema and an invoke grant for `search` to `direct`.
fn connect_brave(store: &PlexusStore, schema: Value) {
    store
        .insert_connection(
            "direct",
            CONNECTION,
            "brave_rest",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, b"apikey:brave")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: CONNECTION.into(),
            name: "search".into(),
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
            connection_id: CONNECTION.into(),
            grant_id: format!("{CONNECTION}-direct"),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["search".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    /// The request Brave's attempt sent.
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

/// One search with order `brave`, answered by the recorded reply `record`.
fn recorded_search(record: &str) -> Recorded {
    recorded_walk(record, &["brave"])
}

/// One search with `order`, which must start with `brave`. Brave's attempt is
/// answered by the recorded reply `record`; each later provider's attempt, by
/// an Exa-shaped success. The fake server expects one request per provider.
fn recorded_walk(record: &str, providers: &[&str]) -> Recorded {
    assert_eq!(providers.first(), Some(&"brave"));
    let recordings: Value =
        serde_json::from_str(include_str!("../../backend/brave/fixtures.json")).unwrap();
    let response = recordings[record].clone();
    assert!(response.is_object(), "missing recorded response {record}");
    let manifest = shipped_manifest();
    let (fixture, _) = super::super::super::tests::granted_exa_engine(&format!(
        "chain-brave-{record}-{}",
        providers.len()
    ));
    connect_brave(
        fixture.store(),
        manifest.actions_baseline[0]
            .http
            .as_ref()
            .unwrap()
            .args_schema
            .clone(),
    );
    order(&fixture, providers);
    // The server starts only after the store is set up, and waits longer than
    // the default for the request: on a loaded test host the store writes
    // before dispatch can outlast the default two-second accept deadline, and
    // the search would then fail to connect rather than see the recorded reply.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        providers.len(),
        "brave",
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
    let service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(BraveRestBackend));
    let result = service.search(
        &engine,
        "direct",
        json!({
            "query": "python web frameworks",
            "max_results": 3,
            "include_domains": ["docs.python.org", "realpython.com"],
            "recency": "week"
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
        unavailable(&[("brave", reason)]),
        "{record} must move on"
    );
    assert_eq!(recorded.cooldown(), Some(cooldown_ms), "{record} cooldown");
    let wire = refusal.to_wire().to_string();
    assert!(
        !wire.contains("ErrorResponse") && !wire.contains("RATE_LIMITED"),
        "{record}: vendor text must not reach the caller: {wire}"
    );
    assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());
    recorded
}

/// The decoded query parameters of a recorded request line.
fn query_parameters(request: &str) -> (String, BTreeMap<String, String>) {
    let line = request.lines().next().unwrap();
    let target = line
        .strip_prefix("GET ")
        .and_then(|rest| rest.strip_suffix(" HTTP/1.1"))
        .unwrap_or_else(|| panic!("not a GET request line: {line}"));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let decode = |text: &str| {
        let bytes = text.as_bytes();
        let mut decoded = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                decoded.push(u8::from_str_radix(&text[index + 1..index + 3], 16).unwrap());
                index += 3;
            } else {
                decoded.push(if bytes[index] == b'+' {
                    b' '
                } else {
                    bytes[index]
                });
                index += 1;
            }
        }
        String::from_utf8(decoded).unwrap()
    };
    let parameters = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap();
            (decode(key), decode(value))
        })
        .collect();
    (path.to_string(), parameters)
}

#[test]
fn a_documented_success_is_served_from_a_keyed_get_to_web_search() {
    let recorded = recorded_search("success");
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(response.backend, "brave");
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
        [
            (
                "https://example.com/python-frameworks",
                "Python Web Frameworks",
                Some("2025-03-11T17:00:00.000Z")
            ),
            (
                "https://example.org/compare",
                "Comparing Python web frameworks",
                None
            )
        ]
    );
    assert_eq!(recorded.cooldown(), None);

    let (head, body) = recorded.request.split_once("\r\n\r\n").unwrap();
    assert_eq!(body, "", "a GET search carries no body");
    let (path, parameters) = query_parameters(head);
    assert_eq!(path, "/res/v1/web/search");
    assert_eq!(
        parameters,
        BTreeMap::from(
            [
                (
                    "q",
                    "python web frameworks site:docs.python.org OR site:realpython.com"
                ),
                ("count", "3"),
                ("freshness", "pw"),
                ("extra_snippets", "true"),
                ("text_decorations", "false"),
            ]
            .map(|(key, value)| (key.to_string(), value.to_string()))
        ),
        "every argument travels in the query string"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("x-subscription-token: test-credential")),
        "the key travels bare in X-Subscription-Token: {head}"
    );
    assert!(
        !head.lines().next().unwrap().contains("test-credential"),
        "the key never travels in the URL"
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:brave"],
        "the credential is read from the vault by name at dispatch"
    );
}

#[test]
fn documented_empty_replies_are_served_empty() {
    for record in ["empty", "empty_web"] {
        let recorded = recorded_search(record);
        let response = recorded.result.unwrap();
        assert_eq!(
            (response.backend.as_str(), response.results.len()),
            ("brave", 0),
            "{record}"
        );
        assert!(recorded.service.chain_cooldowns.lock().unwrap().is_empty());
    }
}

/// No official stable bad-key code is declared. An undeclared 422 therefore
/// remains a rejected request without a cooldown or a vault auth report.
#[test]
fn documented_422_replies_reject_without_a_cooldown() {
    for record in ["validation_failed", "token_invalid"] {
        let recorded = recorded_search(record);
        assert_eq!(
            recorded.result,
            Err(WebSearchRefusal::RequestRejected {
                backend: "brave".into()
            }),
            "{record}"
        );
        assert_eq!(recorded.cooldown(), None, "{record}");
        assert!(recorded.vault.auth_failures.lock().unwrap().is_empty());
    }
}

#[test]
fn documented_short_rate_limit_is_throttled_for_a_minute() {
    assert_moved_on("rate_limited", SkipReason::Throttled, 60_000);
}

#[test]
fn documented_monthly_quota_is_skipped_for_an_hour() {
    assert_moved_on("monthly_quota_used", SkipReason::Quota, 3_600_000);
}

#[test]
fn an_exhausted_brave_falls_through_to_the_next_provider() {
    let recorded = recorded_walk("monthly_quota_used", &["brave", "exa"]);
    let response = recorded.result.as_ref().unwrap();
    assert_eq!(
        (response.backend.as_str(), response.results.len()),
        ("exa", 1)
    );
    assert_eq!(recorded.cooldown(), Some(3_600_000));
    assert_eq!(
        recorded.audit,
        Some(json!({"served_by": "exa", "skipped": [{"provider": "brave", "reason": "quota"}]}))
    );
    assert_eq!(
        *recorded.vault.requested.lock().unwrap(),
        ["apikey:brave", "test:exa"]
    );
}

#[test]
fn not_found_server_errors_and_replies_without_results_are_unavailable() {
    assert_moved_on("not_found", SkipReason::Unavailable, 60_000);
    assert_moved_on("server_error", SkipReason::Unavailable, 60_000);
    assert_moved_on("malformed", SkipReason::Unavailable, 60_000);
}

/// A query that Brave cannot take once its site: operators are added is
/// skipped before any connection, allowance or dispatch work.
#[test]
fn a_query_too_long_after_operators_skips_brave_without_dispatch() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("chain-brave-skip");
    add_connection(&engine, CONNECTION, "brave", Some("direct"));
    order(&engine, &["brave"]);
    let service = WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(BraveRestBackend));
    let refusal = service
        .search(
            &engine,
            "direct",
            json!({
                "query": "x".repeat(480),
                "include_domains": ["docs.python.org", "realpython.com"]
            })
            .as_object()
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(refusal, unavailable(&[("brave", SkipReason::Capability)]));
    assert!(transport.requests().is_empty(), "nothing is dispatched");
    assert!(service.chain_cooldowns.lock().unwrap().is_empty());
}
