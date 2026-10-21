//! Recorded-shape SearXNG requests through the stored connection and real REST path.

use super::*;
use crate::catalog::{CatalogReconciler, CatalogRefreshPolicy};
use crate::credentials::{CredentialError, ResolvedCredential};
use crate::instance_url::InstanceUrl;
use crate::mcp_remote::McpRemoteTransport;
use crate::rest_api::{RestConfig, RestTransport};
use crate::transport::{TransportRequest, TransportResponse};
use std::sync::Mutex;

const CONNECTION: &str = "searxng-rest";
const KEY: &str = "apikey:searxng";

#[derive(Default)]
struct Vault {
    reads: Mutex<Vec<String>>,
    failures: Mutex<Vec<u16>>,
}
impl CredentialSource for Vault {
    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        self.reads.lock().unwrap().push(id.into());
        Ok(ResolvedCredential::new(b"test-key".to_vec(), None, 1))
    }
    fn report_id_auth_failure(&self, _: &str, status: u16) {
        self.failures.lock().unwrap().push(status);
    }
}

fn manifest() -> crate::manifest::IngestedManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!(
                "../../../../../../catalog/searxng_rest.jsonc"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn connect(
    store: &crate::storage::PlexusStore,
    id: &str,
    caller: &str,
    address: &str,
    bearer: bool,
) {
    store.upsert_manifest("system", &manifest()).unwrap();
    store
        .insert_connection("direct", id, "searxng_rest", "pending", &json!({}))
        .unwrap();
    let ticket = store
        .create_binding_ticket_with_instance(
            "direct",
            id,
            if bearer {
                "credential_reference"
            } else {
                crate::NO_CREDENTIAL_REF_ROLE
            },
            if bearer { KEY.as_bytes() } else { &[] },
            Some(&InstanceUrl::parse(address).unwrap()),
        )
        .unwrap();
    assert!(store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .is_some());
    store
        .seed_catalog_from_manifest("direct", id, "searxng_rest")
        .unwrap();
    store
        .insert_grant(&GrantInput {
            principal: "direct".into(),
            connection_id: id.into(),
            grant_id: format!("grant-{id}"),
            grantee_principal: caller.into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["search".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
}

fn service() -> WebSearchService {
    WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW))
        .with_chain_backend(Arc::new(SearxngRestBackend))
}

struct Recorded {
    result: Result<WebSearchResponse, WebSearchRefusal>,
    service: WebSearchService,
    request: String,
    vault: Arc<Vault>,
}

fn recorded(record: &str, bearer: bool) -> Recorded {
    let records: Value =
        serde_json::from_str(include_str!("../../backend/searxng/fixtures.json")).unwrap();
    let response = records[record].clone();
    let received = Arc::new(Mutex::new(String::new()));
    let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
        1,
        "searxng",
        std::time::Duration::from_secs(30),
        {
            let received = received.clone();
            move |_, request| {
                *received.lock().unwrap() = request.to_string();
                let body = response["body"].as_str().unwrap();
                format!("HTTP/1.1 {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",response["status"],response["headers"].as_str().unwrap(),body.len())
            }
        },
    );
    let (fixture, _) =
        super::super::super::tests::granted_exa_engine(&format!("searxng-{record}-{bearer}"));
    connect(
        fixture.store(),
        CONNECTION,
        "direct",
        &format!("{endpoint}/private-base"),
        bearer,
    );
    order(&fixture, &["searxng"]);
    let rest = Arc::new(RestTransport::default());
    let vault = Arc::new(Vault::default());
    let reconciler = CatalogReconciler::new(
        fixture.store().clone(),
        Arc::new(McpRemoteTransport::default()),
        CatalogRefreshPolicy::default(),
    )
    .with_rest_transport(rest.clone());
    // No endpoint override: discovery must load the instance from the connection.
    reconciler
        .discover_for_connection("direct", CONNECTION, vault.as_ref(), None)
        .unwrap();
    let engine = GovernanceEngine::new(fixture.store().clone(), vault.clone(), rest);
    let service = service();
    let result = service.search(
        &engine,
        "direct",
        json!({"query":"weather & climate?","max_results":1,"recency":"month"})
            .as_object()
            .unwrap(),
    );
    server
        .join()
        .unwrap_or_else(|e| panic!("{record}: {e}; {result:?}"));
    let request = received.lock().unwrap().clone();
    Recorded {
        result,
        service,
        request,
        vault,
    }
}

#[test]
fn stored_instance_sends_get_search_json_filters_with_optional_bearer() {
    for bearer in [false, true] {
        let r = recorded("success", bearer);
        let reply = r.result.unwrap();
        assert_eq!(
            (reply.backend.as_str(), reply.results.len()),
            ("searxng", 1)
        );
        assert_eq!(reply.results[0].title, "Weather report");
        let (head, body) = r.request.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("GET "));
        let target = reqwest::Url::parse(&format!(
            "http://fixture.invalid{}",
            head.split_whitespace().nth(1).unwrap()
        ))
        .unwrap();
        assert_eq!(target.path(), "/private-base/search");
        let sent: std::collections::BTreeMap<_, _> = target.query_pairs().into_owned().collect();
        assert_eq!(
            sent,
            std::collections::BTreeMap::from([
                ("q".into(), "weather & climate?".into()),
                ("format".into(), "json".into()),
                ("language".into(), "all".into()),
                ("time_range".into(), "month".into())
            ])
        );
        assert!(body.is_empty());
        assert_eq!(
            head.lines()
                .any(|l| l.eq_ignore_ascii_case("authorization: Bearer test-key")),
            bearer
        );
        assert_eq!(
            head.lines()
                .any(|l| l.to_ascii_lowercase().starts_with("authorization:")),
            bearer
        );
        let reads = r.vault.reads.lock().unwrap();
        assert_eq!(reads.is_empty(), !bearer);
        assert!(reads.iter().all(|key| key == KEY));
    }
}

#[test]
fn recorded_outcomes_serve_empty_reject_bad_requests_and_cool_failures() {
    let r = recorded("empty", false);
    assert!(r.result.unwrap().results.is_empty());
    assert!(r.service.chain_cooldowns.lock().unwrap().is_empty());
    for record in ["bad_request", "unprocessable"] {
        let r = recorded(record, false);
        assert_eq!(
            r.result,
            Err(WebSearchRefusal::RequestRejected {
                backend: "searxng".into()
            })
        );
        assert!(r.service.chain_cooldowns.lock().unwrap().is_empty());
    }
    for (record, reason, cooldown) in [
        ("payment_required", SkipReason::Quota, 3_600_000),
        ("unauthorized", SkipReason::Credential, 60_000),
        ("forbidden", SkipReason::Unavailable, 60_000),
        ("not_found", SkipReason::Unavailable, 60_000),
        ("rate_limited", SkipReason::Throttled, 60_000),
        ("rate_limited_retry", SkipReason::Throttled, 7_000),
        ("server_error", SkipReason::Unavailable, 60_000),
        ("malformed", SkipReason::Unavailable, 60_000),
        ("invalid_json", SkipReason::Unavailable, 60_000),
        ("no_body", SkipReason::Unavailable, 60_000),
    ] {
        let r = recorded(record, true);
        assert_eq!(
            r.result,
            Err(unavailable(&[("searxng", reason)])),
            "{record}"
        );
        assert_eq!(
            r.service
                .chain_cooldowns
                .lock()
                .unwrap()
                .get(CONNECTION)
                .copied(),
            Some(NOW + cooldown),
            "{record}"
        );
        assert_eq!(
            *r.vault.failures.lock().unwrap(),
            if record == "unauthorized" {
                vec![401]
            } else {
                vec![]
            }
        );
    }
}

#[test]
fn capability_skip_never_dispatches_counts_or_cools() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("searxng-skip");
    connect(
        engine.store(),
        CONNECTION,
        "direct",
        "https://private-instance.invalid/base",
        false,
    );
    order(&engine, &["searxng"]);
    engine
        .store()
        .set_web_search_allowance("searxng", 5)
        .unwrap();
    let service = service();
    for args in [
        json!({"query":"weather", "include_domains":["example.org"]}),
        json!({"query":"weather", "recency":"week"}),
    ] {
        assert_eq!(
            service.search(&engine, "direct", args.as_object().unwrap()),
            Err(unavailable(&[("searxng", SkipReason::Capability)]))
        );
    }
    assert!(
        transport.requests().is_empty(),
        "capability skip must not dispatch"
    );
    assert_eq!(
        engine
            .store()
            .web_search_allowance_used("searxng", "direct", NOW)
            .unwrap(),
        0
    );
    assert!(service.chain_cooldowns.lock().unwrap().is_empty());
}

#[test]
fn production_backend_cache_is_separated_by_stored_instance_digest() {
    let (engine, transport) = super::super::super::tests::granted_exa_engine("searxng-real-cache");
    connect(
        engine.store(),
        "sx-a",
        "direct",
        "https://private-a.invalid/base",
        false,
    );
    connect(
        engine.store(),
        "sx-b",
        "other",
        "https://private-b.invalid/base",
        false,
    );
    order(&engine, &["searxng"]);
    transport.set_response(crate::transport::MockResponse::Success(
        json!({"results":[]}),
    ));
    let service = service();
    let args = json!({"query":"weather"});
    assert!(
        !service
            .search(&engine, "direct", args.as_object().unwrap())
            .unwrap()
            .cached
    );
    let parsed = WebSearchQuery::parse(args.as_object().unwrap()).unwrap();
    let entry = service
        .cache
        .get_served(&CacheKey::new("chain", &parsed), NOW)
        .unwrap();
    let digest = entry.served.instance_digest.unwrap();
    assert_eq!(
        digest,
        "adc0a1fdcbc99500765b37a00b5503e58feb5d82f818e7b3d47a11c2e412cc5a"
    );
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!format!("{:?}", entry.served.provider).contains("private-a"));
    assert!(
        !service
            .search(&engine, "other", args.as_object().unwrap())
            .unwrap()
            .cached
    );
    assert!(
        service
            .search(&engine, "other", args.as_object().unwrap())
            .unwrap()
            .cached
    );
    assert_eq!(
        transport.requests().len(),
        2,
        "different stored instances must not share cache entries"
    );
    for row in engine.store().list_audit("direct").unwrap() {
        let debug = format!("{row:?}");
        assert!(!debug.contains("private-a.invalid"));
        assert!(!debug.contains("private-b.invalid"));
        assert!(!debug.contains(&digest));
    }
}

#[test]
fn tickets_require_an_instance_and_store_it_without_exposing_it_in_summaries() {
    let (engine, _) = super::super::super::tests::granted_exa_engine("searxng-ticket");
    let store = engine.store();
    store.upsert_manifest("system", &manifest()).unwrap();
    store
        .insert_connection("direct", CONNECTION, "searxng_rest", "pending", &json!({}))
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", CONNECTION, KEY.as_bytes())
        .unwrap();
    assert!(store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .connection("direct", CONNECTION)
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
    let instance =
        InstanceUrl::parse("https://private-instance-canary.invalid/secret-path").unwrap();
    let approved = store
        .create_binding_ticket_with_instance(
            "direct",
            CONNECTION,
            "credential_reference",
            KEY.as_bytes(),
            Some(&instance),
        )
        .unwrap();
    assert!(
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .unwrap()
            .is_none(),
        "superseded ticket must not choose the destination"
    );
    assert!(!format!("{approved:?}").contains("private-instance-canary"));
    let summary = store
        .connect_with_ticket("direct", &approved.ticket_id)
        .unwrap()
        .unwrap();
    let record = store.connection("direct", CONNECTION).unwrap().unwrap();
    assert_eq!(record.instance_url.as_ref(), Some(&instance));
    assert_eq!(
        SearxngRestBackend.instance_url(&record).as_deref(),
        Some(instance.as_str())
    );
    assert!(!serde_json::to_string(&summary)
        .unwrap()
        .contains("private-instance-canary"));
    assert!(!format!("{record:?}").contains("private-instance-canary"));
    assert!(store
        .connect_with_ticket("direct", &approved.ticket_id)
        .unwrap()
        .is_none());
}

#[test]
fn rest_config_diagnostics_hide_the_entire_instance_address() {
    let mut config = RestConfig::from_manifest(&manifest().manifest);
    config.base_url = "https://private-instance-canary.invalid/secret-path".into();
    let rendered = format!("{config:?}");
    assert!(rendered.contains("action_count"));
    assert!(
        !rendered.contains("private-instance-canary"),
        "instance host must be redacted"
    );
    assert!(
        !rendered.contains("secret-path"),
        "instance path must be redacted"
    );
}

struct LocalOutcome(TransportResponse);
impl crate::transport::Transport for LocalOutcome {
    fn dispatch(&self, _: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.0.clone()
    }
}

#[test]
fn local_outcomes_move_on_and_release_only_unsent_allowance() {
    use crate::transport::TransmissionState::{NotSent, OutcomeUnknown, Sent};
    let records: Value =
        serde_json::from_str(include_str!("../../backend/searxng/fixtures.json")).unwrap();
    for (name, transmission, retry, reason, used) in [
        ("not_sent", NotSent, None, SkipReason::Unavailable, 0),
        (
            "not_sent_retry",
            NotSent,
            Some(9000),
            SkipReason::Throttled,
            0,
        ),
        (
            "outcome_unknown",
            OutcomeUnknown,
            None,
            SkipReason::Unavailable,
            1,
        ),
        ("timeout", OutcomeUnknown, None, SkipReason::Unavailable, 1),
        (
            "completed_without_body",
            Sent,
            None,
            SkipReason::Unavailable,
            1,
        ),
    ] {
        assert!(records["local_outcomes"]
            .as_array()
            .unwrap()
            .contains(&json!(name)));
        let (fixture, _) =
            super::super::super::tests::granted_exa_engine(&format!("searxng-{name}"));
        connect(
            fixture.store(),
            CONNECTION,
            "direct",
            "https://private.invalid",
            false,
        );
        order(&fixture, &["searxng"]);
        fixture
            .store()
            .set_web_search_allowance("searxng", 5)
            .unwrap();
        let mut response = TransportResponse::success(Value::Null);
        response.response = None;
        response.transmission = transmission;
        response.retry_after_ms = retry;
        response.error_code = (name == "timeout").then(|| "timeout".into());
        let engine = GovernanceEngine::new(
            fixture.store().clone(),
            Arc::new(Vault::default()),
            Arc::new(LocalOutcome(response)),
        );
        let service = service();
        assert_eq!(
            service.search(
                &engine,
                "direct",
                json!({"query":"weather"}).as_object().unwrap()
            ),
            Err(unavailable(&[("searxng", reason)])),
            "{name}"
        );
        assert_eq!(
            engine
                .store()
                .web_search_allowance_used("searxng", "direct", NOW)
                .unwrap(),
            used,
            "{name}"
        );
        assert_eq!(
            service
                .chain_cooldowns
                .lock()
                .unwrap()
                .get(CONNECTION)
                .copied(),
            Some(NOW + retry.unwrap_or(60_000) as i64)
        );
    }
}

#[test]
fn private_endpoint_diagnostics_never_print_instance_or_reflected_vendor_text() {
    const TEST: &str = "web_search::chain::tests::searxng::private_endpoint_diagnostics_never_print_instance_or_reflected_vendor_text";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        use crate::test_logging as logging;
        logging::init_child();
        let (endpoint, server) = crate::test_http::FixedRequestServer::start_with_deadline(
            2,
            "searxng-private-logs",
            std::time::Duration::from_secs(15),
            |index, _| {
                let body = r#"{"message":"private-instance-canary.invalid secret-instance-path"}"#;
                format!("HTTP/1.1 {}\r\nLocation: http://127.0.0.1/secret-instance-path\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",if index==0 {403} else {302},body.len())
            },
        );
        let mut config = RestConfig::from_manifest(&manifest().manifest);
        config.base_url = format!("{endpoint}/secret-instance-path");
        let transport = RestTransport::new(config);
        for _ in 0..2 {
            let response = crate::transport::Transport::dispatch(
                &transport,
                TransportRequest {
                    request_id: "diagnostic-request".into(),
                    credential_fingerprint: "test".into(),
                    connection_id: CONNECTION.into(),
                    action: "search".into(),
                    args: json!({"q":"weather","format":"json","language":"all"}),
                },
                &ResolvedCredential::anonymous(),
            );
            assert!(response.error_code.is_some());
        }
        server.join().unwrap();
        crate::diag!(warn transport: "private diagnostic fixture finished");
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[("PLEXUS_LOG_STDERR_CHILD", "1")],
        std::time::Duration::from_secs(45),
        "SearXNG diagnostic child",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout} {stderr}");
    assert!(
        stdout.contains("1 passed"),
        "diagnostic fixture must execute"
    );
    assert!(
        stderr.contains("private diagnostic fixture finished"),
        "real diagnostic sink must be observed: {stderr}"
    );
    for private in [
        "private-instance-canary",
        "secret-instance-path",
        "127.0.0.1",
    ] {
        assert!(
            !stderr.contains(private),
            "private instance leaked in diagnostics: {stderr}"
        );
    }
}
