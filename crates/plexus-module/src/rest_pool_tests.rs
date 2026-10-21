//! The scheduler must keep polling while one REST connection is stuck in a
//! slow vendor call: the idle-pool sweep it runs between passes skips that busy
//! connection instead of waiting for it.

use super::*;
use plexus_core::{CredentialSource, GovernanceEngine, RestConfig, RestTransport, Transport};
use std::time::Duration;

struct PollTransport(mpsc::UnboundedSender<()>);

impl Transport for PollTransport {
    fn dispatch(
        &self,
        request: plexus_core::TransportRequest,
        _: &plexus_core::ResolvedCredential,
    ) -> plexus_core::TransportResponse {
        assert_eq!(request.connection_id, "poll-connection");
        assert_eq!(request.action, "poll");
        let _ = self.0.send(());
        plexus_core::TransportResponse::success(json!({"tag_name": "v1"}))
    }
}

fn poll_store() -> Arc<PlexusStore> {
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "rest-sweep-scheduler".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap(),
    );
    let schema = json!({"type": "object"});
    // REST discovery uses the reviewed schema locally, so the scheduler's
    // health probe never needs a second vendor or an external network service.
    let manifest = plexus_core::ingest_value(json!({
        "schema_version": 1, "key": "poll_test", "name": "Poll test", "tier": "S2",
        "description": "A local scalar polling fixture",
        "reuse_path": "openapi_shim", "reuse_rationale": "Static REST polling fixture",
        "transport": {"kind": "rest_api", "url": "http://127.0.0.1:1"},
        "auth": {"mode": "api_key"}, "credential_bindings": [{
            "ref_role":"primary", "placement":"header", "key":"Authorization", "prefix":"Bearer ", "required":true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [{"name": "poll", "risk": "read",
            "http": {"method": "GET", "path": "/poll", "args_schema": schema},
            "poll": {"item_kind": "release", "cursor_kind": "scalar_diff", "scalar_field": "tag_name"}}],
        "defaults": {"ask_first_risk": ["write", "destructive"], "rate_limit": {"calls_per_min": 120}},
        "availability": "ga"
    })).unwrap();
    store.upsert_manifest("system", &manifest).unwrap();
    store
        .insert_connection(
            "direct",
            "poll-connection",
            "poll_test",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", "poll-connection", b"test:poll")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: "poll-connection".into(),
            principal: "direct".into(),
            name: "poll".into(),
            title: None,
            schema: schema.clone(),
            schema_hash: plexus_core::jcs_sha256(&schema).unwrap(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "poll-grant".into(),
            principal: "direct".into(),
            connection_id: "poll-connection".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["poll".into()],
            authority_kind: "poll".into(),
            expires_at: None,
        })
        .unwrap();
    store
        .subscribe_with_cursor_state(
            "direct",
            "poll-connection",
            "poll",
            1,
            &json!({}),
            &json!({}),
        )
        .unwrap()
        .unwrap();
    store
}

#[test]
fn scheduler_polls_again_while_the_rest_sweep_skips_a_busy_entry() {
    // reqwest's blocking client panics if it's dropped inside a Tokio runtime.
    // So the transport that owns the clients is held outside the runtime and
    // dropped after it, including when an assertion below fails.
    crate::test_support::assert_loopback_is_not_proxied();
    let rest = Arc::new(RestTransport::default());
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async {
        let (arrived, mut requests) = mpsc::channel(1);
        let (release, released) = std::sync::mpsc::channel();
        let (url, vendor) =
            test_http::FixedRequestServer::start(1, "busy REST vendor", move |_, _| {
                arrived.blocking_send(()).unwrap();
                released
                    .recv_timeout(Duration::from_secs(10))
                    .expect("release REST vendor");
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into()
            });
        let mut config = RestConfig::new(url).with_actions(HashMap::from([(
            "read".into(),
            plexus_core::manifest::HttpOperation {
                method: plexus_core::manifest::HttpMethod::Get,
                parameters: None,
                path: "/read".into(),
                args_schema: json!({"type": "object"}),
                request_constants: None,
                credentialless_tail: None,
                text_path_parameters: None,
                header_parameters: None,
            },
        )]));
        // An expired idle clock must not make an in-flight client evictable.
        config.idle_timeout = Duration::ZERO;
        rest.register_config("busy", config);
        let busy_rest = Arc::clone(&rest);
        let busy = tokio::task::spawn_blocking(move || {
            busy_rest.dispatch(
                plexus_core::TransportRequest {
                    request_id: "busy-request".into(),
                    connection_id: "busy".into(),
                    action: "read".into(),
                    args: json!({}),
                    credential_fingerprint: "anonymous".into(),
                },
                &plexus_core::ResolvedCredential::anonymous(),
            )
        });
        recv_within(requests.recv(), Duration::from_secs(5), "busy REST request").await;

        let store = poll_store();
        let credentials = Arc::new(StubCredentialSource::with_default_success(
            b"poll-key".to_vec(),
        ));
        let (polls, mut poll_requests) = mpsc::unbounded_channel();
        let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
            Arc::clone(&store),
            Arc::clone(&credentials),
            Arc::new(MockTransport::default()),
        );
        runtime.engine = GovernanceEngine::new(
            store,
            credentials as Arc<dyn CredentialSource>,
            Arc::new(PollTransport(polls)) as Arc<dyn Transport>,
        );
        runtime.rest_transport = Arc::clone(&rest);
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });
        let (shutdown, stop) = mpsc::channel(1);
        let scheduler = spawn_trigger_scheduler(
            Arc::clone(&state),
            stop,
            DEFAULT_AUDIT_RETENTION_DAYS * AUDIT_MILLIS_PER_DAY,
        );
        recv_within(
            poll_requests.recv(),
            Duration::from_secs(5),
            "first scheduler poll",
        )
        .await;
        // After its first poll, the scheduler runs the idle-pool sweep, and only
        // then can it start the next poll. A second poll arriving proves the sweep
        // didn't wait on the busy REST connection.
        let next_poll = tokio::time::timeout(Duration::from_secs(4), poll_requests.recv()).await;

        drop(shutdown);
        release.send(()).unwrap();
        recv_within(
            async {
                scheduler.await.unwrap();
                Some(())
            },
            Duration::from_secs(5),
            "scheduler shutdown",
        )
        .await;
        let response = recv_within(
            async { Some(busy.await.unwrap()) },
            Duration::from_secs(5),
            "REST completion",
        )
        .await;
        blocking_section(|| vendor.join().unwrap());
        assert!(
            response.response.is_some(),
            "busy REST request must complete"
        );
        assert!(
            matches!(next_poll, Ok(Some(()))),
            "scheduler must reach its next poll pass before the busy REST request is released"
        );
        assert_eq!(
            rest.connection_count(),
            1,
            "REST sweep must retain a busy entry even after its idle deadline"
        );
    });
}
