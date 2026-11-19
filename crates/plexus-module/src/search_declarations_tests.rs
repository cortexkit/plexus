use super::*;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use serde_json::json;
use std::sync::atomic::{AtomicI64, Ordering};

const NOW: i64 = 1_790_000_000_000;

fn store(name: &str) -> (Arc<PlexusStore>, plexus_core::test_scratch::Scratch) {
    let scratch = plexus_core::test_scratch::Scratch::database(name);
    let store = PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: name.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    (Arc::new(store), scratch)
}

/// Answer every `catalog.update_role_declarations` the declarations send,
/// recording the declaration maps in order.
fn daemon(
    mut outbound: mpsc::Receiver<Frame>,
    pending: Arc<PendingControlReplies>,
) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
    std::thread::spawn(move || {
        let mut sent = Vec::new();
        while let Some(request) = outbound.blocking_recv() {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["op"], "catalog.update_role_declarations");
            sent.push(body["role_declarations"].clone());
            let reply = Frame::build_with_version(
                subc_protocol::PROTOCOL_VERSION,
                FrameType::Response,
                crate::wire::control_flags(),
                0,
                0,
                request.header.corr,
                serde_json::to_vec(
                    &ModuleControlResponseToModule::CatalogUpdateRoleDeclarations {},
                )
                .unwrap(),
            )
            .unwrap();
            assert!(pending.complete(reply));
        }
        sent
    })
}

#[test]
fn declaration_follows_live_connections_and_marks_added_routes() {
    let (store, _scratch) = store("search-declarations");
    let (writer, outbound) = mpsc::channel::<Frame>(4);
    let pending = Arc::new(PendingControlReplies::default());
    let responder = daemon(outbound, Arc::clone(&pending));
    let declarations = SearchDeclarations::new(
        writer,
        subc_protocol::PROTOCOL_VERSION,
        Arc::clone(&pending),
    );
    let now = Arc::new(AtomicI64::new(NOW));
    let clock = Arc::clone(&now);
    let search = WebSearchService::with_clock(
        Arc::new(plexus_core::web_search::ExaRestBackend),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    let principals = ["direct".to_string()];
    store
        .insert_connection("direct", "exa", "exa_rest", "active", &json!({}))
        .unwrap();
    // A connected provider without a catalog row is never declared.
    store
        .insert_connection("direct", "searx", "searxng_rest", "active", &json!({}))
        .unwrap();
    assert_eq!(declarations.status(), DeclarationStatus::at_hello());
    // Narrowing from HELLO's full table only removes routes.
    declarations.reconcile(&store, &principals, &search);
    assert_eq!(search.routes_added_at_for_test(), None);
    let narrowed = declarations.status();
    assert_eq!(narrowed.routes, [RouteRef::new("exa", "search")]);
    assert!(narrowed.updated_at_ms.is_some(), "{narrowed:?}");
    // Unchanged: nothing is sent.
    declarations.reconcile(&store, &principals, &search);
    now.store(NOW + 5, Ordering::SeqCst);
    store
        .insert_connection("direct", "tavily", "tavily_rest", "active", &json!({}))
        .unwrap();
    declarations.reconcile(&store, &principals, &search);
    assert_eq!(search.routes_added_at_for_test(), Some(NOW + 5));
    drop(declarations);
    let sent = responder.join().unwrap();
    assert_eq!(
        sent.iter()
            .map(|declaration| declaration["search-provider/v1"].clone())
            .collect::<Vec<_>>(),
        [
            json!({"routes": [{"provider": "exa", "model": "search"}]}),
            json!({"routes": [
                {"provider": "exa", "model": "search"},
                {"provider": "tavily", "model": "search"}
            ]}),
        ]
    );
    assert_eq!(
        sent[0]["routing/v1"],
        json!({"consumers": [{"name": "plexus.web_search", "kind": "search", "selectors": ["plexus"]}]})
    );
}

#[test]
fn an_error_reply_is_a_failed_update() {
    let reply = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Error,
        crate::wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&ErrorBody {
            code: "invalid_request".into(),
            message: "bad map".into(),
            detail: None,
        })
        .unwrap(),
    )
    .unwrap();
    assert!(update_reply(&reply)
        .unwrap_err()
        .contains("invalid_request"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiet_scheduler_ticks_do_not_reread_connections_for_declarations() {
    let (store, _scratch) = store("quiet-search-declarations");
    let (writer, outbound) = mpsc::channel::<Frame>(4);
    let pending = Arc::new(PendingControlReplies::default());
    let responder = daemon(outbound, pending.clone());
    let declarations = Arc::new(SearchDeclarations::new(
        writer,
        subc_protocol::PROTOCOL_VERSION,
        pending,
    ));
    let mut runtime = crate::runtime_for_test(store);
    runtime.search_declarations = Some(declarations.clone());
    let state = Arc::new(crate::ModuleState {
        runtime,
        health: Arc::new(crate::health::HealthState::new()),
    });
    let (shutdown, stop) = mpsc::channel(1);
    let task = crate::test_support::spawn_test_scheduler(state.clone(), stop);
    // The helper observes pass starts, so the next start proves the previous pass finished.
    let ticked = crate::test_support::scheduler_passes(&state.health, 61).await;
    drop(shutdown);
    crate::background::stop_task("test scheduler", task, Duration::from_secs(5)).await;
    assert!(ticked, "the scheduler must complete at least sixty passes");
    assert_eq!(
        declarations.connection_list_reads.load(Ordering::Relaxed),
        1
    );
    drop(state);
    drop(declarations);
    assert_eq!(responder.join().unwrap().len(), 1);
}
