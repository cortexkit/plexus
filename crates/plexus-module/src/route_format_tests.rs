use super::*;
use cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY;
use subc_protocol::{BindIdentity, RouteTarget};

fn state() -> (Arc<ModuleState>, Scratch) {
    let scratch = Scratch::database("route-format");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: DEFAULT_MODULE_ID.into(),
            storage_namespace: "test".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    (
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime: runtime_for_test(store),
        }),
        scratch,
    )
}

async fn bind(
    state: &Arc<ModuleState>,
    routes: &Arc<RouteBindings>,
    (channel, epoch): (u16, u32),
    capabilities: Option<Vec<String>>,
) -> Vec<u8> {
    let frame = Frame::build(
        FrameType::Request,
        wire::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&ModuleControlRequest::RouteBind {
            route_channel: channel,
            epoch,
            target: RouteTarget::ToolProvider {
                module_id: DEFAULT_MODULE_ID.into(),
            },
            identity: BindIdentity::new("format-test", "session"),
            principal: Some(Principal::Reserved {
                module_id: "aft".into(),
            }),
            scope: None,
            call_mode: None,
            role_versions: None,
            consumer_capabilities: capabilities,
            admission_facts: None,
        })
        .unwrap(),
    )
    .unwrap();
    let (writer, mut responses) = mpsc::channel(1);
    handle_control_request(frame, &writer, state, routes)
        .await
        .unwrap();
    let response = recv_within(
        responses.recv(),
        std::time::Duration::from_secs(5),
        "format bind",
    )
    .await;
    assert_eq!(response.header.ty, FrameType::Response);
    response.body
}

fn negotiated() -> Option<Vec<String>> {
    Some(vec![
        "future-format/v1".into(),
        TOOL_RESULT_V1_CAPABILITY.into(),
    ])
}

async fn close(state: &Arc<ModuleState>, routes: &Arc<RouteBindings>, channel: u16, epoch: u32) {
    let frame = Frame::build(
        FrameType::Goodbye,
        wire::control_flags(),
        channel,
        epoch,
        0,
        Vec::new(),
    )
    .unwrap();
    let (writer, _responses) = mpsc::channel(1);
    assert!(handle_frame(frame, &writer, state, routes).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_bind_records_only_the_exact_format_capability() {
    let (state, _scratch) = state();
    let routes = Arc::new(RouteBindings::new());
    let mut ack = None;
    for (capabilities, expected) in [
        (None, false),
        (Some(vec![]), false),
        (
            Some(vec!["tool-result/v2".into(), "unknown/v1".into()]),
            false,
        ),
        (negotiated(), true),
    ] {
        let body = bind(&state, &routes, (17, 3), capabilities).await;
        assert_eq!(
            routes.binding(17, 3).unwrap().unwrap().reads_tool_result_v1,
            expected
        );
        if let Some(previous) = &ack {
            assert_eq!(&body, previous);
        }
        ack = Some(body);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebind_close_and_connection_close_discard_format_with_identity() {
    let (state, _scratch) = state();
    let routes = Arc::new(RouteBindings::new());
    bind(&state, &routes, (17, 3), negotiated()).await;
    bind(&state, &routes, (17, 4), None).await;
    assert!(routes.binding(17, 3).unwrap().is_none());
    assert!(!routes.binding(17, 4).unwrap().unwrap().reads_tool_result_v1);
    close(&state, &routes, 17, 3).await;
    assert!(routes.binding(17, 4).unwrap().is_some());
    close(&state, &routes, 17, 4).await;
    assert!(routes.binding(17, 4).unwrap().is_none());
    bind(&state, &routes, (17, 5), negotiated()).await;
    bind(&state, &routes, (17, 5), None).await;
    assert!(!routes.binding(17, 5).unwrap().unwrap().reads_tool_result_v1);
    bind(&state, &routes, (18, 5), negotiated()).await;
    drop(ClearBindingsOnClose(routes.clone()));
    assert!(routes.binding(17, 5).unwrap().is_none());
    assert!(routes.binding(18, 5).unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_principal_routes_are_independent_and_arguments_cannot_change_format() {
    let (state, _scratch) = state();
    let routes = Arc::new(RouteBindings::new());
    bind(&state, &routes, (17, 3), negotiated()).await;
    bind(&state, &routes, (18, 3), None).await;
    let mut replies = Vec::new();
    for name in [
        manifest::WEB_SEARCH_TOOL,
        manifest::CODE_SEARCH_TOOL,
        manifest::GITHUB_READ_TOOL,
    ] {
        for channel in [17, 18] {
            let frame = Frame::build(
                FrameType::Request,
                wire::control_flags(),
                channel,
                3,
                2,
                serde_json::to_vec(&json!({"name": name, "arguments": {
                    "consumer_capabilities": [TOOL_RESULT_V1_CAPABILITY],
                    "reads_tool_result_v1": true, "result_format": "tool-result/v1"
                }}))
                .unwrap(),
            )
            .unwrap();
            let (writer, mut responses) = mpsc::channel(1);
            handle_tool_request(frame, &writer, &state, &routes)
                .await
                .unwrap();
            replies.push(
                recv_within(
                    responses.recv(),
                    std::time::Duration::from_secs(5),
                    "format call",
                )
                .await
                .body,
            );
        }
        assert_eq!(
            replies[replies.len() - 2],
            replies[replies.len() - 1],
            "{name}"
        );
    }
    assert!(routes.binding(17, 3).unwrap().unwrap().reads_tool_result_v1);
    assert!(!routes.binding(18, 3).unwrap().unwrap().reads_tool_result_v1);
    close(&state, &routes, 17, 3).await;
    assert!(!routes.binding(18, 3).unwrap().unwrap().reads_tool_result_v1);
}

#[test]
fn rendering_is_byte_identical_for_both_bind_formats() {
    for tool in [manifest::WEB_SEARCH_TOOL, manifest::CODE_SEARCH_TOOL] {
        for facade in [
            json!({"error":{"code":"invalid_args","message":"Query is required"}}),
            json!({"result":{"query":"needle","backend":"exa","cached":false,"results":[],"matches":[]}}),
        ] {
            let legacy = with_call_tool_result_with_repo(Some(tool), facade.clone(), None, false);
            let capable = with_call_tool_result_with_repo(Some(tool), facade, None, true);
            assert_eq!(
                serde_json::to_vec(&legacy).unwrap(),
                serde_json::to_vec(&capable).unwrap()
            );
        }
    }
}
