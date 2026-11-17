//! ck-plexus: the thin subc wire module for the connector substrate.
//!
//! At startup, ck-plexus authenticates to subc, registers its fixed facade
//! manifest, receives the storage descriptor, opens and migrates the store,
//! loads catalog files, and then serves control and tool-route frames.

#![forbid(unsafe_code)]

// Shadow the standard macro throughout the daemon crate. The fleet event lives in
// `plexus-core`, which this crate already depends on, so every daemon diagnostic
// receives shared-log attribution without a second implementation. A site must
// name a level and a component, both documented on `plexus_core::diag!`; a bare
// message does not compile.
macro_rules! eprintln {
    ($level:ident $component:ident: $($arg:tt)*) => {
        plexus_core::diag!($level $component: $($arg)*)
    };
}

mod background;
mod catalog_loader;
mod facade;
mod facade_catalog;
mod facade_connections;
mod facade_events;
mod facade_requests;
pub mod flow_audience;
mod github_react;
mod grants_would_ask;
mod management;
mod permissions;
mod replies;
mod routes;
mod runtime_loop;
mod tool_dispatch;

use background::*;
use catalog_loader::*;
use facade::*;
use facade_catalog::*;
use facade_connections::*;
use facade_events::*;
use facade_requests::*;
use management::*;
use replies::*;
pub use routes::RouteBindings;
use routes::*;
use runtime_loop::*;
pub use runtime_loop::{printed_manifest, run_entry, version_line};
use tool_dispatch::*;

#[cfg(test)]
#[path = "../../plexus-core/tests/support/bounded.rs"]
mod bounded;
pub mod bus;
pub mod bus_wakes;
pub mod ceremony;
mod composite_admin;
pub mod composition;
mod connection_enrollment_admin;
pub mod connector_home;
#[cfg(test)]
mod connector_home_tests;
#[cfg(test)]
mod consent_capacity_tests;
#[cfg(test)]
mod consent_test_support;
pub mod daemon_runtime;
mod engram_catalog;
mod federated;
mod github_bindings_list;
mod github_bot_admin;
mod github_read_tool;
pub mod health;
pub mod manifest;
pub mod operator_confirmation;
pub mod principal;
pub use federated::FEDERATED_CALLERS_ENABLED;
mod registration;
pub mod relay;
mod remaining_tool_guard;
mod reply_guard;
mod request_execution;
pub mod scope_reader;
mod search_declarations;
pub mod smoke;
mod startup;
#[cfg(test)]
#[path = "../../plexus-core/tests/support/http_server.rs"]
mod test_http;
/// The shared stderr-capture helpers, compiled once so every test module uses
/// the same one-time logger initialization. plexus-core's support/audit.rs,
/// which this crate also compiles, reaches them under this name too.
#[cfg(test)]
#[path = "../../plexus-core/tests/support/logging.rs"]
mod test_logging;
#[cfg(test)]
mod test_support;
#[cfg(test)]
use test_support::{
    assert_bind_ack, facade_tool_reply, run_health_probes, test_mcp_manifest, test_write_manifest,
    with_call_tool_result,
};
mod manifest_binding;
mod tool_provider;
mod web_search_auto;
mod web_search_health;
mod web_search_provider_admin;
mod widen_and_grant_admin;
pub mod wire;
#[cfg(test)]
mod wire_safety_tests;
#[cfg(test)]
use bounded::recv_within;

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use composition::ModuleRuntime;
use cortexkit_store_types::StorageDescriptor;
use plexus_core::poller::PollCycle;
use plexus_core::scope::{resolve_call_agent, CallScope};
use plexus_core::storage::{
    AUDIT_DELETE_FLOOR_DAYS, AUDIT_MILLIS_PER_DAY, DEFAULT_AUDIT_RETENTION_DAYS,
};
#[cfg(any(test, feature = "test-support"))]
use plexus_core::test_scratch::Scratch;
use plexus_core::withdraw::{WithdrawCall, WithdrawRefusal, WITHDRAW_NOT_PERMITTED};
use plexus_core::{
    ActorSource, AuditRecord, AuthorizationRequest, CatalogError, ConfigureOutcome,
    ConnectionAdminRevokeOutcome, DispatchOutcome, EventLookupOutcome, EventReader, PlexusStore,
    TransportOutcome,
};
#[cfg(any(test, feature = "test-support"))]
use plexus_core::{MockTransport, StubCredentialSource};
use scope_reader::{DaemonScopeReader, PendingControlReplies};
use serde_json::{json, Value};
use subc_protocol::call_mode::{derive_call_mode, CallMode};
use subc_protocol::session::{
    ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
};
use subc_protocol::tool_call::{validate_call_key, CALL_KEY_FIELD};
use subc_protocol::{
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Principal, Priority,
    PROTOCOL_VERSION, SUBC_MODULE_ID_ENV,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub const DEFAULT_MODULE_ID: &str = "plexus";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

struct ModuleState {
    health: Arc<health::HealthState>,
    runtime: ModuleRuntime,
}

impl ModuleState {
    fn store(&self) -> &Arc<PlexusStore> {
        &self.runtime.store
    }
}

#[derive(Debug)]
pub enum ModuleError {
    RouteCapacity,
    Message(String),
    Json(serde_json::Error),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteCapacity => write!(formatter, "route binding capacity exhausted"),
            Self::Message(message) => write!(formatter, "{message}"),
            Self::Json(error) => write!(formatter, "json: {error}"),
        }
    }
}

impl std::error::Error for ModuleError {}

/// Explicit test constructor: stub credentials + mock transport.
#[cfg(any(test, feature = "test-support"))]
pub fn runtime_for_test(store: Arc<PlexusStore>) -> ModuleRuntime {
    ModuleRuntime::with_stub_credentials_and_mock_transport(
        store,
        Arc::new(StubCredentialSource::with_default_success(
            b"mock-credential".to_vec(),
        )),
        Arc::new(MockTransport::default()),
    )
}

/// Exercise route.bind and health handlers without opening a daemon socket.
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_control_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health: &Arc<health::HealthState>,
) -> Result<(), ModuleError> {
    // Declared before the store so it outlives it: the guard removes the
    // directory the store's file sits in.
    let scratch = Scratch::database("handler-test-store");
    let descriptor = StorageDescriptor {
        module_id: DEFAULT_MODULE_ID.to_string(),
        storage_namespace: "test".to_string(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(
        PlexusStore::open(&descriptor)
            .map_err(|error| ModuleError::Message(format!("open test plexus store: {error}")))?,
    );
    let state = Arc::new(ModuleState {
        health: Arc::clone(health),
        runtime: runtime_for_test(store),
    });
    handle_control_request(frame, writer, &state, &Arc::new(RouteBindings::new())).await
}

/// Exercise an already accepted principal's facade call without a daemon socket.
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    runtime: ModuleRuntime,
    principal: Principal,
) -> Result<(), ModuleError> {
    handle_scoped_tool_request_for_test(frame, writer, runtime, principal, None).await
}

/// [`handle_tool_request_for_test`] on a route whose bind carried the daemon
/// scope stamp `scope`, as a scoped `route.bind` records it.
#[cfg(any(test, feature = "test-support"))]
pub async fn handle_scoped_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    runtime: ModuleRuntime,
    principal: Principal,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) -> Result<(), ModuleError> {
    let routes = Arc::new(RouteBindings::new());
    routes.insert_mode(
        frame.header.channel,
        frame.header.epoch,
        principal,
        scope.as_ref().map(CallScope::from_stamp),
        derive_call_mode(scope.as_ref()),
    )?;
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime,
    });
    handle_tool_request_with_confirmed_test_peer(frame, writer, &state, &routes).await
}

/// Handler fixtures explicitly approve confirmation frames with a fake daemon;
/// confirmation refusal tests use the production handler and their own peer.
#[cfg(any(test, feature = "test-support"))]
async fn handle_tool_request_with_confirmed_test_peer(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    routes: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let needs_fake_peer = serde_json::from_slice::<Value>(&frame.body)
        .ok()
        .is_some_and(|request| {
            request["method"].as_str().is_some_and(|method| {
                operator_confirmation::may_need_confirmation(method, &request["params"])
            })
        });
    if needs_fake_peer {
        let (proxy, requests) = mpsc::channel(4);
        let (result, ()) = tokio::join!(
            handle_tool_request(frame, &proxy, state, routes),
            operator_confirmation::approving_test_peer(requests, writer, &routes.control_replies),
        );
        result
    } else {
        handle_tool_request(frame, writer, state, routes).await
    }
}

#[cfg(test)]
// Shared with the core test suites; this crate's tests use only part of it.
#[allow(dead_code)]
#[path = "../../plexus-core/tests/support/audit.rs"]
mod audit_test;

#[cfg(test)]
mod relay_vectors;

#[cfg(test)]
mod call_mode_tests;
#[cfg(test)]
mod code_search_tests;
#[cfg(test)]
mod federated_tests;
#[cfg(test)]
mod route_select_search_vectors_tests;
#[cfg(test)]
mod web_search_tests;

#[cfg(test)]
mod web_search_rendering_tests;

#[cfg(test)]
mod refusal_echo_tests;

#[cfg(test)]
mod rest_pool_tests;

#[cfg(test)]
mod withdraw_tests;

#[cfg(test)]
mod github_react_tests;

#[cfg(test)]
mod recipient_tests;
#[cfg(test)]
mod route_format_tests;

#[cfg(test)]
mod remaining_tool_guard_tests;

#[cfg(test)]
mod permissions_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod events_delivery_tests;

#[cfg(test)]
mod subscription_lifecycle_tests;

#[cfg(test)]
mod events_get_tests;

#[cfg(test)]
mod approval_gate_tests;

#[cfg(test)]
mod connection_admin_tests;

#[cfg(test)]
mod pool_sweep_tests;

#[cfg(test)]
mod health_probe_scope_tests;

#[cfg(test)]
mod health_handler_tests;
#[cfg(test)]
mod startup_tests;

#[cfg(test)]
mod scheduler_liveness_tests;

#[cfg(test)]
mod secret_input_tests;

#[cfg(test)]
mod stamp_invoke_tests;

#[cfg(test)]
mod github_bindings_contract_tests;
#[cfg(test)]
mod github_read_frame_tests;

#[cfg(test)]
mod consent_pending_tests;
