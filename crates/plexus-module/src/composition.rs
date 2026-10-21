//! Runtime composition for the facade: credential source, MCP transport, and
//! catalog reconciler. Production wiring is fail-closed on the vault route;
//! stub credentials and mock transport are available only through explicit
//! test constructors.

use std::path::Path;
use std::sync::Arc;

use plexus_core::github::credential::{HandleCredentialPreparer, HandleCredentialProvider};
use plexus_core::storage::github_store::GithubGovernanceSeams;
use plexus_core::web_search::WebSearchService;
use plexus_core::{
    AgentRegistry, CatalogReconciler, CatalogRefreshPolicy, CkcredCredentialSource, ConsentCards,
    CredentialSource, FailClosedAgentRegistry, FailClosedCredentialSource, Freshness,
    GovernanceEngine, McpRemoteTransport, PlexusStore, PrefrontalAgentRegistry, RestTransport,
    SubcCkcredRoutePeer, SubcPrefrontalRoutePeer, Transport, TransportRequest, TransportResponse,
};
#[cfg(any(test, feature = "test-support"))]
use plexus_core::{MockTransport, StubAgentRegistry, StubCredentialSource};
use subc_protocol::BindIdentity;

fn plexus_bind_identity() -> BindIdentity {
    BindIdentity::new(
        std::env::var("PLEXUS_PROJECT_ROOT").unwrap_or_else(|_| "/".into()),
        "plexus",
        "module",
    )
}

fn peer_failure_warning(role: &str, target: &str) -> String {
    format!(
        "configured {role} peer {} unavailable; keeping the route fail-closed",
        crate::diagnostic_label(target)
    )
}

fn configured_peer<T, E>(result: Result<T, E>, role: &str, target: &str) -> Option<T> {
    match result {
        Ok(peer) => Some(peer),
        Err(_) => {
            // Called once per startup connection attempt, never by retry loops.
            // Peer error bodies and connection-file contents are not printable.
            eprintln!(warn wire: "{}", peer_failure_warning(role, target));
            None
        }
    }
}

/// Shared engine type used by the wire facade. Both production and test
/// constructors erase the concrete credential and transport types so the
/// handler code stays monomorphic.
pub type FacadeEngine = GovernanceEngine<dyn CredentialSource, dyn Transport>;

/// Dispatch registered REST connections, with remote MCP as the fail-closed fallback.
struct VendorTransportRouter {
    mcp: Arc<McpRemoteTransport>,
    rest: Arc<RestTransport>,
}

impl Transport for VendorTransportRouter {
    fn dispatch_github_facade(
        &self,
        request: TransportRequest,
        credential: &plexus_core::ResolvedCredential,
    ) -> TransportResponse {
        if self.rest.has_connection(&request.connection_id) {
            self.rest.dispatch_github_facade(request, credential)
        } else {
            self.dispatch(request, credential)
        }
    }

    fn dispatch(
        &self,
        request: TransportRequest,
        credential: &plexus_core::ResolvedCredential,
    ) -> TransportResponse {
        if self.rest.has_connection(&request.connection_id) {
            self.rest.dispatch(request, credential)
        } else {
            self.mcp.dispatch(request, credential)
        }
    }
}

pub struct ModuleRuntime {
    pub connector_home: Arc<crate::connector_home::ConnectorHome>,
    pub store: Arc<PlexusStore>,
    pub engine: FacadeEngine,
    pub reconciler: CatalogReconciler,
    pub mcp_transport: Arc<McpRemoteTransport>,
    pub rest_transport: Arc<RestTransport>,
    /// Registry lookup runs when an operator sets an explicit delivery target
    /// and in the scheduler's hourly sweep for retired agents' grants.
    pub agent_registry: Arc<dyn AgentRegistry>,
    pub flow_audiences: crate::flow_audience::FlowAudiences,
    pub repository_registry: Option<Arc<dyn plexus_core::repository_ownership::RepositoryRegistry>>,
    pub github_handle_credentials: Option<Arc<dyn HandleCredentialProvider>>,
    /// Optional read-only installation peer for management ceremonies.
    pub github_control_reader:
        Option<Arc<dyn plexus_core::github::control::InstallationReader + Send + Sync>>,
    /// Optional endpoint override used by the conformance harness when the
    /// reviewed manifest URL should not be contacted.
    pub endpoint_override: Option<String>,
    /// The `web_search` tool's backend, rate limiter and result cache. Held
    /// behind an `Arc` so its in-memory state outlives any one call.
    pub web_search: Arc<WebSearchService>,
    pub code_search: Arc<plexus_core::code_search::CodeSearchService>,
}

impl ModuleRuntime {
    /// Production composition: REST and remote MCP transports,
    /// and credentials supplied by the claustrum vault when its route is
    /// configured and reachable. Missing or unreachable credential routes fail
    /// closed; they never fall back to stubs.
    pub fn production(store: Arc<PlexusStore>, connection_file: &Path) -> Self {
        let mcp_transport = Arc::new(McpRemoteTransport::default());
        let rest_transport = Arc::new(RestTransport::default());
        let credentials = production_credential_source(connection_file);
        let agent_registry = production_agent_registry(connection_file);
        let github_handle_credentials = production_handle_credential_provider(connection_file);
        let consent_cards = production_consent_cards(connection_file);
        let connector_home = Arc::new(crate::connector_home::ConnectorHome::production(
            connection_file,
        ));
        let guard_home = Arc::clone(&connector_home);
        let engine = GovernanceEngine::new(
            Arc::clone(&store),
            credentials,
            Arc::new(VendorTransportRouter {
                mcp: Arc::clone(&mcp_transport),
                rest: Arc::clone(&rest_transport),
            }) as Arc<dyn Transport>,
        )
        .with_connector_home_guard(Arc::new(move || {
            if guard_home.held() {
                None
            } else {
                Some(guard_home.status())
            }
        }))
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: Arc::clone(&store),
            credential_provider: github_handle_credentials.clone(),
        }));
        let engine = with_freshness_check(engine, &store, &mcp_transport, &rest_transport);
        let engine = match consent_cards {
            Some(cards) => engine.with_consent_cards(cards),
            None => engine,
        };
        let reconciler = CatalogReconciler::new(
            Arc::clone(&store),
            Arc::clone(&mcp_transport),
            CatalogRefreshPolicy::default(),
        )
        .with_rest_transport(Arc::clone(&rest_transport));
        Self {
            connector_home,
            store: Arc::clone(&store),
            engine,
            reconciler,
            mcp_transport,
            rest_transport,
            agent_registry,
            flow_audiences: crate::flow_audience::FlowAudiences::new(
                production_prefrontal_peer(connection_file)
                    .map(|peer| peer.with_call_timeout(std::time::Duration::from_secs(3))),
            ),
            repository_registry: production_repository_registry(connection_file),
            github_handle_credentials,
            github_control_reader: None,
            endpoint_override: None,
            web_search: Arc::new(WebSearchService::production()),
            code_search: Arc::new(plexus_core::code_search::CodeSearchService::default()),
        }
    }

    /// Explicit dev/test constructor: stub credentials + mock transport. The
    /// MCP transport and reconciler still exist so connect-time discovery can
    /// be exercised against an in-process stub server when an endpoint
    /// override is supplied.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_stub_credentials_and_mock_transport(
        store: Arc<PlexusStore>,
        credentials: Arc<StubCredentialSource>,
        mock_transport: Arc<MockTransport>,
    ) -> Self {
        let mcp_transport = Arc::new(McpRemoteTransport::default());
        let rest_transport = Arc::new(RestTransport::default());
        let agent_registry: Arc<dyn AgentRegistry> = Arc::new(StubAgentRegistry::default());
        let engine = GovernanceEngine::new(
            Arc::clone(&store),
            credentials as Arc<dyn CredentialSource>,
            mock_transport as Arc<dyn Transport>,
        );
        let engine = with_freshness_check(engine, &store, &mcp_transport, &rest_transport);
        let reconciler = CatalogReconciler::new(
            Arc::clone(&store),
            Arc::clone(&mcp_transport),
            CatalogRefreshPolicy::default(),
        )
        .with_rest_transport(Arc::clone(&rest_transport));
        Self {
            connector_home: Arc::new(crate::connector_home::ConnectorHome::test_admitted()),
            store: Arc::clone(&store),
            engine,
            reconciler,
            mcp_transport,
            rest_transport,
            agent_registry,
            flow_audiences: crate::flow_audience::FlowAudiences::global_fixture(),
            repository_registry: None,
            github_handle_credentials: None,
            github_control_reader: None,
            endpoint_override: None,
            web_search: Arc::new(WebSearchService::production()),
            code_search: Arc::new(plexus_core::code_search::CodeSearchService::default()),
        }
    }

    /// Explicit test constructor: stub credentials + real MCP transport (for
    /// harness runs against an in-process stub MCP server).
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_stub_credentials_and_mcp_transport(
        store: Arc<PlexusStore>,
        credentials: Arc<StubCredentialSource>,
        mcp_transport: Arc<McpRemoteTransport>,
        endpoint_override: Option<String>,
    ) -> Self {
        let rest_transport = Arc::new(RestTransport::default());
        let agent_registry: Arc<dyn AgentRegistry> = Arc::new(StubAgentRegistry::default());
        let engine = GovernanceEngine::new(
            Arc::clone(&store),
            credentials as Arc<dyn CredentialSource>,
            Arc::new(VendorTransportRouter {
                mcp: Arc::clone(&mcp_transport),
                rest: Arc::clone(&rest_transport),
            }) as Arc<dyn Transport>,
        );
        let engine = with_freshness_check(engine, &store, &mcp_transport, &rest_transport);
        let reconciler = CatalogReconciler::new(
            Arc::clone(&store),
            Arc::clone(&mcp_transport),
            CatalogRefreshPolicy::default(),
        )
        .with_rest_transport(Arc::clone(&rest_transport));
        Self {
            connector_home: Arc::new(crate::connector_home::ConnectorHome::test_admitted()),
            store: Arc::clone(&store),
            engine,
            reconciler,
            mcp_transport,
            rest_transport,
            agent_registry,
            flow_audiences: crate::flow_audience::FlowAudiences::global_fixture(),
            repository_registry: None,
            github_handle_credentials: None,
            github_control_reader: None,
            endpoint_override,
            web_search: Arc::new(WebSearchService::production()),
            code_search: Arc::new(plexus_core::code_search::CodeSearchService::default()),
        }
    }

    pub fn credential_source(&self) -> &Arc<dyn CredentialSource> {
        self.engine.credential_source()
    }
}

/// Add the pre-write catalog check to the engine. Before a write or
/// destructive action is sent, the connection's stored catalog of vendor
/// actions must be current; the check refreshes it from the vendor when it is
/// stale. Reads skip the check. When the check refreshes the catalog or
/// refuses, an audit row is written for the call being checked, and a refused
/// write is not sent.
fn with_freshness_check(
    engine: FacadeEngine,
    store: &Arc<PlexusStore>,
    mcp_transport: &Arc<McpRemoteTransport>,
    rest_transport: &Arc<RestTransport>,
) -> FacadeEngine {
    let engine =
        engine.with_consent_wait_hook(Arc::new(crate::request_execution::ConsentWaitCapacity));
    let reconciler = CatalogReconciler::new(
        Arc::clone(store),
        Arc::clone(mcp_transport),
        CatalogRefreshPolicy::default(),
    )
    .with_rest_transport(Arc::clone(rest_transport));
    let store = Arc::clone(store);
    let credentials: Arc<dyn CredentialSource> = Arc::clone(engine.credential_source());
    engine.with_freshness_check(Arc::new(move |reservation| {
        if !matches!(
            reservation.risk,
            plexus_core::manifest::Risk::Write | plexus_core::manifest::Risk::Destructive
        ) {
            return Ok(());
        }
        let result = reconciler.ensure_fresh_for_action(
            &reservation.principal,
            &reservation.connection_id,
            &reservation.action,
            credentials.as_ref(),
        );
        let refreshed = matches!(&result, Ok(Freshness::Refreshed));
        let refusal = match result {
            Ok(_) => None,
            Err(plexus_core::CatalogError::StaleWrite) => Some((
                "catalog_stale_write".to_string(),
                "catalog is stale and writes are blocked".to_string(),
            )),
            Err(plexus_core::CatalogError::TransportUnavailable { kind }) => Some((
                "transport_unavailable".to_string(),
                format!("transport kind '{kind}' is not available"),
            )),
            Err(other) => {
                plexus_core::diag!(warn catalog:
                    "freshness check for {}/{} could not complete: {other}",
                    reservation.connection_id, reservation.action
                );
                Some((
                    "freshness_check_failed".to_string(),
                    "the check that this write's target is current could not run, so the write was not sent".to_string(),
                ))
            }
        };
        if refusal.is_none() && !refreshed {
            return Ok(());
        }
        let audit = plexus_core::AuditRecord { principal: reservation.principal.clone(),
        actor: reservation.actor.clone(),
        acting_principal: reservation.acting_principal.clone(),
        agent_id: reservation.attributed_agent_id.clone(), app_handle_id: if reservation.origin == plexus_core::governance::RequestOrigin::Facade { reservation.bound_agent_handle.clone() } else { None }, agent_handle: reservation.bound_agent_handle.clone(), connection_id: Some(reservation.connection_id.clone()),
        app_key: Some(reservation.app_key.clone()),
        action: Some(reservation.action.clone()),
        risk: None,
        severity: None,
        decision: if refusal.is_some() { "deny" } else { "allow" }.to_string(),
        reason_code: refusal
            .as_ref()
            .map_or("catalog_refreshed".to_string(), |(code, _)| code.clone()),
        gate: Some("freshness".to_string()),
        args_redaction_summary: None,
        outcome: None,
        latency_ms: None,
        request_id: Some(reservation.request_id.clone()),
        credential_fingerprint: None,
        provider_account_fingerprint: None,
        attempt_no: None,
        vendor_request_id: None,
        idempotency_key_fingerprint: None,
        response_class: None,
        reconciliation_of: None, };
        if let Err(error) = store.append_audit(&audit) {
            plexus_core::diag!(error governance:
                "audit append failed: freshness check for {}/{}: {error}",
                reservation.connection_id, reservation.action
            );
        }
        refusal.map_or(Ok(()), Err)
    }))
}

fn production_handle_credential_provider(
    connection_file: &Path,
) -> Option<Arc<dyn HandleCredentialProvider>> {
    let module_id = credentials_route_module_id()?;
    let identity = plexus_bind_identity();
    let peer = configured_peer(
        SubcCkcredRoutePeer::connect(connection_file, module_id.as_str(), identity),
        "handle credential",
        &module_id,
    )?;
    let source = CkcredCredentialSource::new(Arc::new(peer));
    Some(Arc::new(HandleCredentialPreparer::new(
        source,
        Arc::new(plexus_core::storage::now_ms),
    )))
}

fn production_credential_source(connection_file: &Path) -> Arc<dyn CredentialSource> {
    let Some(module_id) = credentials_route_module_id() else {
        return Arc::new(FailClosedCredentialSource);
    };
    let identity = plexus_bind_identity();
    match configured_peer(
        SubcCkcredRoutePeer::connect(connection_file, module_id.as_str(), identity),
        "credential source",
        &module_id,
    ) {
        Some(peer) => Arc::new(CkcredCredentialSource::new(Arc::new(peer))),
        None => Arc::new(FailClosedCredentialSource),
    }
}

/// A credentials route is present only when the operator or daemon configures
/// one. Absence is fail-closed, not an implicit stub.
fn credentials_route_module_id() -> Option<String> {
    std::env::var("PLEXUS_CKCRED_MODULE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn production_repository_registry(
    connection_file: &Path,
) -> Option<Arc<dyn plexus_core::repository_ownership::RepositoryRegistry>> {
    let identity = plexus_bind_identity();
    match SubcPrefrontalRoutePeer::connect(connection_file, "entorhinal", identity) {
        Ok(peer) => Some(Arc::new(
            plexus_core::repository_ownership::EntorhinalRepositoryRegistry::new(Arc::new(
                peer.with_call_timeout(plexus_core::repository_ownership::OWNERSHIP_CALL_TIMEOUT),
            )),
        )),
        Err(_) => {
            eprintln!(warn scheduler: "{}", peer_failure_warning("repository ownership", "entorhinal"));
            None
        }
    }
}

fn production_agent_registry(connection_file: &Path) -> Arc<dyn AgentRegistry> {
    match production_prefrontal_peer(connection_file) {
        Some(peer) => Arc::new(PrefrontalAgentRegistry::new(Arc::new(peer))),
        None => Arc::new(FailClosedAgentRegistry),
    }
}

/// The agent registry is managed through a route to the Prefrontal module,
/// whose module id comes from `PLEXUS_PREFRONTAL_MODULE_ID`. When that id is
/// unset or the route cannot be opened, this returns `None` and the caller
/// uses a registry that answers every lookup as unavailable.
fn production_prefrontal_peer(connection_file: &Path) -> Option<SubcPrefrontalRoutePeer> {
    let module_id = prefrontal_route_module_id()?;
    let identity = plexus_bind_identity();
    configured_peer(
        SubcPrefrontalRoutePeer::connect(connection_file, module_id.as_str(), identity),
        "agent registry",
        &module_id,
    )
}

/// Filing, reading, withdrawing and detaching a card each get five seconds,
/// so a stalled approval service cannot exhaust the held tool call's budget.
const CONSENT_CARD_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Cingulate is the consent module that shows approval cards on the user's
/// phone. Each card is filed on a route opened under the held call's own
/// session scope (its owner, reference and epoch), so Cingulate learns which
/// agent is asking from the daemon's stamp on that route. The identity plexus
/// binds with names only plexus; it never claims an agent or subject itself.
fn production_consent_cards(connection_file: &Path) -> Option<Arc<ConsentCards>> {
    let module_id = "cingulate";
    let identity = plexus_bind_identity();
    let peer = configured_peer(
        SubcPrefrontalRoutePeer::connect(connection_file, module_id, identity),
        "consent cards",
        module_id,
    )?
    .with_call_timeout(CONSENT_CARD_CALL_TIMEOUT);
    Some(Arc::new(ConsentCards::new(Arc::new(peer))))
}

/// Prefrontal's module id is deployment configuration rather than a Plexus
/// constant, so changing that supervised module's id does not require a Plexus
/// release.
fn prefrontal_route_module_id() -> Option<String> {
    std::env::var("PLEXUS_PREFRONTAL_MODULE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::test_logging as diagnostic_logging;

    #[test]
    fn configured_peer_warning_names_role_and_target_without_error_contents() {
        const TEST: &str = "composition::tests::configured_peer_warning_names_role_and_target_without_error_contents";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
            let output = crate::bounded::child_output(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env("PLEXUS_LOG_STDERR_CHILD", "1"),
                std::time::Duration::from_secs(10),
                "configured peer warning child",
            )
            .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{stderr}");
            assert!(
                stderr.contains("configured agent registry peer prefrontal-core unavailable"),
                "configured peer failure must be visible: {stderr}"
            );
            let line = stderr
                .lines()
                .find(|line| {
                    line.contains("configured agent registry peer prefrontal-core unavailable")
                })
                .expect("configured peer failure must be visible");
            diagnostic_logging::assert_diagnostic(line, cortexkit_log::ParsedLevel::Warn, "plexus.wire",
                "configured agent registry peer prefrontal-core unavailable; keeping the route fail-closed");
            assert!(
                !stderr.contains("opaque-token-secret"),
                "peer errors must not be dumped: {stderr}"
            );
            return;
        }
        diagnostic_logging::init_child();
        let message = peer_failure_warning("agent registry", "prefrontal-core");
        assert!(message.contains("agent registry") && message.contains("prefrontal-core"));
        assert!(message.contains("fail-closed"));
        assert!(configured_peer::<u8, _>(
            Err("opaque-token-secret"),
            "agent registry",
            "prefrontal-core"
        )
        .is_none());
        assert_eq!(
            configured_peer::<u8, &str>(Ok(7), "agent registry", "prefrontal-core"),
            Some(7)
        );
    }

    #[test]
    fn unregistered_connections_fail_closed_in_the_remote_transport() {
        let router = VendorTransportRouter {
            mcp: Arc::new(McpRemoteTransport::default()),
            rest: Arc::new(RestTransport::default()),
        };
        let response = router.dispatch(
            TransportRequest {
                request_id: "request".to_string(),
                connection_id: "local".to_string(),
                action: "read".to_string(),
                args: json!({}),
                credential_fingerprint: "unused".to_string(),
            },
            &plexus_core::ResolvedCredential::anonymous(),
        );
        assert!(response.response.is_none());
    }
}

#[cfg(test)]
mod github_facade_wiring_tests {
    use super::*;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::storage::CatalogActionInput;
    use plexus_core::{AuthorizationRequest, Denial};
    use serde_json::json;

    #[test]
    fn production_engine_refuses_ordinary_handle_write_before_grant_matching() {
        let scratch = plexus_core::test_scratch::Scratch::database("module-github-seams");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "module-github-seams".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
        store
            .insert_connection(
                "direct",
                "github-connection",
                "github_rest",
                "active",
                &json!({}),
            )
            .unwrap();
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "github-connection".into(),
                principal: "direct".into(),
                name: "add_issue_comment".into(),
                title: None,
                schema: json!({}),
                schema_hash: "schema".into(),
                risk: "write".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        let mut runtime = ModuleRuntime::production(store, Path::new("/unavailable-route"));
        // A production runtime starts with the connector-home claim unknown, which
        // refuses every authorization before any other check. A guard that never
        // refuses lets this test reach the check it is about: a bot write sent
        // straight to `authorize` is refused unless it came through the GitHub
        // bot-request entry point.
        runtime.engine = runtime.engine.with_connector_home_guard(Arc::new(|| None));
        let denied = runtime.engine.authorize(AuthorizationRequest::new(
            "direct",
            "github-connection",
            "add_issue_comment",
            json!({"repository":"org/repo"}),
        ));
        assert!(
            matches!(denied, Err(Denial::BotActionRequiresFacade)),
            "{denied:?}"
        );
    }
}

#[cfg(test)]
mod web_search_composition_tests {
    use super::*;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::web_search::providers::PROVIDER_NAMES;
    use plexus_core::web_search::registered_backend;

    #[test]
    fn production_composition_registers_every_backend_in_the_name_table_registry() {
        let scratch = plexus_core::test_scratch::Scratch::database("module-web-search-composition");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "module-web-search-composition".into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: scratch.path().to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let runtime = ModuleRuntime::production(store, Path::new("/unavailable-route"));

        let mut registered = Vec::new();
        for provider in PROVIDER_NAMES {
            if let Some(backend) = registered_backend(provider) {
                assert_eq!(
                    (backend.name(), backend.app_key(), backend.action()),
                    (provider.name, provider.app_key, provider.action),
                    "a registered backend serves exactly its name-table row"
                );
                registered.push(provider.name);
            }
        }
        registered.sort_unstable();
        assert!(registered.contains(&"exa"), "{registered:?}");
        assert_eq!(
            runtime.web_search.chain_backend_names(),
            registered,
            "the production service offers an order every registered backend"
        );
        assert_eq!(
            runtime.web_search.backend_name(),
            "exa",
            "searches with no order still use Exa"
        );
    }
}
