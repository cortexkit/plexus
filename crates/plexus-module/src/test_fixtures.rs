//! Store and runtime fixtures shared by the unit and integration tests.

use super::{
    health, MockTransport, ModuleRuntime, ModuleState, PlexusStore, Scratch, StubCredentialSource,
};
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle, GithubImportRow};
use plexus_core::{ingest_value, MockResponse, CATALOG_PRINCIPAL};
use serde_json::json;
use std::{path::Path, sync::Arc};

pub(super) fn github_manifest() -> plexus_core::IngestedManifest {
    let source = include_str!("../../../catalog/github_rest.jsonc");
    ingest_value(serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap())
        .unwrap()
}

pub(super) fn imported_runtime() -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    imported_runtime_with_actions(&[
        "github.issue.get",
        "github.issue_comments.list",
        "github.issue.search",
    ])
}

pub(super) fn imported_runtime_with_actions(
    actions: &[&str],
) -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    imported_runtime_with_provider(actions, anonymous_handle_credentials())
}

/// [`imported_runtime_with_actions`] whose bot tokens come from `provider`,
/// so a test can see what the vault is told about a vendor reply.
pub(super) fn imported_runtime_with_provider(
    actions: &[&str],
    provider: Arc<dyn HandleCredentialProvider>,
) -> (
    Arc<ModuleState>,
    Arc<PlexusStore>,
    Arc<MockTransport>,
    Scratch,
) {
    let scratch = Scratch::database("github-read-frame");
    let store = Arc::new(open_file_store(&scratch));
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
        .unwrap();
    store
        .import_github_handles(&[GithubImportRow {
            handle: GithubHandle {
                app_handle_id: "app-x".into(),
                agent_id: "agent-x".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:app-x".into(),
                credential_generation: 0,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "github-handle-app-x".into(),
            },
            repositories: vec!["o/x".into()],
            grants: vec![],
            module_actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            policies: vec![],
        }])
        .unwrap();
    let transport = Arc::new(MockTransport::default());
    transport.set_response(MockResponse::Success(json!({"items":[
        {"repository":{"full_name":"o/x"}},
        {"repository":{"full_name":"o/unbound"}}
    ]})));
    let mut runtime = ModuleRuntime::with_stub_credentials_and_mock_transport(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        transport.clone(),
    );
    runtime.engine = runtime
        .engine
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(provider),
        }));
    (
        Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        }),
        store,
        transport,
        scratch,
    )
}

/// A bot-token source that hands every handle an anonymous credential, for
/// tests whose vendor is a mock transport that never reads the token.
pub(super) fn anonymous_handle_credentials(
) -> Arc<dyn plexus_core::github::credential::HandleCredentialProvider> {
    struct Anonymous;
    impl plexus_core::github::credential::HandleCredentialProvider for Anonymous {
        fn prepare(
            &self,
            _: &str,
            _: i64,
            _: &str,
        ) -> Result<plexus_core::ResolvedCredential, &'static str> {
            Ok(plexus_core::ResolvedCredential::anonymous())
        }
        fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
    }
    Arc::new(Anonymous)
}

/// A migrated store in the SQLite database file at `path`, namespaced by that
/// path, the way most fixtures open theirs.
pub(crate) fn open_file_store(path: &Path) -> PlexusStore {
    let location = path.to_string_lossy().into_owned();
    plexus_core::PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
        module_id: crate::DEFAULT_MODULE_ID.to_string(),
        storage_namespace: location.clone(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite { path: location },
    })
    .expect("open the test store file")
}
