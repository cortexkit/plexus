use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::catalog::facade_only_from_stored_manifest;
use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::control::{
    self, AgentPermission, InstallationReader, Inventory, InventoryHandle,
};
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::storage::PlexusStore;
use plexus_core::{ingest_value, CATALOG_PRINCIPAL};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

fn store() -> PlexusStore {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let store = PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "github-control-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    })
    .unwrap();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
        .unwrap();
    store
}

// Parse the shipped reviewed JSONC rather than deriving expected catalog rows
// from the seeder under test.
fn github_manifest() -> plexus_core::IngestedManifest {
    let source = include_str!(concat!("../", "../../../catalog/github_rest.jsonc"));
    let mut clean = String::new();
    let mut chars = source.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if quoted {
            clean.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            clean.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    clean.push(next);
                    break;
                }
            }
        } else {
            clean.push(ch);
        }
    }
    ingest_value(serde_json::from_str(&clean).unwrap()).unwrap()
}

struct Credentials(AtomicUsize);
impl HandleCredentialProvider for Credentials {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if reference == "github_app:retired" {
            return Err("handle_credential_unresolvable");
        }
        Ok(ResolvedCredential::new(
            reference.as_bytes().to_vec(),
            Some(1_000_000),
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

struct Reader(AtomicUsize);
impl InstallationReader for Reader {
    fn repositories_page(
        &self,
        credential: &ResolvedCredential,
        page: usize,
        per_page: usize,
    ) -> Result<Value, String> {
        assert_eq!(per_page, 100);
        self.0.fetch_add(1, Ordering::Relaxed);
        let name = std::str::from_utf8(credential.payload()).unwrap();
        if name == "github_app:bad" {
            return Err("vendor_unreachable".into());
        }
        let repos = if page == 1 {
            (0..100)
                .map(|i| json!({"full_name":format!("org/repo{i}")}))
                .collect::<Vec<_>>()
        } else {
            vec![
                json!({"full_name":"org/last"}),
                json!({"full_name":"org/unbound"}),
            ]
        };
        Ok(json!({"repositories":repos}))
    }
}

fn inventory() -> Inventory {
    Inventory {
        version: "github-grant-import.v1".into(),
        handles: vec![InventoryHandle {
            app_handle_id: "app-one".into(),
            agent_id: "agent-one".into(),
            app_id: 42,
            installation_id: None,
            credential_id: "github_app:app-one".into(),
            status: "enabled".into(),
            grants: vec![AgentPermission {
                action: "create_issue".into(),
                repository: "org/last".into(),
                provenance: "today-grant-1".into(),
                policy: "allow".into(),
            }],
        }],
    }
}

#[test]
fn inventory_handle_and_credential_must_name_the_same_app() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    let mut input = inventory();
    input.handles[0].credential_id = "github_app:other".into();
    assert_eq!(
        control::import(&store, "direct", &input, &provider, &reader, 0, true).unwrap_err(),
        "inventory_handle_invalid"
    );
    assert_eq!(provider.0.load(Ordering::Relaxed), 0);
}

#[test]
fn import_preview_detects_existing_handle_before_apply() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    control::import(&store, "direct", &inventory(), &provider, &reader, 0, false).unwrap();
    assert!(control::import(&store, "direct", &inventory(), &provider, &reader, 0, true).is_err());
}

#[test]
fn import_mints_one_agent_grant_per_action_not_per_repository() {
    let store = store();
    let mut input = inventory();
    let mut second = input.handles[0].grants[0].clone();
    second.repository = "org/repo0".into();
    input.handles[0].grants.push(second);
    let plan = control::import(
        &store,
        "direct",
        &input,
        &Credentials(AtomicUsize::new(0)),
        &Reader(AtomicUsize::new(0)),
        0,
        false,
    )
    .unwrap();
    assert_eq!(plan["agents"]["agent-one"].as_array().unwrap().len(), 2);
    assert_eq!(
        store
            .list_grants("direct", "github-handle-app-one")
            .unwrap()
            .iter()
            .filter(|grant| grant.grant_id.contains(":agent:"))
            .count(),
        1
    );
}

#[test]
fn failed_probe_clears_previous_proof() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    control::import(&store, "direct", &inventory(), &provider, &reader, 0, false).unwrap();
    control::probe(&store, "direct", "app-one", &provider, &reader, 1).unwrap();
    store
        .bind_github_repo("org/inaccessible", "app-one")
        .unwrap();
    assert!(control::probe(&store, "direct", "app-one", &provider, &reader, 2).is_err());
    assert_eq!(
        store
            .github_handle_and_bindings("app-one")
            .unwrap()
            .unwrap()
            .0
            .proven_at,
        None
    );
}

#[test]
fn probe_cannot_prove_a_rotated_credential_or_changed_binding() {
    struct ChangingReader<'a> {
        store: &'a PlexusStore,
        rotate: bool,
    }
    impl InstallationReader for ChangingReader<'_> {
        fn repositories_page(
            &self,
            _: &ResolvedCredential,
            _: usize,
            _: usize,
        ) -> Result<Value, String> {
            if self.rotate {
                let (mut handle, _) = self
                    .store
                    .github_handle_and_bindings("app-one")
                    .unwrap()
                    .unwrap();
                handle.credential_generation += 1;
                self.store.put_github_handle(&handle).unwrap();
            } else {
                self.store.bind_github_repo("org/new", "app-one").unwrap();
            }
            Ok(json!({"repositories":[{"full_name":"org/last"}]}))
        }
    }
    for rotate in [false, true] {
        let store = store();
        let provider = Credentials(AtomicUsize::new(0));
        control::import(
            &store,
            "direct",
            &inventory(),
            &provider,
            &Reader(AtomicUsize::new(0)),
            0,
            false,
        )
        .unwrap();
        assert_eq!(
            control::probe(
                &store,
                "direct",
                "app-one",
                &provider,
                &ChangingReader {
                    store: &store,
                    rotate
                },
                1
            )
            .unwrap_err(),
            "store_failure"
        );
        assert_eq!(
            store
                .github_handle_and_bindings("app-one")
                .unwrap()
                .unwrap()
                .0
                .proven_at,
            None
        );
    }
}

#[test]
fn import_requires_direct_and_does_not_read_vault_on_refusal() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    assert_eq!(
        control::import(
            &store,
            plexus_core::github::AFT_PRINCIPAL,
            &inventory(),
            &provider,
            &reader,
            0,
            false
        )
        .unwrap_err(),
        "operator_authority_required"
    );
    assert_eq!(provider.0.load(Ordering::Relaxed), 0);
    assert!(store
        .github_handle_and_bindings("app-one")
        .unwrap()
        .is_none());
}

#[test]
fn import_resolves_repositories_with_own_installation_token_and_pages_to_completion() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    let plan =
        control::import(&store, "direct", &inventory(), &provider, &reader, 0, true).unwrap();
    assert_eq!(plan["agents"]["agent-one"][0]["repository"], "org/last");
    assert_eq!(plan["module_grants"].as_array().unwrap().len(), 2);
    assert_eq!(reader.0.load(Ordering::Relaxed), 2);
    assert!(store
        .github_handle_and_bindings("app-one")
        .unwrap()
        .is_none());
    control::import(&store, "direct", &inventory(), &provider, &reader, 0, false).unwrap();
    assert_eq!(
        store
            .github_handle_and_bindings("app-one")
            .unwrap()
            .unwrap()
            .1,
        vec!["org/last"]
    );
    assert_eq!(store.github_repo_binding_generation().unwrap(), 1);
    // An imported handle's allowlist has the same shape bind_github_repo
    // writes: the single installation owner plus bare repository names, since
    // REST calls carry owner and repo as separate path arguments.
    let filters = store
        .connection("direct", "github-handle-app-one")
        .unwrap()
        .unwrap()
        .resource_filters;
    assert_eq!(filters["values"]["owner"], "org");
    assert_eq!(filters["values"]["repo"], serde_json::json!(["last"]));
    assert_eq!(
        filters["write_enabling"],
        serde_json::json!(["owner", "repo"])
    );
    let seeded = store
        .list_catalog_actions_all("direct", "github-handle-app-one")
        .unwrap();
    let declared = github_manifest().manifest.actions_baseline;
    assert_eq!(
        seeded.len(),
        declared.len(),
        "every reviewed action must be seeded"
    );
    for declaration in &declared {
        let action = seeded
            .iter()
            .find(|action| action.name == declaration.name)
            .unwrap_or_else(|| panic!("missing reviewed action {}", declaration.name));
        assert_eq!(
            action.risk,
            match declaration.risk {
                plexus_core::manifest::Risk::Read => "read",
                plexus_core::manifest::Risk::Write => "write",
                plexus_core::manifest::Risk::Destructive => "destructive",
            },
            "{} risk",
            action.name
        );
        assert_eq!(
            facade_only_from_stored_manifest(&store, action),
            declaration.facade_only,
            "{} facade_only",
            action.name
        );
    }
    let grants = store
        .list_grants("direct", "github-handle-app-one")
        .unwrap();
    assert_eq!(grants.len(), 3);
    assert_eq!(
        grants
            .iter()
            .filter(|row| row.grantee_principal == plexus_core::github::AFT_PRINCIPAL)
            .count(),
        2
    );
    assert!(grants
        .iter()
        .any(|row| row.grant_id.contains("today-grant-1")));
    for principal in [
        plexus_core::github::AFT_PRINCIPAL,
        plexus_core::github::PREFRONTAL_PRINCIPAL,
    ] {
        assert_eq!(
            store
                .connection_for_invoke(principal, "github-handle-app-one")
                .unwrap()
                .unwrap()
                .principal,
            "direct"
        );
    }
    assert!(
        control::import(&store, "direct", &inventory(), &provider, &reader, 0, false).is_err(),
        "import only once"
    );
    for grant in grants {
        assert!(store.revoke_grant("direct", &grant.grant_id).unwrap());
    }
    assert!(store
        .list_grants("direct", "github-handle-app-one")
        .unwrap()
        .iter()
        .all(|row| row.revoked_at_ms.is_some()));
    assert!(!store
        .github_module_grant("github-handle-app-one", plexus_core::github::AFT_PRINCIPAL)
        .unwrap());
}

#[test]
fn import_rolls_back_connection_handle_bindings_and_grants_on_a_late_error() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    let mut input = inventory();
    let mut second = input.handles[0].clone();
    second.app_handle_id = "app-two".into();
    second.agent_id = "agent-two".into();
    second.credential_id = "github_app:app-two".into();
    second.grants[0].provenance = "today-grant-2".into();
    second.grants[0].repository = "org/last".into();
    input.handles.push(second);
    assert!(control::import(&store, "direct", &input, &provider, &reader, 0, false).is_err());
    assert!(store
        .github_handle_and_bindings("app-one")
        .unwrap()
        .is_none());
    assert!(store
        .github_handle_and_bindings("app-two")
        .unwrap()
        .is_none());
    for id in ["github-handle-app-one", "github-handle-app-two"] {
        assert!(
            store
                .list_catalog_actions_all("direct", id)
                .unwrap()
                .is_empty(),
            "failed import left catalog rows for {id}"
        );
    }
    assert_eq!(store.github_repo_binding_generation().unwrap(), 0);
    assert!(!store
        .github_module_grant("github-handle-app-one", plexus_core::github::AFT_PRINCIPAL)
        .unwrap());
}

#[test]
fn bindings_read_requires_a_module_grant_and_reports_rebinding_generation() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    let connection = "github-handle-app-one";
    assert_eq!(
        control::bindings_read(&store, plexus_core::github::AFT_PRINCIPAL, connection)
            .unwrap_err()
            .reason_code(),
        "module_grant_absent"
    );
    let mut input = inventory();
    let mut second = input.handles[0].clone();
    second.app_handle_id = "app-two".into();
    second.agent_id = "agent-two".into();
    second.credential_id = "github_app:app-two".into();
    second.grants[0].repository = "org/repo0".into();
    input.handles.push(second);
    control::import(&store, "direct", &input, &provider, &reader, 0, false).unwrap();
    let before =
        control::bindings_read(&store, plexus_core::github::AFT_PRINCIPAL, connection).unwrap();
    assert_eq!(
        before["bindings"],
        json!([{"repository":"org/last","app_handle_id":"app-one","agent_id":"agent-one"}])
    );
    assert_eq!(
        control::bindings_read(&store, "reserved:other", connection)
            .unwrap_err()
            .reason_code(),
        "module_grant_absent"
    );
    assert_eq!(
        control::bindings_read(
            &store,
            plexus_core::github::PREFRONTAL_PRINCIPAL,
            connection
        )
        .unwrap()["bindings"],
        before["bindings"]
    );
    store.bind_github_repo("org/last", "app-two").unwrap();
    let after =
        control::bindings_read(&store, plexus_core::github::AFT_PRINCIPAL, connection).unwrap();
    assert!(
        after["repo_binding_generation"].as_i64().unwrap()
            > before["repo_binding_generation"].as_i64().unwrap()
    );
    assert_eq!(after["bindings"], json!([]));
}

#[test]
fn probe_requires_direct_and_records_proof_only_after_complete_readback() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    control::import(&store, "direct", &inventory(), &provider, &reader, 0, false).unwrap();
    assert_eq!(
        control::probe(
            &store,
            plexus_core::github::AFT_PRINCIPAL,
            "app-one",
            &provider,
            &reader,
            0
        )
        .unwrap_err(),
        "operator_authority_required"
    );
    assert_eq!(
        store
            .github_handle_and_bindings("app-one")
            .unwrap()
            .unwrap()
            .0
            .proven_at,
        None
    );
    store
        .bind_github_repo("org/inaccessible", "app-one")
        .unwrap();
    assert!(
        control::probe(&store, "direct", "app-one", &provider, &reader, 0)
            .unwrap_err()
            .contains("org/inaccessible")
    );
    assert_eq!(
        store
            .github_handle_and_bindings("app-one")
            .unwrap()
            .unwrap()
            .0
            .proven_at,
        None
    );
    store.unbind_github_repo("org/inaccessible").unwrap();
    control::probe(&store, "direct", "app-one", &provider, &reader, 8).unwrap();
    assert_eq!(
        store
            .github_handle_and_bindings("app-one")
            .unwrap()
            .unwrap()
            .0
            .proven_at,
        Some(8)
    );
}

/// The import refuses an ask_first policy on a read, a repository the
/// installation does not list, and a credential the vault cannot resolve. The
/// last is refused with the credential provider's own refusal code plus the
/// inventory's credential id, the same for every credential id: none is
/// special-cased.
#[test]
fn inventory_rejects_ask_first_reads_unreachable_repos_and_unresolvable_credentials() {
    let store = store();
    let provider = Credentials(AtomicUsize::new(0));
    let reader = Reader(AtomicUsize::new(0));
    let mut input = inventory();
    input.handles[0].grants[0].action = "github.issue.get".into();
    input.handles[0].grants[0].policy = "ask_first".into();
    assert_eq!(
        control::import(&store, "direct", &input, &provider, &reader, 0, false).unwrap_err(),
        "inventory_grant_invalid"
    );
    input.handles[0].grants[0].policy = "allow".into();
    input.handles[0].grants[0].repository = "org/not-listed".into();
    assert!(
        control::import(&store, "direct", &input, &provider, &reader, 0, false)
            .unwrap_err()
            .contains("org/not-listed")
    );
    input.handles[0].credential_id = "github_app:retired".into();
    input.handles[0].app_handle_id = "retired".into();
    assert_eq!(
        control::import(&store, "direct", &input, &provider, &reader, 0, false).unwrap_err(),
        "handle_credential_unresolvable{credential_id: github_app:retired}"
    );
}

/// A vault that resolves every scoped read to the credential it was asked for,
/// with the credential id itself as the token, and counts the reads.
#[derive(Default)]
struct CountingVault(AtomicUsize);
impl plexus_core::credentials::CkcredRoutePeer for CountingVault {
    fn call(
        &self,
        _: &str,
        params: Value,
    ) -> Result<Value, plexus_core::credentials::CkcredRouteError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let id = params["credential_id"].as_str().unwrap_or_default();
        Ok(json!({"result": {
            "payload": id.as_bytes(),
            "expires_at_ms": 3_600_000,
            "record_version": 1,
            "credential_id": id,
        }}))
    }
}

/// The probe and the bind read the installation with the handle row's own
/// credential generation, so a probe does not fetch an obsolete generation.
#[test]
fn probe_and_bind_keep_the_dispatch_token_of_the_handles_generation() {
    use plexus_core::credentials::CkcredCredentialSource;
    use plexus_core::github::credential::HandleCredentialPreparer;
    let store = store();
    let reader = Reader(AtomicUsize::new(0));
    control::import(
        &store,
        "direct",
        &inventory(),
        &Credentials(AtomicUsize::new(0)),
        &reader,
        0,
        false,
    )
    .unwrap();
    // The handle's credential has been rotated past the imported generation.
    let (mut handle, _) = store
        .github_handle_and_bindings("app-one")
        .unwrap()
        .unwrap();
    handle.credential_generation = 3;
    store.put_github_handle(&handle).unwrap();
    let vault = std::sync::Arc::new(CountingVault::default());
    let preparer = HandleCredentialPreparer::new(
        CkcredCredentialSource::new(vault.clone()),
        std::sync::Arc::new(|| 0),
    );
    // Dispatch prepares the handle's current generation.
    preparer
        .prepare("app-one", 3, "github_app:app-one")
        .unwrap();
    control::probe(&store, "direct", "app-one", &preparer, &reader, 1).unwrap();
    control::bind(
        &store,
        "direct",
        "app-one",
        &["org/repo1".to_owned()],
        &preparer,
        &reader,
        2,
        false,
    )
    .unwrap();
    preparer
        .prepare("app-one", 3, "github_app:app-one")
        .unwrap();
    assert_eq!(
        vault.0.load(Ordering::SeqCst),
        1,
        "the probe, the bind and the second dispatch all used the cached token"
    );
}

struct BotGateStore;
impl plexus_core::github::facade::gates::GateStore for BotGateStore {
    fn handle(
        &self,
        _: &str,
    ) -> Result<Option<plexus_core::github::facade::gates::Handle>, String> {
        Ok(Some(plexus_core::github::facade::gates::Handle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            connection_id: "github-handle-app-fixture".into(),
            connection_principal: "direct".into(),
            credential_reference: "github_app:app-fixture".into(),
            status: "enabled".into(),
            proven: true,
        }))
    }
    fn handle_for_agent(
        &self,
        agent: &str,
    ) -> Result<Option<plexus_core::github::facade::gates::Handle>, String> {
        Ok(self
            .handle("app-fixture")?
            .filter(|handle| handle.agent_id == agent))
    }
    fn binding(
        &self,
        _: &str,
    ) -> Result<Option<(plexus_core::github::resolver::Binding, String)>, String> {
        Ok(Some((
            plexus_core::github::resolver::Binding {
                app_handle_id: "app-fixture".into(),
                connection_id: "github-handle-app-fixture".into(),
            },
            "agent-fixture".into(),
        )))
    }
    fn authority(
        &self,
        _: &plexus_core::github::facade::gates::Handle,
        _: &str,
        _: &str,
        _: &plexus_core::github::facade::request_map::MappedRequest,
        _: &str,
    ) -> Result<plexus_core::github::facade::gates::Authority, String> {
        Ok(plexus_core::github::facade::gates::Authority {
            module_grant: false,
            agent_grant: true,
            pair_allowed: true,
            module_effect: "allow".into(),
            agent_effect: None,
            baseline: Value::Null,
        })
    }
    fn receipt(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<plexus_core::github::receipt::Receipt>, String> {
        Ok(None)
    }
    fn claim(
        &self,
        _: &str,
        _: &str,
        _: &plexus_core::github::facade::request_map::MappedRequest,
        _: &plexus_core::github::facade::gates::Handle,
        _: &str,
        _: &Value,
        _: &[plexus_core::github::receipt::Effect],
        _: bool,
        _: i64,
        _: i64,
    ) -> Result<plexus_core::github::receipt::Claim, String> {
        panic!("missing module grant reached claim")
    }
}

#[test]
fn bot_request_requires_a_module_grant_even_with_a_delegating_stamp() {
    let scope = crate::scope_support::delegating_scope("agent-fixture");
    let request = json!({"repository":"org/last","action":"issue create","title":"hello"});
    for caller in [plexus_core::github::AFT_PRINCIPAL, "reserved:other"] {
        let reply = plexus_core::github::facade::gates::run_scoped(
            &BotGateStore,
            caller,
            Some(&scope),
            &request,
            "nonce",
            "request-id",
            "owner",
            1_700_000_100_000,
            120,
        );
        assert_eq!(reply.refusal_code.as_deref(), Some("module_grant_absent"));
        assert_eq!(reply.gate, "G6");
    }
}
