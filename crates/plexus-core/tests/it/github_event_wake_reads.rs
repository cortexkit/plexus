use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::credentials::{ResolvedCredential, StubCredentialSource};
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::github::reads::{read, ReadError};
use plexus_core::governance::{Denial, GovernanceEngine, ResolverDenial};
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle, GithubImportRow};
use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
use plexus_core::{ingest_value, PlexusStore, CATALOG_PRINCIPAL};
use serde_json::json;
use std::sync::{Arc, Mutex};

const PRINCIPAL: &str = plexus_core::github::PREFRONTAL_PRINCIPAL;

#[derive(Default)]
struct Wire {
    events: Mutex<Vec<String>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl Transport for Wire {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        self.events.lock().unwrap().push("github".into());
        let answer = match request.action.as_str() {
            "github.issue.get" => json!({"number":7}),
            "github.issue.search" => json!({"items":[
                {"repository":{"full_name":"o/x"}},
                {"repository":{"full_name":"o/unbound"}}],"total_count":2}),
            "github.issue_comments.list" => {
                if request.args["page"] == 1 {
                    json!((0..100).map(|n| json!({"id":n})).collect::<Vec<_>>())
                } else {
                    json!([{"id":101}])
                }
            }
            other => panic!("unexpected action {other}"),
        };
        self.requests.lock().unwrap().push(request);
        TransportResponse::success(answer)
    }
}
impl HandleCredentialProvider for Wire {
    fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
        self.events.lock().unwrap().push("vault".into());
        Ok(ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

fn manifest() -> plexus_core::IngestedManifest {
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

fn setup() -> (
    Arc<PlexusStore>,
    GovernanceEngine<StubCredentialSource, Wire>,
    Arc<Wire>,
) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "wake-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    for (id, repositories) in [("x", vec!["o/x", "o/also-x"]), ("y", vec!["o/y"])] {
        store
            .import_github_handles(&[GithubImportRow {
                handle: GithubHandle {
                    app_handle_id: id.into(),
                    agent_id: format!("agent-{id}"),
                    app_id: 1,
                    installation_id: None,
                    credential_reference: format!("github_app:{id}"),
                    credential_generation: 0,
                    status: "enabled".into(),
                    proven_at: None,
                    connection_principal: "direct".into(),
                    connection_id: format!("github-handle-{id}"),
                },
                repositories: repositories.into_iter().map(str::to_owned).collect(),
                grants: vec![],
                module_actions: vec![
                    "github.issue.get".into(),
                    "github.issue_comments.list".into(),
                    "github.issue.search".into(),
                ],
                policies: vec![],
            }])
            .unwrap();
    }
    let wire = Arc::new(Wire::default());
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        wire.clone(),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(wire.clone()),
    }));
    (store, engine, wire)
}

#[test]
fn prefrontal_reads_use_bound_handle_and_cold_scoped_credential() {
    let (store, engine, wire) = setup();
    assert!(wire.events.lock().unwrap().is_empty());
    assert_eq!(
        read(
            &engine,
            PRINCIPAL,
            "github.issue.get",
            &json!("o/x"),
            &json!({"issue_number":7})
        )
        .unwrap()["number"],
        7
    );
    assert_eq!(*wire.events.lock().unwrap(), ["vault", "github"]);
    let request = &wire.requests.lock().unwrap()[0];
    assert_eq!(request.connection_id, "github-handle-x");
    assert_eq!(request.args["owner"], "o");
    assert_eq!(request.args["repo"], "x");
    assert!(store.list_action_requests(PRINCIPAL).unwrap().is_empty());
    let rows = store.list_audit("direct").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].request_id, rows[1].request_id);
}

#[test]
fn resolver_refusals_do_not_load_a_connection_or_contact_vault() {
    for (action, repository, args, reason) in [
        (
            "github.issue.get",
            json!("o/unbound"),
            json!({"issue_number":7}),
            ResolverDenial::RepositoryUnbound,
        ),
        (
            "github.issue.get",
            json!("o/x"),
            json!({"issue_number":7,"repo":"y"}),
            ResolverDenial::RepositoryUnbound,
        ),
        (
            "github.issue.search",
            json!(["o/x", "o/y"]),
            json!({"terms":"bug"}),
            ResolverDenial::RequestFieldForbidden {
                field: "repositories".into(),
            },
        ),
        (
            "github.issue.search",
            json!(["o/x"]),
            json!({"terms":"bug repo:o/y"}),
            ResolverDenial::RequestFieldForbidden {
                field: "query_qualifier".into(),
            },
        ),
    ] {
        let (store, engine, wire) = setup();
        assert_eq!(
            read(&engine, PRINCIPAL, action, &repository, &args),
            Err(ReadError::Denied(Denial::Resolver(reason)))
        );
        assert!(wire.events.lock().unwrap().is_empty());
        assert!(
            store.list_audit("direct").unwrap().is_empty(),
            "connection was loaded before resolver refusal"
        );
        let rows = store.list_audit(PRINCIPAL).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].gate.as_deref(), Some("resolver"));
        assert_eq!(rows[0].agent_id, None);
        assert_eq!(rows[0].agent_handle, None);
        assert_eq!(rows[0].connection_id, None);
    }
}

#[test]
fn unsupported_action_refuses_before_binding_lookup() {
    let (store, engine, wire) = setup();
    assert_eq!(
        read(
            &engine,
            PRINCIPAL,
            "add_issue_comment",
            &json!("o/x"),
            &json!({})
        ),
        Err(ReadError::UnsupportedAction)
    );
    assert!(store.list_audit(PRINCIPAL).unwrap().is_empty());
    assert!(wire.events.lock().unwrap().is_empty());
}

#[test]
fn search_qualifies_server_side_filters_unbound_hits_and_uses_one_reservation() {
    let (store, engine, wire) = setup();
    let answer = read(
        &engine,
        PRINCIPAL,
        "github.issue.search",
        &json!(["o/x"]),
        &json!({"terms":"bug"}),
    )
    .unwrap();
    assert_eq!(answer["items"], json!([{"repository":{"full_name":"o/x"}}]));
    let requests = wire.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].args["q"], "bug repo:o/x");
    drop(requests);
    let rows = store.list_audit("direct").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].request_id, rows[1].request_id);
    assert_eq!(rows[0].reason_code, "credential_resolved");
    assert_eq!(rows[1].reason_code, "dispatched");
}

#[test]
fn comments_list_walks_all_pages() {
    let (_, engine, wire) = setup();
    let answer = read(
        &engine,
        PRINCIPAL,
        "github.issue_comments.list",
        &json!("o/x"),
        &json!({"issue_number":7}),
    )
    .unwrap();
    assert_eq!(answer.as_array().unwrap().len(), 101);
    let requests = wire.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].args["page"], 1);
    assert_eq!(requests[1].args["page"], 2);
}
