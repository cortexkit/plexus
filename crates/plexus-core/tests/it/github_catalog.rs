use std::sync::Arc;

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::catalog::{facade_only_from_stored_manifest, CatalogReconciler};
use plexus_core::governance::{GovernanceSeams, ResolverDenial};
use plexus_core::{
    ingest_value, AuthorizationRequest, CatalogAction, Denial, GovernanceEngine,
    McpRemoteTransport, MockTransport, PlexusStore, RestConnection, StubCredentialSource,
    CATALOG_PRINCIPAL,
};
use serde_json::{json, Value};

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
    let jsonc = serde_json::from_str(&clean).expect("parse github REST JSONC");
    ingest_value(jsonc).expect("ingest github REST manifest")
}

fn store() -> Arc<PlexusStore> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: format!(
            "github-catalog-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    };
    Arc::new(PlexusStore::open(&descriptor).expect("open catalog store"))
}

fn installed_catalog() -> (Arc<PlexusStore>, plexus_core::IngestedManifest) {
    let store = store();
    let ingested = github_manifest();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
        .expect("store reviewed manifest");
    store
        .insert_connection(
            "direct",
            "github-connection",
            "github_rest",
            "active",
            &json!({"write_enabling": ["repo"], "repo": ["cortexkit/aft"]}),
        )
        .expect("insert connection");
    store
        .insert_grant(&plexus_core::GrantInput {
            grant_id: "aft-catalog-test".into(),
            principal: "direct".into(),
            connection_id: "github-connection".into(),
            grantee_principal: plexus_core::github::AFT_PRINCIPAL.into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["*".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .expect("grant cross-principal connection lookup");
    let reconciler = CatalogReconciler::new(
        store.clone(),
        Arc::new(McpRemoteTransport::default()),
        Default::default(),
    );
    reconciler
        .refresh_rest(
            "direct",
            &RestConnection::from_manifest("github-connection", &ingested.manifest),
            &ingested.manifest,
        )
        .expect("seed every action from manifest");
    (store, ingested)
}

struct ReviewedSeams(Arc<PlexusStore>);
impl GovernanceSeams for ReviewedSeams {
    fn resolve_invoke(&self, _: &AuthorizationRequest) -> Result<(), ResolverDenial> {
        Ok(())
    }
    fn facade_only(&self, action: &CatalogAction) -> bool {
        facade_only_from_stored_manifest(&self.0, action)
    }
}

#[test]
fn github_manifest_catalog_classifies_every_routed_action() {
    let (store, ingested) = installed_catalog();
    let writes = [
        "add_reaction",
        "add_issue_comment",
        "update_issue_comment",
        "add_pr_review",
        "close_issue",
        "reopen_issue",
        "create_issue",
        "create_pull_request",
        "edit_issue",
        "add_issue_labels",
        "remove_issue_label",
        "add_issue_assignees",
        "remove_issue_assignees",
        "mark_pull_request_ready",
        "convert_pull_request_to_draft",
    ];
    let reads = [
        "github.issue.get",
        "github.issue_comment.get",
        "github.issue_comments.list",
        "github.issue_timeline.list",
        "github.issue.search",
        "github.pull_request.get",
    ];
    assert_eq!(ingested.manifest.resource_filters.write_enabling, ["repo"]);
    assert_eq!(
        ingested
            .manifest
            .actions_baseline
            .iter()
            .filter(|action| action.facade_only)
            .count(),
        writes.len()
    );
    for name in writes {
        let action = store
            .catalog_action("direct", "github-connection", name)
            .unwrap()
            .expect(name);
        assert!(facade_only_from_stored_manifest(&store, &action), "{name}");
    }
    for name in reads {
        let action = store
            .catalog_action("direct", "github-connection", name)
            .unwrap()
            .expect(name);
        assert!(!facade_only_from_stored_manifest(&store, &action), "{name}");
        assert!(
            !ingested
                .manifest
                .actions_baseline
                .iter()
                .find(|entry| entry.name == name)
                .unwrap()
                .ask_first
        );
        assert!(!action.ask_first, "{name} must not create an approval");
    }
    for action in store
        .list_catalog_actions_all("direct", "github-connection")
        .unwrap()
    {
        assert_ne!(
            action.status, "disabled",
            "{} lost its catalog entry",
            action.name
        );
        assert_eq!(
            action.schema_hash,
            plexus_core::jcs_sha256(&action.schema).unwrap()
        );
    }
    assert_eq!(
        store
            .list_catalog_actions_all("direct", "github-connection")
            .unwrap()
            .len(),
        ingested.manifest.actions_baseline.len()
    );
}

#[test]
fn github_manifest_unknown_action_field_fails_closed() {
    let mut value = github_manifest().json;
    value["actions_baseline"][0]["unexpected"] = json!(true);
    assert!(ingest_value(value).is_err());
}

#[test]
fn explicit_ask_first_cannot_weaken_write_floor() {
    let mut value = github_manifest().json;
    let actions = value["actions_baseline"].as_array_mut().unwrap();
    actions
        .iter_mut()
        .find(|action| action["name"] == "github.issue.get")
        .unwrap()["ask_first"] = json!(true);
    let manifest = ingest_value(value).unwrap();
    assert!(
        manifest
            .manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == "github.issue.get")
            .unwrap()
            .ask_first
    );
    let (store, _) = installed_catalog();
    let reconciler = CatalogReconciler::new(
        store.clone(),
        Arc::new(McpRemoteTransport::default()),
        Default::default(),
    );
    reconciler
        .refresh_rest(
            "direct",
            &RestConnection::from_manifest("github-connection", &manifest.manifest),
            &manifest.manifest,
        )
        .unwrap();
    assert!(
        store
            .catalog_action("direct", "github-connection", "github.issue.get")
            .unwrap()
            .unwrap()
            .ask_first
    );
}

#[test]
fn github_issue_edit_goldens_expose_all_six_mutation_fields() {
    let title_body: Value = serde_json::from_str(include_str!(concat!(
        "../",
        "fixtures/gh_shim_wire/requests/v14-issue-edit-title-body.request.json"
    )))
    .unwrap();
    let labels: Value = serde_json::from_str(include_str!(concat!(
        "../",
        "fixtures/gh_shim_wire/requests/v14-issue-edit-labels.request.json"
    )))
    .unwrap();
    let manifest = github_manifest().manifest;
    let actions: Vec<_> = manifest
        .actions_baseline
        .iter()
        .filter(|action| action.facade_only)
        .map(|action| action.name.as_str())
        .collect();
    assert_eq!(title_body["action"], "issue edit");
    assert_eq!(labels["action"], "issue edit");
    assert_eq!(title_body["author_scope"], "own");
    assert_eq!(labels["author_scope"], "own");
    assert_eq!(title_body["target"]["number"], "42");
    assert_eq!(labels["target"]["number"], "42");
    for (field, action) in [
        ("title", "edit_issue"),
        ("body", "edit_issue"),
        ("add_labels", "add_issue_labels"),
        ("remove_labels", "remove_issue_label"),
        ("add_assignees", "add_issue_assignees"),
        ("remove_assignees", "remove_issue_assignees"),
    ] {
        assert!(actions.contains(&action), "missing {field} leg");
        assert!(
            title_body["body"].get(field).is_some()
                || labels["body"].get(field).is_some()
                || matches!(field, "add_assignees" | "remove_assignees"),
            "golden omitted {field}"
        );
    }
}

#[test]
fn ordinary_invokes_of_each_facade_write_refuse_before_contact_or_reservation() {
    let (store, manifest) = installed_catalog();
    let writes: Vec<_> = manifest
        .manifest
        .actions_baseline
        .iter()
        .filter(|action| action.facade_only)
        .map(|action| action.name.clone())
        .collect();
    let transport = Arc::new(MockTransport::default());
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(StubCredentialSource::default()),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(ReviewedSeams(store.clone())));
    for name in writes {
        for principal in ["direct", plexus_core::github::AFT_PRINCIPAL] {
            for with_assertion in [false, true] {
                let mut request = AuthorizationRequest::new(
                    principal,
                    "github-connection",
                    &name,
                    json!({"repo": "cortexkit/aft"}),
                );
                if with_assertion {
                    request = request.with_bound_agent("agent-a", "handle-a");
                }
                assert_eq!(
                    engine.authorize(request),
                    Err(Denial::BotActionRequiresFacade),
                    "{name} {principal} {with_assertion}"
                );
                assert!(transport.requests().is_empty(), "{name} contacted vendor");
                let rows = store.list_audit("direct").unwrap();
                let row = rows.last().expect("denial audit");
                assert_eq!(row.reason_code, "bot_action_requires_facade");
                assert_eq!(row.agent_id, None);
                assert_eq!(row.agent_handle, None);
            }
        }
    }
    assert!(store.list_action_requests("direct").unwrap().is_empty());
    assert!(store
        .list_action_requests(plexus_core::github::AFT_PRINCIPAL)
        .unwrap()
        .is_empty());
}

#[test]
fn missing_manifest_or_action_is_classified_facade_only() {
    let (store, _) = installed_catalog();
    let mut action = store
        .catalog_action("direct", "github-connection", "github.issue.get")
        .unwrap()
        .unwrap();
    assert!(!facade_only_from_stored_manifest(&store, &action));
    action.name = "not-in-reviewed-manifest".into();
    assert!(facade_only_from_stored_manifest(&store, &action));
    action.name = "github.issue.get".into();
    action.connection_id = "missing-connection".into();
    assert!(facade_only_from_stored_manifest(&store, &action));
    store
        .insert_connection(
            "direct",
            "missing-manifest",
            "unreviewed_app",
            "active",
            &json!({}),
        )
        .unwrap();
    action.connection_id = "missing-manifest".into();
    assert!(facade_only_from_stored_manifest(&store, &action));
}

/// The facade enforces its reaction list because nothing validates the
/// catalog's args_schema on invoke. The shipped catalog and that list must name
/// the same reactions, or one of them is lying about what an agent may place.
#[test]
fn facade_reaction_list_matches_the_shipped_catalog_enum() {
    let manifest = github_manifest().manifest;
    let action = manifest
        .actions_baseline
        .iter()
        .find(|action| action.name == "add_reaction")
        .expect("add_reaction is declared");
    let schema = &action
        .http
        .as_ref()
        .expect("add_reaction is REST")
        .args_schema;
    let declared: std::collections::BTreeSet<&str> = schema["properties"]["content"]["enum"]
        .as_array()
        .expect("content has an enum")
        .iter()
        .map(|value| value.as_str().expect("enum values are strings"))
        .collect();
    let enforced: std::collections::BTreeSet<&str> =
        plexus_core::github::facade::request_map::REACTIONS
            .iter()
            .copied()
            .collect();
    assert_eq!(declared, enforced);
}

/// The facade's pull request allowlist and the shipped create_pull_request
/// schema must name the same fields. Nothing validates the schema at dispatch
/// and the REST transport sends every argument, so a field the facade let
/// through without the catalog declaring it (or the reverse) would go
/// unreviewed. The request below carries every body field GitHub's endpoint
/// accepts, and the mapped arguments must be exactly the declared properties.
#[test]
fn pr_create_allowlist_matches_the_shipped_create_pull_request_schema() {
    use plexus_core::github::facade::request_map;
    use plexus_core::github::resolver::{Binding, ResolvedRepositories};
    let manifest = github_manifest().manifest;
    let action = manifest
        .actions_baseline
        .iter()
        .find(|action| action.name == "create_pull_request")
        .expect("create_pull_request is declared");
    assert!(action.facade_only);
    let http = action.http.as_ref().expect("create_pull_request is REST");
    assert_eq!(http.method, plexus_core::HttpMethod::Post);
    assert_eq!(http.path, "/repos/{owner}/{repo}/pulls");
    let declared: std::collections::BTreeSet<&str> = http.args_schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();

    let request = json!({"action":"pr create","target":{},"repository":"org/repo","body":{
        "title":"t","body":"b","head":"feature","base":"main","draft":true,
        "head_repo":"other/repo","maintainer_can_modify":true,"issue":7}});
    let resolved = ResolvedRepositories {
        repositories: vec!["org/repo".into()],
        binding: Binding {
            app_handle_id: "app".into(),
            connection_id: "conn".into(),
        },
    };
    let mapped = request_map::map(&request, &resolved, "org/repo").unwrap();
    assert_eq!(mapped.action, "create_pull_request");
    let sent: std::collections::BTreeSet<&str> = mapped
        .args
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(sent, declared);
}
