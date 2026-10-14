//! `github.bot_request` authorizes the module that calls it, through the real
//! handle import and the real facade. prefrontal-core sends the eyes reaction
//! that marks an issue as seen; AFT sends everything else. A caller without a
//! module grant on the handle connection is refused before any GitHub contact.
use crate::scope_support::{delegating_scope, LiveScopeReader};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::control::{
    self, AgentPermission, InstallationReader, Inventory, InventoryHandle,
};
use plexus_core::github::credential::HandleCredentialProvider;
use plexus_core::github::facade::{bot_request_scoped, gates, vendor_band};
use plexus_core::github::{AFT_PRINCIPAL, PREFRONTAL_PRINCIPAL};
use plexus_core::governance::GovernanceEngine;
use plexus_core::scope::CallScope;
use plexus_core::storage::github_store::GithubGovernanceSeams;
use plexus_core::transport::MockTransport;
use plexus_core::{ingest_value, PlexusStore, CATALOG_PRINCIPAL};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::sync::Arc;

const AGENT: &str = "agent-fixture";
const HANDLE: &str = "app-fixture";
const CONNECTION: &str = "github-handle-app-fixture";

struct Token;
impl HandleCredentialProvider for Token {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        Ok(ResolvedCredential::new(
            reference.as_bytes().to_vec(),
            None,
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}
/// The installation reachable with the handle's own token.
struct Installation;
impl InstallationReader for Installation {
    fn repositories_page(
        &self,
        _: &ResolvedCredential,
        _: usize,
        _: usize,
    ) -> Result<Value, String> {
        Ok(json!({"repositories":[{"full_name":"org/repo"}]}))
    }
}

// Parse the shipped reviewed catalog rather than hand-writing catalog rows.
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

type Engine = GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>;

struct Fixture {
    _scratch: plexus_core::test_scratch::Scratch,
    store: Arc<PlexusStore>,
    engine: Engine,
    transport: Arc<MockTransport>,
    scope: CallScope,
    path: std::path::PathBuf,
    now: i64,
}

impl Fixture {
    /// Import the stamped agent and its handle with the given agent
    /// writes on org/repo, then prove the handle, both as the operator.
    fn new(label: &str, agent_writes: &[&str]) -> Self {
        let scratch = plexus_core::test_scratch::Scratch::database(label);
        let path = scratch.path().to_path_buf();
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: label.into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &github_manifest())
            .unwrap();
        let inventory = Inventory {
            version: "github-grant-import.v1".into(),
            handles: vec![InventoryHandle {
                app_handle_id: HANDLE.into(),
                agent_id: AGENT.into(),
                app_id: 1,
                installation_id: None,
                credential_id: "github_app:app-fixture".into(),
                status: "enabled".into(),
                grants: agent_writes
                    .iter()
                    .map(|action| AgentPermission {
                        action: (*action).into(),
                        repository: "org/repo".into(),
                        provenance: format!("today-{action}"),
                        policy: "allow".into(),
                    })
                    .collect(),
            }],
        };
        control::import(
            &store,
            "direct",
            &inventory,
            &Token,
            &Installation,
            0,
            false,
        )
        .unwrap();
        control::probe(&store, "direct", HANDLE, &Token, &Installation, 1).unwrap();
        let scope = delegating_scope("agent-fixture");
        let transport = Arc::new(MockTransport::default());
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(
                plexus_core::credentials::StubCredentialSource::with_default_success(
                    b"unused".to_vec(),
                ),
            ),
            transport.clone(),
        )
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(Token)),
        }))
        .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
        Self {
            _scratch: scratch,
            store,
            engine,
            transport,
            scope,
            path,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
        }
    }

    fn call(&self, caller: &str, request: &Value, nonce: &str) -> Value {
        bot_request_scoped(
            &self.store,
            &self.engine,
            caller,
            Some(&self.scope),
            request,
            nonce,
            nonce,
            "worker",
            self.now,
        )
    }

    /// (principal, acting_principal, action, decision, reason_code) for every
    /// audit row written for one request id, in journal order.
    fn audit(&self, request_id: &str) -> Vec<(String, String, String, String, String)> {
        let db = Connection::open(&self.path).unwrap();
        let mut statement = db
            .prepare(
                "SELECT principal, acting_principal, COALESCE(action,''), decision, reason_code
                 FROM audit_journal WHERE request_id=?1 ORDER BY journal_id",
            )
            .unwrap();
        statement
            .query_map([request_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// Audit rows for the governed GitHub action, keyed by the request id the
    /// governance pipeline assigned to that action.
    fn governed_rows(&self, action: &str) -> Vec<(String, String, String)> {
        let db = Connection::open(&self.path).unwrap();
        let mut statement = db
            .prepare(
                "SELECT principal, acting_principal, decision FROM audit_journal
                 WHERE action=?1 ORDER BY journal_id",
            )
            .unwrap();
        statement
            .query_map([action], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn revoke(&self, grant_id: &str) {
        assert!(
            self.store.revoke_grant("direct", grant_id).unwrap(),
            "{grant_id}"
        );
    }
}

fn seen_marker() -> Value {
    json!({"operation":"gh.route","gh_route_schema":1,"action":"issue reaction",
        "target":{"number":"42"},"body":{"reaction":"eyes"},"repository":"org/repo"})
}

fn comment() -> Value {
    json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},
        "body":{"body":"hello"}})
}

fn refused(reply: &Value, code: &str) {
    let mut expected = json!({"status":"refused","refusal_code":code});
    if matches!(code, "module_grant_absent" | "agent_grant_absent") {
        let detail = &reply["result"]["detail"];
        assert_eq!(detail["connection"], CONNECTION);
        assert_eq!(
            detail["layer"],
            if code == "module_grant_absent" {
                "module"
            } else {
                "agent"
            }
        );
        assert!(matches!(
            detail["action"].as_str(),
            Some("add_reaction" | "add_issue_comment")
        ));
        assert!(matches!(
            detail["cause"].as_str(),
            Some("missing" | "action_selector")
        ));
        assert!(
            plexus_core::grant_refusal::GrantTarget::decode(detail["grant"].as_str().unwrap())
                .is_some()
        );
        assert!(!detail["grant_label"].as_str().unwrap().is_empty());
        expected["code"] = json!(code);
        expected["detail"] = detail.clone();
    }
    assert_eq!(reply["result"], expected, "{reply}");
}

#[test]
fn prefrontal_seen_marker_completes_through_import_and_facade() {
    let f = Fixture::new("callers-seen-marker", &["add_reaction"]);
    let reply = f.call(PREFRONTAL_PRINCIPAL, &seen_marker(), "seen");
    assert_eq!(reply["result"]["status"], "completed", "{reply}");
    let requests = f.transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].action, "add_reaction");
    assert_eq!(requests[0].connection_id, CONNECTION);
    assert_eq!(requests[0].args["content"], "eyes");
    assert_eq!(requests[0].args["owner"], "org");
    assert_eq!(requests[0].args["repo"], "repo");
    assert_eq!(requests[0].args["issue_number"], 42);
    // The import's module allow on add_reaction applies to this caller too,
    // so the request never parks for approval.
    assert!(f
        .store
        .list_action_requests(PREFRONTAL_PRINCIPAL)
        .unwrap()
        .is_empty());
    // Both governed audit rows for the reaction (authorization and dispatch)
    // name the module that actually called.
    let governed = f.governed_rows("add_reaction");
    assert_eq!(governed.len(), 2, "{governed:?}");
    for (_, acting, decision) in &governed {
        assert_eq!(acting, PREFRONTAL_PRINCIPAL, "{governed:?}");
        assert_eq!(decision, "allow", "{governed:?}");
    }
    let facade = f.audit("seen");
    let facade = facade
        .iter()
        .find(|row| row.2 == "github.bot_request")
        .unwrap();
    assert_eq!(facade.0, PREFRONTAL_PRINCIPAL);
    assert_eq!(facade.1, PREFRONTAL_PRINCIPAL);
    assert_eq!(facade.4, "allowed");
    let receipt = f.store.github_receipt(AGENT, "seen").unwrap().unwrap();
    assert_eq!(receipt.state, "completed");
    assert_eq!(
        receipt.authority_baseline["caller_principal"],
        PREFRONTAL_PRINCIPAL
    );
}

#[test]
fn prefrontal_comment_refuses_module_grant_absent_without_contact() {
    let f = Fixture::new(
        "callers-prefrontal-comment",
        &["add_reaction", "add_issue_comment"],
    );
    let reply = f.call(PREFRONTAL_PRINCIPAL, &comment(), "comment");
    refused(&reply, "module_grant_absent");
    assert!(f.transport.requests().is_empty());
    // The agent's own grant covers the comment, so AFT may still send it.
    let aft = f.call(AFT_PRINCIPAL, &comment(), "aft-comment");
    assert_eq!(aft["result"]["status"], "completed", "{aft}");
    assert_eq!(f.transport.requests().len(), 1);
}

#[test]
fn callers_without_a_module_grant_refuse_without_contact() {
    let f = Fixture::new("callers-unknown", &["add_reaction"]);
    for (caller, nonce) in [("direct", "direct"), ("reserved:other", "other")] {
        let reply = f.call(caller, &seen_marker(), nonce);
        refused(&reply, "module_grant_absent");
        let facade = f.audit(nonce);
        assert_eq!(facade.len(), 1, "{facade:?}");
        assert_eq!(facade[0].0, caller);
        assert_eq!(facade[0].4, "module_grant_absent");
    }
    assert!(f.transport.requests().is_empty());
}

#[test]
fn agent_granted_other_writes_but_not_the_reaction_refuses_prefrontal_seen_marker() {
    let f = Fixture::new("callers-agent-without-reaction", &["add_issue_comment"]);
    let reply = f.call(PREFRONTAL_PRINCIPAL, &seen_marker(), "seen");
    refused(
        &reply,
        "agent_grant_excludes_request{request_kind: reaction, repository: org/repo}",
    );
    assert!(f.transport.requests().is_empty());
}

// An agent left with no grant on the handle at all: the import binds only
// repositories named by an agent grant, so this revokes the one it imported.
#[test]
fn revoking_the_agent_reaction_grant_stops_prefrontal_seen_marker() {
    let f = Fixture::new("callers-agent-revoked", &["add_reaction"]);
    f.revoke("github-import:app-fixture:agent:0:today-add_reaction");
    let reply = f.call(PREFRONTAL_PRINCIPAL, &seen_marker(), "seen");
    refused(&reply, "agent_grant_absent");
    assert!(f.transport.requests().is_empty());
}

#[test]
fn revoking_prefrontal_module_grant_stops_its_seen_marker_but_not_aft() {
    let f = Fixture::new("callers-module-revoked", &["add_reaction"]);
    f.revoke("github-import:app-fixture:prefrontal");
    let reply = f.call(PREFRONTAL_PRINCIPAL, &seen_marker(), "seen");
    refused(&reply, "module_grant_absent");
    assert!(f.transport.requests().is_empty());
    let aft = f.call(AFT_PRINCIPAL, &seen_marker(), "aft-seen");
    assert_eq!(aft["result"]["status"], "completed", "{aft}");
    assert_eq!(f.transport.requests().len(), 1);
    let governed = f.governed_rows("add_reaction");
    assert!(
        governed
            .iter()
            .all(|(_, acting, _)| acting == AFT_PRINCIPAL),
        "{governed:?}"
    );
}

/// Claim as prefrontal-core, move one grant, then run the vendor band: the
/// receipt's baseline names the moved dimension and nothing is sent.
fn moved_after_claim(grant_id: &str, dimension: &str) {
    let f = Fixture::new("callers-moved-after-claim", &["add_reaction"]);
    let mut reply = gates::run_scoped(
        &*f.store,
        PREFRONTAL_PRINCIPAL,
        Some(&f.scope),
        &seen_marker(),
        "moved",
        "moved",
        "worker",
        f.now,
        120,
    );
    assert!(reply.refusal_code.is_none(), "{reply:?}");
    f.revoke(grant_id);
    let outcome = vendor_band::run(&f.engine, &f.store, &mut reply, "moved", "worker", f.now);
    assert_eq!(
        outcome["refusal_code"],
        format!("stale_authority{{dimension: {dimension}}}"),
        "{outcome}"
    );
    assert!(f.transport.requests().is_empty());
}

#[test]
fn agent_grant_revoked_after_prefrontal_claim_is_stale_authority() {
    moved_after_claim(
        "github-import:app-fixture:agent:0:today-add_reaction",
        "agent_grant_revoked",
    );
}

#[test]
fn prefrontal_module_grant_revoked_after_claim_is_stale_authority() {
    moved_after_claim(
        "github-import:app-fixture:prefrontal",
        "module_grant_revoked",
    );
}

#[test]
fn import_grants_prefrontal_only_its_reads_and_the_reaction() {
    let f = Fixture::new(
        "callers-import-selectors",
        &["add_reaction", "add_issue_comment"],
    );
    let grants = f.store.list_grants("direct", CONNECTION).unwrap();
    let prefrontal: Vec<_> = grants
        .iter()
        .filter(|row| row.grantee_principal == PREFRONTAL_PRINCIPAL)
        .collect();
    assert_eq!(prefrontal.len(), 1);
    let mut selectors = prefrontal[0].action_selectors.clone();
    selectors.sort();
    assert_eq!(
        selectors,
        [
            "add_reaction",
            "github.issue.get",
            "github.issue.search",
            "github.issue_comments.list"
        ]
    );
}
