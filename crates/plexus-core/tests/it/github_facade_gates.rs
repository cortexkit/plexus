use crate::scope_support::{delegating_scope, LiveScopeReader};
use plexus_core::github::facade::gates::{self, Authority, GateStore, Handle};
use plexus_core::github::facade::request_map::{self, MappedRequest};
use plexus_core::github::receipt::{Claim, Effect, Receipt};
use plexus_core::github::resolver::Binding;
use plexus_core::scope::CallScope;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn test_engine(
    store: Arc<plexus_core::PlexusStore>,
) -> plexus_core::governance::GovernanceEngine<
    plexus_core::credentials::StubCredentialSource,
    plexus_core::transport::MockTransport,
> {
    plexus_core::governance::GovernanceEngine::new(
        store,
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(
                b"fixture".to_vec(),
            ),
        ),
        Arc::new(plexus_core::transport::MockTransport::default()),
    )
    .with_scope_reader(Arc::new(LiveScopeReader(delegating_scope("agent-fixture"))))
}

fn request() -> Value {
    json!({"action":"issue comment","repository":"org/repo","target":{"number":"42"},"body":{"body":"hello"}})
}
fn row() -> Handle {
    Handle {
        app_handle_id: "app-fixture".into(),
        agent_id: "agent-fixture".into(),
        connection_id: "conn-fixture".into(),
        connection_principal: "operator".into(),
        credential_reference: "github_app:app-fixture".into(),
        status: "enabled".into(),
        proven: true,
    }
}
fn authority() -> Authority {
    Authority {
        module_grant: true,
        agent_grant: true,
        pair_allowed: true,
        module_effect: "allow".into(),
        agent_effect: None,
        baseline: json!({"generation":1}),
    }
}
#[derive(Default)]
struct Contacts {
    credential: usize,
    repository: usize,
    secret_reads: usize,
}
struct Store {
    binding_lookups: Mutex<usize>,
    fail_binding_on: Option<usize>,
    handle: Option<Handle>,
    bound: Option<(Binding, String)>,
    authority: Authority,
    receipt_error: bool,
    receipt: Option<Receipt>,
    contacts: Mutex<Contacts>,
    claims: Mutex<usize>,
    /// Every id G2 asked the store to resolve, in order.
    handle_lookups: Mutex<Vec<String>>,
}
impl Store {
    fn good() -> Self {
        Self {
            binding_lookups: Mutex::new(0),
            fail_binding_on: None,
            handle: Some(row()),
            bound: Some((
                Binding {
                    app_handle_id: "app-fixture".into(),
                    connection_id: "conn-fixture".into(),
                },
                "agent-fixture".into(),
            )),
            authority: authority(),
            receipt_error: false,
            receipt: None,
            contacts: Mutex::new(Contacts::default()),
            claims: Mutex::new(0),
            handle_lookups: Mutex::new(Vec::new()),
        }
    }
    fn no_contact(&self) {
        let c = self.contacts.lock().unwrap();
        assert_eq!(c.credential, 0, "credential transport bucket");
        assert_eq!(c.repository, 0, "repository API transport bucket");
        assert_eq!(c.secret_reads, 0, "claustrum secret reads");
    }
}
impl GateStore for Store {
    fn handle(&self, id: &str) -> Result<Option<Handle>, String> {
        self.handle_lookups.lock().unwrap().push(id.into());
        Ok(self.handle.clone())
    }
    fn handle_for_agent(&self, agent: &str) -> Result<Option<Handle>, String> {
        self.handle_lookups
            .lock()
            .unwrap()
            .push(format!("agent:{agent}"));
        Ok(self
            .handle
            .clone()
            .filter(|handle| handle.agent_id == agent))
    }
    fn binding(&self, _: &str) -> Result<Option<(Binding, String)>, String> {
        let mut calls = self.binding_lookups.lock().unwrap();
        *calls += 1;
        if self.fail_binding_on == Some(*calls) {
            return Err("store_failure".into());
        }
        Ok(self.bound.clone())
    }
    fn authority(
        &self,
        _: &Handle,
        caller: &str,
        _: &str,
        _: &MappedRequest,
        _: &str,
    ) -> Result<Authority, String> {
        // Only AFT holds a module grant on this fixture's handle: any other
        // caller, `direct` included, gets module_grant=false and is refused.
        let mut authority = self.authority.clone();
        authority.module_grant &= caller == plexus_core::github::AFT_PRINCIPAL;
        Ok(authority)
    }
    fn receipt(&self, _: &str, _: &str) -> Result<Option<Receipt>, String> {
        if self.receipt_error {
            return Err("store_failure".into());
        }
        Ok(self.receipt.clone())
    }
    fn claim(
        &self,
        agent: &str,
        nonce: &str,
        mapped: &MappedRequest,
        _: &Handle,
        owner: &str,
        baseline: &Value,
        effects: &[Effect],
        ask_first: bool,
        _: i64,
        _: i64,
    ) -> Result<Claim, String> {
        *self.claims.lock().unwrap() += 1;
        Ok(Claim::Owned(Receipt {
            agent_id: agent.into(),
            request_nonce: nonce.into(),
            request_fingerprint: mapped.fingerprint.clone(),
            state: if ask_first {
                "pending_approval"
            } else {
                "pending"
            }
            .into(),
            claim_owner: Some(owner.into()),
            claim_lease_expires_at: Some(10_000),
            authority_baseline: baseline.clone(),
            effects: effects.into(),
            action_request_id: None,
            outcome: None,
            refusal_code: None,
            created_at: 1,
            updated_at: 1,
        }))
    }
}
fn run(store: &Store, scope: Option<&CallScope>, request: &Value) -> gates::GateReply {
    gates::run_scoped(
        store,
        plexus_core::github::AFT_PRINCIPAL,
        scope,
        request,
        "nonce",
        "request-id",
        "worker",
        1,
        120,
    )
}
fn refused(reply: gates::GateReply, gate: &str, code: &str, handle: Option<&str>) {
    assert_eq!(reply.gate, gate);
    assert_eq!(reply.refusal_code.as_deref(), Some(code));
    assert_eq!(reply.app_handle_id.as_deref(), handle);
    assert_eq!(reply.action, "github.bot_request");
    assert_eq!(reply.request_id, "request-id");
}
#[test]
fn g1_requires_an_authorized_delegating_scope_before_lookup_or_claim() {
    let mut non_delegating = delegating_scope("agent-fixture");
    non_delegating.delegates = false;
    let mut unauthorized = delegating_scope("agent-fixture");
    unauthorized.owner_authorized = false;
    let mut unnamed = delegating_scope("agent-fixture");
    unnamed.agent_id = None;
    for scope in [
        None,
        Some(&non_delegating),
        Some(&unauthorized),
        Some(&unnamed),
    ] {
        let store = Store::good();
        let reply = run(&store, scope, &request());
        refused(reply, "G1", "delegating_scope_required", None);
        store.no_contact();
        assert!(store.handle_lookups.lock().unwrap().is_empty());
        assert_eq!(*store.claims.lock().unwrap(), 0);
    }
}
#[test]
fn g2_bot_binding_and_repository_belong_to_stamped_agent() {
    let scope = delegating_scope("agent-fixture");
    let mut store = Store::good();
    store.handle = None;
    refused(
        run(&store, Some(&scope), &request()),
        "G2",
        "agent_handle_unknown",
        None,
    );
    store.handle = Some(Handle {
        agent_id: "other-agent".into(),
        ..row()
    });
    refused(
        run(&store, Some(&scope), &request()),
        "G2",
        "agent_handle_unknown",
        None,
    );
    store.handle = Some(row());
    store.bound = None;
    refused(
        run(&store, Some(&scope), &request()),
        "G2",
        "repository_unbound",
        Some("app-fixture"),
    );
    store.bound = Some((
        Binding {
            app_handle_id: "other-handle".into(),
            connection_id: "other-conn".into(),
        },
        "other-agent".into(),
    ));
    refused(
        run(&store, Some(&scope), &request()),
        "G2",
        "agent_repository_conflict{claimed_agent: agent-fixture, bound_agent: other-agent}",
        Some("app-fixture"),
    );
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g2_stamp_resolves_its_agents_bound_bot_and_reaches_the_claim() {
    let scope = delegating_scope("agent-fixture");
    let store = Store::good();
    let reply = run(&store, Some(&scope), &request());
    assert_eq!(reply.gate, "G7");
    assert!(reply.refusal_code.is_none(), "{:?}", reply.refusal_code);
    assert_eq!(reply.app_handle_id.as_deref(), Some("app-fixture"));
    assert_eq!(
        *store.handle_lookups.lock().unwrap(),
        ["agent:agent-fixture"]
    );
    assert_eq!(*store.claims.lock().unwrap(), 1);
}
#[test]
fn g2_a_stamp_for_an_agent_without_a_bot_refuses_without_contact() {
    let scope = delegating_scope("unknown-agent");
    let store = Store::good();
    let reply = run(&store, Some(&scope), &request());
    refused(reply, "G2", "agent_handle_unknown", None);
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g2_handle_whose_credential_is_another_app_refuses_unknown() {
    let scope = delegating_scope("agent-fixture");
    let mut store = Store::good();
    store.handle = Some(Handle {
        credential_reference: "github_app:other-app".into(),
        ..row()
    });
    let reply = run(&store, Some(&scope), &request());
    refused(reply.clone(), "G2", "agent_handle_unknown", None);
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g3_kind_and_fields_are_closed_before_receipt_claim() {
    let scope = delegating_scope("agent-fixture");
    let store = Store::good();
    for (request, code) in [
        (
            json!({"repository":"org/repo", "action":"unknown"}),
            "request_kind_unmapped",
        ),
        (
            json!({"repository":"org/repo", "verb":"issue close", "body":"bad"}),
            "request_field_forbidden{field: body}",
        ),
        (
            json!({"repository":"org/repo", "verb":"issue close", "title":"bad"}),
            "request_field_forbidden{field: title}",
        ),
        (
            json!({"repository":"org/repo", "action":"issue comment", "target_repository":"other/repo"}),
            "request_field_forbidden{field: target_repository}",
        ),
    ] {
        refused(
            run(&store, Some(&scope), &request),
            "G3",
            code,
            Some("app-fixture"),
        );
    }
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g4_terminal_replay_outweighs_disabled_handle_and_live_lease_refuses() {
    let scope = delegating_scope("agent-fixture");
    let mut store = Store::good();
    let mapped = request_map::map(
        &request(),
        &plexus_core::github::resolver::ResolvedRepositories {
            repositories: vec!["org/repo".into()],
            binding: store.bound.as_ref().unwrap().0.clone(),
        },
        "org/repo",
    )
    .unwrap();
    store.receipt = Some(Receipt {
        agent_id: "agent-fixture".into(),
        request_nonce: "nonce".into(),
        request_fingerprint: mapped.fingerprint.clone(),
        state: "completed".into(),
        claim_owner: None,
        claim_lease_expires_at: None,
        authority_baseline: json!({}),
        effects: vec![],
        action_request_id: None,
        outcome: Some(json!({"status":"completed"})),
        refusal_code: None,
        created_at: 0,
        updated_at: 0,
    });
    store.handle.as_mut().unwrap().status = "disabled".into();
    assert!(matches!(
        run(&store, Some(&scope), &request()).claim,
        Some(Claim::Replay(_))
    ));
    store.receipt.as_mut().unwrap().request_fingerprint = "different".into();
    refused(
        run(&store, Some(&scope), &request()),
        "G4",
        "nonce_payload_mismatch",
        Some("app-fixture"),
    );
    store.receipt.as_mut().unwrap().request_fingerprint = mapped.fingerprint;
    store.receipt.as_mut().unwrap().state = "pending".into();
    store.receipt.as_mut().unwrap().claim_lease_expires_at = Some(10_000);
    refused(
        run(&store, Some(&scope), &request()),
        "G4",
        "nonce_in_flight",
        Some("app-fixture"),
    );
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g5_handle_state_precedes_authorization() {
    let scope = delegating_scope("agent-fixture");
    let mut store = Store::good();
    store.handle.as_mut().unwrap().status = "disabled".into();
    refused(
        run(&store, Some(&scope), &request()),
        "G5",
        "handle_disabled",
        Some("app-fixture"),
    );
    store.handle.as_mut().unwrap().status = "enabled".into();
    store.handle.as_mut().unwrap().proven = false;
    refused(
        run(&store, Some(&scope), &request()),
        "G5",
        "probe_unproven",
        Some("app-fixture"),
    );
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g6_grants_and_policy_refuse_in_fixed_order() {
    let scope = delegating_scope("agent-fixture");
    let mut store = Store::good();
    store.authority.module_grant = false;
    refused(
        run(&store, Some(&scope), &request()),
        "G6",
        "module_grant_absent",
        Some("app-fixture"),
    );
    store.authority.module_grant = true;
    store.authority.agent_grant = false;
    refused(
        run(&store, Some(&scope), &request()),
        "G6",
        "agent_grant_absent",
        Some("app-fixture"),
    );
    store.authority.agent_grant = true;
    store.authority.pair_allowed = false;
    refused(
        run(&store, Some(&scope), &request()),
        "G6",
        "agent_grant_excludes_request{request_kind: comment, repository: org/repo}",
        Some("app-fixture"),
    );
    store.authority.pair_allowed = true;
    store.authority.module_effect = "block".into();
    refused(
        run(&store, Some(&scope), &request()),
        "G6",
        "policy_blocked{source: module}",
        Some("app-fixture"),
    );
    store.authority.module_effect = "allow".into();
    store.authority.agent_effect = Some("block".into());
    refused(
        run(&store, Some(&scope), &request()),
        "G6",
        "policy_blocked{source: agent}",
        Some("app-fixture"),
    );
    store.authority.agent_effect = None;
    refused(
        gates::run_scoped(
            &store,
            "direct",
            Some(&scope),
            &request(),
            "direct-nonce",
            "request-id",
            "worker",
            1,
            120,
        ),
        "G6",
        "module_grant_absent",
        Some("app-fixture"),
    );
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 0);
}
#[test]
fn g7_claim_receives_canonical_fingerprint_and_baseline_without_contact() {
    let scope = delegating_scope("agent-fixture");
    let store = Store::good();
    let reply = run(&store, Some(&scope), &request());
    assert_eq!(reply.gate, "G7");
    assert!(reply.refusal_code.is_none());
    let Claim::Owned(row) = reply.claim.unwrap() else {
        panic!("not claimed")
    };
    assert_eq!(row.authority_baseline, json!({"generation":1}));
    assert_eq!(row.request_fingerprint, reply.mapped.unwrap().fingerprint);
    assert_eq!(row.claim_owner.as_deref(), Some("worker"));
    store.no_contact();
    assert_eq!(*store.claims.lock().unwrap(), 1);
}

#[test]
fn g7_store_claims_one_approval_atomically_and_preserves_other_agents_approval() {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::storage::github_store::GithubHandle;
    use plexus_core::PlexusStore;
    use rusqlite::{params, Connection};
    let scratch = plexus_core::test_scratch::Scratch::database("facade-approval");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "facade-approval".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(PlexusStore::open(&descriptor).unwrap());
    store
        .insert_connection(
            "operator",
            "conn-fixture",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-fixture".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-fixture".into(),
        })
        .unwrap();
    store.bind_github_repo("org/repo", "app-fixture").unwrap();
    let db = Connection::open(scratch.path()).unwrap();
    db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
        VALUES ('conn-fixture','operator','add_issue_comment','{}','schema','write','S1','active',1,1,1)",[]).unwrap();
    for (grant, agent) in [("module", None), ("agent", Some("agent-fixture"))] {
        db.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,
            authority_kind,created_at_ms,action_selectors,agent_id)
            VALUES (?1,'operator','conn-fixture','reserved:aft','write','invoke',1,'[\"add_issue_comment\"]',?2)",
            params![grant,agent]).unwrap();
    }
    let scope = delegating_scope("agent-fixture");
    let first = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "nonce",
        "id",
        "first",
        1,
        120,
    );
    let Claim::PendingApproval(first) = first.claim.unwrap() else {
        panic!("missing approval")
    };
    let approval = first.action_request_id.unwrap();
    assert_eq!(first.state, "pending_approval");
    let second = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "nonce",
        "id",
        "second",
        2,
        120,
    );
    let Claim::PendingApproval(second) = second.claim.unwrap() else {
        panic!("retry created a claim")
    };
    assert_eq!(second.action_request_id.as_deref(), Some(approval.as_str()));
    let count: i64 = db
        .query_row("SELECT count(*) FROM action_requests", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    db.execute(
        "UPDATE action_requests SET status='approved' WHERE request_id=?1",
        [&approval],
    )
    .unwrap();
    let approved = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "nonce",
        "id",
        "third",
        3,
        120,
    );
    let Claim::Owned(approved) = approved.claim.unwrap() else {
        panic!("approved retry did not take ownership")
    };
    assert_eq!(approved.claim_owner.as_deref(), Some("third"));
    assert_eq!(approved.authority_baseline["repo_binding_generation"], 1);
    assert_eq!(approved.request_fingerprint, first.request_fingerprint);
    let in_flight = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "nonce",
        "id",
        "fourth",
        4,
        120,
    );
    assert_eq!(in_flight.refusal_code.as_deref(), Some("nonce_in_flight"));
    let mapped = request_map::map(
        &request(),
        &plexus_core::github::resolver::ResolvedRepositories {
            repositories: vec!["org/repo".into()],
            binding: Binding {
                app_handle_id: "app-fixture".into(),
                connection_id: "conn-fixture".into(),
            },
        },
        "org/repo",
    )
    .unwrap();
    let foreign = Handle {
        agent_id: "agent-other".into(),
        ..row()
    };
    let collision = store
        .claim_github_facade(
            "agent-other",
            "different-nonce",
            &mapped,
            &foreign,
            "other",
            &json!({}),
            &[],
            true,
            5,
            120,
        )
        .unwrap();
    let Claim::Replay(collision) = collision else {
        panic!("foreign approval was adopted")
    };
    assert_eq!(
        collision.refusal_code.as_deref(),
        Some("approval_agent_mismatch")
    );
    assert_eq!(collision.action_request_id, None);
    let status: String = db
        .query_row(
            "SELECT status FROM action_requests WHERE request_id=?1",
            [approval],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "approved");
    let changed = json!({"action":"issue comment", "repository":"org/repo",
        "target":{"number":"42"}, "body":{"body":"different speech"}});
    let race = request_map::map(
        &changed,
        &plexus_core::github::resolver::ResolvedRepositories {
            repositories: vec!["org/repo".into()],
            binding: Binding {
                app_handle_id: "app-fixture".into(),
                connection_id: "conn-fixture".into(),
            },
        },
        "org/repo",
    )
    .unwrap();
    let workers: Vec<_> = (0..2)
        .map(|i| {
            let store = Arc::clone(&store);
            let race = race.clone();
            std::thread::spawn(move || {
                store
                    .claim_github_facade(
                        "agent-fixture",
                        "race-nonce",
                        &race,
                        &row(),
                        &format!("worker-{i}"),
                        &json!({"generation":2}),
                        &[],
                        true,
                        6,
                        120,
                    )
                    .unwrap()
            })
        })
        .collect();
    let approvals: Vec<_> = workers
        .into_iter()
        .map(|worker| match worker.join().unwrap() {
            Claim::PendingApproval(receipt) => receipt.action_request_id.unwrap(),
            other => panic!("concurrent first claim did not share approval: {other:?}"),
        })
        .collect();
    assert_eq!(approvals[0], approvals[1]);
    assert_eq!(
        db.query_row("SELECT count(*) FROM action_requests", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    db.execute(
        "UPDATE action_requests SET status='denied' WHERE request_id=?1",
        [&approvals[0]],
    )
    .unwrap();
    let denied = store
        .claim_github_facade(
            "agent-fixture",
            "race-nonce",
            &race,
            &row(),
            "retry",
            &json!({"generation":3}),
            &[],
            true,
            7,
            120,
        )
        .unwrap();
    let Claim::Replay(denied) = denied else {
        panic!("denial not terminal")
    };
    assert_eq!(denied.refusal_code.as_deref(), Some("approval_denied"));
    assert_eq!(denied.request_fingerprint, race.fingerprint);
    let expiring = request_map::map(
        &json!({"action":"issue comment", "repository":"org/repo",
        "target":{"number":"42"}, "body":{"body":"expiring speech"}}),
        &plexus_core::github::resolver::ResolvedRepositories {
            repositories: vec!["org/repo".into()],
            binding: Binding {
                app_handle_id: "app-fixture".into(),
                connection_id: "conn-fixture".into(),
            },
        },
        "org/repo",
    )
    .unwrap();
    let Claim::PendingApproval(pending) = store
        .claim_github_facade(
            "agent-fixture",
            "expiry-nonce",
            &expiring,
            &row(),
            "first",
            &json!({}),
            &[],
            true,
            7,
            120,
        )
        .unwrap()
    else {
        panic!("expected pending approval")
    };
    db.execute(
        "UPDATE action_requests SET expires_at=8 WHERE request_id=?1",
        [pending.action_request_id.unwrap()],
    )
    .unwrap();
    let Claim::Replay(expired) = store
        .claim_github_facade(
            "agent-fixture",
            "expiry-nonce",
            &expiring,
            &row(),
            "retry",
            &json!({}),
            &[],
            true,
            8,
            120,
        )
        .unwrap()
    else {
        panic!("expired approval not terminal")
    };
    assert_eq!(expired.refusal_code.as_deref(), Some("approval_expired"));
    assert_eq!(expired.request_fingerprint, expiring.fingerprint);
    db.execute(
        "UPDATE grants SET action_selectors='[]' WHERE grant_id='agent'",
        [],
    )
    .unwrap();
    let excluded = gates::run_scoped(
        store.as_ref(),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "excluded-nonce",
        "excluded-request",
        "worker",
        6,
        120,
    );
    assert_eq!(
        excluded.refusal_code.as_deref(),
        Some("agent_grant_excludes_request{request_kind: comment, repository: org/repo}")
    );
    assert_eq!(
        store
            .github_receipt("agent-fixture", "excluded-nonce")
            .unwrap(),
        None
    );
    db.execute(
        "UPDATE grants SET action_selectors='[\"add_issue_comment\"]' WHERE grant_id='agent'",
        [],
    )
    .unwrap();
    let response = plexus_core::github::facade::bot_request_scoped(
        store.as_ref(),
        &test_engine(store.clone()),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "facade-nonce",
        "facade-request",
        "worker",
        6,
    );
    assert_eq!(response["repo_binding_generation"], 1);
    let rows = store
        .list_audit(plexus_core::github::AFT_PRINCIPAL)
        .unwrap();
    let row = rows.last().unwrap();
    assert_eq!(row.agent_id.as_deref(), Some("agent-fixture"));
    assert_eq!(row.app_handle_id.as_deref(), Some("app-fixture"));
    assert_eq!(row.action.as_deref(), Some("github.bot_request"));
    assert_eq!(row.request_id.as_deref(), Some("facade-request"));
    assert_eq!(row.reason_code, "allowed");
    let absent = plexus_core::github::facade::bot_request_scoped(
        store.as_ref(),
        &test_engine(store.clone()),
        plexus_core::github::AFT_PRINCIPAL,
        None,
        &request(),
        "absent",
        "absent-request",
        "worker",
        7,
    );
    assert_eq!(
        absent["result"]["refusal_code"],
        "delegating_scope_required"
    );
    assert_eq!(absent["repo_binding_generation"], 1);
    let rows = store
        .list_audit(plexus_core::github::AFT_PRINCIPAL)
        .unwrap();
    let row = rows.last().unwrap();
    assert_eq!(row.agent_id, None);
    assert_eq!(row.app_handle_id, None);
    assert_eq!(row.reason_code, "delegating_scope_required");
}

/// An approval the facade raises names the module that carried the request
/// as its requester. A nonce whose receipt has aged out of retention can be
/// sent again: the new request gets a new approval rather than colliding with
/// the earlier approval row, which is kept.
#[test]
fn g7_approval_names_its_carrier_and_a_reused_nonce_gets_a_fresh_one() {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::storage::github_store::GithubHandle;
    use plexus_core::PlexusStore;
    use rusqlite::{params, Connection};
    let carrier = plexus_core::github::PREFRONTAL_PRINCIPAL;
    let scratch = plexus_core::test_scratch::Scratch::database("facade-approval-reuse");
    let store = Arc::new(
        PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "facade-approval-reuse".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        })
        .unwrap(),
    );
    store
        .insert_connection(
            "operator",
            "conn-fixture",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-fixture".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-fixture".into(),
        })
        .unwrap();
    store.bind_github_repo("org/repo", "app-fixture").unwrap();
    let db = Connection::open(scratch.path()).unwrap();
    db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
        VALUES ('conn-fixture','operator','add_issue_comment','{}','schema','write','S1','active',1,1,1)",[]).unwrap();
    for (grant, grantee, agent) in [
        ("module", carrier, None),
        (
            "agent",
            plexus_core::github::AFT_PRINCIPAL,
            Some("agent-fixture"),
        ),
    ] {
        db.execute("INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,
            authority_kind,created_at_ms,action_selectors,agent_id)
            VALUES (?1,'operator','conn-fixture',?2,'write','invoke',1,'[\"add_issue_comment\"]',?3)",
            params![grant, grantee, agent]).unwrap();
    }
    let scope = delegating_scope("agent-fixture");
    let claim = |now: i64| {
        gates::run_scoped(
            store.as_ref(),
            carrier,
            Some(&scope),
            &request(),
            "reused-nonce",
            "id",
            "worker",
            now,
            120,
        )
        .claim
    };
    let Some(Claim::PendingApproval(first)) = claim(1) else {
        panic!("missing approval")
    };
    let first_approval = first.action_request_id.unwrap();
    let requester: String = db
        .query_row(
            "SELECT requester FROM action_requests WHERE request_id=?1",
            [&first_approval],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        requester, carrier,
        "the approval must name the carrying module"
    );
    // The approval lapses unanswered, which refuses the receipt; retention
    // then removes the refused receipt but keeps the approval row.
    db.execute(
        "UPDATE action_requests SET expires_at=2 WHERE request_id=?1",
        [&first_approval],
    )
    .unwrap();
    let Some(Claim::Replay(expired)) = claim(3) else {
        panic!("lapsed approval did not refuse")
    };
    assert_eq!(expired.refusal_code.as_deref(), Some("approval_expired"));
    let purge_at = 3 + plexus_core::github::receipt::RETENTION_MS;
    store.sweep_github_receipts(purge_at, 100).unwrap();
    assert!(store
        .github_receipt("agent-fixture", "reused-nonce")
        .unwrap()
        .is_none());
    let Some(Claim::PendingApproval(again)) = claim(purge_at + 1) else {
        panic!("the reused nonce did not raise a new approval")
    };
    let second_approval = again.action_request_id.unwrap();
    assert_ne!(second_approval, first_approval);
    let count: i64 = db
        .query_row("SELECT count(*) FROM action_requests", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn g3_shim_request_kinds_map_to_one_write_and_fixed_reads() {
    let fixtures = [
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v1-issue-comment.request.json"
            )),
            "add_issue_comment",
            &[][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v1-pr-comment.request.json"
            )),
            "add_issue_comment",
            &[][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v1-pr-review.request.json"
            )),
            "add_pr_review",
            &[][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v1-issue-reaction.request.json"
            )),
            "add_reaction",
            &[][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v10-issue-comment-edit-last.request.json"
            )),
            "update_issue_comment",
            &["github.issue_comments.list", "github.issue_comment.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v10-pr-comment-edit-last.request.json"
            )),
            "update_issue_comment",
            &["github.issue_comments.list", "github.issue_comment.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v12-issue-close.request.json"
            )),
            "close_issue",
            &["github.issue.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v12-issue-reopen.request.json"
            )),
            "reopen_issue",
            &["github.issue.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v12-pr-close.request.json"
            )),
            "close_issue",
            &["github.issue.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v12-pr-reopen.request.json"
            )),
            "reopen_issue",
            &["github.issue.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v14-api-patch-issue-comment.request.json"
            )),
            "update_issue_comment",
            &["github.issue_comment.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v14-issue-create.request.json"
            )),
            "create_issue",
            &[][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v14-issue-edit-title-body.request.json"
            )),
            "edit_issue",
            &["github.issue.get"][..],
        ),
        (
            include_str!(concat!(
                "../",
                "fixtures/gh_shim_wire/requests/v14-issue-edit-labels.request.json"
            )),
            "edit_issue",
            &["github.issue.get"][..],
        ),
    ];
    let resolved = plexus_core::github::resolver::ResolvedRepositories {
        repositories: vec!["cortexkit/aft".into()],
        binding: Binding {
            app_handle_id: "app-fixture".into(),
            connection_id: "conn-fixture".into(),
        },
    };
    for (contents, action, reads) in fixtures {
        let request: Value = serde_json::from_str(contents).unwrap();
        let mapped = request_map::map(&request, &resolved, "cortexkit/aft").unwrap();
        assert_eq!(mapped.action, action, "{request}");
        assert_eq!(mapped.reads, reads, "{request}");
        assert_eq!(mapped.args["owner"], "cortexkit");
        assert_eq!(mapped.args["repo"], "aft");
        assert!(mapped.args.get("metadata").is_none());
        let mut retry = request.clone();
        retry["rung_as_of_unix_secs"] = json!(1);
        retry["request_nonce"] = json!("new-nonce");
        retry["approved_request_id"] = json!("approved");
        assert_eq!(
            request_map::map(&retry, &resolved, "cortexkit/aft")
                .unwrap()
                .fingerprint,
            mapped.fingerprint
        );
    }
}

fn real_gate_store(
    label: &str,
    status: &str,
) -> (
    plexus_core::test_scratch::Scratch,
    Arc<plexus_core::PlexusStore>,
) {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::storage::github_store::GithubHandle;
    let scratch = plexus_core::test_scratch::Scratch::database(label);
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: label.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let store = Arc::new(plexus_core::PlexusStore::open(&descriptor).unwrap());
    store
        .insert_connection(
            "operator",
            "conn-fixture",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-fixture".into(),
            agent_id: "agent-fixture".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:app-fixture".into(),
            credential_generation: 1,
            status: status.into(),
            proven_at: Some(1),
            connection_principal: "operator".into(),
            connection_id: "conn-fixture".into(),
        })
        .unwrap();
    store.bind_github_repo("org/repo", "app-fixture").unwrap();
    (scratch, store)
}

#[test]
fn g5_refusal_audit_records_resolved_handle_and_g1_records_null() {
    let (_scratch, store) = real_gate_store("facade-audit-handle", "disabled");
    let scope = delegating_scope("agent-fixture");
    let refused = plexus_core::github::facade::bot_request_scoped(
        &store,
        &test_engine(store.clone()),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "disabled-nonce",
        "disabled-id",
        "worker",
        1,
    );
    assert_eq!(refused["result"]["refusal_code"], "handle_disabled");
    let absent = plexus_core::github::facade::bot_request_scoped(
        &store,
        &test_engine(store.clone()),
        plexus_core::github::AFT_PRINCIPAL,
        None,
        &request(),
        "absent-nonce",
        "absent-id",
        "worker",
        1,
    );
    assert_eq!(
        absent["result"]["refusal_code"],
        "delegating_scope_required"
    );
    let audit = store
        .list_audit(plexus_core::github::AFT_PRINCIPAL)
        .unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].gate.as_deref(), Some("G5"));
    assert_eq!(audit[0].app_handle_id.as_deref(), Some("app-fixture"));
    assert_eq!(audit[0].agent_id.as_deref(), Some("agent-fixture"));
    assert_eq!(audit[1].gate.as_deref(), Some("G1"));
    assert_eq!(audit[1].app_handle_id, None);
    assert_eq!(audit[1].agent_id, None);
    assert!(store
        .github_receipt("agent-fixture", "disabled-nonce")
        .unwrap()
        .is_none());
}

#[test]
fn g6_real_agent_selector_exclusion_does_not_use_module_grant_as_substitute() {
    use rusqlite::{params, Connection};
    let (scratch, store) = real_gate_store("facade-agent-selector", "enabled");
    let db = Connection::open(scratch.path()).unwrap();
    db.execute("INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
        VALUES ('conn-fixture','operator','add_issue_comment','{}','schema','write','S1','active',1,1,0)", []).unwrap();
    for (id, agent, selectors) in [
        ("module", None, "[\"add_issue_comment\"]"),
        ("agent", Some("agent-fixture"), "[\"add_reaction\"]"),
    ] {
        db.execute(
            "INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,
            risk_ceiling,authority_kind,created_at_ms,action_selectors,agent_id)
            VALUES (?1,'operator','conn-fixture','reserved:aft','write','invoke',1,?2,?3)",
            params![id, selectors, agent],
        )
        .unwrap();
    }
    let scope = delegating_scope("agent-fixture");
    let result = plexus_core::github::facade::bot_request_scoped(
        &store,
        &test_engine(store.clone()),
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &request(),
        "excluded-nonce",
        "excluded-id",
        "worker",
        1,
    );
    assert_eq!(
        result["result"]["refusal_code"],
        "agent_grant_excludes_request{request_kind: comment, repository: org/repo}"
    );
    assert!(store
        .github_receipt("agent-fixture", "excluded-nonce")
        .unwrap()
        .is_none());
    let audit = store
        .list_audit(plexus_core::github::AFT_PRINCIPAL)
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].gate.as_deref(), Some("G6"));
    assert_eq!(audit[0].app_handle_id.as_deref(), Some("app-fixture"));
}

#[test]
fn receipt_fingerprint_refuses_distinct_large_integers() {
    let scope = delegating_scope("agent-fixture");
    let mut store = Store::good();
    let mut original = request();
    original["n"] = json!(9007199254740992_u64);
    let mut changed = original.clone();
    changed["n"] = json!(9007199254740993_u64);
    let resolved = plexus_core::github::resolver::ResolvedRepositories {
        repositories: vec!["org/repo".into()],
        binding: store.bound.as_ref().unwrap().0.clone(),
    };
    let mapped = request_map::map(&original, &resolved, "org/repo").unwrap();
    assert_ne!(
        mapped.fingerprint,
        request_map::map(&changed, &resolved, "org/repo")
            .unwrap()
            .fingerprint
    );
    store.receipt = Some(Receipt {
        agent_id: "agent-fixture".into(),
        request_nonce: "nonce".into(),
        request_fingerprint: mapped.fingerprint,
        state: "completed".into(),
        claim_owner: None,
        claim_lease_expires_at: None,
        authority_baseline: json!({}),
        effects: vec![],
        action_request_id: None,
        outcome: Some(json!({"status":"completed"})),
        refusal_code: None,
        created_at: 0,
        updated_at: 0,
    });
    assert!(matches!(
        run(&store, Some(&scope), &original).claim,
        Some(Claim::Replay(_))
    ));
    refused(
        run(&store, Some(&scope), &changed),
        "G4",
        "nonce_payload_mismatch",
        Some("app-fixture"),
    );
    store.no_contact();
}

#[test]
fn github_flow_ask_first_refuses_before_claim_but_allow_and_block_keep_their_policy() {
    let scope = plexus_core::scope::CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "flow-1".into(),
        scope_epoch: 1,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: Some("agent-fixture".into()),
        delegates: true,
        owner_authorized: true,
        flow_id: Some("github-flow".into()),
    };
    for effect in ["ask_first", "allow", "block"] {
        let mut store = Store::good();
        store.authority.module_effect = effect.into();
        let reply = gates::run_scoped(
            &store,
            plexus_core::github::AFT_PRINCIPAL,
            Some(&scope),
            &request(),
            "nonce",
            "request-id",
            "worker",
            1,
            120,
        );
        match effect {
            "ask_first" => {
                assert_eq!(reply.refusal_code.as_deref(), Some("consent_unavailable"));
                assert_eq!(*store.claims.lock().unwrap(), 0);
                assert!(reply.claim.is_none());
                store.no_contact();
            }
            "allow" => {
                assert!(reply.refusal_code.is_none(), "{reply:?}");
                assert_eq!(*store.claims.lock().unwrap(), 1);
            }
            "block" => {
                assert!(reply
                    .refusal_code
                    .as_deref()
                    .unwrap()
                    .starts_with("policy_blocked"));
                assert_eq!(*store.claims.lock().unwrap(), 0);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn binding_callback_store_error_is_retryable_and_sends_nothing() {
    let mut store = Store::good();
    store.fail_binding_on = Some(2);
    let scope = delegating_scope("agent-fixture");
    let reply = run(&store, Some(&scope), &request());
    assert_eq!(
        reply.refusal_code.as_deref(),
        Some("store_failure"),
        "binding callback database errors must remain retryable store_failure"
    );
    assert!(
        reply.claim.is_none(),
        "a failed binding lookup must never claim a write"
    );
    assert_eq!(*store.claims.lock().unwrap(), 0);
    store.no_contact();
}

#[test]
fn terminal_replay_store_failure_is_not_repository_unbound() {
    let mut store = Store::good();
    store.bound = None;
    store.receipt_error = true;
    let scope = delegating_scope("agent-fixture");
    let reply = run(&store, Some(&scope), &request());
    assert_eq!(
        reply.refusal_code.as_deref(),
        Some("store_failure"),
        "terminal receipt lookup errors must not become a definite unbound refusal"
    );
    assert!(reply.claim.is_none());
    assert_eq!(*store.claims.lock().unwrap(), 0);
    store.no_contact();
}
