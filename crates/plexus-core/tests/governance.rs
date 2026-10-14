#[path = "support/bounded.rs"]
mod bounded;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::PlexusStore;
use plexus_core::{
    ingest_value, jcs_sha256, now_ms, AuthorizationRequest, CatalogActionInput, CatalogDenial,
    ConfigureOutcome, ConnectionDenial, CredentialError, CredentialSource, Denial,
    GovernanceEngine, GrantDenial, GrantInput, GrantMintRequest, MockResponse, MockTransport,
    PermanentCredentialError, PolicyDenial, PolicyInput, PollAuthorizationRefusal,
    ResolvedCredential, ResourceDenial, Severity, StubCredentialSource, TransportOutcome,
    AUTHORITY_POLL,
};
use serde_json::{json, Value};

fn test_store(label: &str) -> (PlexusStore, Scratch) {
    // The macOS clock ticks in microseconds, so the counter prevents same-tick test nonce collisions.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let path = Scratch::database(&format!("governance-{label}"));
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("{label}-{unique}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    (
        PlexusStore::open(&descriptor).expect("open test store"),
        path,
    )
}

/// A credential source that models an authority change while resolution is in
/// flight. The recovery UPDATE must not overwrite this state transition.
struct AuthorityChangeDuringCredentialResolution {
    store: Arc<PlexusStore>,
    status: &'static str,
}

impl CredentialSource for AuthorityChangeDuringCredentialResolution {
    fn get_by_id(&self, id: &str) -> Result<ResolvedCredential, CredentialError> {
        self.get(id.as_bytes())
    }

    fn get(&self, _handle: &[u8]) -> Result<ResolvedCredential, CredentialError> {
        if self.status == "revoked" {
            self.store
                .revoke_connection("direct", "conn-1")
                .expect("simulate concurrent revocation");
        } else {
            self.store
                .set_connection_health(
                    "direct",
                    "conn-1",
                    self.status,
                    &json!({"reason":"concurrent_authority_change"}),
                )
                .expect("simulate concurrent health change");
        }
        Ok(ResolvedCredential::new(b"vendor-token".to_vec(), None, 1))
    }
}

fn seed(
    label: &str,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Scratch,
) {
    let (store, path) = test_store(label);
    let principal = "direct";
    let connection = "conn-1";
    store
        .insert_connection(
            principal,
            connection,
            "mock",
            "pending",
            &json!({"required": ["team"], "write_enabling": ["team"]}),
        )
        .expect("insert connection");
    let handle = b"test:canary-binding-handle";
    let ticket = store
        .create_binding_ticket(principal, connection, handle)
        .expect("issue binding ticket");
    store
        .connect_with_ticket(principal, &ticket.ticket_id)
        .expect("consume binding ticket")
        .expect("connection activates");
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: connection.to_string(),
            principal: principal.to_string(),
            name: "write_item".to_string(),
            title: Some("Write item".to_string()),
            schema: json!({"type": "object"}),
            schema_hash: jcs_sha256(&json!({"type": "object"}))
                .expect("test JSON is JCS-compatible"),
            risk: "write".to_string(),
            severity: "S2".to_string(),
            ask_first: true,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("insert action");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-1".to_string(),
            principal: principal.to_string(),
            connection_id: connection.to_string(),
            grantee_principal: principal.to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["write_item".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("insert grant");
    store
        .insert_policy(&PolicyInput {
            policy_id: "policy-1".to_string(),
            principal: principal.to_string(),
            connection_id: connection.to_string(),
            action_selector: "write_item".to_string(),
            effect: "allow".to_string(),
            expires_at: None,
        })
        .expect("insert policy");
    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let transport = MockTransport::default();
    let engine = GovernanceEngine::new(Arc::new(store), Arc::new(credentials), Arc::new(transport));
    // Severity reads the app's reviewed tier from its system manifest, and an
    // app without one is gated at the strongest tier.
    install_mock_manifest_tier(&engine, "S1");
    (engine, path)
}

fn engine_with_authority_change_during_credential_resolution(
    label: &str,
    status: &'static str,
) -> (
    GovernanceEngine<AuthorityChangeDuringCredentialResolution, MockTransport>,
    Scratch,
) {
    let (seeded, path) = seed(label);
    let store = seeded.store().clone();
    let transport = seeded.transport().clone();
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(AuthorityChangeDuringCredentialResolution { store, status }),
        transport,
    );
    (engine, path)
}

fn write_request() -> AuthorizationRequest {
    AuthorizationRequest::new("direct", "conn-1", "write_item", json!({"team": "core"}))
}

fn add_cross_principal_invoke_grant(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    grant_id: &str,
    grantee: &str,
    selectors: &[&str],
    expires_at: Option<i64>,
) {
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: grant_id.to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: grantee.to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: selectors
                .iter()
                .map(|selector| (*selector).to_string())
                .collect(),
            authority_kind: "invoke".to_string(),
            expires_at,
        })
        .expect("insert cross-principal invoke grant");
}

fn add_action_with_policy(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    action: &str,
    risk: &str,
    policy: &str,
    ceiling: &str,
) {
    let schema = json!({"type": "object"});
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "conn-1".to_string(),
            principal: "direct".to_string(),
            name: action.to_string(),
            title: Some(action.to_string()),
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: risk.to_string(),
            severity: risk.to_string(),
            ask_first: matches!(risk, "write" | "destructive"),
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("insert extra action");
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-{action}"),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: ceiling.to_string(),
            action_selectors: vec![action.to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("insert extra grant");
    if policy != "none" {
        engine
            .store()
            .insert_policy(&PolicyInput {
                policy_id: format!("policy-{action}"),
                principal: "direct".to_string(),
                connection_id: "conn-1".to_string(),
                action_selector: action.to_string(),
                effect: policy.to_string(),
                expires_at: None,
            })
            .expect("insert extra policy");
    }
}

#[test]
fn policy_expired_before_authorization_does_not_block_dispatch() {
    let (engine, path) = seed("policy-expired-before-authorization");
    let action = "read_after_expired_policy";
    add_action_with_policy(&engine, action, "read", "none", "read");
    engine
        .store()
        .insert_policy(&PolicyInput {
            policy_id: "expired-block".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            action_selector: action.to_string(),
            effect: "block".to_string(),
            expires_at: Some(now_ms().saturating_sub(1)),
        })
        .expect("insert already-expired block policy");

    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            action,
            json!({}),
        ))
        .expect("expired policy must not block authorization");
    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));
    assert_eq!(engine.transport().requests().len(), 1);
    let _ = fs::remove_file(path);
}

#[test]
fn policy_expiring_between_authorization_and_claim_aborts_dispatch() {
    let (engine, path) = seed("policy-expires-before-claim");
    let action = "read_while_policy_expires";
    add_action_with_policy(&engine, action, "read", "none", "read");
    let expires_at = now_ms().saturating_add(5_000);
    engine
        .store()
        .insert_policy(&PolicyInput {
            policy_id: "expiring-allow".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            action_selector: action.to_string(),
            effect: "allow".to_string(),
            expires_at: Some(expires_at),
        })
        .expect("insert expiring allow policy");

    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            action,
            json!({}),
        ))
        .expect("unexpired policy authorizes reservation");
    assert_eq!(reservation.snapshot.policy, 1);
    while now_ms() <= expires_at {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(matches!(
        outcome.outcome,
        TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization"
    ));
    assert!(engine.transport().requests().is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn specific_policy_beats_higher_generation_wildcard_at_claim() {
    let (engine, path) = seed("specific-policy-priority");
    let action = "read_with_specific_policy";
    add_action_with_policy(&engine, action, "read", "none", "read");
    engine
        .store()
        .insert_policy(&PolicyInput {
            policy_id: "a-wildcard-block".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            action_selector: "*".to_string(),
            effect: "block".to_string(),
            expires_at: None,
        })
        .expect("insert wildcard policy");
    assert!(engine
        .store()
        .update_policy_effect("direct", "a-wildcard-block", "block")
        .expect("raise wildcard generation"));
    engine
        .store()
        .insert_policy(&PolicyInput {
            policy_id: "z-specific-allow".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            action_selector: action.to_string(),
            effect: "allow".to_string(),
            expires_at: None,
        })
        .expect("insert specific policy");

    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            action,
            json!({}),
        ))
        .expect("specific allow policy takes priority");
    assert_eq!(reservation.snapshot.policy, 1);
    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));
    assert_eq!(engine.transport().requests().len(), 1);
    let _ = fs::remove_file(path);
}

#[test]
fn policy_changed_between_authorization_and_claim_aborts_dispatch() {
    let (engine, path) = seed("policy-changed-before-claim");
    let action = "read_before_policy_change";
    add_action_with_policy(&engine, action, "read", "allow", "read");
    let reservation = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            action,
            json!({}),
        ))
        .expect("allow policy authorizes reservation");
    assert!(engine
        .store()
        .update_policy_effect("direct", &format!("policy-{action}"), "block")
        .expect("change governing policy"));

    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(matches!(
        outcome.outcome,
        TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization"
    ));
    assert!(engine.transport().requests().is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn stale_authorization_aborts_before_mock_transport_is_invoked() {
    let (engine, path) = seed("stale");
    let reservation = engine.authorize(write_request()).expect("write reserves");
    engine
        .store()
        .quarantine_action("direct", "conn-1", "write_item", "catalog changed")
        .expect("quarantine invalidates reservation");

    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization"
    ));
    assert_eq!(outcome.retryability, plexus_core::Retryability::Terminal);
    // The load-bearing assertion, and the one the outcome check cannot make:
    // that the call the guard exists to prevent DID NOT GO OUT. A refusal can
    // be returned while the request has already reached the vendor, and only a
    // zero-call assertion distinguishes those.
    //
    // Mutation-proved against the realistic defect shape rather than against a
    // removed guard: dispatching to the transport while leaving the refusal
    // verdict intact fails HERE and nowhere else, so this assertion is what
    // fences enforcement rather than decoration on the outcome check.
    assert!(
        engine.transport().requests().is_empty(),
        "stale authorization must never invoke transport"
    );
    assert_eq!(
        engine
            .store()
            .reservation("direct", &reservation.reservation_id)
            .expect("read reservation")
            .expect("reservation")
            .status,
        "invalidated"
    );
    assert!(engine
        .store()
        .list_audit("direct")
        .expect("read audit")
        .iter()
        .any(|row| row.reason_code == "aborted_stale_authorization"
            && row.gate.as_deref() == Some("dispatch")));
    let requests = engine
        .store()
        .connection("direct", "conn-1")
        .expect("read connection")
        .expect("connection");
    assert_eq!(
        requests.status, "active",
        "quarantine changes action, not connection"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn revocation_invalidates_outstanding_reservation_at_write_time() {
    let (engine, path) = seed("revoke");
    let reservation = engine.authorize(write_request()).expect("write reserves");
    assert!(engine
        .store()
        .revoke_connection("direct", "conn-1")
        .expect("revoke connection"));
    assert_eq!(
        engine
            .store()
            .reservation("direct", &reservation.reservation_id)
            .expect("read reservation")
            .expect("reservation")
            .status,
        "invalidated"
    );
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
    assert!(engine
        .store()
        .list_audit("direct")
        .expect("read audit")
        .iter()
        .any(|row| row.reason_code == "aborted_stale_authorization"));
    let _ = fs::remove_file(path);
}

#[test]
fn allowed_authorization_claims_single_use_reservation_and_dispatches_once() {
    let (engine, path) = seed("dispatch");
    let reservation = engine.authorize(write_request()).expect("write reserves");
    let first = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(first.outcome, TransportOutcome::Completed { .. }));
    assert_eq!(engine.transport().requests().len(), 1);
    assert_eq!(
        engine
            .store()
            .reservation("direct", &reservation.reservation_id)
            .expect("read reservation")
            .expect("reservation")
            .status,
        "dispatched"
    );
    let second = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(second.outcome, TransportOutcome::NotSent { .. }));
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "reservation is single-use"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn successful_governed_call_writes_authorization_and_dispatch_rows() {
    let (engine, path) = seed("folded-authorization-audit");
    let reservation = engine.authorize(write_request()).expect("write reserves");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));

    let rows = engine.store().list_audit("direct").expect("read audit");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].gate.as_deref(), Some("credential"));
    assert_eq!(rows[0].reason_code, "credential_resolved");
    assert_eq!(rows[0].decision, "allow");
    assert_eq!(
        rows[0].credential_fingerprint.as_deref(),
        Some(plexus_core::fingerprint(b"vault-reference:test:canary-binding-handle").as_str())
    );
    assert_eq!(rows[1].gate.as_deref(), Some("dispatch"));
    assert_eq!(rows[1].reason_code, "dispatched");
    let _ = fs::remove_file(path);
}

/// A vendor manifest carrying the given auth mode. `none` is the
/// credential-free shape: a public, unauthenticated MCP server such as
/// DeepWiki, which has no secret to present and stores no binding.
fn public_manifest(auth_mode: &str) -> Value {
    let credential_bindings = if auth_mode == "none" {
        json!([])
    } else {
        json!([{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }])
    };
    json!({
        "schema_version": 1,
        "key": "public",
        "name": "Public",
        "description": "governance test vendor",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "tests",
        "tier": "S1",
        "transport": { "kind": "mcp_remote", "url": "https://example.invalid/mcp" },
        "auth": { "mode": auth_mode },
        "credential_bindings": credential_bindings,
        "resource_filters": { "required": [], "optional": [], "write_enabling": [] },
        "actions_baseline": [{ "name": "ask_question", "risk": "read" }],
        "defaults": {
            "ask_first_risk": ["write"],
            "rate_limit": { "calls_per_min": 30 }
        },
        "availability": "ga"
    })
}

fn install_public_manifest(store: &PlexusStore, auth_mode: &str) {
    let ingested = ingest_value(public_manifest(auth_mode)).expect("manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &ingested)
        .expect("store manifest");
}

/// A connection to the credential-free vendor, enrolled the way the ceremony
/// enrolls one: activated by a ticket whose ref role is `none`, so the
/// connection stores no credential binding at all.
fn seed_credential_free(
    label: &str,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Scratch,
) {
    let (store, path) = test_store(label);
    install_public_manifest(&store, "none");
    store
        .insert_connection("direct", "conn-public", "public", "pending", &json!({}))
        .expect("insert connection");
    let ticket = store
        .create_binding_ticket_with_role(
            "direct",
            "conn-public",
            plexus_core::NO_CREDENTIAL_REF_ROLE,
            b"",
        )
        .expect("issue credential-free binding ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume binding ticket")
        .expect("connection activates");
    let schema = json!({"type": "object"});
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "conn-public".to_string(),
            principal: "direct".to_string(),
            name: "ask_question".to_string(),
            title: Some("Ask question".to_string()),
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("insert action");
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-public".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-public".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["ask_question".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("insert grant");
    let engine = GovernanceEngine::new(
        Arc::new(store),
        Arc::new(StubCredentialSource::default()),
        Arc::new(MockTransport::default()),
    );
    (engine, path)
}

fn public_request() -> AuthorizationRequest {
    AuthorizationRequest::new("direct", "conn-public", "ask_question", json!({}))
}

/// A vendor that needs no credential must be callable, not merely connectable.
///
/// Such a connection stores no credential binding by construction, so a
/// dispatch that demands one refuses every call on it — the vendor enrolls
/// successfully and is then permanently uncallable, as a public vendor such as
/// DeepWiki would be.
///
/// The zero-call assertion is not decoration on the outcome check: a refusal
/// can be reported after the request already went out, and only counting the
/// transport's calls distinguishes "it dispatched" from "it said it did".
#[test]
fn a_credential_free_vendor_dispatches_without_a_credential() {
    let (engine, path) = seed_credential_free("credential-free-dispatch");

    let reservation = engine
        .authorize(public_request())
        .expect("a credential-free vendor authorizes");
    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "a credential-free vendor must dispatch, got {:?}",
        outcome.outcome
    );
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "the vendor call must actually reach the transport"
    );

    // The audit row for an anonymous call carries the reserved `none` ref role
    // fingerprint, the same value the authorization gate records, so a reader
    // cannot mistake it for the fingerprint of a real credential handle.
    let rows = engine.store().list_audit("direct").expect("read audit");
    let dispatched = rows
        .iter()
        .find(|row| row.gate.as_deref() == Some("dispatch"))
        .expect("dispatch audit row");
    assert_eq!(dispatched.reason_code, "dispatched");
    let anonymous = plexus_core::fingerprint(plexus_core::NO_CREDENTIAL_REF_ROLE.as_bytes());
    assert_eq!(
        dispatched.credential_fingerprint.as_deref(),
        Some(anonymous.as_str()),
        "an anonymous dispatch must record the no-credential fingerprint"
    );
    let authorized = rows
        .iter()
        .find(|row| row.gate.as_deref() == Some("credential"))
        .expect("authorization audit row");
    assert_eq!(
        authorized.credential_fingerprint.as_deref(),
        Some(anonymous.as_str()),
        "authorization and dispatch must agree on what an anonymous call presented"
    );

    let _ = fs::remove_file(path);
}

/// The credential waiver comes from the REVIEWED MANIFEST and never from what
/// the connection happens to hold.
///
/// A connection with no stored binding is not permission to call a vendor
/// anonymously — it is a connection that has no credential, which is a
/// failure. Reading the absence of a binding as a waiver would silently
/// downgrade a credential failure into an unauthenticated call, which is worse
/// than refusing.
///
/// The fixture reaches that state the only way it can arise in production: the
/// vendor is authorized while its manifest declares `auth.mode = none`, and the
/// reviewed manifest then changes to require a credential before the call goes
/// out. Asserting the exact refusal code matters — a reservation aborted as
/// stale would also leave the transport untouched and would prove nothing
/// about the credential rule.
#[test]
fn a_vendor_that_stops_being_credential_free_is_not_dispatched_anonymously() {
    let (engine, path) = seed_credential_free("waiver-withdrawn-before-dispatch");
    let reservation = engine
        .authorize(public_request())
        .expect("a credential-free vendor authorizes");

    install_public_manifest(engine.store(), "api_key");
    let outcome = engine.revalidate_and_dispatch(&reservation);

    assert!(
        matches!(
            outcome.outcome,
            TransportOutcome::NotSent { ref code, .. } if code == "credential_missing"
        ),
        "a vendor that requires a credential must refuse when none is bound, got {:?}",
        outcome.outcome
    );
    assert!(
        engine.transport().requests().is_empty(),
        "a credentialed vendor must never be called anonymously"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn connection_gate_denies_revoked_connection() {
    let (engine, path) = seed("deny-connection");
    engine
        .store()
        .revoke_connection("direct", "conn-1")
        .expect("revoke");
    assert!(matches!(
        engine.authorize(write_request()),
        Err(Denial::Connection(ConnectionDenial::Revoked))
    ));
    let rows = engine.store().list_audit("direct").expect("read audit");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gate.as_deref(), Some("connection"));
    assert_eq!(rows[0].reason_code, "connection_revoked");
    assert_eq!(rows[0].decision, "deny");
    let _ = fs::remove_file(path);
}

#[test]
fn catalog_gate_denies_quarantined_action() {
    let (engine, path) = seed("deny-catalog");
    engine
        .store()
        .quarantine_action("direct", "conn-1", "write_item", "changed")
        .expect("quarantine");
    assert!(matches!(
        engine.authorize(write_request()),
        Err(Denial::Catalog(CatalogDenial::Quarantined))
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn catalog_gate_denies_schema_hash_drift() {
    let (engine, path) = seed("deny-schema");
    let request = write_request().with_schema_hash("sha256:not-the-observed-schema");
    assert!(matches!(
        engine.authorize(request),
        Err(Denial::Catalog(CatalogDenial::SchemaMismatch))
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn grant_gate_is_default_deny() {
    let (engine, path) = seed("deny-grant");
    let schema = json!({"type": "object"});
    engine
        .store()
        .insert_connection(
            "other",
            "other-conn",
            "mock",
            "active",
            &json!({"required": ["team"], "write_enabling": ["team"]}),
        )
        .expect("other connection");
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "other-conn".to_string(),
            principal: "other".to_string(),
            name: "write_item".to_string(),
            title: None,
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: "write".to_string(),
            severity: "S2".to_string(),
            ask_first: true,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("other action");
    let request =
        AuthorizationRequest::new("other", "other-conn", "write_item", json!({"team": "core"}));
    assert!(matches!(
        engine.authorize(request),
        Err(Denial::Grant(GrantDenial::Missing))
    ));
    let rows = engine.store().list_audit("other").expect("read audit");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gate.as_deref(), Some("grant"));
    assert_eq!(rows[0].reason_code, "grant_missing");
    assert_eq!(rows[0].decision, "deny");
    let _ = fs::remove_file(path);
}

/// Mutation proved: revert invoke connection resolution to caller-owned rows;
/// the granted caller can no longer dispatch the owner's connection.
#[test]
fn cross_principal_invoke_runs_the_owners_rows_and_attributes_the_caller() {
    let caller = "reserved:x";
    let (engine, path) = seed("cross-principal-dispatch");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-cross-dispatch",
        caller,
        &["write_item"],
        None,
    );

    let reservation = engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect("the named grantee resolves the owner's connection");
    assert_eq!(reservation.principal, "direct");
    assert_eq!(reservation.acting_principal, caller);

    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));
    assert_eq!(engine.transport().requests().len(), 1);
    let audit = engine.store().list_audit("direct").expect("owner audit");
    let dispatch = audit
        .iter()
        .find(|row| row.reason_code == "dispatched")
        .expect("dispatch audit row");
    assert_eq!(dispatch.principal, "direct");
    assert_eq!(dispatch.acting_principal, caller);
    let _ = fs::remove_file(path);
}

/// Mutation proved: resolve owner rows without requiring this caller's grant;
/// the ungranted caller can then distinguish an owned id from an absent id.
#[test]
fn ungranted_caller_cannot_distinguish_an_owned_connection_from_an_absent_one() {
    let (engine, path) = seed("cross-principal-anti-oracle");
    let owned = engine
        .authorize(AuthorizationRequest::new(
            "reserved:no-grant",
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("an ungranted owner's connection stays invisible");
    let absent = engine
        .authorize(AuthorizationRequest::new(
            "reserved:no-grant",
            "conn-does-not-exist",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("an absent connection is refused");

    assert_eq!(owned, absent);
    assert_eq!(owned.reason_code(), "connection_not_found");
    let _ = fs::remove_file(path);
}

/// Mutation proved: filter expired grants out of owner resolution; lookup then
/// hides the connection instead of letting the grant gate report expiration.
#[test]
fn expired_cross_principal_grant_resolves_before_the_grant_gate_refuses_it() {
    let caller = "reserved:expired";
    let (engine, path) = seed("cross-principal-expired");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-cross-expired",
        caller,
        &["write_item"],
        Some(plexus_core::now_ms().saturating_sub(1)),
    );

    let denial = engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("expired authority must refuse");
    assert_eq!(denial, Denial::Grant(GrantDenial::Expired));
    let _ = fs::remove_file(path);
}

/// Mutation proved: apply action selectors during owner resolution; lookup then
/// hides the connection instead of letting the grant gate report the mismatch.
#[test]
fn wrong_action_grant_resolves_before_the_selector_gate_refuses_it() {
    let caller = "reserved:wrong-action";
    let (engine, path) = seed("cross-principal-wrong-action");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-cross-wrong-action",
        caller,
        &["different_action"],
        None,
    );

    let denial = engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("the grant selector does not cover this action");
    assert_eq!(denial, Denial::Grant(GrantDenial::ActionSelector));
    let _ = fs::remove_file(path);
}

/// A directly inserted legacy grant with no selectors confers no invoke
/// authority, while the same route remains usable with an explicit selector.
#[test]
fn an_empty_invoke_grant_authorizes_nothing_but_a_matching_grant_dispatches() {
    let caller = "reserved:empty-selector";
    let (empty_engine, empty_path) = seed("cross-principal-empty-selector");
    add_cross_principal_invoke_grant(
        &empty_engine,
        "grant-cross-empty-selector",
        caller,
        &[],
        None,
    );
    let denial = empty_engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("an empty grant must authorize no action");
    // Grant creation expands wildcard selectors into concrete actions before
    // storage, so a later manifest change cannot widen an existing grant.
    // Treating an empty selector list as unrestricted would recreate the
    // implicit unbounded grant that this expansion prevents.
    assert_eq!(denial, Denial::Grant(GrantDenial::ActionSelector));
    assert!(empty_engine.transport().requests().is_empty());

    let (matching_engine, matching_path) = seed("cross-principal-matching-selector");
    add_cross_principal_invoke_grant(
        &matching_engine,
        "grant-cross-matching-selector",
        caller,
        &["write_item"],
        None,
    );
    let reservation = matching_engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect("a matching nonempty grant must authorize the action");
    let outcome = matching_engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));
    assert_eq!(matching_engine.transport().requests().len(), 1);

    let _ = fs::remove_file(empty_path);
    let _ = fs::remove_file(matching_path);
}

/// Mutation proved: remove the grantee predicate from owner resolution; a grant
/// naming another grantee then reveals the connection to a third principal.
#[test]
fn another_grantees_invoke_grant_confers_nothing_on_a_third_principal() {
    let (engine, path) = seed("cross-principal-third-party");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-cross-other",
        "reserved:other",
        &["write_item"],
        None,
    );

    let denial = engine
        .authorize(AuthorizationRequest::new(
            "reserved:third",
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("another grantee's grant must not reveal the connection");
    assert_eq!(denial, Denial::Connection(ConnectionDenial::NotFound));
    assert_eq!(
        engine.transport().requests().len(),
        0,
        "a third principal must never reach transport"
    );
    let _ = fs::remove_file(path);
}

/// Mutation proved: remove the grantee predicate from `matching_grant`; the
/// owner can then borrow authority granted only to a different principal.
#[test]
fn grant_gate_does_not_borrow_another_grantees_grant() {
    let (engine, path) = seed("grant-two-sided");
    engine
        .store()
        .revoke_grant("direct", "grant-1")
        .expect("remove owner's self grant");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-other-grantee-only",
        "reserved:other",
        &["write_item"],
        None,
    );

    let denial = engine
        .authorize(write_request())
        .expect_err("another grantee's grant must not authorize the owner");
    assert_eq!(denial, Denial::Grant(GrantDenial::Missing));
    assert_eq!(engine.transport().requests().len(), 0);
    let _ = fs::remove_file(path);
}

/// Mutation proved: skip status gates after grant-owner resolution; a revoked
/// owner connection then accepts an otherwise valid cross-principal grant.
#[test]
fn revoked_owner_connection_still_refuses_a_cross_principal_caller() {
    let caller = "reserved:revoked";
    let (engine, path) = seed("cross-principal-revoked");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-cross-revoked",
        caller,
        &["write_item"],
        None,
    );
    engine
        .store()
        .revoke_connection("direct", "conn-1")
        .expect("revoke owner connection");

    let denial = engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        ))
        .expect_err("revoked owner connection must refuse");
    assert_eq!(denial, Denial::Connection(ConnectionDenial::Revoked));
    let _ = fs::remove_file(path);
}

/// Mutation proved: evaluate cross-principal writes against invoking-caller
/// rows; the write no longer receives the owner's configured resource fence.
#[test]
fn cross_principal_write_uses_the_same_owner_resource_filter_as_an_owner_call() {
    let caller = "reserved:filtered";
    let (engine, path) = seed("cross-principal-resource-filter");
    add_cross_principal_invoke_grant(
        &engine,
        "grant-cross-filtered",
        caller,
        &["write_item"],
        None,
    );
    engine
        .store()
        .set_connection_filters(
            "direct",
            "conn-1",
            &json!({
                "required": ["team"],
                "write_enabling": ["team"],
                "values": {"team": ["core"]}
            }),
        )
        .expect("set owner filters");
    let args = json!({"team": "outside"});

    let owner_denial = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "write_item",
            args.clone(),
        ))
        .expect_err("owner write outside the filter must refuse");
    let caller_denial = engine
        .authorize(AuthorizationRequest::new(
            caller,
            "conn-1",
            "write_item",
            args,
        ))
        .expect_err("cross-principal write outside the owner filter must refuse");
    assert_eq!(caller_denial, owner_denial);
    assert!(matches!(
        caller_denial,
        Denial::ResourceFilter(ResourceDenial::ValueNotAllowed(ref key)) if key == "team"
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn policy_gate_blocks_even_when_granted() {
    let (engine, path) = seed("deny-policy");
    add_action_with_policy(&engine, "blocked", "read", "block", "read");
    let request = AuthorizationRequest::new("direct", "conn-1", "blocked", json!({}));
    assert!(matches!(
        engine.authorize(request),
        Err(Denial::Policy(PolicyDenial::Blocked))
    ));
    let rows = engine.store().list_audit("direct").expect("read audit");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].gate.as_deref(), Some("policy"));
    assert_eq!(rows[0].reason_code, "policy_blocked");
    assert_eq!(rows[0].decision, "deny");
    let _ = fs::remove_file(path);
}

#[test]
fn policy_gate_creates_exact_shape_action_request_for_write() {
    let (engine, path) = seed("ask-first");
    add_action_with_policy(&engine, "ask_write", "write", "none", "write");
    let request =
        AuthorizationRequest::new("direct", "conn-1", "ask_write", json!({"team": "core"}));
    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(request) else {
        panic!("write without an allow policy must create an action request");
    };
    let stored = engine
        .store()
        .list_action_requests("direct")
        .expect("requests");
    assert!(stored
        .iter()
        .any(|item| item.request_id == request_id && item.status == "pending"));
    let _ = fs::remove_file(path);
}

/// Lapse a pending approval window without waiting for it.
///
/// The window is five minutes of wall clock, so the only way to reach the
/// expired state in a test is to move the row's deadline into the past. Opened
/// as a second connection because the store exposes no setter for it -- the
/// deadline is meant to be set once at creation and never moved.
fn expire_action_request(path: &Path, request_id: &str) {
    let conn = rusqlite::Connection::open(path).expect("open second connection");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("set busy timeout");
    let changed = conn
        .execute(
            "UPDATE action_requests SET expires_at = 1 WHERE request_id = ?1",
            rusqlite::params![request_id],
        )
        .expect("expire the request");
    assert_eq!(changed, 1, "the request to expire must exist");
}

/// An approval arriving after its window has lapsed is refused, and nothing
/// reaches the vendor.
///
/// This is the fail-closed half of ask-first, and the reason the window exists
/// at all. A pending request records that an operator was asked about THESE
/// arguments under THESE conditions; the longer it sits, the less that consent
/// describes the present. An approval hours later is a decision about a
/// situation that may no longer hold, so the window lapsing has to mean the
/// request is dead rather than merely old.
///
/// The transport assertion is the load-bearing one. A refusal that returns an
/// error after the write has already gone out is indistinguishable from a
/// correct refusal at the call site, and it is the vendor state that cannot be
/// undone.
///
/// Note what stays true: the row remains `pending` rather than being rewritten
/// to an expired status. That is deliberate -- nobody decided anything, and
/// recording a decision that was never made would be a worse lie than leaving
/// a stale row. The deadline is in the projection, so an operator listing
/// requests can see it has passed.
///
/// Mutation-proved against the STORE gate: neutralising the `expires_at > ?6`
/// predicate in `decide_action_request` lets the approval land, and this fails
/// on the recorded status.
///
/// NOT proved here, stated so the coverage is not over-read: governance carries
/// a SECOND deadline check (`approved.expires_at > now` in `authorize`), and
/// neutralising that one leaves this test green. That is not a hole in the
/// test. The two guards cover different instants -- the store gate refuses an
/// approval whose window has already lapsed, while the governance gate catches
/// a window that lapses in the microseconds BETWEEN the approval landing and
/// the dispatch being authorized. Reaching the second requires the deadline to
/// fall inside that interval, which a test cannot schedule without interposing
/// on the engine. Exercising the outer gate is what is available; the inner one
/// is a race backstop and is recorded as unexercised rather than assumed.
#[test]
fn an_approval_after_its_window_lapses_is_refused_before_dispatch() {
    let (engine, path) = seed("approval-expired");
    add_action_with_policy(&engine, "ask_write", "write", "none", "write");
    // Deciding a request needs connection-admin authority, checked BEFORE the
    // window. Without this grant the refusal is `ConnectionAdminRequired` and
    // the expiry gate is never reached -- a pass that would prove nothing
    // about lapsed windows.
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "admin-grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "destructive".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "connection_admin".to_string(),
            expires_at: None,
        })
        .expect("admin grant");

    let request =
        AuthorizationRequest::new("direct", "conn-1", "ask_write", json!({"team": "core"}));
    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(request) else {
        panic!("an ask-first write must park a request");
    };

    expire_action_request(&path, &request_id);

    let denial = engine
        .approve_request("direct", &request_id, "direct")
        .expect_err("an approval past its window must be refused");
    assert!(
        matches!(denial, Denial::Policy(PolicyDenial::ApprovalExpired)),
        "the refusal must name the lapsed window rather than a generic failure: {denial:?}"
    );
    assert!(
        engine.transport().requests().is_empty(),
        "a lapsed approval must not reach the vendor"
    );

    // The request is still listed, still pending: an operator can see it and
    // read its passed deadline rather than finding it silently gone.
    let stored = engine
        .store()
        .list_action_requests("direct")
        .expect("requests");
    let row = stored
        .iter()
        .find(|item| item.request_id == request_id)
        .expect("the lapsed request remains visible");
    assert_eq!(
        row.status, "pending",
        "no decision was made, so none may be recorded"
    );

    let _ = fs::remove_file(path);
}

/// Drift a catalog action's schema hash, as the reconciler would after the
/// vendor changed the tool's input schema.
fn drift_schema_hash(path: &Path, action: &str, schema_hash: &str) {
    let conn = rusqlite::Connection::open(path).expect("open second connection");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("set busy timeout");
    let changed = conn
        .execute(
            "UPDATE catalog_actions SET schema_hash = ?1
             WHERE principal = 'direct' AND connection_id = 'conn-1' AND name = ?2",
            rusqlite::params![schema_hash, action],
        )
        .expect("drift schema hash");
    assert_eq!(changed, 1, "the catalog row to drift must exist");
}

/// An approval is refused when the action's schema moved while the request sat
/// parked, and the refusal names the SCHEMA rather than the approval.
///
/// The scenario is ordinary rather than adversarial: a write parks for an
/// operator, the vendor ships a change to that tool's input schema, the
/// reconciler updates the stored hash on the next health probe, and the
/// operator then approves. Consent was given for a shape that no longer
/// exists, so proceeding would send arguments an operator approved against a
/// contract nobody has seen.
///
/// WHAT THIS PINS IS THE ORDERING, which is the part that can silently change.
/// Two gates can answer here: the catalog gate compares the request's expected
/// schema against the stored one, and a later approval gate re-checks the same
/// thing among its conditions. The catalog gate fires first because
/// `approve_request` carries the parked row's schema hash into the
/// authorization, so the specific refusal reaches the operator instead of a
/// generic approval failure. Reordering those checks would keep this test
/// passing on the denial being an error, which is why it asserts the variant.
///
/// A CONSEQUENCE WORTH RECORDING: because that earlier gate always answers
/// first, and because `approve_request` rebuilds arguments from the stored row
/// rather than accepting them from the caller, `PolicyDenial::ApprovalShapeMismatch`
/// has no reachable production path today. It is a backstop for a future caller
/// that supplies an approved_request_id alongside its own arguments. Left in
/// place deliberately -- the cost is one branch, and the alternative is
/// removing a guard on the grounds that nothing currently violates it.
///
/// Mutation-proved: dropping `expected_schema_hash` from the authorization
/// built in `approve_request` moves the refusal to the approval gate, failing
/// this on the denial variant.
#[test]
fn an_approval_is_refused_when_the_schema_moved_while_it_was_parked() {
    let (engine, path) = seed("approval-schema-drift");
    add_action_with_policy(&engine, "ask_write", "write", "none", "write");
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "admin-grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "destructive".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "connection_admin".to_string(),
            expires_at: None,
        })
        .expect("admin grant");

    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(
        AuthorizationRequest::new("direct", "conn-1", "ask_write", json!({"team": "core"})),
    ) else {
        panic!("an ask-first write must park a request");
    };

    // The vendor changed the tool's shape while the request waited.
    drift_schema_hash(&path, "ask_write", "sha256:moved-after-the-request-parked");

    let denial = engine
        .approve_request("direct", &request_id, "direct")
        .expect_err("an approval against a moved schema must be refused");
    assert!(
        matches!(denial, Denial::Catalog(CatalogDenial::SchemaMismatch)),
        "the refusal must name the moved schema, not a generic approval failure: {denial:?}"
    );
    assert!(
        engine.transport().requests().is_empty(),
        "a stale-shape approval must not reach the vendor"
    );

    let _ = fs::remove_file(path);
}

fn park_write_for_direct_approval(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    action: &str,
    args: &Value,
) -> String {
    add_action_with_policy(engine, action, "write", "none", "write");
    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(
        AuthorizationRequest::new("direct", "conn-1", action, args.clone()),
    ) else {
        panic!("an ask-first write must park a request");
    };
    request_id
}

/// These direct `authorize` calls model a future caller. `approve_request`
/// rebuilds arguments and schema from the stored row, so it cannot create these
/// mismatched shapes today.
#[test]
fn authorize_refuses_a_pending_approval_as_shape_mismatch() {
    let (engine, path) = seed("direct-approval-pending");
    let action = "pending_approval";
    let args = json!({"team": "core"});
    let request_id = park_write_for_direct_approval(&engine, action, &args);

    let denial = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", action, args).approved_from(request_id),
        )
        .expect_err("a row that was never approved must be refused");
    assert!(
        matches!(denial, Denial::Policy(PolicyDenial::ApprovalShapeMismatch)),
        "a present, unexpired row with the wrong status must name its shape: {denial:?}"
    );

    let _ = fs::remove_file(path);
}

/// An approval authorizes the call it was raised for and nothing else. The
/// catalog's schema hash covers only the input schema, so two actions with the
/// same schema share it; an approval for one must still not cover the other,
/// nor a different requester presenting the same approval id.
#[test]
fn an_approval_covers_only_its_own_action_and_requester() {
    let (engine, path) = seed("direct-approval-binding");
    let args = json!({"team": "core"});
    let request_id = park_and_approve(&engine, "archive_item", &args);
    // A second action with an identical schema, which the requester may call.
    add_action_with_policy(&engine, "delete_item", "write", "none", "write");
    add_cross_principal_invoke_grant(
        &engine,
        "other-grant",
        "reserved:other",
        &["archive_item"],
        None,
    );

    for (label, request) in [
        (
            "another action with the same schema",
            AuthorizationRequest::new("direct", "conn-1", "delete_item", args.clone()),
        ),
        (
            "another requester",
            AuthorizationRequest::new("reserved:other", "conn-1", "archive_item", args.clone()),
        ),
    ] {
        let denial = engine
            .authorize(request.approved_from(&request_id))
            .expect_err(label);
        assert_eq!(
            denial,
            Denial::Policy(PolicyDenial::ApprovalShapeMismatch),
            "{label} must not be authorized by the approval"
        );
    }
    assert!(engine.transport().requests().is_empty());
    assert_eq!(
        approval_status(&engine, &request_id),
        "approved",
        "a refused presentation must not use up the approval"
    );
    // The approval still authorizes the call it was raised for.
    engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", "archive_item", args)
                .approved_from(&request_id),
        )
        .expect("the approved call itself is authorized");

    let _ = fs::remove_file(path);
}

#[test]
fn authorize_refuses_an_approved_row_with_a_stale_schema_as_shape_mismatch() {
    let (engine, path) = seed("direct-approval-schema");
    let action = "stale_schema_approval";
    let args = json!({"team": "core"});
    let request_id = park_write_for_direct_approval(&engine, action, &args);
    assert!(
        engine
            .store()
            .decide_action_request("direct", &request_id, true, "operator")
            .expect("approve request"),
        "the request must become approved"
    );
    drift_schema_hash(&path, action, "sha256:changed-after-approval");

    let denial = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", action, args).approved_from(request_id),
        )
        .expect_err("an approval for a stale schema must be refused");
    assert!(
        matches!(denial, Denial::Policy(PolicyDenial::ApprovalShapeMismatch)),
        "an unexpired approval for the wrong schema must name its shape: {denial:?}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn authorize_refuses_an_approved_row_past_its_deadline_as_expired() {
    let (engine, path) = seed("direct-approval-expired");
    let action = "expired_approval";
    let args = json!({"team": "core"});
    let request_id = park_write_for_direct_approval(&engine, action, &args);
    assert!(
        engine
            .store()
            .decide_action_request("direct", &request_id, true, "operator")
            .expect("approve request"),
        "the request must become approved"
    );
    expire_action_request(&path, &request_id);

    let denial = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", action, args).approved_from(request_id),
        )
        .expect_err("an approved row past its deadline must be refused");
    assert!(
        matches!(denial, Denial::Policy(PolicyDenial::ApprovalExpired)),
        "a present row past its deadline must be labelled expired: {denial:?}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn authorize_labels_an_unknown_approval_id_as_missing() {
    let (engine, path) = seed("direct-approval-missing");

    let denial = engine
        .authorize(write_request().approved_from("req-does-not-exist"))
        .expect_err("an unknown approval id must be refused");
    assert!(
        matches!(denial, Denial::Policy(PolicyDenial::ApprovalMissing)),
        "an absent approval row must be labelled missing: {denial:?}"
    );

    let _ = fs::remove_file(path);
}

/// Insert an action with an explicit stored `ask_first` and a matching invoke
/// grant, bypassing the reconciler so the governance gate's reading of the
/// column can be tested in isolation from how the column is computed.
fn add_action_with_ask_first(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    action: &str,
    risk: &str,
    ask_first: bool,
) {
    let schema = json!({"type": "object"});
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: "conn-1".to_string(),
            principal: "direct".to_string(),
            name: action.to_string(),
            title: Some(action.to_string()),
            schema: schema.clone(),
            schema_hash: jcs_sha256(&schema).expect("test JSON is JCS-compatible"),
            risk: risk.to_string(),
            severity: "S1".to_string(),
            ask_first,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("insert ask-first action");
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-{action}"),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: risk.to_string(),
            action_selectors: vec![action.to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("insert ask-first grant");
}

#[test]
fn authorize_honours_stored_ask_first_flag_for_a_read() {
    // Mutation under test: revert `authorize` to derive ask-first from
    // `is_write(risk)` instead of reading the stored column. A read row stored
    // ask-first (as a widened manifest produces) must ask; a read row stored
    // non-ask-first must proceed. The reconciler is deliberately not involved,
    // so this proves the gate reads the column on its own.
    let (engine, path) = seed("ask-first-column");

    // A read stored ask-first asks, and the request row actually exists.
    add_action_with_ask_first(&engine, "read_asks", "read", true);
    let request = AuthorizationRequest::new("direct", "conn-1", "read_asks", json!({}));
    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(request) else {
        panic!("read stored ask-first must create an action request");
    };
    assert!(engine
        .store()
        .list_action_requests("direct")
        .expect("requests")
        .iter()
        .any(|item| item.request_id == request_id && item.status == "pending"));

    // A read stored non-ask-first proceeds all the way to a reservation.
    add_action_with_ask_first(&engine, "read_proceeds", "read", false);
    let request = AuthorizationRequest::new("direct", "conn-1", "read_proceeds", json!({}));
    engine
        .authorize(request)
        .expect("read stored non-ask-first must proceed without asking");
    let _ = fs::remove_file(path);
}

/// Mutation proved: park the action request under the invoking caller; the
/// operator can no longer find it in the connection owner's approval queue.
#[test]
fn cross_principal_ask_first_parks_under_owner_with_caller_attribution() {
    let caller = "reserved:approval-caller";
    let (engine, path) = seed("cross-principal-ask-first");
    add_action_with_ask_first(&engine, "cross_asks", "read", true);
    add_cross_principal_invoke_grant(&engine, "grant-cross-asks", caller, &["cross_asks"], None);

    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(
        AuthorizationRequest::new(caller, "conn-1", "cross_asks", json!({})),
    ) else {
        panic!("cross-principal ask-first action must park");
    };
    let owner_requests = engine
        .store()
        .list_action_requests("direct")
        .expect("owner requests");
    assert!(owner_requests.iter().any(|request| {
        request.request_id == request_id
            && request.principal == "direct"
            && request.requester == caller
    }));
    assert!(engine
        .store()
        .list_action_requests(caller)
        .expect("caller requests")
        .is_empty());
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "grant-cross-asks-admin".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "destructive".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "connection_admin".to_string(),
            expires_at: None,
        })
        .expect("insert operator approval grant");
    let outcome = engine
        .approve_request("direct", &request_id, "direct")
        .expect("operator approves caller's parked action");
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));
    let dispatch = engine
        .store()
        .list_audit("direct")
        .expect("owner audit")
        .into_iter()
        .find(|row| row.reason_code == "dispatched")
        .expect("approved dispatch audit");
    assert_eq!(dispatch.acting_principal, caller);
    let _ = fs::remove_file(path);
}

#[test]
fn poll_constructor_refuses_non_read_catalog_states_before_authorize() {
    let (engine, path) = seed("poll-catalog-guard");
    assert!(matches!(
        engine.poll_authorization_request(
            "direct",
            "conn-1",
            "write_item",
            json!({"team": "core"}),
            "subscription-write",
            "pinned-schema",
        ),
        Err(PollAuthorizationRefusal::ActionRiskNotRead)
    ));

    add_action_with_policy(&engine, "read_quarantined", "read", "allow", "read");
    engine
        .store()
        .quarantine_action("direct", "conn-1", "read_quarantined", "catalog drift")
        .expect("quarantine read action");
    assert!(matches!(
        engine.poll_authorization_request(
            "direct",
            "conn-1",
            "read_quarantined",
            json!({}),
            "subscription-quarantined",
            "pinned-schema",
        ),
        Err(PollAuthorizationRefusal::ActionQuarantined)
    ));

    add_action_with_policy(&engine, "read_disabled", "read", "allow", "read");
    engine
        .store()
        .disable_catalog_action("direct", "conn-1", "read_disabled")
        .expect("disable read action");
    assert!(matches!(
        engine.poll_authorization_request(
            "direct",
            "conn-1",
            "read_disabled",
            json!({}),
            "subscription-disabled",
            "pinned-schema",
        ),
        Err(PollAuthorizationRefusal::ActionDisabled)
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn poll_constructor_is_load_bearing_with_write_grant_and_allow_policy() {
    let (engine, path) = seed("poll-load-bearing");
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "poll-write-ceiling".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec!["write_item".to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: None,
        })
        .expect("write poll grant");
    // The existing invoke grant and allow policy demonstrate that downstream
    // governance would otherwise accept this write.
    engine
        .authorize(write_request())
        .expect("permissive interactive path accepts write");
    let refusal = engine
        .poll_authorization_request(
            "direct",
            "conn-1",
            "write_item",
            json!({"team": "core"}),
            "subscription-write",
            "pinned-schema",
        )
        .expect_err("poll guard must refuse drifted write before authorize");
    assert_eq!(refusal, PollAuthorizationRefusal::ActionRiskNotRead);
    assert!(engine
        .store()
        .list_action_requests("direct")
        .expect("list action requests")
        .is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn severity_gate_returns_decision_plane_envelope_for_s3() {
    let (engine, path) = seed("deny-severity");
    add_action_with_policy(&engine, "destroy", "destructive", "allow", "destructive");
    let request = AuthorizationRequest::new("direct", "conn-1", "destroy", json!({"team": "core"}));
    let Err(Denial::NeedsDecisionPlane(boxed)) = engine.authorize(request) else {
        panic!("S3 actions must be sent to the decision plane");
    };
    assert_eq!(boxed.action, "destroy");
    assert_eq!(
        boxed.args_hash,
        plexus_core::jcs_sha256(&json!({"team": "core"})).expect("jcs hash")
    );
    let _ = fs::remove_file(path);
}

/// Install a minimal reviewed manifest for connection app_key `mock` at `tier`.
fn install_mock_manifest_tier(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    tier: &str,
) {
    let value = mock_manifest_value(tier);
    let ingested = ingest_value(value).expect("mock manifest ingests");
    engine
        .store()
        .upsert_manifest("system", &ingested)
        .expect("store mock manifest");
}

fn mock_manifest_value(tier: &str) -> Value {
    json!({
        "schema_version": 1,
        "key": "mock",
        "name": "Mock",
        "description": "governance unit-test vendor",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "in-process tests",
        "tier": tier,
        "transport": {
            "kind": "mcp_remote",
            "url": "https://example.invalid/mcp"
        },
        "auth": { "mode": "api_key" },
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {
            "required": ["team"],
            "optional": [],
            "write_enabling": ["team"]
        },
        "actions_baseline": [
            { "name": "write_item", "risk": "write" }
        ],
        "defaults": {
            "ask_first_risk": ["write", "destructive"],
            "rate_limit": { "calls_per_min": 30 }
        },
        "availability": "ga"
    })
}

#[test]
fn read_on_s3_floor_vendor_effective_severity_is_s2_not_s3() {
    let (engine, path) = seed("sev-read-s3");
    install_mock_manifest_tier(&engine, "S3");
    add_action_with_policy(&engine, "search", "read", "allow", "read");
    let request = AuthorizationRequest::new("direct", "conn-1", "search", json!({}));
    let reservation = engine
        .authorize(request)
        .expect("S3-floor read must reserve at S2, not escalate");
    assert_eq!(reservation.severity, Severity::S2);
    let _ = fs::remove_file(path);
}

#[test]
fn write_on_s3_floor_vendor_effective_severity_is_s3() {
    let (engine, path) = seed("sev-write-s3");
    install_mock_manifest_tier(&engine, "S3");
    // seed already has write_item with allow policy; tier floor raises it to S3.
    let Err(Denial::NeedsDecisionPlane(boxed)) = engine.authorize(write_request()) else {
        panic!("S3-floor write must escalate to the decision plane");
    };
    assert_eq!(boxed.severity, Severity::S3);
    assert_eq!(boxed.action, "write_item");
    let _ = fs::remove_file(path);
}

#[test]
fn read_on_s4_floor_vendor_effective_severity_is_s2() {
    let (engine, path) = seed("sev-read-s4");
    install_mock_manifest_tier(&engine, "S4");
    add_action_with_policy(&engine, "search", "read", "allow", "read");
    let request = AuthorizationRequest::new("direct", "conn-1", "search", json!({}));
    let reservation = engine
        .authorize(request)
        .expect("S4-floor read must reserve at S2 floor-min, not escalate");
    assert_eq!(reservation.severity, Severity::S2);
    let _ = fs::remove_file(path);
}

#[test]
fn destructive_on_s4_floor_vendor_effective_severity_is_s4() {
    let (engine, path) = seed("sev-destroy-s4");
    install_mock_manifest_tier(&engine, "S4");
    add_action_with_policy(&engine, "destroy", "destructive", "allow", "destructive");
    let request = AuthorizationRequest::new("direct", "conn-1", "destroy", json!({"team": "core"}));
    let Err(Denial::NeedsDecisionPlane(boxed)) = engine.authorize(request) else {
        panic!("S4-floor destructive must escalate to the decision plane");
    };
    assert_eq!(boxed.severity, Severity::S4);
    assert_eq!(boxed.action, "destroy");
    let _ = fs::remove_file(path);
}

#[test]
fn resource_gate_structurally_denies_write_without_enabling_filters() {
    let (engine, path) = seed("deny-resource");
    engine
        .store()
        .set_connection_filters("direct", "conn-1", &json!({}))
        .expect("clear filters");
    assert!(matches!(
        engine.authorize(write_request()),
        Err(Denial::ResourceFilter(ResourceDenial::WriteFiltersAbsent))
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn configure_makes_the_structurally_denied_write_path_reachable() {
    let (engine, path) = seed("configure-unblocks-write");
    install_mock_manifest_tier(&engine, "S2");
    // A freshly connected connection starts with empty filters, so the write
    // gate denies structurally: without configure there is no way out of this
    // state through the tool surface.
    engine
        .store()
        .set_connection_filters("direct", "conn-1", &json!({}))
        .expect("clear filters");
    assert!(
        matches!(
            engine.authorize(write_request()),
            Err(Denial::ResourceFilter(ResourceDenial::WriteFiltersAbsent))
        ),
        "unconfigured connection must deny writes"
    );

    let outcome = engine
        .store()
        .configure_connection_filters(
            "direct",
            "conn-1",
            &json!({"write_enabling": ["team"], "values": {"team": ["core"]}}),
        )
        .expect("configure filters");
    assert!(matches!(outcome, ConfigureOutcome::Configured(_)));

    // Same request, now reachable: the write gate passes and the engine
    // reserves. This is the assertion that would fail if configure did not
    // actually reach the resource gate.
    let reservation = engine
        .authorize(write_request())
        .expect("configured write must reserve");
    assert_eq!(reservation.action, "write_item");
    let _ = fs::remove_file(path);
}

#[test]
fn configure_refuses_filter_keys_the_manifest_never_declared() {
    let (engine, path) = seed("configure-undeclared");
    install_mock_manifest_tier(&engine, "S2");
    // The manifest declares write_enabling: ["team"]. Inventing a key would
    // satisfy the write gate while narrowing nothing, defeating its purpose.
    let outcome = engine
        .store()
        .configure_connection_filters("direct", "conn-1", &json!({"write_enabling": ["anything"]}))
        .expect("configure call succeeds with a typed refusal");
    assert_eq!(
        outcome,
        ConfigureOutcome::UndeclaredFilter("anything".to_string())
    );
    // The refusal must not have written a permissive document.
    engine
        .store()
        .set_connection_filters("direct", "conn-1", &json!({}))
        .expect("reset");
    assert!(matches!(
        engine.authorize(write_request()),
        Err(Denial::ResourceFilter(ResourceDenial::WriteFiltersAbsent))
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn read_with_allowlisted_resource_value_passes_resource_gate() {
    let (engine, path) = seed("read-allowlist-pass");
    engine
        .store()
        .set_connection_filters(
            "direct",
            "conn-1",
            &json!({
                "required": ["calendar_allowlist"],
                "optional": [],
                "write_enabling": [],
                "values": { "calendar_allowlist": ["primary", "work"] }
            }),
        )
        .expect("set filters");
    add_action_with_policy(&engine, "list_events", "read", "allow", "read");
    let request = AuthorizationRequest::new(
        "direct",
        "conn-1",
        "list_events",
        json!({"calendar_allowlist": "primary"}),
    );
    engine
        .authorize(request)
        .expect("allowlisted read value must pass resource gate");
    let _ = fs::remove_file(path);
}

#[test]
fn read_with_non_allowlisted_resource_value_denies_value_not_allowed() {
    let (engine, path) = seed("read-allowlist-deny");
    engine
        .store()
        .set_connection_filters(
            "direct",
            "conn-1",
            &json!({
                "required": ["calendar_allowlist"],
                "optional": [],
                "write_enabling": [],
                "values": { "calendar_allowlist": ["primary", "work"] }
            }),
        )
        .expect("set filters");
    add_action_with_policy(&engine, "list_events", "read", "allow", "read");
    let request = AuthorizationRequest::new(
        "direct",
        "conn-1",
        "list_events",
        json!({"calendar_allowlist": "forbidden"}),
    );
    assert!(matches!(
        engine.authorize(request),
        Err(Denial::ResourceFilter(ResourceDenial::ValueNotAllowed(ref key)))
            if key == "calendar_allowlist"
    ));
    let _ = fs::remove_file(path);
}

/// Intentional stale-open-read: omitting a filter key on a read does not deny.
/// A future change to require keys on reads must update this test deliberately.
#[test]
fn read_omitting_filter_key_passes_resource_gate_intentional_stale_open_read() {
    let (engine, path) = seed("read-omit-filter-key");
    engine
        .store()
        .set_connection_filters(
            "direct",
            "conn-1",
            &json!({
                "required": ["calendar_allowlist"],
                "optional": [],
                "write_enabling": [],
                "values": { "calendar_allowlist": ["primary"] }
            }),
        )
        .expect("set filters");
    add_action_with_policy(&engine, "list_events", "read", "allow", "read");
    let request = AuthorizationRequest::new("direct", "conn-1", "list_events", json!({}));
    engine
        .authorize(request)
        .expect("read omitting filter key is intentional stale-open-read (passes gate)");
    let _ = fs::remove_file(path);
}

#[test]
fn write_still_requires_required_and_write_enabling_filter_keys() {
    let (engine, path) = seed("write-filter-keys");
    engine
        .store()
        .set_connection_filters(
            "direct",
            "conn-1",
            &json!({
                "required": ["workspace"],
                "optional": [],
                "write_enabling": ["team"],
                "values": {
                    "workspace": ["acme"],
                    "team": ["core"]
                }
            }),
        )
        .expect("set filters");
    // Missing required `workspace` (team alone is not enough).
    assert!(matches!(
        engine.authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "write_item",
            json!({"team": "core"}),
        )),
        Err(Denial::ResourceFilter(ResourceDenial::MissingRequiredFilter(ref key)))
            if key == "workspace"
    ));
    // Missing write-enabling `team`.
    assert!(matches!(
        engine.authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "write_item",
            json!({"workspace": "acme"}),
        )),
        Err(Denial::ResourceFilter(ResourceDenial::MissingRequiredFilter(ref key)))
            if key == "team"
    ));
    // Both present and allowlisted → reserve.
    engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "write_item",
            json!({"workspace": "acme", "team": "core"}),
        ))
        .expect("write with required+write_enabling keys must pass resource gate");
    let _ = fs::remove_file(path);
}

#[test]
fn reference_permanent_error_refuses_dispatch_without_authority_mutation() {
    let (engine, path) = seed("deny-credential");
    engine.credential_source().set_error(
        b"test:canary-binding-handle",
        CredentialError::Permanent(PermanentCredentialError::NotFound),
    );
    let reservation = engine
        .authorize(write_request())
        .expect("reference authorization does not read the vault");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
    assert!(engine.transport().requests().is_empty());
    assert_eq!(
        engine
            .store()
            .connection("direct", "conn-1")
            .expect("connection")
            .expect("record")
            .status,
        "active"
    );
    let _ = fs::remove_file(path);
}

/// A recovery must not overwrite an authority change that lands while the
/// credential source is resolving. The source changes the row to `revoked` and
/// returns a credential, so this drives the same successful resolution path as
/// a real recovery instead of calling the store method directly.
///
/// The vault reference resolves at dispatch, after reservation creation.
#[test]
fn a_successful_credential_resolution_does_not_clear_a_revoked_connection() {
    let (engine, path) = engine_with_authority_change_during_credential_resolution(
        "auth-required-recovery-revoked",
        "revoked",
    );

    let reservation = engine
        .authorize(write_request())
        .expect("authorize reference");
    engine.revalidate_and_dispatch(&reservation);
    assert_eq!(
        engine
            .store()
            .connection("direct", "conn-1")
            .expect("connection")
            .expect("record")
            .status,
        "revoked"
    );
    let _ = fs::remove_file(path);
}

/// `pending` is an authority state as well. A credential that resolves after
/// the transition must not make the connection callable again.
///
/// The vault reference resolves at dispatch, after reservation creation.
#[test]
fn a_successful_credential_resolution_does_not_clear_a_pending_connection() {
    let (engine, path) = engine_with_authority_change_during_credential_resolution(
        "auth-required-recovery-pending",
        "pending",
    );

    let reservation = engine
        .authorize(write_request())
        .expect("authorize reference");
    engine.revalidate_and_dispatch(&reservation);
    assert_eq!(
        engine
            .store()
            .connection("direct", "conn-1")
            .expect("connection")
            .expect("record")
            .status,
        "pending"
    );
    let _ = fs::remove_file(path);
}

/// `disabled` is an authority state as well. A credential that resolves after
/// the transition must not make the connection callable again.
///
/// The vault reference resolves at dispatch, after reservation creation.
#[test]
fn a_successful_credential_resolution_does_not_clear_a_disabled_connection() {
    let (engine, path) = engine_with_authority_change_during_credential_resolution(
        "auth-required-recovery-disabled",
        "disabled",
    );

    let reservation = engine
        .authorize(write_request())
        .expect("authorize reference");
    engine.revalidate_and_dispatch(&reservation);
    assert_eq!(
        engine
            .store()
            .connection("direct", "conn-1")
            .expect("connection")
            .expect("record")
            .status,
        "disabled"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn credential_transient_error_is_bounded_retryable_without_status_flip() {
    let (engine, path) = seed("credential-transient");
    engine.credential_source().set_error(
        b"test:canary-binding-handle",
        CredentialError::Transient(plexus_core::TransientCredentialError::VaultLocked),
    );
    let reservation = engine
        .authorize(write_request())
        .expect("authorize reference");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
    assert_eq!(
        outcome.retryability,
        plexus_core::Retryability::AutoRetryable
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(
        engine
            .store()
            .connection("direct", "conn-1")
            .expect("connection")
            .expect("record")
            .status,
        "active"
    );
    let _ = fs::remove_file(path);
}

/// A vault failure at dispatch must not spend the user's approval. The vault
/// is read before the claim that consumes the approval, so a locked vault
/// leaves the approval usable: the refusal is retryable for real, the request
/// is held for the scheduler, and it is sent exactly once when the vault
/// answers again.
#[test]
fn a_locked_vault_at_dispatch_keeps_the_approval_for_a_retry() {
    let (engine, path) = seed("approval-vault-locked");
    add_connection_admin(&engine);
    let action = "vault_locked_write";
    let args = json!({"team": "core"});
    let request_id = park_write_for_direct_approval(&engine, action, &args);
    let handle = b"test:canary-binding-handle";
    engine.credential_source().set_error(
        handle,
        CredentialError::Transient(plexus_core::TransientCredentialError::VaultLocked),
    );

    let outcome = engine
        .approve_request("direct", &request_id, "direct")
        .expect("the approval is decided");
    assert!(
        matches!(&outcome.outcome, TransportOutcome::NotSent { code, .. } if code == "credential_vault_locked"),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.retryability,
        plexus_core::Retryability::AutoRetryable
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(
        approval_status(&engine, &request_id),
        "approved",
        "nothing was sent, so the approval must not be consumed"
    );

    // The vault answers again: the held approval runs once.
    engine
        .credential_source()
        .set_success(handle, b"vendor-token".to_vec(), None, 1);
    assert_eq!(engine.retry_waiting_approvals(16), 1);
    assert_eq!(engine.transport().requests().len(), 1);
    assert_eq!(approval_status(&engine, &request_id), "consumed");
    assert_eq!(engine.retry_waiting_approvals(16), 0);

    let _ = fs::remove_file(path);
}

/// A vendor 401 is reported back to the vault; a vendor 403 is not.
///
/// The report is what moves a credential to `NeedsReauth` on the vault side, so
/// a caller that never sends it leaves a dead credential looking healthy and
/// every later dispatch failing for a reason nothing records. Nothing tested
/// this: the `CredentialSource` trait supplies an empty default body for
/// `report_auth_failure`, so a source that ignores the call is indistinguishable
/// from a caller that never makes it.
///
/// The second half is the one that keeps the first from over-reporting. A 403
/// confirms authentication but rejects this resource, so it must NOT be
/// reported as an auth failure: a false report can move a working credential to
/// `NeedsReauth` on the strength of one permission refusal.
///
/// References report failures by id, not by a bearer-handle record version.
///
/// The REST transport's named 403 test mutation-proves the classifier split:
/// restoring its old `401 | 403` branch reddens that test while its 401 test
/// stays green. This integration test separately fences credential reporting.
#[test]
fn a_401_is_reported_to_the_vault_but_a_403_is_not() {
    let (engine, path) = seed("auth-report");

    // Start with a 403: it proves the source is not reported for every failed
    // dispatch before the 401 arm proves a true auth rejection is reported.
    engine.transport().set_response(MockResponse::VendorError {
        code: "http_403".to_string(),
        message: "credential lacks permission for this resource".to_string(),
    });
    let reservation = engine
        .authorize(write_request())
        .expect("authorize for the forbidden response");
    let _ = engine.revalidate_and_dispatch(&reservation);
    assert!(
        engine.credential_source().auth_failure_reports().is_empty(),
        "a 403 must not be reported as an auth failure: {:?}",
        engine.credential_source().auth_failure_reports()
    );

    // Now the real rejection.
    engine.transport().set_response(MockResponse::VendorError {
        code: "http_401".to_string(),
        message: "credential rejected".to_string(),
    });
    let reservation = engine
        .authorize(write_request())
        .expect("authorize for the auth failure");
    let _ = engine.revalidate_and_dispatch(&reservation);

    let reports = engine.credential_source().auth_failure_reports();
    assert_eq!(
        reports.len(),
        1,
        "a vendor 401 must be reported exactly once: {reports:?}"
    );
    assert_eq!(reports[0].1, 401, "the provider status must be carried");
    assert_eq!(
        reports[0].2, 0,
        "reference reports use the id-scoped route without a handle record version"
    );
    assert_eq!(
        reports[0].0,
        plexus_core::fingerprint(b"test:canary-binding-handle"),
        "the report must name the reference that was rejected"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn canary_handle_is_fingerprinted_at_every_observable_sink_except_authorization_header() {
    let (engine, path) = seed("canary");
    engine.transport().set_response(MockResponse::VendorError {
        code: "vendor_failure".to_string(),
        message: "vendor payload contains canary-binding-handle".to_string(),
    });
    let reservation = engine
        .authorize(write_request())
        .expect("authorize canary flow");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::VendorFailed { .. }
    ));
    let audit = engine.store().list_audit("direct").expect("audit rows");
    let audit_text = format!("{audit:?}");
    assert!(!audit_text.contains("test:canary-binding-handle"));
    assert!(audit_text.contains(&plexus_core::fingerprint(
        b"vault-reference:test:canary-binding-handle"
    )));
    let requests = format!("{:?}", engine.transport().requests());
    assert!(!requests.contains("test:canary-binding-handle"));
    assert!(!requests.contains("vendor-token"));
    let headers = engine.transport().authorization_headers();
    assert!(headers
        .iter()
        .any(|header| header == b"Bearer vendor-token"));
    let outcome_text = format!("{outcome:?}");
    assert!(!outcome_text.contains("test:canary-binding-handle"));
    assert!(!outcome_text.contains("vendor payload"));
    let _ = fs::remove_file(path);
}

#[test]
fn reference_binding_ticket_needs_no_key_and_is_single_use() {
    let (store, path) = test_store("binding");
    let handle = b"test:recognizable-canary-handle";
    store
        .insert_connection("direct", "conn", "mock", "pending", &json!({}))
        .expect("connection");
    let ticket = store
        .create_binding_ticket("direct", "conn", handle)
        .expect("ticket");
    assert!(store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume")
        .is_some());
    assert!(store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("second consume")
        .is_none());
    let key_path = path
        .parent()
        .expect("database parent")
        .join(".plexus-binding-key");
    assert!(!key_path.exists());
    let _ = fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn preexisting_binding_key_is_untouched_even_if_symlinked() {
    use std::os::unix::fs::PermissionsExt;
    // Obsolete key files are operator-owned cleanup, not a store dependency.
    let dir = Scratch::directory("key-mode");
    let db_path = dir.join("store.db");
    let key_path = dir.join(".plexus-binding-key");
    let seeded_key: Vec<u8> = (0_u8..32).collect();
    fs::write(&key_path, &seeded_key).expect("seed key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: "key-mode".to_string(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("store");
    store
        .insert_connection("direct", "conn", "mock", "pending", &json!({}))
        .expect("connection");
    let ticket = store
        .create_binding_ticket("direct", "conn", b"test:mode-test-handle")
        .expect("ticket");
    assert!(store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume")
        .is_some());

    let mode = fs::metadata(&key_path)
        .expect("key metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644, "open must not touch an obsolete key");
    assert_eq!(
        fs::read(&key_path).expect("key bytes"),
        seeded_key,
        "open must not rewrite the obsolete key"
    );

    // Even a symlink is irrelevant: the store never reads the obsolete key.
    let real = dir.join("elsewhere-key");
    fs::write(&real, &seeded_key).expect("target");
    fs::remove_file(&key_path).expect("unlink");
    std::os::unix::fs::symlink(&real, &key_path).expect("symlink");
    let descriptor2 = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: "key-mode-symlink".to_string(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: dir.join("store2.db").to_string_lossy().into_owned(),
        },
    };
    assert!(
        PlexusStore::open(&descriptor2).is_ok(),
        "obsolete key symlinks must not be consulted"
    );
}

#[test]
fn approved_action_request_executes_through_same_reservation_path() {
    let (engine, path) = seed("approval");
    add_action_with_policy(&engine, "approve_write", "write", "none", "write");
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "admin-grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "destructive".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "connection_admin".to_string(),
            expires_at: None,
        })
        .expect("admin grant");
    let Err(Denial::ActionRequestCreated { request_id }) = engine.authorize(
        AuthorizationRequest::new("direct", "conn-1", "approve_write", json!({"team": "core"})),
    ) else {
        panic!("write should wait for approval");
    };
    let outcome = engine
        .approve_request("direct", &request_id, "direct")
        .expect("approve and execute");
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(engine.transport().requests().len(), 1);
    let _ = fs::remove_file(path);
}

/// Give `direct` connection-admin authority so it can decide requests.
fn add_connection_admin(engine: &GovernanceEngine<StubCredentialSource, MockTransport>) {
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: "admin-grant".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "destructive".to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "connection_admin".to_string(),
            expires_at: None,
        })
        .expect("admin grant");
}

fn approval_status(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    request_id: &str,
) -> String {
    engine
        .store()
        .list_action_requests("direct")
        .expect("read requests")
        .into_iter()
        .find(|item| item.request_id == request_id)
        .expect("request exists")
        .status
}

/// Park an ask-first write and approve it without dispatching, the state an
/// executor would find after the operator's decision and before any send.
fn park_and_approve(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    action: &str,
    args: &Value,
) -> String {
    let request_id = park_write_for_direct_approval(engine, action, args);
    assert!(
        engine
            .store()
            .decide_action_request("direct", &request_id, true, "operator")
            .expect("approve request"),
        "the request must become approved"
    );
    request_id
}

/// Move a reservation's deadline into the past, as if it sat unclaimed.
fn expire_reservation(path: &Path, reservation_id: &str) {
    let conn = rusqlite::Connection::open(path).expect("open second connection");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("set busy timeout");
    let changed = conn
        .execute(
            "UPDATE reservations SET expires_at = 1 WHERE reservation_id = ?1",
            rusqlite::params![reservation_id],
        )
        .expect("expire the reservation");
    assert_eq!(changed, 1, "the reservation to expire must exist");
}

/// An approval authorizes exactly one send. The operator's approval dispatches
/// the write once; the same approval presented again for the identical call is
/// refused as consumed, not as expired, and the vendor sees one request.
#[test]
fn an_approved_write_dispatches_once_and_an_identical_retry_is_refused_as_consumed() {
    let (engine, path) = seed("approval-single-use");
    add_connection_admin(&engine);
    let action = "single_use_write";
    let args = json!({"team": "core"});
    let request_id = park_write_for_direct_approval(&engine, action, &args);

    let outcome = engine
        .approve_request("direct", &request_id, "direct")
        .expect("approve and execute");
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(approval_status(&engine, &request_id), "consumed");

    let retry = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", action, args.clone())
                .approved_from(&request_id),
        )
        .expect_err("a consumed approval must not authorize a second send");
    assert_eq!(
        retry,
        Denial::Policy(PolicyDenial::ApprovalConsumed),
        "the retry must learn the approval was used, not that it lapsed"
    );
    assert_eq!(retry.reason_code(), "approval_consumed");
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "the vendor must receive the write exactly once"
    );

    let _ = fs::remove_file(path);
}

/// A reservation that expires before it is claimed never started a send, so
/// the approval behind it stays usable, and is then consumed by the one send
/// that does start.
#[test]
fn an_approval_whose_reservation_expired_unclaimed_can_still_be_used_once() {
    let (engine, path) = seed("approval-unclaimed-reservation");
    let action = "unclaimed_write";
    let args = json!({"team": "core"});
    let request_id = park_and_approve(&engine, action, &args);
    let approved = || {
        AuthorizationRequest::new("direct", "conn-1", action, args.clone())
            .approved_from(&request_id)
    };

    let lapsed = engine.authorize(approved()).expect("first reservation");
    expire_reservation(&path, &lapsed.reservation_id);
    let outcome = engine.revalidate_and_dispatch(&lapsed);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { .. }),
        "an expired reservation must not send: {outcome:?}"
    );
    assert!(engine.transport().requests().is_empty());
    assert_eq!(
        approval_status(&engine, &request_id),
        "approved",
        "a claim that never happened must not spend the approval"
    );

    let reservation = engine.authorize(approved()).expect("second reservation");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(engine.transport().requests().len(), 1);
    assert_eq!(approval_status(&engine, &request_id), "consumed");
    assert_eq!(
        engine.authorize(approved()).expect_err("used once"),
        Denial::Policy(PolicyDenial::ApprovalConsumed)
    );

    let _ = fs::remove_file(path);
}

/// Two callers holding the same approval race to send. Both can pass
/// authorization while the approval is still `approved`, so only the claim can
/// pick a winner: exactly one dispatches.
#[test]
fn a_concurrent_pair_with_one_approval_dispatches_exactly_once() {
    let (engine, path) = seed("approval-concurrent-pair");
    let action = "raced_write";
    let args = json!({"team": "core"});
    let request_id = park_and_approve(&engine, action, &args);
    let approved = || {
        AuthorizationRequest::new("direct", "conn-1", action, args.clone())
            .approved_from(&request_id)
    };

    // The interleaving that matters, made deterministic: both reservations are
    // issued before either is claimed.
    let first = engine.authorize(approved()).expect("first reservation");
    let second = engine.authorize(approved()).expect("second reservation");
    let first_outcome = engine.revalidate_and_dispatch(&first);
    let second_outcome = engine.revalidate_and_dispatch(&second);
    assert!(
        matches!(first_outcome.outcome, TransportOutcome::Completed { .. }),
        "unexpected first outcome: {first_outcome:?}"
    );
    assert!(
        matches!(second_outcome.outcome, TransportOutcome::NotSent { .. }),
        "the losing claim must not send: {second_outcome:?}"
    );
    assert_eq!(engine.transport().requests().len(), 1);
    assert_eq!(approval_status(&engine, &request_id), "consumed");

    // The same race on real threads, against a fresh approval.
    let action = "threaded_raced_write";
    let engine = Arc::new(engine);
    let request_id = park_and_approve(&engine, action, &args);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let racers: Vec<_> = (0..2)
        .map(|_| {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            let action = action.to_string();
            let args = args.clone();
            let request_id = request_id.clone();
            bounded::Task::spawn(move || {
                barrier.wait();
                match engine.authorize(
                    AuthorizationRequest::new("direct", "conn-1", action, args)
                        .approved_from(&request_id),
                ) {
                    Ok(reservation) => matches!(
                        engine.revalidate_and_dispatch(&reservation).outcome,
                        TransportOutcome::Completed { .. }
                    ),
                    Err(denial) => {
                        assert_eq!(denial, Denial::Policy(PolicyDenial::ApprovalConsumed));
                        false
                    }
                }
            })
        })
        .collect();
    barrier.wait();
    let completed = racers
        .into_iter()
        .map(|racer| racer.join().expect("racer completion"))
        .filter(|sent| *sent)
        .count();
    assert_eq!(completed, 1, "exactly one racer may dispatch");
    assert_eq!(
        engine.transport().requests().len(),
        2,
        "one send for each approval across both races"
    );
    assert_eq!(approval_status(&engine, &request_id), "consumed");

    let _ = fs::remove_file(path);
}

/// Consumption happens when the send starts, not when an answer comes back. A
/// vendor failure or an unknown outcome still spends the approval, so a retry
/// can never re-send a write whose effect is unknown.
#[test]
fn an_approval_is_consumed_even_when_the_vendor_fails_or_the_outcome_is_unknown() {
    let (engine, path) = seed("approval-consumed-on-failure");
    add_connection_admin(&engine);
    let args = json!({"team": "core"});
    let cases = [
        (
            "vendor_failed_write",
            MockResponse::VendorError {
                code: "http_500".to_string(),
                message: "vendor failed".to_string(),
            },
        ),
        ("unknown_outcome_write", MockResponse::OutcomeUnknown),
    ];
    for (sent, (action, response)) in cases.into_iter().enumerate() {
        let request_id = park_write_for_direct_approval(&engine, action, &args);
        engine.transport().set_response(response);
        let outcome = engine
            .approve_request("direct", &request_id, "direct")
            .expect("approve and attempt");
        assert!(
            matches!(
                outcome.outcome,
                TransportOutcome::VendorFailed { .. } | TransportOutcome::OutcomeUnknown
            ),
            "{action}: unexpected outcome: {outcome:?}"
        );
        assert_eq!(
            approval_status(&engine, &request_id),
            "consumed",
            "{action}: a started send spends the approval whatever the vendor said"
        );
        assert_eq!(
            engine
                .authorize(
                    AuthorizationRequest::new("direct", "conn-1", action, args.clone())
                        .approved_from(&request_id),
                )
                .expect_err("a retry must not re-send"),
            Denial::Policy(PolicyDenial::ApprovalConsumed),
            "{action}"
        );
        assert_eq!(engine.transport().requests().len(), sent + 1, "{action}");
    }

    let _ = fs::remove_file(path);
}

/// Approving a request that is no longer pending names the state it is in:
/// already decided, already used, or genuinely lapsed.
#[test]
fn approving_a_request_that_is_no_longer_pending_names_its_state() {
    let (engine, path) = seed("approval-state-names");
    add_connection_admin(&engine);
    let args = json!({"team": "core"});

    // Approved but not yet sent.
    let request_id = park_and_approve(&engine, "decided_write", &args);
    assert_eq!(
        engine.approve_request("direct", &request_id, "direct"),
        Err(Denial::Policy(PolicyDenial::ApprovalAlreadyDecided))
    );

    // Denied.
    let request_id = park_write_for_direct_approval(&engine, "denied_write", &args);
    assert_eq!(
        engine.deny_request("direct", &request_id, "direct"),
        Ok(true)
    );
    assert_eq!(
        engine.approve_request("direct", &request_id, "direct"),
        Err(Denial::Policy(PolicyDenial::ApprovalAlreadyDecided))
    );

    // Approved and sent.
    let request_id = park_write_for_direct_approval(&engine, "sent_write", &args);
    engine
        .approve_request("direct", &request_id, "direct")
        .expect("approve and execute");
    assert_eq!(
        engine.approve_request("direct", &request_id, "direct"),
        Err(Denial::Policy(PolicyDenial::ApprovalConsumed))
    );

    // Never decided and past its window.
    let request_id = park_write_for_direct_approval(&engine, "lapsed_write", &args);
    expire_action_request(&path, &request_id);
    assert_eq!(
        engine.approve_request("direct", &request_id, "direct"),
        Err(Denial::Policy(PolicyDenial::ApprovalExpired))
    );

    assert_eq!(
        engine.transport().requests().len(),
        1,
        "only the one approval that reached a claim may send"
    );
    let _ = fs::remove_file(path);
}

/// An approval whose dispatch failed after the decision but before the claim
/// is still `approved`, and the approved-row path resumes it exactly once.
/// This is the state a restart finds when it crashed between the operator's
/// decision and the send.
#[test]
fn an_approval_that_failed_before_its_claim_resumes_exactly_once() {
    let (engine, path) = seed("approval-resume");
    add_connection_admin(&engine);
    let action = "resumed_write";
    let args = json!({"team": "core"});
    let request_id = park_write_for_direct_approval(&engine, action, &args);

    // Authorization fails after the decision: the invoke grant is gone.
    assert!(engine
        .store()
        .revoke_grant("direct", &format!("grant-{action}"))
        .expect("revoke invoke grant"));
    let failed = engine
        .approve_request("direct", &request_id, "direct")
        .expect_err("authorization must fail without an invoke grant");
    assert!(
        matches!(failed, Denial::Grant(_)),
        "unexpected refusal: {failed:?}"
    );
    assert_eq!(approval_status(&engine, &request_id), "approved");
    assert!(engine.transport().requests().is_empty());

    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-{action}-restored"),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "write".to_string(),
            action_selectors: vec![action.to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("restore invoke grant");
    let approved = || {
        AuthorizationRequest::new("direct", "conn-1", action, args.clone())
            .approved_from(&request_id)
    };
    let reservation = engine.authorize(approved()).expect("resume the approval");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::Completed { .. }),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(engine.transport().requests().len(), 1);
    assert_eq!(approval_status(&engine, &request_id), "consumed");
    assert_eq!(
        engine.authorize(approved()).expect_err("resumed once"),
        Denial::Policy(PolicyDenial::ApprovalConsumed)
    );

    let _ = fs::remove_file(path);
}
/// Revoking the grant that AUTHORIZED a reservation must invalidate it, even
/// when other grants on the same action survive.
///
/// The reservation revalidates against MAX(generation) over the SET of grants
/// matching the action, not against the grant row that actually authorized the
/// call. So when a write-ceiling grant authorizes a write and is then revoked,
/// a surviving read-ceiling grant on the same action keeps the maximum
/// unchanged, the reservation still looks fresh, and the write dispatches under
/// authority that no longer permits it. Generation counters exist to close
/// exactly this window.
#[test]
fn revoking_the_authorizing_grant_invalidates_its_reservation() {
    let (engine, path) = seed("reservation-grant-identity");
    let store = engine.store();

    // seed() installs a write-ceiling grant covering the action. Add a
    // narrower read-only grant on the SAME action: it cannot authorize a
    // write, but it does match the revalidation query.
    store
        .insert_grant(&GrantInput {
            grant_id: "grant-zz-readonly".to_string(),
            principal: "direct".to_string(),
            connection_id: "conn-1".to_string(),
            grantee_principal: "direct".to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["write_item".to_string()],
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .expect("insert narrower grant");

    let reservation = engine
        .authorize(write_request())
        .expect("write is authorized by the write-ceiling grant");

    // Revoke every write-capable grant, leaving only the read-only one.
    for grant in store
        .list_grants("direct", "conn-1")
        .expect("list grants")
        .iter()
        .filter(|grant| grant.risk_ceiling != "read")
    {
        store
            .revoke_grant("direct", &grant.grant_id)
            .expect("revoke grant");
    }

    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(&outcome.outcome, TransportOutcome::NotSent { code, .. }
            if code == "aborted_stale_authorization"),
        "revoking the authorizing grant must abort its reservation, but the \
         write dispatched under a surviving read-only grant: {:?}",
        outcome.outcome
    );
    let _ = fs::remove_file(path);
}

/// An interactive `invoke` grant must not authorize a scheduled poll, and a
/// `poll` grant must not authorize an interactive call.
///
/// This is the separation the authority chain could not otherwise express. The
/// gates key on principal, action and risk; none of them reads `actor`. So
/// without distinct authority kinds, an operator who granted invoke for their
/// own interactive use has — with no further act — authorized a daemon to read
/// on a timer indefinitely. "You may read when you ask" is not "the daemon may
/// read every N seconds until revoked".
#[test]
fn invoke_authority_does_not_authorize_a_poll_and_vice_versa() {
    let (engine, path) = seed("authority-kind-separation");
    let store = engine.store();

    // Only an invoke grant exists for this read action (installed by the
    // fixture), so it may be called interactively but not by a timer.
    add_action_with_policy(&engine, "read_item", "read", "allow", "read");
    let interactive = AuthorizationRequest::new("direct", "conn-1", "read_item", json!({}));
    assert!(
        engine.authorize(interactive).is_ok(),
        "an invoke grant must authorize an interactive call"
    );
    let read_schema_hash =
        jcs_sha256(&json!({"type": "object"})).expect("test JSON is JCS-compatible");
    let polled = engine
        .poll_authorization_request(
            "direct",
            "conn-1",
            "read_item",
            json!({}),
            "sub-1",
            read_schema_hash.clone(),
        )
        .expect("active read action can construct a poll request");
    assert!(
        matches!(
            engine.authorize(polled),
            Err(Denial::Grant(GrantDenial::Missing))
        ),
        "an invoke grant must NOT authorize a scheduled poll"
    );

    // Now add poll authority. An UNBOUNDED poll grant is accepted.
    //
    // This asserts the reversal of an earlier rule that refused to mint poll
    // authority without an expiry. That rule made the common case pay -- an
    // operator who still wanted the watch was interrupted on a schedule to
    // re-consent -- and its failure mode was silent: when the deadline passed
    // the watches simply stopped collecting, with no error anywhere, which reads
    // as a quiet week rather than as revoked authority.
    //
    // Revocation is the right remedy for a forgotten grant, not expiry, and it
    // is already frictionless. An operator who WANTS a bounded grant still
    // passes an expiry and it is still enforced on every poll.
    let unbounded = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: "conn-1",
            grantee_principal: "direct",
            authority_kind: AUTHORITY_POLL,
            requested_risk: "write",
            requested_selectors: &["write_item".to_string()],
            expires_at: None,
        })
        .expect("mint call succeeds")
        .expect("poll authority without an expiry must be MINTED, not refused");
    assert_eq!(unbounded.authority_kind, AUTHORITY_POLL);
    assert_eq!(
        unbounded.expires_at, None,
        "the minted grant must carry no deadline rather than a substituted one"
    );

    store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: "conn-1",
            grantee_principal: "direct",
            authority_kind: AUTHORITY_POLL,
            requested_risk: "read",
            requested_selectors: &["read_item".to_string()],
            expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_millis() as i64
                    + 3_600_000,
            ),
        })
        .expect("mint bounded poll grant")
        .expect("bounded poll authority is accepted");

    let polled = engine
        .poll_authorization_request(
            "direct",
            "conn-1",
            "read_item",
            json!({}),
            "sub-1",
            read_schema_hash,
        )
        .expect("active read action can construct a poll request");
    let reservation = engine
        .authorize(polled)
        .expect("a poll grant authorizes a scheduled poll");
    assert_eq!(
        reservation.actor, "trigger:sub-1",
        "a poll must be attributable to its subscription in the audit trail"
    );
    let _ = fs::remove_file(path);
}

/// A `resource_filters` key that configure does not read is refused, and the
/// two keys it does read are still accepted.
///
/// Configure reads exactly `write_enabling` and `values`. A near-miss such as
/// `write_enabled` was previously stored as a success while `write_enabling`
/// resolved EMPTY -- so every write stayed blocked while the operator was told
/// the connection had been configured. That direction is fail-closed, which is
/// why this is a usability defect rather than a security one, and it is worth
/// refusing anyway: a success response beside filters that do not reflect the
/// request is a debugging session that starts at the vendor and ends at a
/// spelling mistake.
///
/// The accept leg is asserted because refusing every request would satisfy the
/// refusal assertion alone while breaking configure entirely.
///
/// Mutation-proved: dropping the unread-key check stores the typo as a success;
/// removing `values` from the accepted list refuses a legitimate request.
#[test]
fn configure_refuses_a_key_it_does_not_read() {
    let (engine, path) = seed("configure-unread-key");
    install_mock_manifest_tier(&engine, "S2");

    let outcome = engine
        .store()
        .configure_connection_filters("direct", "conn-1", &json!({"write_enabled": ["team"]}))
        .expect("configure call succeeds with a typed refusal");
    assert!(
        matches!(
            outcome,
            ConfigureOutcome::UnreadFilterKey { ref key, .. } if key == "write_enabled"
        ),
        "a key configure never reads must be refused rather than stored: {outcome:?}"
    );

    // The refusal must not have written anything. Asserted against the STORED
    // document rather than against a later authorize call, because this fixture
    // seeds usable filters -- so a write would succeed either way and could not
    // distinguish "refused and stored nothing" from "refused and overwrote".
    let stored = engine
        .store()
        .connection("direct", "conn-1")
        .expect("read connection")
        .expect("connection exists")
        .resource_filters;
    assert_eq!(
        stored,
        json!({"required": ["team"], "write_enabling": ["team"]}),
        "a refused configure must leave the previous filters exactly as they were"
    );

    // Both read keys are still accepted together, so the check narrows rather
    // than blocking the operation it guards.
    let outcome = engine
        .store()
        .configure_connection_filters(
            "direct",
            "conn-1",
            &json!({"write_enabling": ["team"], "values": {"team": ["core"]}}),
        )
        .expect("configure call succeeds");
    assert!(
        matches!(outcome, ConfigureOutcome::Configured(_)),
        "a request using only the read keys must be accepted: {outcome:?}"
    );

    let _ = std::fs::remove_file(path);
}

/// A request part with the wrong JSON shape is refused with an error naming
/// that part, and stores nothing, rather than being dropped beside a
/// "configured" reply.
#[test]
fn configure_refuses_malformed_filters_and_stores_nothing() {
    let (engine, path) = seed("configure-malformed");
    install_mock_manifest_tier(&engine, "S2");
    let before = engine
        .store()
        .connection("direct", "conn-1")
        .unwrap()
        .unwrap()
        .resource_filters;
    for (request, field) in [
        (json!("team"), "resource_filters"),
        (json!(["team"]), "resource_filters"),
        (json!({"write_enabling": "team"}), "write_enabling"),
        (json!({"write_enabling": ["team", 7]}), "write_enabling"),
        (json!({"values": ["core"]}), "values"),
    ] {
        let outcome = engine
            .store()
            .configure_connection_filters("direct", "conn-1", &request)
            .expect("configure call");
        assert!(
            matches!(outcome, ConfigureOutcome::MalformedFilters { field: ref named, .. } if named == field),
            "{request}: {outcome:?}"
        );
        assert_eq!(
            engine
                .store()
                .connection("direct", "conn-1")
                .unwrap()
                .unwrap()
                .resource_filters,
            before,
            "{request}: nothing may be stored"
        );
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn verified_agent_subject_is_carried_through_accepted_reservation_audit() {
    // The tested mutation drops the verified subject from authorization or
    // reservation; either change makes an accepted audit row lose attribution.
    let (engine, path) = seed("assertion-attribution");
    let reservation = engine
        .authorize(write_request().with_bound_agent("agent_verified", "plex-verified[bot]"))
        .expect("verified request reserves");
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(matches!(
        outcome.outcome,
        TransportOutcome::Completed { .. }
    ));

    let rows = engine.store().list_audit("direct").expect("read audit");
    assert!(rows.iter().any(|row| {
        row.decision == "allow"
            && row.agent_id.as_deref() == Some("agent_verified")
            && row.agent_handle.as_deref() == Some("plex-verified[bot]")
    }));
    fs::remove_file(path).expect("remove test store");
}

#[test]
fn authorization_audit_decision_preserves_argument_hash_bytes() {
    let (engine, path) = seed("audit-argument-hash");
    for (request_id, args) in [
        (
            "audit-first",
            json!({"team": "core", "z": [null, true, {"b": 2, "a": "é\n"}], "a": 1}),
        ),
        (
            "audit-second",
            json!({"team": "core", "body": "different request", "nested": {"z": false, "a": [3, 2, 1]}}),
        ),
    ] {
        let expected = format!(
            "args_hash:{}",
            jcs_sha256(&args).expect("test JSON is JCS-compatible")
        );
        engine
            .authorize(
                AuthorizationRequest::new("direct", "conn-1", "write_item", args)
                    .with_request_id(request_id),
            )
            .expect("authorize decision");
        let rows = engine.store().list_audit("direct").expect("read audit");
        let rows: Vec<_> = rows
            .iter()
            .filter(|row| row.request_id.as_deref() == Some(request_id))
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].gate.as_deref(), Some("credential"));
        assert_eq!(rows[0].decision, "allow");
        assert_eq!(
            rows[0].args_redaction_summary.as_deref(),
            Some(expected.as_str()),
            "request {request_id}"
        );
    }
    drop(engine);
    let _ = fs::remove_file(path);
}

#[test]
fn early_denial_audit_preserves_argument_hash_bytes() {
    let (engine, path) = seed("denial-argument-hash");
    let args = json!({"team": "core", "nested": {"z": [null, 7], "a": "denied"}});
    let expected = format!(
        "args_hash:{}",
        jcs_sha256(&args).expect("test JSON is JCS-compatible")
    );
    assert!(matches!(
        engine.authorize(
            AuthorizationRequest::new("direct", "missing-connection", "write_item", args)
                .with_request_id("audit-denied"),
        ),
        Err(Denial::Connection(ConnectionDenial::NotFound))
    ));
    let rows = engine.store().list_audit("direct").expect("read audit");
    let rows: Vec<_> = rows
        .iter()
        .filter(|row| row.request_id.as_deref() == Some("audit-denied"))
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision, "deny");
    assert_eq!(rows[0].gate.as_deref(), Some("connection"));
    assert_eq!(
        rows[0].args_redaction_summary.as_deref(),
        Some(expected.as_str())
    );
    drop(engine);
    let _ = fs::remove_file(path);
}

#[test]
fn revoked_grant_refuses_invoke() {
    let (engine, path) = seed("revoked-invoke");
    assert!(engine.authorize(write_request()).is_ok());
    engine.store().revoke_grant("direct", "grant-1").unwrap();
    assert!(matches!(
        engine.authorize(write_request()),
        Err(Denial::Grant(GrantDenial::Missing))
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn revoked_grant_refuses_poll() {
    let (engine, path) = seed("revoked-poll");
    add_action_with_policy(&engine, "read_item", "read", "allow", "read");
    let grant = engine
        .store()
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: "conn-1",
            grantee_principal: "direct",
            authority_kind: AUTHORITY_POLL,
            requested_risk: "read",
            requested_selectors: &["read_item".to_string()],
            expires_at: None,
        })
        .unwrap()
        .unwrap();
    let request = || {
        engine
            .poll_authorization_request(
                "direct",
                "conn-1",
                "read_item",
                json!({}),
                "sub-1",
                jcs_sha256(&json!({"type": "object"})).unwrap(),
            )
            .unwrap()
    };
    assert!(engine.authorize(request()).is_ok());
    engine
        .store()
        .revoke_grant("direct", &grant.grant_id)
        .unwrap();
    assert!(matches!(
        engine.authorize(request()),
        Err(Denial::Grant(GrantDenial::Missing))
    ));
    let _ = fs::remove_file(path);
}

#[path = "support/audit.rs"]
mod audit_test;

#[test]
fn authorization_audit_failure_is_loud_and_preserves_reservation() {
    if audit_test::captured_by_parent(
        "authorization_audit_failure_is_loud_and_preserves_reservation",
        "authorization decision=\"allow\"",
    ) {
        return;
    }
    for fail in [false, true] {
        let (engine, path) = seed("authorization-audit-failure");
        if fail {
            audit_test::reject_inserts(&path);
        }
        let reservation = engine
            .authorize(write_request())
            .expect("audit failure must not revoke permission");
        assert_eq!(
            engine
                .store()
                .reservation("direct", &reservation.reservation_id)
                .unwrap()
                .unwrap()
                .status,
            "reserved"
        );
        assert!(engine.transport().requests().is_empty());
        assert_eq!(
            engine.store().list_audit("direct").unwrap().len(),
            usize::from(!fail)
        );
        drop(engine);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn dispatch_denial_audit_failure_is_loud_and_preserves_refusal() {
    if audit_test::captured_by_parent(
        "dispatch_denial_audit_failure_is_loud_and_preserves_refusal",
        "dispatch denial",
    ) {
        return;
    }
    for fail in [false, true] {
        let (engine, path) = seed("dispatch-denial-audit-failure");
        let reservation = engine.authorize(write_request()).unwrap();
        engine.store().revoke_grant("direct", "grant-1").unwrap();
        if fail {
            audit_test::reject_inserts(&path);
        }
        let result = engine.revalidate_and_dispatch(&reservation);
        assert!(matches!(result.outcome, TransportOutcome::NotSent { .. }));
        assert!(engine.transport().requests().is_empty());
        assert_eq!(
            engine.store().list_audit("direct").unwrap().len(),
            if fail { 1 } else { 2 }
        );
        drop(engine);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn dispatch_result_audit_failure_is_loud_and_preserves_completion() {
    if audit_test::captured_by_parent(
        "dispatch_result_audit_failure_is_loud_and_preserves_completion",
        "dispatch result",
    ) {
        return;
    }
    for fail in [false, true] {
        let (engine, path) = seed("dispatch-result-audit-failure");
        let reservation = engine.authorize(write_request()).unwrap();
        if fail {
            audit_test::reject_inserts(&path);
        }
        let result = engine.revalidate_and_dispatch(&reservation);
        assert!(matches!(result.outcome, TransportOutcome::Completed { .. }));
        assert_eq!(engine.transport().requests().len(), 1);
        assert_eq!(
            engine
                .store()
                .reservation("direct", &reservation.reservation_id)
                .unwrap()
                .unwrap()
                .status,
            "dispatched"
        );
        assert_eq!(
            engine.store().list_audit("direct").unwrap().len(),
            if fail { 1 } else { 2 }
        );
        drop(engine);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn reconciliation_audit_failure_is_loud_and_preserves_result() {
    if audit_test::captured_by_parent(
        "reconciliation_audit_failure_is_loud_and_preserves_result",
        "reconciliation status=\"ambiguous\"",
    ) {
        return;
    }
    for fail in [false, true] {
        let (engine, path) = seed("reconciliation-audit-failure");
        if fail {
            audit_test::reject_inserts(&path);
        }
        let result = engine.reconcile(&plexus_core::OutcomeUnknownRecord {
            request_id: "audit-reconcile".into(),
            principal: "direct".into(),
            acting_principal: "direct".into(),
            actor: "direct".into(),
            connection_id: "conn-1".into(),
            action: "write_item".into(),
            args: json!({}),
            occurred_at_ms: now_ms(),
        });
        assert_eq!(
            result,
            plexus_core::ReconcileResult::Ambiguous {
                reason: "reconciliation_class_missing".into()
            }
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        let status: String = conn.query_row("SELECT status FROM write_reconciliation_results WHERE request_id='audit-reconcile'", [], |row| row.get(0)).unwrap();
        assert_eq!(status, "ambiguous");
        assert_eq!(
            engine.store().list_audit("direct").unwrap().len(),
            usize::from(!fail)
        );
        drop(conn);
        drop(engine);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn approval_match_refuses_distinct_large_integers() {
    let (engine, _path) = seed("approval-exact-integer");
    let args = json!({"team": "core", "n": 9007199254740992_u64});
    let changed = json!({"team": "core", "n": 9007199254740993_u64});
    assert_eq!(
        plexus_core::jcs_sha256(&args).unwrap(),
        plexus_core::jcs_sha256(&changed).unwrap()
    );
    let id = park_write_for_direct_approval(&engine, "exact_write", &args);
    assert!(engine
        .store()
        .decide_action_request("direct", &id, true, "operator")
        .unwrap());
    let denial = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", "exact_write", changed)
                .approved_from(id.clone()),
        )
        .expect_err("different integer must not use approval");
    assert!(matches!(
        denial,
        Denial::Policy(PolicyDenial::ApprovalShapeMismatch)
    ));
    let reservation = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", "exact_write", args).approved_from(id),
        )
        .expect("exact approved arguments remain usable");
    assert!(matches!(
        engine.revalidate_and_dispatch(&reservation).outcome,
        TransportOutcome::Completed { .. }
    ));
    assert_eq!(engine.transport().requests().len(), 1);
}

#[test]
fn dispatch_staleness_refuses_distinct_large_integers() {
    let (engine, _path) = seed("dispatch-exact-integer");
    let args = json!({"team": "core", "n": 9007199254740992_u64});
    let id = park_write_for_direct_approval(&engine, "exact_write", &args);
    assert!(engine
        .store()
        .decide_action_request("direct", &id, true, "operator")
        .unwrap());
    let mut reservation = engine
        .authorize(
            AuthorizationRequest::new("direct", "conn-1", "exact_write", args).approved_from(id),
        )
        .unwrap();
    reservation.args["n"] = json!(9007199254740993_u64);
    assert_eq!(
        plexus_core::jcs_sha256(&reservation.args).unwrap(),
        reservation.approved_args_hash
    );
    let outcome = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization")
    );
    assert!(engine.transport().requests().is_empty());
}

/// When this instance turns out not to hold the connector home at dispatch,
/// nothing is sent, and the refusal is final for that reservation: it is
/// recorded in the audit journal and the reservation can never be claimed
/// later, by this engine or another that does hold the home.
#[test]
fn a_connector_home_trip_at_dispatch_abandons_and_audits_the_reservation() {
    let (engine, path) = seed("connector-home-trip");
    let reservation = engine
        .authorize(write_request())
        .expect("an allowed write reserves");
    let guarded = engine
        .clone()
        .with_connector_home_guard(Arc::new(|| Some(json!({"holder": "elsewhere"}))));
    let outcome = guarded.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(&outcome.outcome, TransportOutcome::NotSent { code, .. } if code == "connector_home_not_held"),
        "{outcome:?}"
    );
    let audit = engine.store().list_audit("direct").expect("audit");
    assert!(
        audit
            .iter()
            .any(|row| row.reason_code == "connector_home_not_held"
                && row.outcome.as_deref() == Some("not_sent")),
        "the refusal is audited: {audit:?}"
    );
    let later = engine.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(later.outcome, TransportOutcome::NotSent { .. }),
        "an abandoned reservation must not be sent later: {later:?}"
    );
    assert!(engine.transport().requests().is_empty());
    let _ = fs::remove_file(path);
}

/// An app whose reviewed tier cannot be established (no system manifest) is
/// gated at the strongest tier, never the weakest. A write on it needs the
/// decision plane, so with none configured it is refused and nothing is sent.
/// A read is still capped at S2 and goes through.
#[test]
fn a_write_on_an_app_without_a_system_manifest_is_refused_not_dispatched() {
    let (engine, path) = seed("severity-no-manifest");
    rusqlite::Connection::open(&path as &Path)
        .expect("open store file")
        .execute(
            "DELETE FROM app_manifests WHERE principal = 'system' AND key = 'mock'",
            [],
        )
        .expect("remove the app's reviewed manifest");
    let denial = engine
        .authorize(write_request())
        .expect_err("a write whose app tier is unknown must not reserve as a low-severity write");
    assert!(
        matches!(denial, Denial::Severity(_) | Denial::NeedsDecisionPlane(_)),
        "an unknown tier routes the write to the decision plane: {denial:?}"
    );
    assert!(engine.transport().requests().is_empty());

    add_action_with_policy(&engine, "search", "read", "allow", "read");
    let read = engine
        .authorize(AuthorizationRequest::new(
            "direct",
            "conn-1",
            "search",
            json!({}),
        ))
        .expect("a read is capped at S2 whatever the tier");
    assert_eq!(read.severity, Severity::S2);
    let _ = fs::remove_file(path);
}

/// Connection ids are unique only per owner. When two owners each have a
/// connection called `mail`, a recipient one owner allowlisted must not let the
/// other owner's send skip the ask-first that an unlisted recipient gets.
#[test]
fn one_owners_recipient_entry_does_not_authorize_another_owners_send() {
    let (store, _path) = test_store("recipient-owners");
    let manifest = ingest_value(json!({
        "schema_version":1,"key":"messaging_fixture","name":"Messaging fixture",
        "description":"send fixture","reuse_path":"openapi_shim","reuse_rationale":"fixture",
        "tier":"S1","transport":{"kind":"rest_api","url":"http://127.0.0.1:0"},
        "auth":{"mode":"none"},"credential_bindings":[],
        "resource_filters":{"required":[],"optional":[],"write_enabling":["to"]},
        "actions_baseline":[{"name":"send","risk":"write","recipients":["/to"],"http":{"method":"POST","path":"/send","args_schema":{
            "type":"object","properties":{"to":{"type":"string"},"text":{"type":"string"}},"additionalProperties":false
        }}}],
        "defaults":{"ask_first_risk":["write"],"rate_limit":{"calls_per_min":60}},"availability":"ga"
    }))
    .expect("fixture manifest");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &manifest)
        .unwrap();
    for owner in ["owner-a", "owner-b"] {
        store
            .insert_connection(
                owner,
                "mail",
                "messaging_fixture",
                "active",
                &json!({"required":[],"optional":[],"write_enabling":["to"]}),
            )
            .unwrap();
        store
            .seed_catalog_from_manifest(owner, "mail", "messaging_fixture")
            .unwrap();
        store
            .insert_grant(&GrantInput {
                grant_id: format!("invoke-{owner}"),
                principal: owner.into(),
                connection_id: "mail".into(),
                grantee_principal: owner.into(),
                risk_ceiling: "write".into(),
                action_selectors: vec!["send".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        store
            .set_policy(owner, "mail", "send", "allow", None)
            .unwrap();
    }
    store
        .change_recipient("owner-a", "mail", None, "alice@example.com", true, true)
        .unwrap();
    let engine = GovernanceEngine::new(
        Arc::new(store),
        Arc::new(StubCredentialSource::default()),
        Arc::new(MockTransport::default()),
    );
    let send = |owner: &str| {
        engine.authorize(AuthorizationRequest::new(
            owner,
            "mail",
            "send",
            json!({"to":"alice@example.com","text":"hello"}),
        ))
    };
    assert!(
        send("owner-a").is_ok(),
        "positive control: the owner that listed the recipient sends under allow"
    );
    let other = send("owner-b");
    assert!(
        matches!(other, Err(Denial::ActionRequestCreated { .. })),
        "owner-b never listed the recipient, so its send must ask first: {other:?}"
    );
}

fn mock_manifest() -> plexus_core::IngestedManifest {
    ingest_value(json!({
        "schema_version": 1, "key": "mock", "name": "Mock", "description": "retirement fixture",
        "reuse_path": "mcp_direct", "reuse_rationale": "tests", "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"}, "credential_bindings": [],
        "resource_filters": {"required": ["team"], "optional": [], "write_enabling": ["team"]},
        "actions_baseline": [{"name": "write_item", "risk": "write"}],
        "defaults": {"ask_first_risk": [], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    }))
    .expect("fixture manifest")
}

/// Retiring an app's manifest stops live traffic: calls are refused as
/// disabled and active watches are suspended as `app_retired`. The manifest
/// coming back restores calls and resumes only those watches, cursors intact;
/// a watch suspended for another reason stays suspended.
#[test]
fn retiring_an_app_refuses_calls_and_suspends_watches_until_it_returns() {
    let (engine, path) = seed("retire-app");
    let store = engine.store().clone();
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &mock_manifest())
        .unwrap();
    // Watches may poll only read actions named by an unrevoked, unexpired poll
    // grant. Use its real schema pin so app return tests that authority check.
    let schema = json!({"type":"object"});
    let hash = plexus_core::jcs_sha256(&schema).unwrap();
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            principal: "direct".into(),
            connection_id: "conn-1".into(),
            name: "read_items".into(),
            title: None,
            schema,
            schema_hash: hash.clone(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    store
        .insert_grant(&GrantInput {
            grant_id: "retirement-poll".into(),
            principal: "direct".into(),
            connection_id: "conn-1".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["read_items".into()],
            authority_kind: "poll".into(),
            expires_at: None,
        })
        .unwrap();
    let db = rusqlite::Connection::open(path.path()).unwrap();
    db.execute(
        "INSERT INTO trigger_subscriptions (subscription_id, principal, connection_id, action,
            cadence_s, cursor_kind, cursor_state, schema_hash, status, suspended_reason, created_at_ms)
         VALUES ('watch-live', 'direct', 'conn-1', 'read_items', 60, 'sync_token',
                 '{\"sync_token\":\"kept\"}', ?1, 'active', NULL, 1),
                ('watch-held', 'direct', 'conn-1', 'read_items', 60, 'sync_token',
                 '{}', ?1, 'suspended', 'schema_changed', 1);",[hash]
    )
    .unwrap();
    let watch = |id: &str| -> (String, Option<String>, String) {
        db.query_row(
            "SELECT status, suspended_reason, cursor_state FROM trigger_subscriptions
             WHERE subscription_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };
    let disabled = |result: &Result<plexus_core::Reservation, Denial>| {
        matches!(result, Err(Denial::Catalog(CatalogDenial::Disabled)))
    };
    assert!(
        !disabled(&engine.authorize(write_request())),
        "positive control: a live app's call is not refused as disabled"
    );

    let retired = store
        .retire_absent_manifests(plexus_core::CATALOG_PRINCIPAL, &["other".to_string()])
        .unwrap();
    assert_eq!(retired, vec!["mock".to_string()]);
    let refused = engine.authorize(write_request());
    assert!(
        disabled(&refused),
        "a retired app's call must be refused: {refused:?}"
    );
    assert_eq!(
        store
            .catalog_action("direct", "conn-1", "write_item")
            .unwrap()
            .unwrap()
            .quarantine_reason
            .as_deref(),
        Some("app_retired")
    );
    assert_eq!(
        watch("watch-live"),
        (
            "suspended".into(),
            Some("app_retired".into()),
            "{\"sync_token\":\"kept\"}".into()
        ),
        "retirement must suspend the app's active watches"
    );
    assert_eq!(watch("watch-held").1.as_deref(), Some("schema_changed"));

    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &mock_manifest())
        .unwrap();
    assert!(
        !disabled(&engine.authorize(write_request())),
        "a returning manifest restores calls"
    );
    assert_eq!(
        watch("watch-live"),
        ("active".into(), None, "{\"sync_token\":\"kept\"}".into())
    );
    assert_eq!(
        watch("watch-held"),
        (
            "suspended".into(),
            Some("schema_changed".into()),
            "{}".into()
        ),
        "a watch suspended for another reason stays suspended"
    );
}

/// The fixture's `send` is a read action on purpose. Every write action
/// requires approval before it runs (`ask_first`) regardless of recipients,
/// so only a read shows whether a recipient declaration turns that on.
fn messaging_manifest(recipients: bool) -> plexus_core::IngestedManifest {
    let mut manifest = json!({
        "schema_version":1,"key":"messaging_fixture","name":"Messaging fixture",
        "description":"send fixture","reuse_path":"openapi_shim","reuse_rationale":"fixture",
        "tier":"S1","transport":{"kind":"rest_api","url":"http://127.0.0.1:0"},
        "auth":{"mode":"none"},"credential_bindings":[],
        "resource_filters":{"required":[],"optional":[],"write_enabling":["to"]},
        "actions_baseline":[{"name":"send","risk":"read","http":{"method":"POST","path":"/send","args_schema":{
            "type":"object","properties":{"to":{"type":"string"}},"additionalProperties":false
        }}}],
        "defaults":{"ask_first_risk":[],"rate_limit":{"calls_per_min":60}},"availability":"ga"
    });
    if recipients {
        manifest["actions_baseline"][0]["recipients"] = json!(["/to"]);
    }
    ingest_value(manifest).expect("fixture manifest")
}

/// A recipient declaration added to the reviewed manifest reaches connections
/// that already existed: their `send` row asks first, like a new
/// connection's, and only reservations on that app's connections are
/// invalidated, matched by owner as well as id.
#[test]
fn a_new_recipient_declaration_reaches_existing_connections_of_that_app_only() {
    let (store, path) = test_store("recipient-declaration");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &messaging_manifest(false))
        .unwrap();
    store
        .insert_connection("owner-a", "mail", "messaging_fixture", "active", &json!({}))
        .unwrap();
    store
        .seed_catalog_from_manifest("owner-a", "mail", "messaging_fixture")
        .unwrap();
    // Another app's connection with the same id under another owner.
    store
        .insert_connection("owner-b", "mail", "other_app", "active", &json!({}))
        .unwrap();
    assert!(
        !store
            .catalog_action("owner-a", "mail", "send")
            .unwrap()
            .unwrap()
            .ask_first,
        "precondition: before any recipient declaration the row does not ask first"
    );
    let db = rusqlite::Connection::open(path.path()).unwrap();
    db.execute_batch(
        "INSERT INTO reservations(reservation_id,principal,connection_id,action,snapshot_generations,
            approved_args_hash,schema_hash,expires_at,status,created_at_ms)
         VALUES ('r-a','owner-a','mail','send','{}','h','h',9007199254740991,'reserved',1),
                ('r-b','owner-b','mail','send','{}','h','h',9007199254740991,'reserved',1);",
    )
    .unwrap();

    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &messaging_manifest(true))
        .unwrap();

    assert!(
        store
            .catalog_action("owner-a", "mail", "send")
            .unwrap()
            .unwrap()
            .ask_first,
        "a newly declared recipient must make the existing row ask first"
    );
    let status = |id: &str| -> String {
        db.query_row(
            "SELECT status FROM reservations WHERE reservation_id = ?1",
            [id],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(status("r-a"), "invalidated");
    assert_eq!(
        status("r-b"),
        "reserved",
        "another app's reservation is untouched"
    );
}
