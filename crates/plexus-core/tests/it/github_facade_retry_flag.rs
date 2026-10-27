use crate::facade_rows;
use crate::scope_support::{delegating_scope, LiveScopeReader};
use plexus_core::github::facade::bot_request_scoped;
use plexus_core::governance::GovernanceEngine;
use plexus_core::scope::CallScope;
use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
use plexus_core::transport::{MockResponse, MockTransport};
use plexus_core::PlexusStore;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::sync::Arc;

type Setup = (
    plexus_core::test_scratch::Scratch,
    Arc<PlexusStore>,
    GovernanceEngine<plexus_core::credentials::StubCredentialSource, MockTransport>,
    Arc<MockTransport>,
    CallScope,
);

fn github_manifest() -> plexus_core::AppManifest {
    parse_catalog_source(include_str!(concat!(
        "../",
        "../../../catalog/github_rest.jsonc"
    )))
}

fn parse_catalog_source(source: &str) -> plexus_core::AppManifest {
    let clean = subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
    plexus_core::ingest_value(serde_json::from_str(&clean).unwrap())
        .unwrap()
        .manifest
}

fn setup(label: &str, actions: &[(&str, &str)]) -> Setup {
    let (scratch, store) = crate::scratch_store::open(label);
    let store = Arc::new(store);
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
    let manifest = github_manifest();
    facade_rows::insert_reviewed_manifest(&db, &serde_json::to_string(&manifest).unwrap());
    let selectors =
        serde_json::to_string(&actions.iter().map(|(action, _)| action).collect::<Vec<_>>())
            .unwrap();
    for (name, risk) in actions {
        let schema = manifest
            .actions_baseline
            .iter()
            .find(|declared| declared.name == *name)
            .and_then(|declared| declared.http.as_ref())
            .map_or_else(|| json!({}), |http| http.args_schema.clone());
        facade_rows::insert_catalog_action(&db, name, risk, &schema.to_string(), false);
    }
    for (grant, grantee, agent) in [
        ("module", plexus_core::github::AFT_PRINCIPAL, None),
        (
            "agent",
            plexus_core::github::AFT_PRINCIPAL,
            Some("agent-fixture"),
        ),
    ] {
        facade_rows::insert_invoke_grant(&db, grant, grantee, &selectors, agent);
    }
    let scope = delegating_scope("agent-fixture");
    let transport = Arc::new(MockTransport::default());
    let seams = GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(Token)),
    };
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(
            plexus_core::credentials::StubCredentialSource::with_default_success(b"test".to_vec()),
        ),
        transport.clone(),
    )
    .with_governance_seams(Arc::new(seams))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    (scratch, store, engine, transport, scope)
}

struct Token;
impl plexus_core::github::credential::HandleCredentialProvider for Token {
    fn prepare(
        &self,
        _: &str,
        _: i64,
        _: &str,
    ) -> Result<plexus_core::credentials::ResolvedCredential, &'static str> {
        Ok(plexus_core::credentials::ResolvedCredential::anonymous())
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

fn reaction_request() -> Value {
    json!({"action":"issue reaction","repository":"org/repo","target":{"number":"42"},"body":{"reaction":"eyes"}})
}

// Admission checks before the receipt is claimed keep the same nonce safe to retry.
#[test]
fn g1_early_refusal_carries_retry_true() {
    let (_scratch, store, engine, _transport, _scope) =
        setup("retry-g1", &[("add_reaction", "write")]);
    let refused = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        None,
        &reaction_request(),
        "g1-nonce",
        "g1-id",
        "worker",
        plexus_core::now_ms(),
    );
    assert_eq!(
        refused["result"]["refusal_code"],
        "delegating_scope_required"
    );
    assert_eq!(refused["result"]["retry_same_nonce"], json!(true));
}

// A 429 releases the claim without recording a refusal, so the same nonce
// resumes at the first unsent write step.
#[test]
fn released_retryable_429_carries_retry_true() {
    let (_scratch, store, engine, transport, scope) =
        setup("retry-429", &[("add_reaction", "write")]);
    transport.set_response(MockResponse::VendorError {
        code: "http_429".into(),
        message: "limited".into(),
    });
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reaction_request(),
        "retry-429-nonce",
        "retry-429-id",
        "worker",
        now,
    );
    assert_eq!(
        first["result"]["refusal_code"],
        "vendor_rejected{status: 429}"
    );
    assert_eq!(first["result"]["retry_same_nonce"], json!(true));
    // A released claim leaves the receipt pending, not finished as refused.
    let row = store
        .github_receipt("agent-fixture", "retry-429-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "pending");
}

// A 403 finishes the receipt as refused, so the same nonce replays it.
#[test]
fn terminal_refusal_carries_retry_false() {
    let (_scratch, store, engine, transport, scope) =
        setup("retry-403", &[("add_reaction", "write")]);
    transport.set_response(MockResponse::VendorError {
        code: "http_403".into(),
        message: "forbidden".into(),
    });
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reaction_request(),
        "retry-403-nonce",
        "retry-403-id",
        "worker",
        now,
    );
    assert_eq!(
        first["result"]["refusal_code"],
        "vendor_rejected{status: 403}"
    );
    assert_eq!(first["result"]["retry_same_nonce"], json!(false));
    let row = store
        .github_receipt("agent-fixture", "retry-403-nonce")
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "refused");
}

// Replaying a terminal refusal with the same nonce returns the same bytes,
// including the false flag.
#[test]
fn stored_terminal_replay_carries_retry_false() {
    let (_scratch, store, engine, transport, scope) =
        setup("retry-replay", &[("add_reaction", "write")]);
    transport.set_response(MockResponse::VendorError {
        code: "http_403".into(),
        message: "forbidden".into(),
    });
    let now = plexus_core::now_ms();
    let first = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reaction_request(),
        "retry-replay-nonce",
        "retry-replay-id",
        "worker",
        now,
    );
    assert_eq!(first["result"]["retry_same_nonce"], json!(false));
    let replay = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reaction_request(),
        "retry-replay-nonce",
        "retry-replay-id-2",
        "worker",
        now + 1,
    );
    assert_eq!(replay["result"], first["result"]);
    assert_eq!(replay["result"]["retry_same_nonce"], json!(false));
    assert_eq!(transport.requests().len(), 1);
}

// Another owner holds the receipt, so the caller waits and retries the nonce.
#[test]
fn nonce_in_flight_carries_retry_true() {
    let (_scratch, store, engine, transport, scope) =
        setup("retry-inflight", &[("add_reaction", "write")]);
    let now = plexus_core::now_ms();
    let claim = plexus_core::github::facade::gates::run_scoped(
        &*store,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reaction_request(),
        "retry-flight-nonce",
        "retry-flight-id",
        "owner",
        now,
        120,
    );
    assert!(matches!(
        claim.claim,
        Some(plexus_core::github::receipt::Claim::Owned(_))
    ));
    store
        .mark_github_dispatch(
            "agent-fixture",
            "retry-flight-nonce",
            "owner",
            0,
            now,
            "retry-flight-id",
        )
        .unwrap();
    let refused = bot_request_scoped(
        &store,
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        Some(&scope),
        &reaction_request(),
        "retry-flight-nonce",
        "retry-flight-id-2",
        "next",
        now + 1,
    );
    assert_eq!(refused["result"]["refusal_code"], "nonce_in_flight");
    assert_eq!(refused["result"]["retry_same_nonce"], json!(true));
    assert!(transport.requests().is_empty());
}
