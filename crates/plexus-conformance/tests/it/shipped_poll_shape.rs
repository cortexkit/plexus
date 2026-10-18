//! Drives a poll cycle with the SHIPPED `catalog/github.jsonc` manifest and a
//! captured vendor response shape with anonymized titles.
//!
//! Every poller test in plexus-core declares its own poll shape inline, so all
//! of them pass against a manifest that does not exist, so a shipped manifest
//! with a broken poll shape leaves triggers unsubscribable while the suite
//! stays green. This reads the shipped catalog file instead, and replays a response
//! captured from `api.githubcopilot.com/mcp/readonly` on 2026-08-07 (four
//! issues from rust-lang/rust, trimmed to the fields the poll shape names plus
//! enough context to stay recognisable as a GitHub payload). Captured titles
//! have since been replaced with invented text; fields and cursor values remain.
//!
//! It lives in the conformance crate rather than beside the other poller tests
//! for one concrete reason: parsing a real catalog file needs the production
//! JSONC parser, and plexus-core deliberately does not depend on subc-jsonc.
//! Its own tests strip comments with a hand-rolled helper, which is fine for
//! documents it authors and wrong for a document whose exact bytes are the
//! thing under test.
//!
//! Why a captured payload rather than a live call: a test that reaches the
//! network cannot run in CI and rots into an ignored test nobody executes. The
//! capture is the evidence; replaying it through the real strategy is the
//! check.

use std::path::Path;
use std::sync::Arc;

use plexus_core::{
    jcs_sha256, CatalogActionInput, GovernanceEngine, GrantInput, MockResponse, MockTransport,
    PollCycle, Poller, StubCredentialSource, AUTHORITY_POLL, CATALOG_PRINCIPAL,
};
use serde_json::{json, Value};

const PRINCIPAL: &str = "direct";
const CONNECTION: &str = "conn-github";
const ACTION: &str = "list_issues";

fn captured_github_response() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github_list_issues_live.json");
    let source = std::fs::read_to_string(path).expect("captured github response must exist");
    serde_json::from_str(&source).expect("captured github response must be valid json")
}

fn seeded_engine(
    action: &str,
    schema: Value,
    fixed_args: Value,
) -> (
    GovernanceEngine<StubCredentialSource, MockTransport>,
    String,
) {
    let descriptor = cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("shipped-poll-{action}-{}", std::process::id()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = plexus_core::PlexusStore::open(&descriptor).expect("test store");

    let ingested = plexus_conformance::drift::ingest_manifest(include_str!(
        "../../../../catalog/github.jsonc"
    ))
    .expect("shipped manifest ingests");
    let app_key = ingested.manifest.key.clone();
    store
        .insert_connection(
            PRINCIPAL,
            CONNECTION,
            &app_key,
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert connection");
    let handle = b"test:github-binding-handle";
    let ticket = store
        .create_binding_ticket(PRINCIPAL, CONNECTION, handle)
        .expect("issue binding ticket");
    store
        .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
        .expect("consume binding ticket")
        .expect("connection activates");
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
        .expect("store shipped manifest");

    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let engine = GovernanceEngine::new(
        Arc::new(store),
        Arc::new(credentials),
        Arc::new(MockTransport::default()),
    );

    let schema_hash = jcs_sha256(&schema).expect("test JSON is JCS-compatible");
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: CONNECTION.to_string(),
            principal: PRINCIPAL.to_string(),
            name: action.to_string(),
            title: Some(action.to_string()),
            schema,
            schema_hash: schema_hash.clone(),
            risk: "read".to_string(),
            severity: "S1".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("seed catalog action");
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
        + 3_600_000;
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-poll-{action}"),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![action.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(expiry),
        })
        .expect("insert poll grant");

    let created = engine
        .store()
        .subscribe_with_cursor_state(PRINCIPAL, CONNECTION, action, 30, &json!({}), &fixed_args)
        .expect("subscribe store")
        .expect("the shipped manifest must be subscribable");
    let stored = engine
        .store()
        .list_catalog_actions(PRINCIPAL, CONNECTION)
        .unwrap();
    assert_eq!(
        stored[0].schema_hash,
        jcs_sha256(&stored[0].schema).unwrap(),
        "catalog pin must hash the actual seeded schema"
    );
    (engine, created.subscription_id)
}

/// Replay a captured GitHub response through the shipped issue poll shape.
/// The assertions cover the response's items envelope, numeric event identifiers,
/// manifest-owned ordering/page-size arguments, and subscription repository args.
/// An inline poll declaration would not catch drift in the shipped catalog.
#[test]
fn the_shipped_github_poll_shape_reads_a_real_vendor_response() {
    let (engine, subscription_id) = seeded_engine(
        ACTION,
        json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "after": {"type": "string"},
                "direction": {"type": "string"},
                "field_filters": {},
                "fields": {},
                "labels": {},
                "orderBy": {"type": "string"},
                "perPage": {"type": "number"},
                "since": {"type": "string"},
                "state": {"type": "string"}
            }
        }),
        json!({"owner":"rust-lang","repo":"rust"}),
    );

    engine
        .transport()
        .set_response(MockResponse::Success(captured_github_response()));
    let poller = Poller::new(engine.clone());

    assert_eq!(
        poller.poll_once(PRINCIPAL, &subscription_id),
        PollCycle::Completed {
            inserted: 4,
            duplicates: 0,
        },
        "the shipped poll shape must read all four issues out of the real envelope"
    );

    // Asserted on the request the transport RECEIVED. The constants are
    // declared in the manifest; only the wire proves they were sent.
    let requests = engine.transport().requests();
    assert_eq!(requests.len(), 1, "exactly one poll must have dispatched");
    let args = requests[0].args.as_object().expect("request args object");
    assert_eq!(args.get("perPage"), Some(&json!(30)));
    assert_eq!(args.get("orderBy"), Some(&json!("UPDATED_AT")));
    assert_eq!(args.get("direction"), Some(&json!("ASC")));
    assert_eq!(args.get("owner"), Some(&json!("rust-lang")));
    assert_eq!(args.get("repo"), Some(&json!("rust")));

    // The watermark takes the MAXIMUM updated_at across the page, and the real
    // capture is ordered ascending, so the last row carries it. Asserting the
    // id — not just the count — is what proves the integer `number` survived
    // canonicalisation into a string event id.
    let stored = engine
        .store()
        .subscription(PRINCIPAL, &subscription_id)
        .expect("read subscription")
        .expect("subscription row");
    assert_eq!(
        stored
            .cursor_state
            .get("watermark_id")
            .and_then(Value::as_str),
        Some("133480"),
        "the watermark must record the real issue number carrying the newest updated_at"
    );
}

fn captured_pull_request_response() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/github_list_pull_requests_live.json");
    let source = std::fs::read_to_string(path).expect("captured pull request response must exist");
    serde_json::from_str(&source).expect("captured pull request response must be valid json")
}

/// The shipped `list_pull_requests` shape reads a real vendor response.
///
/// Separate from the issues test because the two actions differ in the one way
/// that matters most here, and the difference is invisible in a hand-written
/// fixture: `list_issues` answers `{issues, totalCount, pageInfo}` while
/// `list_pull_requests` answers a BARE ARRAY — same server, same session,
/// measured. Every other list strategy in this codebase calls `as_object()`
/// first, so a pull-request watch built on one would suspend on shape before
/// any cursor logic ran.
///
/// What this fences that an inline fixture cannot:
///
/// - The captured bare-array envelope, with anonymized titles but unchanged fields.
/// - `request_constants` reaching the WIRE. They are load-bearing for this
///   cursor kind in a way they are not for a windowed one: sorted-head trusts
///   the vendor's ordering instead of sending a bound, so `direction: desc` is
///   what makes the first page the NEWEST page. With `asc` the page would be
///   the oldest pull requests, identical every poll, and the watch would
///   deliver nothing forever while reporting success.
/// - `state: all`, without which a pull request merged or closed between polls
///   silently disappears from the feed — the updates most worth seeing.
/// - `tiebreaker_id_field: number` arriving as an INTEGER and surviving into a
///   string event id.
#[test]
fn the_shipped_pull_request_poll_shape_reads_a_real_vendor_response() {
    const PR_ACTION: &str = "list_pull_requests";

    let (engine, subscription_id) = seeded_engine(
        PR_ACTION,
        json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "base": {"type": "string"},
                "direction": {"type": "string"},
                "fields": {},
                "head": {"type": "string"},
                "page": {"type": "number"},
                "perPage": {"type": "number"},
                "sort": {"type": "string"},
                "state": {"type": "string"}
            },
            "required": ["owner", "repo"]
        }),
        json!({"owner":"cortexkit","repo":"magic-context"}),
    );

    engine
        .transport()
        .set_response(MockResponse::Success(captured_pull_request_response()));
    let poller = Poller::new(engine.clone());

    assert_eq!(
        poller.poll_once(PRINCIPAL, &subscription_id),
        PollCycle::Completed {
            inserted: 4,
            duplicates: 0,
        },
        "the shipped poll shape must read all four pull requests out of the bare array"
    );

    // Asserted on the request the transport RECEIVED. For this cursor kind the
    // constants ARE the method, so proving they were sent is proving the watch
    // can work at all.
    let requests = engine.transport().requests();
    assert_eq!(requests.len(), 1, "exactly one poll must have dispatched");
    let args = requests[0].args.as_object().expect("request args object");
    assert_eq!(args.get("perPage"), Some(&json!(100)));
    assert_eq!(args.get("sort"), Some(&json!("updated")));
    assert_eq!(
        args.get("direction"),
        Some(&json!("desc")),
        "descending is what makes the first page the NEWEST page"
    );
    assert_eq!(
        args.get("state"),
        Some(&json!("all")),
        "without state=all a merged or closed pull request vanishes from the feed"
    );
    assert_eq!(args.get("owner"), Some(&json!("cortexkit")));
    assert_eq!(args.get("repo"), Some(&json!("magic-context")));

    // The capture is DESCENDING, so the newest row is first — the opposite of
    // the issues capture. Asserting the id proves the integer `number` survived
    // into a string event id, and that the maximum was taken across the page
    // rather than the last row being assumed newest.
    let stored = engine
        .store()
        .subscription(PRINCIPAL, &subscription_id)
        .expect("read subscription")
        .expect("subscription row");
    assert_eq!(
        stored
            .cursor_state
            .get("watermark_id")
            .and_then(Value::as_str),
        Some("308"),
        "the watermark must record the pull request carrying the newest updated_at"
    );
}
