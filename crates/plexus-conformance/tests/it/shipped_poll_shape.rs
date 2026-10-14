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
    ingest_value, jcs_sha256, CatalogActionInput, GovernanceEngine, GrantInput, MockResponse,
    MockTransport, PollCycle, Poller, StubCredentialSource, AUTHORITY_POLL, CATALOG_PRINCIPAL,
};
use serde_json::{json, Value};

const PRINCIPAL: &str = "direct";
const CONNECTION: &str = "conn-github";
const ACTION: &str = "list_issues";

fn shipped_github_manifest() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/github.jsonc");
    let source = std::fs::read_to_string(path).expect("shipped github manifest must exist");
    let normalized =
        subc_jsonc::jsonc_to_json(&source).expect("shipped github manifest must be valid jsonc");
    serde_json::from_str(&normalized).expect("shipped github manifest must parse")
}

fn captured_github_response() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/github_list_issues_live.json");
    let source = std::fs::read_to_string(path).expect("captured github response must exist");
    serde_json::from_str(&source).expect("captured github response must be valid json")
}

/// A poll driven entirely by shipped catalog data must read a real payload.
///
/// What this fences, none of which an inline fixture can:
///
/// - `items_field: issues` against the REAL envelope, which also carries
///   `totalCount` and `pageInfo`. A wrong name yields zero events, which is
///   indistinguishable from a quiet period — the failure never surfaces.
/// - `tiebreaker_id_field: number`, which GitHub returns as an INTEGER while
///   the event log keys on strings. The strategy refuses a malformed item
///   whole rather than skipping it, so a type mismatch fails the entire cycle
///   on first contact.
/// - `request_constants` reaching the WIRE. That is the whole reason the
///   manifest field exists: without `orderBy`/`direction` GitHub returns a page
///   ordered by neither, and the watermark — which takes the maximum timestamp
///   across items — advances past rows that were never delivered.
/// - `fixed_args` composing with the constants: the subscription says WHICH
///   repository, the manifest says HOW to order it.
#[test]
fn the_shipped_github_poll_shape_reads_a_real_vendor_response() {
    let descriptor = cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("shipped-poll-{}", std::process::id()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = plexus_core::PlexusStore::open(&descriptor).expect("test store");

    let ingested = ingest_value(shipped_github_manifest()).expect("shipped manifest ingests");
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

    let schema_hash = jcs_sha256(&json!({"type": "object"})).expect("test JSON is JCS-compatible");
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: CONNECTION.to_string(),
            principal: PRINCIPAL.to_string(),
            name: ACTION.to_string(),
            title: Some(ACTION.to_string()),
            // The argument names GitHub's MCP server declares for
            // list_issues. Governance refuses an argument the pinned schema
            // does not declare, so the schema must list the request constants
            // and cursor fields the shipped poll shape sends.
            schema: json!({
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
            grant_id: "grant-poll-github".to_string(),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![ACTION.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(expiry),
        })
        .expect("insert poll grant");

    let created = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            ACTION,
            30,
            &json!({}),
            &json!({"owner": "rust-lang", "repo": "rust"}),
        )
        .expect("subscribe store")
        .expect("the shipped manifest must be subscribable");

    engine
        .transport()
        .set_response(MockResponse::Success(captured_github_response()));
    let poller = Poller::new(engine.clone());

    assert_eq!(
        poller.poll_once(PRINCIPAL, &created.subscription_id),
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
        .subscription(PRINCIPAL, &created.subscription_id)
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

    let descriptor = cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("shipped-pr-poll-{}", std::process::id()),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".to_string(),
        },
    };
    let store = plexus_core::PlexusStore::open(&descriptor).expect("test store");

    let ingested = ingest_value(shipped_github_manifest()).expect("shipped manifest ingests");
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

    let schema_hash = jcs_sha256(&json!({"type": "object"})).expect("test JSON is JCS-compatible");
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: CONNECTION.to_string(),
            principal: PRINCIPAL.to_string(),
            name: PR_ACTION.to_string(),
            title: Some(PR_ACTION.to_string()),
            // The argument names GitHub's MCP server declares for
            // list_pull_requests, which include the shipped poll shape's
            // request constants.
            schema: json!({
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
            grant_id: "grant-poll-github-pr".to_string(),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![PR_ACTION.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(expiry),
        })
        .expect("insert poll grant");

    let created = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            PR_ACTION,
            30,
            &json!({}),
            &json!({"owner": "cortexkit", "repo": "magic-context"}),
        )
        .expect("subscribe store")
        .expect("the shipped pull request shape must be subscribable");

    engine
        .transport()
        .set_response(MockResponse::Success(captured_pull_request_response()));
    let poller = Poller::new(engine.clone());

    assert_eq!(
        poller.poll_once(PRINCIPAL, &created.subscription_id),
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
        .subscription(PRINCIPAL, &created.subscription_id)
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
