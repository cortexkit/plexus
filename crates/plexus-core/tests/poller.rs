//! End-to-end tests for the poll executor. Each guard gets a test that asserts
//! stored STATE (not just a return value) and that fails when the guard is
//! removed; the mutation each test proves is stated in its doc comment. The
//! suite includes the healthy path that must SUCCEED, so it can distinguish a
//! real implementation from one that refuses everything.

#[path = "support/bounded.rs"]
mod bounded;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    fingerprint, ingest_value, jcs_sha256, ActorSource, CatalogActionInput, GovernanceEngine,
    GrantInput, MockResponse, MockTransport, PollCycle, Poller, ProbeRegistration, Scheduler,
    StubCredentialSource, SubscriptionRefusal, TriggerSubscription,
    ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE, ACTOR_TIMELINE_ACTION, AUTHORITY_POLL,
    CIRCUIT_BREAKER_SUSPENSION_REASON,
};
use serde_json::{json, Value};

#[path = "support/logging.rs"]
mod logging;

const PRINCIPAL: &str = "direct";
/// The credential handle the fixture binds to the connection.
///
/// Shared rather than written twice, because `StubCredentialSource` resolves a
/// HANDLE-SPECIFIC response before its default: a test that overrides the
/// default while the fixture holds a specific success for this handle changes
/// nothing at all.
const BINDING_HANDLE: &[u8] = b"test:poller-binding-handle";
const CONNECTION: &str = "conn-1";
const FEED: &str = "read_feed";
const PR_FEED: &str = "read_pull_requests";
const ACTOR_CONNECTION: &str = "conn-actors";
const ISSUE_READ: &str = "issue_read";
const PULL_REQUEST_READ: &str = "pull_request_read";
const TIMESTAMPED: &str = "read_ts";
const SORTED_HEAD: &str = "read_sorted_head";
const ACTOR_WINDOW_PREVIOUS_MS: i64 = 1_787_227_200_500;
/// An action whose manifest declares vendor-specific response and request field
/// names instead of the reference envelope.
const VENDOR_NAMED: &str = "read_vendor_named";
/// A snapshot-diff action: the one cursor kind this slice still does not
/// implement, used to prove an unsupported kind suspends rather than guesses.
const SNAPSHOT: &str = "read_snapshot";

fn test_store(label: &str) -> (plexus_core::PlexusStore, Scratch) {
    logging::init_child();
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
    let path = Scratch::database(&format!("poller-{label}"));
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("{label}-{unique}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    (
        plexus_core::PlexusStore::open(&descriptor).expect("open test store"),
        path,
    )
}

fn manifest_value() -> Value {
    json!({
        "schema_version": 1,
        "key": "mock",
        "name": "Mock",
        "description": "poller test vendor",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "in-process tests",
        "tier": "S2",
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [
            {
                "name": FEED,
                "risk": "read",
                // Declares no field names, so the reference envelope applies:
                // items under `items`, next cursor under `next_cursor`, request
                // parameter `sync_token`.
                "poll": {"item_kind": "issue", "cursor_kind": "sync_token"}
            },
            {
                "name": PR_FEED,
                "risk": "read",
                "poll": {"item_kind": "pull_request", "cursor_kind": "sync_token"}
            },
            {
                // Google Calendar's real naming, which agrees with the
                // reference envelope on nothing: records under `items`, the
                // next cursor returned as `nextSyncToken`, and that value sent
                // back as the request parameter `syncToken`. The response and
                // request names differ, which is why they are separate fields.
                "name": VENDOR_NAMED,
                "risk": "read",
                "poll": {
                    "cursor_kind": "sync_token",
                    "item_kind": "issue",
                    "token_field": "nextSyncToken",
                    "request_token_field": "syncToken",
                    "items_field": "entries"
                }
            },
            {
                "name": TIMESTAMPED,
                "risk": "read",
                "poll": {
                    "cursor_kind": "ordered_timestamp",
                    "item_kind": "issue",
                    "timestamp_field": "updated_at",
                    "tiebreaker_id_field": "id",
                    "request_since_field": "updatedSince",
                    "request_constants": {}
                }
            },
            {
                "name": SORTED_HEAD,
                "risk": "read",
                "poll": {
                    "cursor_kind": "sorted_head",
                    "item_kind": "issue",
                    "items_field": "items",
                    "timestamp_field": "updated_at",
                    "tiebreaker_id_field": "id",
                    "request_page_size_field": "perPage",
                    "request_constants": {
                        "sort": "updated",
                        "direction": "desc",
                        "perPage": 100
                    }
                }
            },
            {
                "name": SNAPSHOT,
                "risk": "read",
                "poll": {
                    "cursor_kind": "sync_token",
                    "item_kind": "issue"
                }
            }
        ],
        "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    })
}

fn schema_hash() -> String {
    jcs_sha256(&json!({"type": "object"})).expect("test JSON is JCS-compatible")
}

/// Every request argument the test manifest's poll shape for `action` can send:
/// its cursor field (the sync token or the since timestamp, each with its
/// documented default), its page cursor, and its request constants.
fn poll_shape_argument_names(action: &str) -> Vec<String> {
    poll_argument_names_in(&manifest_value(), action)
}

fn poll_argument_names_in(manifest: &Value, action: &str) -> Vec<String> {
    let poll = manifest["actions_baseline"]
        .as_array()
        .unwrap()
        .iter()
        .find(|declared| declared["name"] == action)
        .map(|declared| declared["poll"].clone())
        .unwrap_or(Value::Null);
    let field = |key: &str, default: &str| {
        poll[key]
            .as_str()
            .map_or_else(|| default.to_string(), str::to_string)
    };
    let mut names = match poll["cursor_kind"].as_str() {
        Some("sync_token") => vec![field("request_token_field", "sync_token")],
        Some("ordered_timestamp") => vec![field("request_since_field", "since")],
        _ => Vec::new(),
    };
    if let Some(page_cursor) = poll["pagination"]["request_cursor_field"].as_str() {
        names.push(page_cursor.to_string());
    }
    if let Some(constants) = poll["request_constants"].as_object() {
        names.extend(constants.keys().cloned());
    }
    names
}

fn upsert_action(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    name: &str,
    risk: &str,
    hash: &str,
    status: &str,
) {
    upsert_action_with_schema(engine, name, risk, hash, status, json!({"type": "object"}));
}

fn upsert_action_with_schema(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    name: &str,
    risk: &str,
    hash: &str,
    status: &str,
    schema: Value,
) {
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: CONNECTION.to_string(),
            principal: PRINCIPAL.to_string(),
            name: name.to_string(),
            title: Some(name.to_string()),
            schema,
            schema_hash: hash.to_string(),
            risk: risk.to_string(),
            severity: "S2".to_string(),
            ask_first: matches!(risk, "write" | "destructive"),
            status: status.to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("upsert catalog action");
}

fn insert_poll_grant(engine: &GovernanceEngine<StubCredentialSource, MockTransport>, action: &str) {
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
}

/// A live, credentialed connection with a reviewed manifest, read actions across
/// every cursor kind (sync-token, ordered-timestamp, sorted-head, and a
/// snapshot-diff the poller does not yet implement), poll grants for each, and a sync-token
/// subscription on the feed action. Returns the poller, a clone of the engine
/// (to reach the shared store and transport), the database path, and the feed
/// subscription id.
fn fixture(
    label: &str,
) -> (
    Poller<StubCredentialSource, MockTransport>,
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Scratch,
    String,
) {
    let (store, path) = test_store(label);
    store
        .insert_connection(
            PRINCIPAL,
            CONNECTION,
            "mock",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert connection");
    let handle = BINDING_HANDLE;
    let ticket = store
        .create_binding_ticket(PRINCIPAL, CONNECTION, handle)
        .expect("issue binding ticket");
    store
        .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
        .expect("consume binding ticket")
        .expect("connection activates");
    store
        .upsert_manifest(
            plexus_core::CATALOG_PRINCIPAL,
            &ingest_value(manifest_value()).expect("manifest"),
        )
        .expect("store manifest");
    let credentials = StubCredentialSource::default();
    credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
    let transport = MockTransport::default();
    let engine = GovernanceEngine::new(Arc::new(store), Arc::new(credentials), Arc::new(transport));

    let hash = schema_hash();
    upsert_action(&engine, FEED, "read", &hash, "active");
    upsert_action(&engine, TIMESTAMPED, "read", &hash, "active");
    upsert_action(&engine, SORTED_HEAD, "read", &hash, "active");
    upsert_action(&engine, VENDOR_NAMED, "read", &hash, "active");
    upsert_action(&engine, SNAPSHOT, "read", &hash, "active");
    insert_poll_grant(&engine, FEED);
    insert_poll_grant(&engine, TIMESTAMPED);
    insert_poll_grant(&engine, VENDOR_NAMED);
    insert_poll_grant(&engine, SNAPSHOT);

    let subscription = engine
        .store()
        .subscribe(PRINCIPAL, CONNECTION, FEED, 30)
        .expect("subscribe store")
        .expect("subscription accepted");
    let poller = Poller::new(engine.clone());
    (poller, engine, path, subscription.subscription_id)
}

fn actor_subscription(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    watched_action: &str,
    actor_action: &str,
    methods: &[&str],
) -> String {
    // The watched action's schema declares the repository arguments and every
    // argument the manifest's poll shape makes the poller send: the cursor on a
    // resumed poll and the fixed request constants. Governance refuses an
    // argument the schema does not declare, so a schema listing only owner and
    // repo would refuse the second poll's cursor.
    let mut properties = json!({
        "owner": {"type": "string"},
        "repo": {"type": "string"}
    });
    for key in poll_shape_argument_names(watched_action) {
        properties[key] = json!({});
    }
    let watched_schema = json!({
        "type": "object",
        "properties": properties,
        "required": ["owner", "repo"]
    });
    upsert_action_with_schema(
        engine,
        watched_action,
        "read",
        &schema_hash(),
        "active",
        watched_schema,
    );
    // `fixture` already granted poll authority for these actions.
    if !matches!(watched_action, FEED | TIMESTAMPED | VENDOR_NAMED | SNAPSHOT) {
        insert_poll_grant(engine, watched_action);
    }
    let subscription = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            watched_action,
            30,
            &json!({}),
            &json!({"owner": "cortexkit", "repo": "plexus"}),
        )
        .expect("subscribe actor-enriched watch")
        .expect("actor-enriched watch accepted");

    engine
        .store()
        .insert_connection(
            PRINCIPAL,
            ACTOR_CONNECTION,
            "mock",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert actor connection");
    let ticket = engine
        .store()
        .create_binding_ticket(PRINCIPAL, ACTOR_CONNECTION, BINDING_HANDLE)
        .expect("issue actor binding ticket");
    engine
        .store()
        .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
        .expect("consume actor binding ticket")
        .expect("actor connection activates");
    let item_number_key = if actor_action == ISSUE_READ {
        "issue_number"
    } else {
        "pullNumber"
    };
    let actor_schema = json!({
        "type": "object",
        "properties": {
            "method": {"type": "string"},
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            (item_number_key): {"type": "integer"},
            "perPage": {"type": "integer"}
        },
        "required": ["method", "owner", "repo", item_number_key]
    });
    engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: ACTOR_CONNECTION.to_string(),
            principal: PRINCIPAL.to_string(),
            name: actor_action.to_string(),
            title: Some(actor_action.to_string()),
            schema_hash: jcs_sha256(&actor_schema).expect("test JSON is JCS-compatible"),
            schema: actor_schema,
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("upsert actor action");
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-actor-{actor_action}"),
            principal: PRINCIPAL.to_string(),
            connection_id: ACTOR_CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![actor_action.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(i64::MAX / 2),
        })
        .expect("insert actor poll grant");
    engine
        .store()
        .set_subscription_actor_source(
            PRINCIPAL,
            &subscription.subscription_id,
            Some(&ActorSource {
                connection_id: ACTOR_CONNECTION.to_string(),
                action: actor_action.to_string(),
                methods: methods.iter().map(|method| (*method).to_string()).collect(),
            }),
        )
        .expect("set actor source");
    subscription.subscription_id
}

fn subscription(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    id: &str,
) -> TriggerSubscription {
    engine
        .store()
        .subscription(PRINCIPAL, id)
        .expect("read subscription")
        .expect("subscription exists")
}

fn register_read_probe(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    name: &str,
) -> String {
    register_read_probe_with_script(engine, name, "() => invoke('read_feed', {})")
}

fn register_read_probe_with_script(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    name: &str,
    script_source: &str,
) -> String {
    let actions = [FEED.to_string()];
    engine
        .store()
        .register_probe(
            PRINCIPAL,
            CONNECTION,
            ProbeRegistration {
                name,
                actions: &actions,
                script_source,
                return_schema: &json!({"kind": "bool"}),
                rearm: "always",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({}),
            },
        )
        .expect("register probe store")
        .expect("probe registration accepted")
        .subscription_id
}

fn prime_issue_actor_window(
    poller: &Poller<StubCredentialSource, MockTransport>,
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    path: &Path,
    id: &str,
) {
    prime_issue_actor_window_at(poller, engine, path, id, ACTOR_WINDOW_PREVIOUS_MS);
}

/// First-observe item 17, then pin that observation to `previous_ms` so the
/// next poll's actor window starts there.
fn prime_issue_actor_window_at(
    poller: &Poller<StubCredentialSource, MockTransport>,
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    path: &Path,
    id: &str,
    previous_ms: i64,
) {
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "before"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    let conn = rusqlite::Connection::open(path).expect("open actor-window fixture");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![previous_ms, PRINCIPAL, id],
        )
        .expect("pin previous actor-window observation"),
        1
    );
}

fn assert_changed_issue_actors(
    poller: &Poller<StubCredentialSource, MockTransport>,
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    id: &str,
    comments: Value,
    expected: Option<Vec<&str>>,
) {
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(comments),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "after"}],
            "next_cursor": "tok-2"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(id))
        .expect("list actor-window events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed actor-window version stored");
    assert_eq!(
        changed.actor_logins,
        expected.map(|logins| logins.into_iter().map(str::to_string).collect())
    );
}

fn sorted_head_subscription(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
) -> String {
    insert_poll_grant(engine, SORTED_HEAD);
    engine
        .store()
        .subscribe(PRINCIPAL, CONNECTION, SORTED_HEAD, 30)
        .expect("subscribe sorted-head store")
        .expect("sorted-head subscription accepted")
        .subscription_id
}

/// Drift the catalog row behind the reconciler's back.
///
/// `upsert_catalog_action` atomically suspends any subscription whose action
/// left `read` or changed schema, so a drift made through the public API is
/// already suspended before the poller runs. The poller's pre-gate and its
/// pinned-schema check exist for the WINDOW between a catalog drift and the
/// next reconcile, so these tests open a second connection and mutate the row
/// directly to reproduce that window with the subscription still active.
fn drift_catalog_raw(path: &Path, column: &str, value: &str, action: &str) {
    let conn = rusqlite::Connection::open(path).expect("open second catalog connection");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("set busy timeout");
    let changed = conn
        .execute(
            &format!(
                "UPDATE catalog_actions SET {column} = ?1
                 WHERE principal = ?2 AND connection_id = ?3 AND name = ?4"
            ),
            rusqlite::params![value, PRINCIPAL, CONNECTION, action],
        )
        .expect("drift catalog row");
    assert_eq!(changed, 1, "the catalog row to drift must exist");
}

/// The success vector: a healthy poll advances the stored cursor and commits
/// the returned events. Without this the refusal tests below could pass against
/// an executor that refuses every poll.
///
/// Mutation proved: dropping the cursor advance (committing events but storing
/// the old cursor) fails the cursor-value assertion; dropping the event commit
/// fails the event-count assertion.
#[test]
fn healthy_poll_advances_the_cursor_and_writes_its_events() {
    let (poller, engine, path, id) = fixture("healthy");
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [
                {"id": "e1", "title": "first"},
                {"id": "e2", "title": "second"}
            ],
            "next_cursor": "tok-2"
        })));

    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Completed {
            inserted: 2,
            duplicates: 0,
        }
    );

    let stored = subscription(&engine, &id);
    assert_eq!(
        stored.cursor_state,
        json!({"sync_token": "tok-2"}),
        "the stored cursor value must advance to the vendor's next token"
    );
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(stored.last_success_at_ms.is_some());
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list events");
    assert_eq!(events.len(), 2, "both vendor events are durable");
    assert!(events
        .iter()
        .any(|event| event.vendor_event_id.as_deref() == Some("e1")));
    assert!(events
        .iter()
        .any(|event| event.vendor_event_id.as_deref() == Some("e2")));
    let _ = std::fs::remove_file(path);
}

struct DeactivateBeforePollCommit {
    store: Arc<plexus_core::PlexusStore>,
    subscription_id: String,
    response: Value,
}

impl plexus_core::Transport for DeactivateBeforePollCommit {
    fn dispatch(
        &self,
        _: plexus_core::TransportRequest,
        _: &plexus_core::ResolvedCredential,
    ) -> plexus_core::TransportResponse {
        assert!(self
            .store
            .suspend(PRINCIPAL, &self.subscription_id, "operator_pause")
            .unwrap());
        plexus_core::TransportResponse::success(self.response.clone())
    }
}

#[test]
fn deactivation_between_selection_and_commit_is_not_eligible() {
    for probe in [false, true] {
        let (_poller, engine, _path, feed_id) = fixture(if probe {
            "probe-commit-race"
        } else {
            "poll-commit-race"
        });
        let id = if probe {
            register_read_probe(&engine, "commit-race")
        } else {
            feed_id
        };
        let before = subscription(&engine, &id);
        let transport = Arc::new(DeactivateBeforePollCommit {
            store: Arc::clone(engine.store()),
            subscription_id: id.clone(),
            response: if probe {
                json!(true)
            } else {
                json!({"items":[{"id":"must-not-commit"}],"next_cursor":"must-not-advance"})
            },
        });
        let poller = Poller::new(GovernanceEngine::new(
            Arc::clone(engine.store()),
            Arc::clone(engine.credential_source()),
            transport,
        ));
        assert_eq!(
            poller.poll_once(PRINCIPAL, &id),
            PollCycle::NotEligible {
                reason: "subscription_not_active".into()
            },
            "inactive commit must not be a storage or vendor failure (probe={probe})"
        );
        let after = subscription(&engine, &id);
        assert_eq!(after.status, "suspended");
        assert_eq!(after.cursor_state, before.cursor_state);
        assert_eq!(after.last_success_at_ms, before.last_success_at_ms);
        assert_eq!(
            after.consecutive_vendor_failures,
            before.consecutive_vendor_failures
        );
        assert!(
            engine
                .store()
                .list_events(PRINCIPAL, None, Some(&id))
                .unwrap()
                .iter()
                .all(|event| event.vendor_event_id.is_none()),
            "no vendor event may commit after deactivation"
        );
    }
}

/// A subscription with no actor source stores unknown actors.
///
/// This is the fleet-default path: existing subscriptions remain unbound until
/// an operator selects independent enrichment authority. Mutation proved by
/// changing the shared early-return value from `None` to `Some([])`; this stored
/// assertion then fails while bound-path actor tests remain green.
#[test]
fn an_unbound_actor_source_stores_unknown_actors() {
    let (poller, engine, path, id) = fixture("actor-source-unbound");
    assert_eq!(
        subscription(&engine, &id).actor_source,
        None,
        "the test must exercise the unbound source guard"
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list unbound event")
        .pop()
        .expect("unbound event stored");
    assert_eq!(event.actor_logins, None);
    let _ = std::fs::remove_file(path);
}

/// A bound source cannot identify actors when the watched action no longer has
/// a poll shape supplying an item kind.
///
/// The subscription is created while its reviewed shape exists, then the stored
/// manifest loses that shape to model a legacy/drifted row. Mutation proved by
/// changing the shared early-return value from `None` to `Some([])`.
#[test]
fn a_missing_item_kind_stores_unknown_actors() {
    let (poller, engine, path, _) = fixture("actor-kind-missing");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    let mut manifest = manifest_value();
    let feed = manifest["actions_baseline"]
        .as_array_mut()
        .expect("manifest actions")
        .iter_mut()
        .find(|action| action["name"] == FEED)
        .expect("feed action");
    feed.as_object_mut()
        .expect("feed action object")
        .remove("poll");
    engine
        .store()
        .upsert_manifest(
            plexus_core::CATALOG_PRINCIPAL,
            &ingest_value(manifest).expect("manifest without feed poll shape"),
        )
        .expect("replace stored manifest");
    assert_eq!(
        engine
            .store()
            .poll_shape(PRINCIPAL, CONNECTION, FEED)
            .expect("read missing poll shape"),
        None,
        "the test must exercise the missing item-kind guard"
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list untyped event")
        .pop()
        .expect("untyped event stored");
    assert_eq!(event.item_kind, None);
    assert_eq!(event.actor_logins, None);
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        0,
        "a missing kind must stop before actor dispatch"
    );
    let _ = std::fs::remove_file(path);
}

/// A source whose method set does not cover the watched item kind stores unknown
/// actors and makes no partial enrichment call.
///
/// Here an issue is bound only to the PR review-comment method. Mutation proved
/// by changing the shared early-return value from `None` to `Some([])`.
#[test]
fn methods_that_do_not_cover_the_item_kind_store_unknown_actors() {
    let (poller, engine, path, _) = fixture("actor-methods-mismatch");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_review_comments"]);
    assert_eq!(
        subscription(&engine, &id)
            .actor_source
            .expect("bound actor source")
            .methods,
        vec!["get_review_comments".to_string()],
        "the test must exercise the item-kind coverage guard"
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list method-mismatch event")
        .pop()
        .expect("method-mismatch event stored");
    assert_eq!(event.actor_logins, None);
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        0,
        "a method mismatch must stop before actor dispatch"
    );
    let _ = std::fs::remove_file(path);
}

/// A successful issue-comment read stamps every login in stable order.
///
/// Mutation proved: replacing response-derived actors with a fixed set, dropping
/// one list element, or preserving vendor order instead of stable ordering fails
/// the stored actor assertion.
#[test]
fn issue_comment_actors_round_trip_in_stable_order() {
    let (poller, engine, path, _) = fixture("issue-actors");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([
            {
                "user": {"login": "zara"},
                "created_at": "2026-08-20T12:00:00Z"
            },
            {
                "user": {"login": "alice"},
                "created_at": "2026-08-20T12:01:00Z"
            }
        ])),
    );

    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list enriched event");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].actor_logins,
        Some(vec!["alice".to_string(), "zara".to_string()])
    );
    let _ = std::fs::remove_file(path);
}

/// Actor extraction excludes comments from strictly older reported seconds and
/// includes comments from strictly newer reported seconds.
///
/// Both sides share one event so the guard cannot pass by choosing the wrong
/// baseline for two independent cases. Removing the filter admits the old
/// comment; using the current observation as the baseline drops the new one.
#[test]
fn actor_window_excludes_before_and_includes_after_previous_observation() {
    let (poller, engine, path, _) = fixture("actor-window");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "before"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    // The host observed halfway through 12:00:00. The actor fixture stays out
    // of that ambiguous second so this test proves only the definite regions.
    let previous = 1_787_227_200_500_i64;
    let conn = rusqlite::Connection::open(&path).expect("open window fixture");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![previous, PRINCIPAL, id],
        )
        .expect("pin previous observation"),
        1
    );
    drop(conn);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([
            {
                "user": {"login": "before"},
                "created_at": "2026-08-20T11:59:58Z"
            },
            {
                "user": {"login": "after"},
                "created_at": "2026-08-20T12:00:01Z"
            }
        ])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "after"}],
            "next_cursor": "tok-2"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list windowed events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed version stored");
    assert_eq!(changed.actor_logins, Some(vec!["after".to_string()]));
    let _ = std::fs::remove_file(path);
}

/// Editing is activity even when the comment itself predates the observation.
/// Reverting the window to creation time alone loses this author and makes the
/// stored actor set unknown.
#[test]
fn edited_comment_created_before_window_is_attributed() {
    let (poller, engine, path, _) = fixture("actor-window-edited-comment");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);

    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([{
            "user": {"login": "edited-human"},
            "created_at": "2026-08-20T11:59:58Z",
            "updated_at": "2026-08-20T12:00:01Z"
        }]),
        Some(vec!["edited-human"]),
    );
    let _ = std::fs::remove_file(path);
}

/// A concurrent operator comment must not hide the external author whose old
/// comment was edited in the same window. The exact two-actor set is the
/// downstream suppression contract: an operator-only set would suppress the
/// wake caused by the external edit.
#[test]
fn edited_external_comment_prevents_an_operator_only_actor_set() {
    let (poller, engine, path, _) = fixture("actor-window-edited-external-and-operator");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);

    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([
            {
                "user": {"login": "operator"},
                "created_at": "2026-08-20T12:00:02Z",
                "updated_at": "2026-08-20T12:00:02Z"
            },
            {
                "user": {"login": "external-human"},
                "created_at": "2026-08-20T11:59:58Z",
                "updated_at": "2026-08-20T12:00:01Z"
            }
        ]),
        Some(vec!["external-human", "operator"]),
    );
    let _ = std::fs::remove_file(path);
}

/// Creation and update both before the observation remain historical. Dropping
/// the update-time side of the window guard admits the old operator and widens
/// this event's attribution into unrelated history.
#[test]
fn comment_created_and_updated_before_window_stays_excluded() {
    let (poller, engine, path, _) = fixture("actor-window-historical-update");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);

    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([
            {
                "user": {"login": "historical-operator"},
                "created_at": "2026-08-20T11:59:57Z",
                "updated_at": "2026-08-20T11:59:58Z"
            },
            {
                "user": {"login": "new-external"},
                "created_at": "2026-08-20T12:00:01Z",
                "updated_at": "2026-08-20T12:00:01Z"
            }
        ]),
        Some(vec!["new-external"]),
    );
    let _ = std::fs::remove_file(path);
}

/// An edit reported in the host observation's second is just as ambiguous as a
/// creation in that second. The whole actor set must stay unknown rather than
/// preserving only the definitely newer operator.
#[test]
fn same_second_comment_update_fails_open_to_unknown() {
    let (poller, engine, path, _) = fixture("actor-window-same-second-update");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);

    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([
            {
                "user": {"login": "operator"},
                "created_at": "2026-08-20T12:00:01Z",
                "updated_at": "2026-08-20T12:00:01Z"
            },
            {
                "user": {"login": "same-second-human"},
                "created_at": "2026-08-20T11:59:58Z",
                "updated_at": "2026-08-20T12:00:00Z"
            }
        ]),
        None,
    );
    let _ = std::fs::remove_file(path);
}

/// A comment created after the host's previous observation can share its
/// vendor-reported second because GitHub omits sub-second precision. That
/// ambiguous comment makes the complete actor set unknown, even when another
/// comment has a definitely newer timestamp. This fail-open result prevents a
/// partial actor set from suppressing a wake.
#[test]
fn same_second_comment_after_previous_observation_fails_open_to_unknown() {
    let (poller, engine, path, _) = fixture("actor-window-same-second");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "before"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    // The comment was created after this .500 observation, but the vendor can
    // report only the containing second and therefore sends 12:00:00Z.
    let previous = 1_787_227_200_500_i64;
    let conn = rusqlite::Connection::open(&path).expect("open same-second fixture");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![previous, PRINCIPAL, id],
        )
        .expect("pin previous observation"),
        1
    );
    drop(conn);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([
            {
                "user": {"login": "same-second-human"},
                "created_at": "2026-08-20T12:00:00Z"
            },
            {
                "user": {"login": "definitely-newer"},
                "created_at": "2026-08-20T12:00:01Z"
            }
        ])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "after"}],
            "next_cursor": "tok-2"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list same-second events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed version stored");
    assert_eq!(
        changed.actor_logins, None,
        "same-second uncertainty must fail open rather than store a partial set"
    );
    let _ = std::fs::remove_file(path);
}

/// The definitely newer agent comment is intentionally ordered before the
/// ambiguous human comment. If the ambiguous branch returns actors collected
/// so far, it stores an agent-only set; the downstream all-agent matcher then
/// suppresses the wake and hides the human activity. This ordering is
/// load-bearing because an empty partial set is already collapsed to unknown.
#[test]
fn ambiguous_human_after_collected_agent_cannot_leave_suppressing_partial_set() {
    let (poller, engine, path, _) = fixture("actor-window-agent-before-ambiguous-human");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "before"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    let previous = 1_787_227_200_500_i64;
    let conn = rusqlite::Connection::open(&path).expect("open partial-set fixture");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![previous, PRINCIPAL, id],
        )
        .expect("pin previous observation"),
        1
    );
    drop(conn);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([
            {
                "user": {"login": "agent-bot"},
                "created_at": "2026-08-20T12:00:01Z"
            },
            {
                "user": {"login": "same-second-human"},
                "created_at": "2026-08-20T12:00:00Z"
            }
        ])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "after"}],
            "next_cursor": "tok-2"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list partial-set events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed version stored");
    assert_eq!(
        changed.actor_logins, None,
        "an ambiguous human must not leave behind a suppressing agent-only set"
    );
    let _ = std::fs::remove_file(path);
}

/// Replays an anonymized `get_comments` capture from GitHub issue
/// cortexkit/magic-context#289 (captured live 2026-08-22). Two comments predate
/// the pinned previous observation and one follows it. Extraction must keep
/// only the later commenter, so old comments cannot suppress new activity.
///
/// The windowing proved here is a contract with a consumer, not just local
/// coverage: the prefrontal module's echo-suppression matcher pins the same
/// issue's actor set as its fixture and suppresses a wake only when EVERY
/// login in the set is an operator or the agent itself. That fold is only
/// correct over new-since-last-seen actors — if this code regressed to
/// returning all historical commenters, a months-old operator comment would
/// make the fold suppress an event whose new activity is external. Weakening
/// this test therefore breaks suppression correctness in prefrontal, silently.
///
/// The boundary arithmetic itself is proved by
/// `actor_window_excludes_before_and_includes_after_previous_observation`;
/// this test adds the real vendor payload shape (full comment objects, real
/// timestamps) over the same window logic.
#[test]
fn the_real_mc289_payload_windows_to_the_single_in_window_commenter() {
    let (poller, engine, path, _) = fixture("actor-window-mc289");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-289", "number": 289, "title": "before"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    // 2026-08-15T00:00:00Z: after both Aug-09 comments, before the Aug-21 one.
    let previous = 1_786_752_000_000_i64;
    let conn = rusqlite::Connection::open(&path).expect("open mc289 fixture");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![previous, PRINCIPAL, id],
        )
        .expect("pin previous observation"),
        1
    );
    drop(conn);
    let real_payload: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mc289_get_comments.json"))
            .expect("parse vendored mc289 payload");
    assert_eq!(
        real_payload.as_array().map(Vec::len),
        Some(3),
        "the vendored payload must still carry all three comments; \
         a shrunken fixture would pass the window assertion vacuously"
    );
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(real_payload),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-289", "number": 289, "title": "after"}],
            "next_cursor": "tok-2"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list mc289 events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed version stored");
    assert_eq!(
        changed.actor_logins,
        Some(vec!["octo-sprout".to_string()]),
        "only the in-window commenter may survive; the two Aug-09 authors \
         predate the pinned observation"
    );
    let _ = std::fs::remove_file(path);
}

/// Known empty and unknown actor sets survive as opposite storage and wire
/// shapes: `[]` for a successful empty first-observation read, NULL/absent for a
/// failed first-observation read. A later title-only change with a successful
/// empty comment window is also unknown because the comment endpoint cannot name
/// that actor.
///
/// Each collapse is a separate mutation. Mapping failure to empty breaks the
/// second assertion; mapping successful empty to unknown breaks the first.
#[test]
fn successful_empty_and_failed_actor_reads_do_not_collapse() {
    let (poller, engine, path, _) = fixture("actor-empty-unknown");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "first"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::VendorError {
            code: "comments_unavailable".to_string(),
            message: "unavailable".to_string(),
        },
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-18", "number": 18, "title": "second"}],
            "next_cursor": "tok-2"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "third"}],
            "next_cursor": "tok-3"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list empty and unknown events");
    let known_empty = events
        .iter()
        .find(|event| event.payload["title"] == "first")
        .expect("known-empty event");
    let failed_unknown = events
        .iter()
        .find(|event| event.payload["title"] == "second")
        .expect("failed-read event");
    let non_comment_unknown = events
        .iter()
        .find(|event| event.payload["title"] == "third")
        .expect("title-only event");
    assert_eq!(known_empty.actor_logins, Some(Vec::new()));
    assert_eq!(failed_unknown.actor_logins, None);
    assert_eq!(non_comment_unknown.actor_logins, None);
    assert!(
        serde_json::to_value(failed_unknown)
            .expect("serialize unknown event")
            .get("actor_logins")
            .is_none(),
        "unknown actors must be absent rather than serialized as null or empty"
    );
    let _ = std::fs::remove_file(path);
}

/// Pull requests require both GitHub comment objects. Their actor sets are
/// unioned only after both governed reads complete.
///
/// Dropping either method removes its unique login and fails the assertion; the
/// request-method assertion also proves both calls traversed dispatch.
#[test]
fn pull_request_actors_union_issue_and_review_comments() {
    let (poller, engine, path, _) = fixture("pr-actors");
    let id = actor_subscription(
        &engine,
        PR_FEED,
        PULL_REQUEST_READ,
        &["get_comments", "get_review_comments"],
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "pr-7", "number": 7, "title": "changed"}],
            "next_cursor": "tok-1"
        })));
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_comments",
        MockResponse::Success(json!([{
            "user": {"login": "alice"},
            "created_at": "2026-08-20T12:00:00Z"
        }])),
    );
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_review_comments",
        MockResponse::Success(json!({
            "review_threads": [{
                "comments": [{
                    "author": "bob",
                    "created_at": "2026-08-20T12:01:00Z"
                }],
                "total_count": 1
            }],
            "totalCount": 1,
            "pageInfo": {"hasNextPage": false}
        })),
    );

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list PR event")
        .pop()
        .expect("PR event stored");
    assert_eq!(
        event.actor_logins,
        Some(vec!["alice".to_string(), "bob".to_string()])
    );
    let actor_requests = engine
        .transport()
        .requests()
        .into_iter()
        .filter(|request| request.action == PULL_REQUEST_READ)
        .collect::<Vec<_>>();
    assert_eq!(actor_requests.len(), 2);
    let methods = actor_requests
        .iter()
        .map(|request| request.args["method"].as_str().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        methods,
        BTreeSet::from(["get_comments", "get_review_comments"])
    );
    assert!(actor_requests.iter().all(|request| {
        request.args["pullNumber"] == 7 && request.args.get("issue_number").is_none()
    }));
    let _ = std::fs::remove_file(path);
}

#[test]
fn pr_v2_comment_metadata_reuses_actor_reads_without_extra_calls() {
    let (poller, engine, path, _) = fixture("pr-v2-comment");
    let id = actor_subscription(
        &engine,
        PR_FEED,
        PULL_REQUEST_READ,
        &["get_comments", "get_review_comments"],
    );
    let mut manifest = manifest_value();
    manifest["key"] = json!("github");
    manifest["actions_baseline"][1]["name"] = json!("list_pull_requests");
    engine
        .store()
        .upsert_manifest(
            plexus_core::CATALOG_PRINCIPAL,
            &ingest_value(manifest).unwrap(),
        )
        .unwrap();
    upsert_action_with_schema(
        &engine,
        "list_pull_requests",
        "read",
        &schema_hash(),
        "active",
        json!({"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"},"sync_token":{"type":"string"}},"required":["owner","repo"]}),
    );
    insert_poll_grant(&engine, "list_pull_requests");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE connections SET app_key='github' WHERE connection_id=?1",
        [CONNECTION],
    )
    .unwrap();
    db.execute(
        "UPDATE trigger_subscriptions SET action='list_pull_requests' WHERE subscription_id=?1",
        [&id],
    )
    .unwrap();
    engine
        .store()
        .record_repo_id_resolution("cortexkit/plexus", Some(101), plexus_core::now_ms())
        .unwrap();
    engine.transport().set_response(MockResponse::Success(json!({"items":[{
        "id":"pr-7","number":7,"title":"changed","created_at":"2026-08-20T12:00:00Z","updated_at":"2026-08-20T12:02:00Z"
    }],"next_cursor":"tok-1"})));
    engine.transport().set_response_for_method(PULL_REQUEST_READ,"get_comments",MockResponse::Success(json!([
        {"created_at":"2026-08-20T12:00:00Z","html_url":"https://github.com/cortexkit/plexus/pull/7#issuecomment-1","user":{"login":"alice"}},
        {"created_at":"2026-08-20T12:01:00Z","html_url":"https://github.com/cortexkit/plexus/pull/7#issuecomment-2","user":{"login":"bob"}}
    ])));
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_review_comments",
        MockResponse::Success(
            json!({"review_threads":[],"totalCount":0,"pageInfo":{"hasNextPage":false}}),
        ),
    );
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let pending = engine.store().drain_event_outbox_version(10, 2).unwrap();
    assert_eq!(pending.len(), 1);
    let body: Value = serde_json::from_str(pending[0].envelope_v2.as_ref().unwrap()).unwrap();
    assert_eq!(body["kind"], "pull_request");
    assert_eq!(body["number"], 7);
    assert_eq!(
        body["comment_url"],
        "https://github.com/cortexkit/plexus/pull/7#issuecomment-2"
    );
    assert_eq!(body["comment_author"], "bob");
    assert_eq!(body["actor_logins"], json!(["alice", "bob"]));
    let requests = engine.transport().requests();
    assert_eq!(
        requests.len(),
        3,
        "v2 comment metadata must add no GitHub calls"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.action == PULL_REQUEST_READ)
            .count(),
        2
    );
    assert!(!requests.iter().any(|r| r.action == "get_repository"));
}

/// A review thread with an unrecognisable leaf invalidates the whole actor set,
/// even when the issue-style read already yielded a valid login.
///
/// Accepting partial extraction stores `alice` and fails this NULL assertion.
#[test]
fn unrecognised_review_comment_shape_is_unknown_not_partial() {
    let (poller, engine, path, _) = fixture("pr-review-unknown");
    let id = actor_subscription(
        &engine,
        PR_FEED,
        PULL_REQUEST_READ,
        &["get_comments", "get_review_comments"],
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "pr-7", "number": 7, "title": "changed"}],
            "next_cursor": "tok-1"
        })));
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_comments",
        MockResponse::Success(json!([{
            "user": {"login": "alice"},
            "created_at": "2026-08-20T12:00:00Z"
        }])),
    );
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_review_comments",
        MockResponse::Success(json!({
            "review_threads": [{
                "comments": [{
                    "author": 42,
                    "created_at": "2026-08-20T12:01:00Z"
                }],
                "total_count": 1
            }],
            "totalCount": 1,
            "pageInfo": {"hasNextPage": false}
        })),
    );

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list malformed-review event")
        .pop()
        .expect("event stored");
    assert_eq!(event.actor_logins, None);
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == PULL_REQUEST_READ)
            .count(),
        2,
        "both PR actor objects must be read before the malformed leaf is judged"
    );
    let _ = std::fs::remove_file(path);
}

/// Revoking only the enrichment connection cannot damage the working feed. The
/// watched poll still commits its cursor and event, while actors remain unknown
/// and the vendor-failure streak follows the successful watched read.
///
/// Propagating any enrichment refusal fails the Completed, cursor, and event
/// assertions together.
#[test]
fn enrichment_authority_failure_is_isolated_from_poll_success() {
    let (poller, engine, path, _) = fixture("actor-failure-isolation");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    assert!(engine
        .store()
        .revoke_connection(PRINCIPAL, ACTOR_CONNECTION)
        .expect("revoke actor connection"));
    let streak_before = subscription(&engine, &id).consecutive_vendor_failures;
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-advanced"
        })));

    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let stored = subscription(&engine, &id);
    assert_eq!(stored.cursor_state, json!({"sync_token": "tok-advanced"}));
    assert_eq!(stored.consecutive_vendor_failures, streak_before);
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list isolated event")
        .pop()
        .expect("event stored");
    assert_eq!(event.actor_logins, None);
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        0,
        "revoked enrichment authority must refuse before vendor dispatch"
    );
    let _ = std::fs::remove_file(path);
}

/// A large derived batch can issue at most the named enrichment-call cap. Events
/// beyond it are still committed with unknown actors.
///
/// Removing the cap makes the transport count and known/unknown split both fail.
#[test]
fn actor_enrichment_call_cap_bounds_a_poll_cycle() {
    let (poller, engine, path, _) = fixture("actor-call-cap");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    let items = (0..=ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE)
        .map(|index| {
            json!({
                "id": format!("issue-{index}"),
                "number": index + 1,
                "title": format!("item-{index}")
            })
        })
        .collect::<Vec<_>>();
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": items,
            "next_cursor": "tok-cap"
        })));
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );

    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE + 1,
            duplicates: 0
        }
    );
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list capped events");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.actor_logins == Some(Vec::new()))
            .count(),
        ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.actor_logins.is_none())
            .count(),
        1
    );
    let _ = std::fs::remove_file(path);
}

/// A two-method event at the cycle cap consumes at most 32 governed reads; the
/// 33rd is refused and that event stays unknown.
///
/// Sixteen complete pull requests spend the cap. A seventeenth is stored, but
/// must not dispatch either actor method.
///
/// MUTATION: taking one first attempt instead of reserving both lets the last
/// event dispatch call 33 and reddens the request-count assertion.
#[test]
fn two_method_event_at_the_call_cap_refuses_the_33rd_read() {
    let (poller, engine, path, _) = fixture("pr-call-cap-33");
    let id = actor_subscription(
        &engine,
        PR_FEED,
        PULL_REQUEST_READ,
        &["get_comments", "get_review_comments"],
    );
    let fully_enriched_events = ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE / 2;
    assert_eq!(
        fully_enriched_events * 2,
        ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE
    );
    let items = (0..=fully_enriched_events)
        .map(|index| {
            json!({
                "id": format!("pr-{index}"),
                "number": index + 1,
                "title": format!("item-{index}")
            })
        })
        .collect::<Vec<_>>();
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": items,
            "next_cursor": "tok-pr-cap-33"
        })));
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_review_comments",
        MockResponse::Success(json!({
            "review_threads": [],
            "totalCount": 0,
            "pageInfo": {"hasNextPage": false}
        })),
    );

    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: fully_enriched_events + 1,
            duplicates: 0
        }
    );
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == PULL_REQUEST_READ)
            .count(),
        ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE,
        "a two-method event must not dispatch a 33rd governed read"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list two-method capped events");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.actor_logins == Some(Vec::new()))
            .count(),
        fully_enriched_events
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.actor_logins.is_none())
            .count(),
        1
    );
    let _ = std::fs::remove_file(path);
}

/// A retry for one method must leave room for every undispatched method of the
/// same event. Fifteen complete pull requests spend 30 calls; the next comment
/// read fails on call 31, so retrying it would force the review read to call 33.
///
/// MUTATION: restoring the unconditional retry dispatches both calls 32 and 33,
/// reddening the exact request-count assertion.
#[test]
fn two_method_retry_preserves_cycle_call_cap() {
    let (poller, engine, path, _) = fixture("pr-retry-cap");
    let id = actor_subscription(
        &engine,
        PR_FEED,
        PULL_REQUEST_READ,
        &["get_comments", "get_review_comments"],
    );
    let calls_before_boundary = ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE - 2;
    let fully_enriched_events = calls_before_boundary / 2;
    assert_eq!(fully_enriched_events * 2, calls_before_boundary);
    let items = (0..=fully_enriched_events)
        .map(|index| {
            json!({
                "id": format!("pr-{index}"),
                "number": index + 1,
                "title": format!("item-{index}")
            })
        })
        .collect::<Vec<_>>();
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": items,
            "next_cursor": "tok-pr-retry-cap"
        })));
    let mut comment_responses = vec![MockResponse::Success(json!([])); fully_enriched_events];
    comment_responses.push(MockResponse::TransientNotSent {
        message: "pool hiccup".to_string(),
    });
    comment_responses.push(MockResponse::Success(json!([])));
    engine.transport().set_response_sequence_for_method(
        PULL_REQUEST_READ,
        "get_comments",
        comment_responses,
    );
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_review_comments",
        MockResponse::Success(json!({
            "review_threads": [],
            "totalCount": 0,
            "pageInfo": {"hasNextPage": false}
        })),
    );

    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: fully_enriched_events + 1,
            duplicates: 0
        }
    );
    let actor_requests = engine
        .transport()
        .requests()
        .into_iter()
        .filter(|request| request.action == PULL_REQUEST_READ)
        .collect::<Vec<_>>();
    assert_eq!(
        actor_requests.len(),
        ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE - 1,
        "the failed call 31 must not spend the retry reserved for calls 32 and 33"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list retry-fenced PR events");
    let boundary = events
        .iter()
        .find(|event| event.payload["title"] == format!("item-{fully_enriched_events}"))
        .expect("boundary PR event stored");
    assert_eq!(boundary.actor_logins, None);
    let _ = std::fs::remove_file(path);
}

/// A pull request that cannot afford both actor reads must dispatch neither one.
/// One earlier retry makes fifteen complete events consume 31 calls, leaving the
/// next event with too little room; its actor set therefore remains unknown.
///
/// MUTATION: dispatching each affordable method and returning the accumulated
/// actors stores the operator-only partial set instead of NULL.
#[test]
fn budget_exhaustion_keeps_two_method_enrichment_atomic() {
    let (poller, engine, path, _) = fixture("pr-atomic-cap");
    let id = actor_subscription(
        &engine,
        PR_FEED,
        PULL_REQUEST_READ,
        &["get_comments", "get_review_comments"],
    );
    let calls_before_boundary = ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE - 1;
    let fully_enriched_events = (calls_before_boundary - 1) / 2;
    assert_eq!(fully_enriched_events * 2 + 1, calls_before_boundary);
    let items = (0..=fully_enriched_events)
        .map(|index| {
            json!({
                "id": format!("pr-{index}"),
                "number": index + 1,
                "title": format!("item-{index}")
            })
        })
        .collect::<Vec<_>>();
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": items,
            "next_cursor": "tok-pr-atomic-cap"
        })));
    engine.transport().set_response_sequence_for_method(
        PULL_REQUEST_READ,
        "get_comments",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "pool hiccup".to_string(),
            },
            MockResponse::Success(json!([{
                "user": {"login": "octo-lantern"},
                "created_at": "2026-08-20T12:00:00Z"
            }])),
        ],
    );
    engine.transport().set_response_for_method(
        PULL_REQUEST_READ,
        "get_review_comments",
        MockResponse::Success(json!({
            "review_threads": [{
                "comments": [{
                    "author": "some-external-person",
                    "created_at": "2026-08-20T12:01:00Z"
                }],
                "total_count": 1
            }],
            "totalCount": 1,
            "pageInfo": {"hasNextPage": false}
        })),
    );

    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: fully_enriched_events + 1,
            duplicates: 0
        }
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list atomically capped PR events");
    let boundary = events
        .iter()
        .find(|event| event.payload["title"] == format!("item-{fully_enriched_events}"))
        .expect("budget-exhausted PR event stored");
    assert_eq!(
        boundary.actor_logins, None,
        "an event must never retain actors from only its affordable method"
    );
    let boundary_number = u64::try_from(fully_enriched_events + 1).expect("test index fits u64");
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| {
                request.action == PULL_REQUEST_READ && request.args["pullNumber"] == boundary_number
            })
            .count(),
        0,
        "a budget-exhausted event must dispatch none of its methods"
    );
    let _ = std::fs::remove_file(path);
}

/// A transient dispatch failure is retried once and, when the retry succeeds,
/// the event is attributed rather than stored as unknown.
///
/// The first attempt for the method fails transiently; the retry returns the
/// comment payload, so the event row carries the attributed logins and the
/// dispatch count shows exactly two calls for that method.
///
/// MUTATION: removing the retry (single attempt) makes the first failure
/// collapse to NULL and the dispatch count drop to 1, reddening both the
/// actor_logins and the count assertions.
#[test]
fn transient_dispatch_failure_is_retried_once_and_attributes() {
    let (poller, engine, path, _) = fixture("actor-transient-retry");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_sequence_for_method(
        ISSUE_READ,
        "get_comments",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "pool hiccup".to_string(),
            },
            MockResponse::Success(json!([{
                "user": {"login": "alice"},
                "created_at": "2026-08-20T12:00:00Z"
            }])),
        ],
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list retried event")
        .pop()
        .expect("retried event stored");
    assert_eq!(
        event.actor_logins,
        Some(vec!["alice".to_string()]),
        "the retried read must attribute the event"
    );
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        2,
        "the transient failure must be retried exactly once"
    );
    let _ = std::fs::remove_file(path);
}

/// Two consecutive transient failures leave the event unknown, with no third
/// attempt.
///
/// MUTATION: an unbounded retry (loop until success) keeps dispatching past
/// the second failure and reddens the dispatch-count assertion.
#[test]
fn transient_twice_stays_unknown() {
    let (poller, engine, path, _) = fixture("actor-transient-twice");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_sequence_for_method(
        ISSUE_READ,
        "get_comments",
        vec![
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "pool hiccup".to_string(),
            },
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "still down".to_string(),
            },
        ],
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list twice-failed event")
        .pop()
        .expect("twice-failed event stored");
    assert_eq!(event.actor_logins, None);
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        2,
        "both attempts fail and no third attempt is made"
    );
    let _ = std::fs::remove_file(path);
}

/// A deterministic miss (unbuildable actor-read args) is never retried.
///
/// The event carries no `number` field, so `actor_read_args` cannot build the
/// request. The same inputs always produce the same outcome, so a retry would
/// burn a governed read to learn nothing. Even a transient response is ignored
/// because the miss short-circuits before dispatch.
///
/// MUTATION: retrying class (b) dispatches for the unbuildable event and
/// reddens the dispatch-count assertion.
#[test]
fn deterministic_miss_does_not_retry() {
    let (poller, engine, path, _) = fixture("actor-deterministic-miss");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "title": "no-number"}],
            "next_cursor": "tok-1"
        })));
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::TransientNotSent {
            message: "unreachable".to_string(),
        },
    );

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    let event = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list deterministic-miss event")
        .pop()
        .expect("deterministic-miss event stored");
    assert_eq!(event.actor_logins, None);
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        0,
        "an unbuildable-args miss must not dispatch, let alone retry"
    );
    let _ = std::fs::remove_file(path);
}

/// A semantic unknown (later observation, empty in-window actor set) is never
/// retried.
///
/// The vendor already answered the question: there are no comment actors in the
/// window, which is unattributable by design. The dispatch succeeds, so a retry
/// would re-ask a question the vendor already answered.
///
/// MUTATION: retrying class (c) dispatches a second time for the later
/// observation and reddens the dispatch-count assertion.
#[test]
fn semantic_unknown_does_not_retry() {
    let (poller, engine, path, _) = fixture("actor-semantic-unknown");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    // The empty comment window falls through to the timeline, which is empty
    // too, so the event stays `empty_actor_window`.
    bind_timeline_handle(&engine, true);
    set_timeline_pages(&engine, vec![json!([])]);
    // First observation: an empty complete history is a known empty set.
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "first"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    // Pin the previous observation to a past millisecond so the second poll is
    // a later observation.
    let previous = 1_787_227_200_000_i64;
    let conn = rusqlite::Connection::open(&path).expect("open semantic fixture");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![previous, PRINCIPAL, id],
        )
        .expect("pin previous observation"),
        1
    );
    drop(conn);

    // Later observation: dispatch succeeds but the window has zero comments.
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "second"}],
            "next_cursor": "tok-2"
        })));
    let dispatches_before = engine
        .transport()
        .requests()
        .iter()
        .filter(|request| request.action == ISSUE_READ)
        .count();
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list semantic-unknown events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "second")
        .expect("second event stored");
    assert_eq!(
        changed.actor_logins, None,
        "an empty in-window set on a later observation is unknown"
    );
    let dispatches_after = engine
        .transport()
        .requests()
        .iter()
        .filter(|request| request.action == ISSUE_READ)
        .count();
    assert_eq!(
        dispatches_after - dispatches_before,
        1,
        "the semantic-unknown read must dispatch exactly once, never retried"
    );
    let _ = std::fs::remove_file(path);
}

/// A retry that would exceed the cycle call cap is refused: the first attempt
/// fits, the retry would not, so exactly the capped number of dispatches occur
/// and the event stays unknown.
///
/// The first 31 events each dispatch once and succeed; the 32nd event's first
/// attempt is the 32nd call and fails transiently, so its retry would be the
/// 33rd call and is blocked by the cap.
///
/// MUTATION: a retry that ignores the cap dispatches a 33rd time and reddens
/// the dispatch-count assertion.
#[test]
fn retry_respects_the_cycle_call_cap() {
    let (poller, engine, path, _) = fixture("actor-cap-fence");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    let items = (0..ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE)
        .map(|index| {
            json!({
                "id": format!("issue-{index}"),
                "number": index + 1,
                "title": format!("item-{index}")
            })
        })
        .collect::<Vec<_>>();
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": items,
            "next_cursor": "tok-cap"
        })));
    // 31 successes then a transient failure for the 32nd call.
    let mut sequence =
        vec![MockResponse::Success(json!([])); ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE - 1];
    sequence.push(MockResponse::TransientNotSent {
        message: "pool hiccup".to_string(),
    });
    engine
        .transport()
        .set_response_sequence_for_method(ISSUE_READ, "get_comments", sequence);

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE,
            ..
        }
    ));
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE,
        "the retry must not overrun the cycle cap"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list cap-fenced events");
    let last = events
        .iter()
        .find(|event| {
            event.payload["title"] == format!("item-{}", ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE - 1)
        })
        .expect("last event stored");
    assert_eq!(
        last.actor_logins, None,
        "the capped-out event stays unknown"
    );
    let _ = std::fs::remove_file(path);
}

/// A subscription may only name an action reviewed as `read`, and may only be
/// created with poll authority. Both refusals leave no subscription behind.
///
/// These are the two gates that decide what a trigger is ALLOWED to be, and
/// they are the reason a poller cannot become a general execution channel. A
/// subscription runs unattended on a timer, so anything it can reach runs
/// without anyone present to judge it: a write reachable this way would be a
/// standing authorization to mutate a vendor with no operator in the loop.
/// Requiring poll authority specifically -- an invoke grant is not enough --
/// keeps the decision to poll separate from the decision to call, so an agent
/// granted an action cannot convert that into a permanent background loop.
///
/// The stored-state assertion is the load-bearing one in both halves. A refusal
/// that returns an error AFTER writing the row would leave a subscription that
/// the scheduler picks up on its next tick, and the returned error would look
/// identical to a correct refusal.
///
/// Mutation-proved in three parts, one per gate: ignoring the action risk
/// accepts the write, ignoring the grant's selectors accepts a subscription
/// covered only by another action's grant, and ignoring the grant's deadline
/// accepts one on lapsed authority. Each fails on its refusal and on the
/// stored state.
#[test]
fn subscribe_refuses_a_write_action_and_a_missing_poll_grant() {
    let (_, engine, path, _) = fixture("subscribe-authority");

    // A write action, otherwise perfectly subscribable: active, schema'd, and
    // covered by a poll grant, so risk is the only thing that can refuse it.
    upsert_action_with_schema(
        &engine,
        "send_message",
        "write",
        &schema_hash(),
        "active",
        json!({"type": "object", "properties": {}}),
    );
    insert_poll_grant(&engine, "send_message");

    let refusal = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            "send_message",
            30,
            &json!({}),
            &json!({}),
        )
        .expect("subscribe check")
        .expect_err("a write action must not be subscribable");
    assert_eq!(refusal, SubscriptionRefusal::ActionRiskNotRead);
    assert_eq!(refusal.code(), "trigger_requires_read_action");

    // A manifest-declared read action whose poll grant is revoked, while OTHER
    // poll grants remain on the same connection. Both details are load-bearing.
    //
    // It must be an action the manifest declares a cursor shape for, because an
    // undeclared one is refused earlier as `cursor_shape_missing` and never
    // reaches this gate -- the assertion below would pass for the wrong reason.
    //
    // And leaving the fixture's other poll grants in place is what makes this
    // test discriminating: the gate resolves the nearest grant on the
    // connection, which is `Some` whenever ANY poll grant exists. A fixture
    // that revoked every grant would leave that resolver empty and pass
    // against a check that never inspects what it found.
    assert!(
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{VENDOR_NAMED}"))
            .expect("revoke poll grant"),
        "the poll grant to revoke must exist"
    );

    let refusal = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            VENDOR_NAMED,
            30,
            &json!({}),
            &json!({}),
        )
        .expect("subscribe check")
        .expect_err("a subscription without poll authority must be refused");
    assert_eq!(refusal, SubscriptionRefusal::PollGrantRequired);
    assert_eq!(refusal.code(), "poll_grant_required");

    // A poll grant that NAMES the action but has expired. Separate from the
    // revoked case above because the two failures are independent: a check that
    // reads the selectors but ignores the deadline refuses the grant above and
    // accepts this one, which would mint a subscription on lapsed authority and
    // poll it indefinitely -- the exact outcome the mandatory expiry exists to
    // prevent.
    assert!(
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{TIMESTAMPED}"))
            .expect("revoke the live grant"),
        "the fixture's live grant for this action must exist"
    );
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-poll-expired-{TIMESTAMPED}"),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![TIMESTAMPED.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(1),
        })
        .expect("insert the expired poll grant");

    let refusal = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({}),
        )
        .expect("subscribe check")
        .expect_err("a subscription on an expired poll grant must be refused");
    assert_eq!(refusal, SubscriptionRefusal::PollGrantRequired);

    let stored = engine
        .store()
        .list_subscriptions(PRINCIPAL, None, None)
        .expect("list subscriptions");
    assert!(
        stored
            .iter()
            .all(|subscription| subscription.action != "send_message"
                && subscription.action != VENDOR_NAMED
                && subscription.action != TIMESTAMPED),
        "a refused subscription must not be left for the scheduler to pick up"
    );

    let _ = std::fs::remove_file(path);
}

/// A fixed cursor argument is refused using the non-default request field read
/// from the manifest. The deliberate `updatedSince` spelling distinguishes
/// configuration-derived ownership from the strategy's `since` default.
///
/// Mutation proved: making `CursorStrategy::owned_keys` return an empty vector,
/// or hardcoding its result to `since`, lets schema validation accept the
/// argument, so this assertion fails.
#[test]
fn subscribe_refuses_a_real_manifest_cursor_key_in_fixed_args() {
    let (_, engine, path, _) = fixture("fixed-owned-key");
    upsert_action_with_schema(
        &engine,
        TIMESTAMPED,
        "read",
        &schema_hash(),
        "active",
        json!({
            "type": "object",
            "properties": {
                "updatedSince": {"type": "string"},
                "owner": {"type": "string"}
            }
        }),
    );

    let refusal = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({"updatedSince": "2024-01-01T00:00:00Z"}),
        )
        .expect("subscribe check")
        .expect_err("a cursor-owned fixed argument must be refused");
    assert_eq!(
        refusal,
        SubscriptionRefusal::FixedArgCursorOwned("updatedSince".to_string())
    );
    assert_eq!(refusal.code(), "fixed_arg_cursor_owned");
    assert!(
        engine
            .store()
            .list_subscriptions(PRINCIPAL, None, None)
            .expect("list subscriptions")
            .iter()
            .all(|subscription| subscription.action != TIMESTAMPED),
        "a refused fixed argument must not create a subscription"
    );
    let _ = std::fs::remove_file(path);
}

/// The sync-token strategy also protects the request name declared by the
/// manifest. `syncToken` is deliberately different from the storage key
/// `sync_token` and the strategy default, matching Google Calendar's shape.
///
/// Mutation proved: hardcoding `owned_keys` to `sync_token` leaves this
/// `syncToken` fixed argument unprotected, so the subscription is accepted and
/// the assertion fails.
#[test]
fn subscribe_refuses_a_declared_sync_token_request_key() {
    let (_, engine, path, _) = fixture("fixed-sync-owned-key");
    upsert_action_with_schema(
        &engine,
        VENDOR_NAMED,
        "read",
        &schema_hash(),
        "active",
        json!({
            "type": "object",
            "properties": {"syncToken": {"type": "string"}}
        }),
    );

    let refusal = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            VENDOR_NAMED,
            30,
            &json!({}),
            &json!({"syncToken": "must-not-pin"}),
        )
        .expect("subscribe check")
        .expect_err("a manifest-owned sync request key must be refused");
    assert_eq!(
        refusal,
        SubscriptionRefusal::FixedArgCursorOwned("syncToken".to_string())
    );
    assert_eq!(refusal.code(), "fixed_arg_cursor_owned");
    assert!(
        engine
            .store()
            .list_subscriptions(PRINCIPAL, None, None)
            .expect("list subscriptions")
            .iter()
            .all(|subscription| subscription.action != VENDOR_NAMED),
        "a refused fixed argument must not create a subscription"
    );
    let _ = std::fs::remove_file(path);
}

/// Fixed arguments are checked against the pinned action schema for key presence
/// and JSON type, without attempting full JSON Schema evaluation.
#[test]
fn subscribe_refuses_undeclared_and_mistyped_fixed_args() {
    let (_, engine, path, _) = fixture("fixed-schema");
    upsert_action_with_schema(
        &engine,
        TIMESTAMPED,
        "read",
        &schema_hash(),
        "active",
        json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"}
            }
        }),
    );

    let undeclared = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({"repo": "hello-world"}),
        )
        .expect("subscribe check")
        .expect_err("an undeclared fixed argument must be refused");
    assert_eq!(undeclared.code(), "fixed_arg_not_declared");

    let mistyped = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({"owner": 42}),
        )
        .expect("subscribe check")
        .expect_err("a mistyped fixed argument must be refused");
    assert_eq!(mistyped.code(), "fixed_arg_type_mismatch");
    let _ = std::fs::remove_file(path);
}

/// A required argument the subscription cannot supply is refused at subscribe,
/// not discovered at the first poll.
///
/// The poller builds every request from the cursor strategy, the manifest's
/// request constants and `fixed_args`. An argument the vendor requires and none
/// of those three provides can never appear, so the subscription is not merely
/// misconfigured — it is incapable of ever succeeding.
///
/// Accepting it defers the failure rather than preventing it, and the deferred
/// form is much worse to diagnose: the subscription polls on its cadence and is
/// rejected by the vendor every time, which reads as a flaky integration rather
/// than a subscription that was never viable. Exponential backoff then makes it
/// quieter the longer it runs.
///
/// The second half is the one that keeps the check from over-refusing: a key
/// the CURSOR or a manifest constant supplies is not missing, and demanding it
/// in `fixed_args` would make the action unsubscribable for requiring exactly
/// what the poller already sends — while the collision checks refuse that same
/// key if a subscription tries to set it.
///
/// Mutation-proved: dropping the required-key loop accepts the first case;
/// dropping the `supplied_elsewhere` carve-out refuses the second.
#[test]
fn subscribe_refuses_a_required_argument_nothing_can_supply() {
    let (_, engine, path, _) = fixture("fixed-required");
    upsert_action_with_schema(
        &engine,
        TIMESTAMPED,
        "read",
        &schema_hash(),
        "active",
        json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"}
            },
            "required": ["owner", "repo"]
        }),
    );

    let missing = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({"owner": "rust-lang"}),
        )
        .expect("subscribe check")
        .expect_err("a required argument nothing supplies must be refused");
    assert_eq!(
        missing,
        SubscriptionRefusal::FixedArgRequiredMissing("repo".to_string())
    );
    assert_eq!(missing.code(), "fixed_arg_required_missing");
    assert!(
        engine
            .store()
            .list_subscriptions(PRINCIPAL, None, None)
            .expect("list subscriptions")
            .iter()
            .all(|subscription| subscription.action != TIMESTAMPED),
        "a refused subscription must not be created"
    );

    // Supplying both required keys is accepted, so the refusal above is about
    // the missing key rather than the check refusing everything.
    engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({"owner": "rust-lang", "repo": "rust"}),
        )
        .expect("subscribe check")
        .expect("a fully scoped subscription must be accepted");

    let _ = std::fs::remove_file(path);
}

/// A required key the POLLER supplies must not be demanded from the operator.
///
/// The companion to the test above, and the reason the required check needs a
/// carve-out at all: a vendor may mark its cursor parameter required, and the
/// cursor strategy supplies that key on every request. Without the carve-out
/// such an action becomes permanently unsubscribable — and the operator cannot
/// satisfy it either, because setting a cursor-owned key in `fixed_args` is
/// refused by design (it would pin the watermark forever).
#[test]
fn subscribe_allows_a_required_key_the_cursor_supplies() {
    let (_, engine, path, _) = fixture("fixed-required-cursor");
    upsert_action_with_schema(
        &engine,
        TIMESTAMPED,
        "read",
        &schema_hash(),
        "active",
        json!({
            "type": "object",
            // `updatedSince` is what this action's manifest declares as its
            // cursor request key, so it is the key the strategy supplies. Using
            // a plausible-looking name like `since` instead would test nothing:
            // the carve-out is keyed on the DECLARED name, and a mismatched one
            // is genuinely missing.
            "properties": {
                "owner": {"type": "string"},
                "updatedSince": {"type": "string"}
            },
            "required": ["owner", "updatedSince"]
        }),
    );

    engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            30,
            &json!({}),
            &json!({"owner": "rust-lang"}),
        )
        .expect("subscribe check")
        .expect("a required cursor key must not be demanded from fixed_args");

    let _ = std::fs::remove_file(path);
}

/// An expired poll grant suspends the subscription and reaches no vendor.
///
/// This path fires for EVERY trigger subscription eventually: poll grants carry
/// a mandatory finite expiry, refused at mint time without one, precisely so
/// that polling authority cannot outlive the attention that granted it. The end
/// of a grant's life is therefore ordinary operation rather than an error case,
/// and what happens at that moment is worth pinning.
///
/// Suspension is correct here, and it is NOT the same judgement as the
/// transient-vault case below. A vault blip is a momentary fault that resolves
/// itself, so retrying is right. An expiry is a decision that has run out, and
/// resuming would extend authority nobody renewed -- the one thing the
/// mandatory expiry exists to prevent. The subscription stays suspended until
/// an operator mints a fresh grant.
///
/// The reason code is asserted as well as the status, because an operator
/// reading `grant_expired` renews a grant while one reading a generic failure
/// hunts a vendor problem. The zero-request assertion proves the refusal
/// happened BEFORE dispatch rather than being reported after a call went out.
///
/// Mutation-proved: dropping the expiry check in `authorize` lets the poll
/// reach the vendor, failing this on both the request count and the status.
#[test]
fn an_expired_poll_grant_suspends_the_subscription() {
    let (poller, engine, path, subscription_id) = fixture("grant-expired");

    // Replace the fixture's live grant with an expired one, leaving everything
    // else intact so the expiry is the only thing that can refuse this poll.
    // Revoked first because a grant id is unique per principal, and because
    // leaving the live grant in place would let it satisfy the poll and prove
    // nothing.
    assert!(
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{FEED}"))
            .expect("revoke the fixture grant"),
        "the fixture grant must exist to be replaced"
    );
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-poll-{FEED}-expired"),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![FEED.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(1),
        })
        .expect("expire the poll grant");

    let cycle = poller.poll_once(PRINCIPAL, &subscription_id);
    let reason = match &cycle {
        PollCycle::Suspended { reason } => reason.clone(),
        other => panic!("an expired poll grant must suspend the subscription: {other:?}"),
    };
    assert_eq!(
        reason, "grant_expired",
        "the reason must tell an operator to renew rather than to chase a vendor"
    );

    let stored = subscription(&engine, &subscription_id);
    assert_eq!(
        stored.status, "suspended",
        "the subscription must not keep polling on expired authority"
    );
    assert!(
        engine.transport().requests().is_empty(),
        "an expired grant must refuse before the vendor is contacted"
    );

    let _ = std::fs::remove_file(path);
}

/// A listed subscription reports the deadline of the authority behind it, and
/// distinguishes lapsed authority from authority that never covered the action.
///
/// The subscription row carries no expiry of its own -- a watch runs until its
/// POLL GRANT lapses, and every poll grant lapses by design, since minting one
/// without a deadline is refused. So the normal end of a watch is invisible from
/// the subscription alone: it stays `active` right up until a poll is refused,
/// and the first sign is a feed that stopped. A consumer cannot warn about that
/// without this field.
///
/// Three states rather than two, because `matching_grant` is a diagnostic
/// resolver whose `Some` may be a grant that names the action but has lapsed, OR
/// one that is live but covers something else. Reporting the second as `expired`
/// would send an operator to renew a deadline that is fine when the selector is
/// the problem.
///
/// Mutation-proved three ways: reporting `live` unconditionally fails the
/// expired leg; deriving the state from the timestamp alone (rather than from
/// `GrantRecord::authorizes`) fails the wrong-action leg, since that grant is
/// unexpired; and dropping the resolution entirely fails the live leg's
/// deadline assertion.
#[test]
fn a_listed_subscription_reports_the_deadline_of_its_authority() {
    let (_poller, engine, path, subscription_id) = fixture("authority-expiry");

    // Leg 1: the fixture's grant is live and names the action.
    let listed = engine
        .store()
        .list_subscriptions(PRINCIPAL, None, Some(&subscription_id))
        .expect("list subscriptions");
    let watch = listed.first().expect("the subscription is listed");
    assert_eq!(
        watch.authority_state, "live",
        "a subscription under a live, action-naming grant must read live"
    );
    assert!(
        watch
            .authority_expires_at_ms
            .is_some_and(|at| at > plexus_core::now_ms()),
        "the deadline must be reported so a consumer can warn before it passes: {:?}",
        watch.authority_expires_at_ms
    );

    // Leg 2: same grant, expired. The deadline must SURVIVE rather than being
    // cleared -- "expired two days ago" is the actionable reading, and an absent
    // value cannot express it.
    assert!(
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{FEED}"))
            .expect("revoke the live grant"),
        "the fixture grant must exist to be replaced"
    );
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-poll-{FEED}-lapsed"),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec![FEED.to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(1),
        })
        .expect("insert the lapsed grant");
    let listed = engine
        .store()
        .list_subscriptions(PRINCIPAL, None, Some(&subscription_id))
        .expect("list subscriptions");
    let watch = listed.first().expect("the subscription is listed");
    assert_eq!(
        watch.authority_state, "expired",
        "a lapsed grant naming the action must read expired"
    );
    assert_eq!(
        watch.authority_expires_at_ms,
        Some(1),
        "the past deadline must survive so the consumer can say how long ago"
    );

    // Leg 3: a LIVE grant that does not name this action. Unexpired, so a
    // timestamp comparison would call it healthy; it authorizes nothing.
    assert!(
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{FEED}-lapsed"))
            .expect("revoke the lapsed grant"),
        "the lapsed grant must exist to be replaced"
    );
    engine
        .store()
        .insert_grant(&GrantInput {
            grant_id: format!("grant-poll-{FEED}-elsewhere"),
            principal: PRINCIPAL.to_string(),
            connection_id: CONNECTION.to_string(),
            grantee_principal: PRINCIPAL.to_string(),
            risk_ceiling: "read".to_string(),
            action_selectors: vec!["some_other_action".to_string()],
            authority_kind: AUTHORITY_POLL.to_string(),
            expires_at: Some(plexus_core::now_ms() + 3_600_000),
        })
        .expect("insert the mismatched grant");
    let listed = engine
        .store()
        .list_subscriptions(PRINCIPAL, None, Some(&subscription_id))
        .expect("list subscriptions");
    let watch = listed.first().expect("the subscription is listed");
    assert_eq!(
        watch.authority_state, "absent",
        "a live grant that does not name the action authorizes nothing"
    );
    assert_eq!(
        watch.authority_expires_at_ms, None,
        "no deadline explains this refusal, so reporting one would mislead"
    );

    let _ = std::fs::remove_file(path);
}

/// A transient vault failure is counted as a vendor failure, never a
/// suspension.
///
/// The distinction is the whole point of the carve-out in `poll_once`. A
/// suspension NEVER auto-resumes by design: the reviewed meaning of an action
/// may have changed, so resuming is fresh operator consent. That is correct for
/// an authorization denial and catastrophic for a momentary vault outage, which
/// would otherwise permanently kill every subscription that happened to tick
/// during it, each needing manual reinstatement.
///
/// Asserted on STORED STATE rather than the returned cycle, because a
/// suspension that happened while reporting a vendor failure is the worse
/// outcome and the return value cannot see it: the row must stay active, and
/// the vendor-failure streak must advance so the existing backoff absorbs the
/// outage and the next tick retries.
///
/// References resolve at dispatch; an unsent failure is inconclusive.
#[test]
fn a_transient_reference_failure_is_inconclusive_instead_of_suspending() {
    let (poller, engine, path, subscription_id) = fixture("vault-transient");

    // Momentarily unavailable rather than refusing: the shape of a locked or
    // restarting credential module, not a revoked handle.
    //
    // Set on the FIXTURE'S HANDLE, not as a default. The stub resolves a
    // handle-specific response first, and the fixture already registered a
    // success for this one, so overriding the default would leave the poll
    // succeeding and the test asserting nothing.
    engine.credential_source().set_error(
        BINDING_HANDLE,
        plexus_core::CredentialError::Transient(plexus_core::TransientCredentialError::VaultLocked),
    );

    let cycle = poller.poll_once(PRINCIPAL, &subscription_id);
    assert!(
        matches!(cycle, PollCycle::Inconclusive { .. }),
        "an unsent reference failure must be inconclusive, not a suspension: {cycle:?}"
    );

    let stored = subscription(&engine, &subscription_id);
    assert_eq!(
        stored.status, "active",
        "the subscription must survive a momentary vault outage"
    );
    assert_eq!(
        stored.consecutive_vendor_failures, 0,
        "an unsent vault failure must not count as a vendor failure"
    );

    let _ = std::fs::remove_file(path);
}

/// A credential only a person can repair (the vault wants the user to
/// authenticate again, or the credential is permanently broken) is reported at
/// dispatch as a request that was not sent. It is inconclusive: the watch stays
/// active and its failure streak untouched, because one such credential
/// usually backs every watch on its connection and suspending them would need
/// each resumed by hand after the repair. The scheduler instead waits an hour
/// before polling the watch again rather than repeating the failure every
/// cadence, and the first successful poll puts it back on its cadence.
#[test]
fn a_credential_needing_human_repair_defers_the_watch_and_recovers_by_itself() {
    for (label, error, code) in [
        (
            "vault-auth-required",
            plexus_core::CredentialError::AuthRequired,
            "credential_auth_required",
        ),
        (
            "vault-permanent",
            plexus_core::CredentialError::Permanent(plexus_core::PermanentCredentialError::Corrupt),
            "credential_permanent",
        ),
    ] {
        let (_poller, engine, path, id) = fixture(label);
        engine.credential_source().set_error(BINDING_HANDLE, error);
        let scheduler = Scheduler::new(engine.clone(), 30 * 86_400_000);
        let principals = [PRINCIPAL.to_string()];
        let polled = |now: i64| -> Vec<PollCycle> {
            scheduler
                .run_pass(&principals, now)
                .into_iter()
                .filter(|outcome| outcome.subscription_id == id)
                .map(|outcome| outcome.cycle)
                .collect()
        };
        let due = |now: i64| {
            scheduler
                .due_now(&principals, now)
                .iter()
                .any(|watch| watch.subscription_id == id)
        };

        let start = plexus_core::now_ms();
        assert_eq!(
            polled(start),
            [PollCycle::Inconclusive {
                code: code.to_string()
            }],
            "{label}"
        );
        let stored = subscription(&engine, &id);
        assert_eq!(stored.status, "active", "{label}");
        assert_eq!(stored.consecutive_vendor_failures, 0, "{label}");

        // Its 30 s cadence has passed, but the watch waits out the hour.
        let one_cadence_later = start + 31_000;
        assert!(!due(one_cadence_later), "{label}: polled before the hour");
        assert!(polled(one_cadence_later).is_empty(), "{label}");
        assert!(!due(start + 3_599_000), "{label}: polled before the hour");

        // The credential is repaired; the hour passes; the poll succeeds.
        engine
            .credential_source()
            .set_success(BINDING_HANDLE, b"vendor-token".to_vec(), None, 1);
        engine.transport().set_response(MockResponse::Success(
            json!({"items": [], "next_cursor": "tok-1"}),
        ));
        let an_hour_later = start + 3_600_000;
        assert!(due(an_hour_later), "{label}: not polled after the hour");
        assert!(
            matches!(polled(an_hour_later)[..], [PollCycle::Completed { .. }]),
            "{label}"
        );
        // Back on its cadence: due again one cadence after the success.
        assert!(
            due(plexus_core::now_ms() + 31_000),
            "{label}: a successful poll must restore the cadence"
        );
        let _ = std::fs::remove_file(path);
    }
}

/// Runs only inside the child process of
/// [`a_credential_needing_repair_is_logged_once_per_state_change`], where it
/// has the process-wide repair metrics and log to itself.
#[test]
fn credential_repair_log_fixture() {
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
        return;
    }
    let (poller, engine, path, id) = fixture("credential-repair-log");
    let repair = || {
        plexus_core::poller::poll_accounting_metrics()["credentialNeedsRepairByConnection"].clone()
    };
    engine
        .credential_source()
        .set_error(BINDING_HANDLE, plexus_core::CredentialError::AuthRequired);
    for _ in 0..3 {
        assert_eq!(
            poller.poll_once(PRINCIPAL, &id),
            PollCycle::Inconclusive {
                code: "credential_auth_required".to_string()
            }
        );
    }
    assert_eq!(
        repair(),
        json!({ (format!("{PRINCIPAL}/{CONNECTION}")): "credential_auth_required" })
    );
    engine
        .credential_source()
        .set_success(BINDING_HANDLE, b"vendor-token".to_vec(), None, 1);
    engine.transport().set_response(MockResponse::Success(
        json!({"items": [], "next_cursor": "tok-1"}),
    ));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { .. }
    ));
    assert_eq!(repair(), json!({}));
    let _ = std::fs::remove_file(path);
}

/// A credential needing repair is loud once per state change, not once per
/// poll: three failing polls write one ERROR line naming the connection and
/// the code, and the first success writes one recovery line.
#[test]
fn a_credential_needing_repair_is_logged_once_per_state_change() {
    let stderr = actor_diagnostic_output("credential_repair_log_fixture");
    let needs_repair: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("credential_needs_repair"))
        .collect();
    assert_eq!(needs_repair.len(), 1, "{stderr}");
    logging::assert_diagnostic(
        needs_repair[0],
        cortexkit_log::ParsedLevel::Error,
        "plexus.poller",
        &format!(
            "credential_needs_repair connection=\"{PRINCIPAL}/{CONNECTION}\" code=credential_auth_required: watches on this connection are retried at most hourly until the credential is repaired"
        ),
    );
    let repaired = stderr
        .lines()
        .filter(|line| line.contains("credential_repaired"))
        .count();
    assert_eq!(repaired, 1, "{stderr}");
}

/// A successful poll carries both per-subscription scope and the stored cursor
/// to the transport, and stores the scope on the subscription row.
///
/// Mutation proved: dropping fixed arguments from the request fails the owner
/// and repo assertions; dropping cursor arguments fails the syncToken assertion.
#[test]
fn poll_dispatches_fixed_args_alongside_cursor_args() {
    let (poller, engine, path, _) = fixture("fixed-poll");
    upsert_action_with_schema(
        &engine,
        VENDOR_NAMED,
        "read",
        &schema_hash(),
        "active",
        // The reviewed schema declares the cursor parameter the poll shape
        // sends; governance refuses an argument it does not declare.
        json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "syncToken": {"type": "string"}
            }
        }),
    );
    assert!(engine.transport().requests().is_empty());
    let created = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            VENDOR_NAMED,
            30,
            &json!({"sync_token": "resume-1"}),
            &json!({"owner": "octocat", "repo": "hello-world"}),
        )
        .expect("subscribe store")
        .expect("subscription accepted");
    assert_eq!(
        created.fixed_args,
        json!({"owner": "octocat", "repo": "hello-world"})
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "entries": [{"id": "issue-1"}]
        })));

    assert_eq!(
        poller.poll_once(PRINCIPAL, &created.subscription_id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0,
        }
    );
    let requests = engine.transport().requests();
    assert_eq!(requests.len(), 1, "the poll must dispatch exactly once");
    let args = requests[0].args.as_object().expect("request args object");
    assert_eq!(args.get("owner"), Some(&json!("octocat")));
    assert_eq!(args.get("repo"), Some(&json!("hello-world")));
    let expected_cursor =
        fingerprint(&serde_json::to_vec(&json!("resume-1")).expect("cursor bytes"));
    assert_eq!(args.get("syncToken"), Some(&json!(expected_cursor)));
    let stored = subscription(&engine, &created.subscription_id);
    assert_eq!(
        stored.fixed_args,
        json!({"owner": "octocat", "repo": "hello-world"})
    );
    let _ = std::fs::remove_file(path);
}

/// Cursor arguments must win over fixed arguments when a legacy or direct store
/// write bypasses the subscribe-time collision refusal.
///
/// Mutation proved: reversing the merge order makes the fixed `sync_token` value
/// reach the transport and fails the assertion below.
#[test]
fn poll_merges_fixed_args_under_cursor_args() {
    let (poller, engine, path, id) = fixture("fixed-merge");
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "first"}],
            "next_cursor": "cursor-wins"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { .. }
    ));
    assert_eq!(engine.transport().requests().len(), 1);

    let conn = rusqlite::Connection::open(&path).expect("open subscription store");
    let changed = conn
        .execute(
            "UPDATE trigger_subscriptions SET fixed_args = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![r#"{"sync_token":"fixed-must-lose"}"#, PRINCIPAL, id],
        )
        .expect("write legacy-shaped fixed args");
    assert_eq!(
        changed, 1,
        "the subscription row must exist before mutation"
    );
    assert_eq!(
        subscription(&engine, &id).fixed_args,
        json!({"sync_token": "fixed-must-lose"})
    );

    engine
        .transport()
        .set_response(MockResponse::Success(json!({"items": []})));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { .. }
    ));
    let requests = engine.transport().requests();
    let args = requests
        .last()
        .expect("second request")
        .args
        .as_object()
        .expect("args object");
    let cursor_value =
        fingerprint(&serde_json::to_vec(&json!("cursor-wins")).expect("cursor bytes"));
    let fixed_value =
        fingerprint(&serde_json::to_vec(&json!("fixed-must-lose")).expect("fixed bytes"));
    assert_eq!(args.get("sync_token"), Some(&json!(cursor_value)));
    assert_ne!(args.get("sync_token"), Some(&json!(fixed_value)));
    let _ = std::fs::remove_file(path);
}

/// A row written before migration 9 omits the new column. SQLite's migration
/// default supplies `{}`, and the poller can still dispatch that subscription.
///
/// Mutation proved: removing the migration default makes the precondition read
/// fail; removing the poll merge path makes the poll request assertion fail.
#[test]
fn pre_v9_subscription_row_polls_with_empty_fixed_args() {
    let (poller, engine, path, _) = fixture("fixed-migration");
    let legacy_id = "subscription-before-v9";
    let conn = rusqlite::Connection::open(&path).expect("open subscription store");
    conn.execute(
        "INSERT INTO trigger_subscriptions
            (subscription_id, principal, connection_id, action, cadence_s,
             cursor_kind, cursor_state, schema_hash, status, generation, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', 0, ?9)",
        rusqlite::params![
            legacy_id,
            PRINCIPAL,
            CONNECTION,
            FEED,
            30,
            "sync_token",
            "{}",
            schema_hash(),
            plexus_core::now_ms(),
        ],
    )
    .expect("insert pre-v9 subscription row");
    let stored = subscription(&engine, legacy_id);
    assert_eq!(
        stored.fixed_args,
        json!({}),
        "migration default must be an empty object"
    );
    assert!(engine.transport().requests().is_empty());

    engine
        .transport()
        .set_response(MockResponse::Success(json!({"items": []})));
    assert_eq!(
        poller.poll_once(PRINCIPAL, legacy_id),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 0,
        }
    );
    assert_eq!(engine.transport().requests().len(), 1);
    let _ = std::fs::remove_file(path);
}

/// The poller reads the RESPONSE field names the manifest declares, and sends
/// the token back under the REQUEST name it declares, rather than assuming a
/// house envelope.
///
/// This vector is Google Calendar's real shape: records under a vendor-chosen
/// key, the next cursor returned as `nextSyncToken`, and that same value sent
/// back as the request parameter `syncToken`. Response and request names
/// differ, which is why one declared field cannot serve both.
///
/// Both halves fail SILENTLY when wrong, which is why each is asserted
/// separately rather than inferred from the cycle result. An unrecognised items
/// field yields zero events — indistinguishable from a quiet period — and an
/// unrecognised cursor field leaves the watermark unmoved, so the poller
/// re-reads the same window forever while reporting success.
///
/// Mutation proved: hardcoding either response name back to the reference
/// envelope fails this test and nothing else; hardcoding the request name fails
/// the argument assertion alone.
#[test]
fn the_poller_honours_the_field_names_the_manifest_declares() {
    let (_, engine, path, _) = fixture("vendor-named");
    let created = engine
        .store()
        .subscribe(PRINCIPAL, CONNECTION, VENDOR_NAMED, 30)
        .expect("subscribe store")
        .expect("subscription accepted");
    let poller = Poller::new(engine.clone());

    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "entries": [{"id": "v1", "title": "vendor named"}],
            "nextSyncToken": "CPjq7abc"
        })));

    let cycle = poller.poll_once(PRINCIPAL, &created.subscription_id);
    assert_eq!(
        cycle,
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0,
        },
        "the declared items field was not read, so the poll saw no records"
    );

    let stored = subscription(&engine, &created.subscription_id);
    assert_eq!(
        stored.cursor_state,
        json!({"sync_token": "CPjq7abc"}),
        "the declared cursor field was not read, so the watermark never moved"
    );

    // The second poll proves the REQUEST name: the stored token must go back
    // under the vendor's parameter, not the storage key.
    engine
        .transport()
        .set_response(MockResponse::Success(json!({ "entries": [] })));
    poller.poll_once(PRINCIPAL, &created.subscription_id);
    // The mock redacts the recorded REQUEST projection (arguments are ours, and
    // that projection is a diagnostic), so assert the parameter NAME rather than
    // the token value — the name is what the manifest declares and what this
    // test is about. A wrong name would surface as a missing key, not as a
    // different value.
    let sent = engine.transport().requests();
    let last = sent.last().expect("a second request was dispatched");
    let args = last.args.as_object().expect("request args are an object");
    assert!(
        args.contains_key("syncToken"),
        "the resume token was sent under the wrong request parameter: {:?}",
        last.args
    );
    assert!(
        !args.contains_key("sync_token"),
        "the storage key leaked into the vendor request: {:?}",
        last.args
    );
    let _ = std::fs::remove_file(path);
}

/// A definitive vendor failure increments the vendor streak and leaves the
/// cursor exactly where it was, so the next poll re-reads the same window.
///
/// Mutation proved: advancing the cursor on a vendor failure fails the
/// cursor-value assertion; suspending instead of counting the failure fails the
/// `status == active` and `consecutive_vendor_failures == 1` assertions.
#[test]
fn vendor_failure_increments_the_streak_and_leaves_the_cursor_unmoved() {
    let (poller, engine, path, id) = fixture("vendor-failure");
    // First advance the cursor to a known value so "unmoved" is observable.
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "e1"}],
            "next_cursor": "tok-1"
        })));
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0,
        }
    );

    engine.transport().set_response(MockResponse::VendorError {
        code: "http_503".to_string(),
        message: "vendor unavailable".to_string(),
    });
    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert!(matches!(cycle, PollCycle::VendorFailed { ref code } if code == "http_503"));

    let stored = subscription(&engine, &id);
    assert_eq!(
        stored.cursor_state,
        json!({"sync_token": "tok-1"}),
        "a vendor failure must not advance the cursor"
    );
    assert_eq!(
        stored.status, "active",
        "a vendor failure is not a suspension"
    );
    assert_eq!(stored.consecutive_vendor_failures, 1);
    let _ = std::fs::remove_file(path);
}

/// A probe's definitive vendor failure reaches the same durable streak used by
/// ordinary subscriptions.
///
/// Mutation control: removing the probe path's `record_vendor_failure` call
/// leaves the stored streak at zero and fails this test.
#[test]
fn probe_vendor_failure_advances_the_streak() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-vendor-failure");
    let probe_id = register_read_probe(&engine, "vendor-failure-probe");
    engine.transport().set_response(MockResponse::VendorError {
        code: "http_503".to_string(),
        message: "vendor unavailable".to_string(),
    });

    assert_eq!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::VendorFailed {
            code: "http_503".to_string()
        }
    );
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "active");
    assert_eq!(
        stored.consecutive_vendor_failures, 1,
        "the probe failure must feed scheduler backoff"
    );

    let _ = std::fs::remove_file(path);
}

/// An unknown probe dispatch preserves the active watch without advancing its
/// failure streak, because the vendor may have completed the request.
///
/// Mutation control: treating `OutcomeUnknown` as a vendor failure advances the
/// streak and fails this test.
#[test]
fn probe_outcome_unknown_does_not_advance_the_streak() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-outcome-unknown");
    let probe_id = register_read_probe(&engine, "outcome-unknown-probe");
    engine
        .transport()
        .set_response(MockResponse::OutcomeUnknown);

    assert_eq!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::Inconclusive {
            code: "outcome_unknown".to_string()
        }
    );
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "active");
    assert_eq!(
        stored.consecutive_vendor_failures, 0,
        "an unknown outcome must remain safe to reconcile or retry"
    );

    let _ = std::fs::remove_file(path);
}

/// A request that never reached the vendor must not consume circuit-breaker
/// capacity. This is the probe-side fence for every `NotSent` transport code,
/// including a local MCP adapter's `spawn_failed` refusal.
///
/// Mutation control: recording a vendor failure in the `NotSent` arm advances
/// the streak and fails this test.
#[test]
fn probe_not_sent_does_not_advance_the_streak() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-not-sent");
    let probe_id = register_read_probe(&engine, "not-sent-probe");
    engine
        .transport()
        .set_response(MockResponse::TransientNotSent {
            message: "local adapter unavailable".to_string(),
        });

    assert_eq!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::Inconclusive {
            code: "transport_transient".to_string()
        }
    );
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "active");
    assert_eq!(
        stored.consecutive_vendor_failures, 0,
        "a request that was not sent must not drive vendor backoff"
    );

    let _ = std::fs::remove_file(path);
}

/// A probe whose stored spec can never complete a run is suspended with a
/// visible reason instead of being reported inconclusive.
///
/// An inconclusive result leaves a watch due. Both checks run before the poll
/// attempt is recorded, so an inconclusive answer would make the scheduler
/// re-run the probe on every one-second tick, forever. The two standing defects are
/// a stored return schema that does not parse and a cursor whose observation
/// ordinal is not an integer; neither may reach the vendor.
#[test]
fn an_unusable_probe_spec_or_cursor_suspends_without_dispatch() {
    for (label, sql, reason) in [
        (
            "probe-bad-return-schema",
            "UPDATE probe_subscriptions SET return_schema = '{\"kind\": \"no-such-kind\"}'",
            "probe_return_schema_invalid",
        ),
        (
            "probe-bad-ordinal",
            "UPDATE trigger_subscriptions SET cursor_state = '{\"observation_ordinal\": \"seven\"}' WHERE cursor_kind = 'probe'",
            "cursor_state_unusable",
        ),
    ] {
        let (poller, engine, path, _ordinary_id) = fixture(label);
        let probe_id = register_read_probe(&engine, label);
        engine
            .transport()
            .set_response(MockResponse::Success(json!(true)));
        rusqlite::Connection::open(&path)
            .expect("open probe store")
            .execute_batch(sql)
            .expect("corrupt the stored probe");

        assert_eq!(
            poller.poll_once(PRINCIPAL, &probe_id),
            PollCycle::Suspended {
                reason: reason.to_string()
            },
            "{label}"
        );
        let stored = subscription(&engine, &probe_id);
        assert_eq!(stored.status, "suspended", "{label}");
        assert_eq!(stored.suspended_reason.as_deref(), Some(reason), "{label}");
        assert!(
            engine.transport().requests().is_empty(),
            "{label}: an unusable probe must not reach the vendor"
        );
        let _ = std::fs::remove_file(path);
    }
}

/// Host-side probe failures are distinct from transport `NotSent`: this one is
/// rejected before dispatch because the action argument is not an object. It is
/// also inconclusive and must leave the vendor streak untouched.
#[test]
fn probe_host_inconclusive_does_not_advance_the_streak() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-host-inconclusive");
    let probe_id = register_read_probe_with_script(
        &engine,
        "host-inconclusive-probe",
        "() => invoke('read_feed', null)",
    );

    assert_eq!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::Inconclusive {
            code: "probe_action_failed".to_string()
        }
    );
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "active");
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(
        engine.transport().requests().is_empty(),
        "an invalid host argument must fail before transport dispatch"
    );

    let _ = std::fs::remove_file(path);
}

/// A store failure while creating probe dispatch authority remains a store
/// failure and never mutates the vendor streak.
#[test]
fn probe_action_store_failure_surfaces_without_advancing_the_streak() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-action-store-failure");
    let probe_id = register_read_probe(&engine, "action-store-failure-probe");
    let conn = rusqlite::Connection::open(&path).expect("open probe store fixture");
    conn.execute_batch(
        "CREATE TRIGGER fail_probe_reservation
         BEFORE INSERT ON reservations
         BEGIN
             SELECT RAISE(ABORT, 'injected probe reservation failure');
         END;",
    )
    .expect("install probe reservation failure");

    assert_eq!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::StoreFailed {
            reason: "store_failure".to_string()
        }
    );
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "active");
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(engine.transport().requests().is_empty());

    let _ = std::fs::remove_file(path);
}

/// Repeated probe vendor failures trip the scheduler's real circuit breaker,
/// proving that the probe streak is wired into policy rather than merely
/// returned from one poll call.
#[test]
fn repeated_probe_vendor_failures_trip_the_circuit_breaker() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-circuit-breaker");
    let probe_id = register_read_probe(&engine, "breaker-probe");
    engine.transport().set_response(MockResponse::VendorError {
        code: "http_503".to_string(),
        message: "vendor unavailable".to_string(),
    });

    for expected_streak in 1..=5 {
        assert!(matches!(
            poller.poll_once(PRINCIPAL, &probe_id),
            PollCycle::VendorFailed { ref code } if code == "http_503"
        ));
        assert_eq!(
            subscription(&engine, &probe_id).consecutive_vendor_failures,
            expected_streak
        );
    }

    let scheduler = Scheduler::new(engine.clone(), 30 * 86_400_000);
    let outcomes = scheduler.run_pass(
        &[PRINCIPAL.to_string()],
        plexus_core::now_ms().saturating_add(31_000),
    );
    assert!(outcomes.iter().any(|outcome| {
        outcome.subscription_id == probe_id
            && outcome.cycle
                == (PollCycle::Suspended {
                    reason: CIRCUIT_BREAKER_SUSPENSION_REASON.to_string(),
                })
    }));
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(
        stored.suspended_reason.as_deref(),
        Some(CIRCUIT_BREAKER_SUSPENSION_REASON)
    );

    let _ = std::fs::remove_file(path);
}

/// Failure to persist the probe vendor streak is a store failure, never a
/// successful-looking vendor-failure result.
#[test]
fn probe_vendor_failure_recording_error_surfaces_as_store_failed() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-store-failure");
    let probe_id = register_read_probe(&engine, "store-failure-probe");
    engine.transport().set_response(MockResponse::VendorError {
        code: "http_503".to_string(),
        message: "vendor unavailable".to_string(),
    });
    let conn = rusqlite::Connection::open(&path).expect("open probe store fixture");
    conn.execute_batch(
        "CREATE TRIGGER fail_probe_vendor_streak
         BEFORE UPDATE OF consecutive_vendor_failures ON trigger_subscriptions
         BEGIN
             SELECT RAISE(ABORT, 'injected probe streak failure');
         END;",
    )
    .expect("install probe streak failure");

    let cycle = poller.poll_once(PRINCIPAL, &probe_id);
    assert!(
        matches!(cycle, PollCycle::StoreFailed { ref reason } if reason.contains("injected probe streak failure")),
        "the persistence error must remain distinguishable: {cycle:?}"
    );
    assert_eq!(
        subscription(&engine, &probe_id).consecutive_vendor_failures,
        0
    );

    let _ = std::fs::remove_file(path);
}

/// Probe authorization refusals follow ordinary poll semantics: a standing
/// denial suspends and records a gap instead of consuming breaker capacity.
#[test]
fn probe_authorization_refusal_suspends_without_counting() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-auth-refusal");
    let probe_id = register_read_probe(&engine, "authorization-refusal-probe");
    for action in [FEED, TIMESTAMPED, VENDOR_NAMED, SNAPSHOT] {
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{action}"))
            .expect("revoke poll grant");
    }

    assert_eq!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::Suspended {
            reason: "grant_missing".to_string()
        }
    );
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(stored.consecutive_vendor_failures, 0);

    let _ = std::fs::remove_file(path);
}

/// A transient credential fault during probe authorization remains retryable:
/// it leaves the watch active without counting an unsent call as a vendor failure.
#[test]
fn probe_transient_reference_failure_is_inconclusive_without_suspending() {
    let (poller, engine, path, _ordinary_id) = fixture("probe-auth-transient");
    let probe_id = register_read_probe(&engine, "transient-credential-probe");
    engine.credential_source().set_error(
        BINDING_HANDLE,
        plexus_core::CredentialError::Transient(plexus_core::TransientCredentialError::VaultLocked),
    );

    assert!(matches!(
        poller.poll_once(PRINCIPAL, &probe_id),
        PollCycle::Inconclusive { .. }
    ));
    let stored = subscription(&engine, &probe_id);
    assert_eq!(stored.status, "active");
    assert_eq!(stored.consecutive_vendor_failures, 0);

    let _ = std::fs::remove_file(path);
}

/// An authorization denial suspends the subscription with a machine-readable
/// reason and a coverage gap, and never touches the vendor-failure streak.
///
/// Mutation proved: routing a denial through `record_vendor_failure` instead of
/// `suspend` fails the `status == suspended` and `consecutive_vendor_failures
/// == 0` assertions, and leaves no gap event.
/// Revoking a connection stops its pollers on the next tick, without touching
/// their grants.
///
/// This is the operator's stop button. If a credential is suspected
/// compromised, the reachable response is to revoke the connection rather than
/// to hunt down every grant that mentions it, so that must be enough on its
/// own. Grants stay minted and the subscription keeps its row -- the
/// authority that has been withdrawn is the connection's, and revoking it has
/// to be sufficient on its own, because an operator under pressure will not
/// enumerate the grants and should not have to.
///
/// Timing is what makes this worth a test rather than an inference.
/// `subscribe` refuses an inactive connection at creation, so nothing wrong
/// happens while an operator is watching; a subscription created against a
/// healthy connection then OUTLIVES that state, and by the time revocation
/// matters it is a background timer with nobody present. The re-check on every
/// tick is the only thing standing between a revoked connection and continued
/// vendor traffic.
///
/// The transport assertion is the load-bearing one: a revocation honoured only
/// after the request goes out is not a revocation. The status assertion pins
/// the other half -- the subscription is suspended rather than merely skipped,
/// so it does not silently resume if the connection is later reactivated,
/// since resuming is a fresh operator decision.
///
/// Mutation-proved: treating a revoked connection as usable in
/// `connection_denial` fails this test. Proved twice, because the reason
/// assertion fires first and would mask the rest -- with that assertion
/// widened to accept the mutant's own result, the vendor request count still
/// fails on its own.
#[test]
fn revoking_a_connection_stops_its_pollers_without_revoking_grants() {
    let (poller, engine, path, id) = fixture("connection-revoked");

    // Every poll grant stays in place, so nothing but the connection's own
    // status can refuse this poll.
    assert!(
        engine
            .store()
            .revoke_connection(PRINCIPAL, CONNECTION)
            .expect("revoke connection"),
        "the connection to revoke must exist"
    );

    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "connection_revoked".to_string()
        },
        "the reason must name the connection, so an operator is not sent hunting grants"
    );

    let stored = subscription(&engine, &id);
    assert_eq!(
        stored.status, "suspended",
        "a revoked connection must stop its subscriptions, not merely skip a tick"
    );
    assert!(
        engine.transport().requests().is_empty(),
        "a revocation honoured after the request goes out is not a revocation"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn authorization_denial_suspends_and_does_not_count_as_a_vendor_failure() {
    let (poller, engine, path, id) = fixture("denial-suspends");
    // Revoke every poll grant on the connection: the read is still catalogued,
    // but the timer no longer has authority to exercise it. ALL of them are
    // revoked, not just the subscribed action's, so the denial is a clean
    // `grant_missing` rather than a selector mismatch against a survivor — the
    // reason code is what this test asserts, so it must not depend on how many
    // unrelated grants the fixture happens to mint.
    for action in [FEED, TIMESTAMPED, VENDOR_NAMED, SNAPSHOT] {
        engine
            .store()
            .revoke_grant(PRINCIPAL, &format!("grant-poll-{action}"))
            .expect("revoke poll grant");
    }

    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "grant_missing".to_string()
        }
    );

    let stored = subscription(&engine, &id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(stored.suspended_reason.as_deref(), Some("grant_missing"));
    assert_eq!(
        stored.consecutive_vendor_failures, 0,
        "a denial is not a vendor failure"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list events");
    assert!(
        events.iter().any(|event| event.kind == "gap"),
        "the suspension records a visible coverage gap"
    );
    assert!(
        engine.transport().requests().is_empty(),
        "a denied poll never reaches the vendor"
    );
    let _ = std::fs::remove_file(path);
}

/// The pre-gate refusal is load-bearing: an action that drifted off `read` is
/// refused before `authorize` runs, suspending the subscription rather than
/// letting the poller ride a permissive grant or policy row.
///
/// Mutation proved: skipping the poll pre-gate and constructing a plain request
/// would not produce the `action_risk_not_read` suspension reason; and treating
/// the refusal as a vendor failure fails the streak and suspension assertions.
#[test]
fn pregate_refusal_of_a_drifted_action_suspends_before_authorize() {
    let (poller, engine, path, id) = fixture("pregate-refusal");
    // Simulate the drift-before-reconcile window: the reviewed action is no
    // longer a read, but the subscription has not been suspended yet.
    drift_catalog_raw(&path, "risk", "write", FEED);

    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "action_risk_not_read".to_string()
        }
    );

    let stored = subscription(&engine, &id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(
        engine.transport().requests().is_empty(),
        "the pre-gate refusal must stop the cycle before any dispatch"
    );
    let _ = std::fs::remove_file(path);
}

/// An unsupported cursor in a legacy store must suspend rather than guess,
/// because a wrong watermark silently skips records. New catalogs cannot ingest
/// snapshot_diff; insert the old shape only after the valid fixture is ingested.
///
/// Mutation proved: returning a strategy for `snapshot_diff` (instead of
/// suspending) fails the `cursor_kind_unsupported` suspension assertion.
#[test]
fn unsupported_cursor_kind_suspends_with_cursor_kind_unsupported() {
    let (poller, engine, path, _feed_id) = fixture("unsupported-cursor");
    let mut legacy = manifest_value();
    legacy["actions_baseline"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["name"] == SNAPSHOT)
        .unwrap()["poll"] = json!({
        "cursor_kind":"snapshot_diff", "item_kind":"issue", "item_count_ceiling":100
    });
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE app_manifests SET manifest_json=?1 WHERE key='mock'",
            [legacy.to_string()],
        )
        .unwrap();
    let snapshot = engine
        .store()
        .subscribe(PRINCIPAL, CONNECTION, SNAPSHOT, 30)
        .expect("subscribe store")
        .expect("snapshot-diff subscription accepted");

    let cycle = poller.poll_once(PRINCIPAL, &snapshot.subscription_id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "cursor_kind_unsupported".to_string()
        }
    );

    let stored = subscription(&engine, &snapshot.subscription_id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(
        stored.suspended_reason.as_deref(),
        Some("cursor_kind_unsupported")
    );
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(engine.transport().requests().is_empty());
    let _ = std::fs::remove_file(path);
}

/// The ordered-timestamp happy path at the integration level: a healthy poll
/// advances the settled watermark, seeds the overlap window, and commits its
/// events through the real (file-backed) store and governance chain.
///
/// Mutation proved: dropping the cursor advance leaves `watermark_ms` unset;
/// dropping the event commit fails the inserted-count assertion.
#[test]
fn ordered_timestamp_poll_advances_the_watermark_and_commits_events() {
    let (poller, engine, path, _feed_id) = fixture("ordered-timestamp");
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [
                {"id": "a", "updated_at": "2024-01-15T10:00:00Z"},
                {"id": "b", "updated_at": "2024-01-15T10:00:05Z"}
            ]
        })));
    let sub = engine
        .store()
        .subscribe(PRINCIPAL, CONNECTION, TIMESTAMPED, 30)
        .expect("subscribe store")
        .expect("ordered-timestamp subscription accepted");

    let cycle = poller.poll_once(PRINCIPAL, &sub.subscription_id);
    assert_eq!(
        cycle,
        PollCycle::Completed {
            inserted: 2,
            duplicates: 0,
        }
    );

    let stored = subscription(&engine, &sub.subscription_id);
    assert_eq!(stored.status, "active");
    assert!(
        stored
            .cursor_state
            .get("watermark_ms")
            .and_then(Value::as_i64)
            .is_some(),
        "the watermark advanced: {}",
        stored.cursor_state
    );
    assert_eq!(
        stored
            .cursor_state
            .get("watermark_id")
            .and_then(Value::as_str),
        Some("b"),
        "the watermark id is the newest row"
    );
    assert_eq!(
        stored.cursor_state.get("window_ms").and_then(Value::as_i64),
        Some(60_000),
        "the first poll seeds the documented initial overlap window"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&sub.subscription_id))
        .expect("list events");
    let ids: Vec<String> = events
        .iter()
        .filter_map(|event| event.vendor_event_id.clone())
        .collect();
    assert!(
        ids.contains(&"a".to_string()) && ids.contains(&"b".to_string()),
        "{ids:?}"
    );
    let _ = std::fs::remove_file(path);
}

/// A second-resolution timestamp cannot distinguish two edits of one item, so a
/// changed payload at the stored boundary is delivered once on the next poll.
///
/// Mutation-proved: restoring the sorted-head strict-greater-only filter removes
/// the second observation before content comparison and fails the second cycle's
/// inserted count.
#[test]
fn same_second_edit_is_delivered() {
    let (poller, engine, path, _) = fixture("sorted-head-same-second-edit");
    let id = sorted_head_subscription(&engine);
    let timestamp = "2026-09-06T12:00:00Z";
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{
                "id": "pr-1",
                "number": 1,
                "updated_at": timestamp,
                "title": "before"
            }]
        })));
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );

    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{
                "id": "pr-1",
                "number": 1,
                "updated_at": timestamp,
                "title": "after"
            }]
        })));
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        },
        "changed content at the same timestamp must be delivered exactly once"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list same-second versions");
    assert_eq!(events.len(), 2, "both content versions must be durable");
    assert!(events.iter().any(|event| event.payload["title"] == "after"));
    let _ = std::fs::remove_file(path);
}

/// An unchanged boundary replay is removed before actor enrichment and therefore
/// consumes no governed enrichment dispatches on the second poll.
///
/// Mutation-proved: removing the store-backed candidate filter leaves the replay
/// in the batch and makes the second-poll dispatch count one instead of zero.
#[test]
fn unchanged_boundary_item_never_reaches_enrichment() {
    let (poller, engine, path, _) = fixture("sorted-head-unchanged-boundary");
    let id = actor_subscription(&engine, SORTED_HEAD, ISSUE_READ, &["get_comments"]);
    let response = json!({
        "items": [{
            "id": "pr-1",
            "number": 1,
            "updated_at": "2026-09-06T12:00:00Z",
            "title": "unchanged"
        }]
    });
    engine
        .transport()
        .set_response(MockResponse::Success(response));
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let enrichment_dispatches_before = engine
        .transport()
        .requests()
        .iter()
        .filter(|request| request.action == ISSUE_READ)
        .count();

    let second_cycle = poller.poll_once(PRINCIPAL, &id);
    let enrichment_dispatches_after = engine
        .transport()
        .requests()
        .iter()
        .filter(|request| request.action == ISSUE_READ)
        .count();
    assert_eq!(
        enrichment_dispatches_after - enrichment_dispatches_before,
        0,
        "the second poll must dispatch zero enrichment reads"
    );
    assert_eq!(
        second_cycle,
        PollCycle::Completed {
            inserted: 0,
            duplicates: 0
        },
        "identical boundary content must be dropped before commit"
    );
    let _ = std::fs::remove_file(path);
}

/// A boundary id with no prior event row is new content even when its timestamp
/// and ordering position do not exceed the stored composite watermark.
///
/// Mutation-proved: treating every boundary candidate as unchanged drops `pr-a`
/// and fails both the inserted count and durable-id assertion.
#[test]
fn unseen_boundary_item_is_emitted() {
    let (poller, engine, path, _) = fixture("sorted-head-unseen-boundary");
    let id = sorted_head_subscription(&engine);
    let timestamp = "2026-09-06T12:00:00Z";
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "pr-z", "updated_at": timestamp, "title": "known"}]
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [
                {"id": "pr-z", "updated_at": timestamp, "title": "known"},
                {"id": "pr-a", "updated_at": timestamp, "title": "unseen"}
            ]
        })));
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list boundary events");
    assert!(
        events
            .iter()
            .any(|event| event.vendor_event_id.as_deref() == Some("pr-a")),
        "an unseen boundary id must be committed"
    );
    let _ = std::fs::remove_file(path);
}

/// The subscription's pinned schema hash is passed as `expected_schema_hash`, so
/// a vendor schema change fails closed at the catalog gate and suspends, instead
/// of the poller quietly sending a stale argument shape.
///
/// Mutation proved: passing the catalog's CURRENT schema hash (rather than the
/// pinned one) would match after the drift and dispatch; the suspension
/// assertion below would fail.
#[test]
fn schema_drift_suspends_at_the_catalog_gate() {
    let (poller, engine, path, id) = fixture("schema-drift");
    // The subscription pinned the original hash; drift the catalog's in the
    // window before reconcile would suspend it.
    drift_catalog_raw(&path, "schema_hash", "sha256:drifted-schema", FEED);

    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "catalog_schema_mismatch".to_string()
        }
    );

    let stored = subscription(&engine, &id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(engine.transport().requests().is_empty());
    let _ = std::fs::remove_file(path);
}

/// An unknown dispatch outcome is benign to repeat and catastrophic to skip, so
/// it leaves the cursor and the streak untouched and does not suspend.
///
/// Mutation proved: counting an unknown outcome as a vendor failure fails the
/// streak assertion; advancing the cursor fails the cursor-value assertion;
/// suspending fails the `status == active` assertion.
#[test]
fn outcome_unknown_leaves_cursor_and_streak_untouched() {
    let (poller, engine, path, id) = fixture("outcome-unknown");
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "e1"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { .. }
    ));

    engine
        .transport()
        .set_response(MockResponse::OutcomeUnknown);
    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Inconclusive {
            code: "outcome_unknown".to_string()
        }
    );

    let stored = subscription(&engine, &id);
    assert_eq!(stored.cursor_state, json!({"sync_token": "tok-1"}));
    assert_eq!(stored.status, "active");
    assert_eq!(stored.consecutive_vendor_failures, 0);
    let _ = std::fs::remove_file(path);
}

/// A subscription that does not exist for this principal is not eligible, and
/// nothing is written.
#[test]
fn missing_subscription_is_not_eligible() {
    let (poller, _engine, path, _id) = fixture("missing");
    let cycle = poller.poll_once(PRINCIPAL, "sub_does_not_exist");
    assert_eq!(
        cycle,
        PollCycle::NotEligible {
            reason: "subscription_not_found".to_string()
        }
    );
    let _ = std::fs::remove_file(path);
}

/// A stored cursor the strategy cannot use suspends rather than polling from a
/// guessed position.
///
/// Mutation proved: falling back to a full sync (empty args) on an unusable
/// cursor, instead of suspending, would fail the `cursor_state_unusable`
/// suspension assertion and silently re-read the vendor from the beginning.
#[test]
fn unusable_cursor_state_suspends_with_cursor_state_unusable() {
    let (poller, engine, path, _id) = fixture("unusable-cursor");
    let sub = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            FEED,
            30,
            &json!({"sync_token": 42}),
            &json!({}),
        )
        .expect("subscribe store")
        .expect("subscription accepted");

    let cycle = poller.poll_once(PRINCIPAL, &sub.subscription_id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "cursor_state_unusable".to_string()
        }
    );
    let stored = subscription(&engine, &sub.subscription_id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(stored.consecutive_vendor_failures, 0);
    assert!(engine.transport().requests().is_empty());
    let _ = std::fs::remove_file(path);
}

/// A completed read whose body cannot be parsed into a cursor advance suspends
/// rather than advancing past events it could not record.
///
/// Mutation proved: advancing the cursor (or counting a vendor failure) on an
/// unparseable response would fail the `response_shape_invalid` suspension and
/// cursor-unmoved assertions; the vendor returned a definitive success, so the
/// only safe action is to stop and make the gap visible.
#[test]
fn unparseable_response_suspends_with_response_shape_invalid() {
    let (poller, engine, path, id) = fixture("bad-response");
    // Advance to a known cursor first so "unmoved" is observable.
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "e1"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { .. }
    ));

    // A record without a stable id makes the whole response unusable.
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"title": "no id"}],
            "next_cursor": "tok-2"
        })));
    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        cycle,
        PollCycle::Suspended {
            reason: "response_shape_invalid".to_string()
        }
    );
    let stored = subscription(&engine, &id);
    assert_eq!(stored.status, "suspended");
    assert_eq!(
        stored.cursor_state,
        json!({"sync_token": "tok-1"}),
        "an unparseable response must not advance the cursor"
    );
    assert_eq!(stored.consecutive_vendor_failures, 0);
    let _ = std::fs::remove_file(path);
}

/// A watch on a revoked connection does not read as healthy.
///
/// Revoking a connection deliberately leaves grants intact -- authority and
/// health are different questions, and revocation answers neither by expiring a
/// grant. So the grant behind a watch on a revoked connection is still live and
/// still names the action, which means `authority_state` alone reports `live`
/// for a watch that can never poll again.
///
/// That is the reporting hole this asserts against: a consumer rendering watch
/// health from authority alone would show a healthy watch on a dead connection.
/// The discriminator already exists -- the subscription's own `status` goes
/// `suspended` with `connection_revoked` -- so this test pins that BOTH are
/// required to read a watch correctly, and that the pair is unambiguous.
#[test]
fn a_watch_on_a_revoked_connection_is_not_reported_as_healthy() {
    let (poller, engine, path, subscription_id) = fixture("revoked-authority");

    assert!(
        engine
            .store()
            .revoke_connection(PRINCIPAL, CONNECTION)
            .expect("revoke connection"),
        "the connection to revoke must exist"
    );
    // The suspension lands on the next tick rather than at revocation, so drive
    // one: before it, the row still reads active and only the connection says
    // otherwise.
    let _ = poller.poll_once(PRINCIPAL, &subscription_id);

    let listed = engine
        .store()
        .list_subscriptions(PRINCIPAL, None, Some(&subscription_id))
        .expect("list subscriptions");
    let watch = listed.first().expect("the subscription is listed");

    assert_eq!(
        watch.authority_state, "live",
        "revocation must not expire the grant -- if this changes, the comment \
         above and the consumer guidance both need revisiting"
    );
    assert_eq!(
        watch.status, "suspended",
        "a watch on a revoked connection must not read as an active watch"
    );
    assert_eq!(
        watch.suspended_reason.as_deref(),
        Some("connection_revoked"),
        "the reason must name the connection, not the authority: an operator \
         renewing a grant here would wait forever for a feed"
    );

    let _ = std::fs::remove_file(path);
}

/// A seeded cursor state whose key the cursor kind does not read is refused.
///
/// Seeding is how a threshold watch is expressed: a scalar-diff subscription
/// seeded with a value the subscriber has already seen reports on its first
/// poll, while an unseeded one baselines silently. Every strategy resolves its
/// stored state BY KEY, so a seed under the wrong key resolves to "no previous
/// value" -- and the subscription is then accepted, polls happily, and behaves
/// exactly like an unseeded watch. The one event the subscriber asked for is the
/// one that never arrives.
///
/// Both directions are asserted. The accept leg matters as much as the refusal:
/// refusing every seed would satisfy the refusal assertion alone while breaking
/// the capability, and an empty state must stay valid because starting from
/// nothing is the ordinary case.
///
/// Mutation-proved: dropping the key check accepts the misspelled seed; refusing
/// any non-empty state fails the accept leg; returning an empty `state_keys()`
/// refuses the correctly-spelled seed.
#[test]
fn a_seed_under_a_key_the_cursor_kind_ignores_is_refused() {
    let (_poller, engine, path, _subscription_id) = fixture("seed-key-unknown");

    // A plausible misspelling of the real key (`watermark` for `watermark_ms`).
    // Without the key check this seed is accepted and the watch baselines as
    // though it were never seeded.
    let refusal = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            300,
            &json!({"watermark": 1}),
            &json!({}),
        )
        .expect("subscribe query")
        .expect_err("a seed the strategy cannot read must be refused");
    assert!(
        matches!(
            refusal,
            plexus_core::SubscriptionRefusal::CursorStateKeyUnknown { ref key, .. }
                if key == "watermark"
        ),
        "the refusal must name the unreadable key: {refusal:?}"
    );
    assert!(
        refusal.to_string().contains("watermark_ms"),
        "the message must name the keys this kind DOES read, since the caller \
         seeded deliberately: {refusal}"
    );

    // The correctly-spelled seed is accepted, so the check narrows rather than
    // blocking the capability it protects.
    engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            300,
            &json!({"watermark_ms": 1_700_000_000_000i64}),
            &json!({}),
        )
        .expect("subscribe query")
        .expect("a seed the strategy reads must be accepted");

    // An empty state is the ordinary unseeded case and must stay valid.
    engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            VENDOR_NAMED,
            300,
            &json!({}),
            &json!({}),
        )
        .expect("subscribe query")
        .expect("an unseeded subscription must remain valid");

    let _ = std::fs::remove_file(path);
}

/// Capture the actual stderr of an isolated test process, not a formatting proxy.
fn actor_diagnostic_output(test: &str) -> String {
    let output = bounded::child_output(
        std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", test, "--nocapture", "--include-ignored"])
            .env("PLEXUS_LOG_STDERR_CHILD", "1"),
        std::time::Duration::from_secs(30),
        "test binary child",
    )
    .expect("run diagnostic fixture");
    assert!(
        output.status.success(),
        "fixture {test} failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stderr).expect("UTF-8 stderr")
}

#[test]
#[ignore = "child-process diagnostic fixture"]
fn diagnostic_helper_fixture() {
    logging::init_child();
    plexus_core::diag!(warn poller: "diagnostic_helper_probe");
}

#[test]
fn diagnostic_helper_writes_fleet_attribution_to_real_stderr() {
    let stderr = actor_diagnostic_output("diagnostic_helper_fixture");
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains("diagnostic_helper_probe"))
        .collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    logging::assert_diagnostic(
        lines[0],
        cortexkit_log::ParsedLevel::Warn,
        "plexus.poller",
        "diagnostic_helper_probe",
    );
}

#[test]
fn quarantined_enrichment_is_fail_open() {
    let (poller, engine, path, _) = fixture("actor-quarantine-isolation");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine
        .store()
        .quarantine_action(PRINCIPAL, ACTOR_CONNECTION, ISSUE_READ, "schema drift")
        .expect("quarantine actor action");
    let before = subscription(&engine, &id);
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-advanced"
        })));
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let stored = subscription(&engine, &id);
    assert_eq!(
        stored.status, before.status,
        "enrichment must not suspend the watch"
    );
    assert_eq!(stored.cursor_state, json!({"sync_token": "tok-advanced"}));
    assert_eq!(
        stored.consecutive_vendor_failures,
        before.consecutive_vendor_failures
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("deliverable events");
    assert_eq!(
        events.len(),
        1,
        "unknown actors must not silence event delivery"
    );
    assert_eq!(events[0].actor_logins, None);
    assert!(
        serde_json::to_value(&events[0])
            .unwrap()
            .get("actor_logins")
            .is_none(),
        "unknown actors cannot become a known empty set on the consumer wire"
    );
    assert_eq!(
        engine
            .transport()
            .requests()
            .iter()
            .filter(|request| request.action == ISSUE_READ)
            .count(),
        0
    );
    eprintln!("fixture_subscription={id:?}");
    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_refusal_diagnostic_names_code_and_operator_remedy() {
    let stderr = actor_diagnostic_output("quarantined_enrichment_is_fail_open");
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains(" WARN  plexus.poller: actor_enrichment_unknown "))
        .collect();
    assert_eq!(lines.len(), 1, "one diagnostic per unknown event: {stderr}");
    let line = lines[0];
    let id = stderr
        .lines()
        .find_map(|line| line.strip_prefix("fixture_subscription="))
        .expect("fixture id");
    assert!(line.contains(&format!("subscription={id}")), "{line}");
    for expected in [
        "item=\"issue-17\"",
        "governed_read_refusal",
        "code=catalog_action_quarantined",
        "operator action required",
        "not allowed to read",
        "review-action",
        "repin-action",
    ] {
        assert!(line.contains(expected), "missing {expected}: {line}");
    }
}

#[test]
fn saturated_comment_page_is_fail_open() {
    let (poller, engine, path, _) = fixture("actor-saturated-page");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!(vec![
            json!({"user": {"login": "alice"}, "created_at": "2026-08-20T12:00:00Z"});
            100
        ])),
    );
    engine.transport().set_response(MockResponse::Success(
        json!({"items": [{"id":"issue-17", "number":17}], "next_cursor":"tok-page"}),
    ));
    let before = subscription(&engine, &id);
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    let after = subscription(&engine, &id);
    assert_eq!(after.status, before.status);
    assert_eq!(after.cursor_state, json!({"sync_token":"tok-page"}));
    assert_eq!(
        after.consecutive_vendor_failures,
        before.consecutive_vendor_failures
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor_logins, None);
    let _ = std::fs::remove_file(path);
}

#[test]
fn unknown_actor_arms_emit_named_diagnostics() {
    for (test, arm) in [
        (
            "actor_enrichment_call_cap_bounds_a_poll_cycle",
            "call_cap_exhausted",
        ),
        (
            "saturated_comment_page_is_fail_open",
            "comment_page_saturation",
        ),
        (
            "unrecognised_review_comment_shape_is_unknown_not_partial",
            "unrecognized_response_shape",
        ),
        ("transient_twice_stays_unknown", "transport_failure"),
        ("semantic_unknown_does_not_retry", "empty_actor_window"),
        (
            "an_unbound_actor_source_stores_unknown_actors",
            "actor_source_unbound",
        ),
        (
            "a_missing_item_kind_stores_unknown_actors",
            "item_kind_unknown",
        ),
        (
            "methods_that_do_not_cover_the_item_kind_store_unknown_actors",
            "actor_methods_incomplete",
        ),
        (
            "enrichment_authority_failure_is_isolated_from_poll_success",
            "governed_read_refusal code=connection_revoked",
        ),
    ] {
        let stderr = actor_diagnostic_output(test);
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains(" WARN  plexus.poller: actor_enrichment_unknown "))
            .collect();
        assert_eq!(lines.len(), 1, "{test}: {stderr}");
        assert!(
            lines[0].contains(&format!("reason={arm}")),
            "{test}: {stderr}"
        );
        assert!(
            lines[0].contains("subscription=\"") && lines[0].contains("item=\""),
            "{test}: {stderr}"
        );
    }
}

fn paginated_timestamp_subscription(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
) -> String {
    let mut manifest = manifest_value();
    let poll = &mut manifest["actions_baseline"][3]["poll"];
    poll["request_page_size_field"] = json!("perPage");
    poll["request_constants"] = json!({"perPage": 30, "method": "list"});
    poll["pagination"] = json!({
        "request_cursor_field": "after",
        "response_cursor_pointer": "/pageInfo/endCursor"
    });
    engine
        .store()
        .upsert_manifest(
            plexus_core::CATALOG_PRINCIPAL,
            &ingest_value(manifest).expect("pagination manifest"),
        )
        .expect("update manifest");
    engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            TIMESTAMPED,
            300,
            &json!({"watermark_ms": 1705312805000i64, "watermark_id": "29", "window_ms": 60_000}),
            &json!({}),
        )
        .expect("subscribe query")
        .expect("paginated watch")
        .subscription_id
}

fn timestamp_page(start: usize, count: usize, timestamp: &str, cursor: &str) -> MockResponse {
    MockResponse::Success(json!({
        "items": (start..start + count).map(|id| json!({"id": id, "updated_at": timestamp})).collect::<Vec<_>>(),
        "pageInfo": {"endCursor": cursor, "hasNextPage": true}
    }))
}

#[test]
fn ordered_timestamp_overlap_full_page_drains_later_item() {
    let (poller, engine, path, _) = fixture("timestamp-drain");
    let id = paginated_timestamp_subscription(&engine);
    engine.transport().set_response_sequence_for_method(
        TIMESTAMPED,
        "list",
        vec![
            timestamp_page(0, 30, "2024-01-15T10:00:05Z", "page-1"),
            timestamp_page(30, 0, "2024-01-15T10:00:05Z", "empty"),
        ],
    );
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 30,
            duplicates: 0
        }
    );
    engine.transport().set_response_sequence_for_method(
        TIMESTAMPED,
        "list",
        vec![
            timestamp_page(0, 30, "2024-01-15T10:00:05Z", "page-1"),
            timestamp_page(30, 1, "2024-01-15T10:00:06Z", "page-2"),
        ],
    );
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 30
        }
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.vendor_event_id.as_deref() == Some("30")),
        "later item must be delivered"
    );
    let all_requests = engine.transport().requests();
    let requests = &all_requests[2..];
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].args["updatedSince"], "2024-01-15T09:59:05.000Z");
    assert!(requests[0].args.get("after").is_none());
    assert_eq!(requests[1].args["after"], "page-1");
    assert_eq!(
        requests[1].args["updatedSince"],
        requests[0].args["updatedSince"]
    );
    assert_eq!(
        subscription(&engine, &id).cursor_state["watermark_id"],
        "30"
    );
    assert_eq!(subscription(&engine, &id).cursor_state["window_ms"], 60_000);
    assert!(events.iter().all(|event| event.kind != "gap"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn ordered_timestamp_short_page_uses_one_call() {
    let (poller, engine, path, _) = fixture("timestamp-short");
    let id = paginated_timestamp_subscription(&engine);
    // Even a stale hasNextPage flag cannot turn a short answer into more calls.
    engine
        .transport()
        .set_response(timestamp_page(30, 1, "2024-01-15T10:00:06Z", "unused"));
    let cycle = poller.poll_once(PRINCIPAL, &id);
    assert_eq!(
        engine.transport().requests().len(),
        1,
        "short page must end the poll"
    );
    assert_eq!(
        cycle,
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(
        subscription(&engine, &id).cursor_state["watermark_id"],
        "30"
    );
    assert_eq!(
        engine
            .store()
            .list_events(PRINCIPAL, None, Some(&id))
            .unwrap()
            .len(),
        1
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn ordered_timestamp_page_bound_records_gap_and_commits() {
    let (poller, engine, path, _) = fixture("timestamp-bound");
    let id = paginated_timestamp_subscription(&engine);
    engine.transport().set_response_sequence_for_method(
        TIMESTAMPED,
        "list",
        (0..6)
            .map(|page| {
                timestamp_page(
                    page * 30,
                    30,
                    "2024-01-15T10:00:05Z",
                    &format!("page-{page}"),
                )
            })
            .collect(),
    );
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 150,
            duplicates: 0
        }
    );
    assert_eq!(engine.transport().requests().len(), 5);
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "gap"
                && event.gap_reason.as_deref() == Some("ordered_timestamp_page_limit"))
            .count(),
        1,
        "bound must record incomplete coverage"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.vendor_event_id.is_some())
            .count(),
        150
    );
    assert_eq!(
        subscription(&engine, &id).cursor_state["watermark_id"],
        "149"
    );
    assert_eq!(subscription(&engine, &id).status, "active");
    assert!(subscription(&engine, &id).last_success_at_ms.is_some());
    let _ = std::fs::remove_file(path);
}

#[test]
fn ordered_timestamp_missing_cursor_records_gap_without_suspending() {
    let (poller, engine, path, _) = fixture("timestamp-missing-cursor");
    let id = paginated_timestamp_subscription(&engine);
    engine
        .transport()
        .set_response(timestamp_page(0, 30, "2024-01-15T10:00:05Z", ""));
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 30,
            duplicates: 0
        }
    );
    assert_eq!(engine.transport().requests().len(), 1);
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .unwrap();
    assert!(events
        .iter()
        .any(|event| event.gap_reason.as_deref() == Some("ordered_timestamp_cursor_unusable")));
    assert_eq!(subscription(&engine, &id).status, "active");
    let _ = std::fs::remove_file(path);
}

#[test]
fn progressing_ordered_backlog_is_not_a_coverage_gap() {
    let (poller, engine, path, _) = fixture("timestamp-progress-backlog");
    let id = paginated_timestamp_subscription(&engine);
    engine.transport().set_response_sequence_for_method(
        TIMESTAMPED,
        "list",
        (0..6)
            .map(|page| {
                timestamp_page(
                    page * 30,
                    30,
                    "2024-01-15T10:05:00Z",
                    &format!("page-{page}"),
                )
            })
            .collect(),
    );
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 150, .. }
    ));
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .unwrap();
    assert!(
        !events.iter().any(|event| event.kind == "gap"),
        "resumable advancing backlog must not claim lost coverage"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn future_vendor_gap_keeps_the_vendor_boundary() {
    let (poller, engine, path, _) = fixture("timestamp-future-boundary");
    let id = paginated_timestamp_subscription(&engine);
    engine
        .transport()
        .set_response(timestamp_page(0, 30, "9999-01-01T00:00:00Z", ""));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 30, .. }
    ));
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .unwrap();
    let gap = events.iter().find(|event| event.kind == "gap").unwrap();
    let vendor = 253_370_764_800_000_i64;
    assert_eq!(
        gap.gap_from_ms,
        Some(vendor),
        "vendor boundary must not be replaced by the host clock"
    );
    assert_eq!(gap.gap_to_ms, Some(vendor));
    let _ = std::fs::remove_file(path);
}

#[test]
fn ordered_timestamp_pagination_manifest_is_optional_but_requires_sound_wiring() {
    let mut manifest = manifest_value();
    assert!(
        ingest_value(manifest.clone()).is_ok(),
        "old catalogs still parse"
    );
    let poll = &mut manifest["actions_baseline"][3]["poll"];
    poll["pagination"] =
        json!({"request_cursor_field": "after", "response_cursor_pointer": "/pageInfo/endCursor"});
    assert!(
        ingest_value(manifest.clone()).is_err(),
        "page fullness needs a declared size"
    );
    manifest["actions_baseline"][3]["poll"]["request_page_size_field"] = json!("perPage");
    manifest["actions_baseline"][3]["poll"]["request_constants"] = json!({"perPage": 30});
    assert!(ingest_value(manifest.clone()).is_ok());
    manifest["actions_baseline"][3]["poll"]["pagination"]["request_cursor_field"] =
        json!("updatedSince");
    assert!(
        ingest_value(manifest).is_err(),
        "cursor must not overwrite the overlap filter"
    );
}

/// The event as a consumer receives it: read through the granted-events path
/// the `events` facade serves from, then serialized exactly as the wire does.
fn served_event(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    id: &str,
    title: &str,
) -> Value {
    let events = engine
        .store()
        .list_events_including_granted(PRINCIPAL, None, Some(id), plexus_core::now_ms())
        .expect("list served events");
    let event = events
        .iter()
        .find(|event| event.payload["title"] == title)
        .unwrap_or_else(|| panic!("served event titled {title:?}"));
    serde_json::to_value(event).expect("serialize served event")
}

/// The raw `actor_unknown_reason` column, read beside the store rather than
/// through it, so the assertion sees exactly what was persisted.
fn stored_actor_unknown_reason(path: &Path, id: &str, title: &str) -> Option<String> {
    let conn = rusqlite::Connection::open(path).expect("open store for raw read");
    conn.query_row(
        "SELECT actor_unknown_reason FROM trigger_events
         WHERE principal = ?1 AND subscription_id = ?2
           AND json_extract(payload, '$.title') = ?3",
        rusqlite::params![PRINCIPAL, id, title],
        |row| row.get(0),
    )
    .expect("read stored actor_unknown_reason")
}

/// Exactly one actor field: `actor_unknown` with this reason and class, and no
/// `actor_logins` key at all.
fn assert_served_unknown(served: &Value, reason: &str, class: &str) {
    assert_eq!(
        served.get("actor_unknown"),
        Some(&json!({"reason": reason, "class": class})),
        "served event must carry actor_unknown {reason}/{class}: {served}"
    );
    assert!(
        served.get("actor_logins").is_none(),
        "an unknown actor set must not also carry actor_logins: {served}"
    );
}

/// When neither the comments nor the timeline hold anything after the previous
/// observation, the second observation's window is empty: undeterminable, not
/// a known-empty set. The timeline here holds only activity older than the
/// previous observation, so the fallback read runs and still finds nobody.
#[test]
fn empty_actor_window_is_stored_and_served_as_undeterminable() {
    let (poller, engine, path, _) = fixture("actor-unknown-empty-window");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    bind_timeline_handle(&engine, true);
    set_timeline_pages(
        &engine,
        vec![json!([timeline_labeled(
            "octo-lantern",
            "2026-08-20T11:59:59Z"
        )])],
    );
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert_changed_issue_actors(&poller, &engine, &id, json!([]), None);

    assert_eq!(
        stored_actor_unknown_reason(&path, &id, "after").as_deref(),
        Some("empty_actor_window")
    );
    assert_served_unknown(
        &served_event(&engine, &id, "after"),
        "empty_actor_window",
        "undeterminable",
    );
    // The first observation of the same item is a known-empty set, not unknown.
    let first = served_event(&engine, &id, "before");
    assert_eq!(first.get("actor_logins"), Some(&json!([])));
    assert!(first.get("actor_unknown").is_none(), "{first}");
    let _ = std::fs::remove_file(path);
}

/// A well-formed page whose comment shares the previous observation's second
/// is `same_second_ambiguity`; a malformed page is `unrecognized_response_shape`.
/// Both used to collapse into the second code.
#[test]
fn same_second_ambiguity_is_told_apart_from_an_unrecognized_shape() {
    let (poller, engine, path, _) = fixture("actor-unknown-same-second");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([{
            "user": {"login": "same-second-human"},
            "created_at": "2026-08-20T12:00:00Z"
        }]),
        None,
    );
    assert_eq!(
        stored_actor_unknown_reason(&path, &id, "after").as_deref(),
        Some("same_second_ambiguity")
    );
    assert_served_unknown(
        &served_event(&engine, &id, "after"),
        "same_second_ambiguity",
        "undeterminable",
    );

    let (poller, engine, path_malformed, _) = fixture("actor-unknown-malformed");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path_malformed, &id);
    // Same window and timestamp as above, but the comment has no login.
    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([{
            "user": {"id": 7},
            "created_at": "2026-08-20T12:00:01Z"
        }]),
        None,
    );
    assert_eq!(
        stored_actor_unknown_reason(&path_malformed, &id, "after").as_deref(),
        Some("unrecognized_response_shape")
    );
    assert_served_unknown(
        &served_event(&engine, &id, "after"),
        "unrecognized_response_shape",
        "unexpected",
    );
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path_malformed);
}

/// A vendor failure on the actor read is transient. Its message carries
/// arbitrary text (including `:`), and only the bare code may be stored.
#[test]
fn transport_failure_stores_only_its_code_and_serves_transient() {
    let (poller, engine, path, _) = fixture("actor-unknown-transport");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::VendorError {
            code: "comments_unavailable".to_string(),
            message: "upstream said: private-detail-7f3a".to_string(),
        },
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "changed"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));

    assert_eq!(
        stored_actor_unknown_reason(&path, &id, "changed").as_deref(),
        Some("transport_failure"),
        "only the code before the detail may be stored"
    );
    let served = served_event(&engine, &id, "changed");
    assert_served_unknown(&served, "transport_failure", "transient");
    assert!(
        !served.to_string().contains("private-detail-7f3a"),
        "the failure detail must never reach the wire: {served}"
    );
    let _ = std::fs::remove_file(path);
}

/// A successful read serves the login list and nothing else.
#[test]
fn successful_enrichment_serves_logins_and_no_actor_unknown() {
    let (poller, engine, path, _) = fixture("actor-unknown-success");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert_changed_issue_actors(
        &poller,
        &engine,
        &id,
        json!([{
            "user": {"login": "alice"},
            "created_at": "2026-08-20T12:00:01Z"
        }]),
        Some(vec!["alice"]),
    );
    assert_eq!(stored_actor_unknown_reason(&path, &id, "after"), None);
    let served = served_event(&engine, &id, "after");
    assert_eq!(served.get("actor_logins"), Some(&json!(["alice"])));
    assert!(served.get("actor_unknown").is_none(), "{served}");
    let _ = std::fs::remove_file(path);
}

/// A watch with no actor source (a release watch) carries neither field, and
/// stores no reason.
#[test]
fn a_watch_without_an_actor_source_serves_neither_actor_field() {
    let (poller, engine, path, id) = fixture("actor-unknown-unbound");
    assert_eq!(subscription(&engine, &id).actor_source, None);
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "release-1", "number": 1, "title": "v1"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    assert_eq!(stored_actor_unknown_reason(&path, &id, "v1"), None);
    let served = served_event(&engine, &id, "v1");
    assert!(served.get("actor_logins").is_none(), "{served}");
    assert!(served.get("actor_unknown").is_none(), "{served}");
    let _ = std::fs::remove_file(path);
}

/// A row written before the reason column existed has neither field stored.
/// On an actor-sourced watch it is served as `unrecorded`, so consumers see
/// exactly one actor field from the first read after the upgrade.
#[test]
fn a_row_with_neither_field_stored_serves_unrecorded() {
    let (poller, engine, path, _) = fixture("actor-unknown-unrecorded");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::VendorError {
            code: "comments_unavailable".to_string(),
            message: "unavailable".to_string(),
        },
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "legacy"}],
            "next_cursor": "tok-1"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed { inserted: 1, .. }
    ));
    // Reproduce the pre-migration shape: no logins and no recorded reason.
    let conn = rusqlite::Connection::open(&path).expect("open store");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET actor_unknown_reason = NULL, actor_logins = NULL
             WHERE principal = ?1 AND subscription_id = ?2",
            rusqlite::params![PRINCIPAL, id],
        )
        .expect("clear actor columns"),
        1
    );
    drop(conn);
    assert_served_unknown(
        &served_event(&engine, &id, "legacy"),
        "unrecorded",
        "unexpected",
    );
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Timeline fallback: when a later observation's comment window is empty, the
// poller reads the item's issue timeline through the handle connection bound
// to the watched repository and names who acted from it.
// ---------------------------------------------------------------------------

/// The per-bot handle connection the watched repository `cortexkit/plexus` is
/// bound to, as the GitHub handle ceremony names it.
const HANDLE_CONNECTION: &str = "github-handle-magic-alfonso";
const HANDLE_ID: &str = "magic-alfonso";
/// The agent's own App bot account.
const AGENT_BOT: &str = "magic-alfonso[bot]";
/// A fictional human operator used consistently across captured shapes and mocks.
const OPERATOR: &str = "octo-lantern";

/// Create the handle connection, bind `cortexkit/plexus` to it, and install
/// the reviewed timeline read on it. `grant` controls whether the poller's
/// principal also holds poll authority for that read.
fn bind_timeline_handle(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    grant: bool,
) {
    use plexus_core::storage::github_store::GithubHandle;
    let store = engine.store();
    store
        .insert_connection(
            PRINCIPAL,
            HANDLE_CONNECTION,
            "mock",
            "pending",
            &json!({"required": [], "optional": [], "write_enabling": []}),
        )
        .expect("insert handle connection");
    let ticket = store
        .create_binding_ticket(PRINCIPAL, HANDLE_CONNECTION, BINDING_HANDLE)
        .expect("issue handle binding ticket");
    store
        .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
        .expect("consume handle binding ticket")
        .expect("handle connection activates");
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: HANDLE_ID.to_string(),
            agent_id: HANDLE_ID.to_string(),
            app_id: 1,
            installation_id: None,
            credential_reference: format!("github_app:{HANDLE_ID}"),
            credential_generation: 0,
            status: "enabled".to_string(),
            proven_at: None,
            connection_principal: PRINCIPAL.to_string(),
            connection_id: HANDLE_CONNECTION.to_string(),
        })
        .expect("put handle");
    store
        .bind_github_repo("cortexkit/plexus", HANDLE_ID)
        .expect("bind watched repository to the handle");
    // The args schema from the reviewed `github.issue_timeline.list` entry.
    let timeline_schema = json!({
        "type": "object",
        "properties": {
            "owner": {"type": "string"}, "repo": {"type": "string"},
            "issue_number": {"type": "integer"},
            "per_page": {"type": "integer"}, "page": {"type": "integer"}
        },
        "required": ["owner", "repo", "issue_number"]
    });
    store
        .upsert_catalog_action(&CatalogActionInput {
            connection_id: HANDLE_CONNECTION.to_string(),
            principal: PRINCIPAL.to_string(),
            name: ACTOR_TIMELINE_ACTION.to_string(),
            title: Some(ACTOR_TIMELINE_ACTION.to_string()),
            schema_hash: jcs_sha256(&timeline_schema).expect("test JSON is JCS-compatible"),
            schema: timeline_schema,
            risk: "read".to_string(),
            severity: "S2".to_string(),
            ask_first: false,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .expect("upsert timeline action");
    if grant {
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-timeline-poll".to_string(),
                principal: PRINCIPAL.to_string(),
                connection_id: HANDLE_CONNECTION.to_string(),
                grantee_principal: PRINCIPAL.to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec![ACTOR_TIMELINE_ACTION.to_string()],
                authority_kind: AUTHORITY_POLL.to_string(),
                expires_at: Some(i64::MAX / 2),
            })
            .expect("insert timeline poll grant");
    }
}

/// Serve these timeline pages in order, one per dispatch. The timeline read
/// carries no `method` argument, so the mock keys it on the empty method.
fn set_timeline_pages(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    pages: Vec<Value>,
) {
    engine.transport().set_response_sequence_for_method(
        ACTOR_TIMELINE_ACTION,
        "",
        pages.into_iter().map(MockResponse::Success).collect(),
    );
}

fn timeline_requests(engine: &GovernanceEngine<StubCredentialSource, MockTransport>) -> Vec<Value> {
    engine
        .transport()
        .requests()
        .into_iter()
        .filter(|request| request.action == ACTOR_TIMELINE_ACTION)
        .map(|request| {
            assert_eq!(request.connection_id, HANDLE_CONNECTION);
            request.args
        })
        .collect()
}

// Entry shapes follow GitHub's documented timeline events
// (docs.github.com/rest/issues/timeline): event entries carry `actor` and
// `created_at`; a review carries `user` and `submitted_at`; a commit carries
// only git `author`/`committer` identities and no GitHub account.

fn timeline_labeled(actor: &str, at: &str) -> Value {
    json!({
        "id": 6430295168_u64,
        "node_id": "LE_lADOAAAAAc5bUuhszwAAAAF_",
        "url": "https://api.github.com/repos/cortexkit/plexus/issues/events/6430295168",
        "actor": {"login": actor, "id": 1, "type": if actor.ends_with("[bot]") { "Bot" } else { "User" }},
        "event": "labeled",
        "commit_id": null,
        "commit_url": null,
        "created_at": at,
        "label": {"name": "needs-review", "color": "d73a4a"},
        "performed_via_github_app": null
    })
}

fn timeline_merged(actor: &str, at: &str) -> Value {
    json!({
        "id": 6430295169_u64,
        "node_id": "ME_lADOAAAAAc5bUuhszwAAAAF_",
        "url": "https://api.github.com/repos/cortexkit/plexus/issues/events/6430295169",
        "actor": {"login": actor, "id": 2, "type": "User"},
        "event": "merged",
        "commit_id": "9b1e2f0c3a4d5e6f708192a3b4c5d6e7f8091a2b",
        "commit_url": "https://api.github.com/repos/cortexkit/plexus/commits/9b1e2f0c3a4d5e6f708192a3b4c5d6e7f8091a2b",
        "created_at": at,
        "performed_via_github_app": null
    })
}

fn timeline_reviewed(user: &str, at: &str) -> Value {
    json!({
        "id": 80,
        "node_id": "PRR_kwDOAAABbc4AAAAA",
        "user": {"login": user, "id": 3, "type": "Bot"},
        "body": "Looks good; one nit inline.",
        "state": "commented",
        "html_url": "https://github.com/cortexkit/plexus/pull/17#pullrequestreview-80",
        "pull_request_url": "https://api.github.com/repos/cortexkit/plexus/pulls/17",
        "author_association": "NONE",
        "_links": {
            "html": {"href": "https://github.com/cortexkit/plexus/pull/17#pullrequestreview-80"},
            "pull_request": {"href": "https://api.github.com/repos/cortexkit/plexus/pulls/17"}
        },
        "submitted_at": at,
        "commit_id": "ecdd80bb57125d7ba9641ffaa4d7d2c19d3f3091",
        "event": "reviewed"
    })
}

fn timeline_committed(name: &str, email: &str, at: &str) -> Value {
    json!({
        "sha": "7638417db6d59f3c431d3e1f261cc637155684cd",
        "node_id": "C_kwDOAAABbdoAKDc2Mzg0MTdkYjZkNTlmM2M0MzFkM2UxZjI2MWNjNjM3MTU1Njg0Y2Q",
        "url": "https://api.github.com/repos/cortexkit/plexus/git/commits/7638417db6d59f3c431d3e1f261cc637155684cd",
        "html_url": "https://github.com/cortexkit/plexus/commit/7638417db6d59f3c431d3e1f261cc637155684cd",
        "author": {"name": name, "email": email, "date": at},
        "committer": {"name": name, "email": email, "date": at},
        "tree": {
            "sha": "691272480426f78a0138979dd3ce63b77f706feb",
            "url": "https://api.github.com/repos/cortexkit/plexus/git/trees/691272480426f78a0138979dd3ce63b77f706feb"
        },
        "message": "Fix the flaky retry test",
        "parents": [{
            "sha": "1acc419d4d6a9ce985db7be48c6349a0475975b5",
            "url": "https://api.github.com/repos/cortexkit/plexus/git/commits/1acc419d4d6a9ce985db7be48c6349a0475975b5",
            "html_url": "https://github.com/cortexkit/plexus/commit/1acc419d4d6a9ce985db7be48c6349a0475975b5"
        }],
        "verification": {"verified": false, "reason": "unsigned", "signature": null, "payload": null},
        "event": "committed"
    })
}

/// Poll a later observation of item 17 whose comment window is empty (the
/// comment read succeeds with no comments), after `prime_issue_actor_window`
/// pinned the previous observation. Returns the stored actor logins and the
/// stored unknown reason for the changed event.
fn poll_empty_comment_window(
    poller: &Poller<StubCredentialSource, MockTransport>,
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    path: &Path,
    id: &str,
) -> (Option<Vec<String>>, Option<String>) {
    assert_changed_issue_actors_raw(poller, engine, id);
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(id))
        .expect("list timeline events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed event stored");
    (
        changed.actor_logins.clone(),
        stored_actor_unknown_reason(path, id, "after"),
    )
}

fn assert_changed_issue_actors_raw(
    poller: &Poller<StubCredentialSource, MockTransport>,
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    id: &str,
) {
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{"id": "issue-17", "number": 17, "title": "after"}],
            "next_cursor": "tok-2"
        })));
    assert!(matches!(
        poller.poll_once(PRINCIPAL, id),
        PollCycle::Completed { inserted: 1, .. }
    ));
}

/// A later issue watch whose previous observation is pinned at
/// `ACTOR_WINDOW_PREVIOUS_MS` (2026-08-20T12:00:00.500Z), with the timeline
/// handle bound and granted. Returns the poller, engine, path and watch id.
fn timeline_fixture(
    label: &str,
    pages: Vec<Value>,
) -> (
    Poller<StubCredentialSource, MockTransport>,
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Scratch,
    String,
) {
    let (poller, engine, path, _) = fixture(label);
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    bind_timeline_handle(&engine, true);
    set_timeline_pages(&engine, pages);
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert!(
        timeline_requests(&engine).is_empty(),
        "a first observation proves its own empty history and never reads the timeline"
    );
    (poller, engine, path, id)
}

/// Modelled on a real pull request (magic-context#532) whose events all had
/// empty comment windows: its timeline showed a body-only review by the
/// agent's own bot and a merge by the operator. Each event must name exactly
/// the actor its timeline window shows.
#[test]
fn timeline_names_the_reviewer_and_the_merger_of_an_empty_comment_window() {
    let (poller, engine, path, id) = timeline_fixture(
        "timeline-review",
        vec![json!([
            timeline_labeled(OPERATOR, "2026-08-19T09:00:00Z"),
            timeline_reviewed(AGENT_BOT, "2026-08-20T12:03:00Z"),
        ])],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (Some(vec![AGENT_BOT.to_string()]), None)
    );
    let requests = timeline_requests(&engine);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0],
        json!({"owner": "cortexkit", "repo": "plexus", "issue_number": 17, "per_page": 100, "page": 1})
    );
    let _ = std::fs::remove_file(path);

    let (poller, engine, path, id) = timeline_fixture(
        "timeline-merge",
        vec![json!([
            timeline_reviewed(AGENT_BOT, "2026-08-19T12:03:00Z"),
            timeline_merged(OPERATOR, "2026-08-20T12:07:00Z"),
        ])],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (Some(vec![OPERATOR.to_string()]), None)
    );
    let _ = std::fs::remove_file(path);
}

/// A commit's git author name is free text. One that equals the agent's bot
/// login, with an ordinary email, must not become that login: stored as
/// `unresolved_commit_author`, served undeterminable.
///
/// MUTATION: taking the git author name as the login stores
/// `["magic-alfonso[bot]"]` and reddens the tuple assertion.
#[test]
fn a_commit_whose_git_name_equals_a_bot_login_is_unresolved_not_that_login() {
    let (poller, engine, path, id) = timeline_fixture(
        "timeline-commit-collision",
        vec![json!([timeline_committed(
            AGENT_BOT,
            "someone@example.com",
            "2026-08-20T12:04:00Z"
        )])],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (None, Some("unresolved_commit_author".to_string()))
    );
    assert_served_unknown(
        &served_event(&engine, &id, "after"),
        "unresolved_commit_author",
        "undeterminable",
    );
    let _ = std::fs::remove_file(path);
}

/// A GitHub noreply email encodes the account's login, in both its current
/// `<id>+<login>` form and the older bare `<login>` form.
#[test]
fn a_noreply_commit_email_names_its_login() {
    let (poller, engine, path, id) = timeline_fixture(
        "timeline-commit-noreply",
        vec![json!([
            timeline_committed(
                "Some Display Name",
                "1234567+outside-contributor@users.noreply.github.com",
                "2026-08-20T12:04:00Z"
            ),
            timeline_committed(
                "Another Name",
                "legacy-user@users.noreply.github.com",
                "2026-08-20T12:05:00Z"
            ),
        ])],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (
            Some(vec![
                "legacy-user".to_string(),
                "outside-contributor".to_string()
            ]),
            None
        )
    );
    let _ = std::fs::remove_file(path);
}

/// A bot's label change and an unattributable commit in one window: the event
/// is `unresolved_commit_author`, never the bot-only partial set, which would
/// suppress the wake the commit's human author caused.
///
/// MUTATION: returning the logins that could be read stores
/// `["magic-alfonso[bot]"]` and reddens the tuple assertion.
#[test]
fn a_bot_label_beside_an_unresolved_commit_is_unknown_not_a_partial_set() {
    let (poller, engine, path, id) = timeline_fixture(
        "timeline-mixed-window",
        vec![json!([
            timeline_labeled(AGENT_BOT, "2026-08-20T12:02:00Z"),
            timeline_committed("Jane Doe", "jane@example.com", "2026-08-20T12:04:00Z"),
        ])],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (None, Some("unresolved_commit_author".to_string()))
    );
    let _ = std::fs::remove_file(path);
}

/// GitHub serves the timeline oldest first, so the newest activity is on the
/// last page. A full first page of old history must be followed to the short
/// last page that holds the in-window merge.
///
/// MUTATION: reading only the first page sees nothing in the window and
/// stores `empty_actor_window`, reddening the tuple assertion.
#[test]
fn the_timeline_walk_reaches_the_newest_entries_on_the_last_page() {
    let old_history: Vec<Value> = (0..100)
        .map(|_| timeline_labeled(AGENT_BOT, "2026-08-01T08:00:00Z"))
        .collect();
    let (poller, engine, path, id) = timeline_fixture(
        "timeline-last-page",
        vec![
            Value::Array(old_history),
            json!([timeline_merged(OPERATOR, "2026-08-20T12:07:00Z")]),
        ],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (Some(vec![OPERATOR.to_string()]), None)
    );
    let pages: Vec<Value> = timeline_requests(&engine)
        .iter()
        .map(|args| args["page"].clone())
        .collect();
    assert_eq!(pages, vec![json!(1), json!(2)]);
    let _ = std::fs::remove_file(path);
}

/// A timeline entry in the same wall-clock second as the previous observation
/// could be on either side of it: `same_second_ambiguity`, not an actor set.
#[test]
fn a_timeline_entry_in_the_previous_observations_second_is_ambiguous() {
    let (poller, engine, path, id) = timeline_fixture(
        "timeline-same-second",
        vec![json!([timeline_merged(OPERATOR, "2026-08-20T12:00:00Z")])],
    );
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (None, Some("same_second_ambiguity".to_string()))
    );
    let _ = std::fs::remove_file(path);
}

/// No handle connection is bound to the watched repository: the timeline read
/// is refused by name as `governed_read_refusal` (transient, so the event
/// wakes) and nothing is dispatched.
#[test]
fn an_unbound_repository_refuses_the_timeline_read_by_name_without_dispatch() {
    let (poller, engine, path, _) = fixture("timeline-unbound");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (None, Some("governed_read_refusal".to_string()))
    );
    assert_served_unknown(
        &served_event(&engine, &id, "after"),
        "governed_read_refusal",
        "transient",
    );
    assert!(timeline_requests(&engine).is_empty());
    let _ = std::fs::remove_file(path);
}

/// The handle is bound but the poller's principal holds no poll grant for the
/// timeline read on it: refused by governance as `governed_read_refusal`,
/// with nothing dispatched.
#[test]
fn a_missing_timeline_poll_grant_refuses_by_name_without_dispatch() {
    let (poller, engine, path, _) = fixture("timeline-ungranted");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    bind_timeline_handle(&engine, false);
    set_timeline_pages(
        &engine,
        vec![json!([timeline_merged(OPERATOR, "2026-08-20T12:07:00Z")])],
    );
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (None, Some("governed_read_refusal".to_string()))
    );
    assert!(timeline_requests(&engine).is_empty());
    let _ = std::fs::remove_file(path);
}

/// An anonymized GitHub pull-request timeline with ten oldest-first entries,
/// covering commits, reviews, cross-references, comments, merging and closing.
/// The windows below exercise attribution at successive stages of the PR.
/// Capture source: cortexkit/magic-context#532; see
/// `fixtures/github_timeline/magic-context-532.PROVENANCE`.
fn magic_context_532_timeline() -> Vec<Value> {
    let page: Value = serde_json::from_str(include_str!(
        "fixtures/github_timeline/magic-context-532.json"
    ))
    .expect("captured timeline is JSON");
    page.as_array().expect("timeline page is an array").clone()
}

/// Poll a later observation whose previous observation is pinned at
/// `previous_ms`, serving the timeline as it stood at the new observation:
/// the first `entries_so_far` captured entries (the capture is chronological,
/// and a read cannot see activity that has not happened yet).
fn attribute_real_timeline_window(
    label: &str,
    previous_ms: i64,
    entries_so_far: usize,
) -> (Option<Vec<String>>, Option<String>) {
    let timeline = magic_context_532_timeline();
    let (poller, engine, path, _) = fixture(label);
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    bind_timeline_handle(&engine, true);
    set_timeline_pages(
        &engine,
        vec![Value::Array(timeline[..entries_so_far].to_vec())],
    );
    prime_issue_actor_window_at(&poller, &engine, &path, &id, previous_ms);
    let outcome = poll_empty_comment_window(&poller, &engine, &path, &id);
    assert_eq!(
        timeline_requests(&engine).len(),
        1,
        "{label}: one short page"
    );
    let _ = std::fs::remove_file(path);
    outcome
}

/// An anonymized GitHub capture, one step of the pull request's life per window. Every
/// entry type in the capture (committed, ready_for_review, reviewed,
/// cross-referenced, commented, merged, closed) must parse: any shape the
/// parser did not recognise would surface as `unrecognized_response_shape`.
#[test]
fn the_captured_magic_context_532_timeline_attributes_each_step() {
    let timeline = magic_context_532_timeline();
    assert_eq!(timeline.len(), 10);
    // 2026-09-25 wall-clock times as epoch milliseconds (UTC).
    const AT_0800: i64 = 1_790_323_200_000;
    const AT_0840: i64 = 1_790_325_600_000;
    const AT_1105: i64 = 1_790_334_300_000;
    const AT_1800: i64 = 1_790_359_200_000;
    const AT_1900: i64 = 1_790_362_800_000;

    // (08:40, 11:05]: magic-alfonso[bot]'s review at 11:01:34 and its
    // cross-reference at 11:01:40 (entries 3 and 4).
    assert_eq!(
        attribute_real_timeline_window("mc532-review", AT_0840, 5),
        (Some(vec![AGENT_BOT.to_string()]), None)
    );
    // (11:05, 17:10]: only the commit at 17:06:45. Its git author email is
    // `328614759+octo-orbit@users.noreply.github.com`: the part after `+`
    // and before `@` identifies the login, so the commit resolves to octo-orbit.
    assert_eq!(
        attribute_real_timeline_window("mc532-commit", AT_1105, 6),
        (Some(vec!["octo-orbit".to_string()]), None)
    );
    // (18:00, 18:30]: magic-alfonso[bot]'s second review at 18:28:48.
    assert_eq!(
        attribute_real_timeline_window("mc532-rereview", AT_1800, 8),
        (Some(vec![AGENT_BOT.to_string()]), None)
    );
    // (19:00, 19:31]: merged and closed by the operator at 19:30:53.
    assert_eq!(
        attribute_real_timeline_window("mc532-merge", AT_1900, 10),
        (Some(vec![OPERATOR.to_string()]), None)
    );
    // The whole page after 08:00: every entry parses and attributes.
    assert_eq!(
        attribute_real_timeline_window("mc532-whole", AT_0800, 10),
        (
            Some(vec![
                AGENT_BOT.to_string(),
                OPERATOR.to_string(),
                "octo-orbit".to_string(),
                "octo-review[bot]".to_string(),
            ]),
            None
        )
    );
}

// ---------------------------------------------------------------------------
// The live path for handles imported before the timeline read existed: boot
// ingest of the new manifest adds the catalog row, the poll form of
// `github.handle.grant` widens the ceiling and mints the poll grant, and a
// poll then reads the timeline through the real handle-credential seams.
// ---------------------------------------------------------------------------

/// Stands in for the App vault: a handle connection's token comes from here,
/// not from a stored credential binding.
struct VaultStub;

impl plexus_core::github::credential::HandleCredentialProvider for VaultStub {
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

/// The shipped `catalog/github_rest.jsonc`, optionally without the timeline
/// read, to reproduce the manifest the fleet's handles were imported under.
fn github_rest_manifest(with_timeline: bool) -> plexus_core::IngestedManifest {
    let source = include_str!("../../../catalog/github_rest.jsonc");
    // Strip `//` comments outside strings (JSONC to JSON).
    let mut clean = String::new();
    let mut chars = source.chars().peekable();
    let (mut quoted, mut escaped) = (false, false);
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
    let mut value: Value = serde_json::from_str(&clean).expect("github_rest manifest is JSON");
    if !with_timeline {
        value["actions_baseline"]
            .as_array_mut()
            .expect("actions_baseline")
            .retain(|action| action["name"] != ACTOR_TIMELINE_ACTION);
    }
    ingest_value(value).expect("github_rest manifest ingests")
}

/// Every catalog row on the handle connection, with every column a refresh
/// could disturb, read beside the store.
fn handle_catalog_rows(path: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(path).expect("open store for raw read");
    let mut statement = conn
        .prepare(
            "SELECT name||'|'||status||'|'||risk||'|'||schema_hash||'|'||IFNULL(quarantine_reason,'-')
                ||'|'||generation||'|'||first_seen_at_ms||'|'||last_seen_at_ms
                ||'|'||IFNULL(reviewed_schema_json,'-')
             FROM catalog_actions WHERE principal=?1 AND connection_id=?2 ORDER BY name",
        )
        .unwrap();
    let rows = statement
        .query_map([PRINCIPAL, HANDLE_CONNECTION], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows
}

fn handle_ceiling(path: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(path).expect("open store for raw read");
    let selectors: String = conn
        .query_row(
            "SELECT ceiling_selectors FROM connections WHERE principal=?1 AND connection_id=?2",
            [PRINCIPAL, HANDLE_CONNECTION],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&selectors).unwrap()
}

fn authority_rows(path: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(path).expect("open store for raw read");
    let mut rows = Vec::new();
    for query in [
        "SELECT principal||'|'||connection_id||'|'||IFNULL(ceiling_selectors,'-') FROM connections ORDER BY 1",
        "SELECT grant_id||'|'||authority_kind||'|'||action_selectors FROM grants ORDER BY 1",
    ] {
        let mut statement = conn.prepare(query).unwrap();
        rows.extend(
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        );
    }
    rows
}

/// A handle imported before the timeline read existed ends up reading the
/// timeline, using only the operator steps the deploy prescribes: the boot
/// ingest of the new manifest, then `github.handle.grant --kind poll`.
///
/// MUTATION: skipping the ceiling widening in the poll form makes the grant
/// refuse `outside_connection_ceiling{action: github.issue_timeline.list}`,
/// reddening the `expect` on the applied grant.
#[test]
fn an_imported_handle_reads_the_timeline_after_manifest_refresh_and_poll_grant() {
    use plexus_core::storage::github_store::{
        GithubGovernanceSeams, GithubHandle, GithubImportRow,
    };
    let (_, engine, path, _) = fixture("timeline-live-path");
    let id = actor_subscription(&engine, FEED, ISSUE_READ, &["get_comments"]);
    let store = engine.store().clone();

    // The fleet today: handles imported under the manifest without the
    // timeline, with the import's ceiling and catalog seed.
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &github_rest_manifest(false))
        .expect("store the pre-timeline manifest");
    store
        .import_github_handles(&[GithubImportRow {
            handle: GithubHandle {
                app_handle_id: HANDLE_ID.to_string(),
                agent_id: HANDLE_ID.to_string(),
                app_id: 1,
                installation_id: None,
                credential_reference: format!("github_app:{HANDLE_ID}"),
                credential_generation: 0,
                status: "enabled".to_string(),
                proven_at: None,
                connection_principal: PRINCIPAL.to_string(),
                connection_id: HANDLE_CONNECTION.to_string(),
            },
            repositories: vec!["cortexkit/plexus".to_string()],
            grants: vec![],
            module_actions: vec![
                "github.issue.get".to_string(),
                "github.issue.search".to_string(),
                "github.issue_comment.get".to_string(),
                "github.issue_comments.list".to_string(),
            ],
            policies: vec![],
        }])
        .expect("import the handle");
    assert!(store
        .catalog_action(PRINCIPAL, HANDLE_CONNECTION, ACTOR_TIMELINE_ACTION)
        .unwrap()
        .is_none());
    assert!(!handle_ceiling(&path).contains(&ACTOR_TIMELINE_ACTION.to_string()));
    // A reviewer's decision on an existing row must survive the refresh.
    store
        .quarantine_action(
            PRINCIPAL,
            HANDLE_CONNECTION,
            "github.issue.get",
            "under review",
        )
        .expect("quarantine an existing row");
    let rows_before = handle_catalog_rows(&path);

    // Before any operator step the poll form refuses by name: no catalog row.
    let timeline = vec![ACTOR_TIMELINE_ACTION.to_string()];
    let early =
        plexus_core::github::control::grant_poll(&store, "direct", HANDLE_ID, &timeline, false)
            .unwrap_err();
    assert!(early.starts_with("catalog_action_missing"), "{early}");

    // Boot ingest of the new manifest adds exactly the new row.
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &github_rest_manifest(true))
        .expect("boot ingest of the new manifest");
    let rows_after = handle_catalog_rows(&path);
    let (added, kept): (Vec<_>, Vec<_>) = rows_after
        .iter()
        .cloned()
        .partition(|row| row.starts_with(&format!("{ACTOR_TIMELINE_ACTION}|")));
    assert_eq!(
        kept, rows_before,
        "existing rows must be left exactly as they were"
    );
    assert_eq!(added.len(), 1);
    assert!(
        added[0].starts_with(&format!("{ACTOR_TIMELINE_ACTION}|active|read|")),
        "{added:?}"
    );

    // Writes are never pollable.
    let write = plexus_core::github::control::grant_poll(
        &store,
        "direct",
        HANDLE_ID,
        &["add_issue_comment".to_string()],
        false,
    )
    .unwrap_err();
    assert_eq!(write, "poll_write_refused{action: add_issue_comment}");

    // The poll form: a dry run writes nothing, then the applied grant widens
    // the ceiling by exactly the timeline read and mints the poll grant.
    let authority_before = authority_rows(&path);
    let plan =
        plexus_core::github::control::grant_poll(&store, "direct", HANDLE_ID, &timeline, true)
            .expect("dry run");
    assert_eq!(authority_rows(&path), authority_before);
    assert_eq!(plan["ceiling_additions"], json!([ACTOR_TIMELINE_ACTION]));
    assert_eq!(plan["grantee_principal"], PRINCIPAL);
    let ceiling_before = handle_ceiling(&path);
    plexus_core::github::control::grant_poll(&store, "direct", HANDLE_ID, &timeline, false)
        .expect("the poll grant mints inside the widened ceiling");
    let mut expected_ceiling = ceiling_before;
    expected_ceiling.push(ACTOR_TIMELINE_ACTION.to_string());
    assert_eq!(handle_ceiling(&path), expected_ceiling);
    let poll_grants: Vec<_> = store
        .list_grants(PRINCIPAL, HANDLE_CONNECTION)
        .unwrap()
        .into_iter()
        .filter(|grant| grant.authority_kind == AUTHORITY_POLL)
        .collect();
    assert_eq!(poll_grants.len(), 1);
    assert_eq!(poll_grants[0].grantee_principal, PRINCIPAL);
    assert_eq!(poll_grants[0].action_selectors, timeline);
    assert_eq!(poll_grants[0].risk_ceiling, "read");
    // Idempotent: granting again changes nothing.
    let again =
        plexus_core::github::control::grant_poll(&store, "direct", HANDLE_ID, &timeline, false)
            .expect("repeat grant");
    assert_eq!(again["grants"][0]["op"], "unchanged");
    assert_eq!(again["ceiling_additions"], json!([]));

    // A poll through the production seams now reads the timeline.
    let seamed = engine
        .clone()
        .with_governance_seams(Arc::new(GithubGovernanceSeams {
            store: store.clone(),
            credential_provider: Some(Arc::new(VaultStub)),
        }));
    let poller = Poller::new(seamed);
    set_timeline_pages(
        &engine,
        vec![json!([
            timeline_reviewed(AGENT_BOT, "2026-08-19T12:03:00Z"),
            timeline_merged(OPERATOR, "2026-08-20T12:07:00Z"),
        ])],
    );
    prime_issue_actor_window(&poller, &engine, &path, &id);
    assert_eq!(
        poll_empty_comment_window(&poller, &engine, &path, &id),
        (Some(vec![OPERATOR.to_string()]), None)
    );
    assert_eq!(timeline_requests(&engine).len(), 1);
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Already-stored items skip enrichment: the ordered-timestamp overlap window
// re-reads the item at its watermark on every pass. When that item's exact
// payload is already stored, storage would drop it as a duplicate, so the
// comment and timeline reads enrichment would spend on it are skipped.
// ---------------------------------------------------------------------------

/// The newest item's timestamp; the watermark sits on it after the first pass.
const TIMESTAMPED_ISSUE_AT: &str = "2026-08-20T12:00:00Z";

/// An ordered-timestamp issue watch with comment enrichment and the timeline
/// handle bound, so a later observation with an empty comment window would
/// also read the timeline. The comment read always answers with no comments.
fn timestamped_actor_fixture(
    label: &str,
    timeline_pages: Vec<Value>,
) -> (
    Poller<StubCredentialSource, MockTransport>,
    GovernanceEngine<StubCredentialSource, MockTransport>,
    Scratch,
    String,
) {
    let (poller, engine, path, _) = fixture(label);
    let id = actor_subscription(&engine, TIMESTAMPED, ISSUE_READ, &["get_comments"]);
    bind_timeline_handle(&engine, true);
    set_timeline_pages(&engine, timeline_pages);
    engine.transport().set_response_for_method(
        ISSUE_READ,
        "get_comments",
        MockResponse::Success(json!([])),
    );
    (poller, engine, path, id)
}

fn serve_timestamped_issue(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    title: &str,
) {
    engine
        .transport()
        .set_response(MockResponse::Success(json!({
            "items": [{
                "id": "issue-17",
                "number": 17,
                "updated_at": TIMESTAMPED_ISSUE_AT,
                "title": title
            }]
        })));
}

/// Enrichment reads recorded so far: comment reads and timeline reads.
fn enrichment_dispatches(engine: &GovernanceEngine<StubCredentialSource, MockTransport>) -> usize {
    engine
        .transport()
        .requests()
        .iter()
        .filter(|request| request.action == ISSUE_READ || request.action == ACTOR_TIMELINE_ACTION)
        .count()
}

/// First pass of the watch: item 17 is new, is enriched with one comment read
/// (a first observation never reads the timeline), and is stored. The stored
/// observation is then pinned to `ACTOR_WINDOW_PREVIOUS_MS` so a later
/// timeline window has a fixed start.
fn first_timestamped_pass(
    poller: &Poller<StubCredentialSource, MockTransport>,
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    path: &Path,
    id: &str,
) {
    serve_timestamped_issue(engine, "before");
    assert_eq!(
        poller.poll_once(PRINCIPAL, id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(enrichment_dispatches(engine), 1, "one comment read");
    let conn = rusqlite::Connection::open(path).expect("open store for pinning");
    assert_eq!(
        conn.execute(
            "UPDATE trigger_events SET activity_at_ms = ?1
             WHERE principal = ?2 AND subscription_id = ?3",
            rusqlite::params![ACTOR_WINDOW_PREVIOUS_MS, PRINCIPAL, id],
        )
        .expect("pin first observation"),
        1
    );
}

/// The ordered-timestamp overlap window re-reads the unchanged item sitting at
/// its watermark. The second pass makes no comment read and no timeline read,
/// stores nothing, and still reports the item as a duplicate.
///
/// MUTATION: removing the pre-enrichment skip lets the second pass read the
/// comments and then the timeline (their window is empty), so the dispatch
/// delta is 2 instead of 0.
#[test]
fn unchanged_watermark_item_is_not_re_enriched() {
    let (poller, engine, path, id) =
        timestamped_actor_fixture("timestamped-unchanged", vec![json!([])]);
    first_timestamped_pass(&poller, &engine, &path, &id);
    let before = enrichment_dispatches(&engine);
    let list_reads_before = engine.transport().requests().len() - before;

    serve_timestamped_issue(&engine, "before");
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(
        enrichment_dispatches(&engine) - before,
        0,
        "no comment or timeline read for an already-stored item"
    );
    assert_eq!(
        engine.transport().requests().len() - enrichment_dispatches(&engine),
        list_reads_before + 1,
        "the watched list itself was read"
    );
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list events");
    assert_eq!(events.len(), 1, "nothing new stored");
    let _ = std::fs::remove_file(path);
}

/// The same item with a changed payload is a new observation: it is enriched
/// exactly as before the skip existed (a comment read, then a timeline read
/// because its comment window is empty) and stored with the timeline's actor.
///
/// MUTATION: skipping every item whose vendor id is already stored, whatever
/// its payload, drops the edit before enrichment and fails the cycle assertion.
#[test]
fn changed_watermark_item_is_enriched_and_stored() {
    let (poller, engine, path, id) = timestamped_actor_fixture(
        "timestamped-changed",
        vec![json!([timeline_labeled(OPERATOR, "2026-08-20T12:03:00Z")])],
    );
    first_timestamped_pass(&poller, &engine, &path, &id);
    let before = enrichment_dispatches(&engine);

    serve_timestamped_issue(&engine, "after");
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 1,
            duplicates: 0
        }
    );
    assert_eq!(
        enrichment_dispatches(&engine) - before,
        2,
        "a comment read and a timeline read"
    );
    assert_eq!(timeline_requests(&engine).len(), 1);
    let events = engine
        .store()
        .list_events(PRINCIPAL, None, Some(&id))
        .expect("list events");
    let changed = events
        .iter()
        .find(|event| event.payload["title"] == "after")
        .expect("changed version stored");
    assert_eq!(changed.actor_logins, Some(vec![OPERATOR.to_string()]));
    let _ = std::fs::remove_file(path);
}

const LEDGER_CHILD_ENV: &str = "PLEXUS_POLL_LEDGER_CHILD";

/// The drop ledger balances across a skipped item and names the reason
/// storage would have given it: `alreadyDelivered`.
///
/// The ledger counters are process-wide, so the scenario runs in a child
/// process that executes only this test; the parent asserts the child passed.
///
/// MUTATION: recording no drop for a skipped item leaves the second pass with
/// one examined item, nothing inserted and nothing dropped, so
/// `identityViolations` becomes 1 and `alreadyDelivered` 0.
#[test]
fn skipped_watermark_item_balances_the_drop_ledger() {
    const TEST: &str = "skipped_watermark_item_balances_the_drop_ledger";
    if std::env::var_os(LEDGER_CHILD_ENV).is_none() {
        let output = bounded::child_output(
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", TEST, "--nocapture"])
                .env(LEDGER_CHILD_ENV, "1"),
            std::time::Duration::from_secs(30),
            "test binary child",
        )
        .expect("run ledger child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "ledger child failed: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (poller, engine, path, id) =
        timestamped_actor_fixture("timestamped-ledger", vec![json!([])]);
    first_timestamped_pass(&poller, &engine, &path, &id);
    serve_timestamped_issue(&engine, "before");
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Completed {
            inserted: 0,
            duplicates: 1
        }
    );
    assert_eq!(
        plexus_core::poller::poll_accounting_metrics(),
        json!({
            "itemsExamined": 2,
            "eventsInserted": 1,
            "identityViolations": 0,
            "droppedByReason": {
                "olderThanWatermark": 0,
                "initialBaseline": 0,
                "unchangedObservation": 0,
                "unchangedBoundaryReplay": 0,
                "alreadyDelivered": 1
            },
            "lateRowsBySubscription": {},
            "credentialNeedsRepairByConnection": {}
        })
    );
    let _ = std::fs::remove_file(path);
}

/// A read action polled by the scalar-diff strategy in the closed-schema test.
const SCALAR: &str = "read_latest_release";

/// Store `action`'s catalog schema as a closed object schema (one with a
/// `properties` list, so governance refuses any other top-level argument)
/// declaring owner, repo and every argument `manifest`'s poll shape makes the
/// poller send. Returns the declared names.
fn pin_closed_poll_schema(
    engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
    manifest: &Value,
    action: &str,
) -> BTreeSet<String> {
    let mut declared: BTreeSet<String> = ["owner", "repo"].map(str::to_string).into();
    declared.extend(poll_argument_names_in(manifest, action));
    let properties: serde_json::Map<String, Value> = declared
        .iter()
        .map(|name| {
            let schema = if matches!(name.as_str(), "owner" | "repo") {
                json!({"type": "string"})
            } else {
                json!({})
            };
            (name.clone(), schema)
        })
        .collect();
    upsert_action_with_schema(
        engine,
        action,
        "read",
        &schema_hash(),
        "active",
        json!({"type": "object", "properties": properties}),
    );
    declared
}

/// Every cursor strategy that ships polls to completion when its action's
/// pinned schema is CLOSED, and every argument it sends is one that schema
/// declares. Each subscription is built like a production one: fixed owner and
/// repo, a resumed cursor so the strategy adds its own argument, and the
/// manifest's request constants.
///
/// This passes because the poller's arguments are declared, not because polls
/// are exempt from the undeclared-argument check: each request's keys are
/// compared with the schema here directly, and
/// `a_poll_sending_an_undeclared_argument_suspends_by_name` shows the check does
/// run on the poll path.
#[test]
fn every_shipped_cursor_strategy_polls_with_only_declared_arguments() {
    let (poller, engine, path, _) = fixture("closed-schema-strategies");
    let mut manifest = manifest_value();
    // The ordered-timestamp action reads pages of `perPage` items and sends
    // the next page's cursor as `after`, as GitHub's list_issues does.
    let timestamped = &mut manifest["actions_baseline"][3]["poll"];
    timestamped["request_page_size_field"] = json!("perPage");
    timestamped["request_constants"] = json!({"perPage": 2, "method": "list"});
    timestamped["pagination"] = json!({
        "request_cursor_field": "after",
        "response_cursor_pointer": "/pageInfo/endCursor"
    });
    manifest["actions_baseline"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": SCALAR,
            "risk": "read",
            "poll": {"cursor_kind": "scalar_diff", "item_kind": "release", "scalar_field": "tag_name"}
        }));
    engine
        .store()
        .upsert_manifest(
            plexus_core::CATALOG_PRINCIPAL,
            &ingest_value(manifest.clone()).expect("strategy manifest"),
        )
        .expect("update manifest");
    insert_poll_grant(&engine, SORTED_HEAD);
    insert_poll_grant(&engine, SCALAR);
    let fixed = json!({"owner": "cortexkit", "repo": "plexus"});

    // Each case: the action, a resumed cursor state, and the request argument
    // the cursor strategy adds from that state (beyond the fixed arguments and
    // request constants), if it adds one.
    let cases = [
        (FEED, json!({"sync_token": "tok-1"}), Some("sync_token")),
        (
            TIMESTAMPED,
            json!({"watermark_ms": 1705312805000i64, "watermark_id": "29", "window_ms": 60_000}),
            Some("updatedSince"),
        ),
        (SORTED_HEAD, json!({}), None),
        (SCALAR, json!({}), None),
    ];
    engine.transport().set_response_for_method(
        FEED,
        "",
        MockResponse::Success(json!({"items": [{"id": "a"}], "next_cursor": "tok-2"})),
    );
    // A full first page then an empty one, so the page cursor is sent too.
    engine.transport().set_response_sequence_for_method(
        TIMESTAMPED,
        "list",
        vec![
            MockResponse::Success(json!({
                "items": [{"id": 30, "updated_at": "2024-01-15T10:00:05Z"},
                          {"id": 31, "updated_at": "2024-01-15T10:00:06Z"}],
                "pageInfo": {"endCursor": "page-1"}
            })),
            MockResponse::Success(json!({"items": [], "pageInfo": {"endCursor": "page-2"}})),
        ],
    );
    engine.transport().set_response_for_method(
        SORTED_HEAD,
        "",
        MockResponse::Success(json!({"items": [{"id": 5, "updated_at": "2024-01-15T10:00:05Z"}]})),
    );
    engine.transport().set_response_for_method(
        SCALAR,
        "",
        MockResponse::Success(json!({"tag_name": "v1.0.0"})),
    );
    for (action, cursor, strategy_argument) in cases {
        let declared = pin_closed_poll_schema(&engine, &manifest, action);
        let id = engine
            .store()
            .subscribe_with_cursor_state(PRINCIPAL, CONNECTION, action, 30, &cursor, &fixed)
            .expect("subscribe store")
            .expect("subscription accepted")
            .subscription_id;
        let before = engine.transport().requests().len();
        let cycle = poller.poll_once(PRINCIPAL, &id);
        assert!(
            matches!(cycle, PollCycle::Completed { .. }),
            "{action}: {cycle:?}"
        );
        let sent = engine.transport().requests()[before..].to_vec();
        assert!(!sent.is_empty(), "{action} dispatched nothing");
        for request in &sent {
            let keys: BTreeSet<String> =
                request.args.as_object().unwrap().keys().cloned().collect();
            assert!(
                keys.is_subset(&declared),
                "{action} sent {keys:?}, schema declares {declared:?}"
            );
            assert!(
                keys.contains("owner") && keys.contains("repo"),
                "{action}: {keys:?}"
            );
        }
        if let Some(argument) = strategy_argument {
            assert!(
                sent[0].args.get(argument).is_some(),
                "{action} did not send its cursor argument {argument}"
            );
        }
        if action == TIMESTAMPED {
            assert_eq!(sent.len(), 2, "the second page must be read");
            assert!(sent[1].args.get("after").is_some(), "page cursor sent");
        }
        if action == SORTED_HEAD {
            for constant in ["sort", "direction", "perPage"] {
                assert!(sent[0].args.get(constant).is_some(), "{constant}");
            }
        }
    }

    // A probe subscription runs a registered script that calls `invoke` on an
    // action with arguments the script builds; that call is checked against
    // the same closed schema.
    let probe_id = register_read_probe_with_script(
        &engine,
        "closed-schema-probe",
        "() => { invoke('read_feed', {}); return true; }",
    );
    let declared = pin_closed_poll_schema(&engine, &manifest, FEED);
    let before = engine.transport().requests().len();
    let cycle = poller.poll_once(PRINCIPAL, &probe_id);
    assert!(
        matches!(cycle, PollCycle::Completed { .. }),
        "probe: {cycle:?}"
    );
    let sent = engine.transport().requests()[before..].to_vec();
    assert_eq!(sent.len(), 1, "the probe's one read");
    let keys: BTreeSet<String> = sent[0].args.as_object().unwrap().keys().cloned().collect();
    assert!(keys.is_subset(&declared), "probe sent {keys:?}");
    let _ = std::fs::remove_file(path);
}

/// The undeclared-argument check runs on the poll path: a resumed sync-token
/// poll against a schema that declares only the repository scope is refused by
/// name before anything is sent, and the subscription suspends with that
/// reason. Removing the check for poll requests fails this test.
#[test]
fn a_poll_sending_an_undeclared_argument_suspends_by_name() {
    let (poller, engine, path, _) = fixture("undeclared-poll-argument");
    upsert_action_with_schema(
        &engine,
        FEED,
        "read",
        &schema_hash(),
        "active",
        json!({"type": "object", "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"}
        }}),
    );
    let id = engine
        .store()
        .subscribe_with_cursor_state(
            PRINCIPAL,
            CONNECTION,
            FEED,
            30,
            &json!({"sync_token": "tok-1"}),
            &json!({"owner": "cortexkit", "repo": "plexus"}),
        )
        .expect("subscribe store")
        .expect("subscription accepted")
        .subscription_id;
    assert_eq!(
        poller.poll_once(PRINCIPAL, &id),
        PollCycle::Suspended {
            reason: "argument_undeclared".to_string()
        }
    );
    assert!(engine.transport().requests().is_empty());
    let audit = engine.store().list_audit(PRINCIPAL).expect("read audit");
    assert!(
        audit
            .iter()
            .any(|row| row.reason_code == "argument_undeclared"
                && row.decision == "deny"
                && row.gate.as_deref() == Some("catalog")),
        "{audit:?}"
    );
    let _ = std::fs::remove_file(path);
}
