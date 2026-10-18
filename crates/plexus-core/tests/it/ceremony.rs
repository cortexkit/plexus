//! The authority chain: manifest bounds the ticket, ticket bounds the
//! connection, connection bounds every grant. Each test here fails if its link
//! stops narrowing.

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    ingest_value, Ceiling, CeremonyRefusal, GrantMintRequest, PlexusStore, PolicyInput, Risk,
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
    let path = Scratch::database(&format!("ceremony-{label}"));
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

/// A vendor declaring one read action and one write action.
fn vendor_manifest(actions: Value) -> Value {
    json!({
        "schema_version": 1,
        "key": "mock",
        "name": "Mock",
        "description": "ceremony test vendor",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "tests",
        "tier": "S2",
        "transport": { "kind": "mcp_remote", "url": "https://example.invalid/mcp" },
        "auth": { "mode": "api_key" },
        "credential_bindings": [{
            "ref_role": "api_key",
            "placement": "header",
            "key": "Authorization",
            "prefix": "Bearer ",
            "required": true
        }],
        "resource_filters": { "required": [], "optional": [], "write_enabling": [] },
        "actions_baseline": actions,
        "defaults": {
            "ask_first_risk": ["write"],
            "rate_limit": { "calls_per_min": 30 }
        },
        "availability": "ga"
    })
}

fn install_manifest(store: &PlexusStore, actions: Value) {
    let ingested = ingest_value(vendor_manifest(actions)).expect("manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &ingested)
        .expect("store manifest");
}

/// RESTORING a manifest file un-retires it, which is the inverse of the
/// retirement sweep and lives under a name nobody would look for.
///
/// There is no `unretire_manifest`. The reactivation is one line inside the
/// upsert's `ON CONFLICT DO UPDATE SET` clause — `status = 'active'` — so it is
/// filed under INGEST rather than repair, and a reader counting inverses would
/// not find it. That is the category whose absence misleads rather than blocks:
/// the reader concludes retirement is terminal and reaches for something heavier.
///
/// WHY THE UNTESTED VERSION WOULD HAVE BEEN CONFUSING RATHER THAN OBVIOUS: a
/// manifest deleted by an interrupted sync and then restored would stay retired
/// while its file sits correctly on disk. The connector vanishes from the
/// connectable list and refuses tickets with `app_retired`, so the operator sees
/// a present, valid manifest and a system insisting it was withdrawn. Nothing in
/// that picture points at a single line in an upsert.
///
/// The retirement direction has two tests and neither re-ingests, so dropping
/// that line left the suite green.
///
/// Mutation-proved: removing `status = 'active'` from the upsert's conflict
/// clause fails this on the retired assertion, while the retirement test above
/// stays green.
#[test]
fn restoring_a_manifest_file_un_retires_it() {
    let (store, path) = test_store("manifest-restoration");
    install_manifest(&store, json!([{ "name": "read_item", "risk": "read" }]));

    store
        .retire_absent_manifests(
            plexus_core::CATALOG_PRINCIPAL,
            &["something-else".to_string()],
        )
        .expect("retire absent manifests");
    assert!(
        store.manifest_is_retired("mock").expect("retired query"),
        "the fixture must reach the retired state, or restoration proves nothing"
    );

    // What the next boot does when the file is back: ingest upserts it exactly as
    // it would any other reviewed manifest.
    install_manifest(&store, json!([{ "name": "read_item", "risk": "read" }]));

    assert!(
        !store.manifest_is_retired("mock").expect("retired query"),
        "a restored catalog file must make its vendor connectable again, or a \
         deleted-then-restored manifest is permanently dead with its file \
         sitting valid on disk"
    );
    store
        .ceiling_within_manifest("mock", "read", &["read_item".to_string()])
        .expect("ceiling query")
        .expect("a restored vendor must be ticketable again");

    let _ = std::fs::remove_file(path);
}

/// A manifest withdrawn from the catalog directory is retired, disappears from
/// the connectable list, and cannot be ticketed — while a manifest still present
/// is untouched.
///
/// Ingestion is file-driven and additive: it upserts what the directory holds
/// and never consults the store. So before the retirement pass, deleting a
/// manifest left it stored, listed and connectable indefinitely. That matters
/// more than a stale row because withdrawing a manifest IS the response to
/// finding a vendor surface ungovernable, so a retirement with no effect defeats
/// the remedy.
///
/// Both directions are asserted because the sweep must be selective: retiring
/// everything would be as wrong as retiring nothing, and a test that only
/// checks the withdrawn vendor cannot tell those apart.
///
/// Mutation-proved: dropping the `status = 'active'` predicate from
/// `list_manifest_summaries` fails the listing assertion; dropping the retired
/// check in `ceiling_within_manifest` fails the ticket assertion.
#[test]
fn a_manifest_absent_from_the_catalog_is_retired_and_cannot_be_ticketed() {
    let (store, path) = test_store("manifest-retirement");
    install_manifest(&store, json!([{ "name": "read_item", "risk": "read" }]));
    let public = ingest_value(credential_free_manifest()).expect("manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &public)
        .expect("store second manifest");

    // The reviewed set now holds only `public`: `mock` is what a deleted file
    // looks like to the boot pass.
    let retired = store
        .retire_absent_manifests(plexus_core::CATALOG_PRINCIPAL, &["public".to_string()])
        .expect("retire absent manifests");
    assert_eq!(retired, vec!["mock".to_string()]);

    let listed: Vec<String> = store
        .list_manifest_summaries("direct")
        .expect("list manifests")
        .into_iter()
        .map(|summary| summary.key)
        .collect();
    assert_eq!(
        listed,
        vec!["public".to_string()],
        "a retired vendor must not be offered as connectable"
    );

    let refusal = store
        .ceiling_within_manifest("mock", "read", &["read_item".to_string()])
        .expect("ceiling query")
        .expect_err("a retired vendor must not be ticketable");
    assert!(
        matches!(refusal, CeremonyRefusal::RetiredApp(ref key) if key == "mock"),
        "the refusal must name retirement rather than an unknown key: {refusal:?}"
    );

    // The surviving vendor is still fully usable, so the sweep narrowed rather
    // than emptied.
    store
        .ceiling_within_manifest("public", "read", &["ask_question".to_string()])
        .expect("ceiling query")
        .expect("the surviving vendor must still be ticketable");

    let _ = std::fs::remove_file(path);
}

/// An empty reviewed set retires nothing.
///
/// The sweep runs at boot, before anything is served, so a mis-set
/// `PLEXUS_CATALOG_DIR` or a half-finished sync would otherwise retire every
/// vendor in the store from one bad path. An empty directory is far more often a
/// broken sync than a deliberate withdrawal of the entire catalog, and the same
/// reasoning already guards `reconcile_actions` against an empty vendor
/// discovery.
///
/// Mutation-proved: removing the empty-set early return retires both manifests
/// and fails this.
#[test]
fn an_empty_reviewed_set_retires_nothing() {
    let (store, path) = test_store("manifest-retirement-empty");
    install_manifest(&store, json!([{ "name": "read_item", "risk": "read" }]));
    let public = ingest_value(credential_free_manifest()).expect("manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &public)
        .expect("store second manifest");

    let retired = store
        .retire_absent_manifests(plexus_core::CATALOG_PRINCIPAL, &[])
        .expect("retire absent manifests");
    assert!(
        retired.is_empty(),
        "an empty catalog reading must retire nothing: {retired:?}"
    );
    assert_eq!(
        store
            .list_manifest_summaries("direct")
            .expect("list manifests")
            .len(),
        2,
        "both vendors must survive an unbelievable observation"
    );

    let _ = std::fs::remove_file(path);
}

/// A vendor that needs no credential at all (a public, unauthenticated MCP
/// server such as DeepWiki).
fn credential_free_manifest() -> Value {
    json!({
        "schema_version": 1,
        "key": "public",
        "name": "Public",
        "description": "credential-free test vendor",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "tests",
        "tier": "S1",
        "transport": { "kind": "mcp_remote", "url": "https://example.invalid/mcp" },
        "auth": { "mode": "none" },
        "credential_bindings": [],
        "resource_filters": { "required": [], "optional": [], "write_enabling": [] },
        "actions_baseline": [{ "name": "ask_question", "risk": "read" }],
        "defaults": {
            "ask_first_risk": ["write"],
            "rate_limit": { "calls_per_min": 30 }
        },
        "availability": "ga"
    })
}

fn two_action_manifest() -> Value {
    json!([
        { "name": "search", "risk": "read" },
        { "name": "write_item", "risk": "write" }
    ])
}

/// Enroll a connection through the real ceremony path and return its id.
fn enroll(store: &PlexusStore, risk: &str, selectors: &[&str]) -> String {
    let requested: Vec<String> = selectors.iter().map(|value| value.to_string()).collect();
    let ceiling = store
        .ceiling_within_manifest("mock", risk, &requested)
        .expect("ceiling resolves")
        .expect("ceiling within manifest");
    let connection_id = "conn-mock".to_string();
    store
        .create_connection("direct", &connection_id, "mock")
        .expect("create connection");
    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            &connection_id,
            "credential_reference",
            b"test:ceremony",
            &ceiling,
        )
        .expect("issue ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume ticket")
        .expect("connection activates");
    connection_id
}

/// `connect` IS the inverse of `pending`, pinned rather than asserted in prose.
///
/// `pending` has no `clear_connection_pending`, and a reader counting the
/// inverses beside `clear_connection_degraded` and
/// `clear_connection_auth_required` could read that gap as an oversight. It is
/// not: the inverse exists under a name filed under ENROLMENT rather than
/// repair, which is the category that misleads rather than blocks — the reader
/// is not stopped, they are pointed at a more expensive path.
///
/// A comment claiming a transition exists is worth less than a test that fails
/// if the transition stops existing. Eight tests already call
/// `connect_with_ticket` and none asserted the status moved, so the claim was
/// true and unfenced: `create_connection` could start writing `active` and every
/// one of them would stay green while the note silently became wrong.
#[test]
fn connect_is_the_inverse_of_pending() {
    let (store, path) = test_store("pending-inverse");
    install_manifest(&store, two_action_manifest());

    let ceiling = store
        .ceiling_within_manifest("mock", "read", &["search".to_string()])
        .expect("ceiling resolves")
        .expect("ceiling within manifest");
    store
        .create_connection("direct", "conn-pending", "mock")
        .expect("create connection");

    // The precondition is half the point: if a connection is not born pending,
    // the transition this test names does not exist to be the inverse of.
    assert_eq!(
        store
            .connection("direct", "conn-pending")
            .expect("read connection")
            .expect("record")
            .status,
        "pending",
        "a connection must start pending for connect to be its inverse"
    );

    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            "conn-pending",
            "credential_reference",
            b"test:ceremony",
            &ceiling,
        )
        .expect("issue ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume ticket")
        .expect("connection activates");

    assert_eq!(
        store
            .connection("direct", "conn-pending")
            .expect("read connection")
            .expect("record")
            .status,
        "active",
        "connect must complete a pending connection, which is why no separate \
         clear_connection_pending exists"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn ticket_ceiling_is_copied_onto_the_connection_when_consumed() {
    let (store, path) = test_store("ticket-ceiling-copy");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "read", &["search"]);
    let ceiling = store
        .connection_ceiling("direct", &connection)
        .expect("read ceiling")
        .expect("ceiling present");
    assert_eq!(
        ceiling,
        Ceiling {
            risk: Risk::Read,
            action_selectors: vec!["search".to_string()]
        },
        "consuming a ticket must record its ceiling on the connection"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn manifest_refuses_a_ticket_for_an_undeclared_action() {
    let (store, path) = test_store("ticket-undeclared");
    install_manifest(&store, two_action_manifest());
    let refusal = store
        .ceiling_within_manifest("mock", "read", &["not_a_vendor_action".to_string()])
        .expect("call succeeds")
        .expect_err("undeclared action must be refused");
    assert_eq!(
        refusal,
        CeremonyRefusal::UndeclaredAction("not_a_vendor_action".to_string())
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn manifest_refuses_a_ticket_risk_above_what_the_vendor_declares() {
    let (store, path) = test_store("ticket-risk");
    // A read-only vendor: nothing it declares can justify write authority.
    install_manifest(&store, json!([{ "name": "search", "risk": "read" }]));
    let refusal = store
        .ceiling_within_manifest("mock", "write", &["search".to_string()])
        .expect("call succeeds")
        .expect_err("risk above the vendor's own actions must be refused");
    assert!(matches!(refusal, CeremonyRefusal::RiskAboveCeiling { .. }));
    let _ = std::fs::remove_file(path);
}

/// Policy visibility includes the vendor a row belongs to and one store-derived
/// state, so clients cannot disagree about whether an expiring policy is live.
#[test]
fn policies_list_with_vendor_and_derived_state() {
    let (store, path) = test_store("list-policies");
    store
        .insert_connection("direct", "conn-mock", "mock", "active", &json!({}))
        .expect("create connection");
    let now = plexus_core::now_ms();
    for (policy_id, action_selector, effect, expires_at) in [
        ("until", "read_item", "allow", None),
        ("live", "write_item", "ask_first", Some(now + 60_000)),
        ("expired", "delete_item", "block", Some(1)),
    ] {
        store
            .insert_policy(&PolicyInput {
                policy_id: policy_id.to_string(),
                principal: "direct".to_string(),
                connection_id: "conn-mock".to_string(),
                action_selector: action_selector.to_string(),
                effect: effect.to_string(),
                expires_at,
            })
            .expect("insert policy");
    }

    let policies = store
        .list_policies("direct", Some("conn-mock"))
        .expect("list policies");
    assert_eq!(policies.len(), 3);
    for (policy_id, effect, state) in [
        ("until", "allow", "until_revoked"),
        ("live", "ask_first", "live"),
        ("expired", "block", "expired"),
    ] {
        let policy = policies
            .iter()
            .find(|policy| policy.policy_id == policy_id)
            .unwrap_or_else(|| panic!("{policy_id} must be listed"));
        assert_eq!(policy.connection_id, "conn-mock");
        assert_eq!(policy.app_key.as_deref(), Some("mock"));
        assert_eq!(policy.effect, effect);
        assert_eq!(policy.state, state);
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn grant_exceeding_the_connection_ceiling_is_refused_and_writes_nothing() {
    let (store, path) = test_store("grant-over-ceiling");
    install_manifest(&store, two_action_manifest());
    // Enrolled for reads only, so a write grant must not be mintable even though
    // the vendor itself declares a write action.
    let connection = enroll(&store, "read", &["search"]);
    let refusal = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "write",
            requested_selectors: &["search".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect_err("write grant above a read ceiling must be refused");
    assert!(matches!(refusal, CeremonyRefusal::RiskAboveCeiling { .. }));
    // The refusal must leave no authority behind.
    assert!(
        store
            .list_grants("direct", &connection)
            .expect("query grants")
            .is_empty(),
        "a refused mint must not write a grant row"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn grant_naming_an_action_outside_the_connection_ceiling_is_refused() {
    let (store, path) = test_store("grant-outside-selectors");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "write", &["search"]);
    let refusal = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "write",
            requested_selectors: &["write_item".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect_err("action outside the connection ceiling must be refused");
    // The action IS declared by the vendor -- the manifest holds both actions --
    // so this must not report it as undeclared. The two refusals have different
    // remedies: an undeclared action is a manifest edit, while a ceiling breach
    // cannot be repaired on this connection at all, because its ceiling is
    // permanent from ticket issuance.
    assert_eq!(
        refusal,
        CeremonyRefusal::OutsideConnectionCeiling {
            action: "write_item".to_string(),
            ceiling: vec!["search".to_string()],
        }
    );
    // The message must name the ceiling, since an operator cannot widen it and
    // needs to know the bound before deciding whether to re-enroll.
    let rendered = refusal.to_string();
    assert!(
        rendered.contains("search") && !rendered.contains("not declared"),
        "the message must name the ceiling and must not claim the vendor lacks \
         the action: {rendered}"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn grant_within_the_connection_ceiling_is_minted() {
    let (store, path) = test_store("grant-within");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "write", &["search", "write_item"]);
    let grant = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["search".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect("a narrowing grant must be minted");
    assert_eq!(grant.risk_ceiling, "read");
    assert_eq!(grant.action_selectors, vec!["search".to_string()]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_connection_without_a_recorded_ceiling_refuses_every_mint() {
    let (store, path) = test_store("grant-no-ceiling");
    install_manifest(&store, two_action_manifest());
    // insert_connection is the pre-ceiling path: it records no ceiling, exactly
    // like a connection created before the ceiling columns existed. Fail closed.
    store
        .insert_connection("direct", "legacy", "mock", "active", &json!({}))
        .expect("insert legacy connection");
    let refusal = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: "legacy",
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["search".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect_err("a ceiling-less connection must refuse mints");
    assert_eq!(refusal, CeremonyRefusal::CeilingAbsent);
    let _ = std::fs::remove_file(path);
}

#[test]
fn wildcard_selectors_are_stored_expanded_so_manifest_growth_cannot_widen_authority() {
    let (store, path) = test_store("wildcard-pinned");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "write", &["*"]);
    let before = store
        .connection_ceiling("direct", &connection)
        .expect("read ceiling")
        .expect("ceiling present");
    assert_eq!(
        before.action_selectors,
        vec!["search".to_string(), "write_item".to_string()],
        "a wildcard must be stored as the concrete action list"
    );

    // The vendor gains a destructive action after enrollment. The connection's
    // authority must not grow with it.
    install_manifest(
        &store,
        json!([
            { "name": "search", "risk": "read" },
            { "name": "write_item", "risk": "write" },
            { "name": "delete_everything", "risk": "destructive" }
        ]),
    );
    let after = store
        .connection_ceiling("direct", &connection)
        .expect("read ceiling")
        .expect("ceiling present");
    assert_eq!(
        after, before,
        "a manifest gaining actions must not widen an existing ceiling"
    );
    let refusal = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "destructive",
            requested_selectors: &["delete_everything".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect_err("the new vendor action must not be grantable");
    assert!(matches!(
        refusal,
        CeremonyRefusal::RiskAboveCeiling { .. } | CeremonyRefusal::UndeclaredAction(_)
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn revoking_a_grant_is_idempotent() {
    let (store, path) = test_store("revoke-idempotent");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "read", &["search"]);
    let grant = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["search".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect("grant minted");
    assert!(store
        .revoke_grant("direct", &grant.grant_id)
        .expect("first revoke"));
    assert!(
        !store
            .revoke_grant("direct", &grant.grant_id)
            .expect("second revoke must not error"),
        "a retried revoke reports absence rather than failing"
    );
    let _ = std::fs::remove_file(path);
}

/// A vendor declaring `auth.mode = none` enrolls with no handle at all, and the
/// resulting connection still carries a ceiling. Before this was supported the
/// connect path demanded a credential unconditionally, so such a vendor could
/// be listed in the catalog and never connected.
#[test]
fn a_credential_free_vendor_enrolls_without_a_handle() {
    let (store, path) = test_store("ceremony-no-auth");
    let ingested = ingest_value(credential_free_manifest()).expect("manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &ingested)
        .expect("store manifest");
    assert!(store
        .manifest_requires_no_credential("public")
        .expect("read manifest"));

    store
        .create_connection("direct", "conn-public", "public")
        .expect("create connection");
    let ceiling = Ceiling {
        risk: Risk::Read,
        action_selectors: vec!["ask_question".to_string()],
    };
    let ticket = store
        .create_binding_ticket_bounded(
            "direct",
            "conn-public",
            plexus_core::NO_CREDENTIAL_REF_ROLE,
            &[],
            &ceiling,
        )
        .expect("issue credential-free ticket");
    let connection = store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume ticket")
        .expect("connection activates without a credential binding");
    assert_eq!(connection.status, "active");

    // The narrowing chain still applies: an unauthenticated vendor is not an
    // unbounded one.
    let stored = store
        .connection_ceiling("direct", "conn-public")
        .expect("read ceiling")
        .expect("ceiling recorded");
    assert_eq!(stored.action_selectors, vec!["ask_question".to_string()]);
    assert_eq!(stored.risk, Risk::Read);
    let _ = std::fs::remove_file(path);
}

/// The credential-free path must be reachable ONLY through the manifest. A
/// handle-less enrollment against a vendor that declares an auth mode would be
/// a way to create a connection with no credential custody at all.
#[test]
fn a_credentialed_vendor_refuses_a_handle_less_enrollment() {
    let (store, path) = test_store("ceremony-no-auth-guard");
    install_manifest(&store, two_action_manifest());
    assert!(!store
        .manifest_requires_no_credential("mock")
        .expect("read manifest"));

    store
        .create_connection("direct", "conn-1", "mock")
        .expect("create connection");
    let ceiling = Ceiling {
        risk: Risk::Read,
        action_selectors: vec!["search".to_string()],
    };
    // Empty handle with a credentialed ref_role, and a real handle with the
    // credential-free ref_role, are both incoherent and must be refused rather
    // than silently producing a connection that cannot authenticate.
    assert!(store
        .create_binding_ticket_bounded("direct", "conn-1", "credential_reference", &[], &ceiling)
        .is_err());
    assert!(store
        .create_binding_ticket_bounded(
            "direct",
            "conn-1",
            plexus_core::NO_CREDENTIAL_REF_ROLE,
            b"ckh_real_handle",
            &ceiling,
        )
        .is_err());
    let _ = std::fs::remove_file(path);
}

/// An action the vendor exposes but the reviewed manifest never declared must
/// not become callable. Before this, `reconcile` defaulted such an action to
/// `read` and stored it ACTIVE, which meant a vendor could add a tool and have
/// it immediately invocable with no ask-first, no decision plane, and no
/// write-enabling filter check — the three controls that exist to catch exactly
/// this. The test fails if an undeclared action is active or classified read.
#[test]
fn an_undeclared_discovered_action_is_quarantined_not_activated() {
    use plexus_core::{
        CatalogReconciler, CatalogRefreshPolicy, DiscoveredAction, McpConnection, McpRemoteConfig,
        McpRemoteTransport,
    };
    use std::sync::Arc;

    let (store, path) = test_store("reconcile-undeclared");
    install_manifest(&store, two_action_manifest());
    let store = Arc::new(store);
    store
        .create_connection("direct", "conn-1", "mock")
        .expect("create connection");

    let reconciler = CatalogReconciler::new(
        Arc::clone(&store),
        Arc::new(McpRemoteTransport::default()),
        CatalogRefreshPolicy::default(),
    );
    let manifest: plexus_core::AppManifest =
        serde_json::from_value(vendor_manifest(two_action_manifest())).expect("manifest parses");
    let connection = McpConnection {
        connection_id: "conn-1".to_string(),
        config: McpRemoteConfig::new("https://example.invalid/mcp".to_string()),
    };

    // The vendor reports its two declared actions PLUS one the manifest has
    // never seen — the shape of a vendor adding a tool between reviews.
    let discovered = vec![
        DiscoveredAction {
            name: "search".to_string(),
            title: None,
            description: None,
            annotations: None,
            input_schema: json!({"type": "object"}),
        },
        DiscoveredAction {
            name: "delete_everything".to_string(),
            title: None,
            description: None,
            annotations: None,
            input_schema: json!({"type": "object"}),
        },
    ];
    reconciler
        .reconcile("direct", &connection, &manifest, &discovered)
        .expect("reconcile");

    let declared = store
        .catalog_action("direct", "conn-1", "search")
        .expect("read declared action")
        .expect("declared action stored");
    assert_eq!(declared.status, "active", "a declared action stays usable");
    assert_eq!(declared.risk, "read");

    let undeclared = store
        .catalog_action("direct", "conn-1", "delete_everything")
        .expect("read undeclared action")
        .expect("undeclared action stored");
    assert_eq!(
        undeclared.status, "quarantined",
        "an undeclared action must never be active"
    );
    assert_eq!(
        undeclared.quarantine_reason.as_deref(),
        Some("undeclared_requires_review")
    );
    assert_ne!(
        undeclared.risk, "read",
        "an undeclared action must not be classified read: that would skip \
         ask-first, the decision plane, and write-enabling filters"
    );

    // And it must not appear in the projection agents select actions from.
    let visible = store
        .list_catalog_actions("direct", "conn-1")
        .expect("list active actions");
    assert!(
        !visible
            .iter()
            .any(|action| action.name == "delete_everything"),
        "a quarantined action must be invisible to catalog consumers"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn mint_refuses_empty_action_selectors_and_writes_nothing() {
    let (store, path) = test_store("grant-empty-selectors");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "read", &["search"]);
    let refusal = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &[],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect_err("empty actions must be refused");
    assert_eq!(refusal, CeremonyRefusal::EmptyActionSelectors);
    assert!(store
        .list_grants("direct", &connection)
        .expect("list grants")
        .is_empty());
    let _ = std::fs::remove_file(path);
}

#[test]
fn mint_expands_a_wildcard_to_the_connection_ceiling() {
    let (store, path) = test_store("grant-wildcard-expansion");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "read", &["search"]);
    let grant = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["*".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect("wildcard within a nonempty ceiling must mint");
    assert_eq!(grant.action_selectors, vec!["search".to_string()]);
    assert_eq!(
        store
            .list_grants("direct", &connection)
            .expect("list grants")[0]
            .action_selectors,
        vec!["search".to_string()]
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn mint_refuses_a_wildcard_expanding_to_no_actions() {
    let (store, path) = test_store("grant-empty-expansion");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "read", &[]);
    let refusal = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["*".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect_err("an empty wildcard expansion must be refused");
    assert_eq!(refusal, CeremonyRefusal::EmptyActionSelectors);
    let _ = std::fs::remove_file(path);
}

fn ceiling(store: &PlexusStore, risk: &str, selectors: &[&str]) -> Ceiling {
    let requested: Vec<String> = selectors.iter().map(|value| value.to_string()).collect();
    store
        .ceiling_within_manifest("mock", risk, &requested)
        .expect("ceiling resolves")
        .expect("ceiling within manifest")
}

fn issue(
    store: &PlexusStore,
    connection_id: &str,
    app_key: &str,
    ceiling: &Ceiling,
) -> Result<plexus_core::BindingTicket, CeremonyRefusal> {
    store
        .issue_binding_ticket(
            "direct",
            connection_id,
            app_key,
            "credential_reference",
            b"test:ceremony",
            ceiling,
        )
        .expect("ticket issue reaches the store")
}

fn status_of(store: &PlexusStore, connection_id: &str) -> String {
    store
        .connection("direct", connection_id)
        .expect("read connection")
        .expect("connection exists")
        .status
}

/// Revocation is final: a ticket issued before the revoke expires with it, a
/// new ticket is refused by name, and even a ticket that is somehow still
/// marked issued cannot activate the revoked row.
#[test]
fn a_revoked_connection_stays_revoked_when_a_ticket_is_used() {
    let (store, path) = test_store("ticket-revoked");
    install_manifest(&store, two_action_manifest());
    let read = ceiling(&store, "read", &["search"]);
    let first = issue(&store, "conn-a", "mock", &read).expect("first ticket");
    let outstanding = issue(&store, "conn-a", "mock", &read).expect("second ticket while pending");
    store
        .connect_with_ticket("direct", &first.ticket_id)
        .expect("consume")
        .expect("activates");
    // Live re-enrollment used to replace credentials before ticket consumption.
    // Existing connections now rotate credentials through rebind-credential.
    assert_eq!(
        issue(&store, "conn-a", "mock", &read),
        Err(CeremonyRefusal::ConnectionExists)
    );

    assert!(store.revoke_connection("direct", "conn-a").expect("revoke"));
    assert_eq!(
        store
            .issue_binding_ticket(
                "direct",
                "conn-a",
                "mock",
                "credential_reference",
                b"test:ceremony",
                &read
            )
            .expect("store call"),
        Err(CeremonyRefusal::ConnectionRevoked)
    );
    assert_eq!(
        store
            .connect_with_ticket("direct", &outstanding.ticket_id)
            .expect("consume after revoke"),
        None,
        "revoking must expire the outstanding ticket"
    );
    assert_eq!(status_of(&store, "conn-a"), "revoked");

    // Even a ticket left marked issued (written by an older binary, say)
    // must not bring the revoked connection back.
    rusqlite::Connection::open(path.path())
        .unwrap()
        .execute(
            "UPDATE binding_tickets SET status = 'issued' WHERE ticket_id = ?1",
            [&outstanding.ticket_id],
        )
        .expect("re-mark the ticket");
    assert_eq!(
        store
            .connect_with_ticket("direct", &outstanding.ticket_id)
            .expect("consume"),
        None,
        "a ticket still marked issued must not activate a revoked connection"
    );
    assert_eq!(status_of(&store, "conn-a"), "revoked");
    let _ = std::fs::remove_file(path);
}

/// Revoking a connection expires every ticket still issued for it.
#[test]
fn revoking_a_connection_expires_its_outstanding_tickets() {
    let (store, path) = test_store("ticket-expiry-on-revoke");
    install_manifest(&store, two_action_manifest());
    let read = ceiling(&store, "read", &["search"]);
    let pending = issue(&store, "conn-a", "mock", &read).expect("ticket");
    assert!(store.revoke_connection("direct", "conn-a").expect("revoke"));
    let status: String = rusqlite::Connection::open(path.path())
        .unwrap()
        .query_row(
            "SELECT status FROM binding_tickets WHERE ticket_id = ?1",
            [&pending.ticket_id],
            |row| row.get(0),
        )
        .expect("ticket status");
    assert_eq!(
        status, "expired",
        "revoking a connection must expire its issued tickets"
    );
    let _ = std::fs::remove_file(path);
}

/// A ticket for app B naming an existing connection of app A is refused and
/// changes nothing on A, because its ceiling was resolved against B's manifest.
#[test]
fn a_ticket_for_another_app_is_refused_against_an_existing_connection_id() {
    let (store, path) = test_store("ticket-app-mismatch");
    install_manifest(&store, two_action_manifest());
    let public = ingest_value(credential_free_manifest()).expect("manifest ingests");
    store
        .upsert_manifest(plexus_core::CATALOG_PRINCIPAL, &public)
        .expect("store second manifest");
    let read = ceiling(&store, "read", &["search"]);
    let ticket = issue(&store, "conn-a", "mock", &read).expect("ticket");
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .expect("consume")
        .expect("activates");
    let before = store.connection("direct", "conn-a").unwrap().unwrap();
    let public_ceiling = store
        .ceiling_within_manifest("public", "read", &["ask_question".to_string()])
        .unwrap()
        .unwrap();
    let refusal = store
        .issue_binding_ticket(
            "direct",
            "conn-a",
            "public",
            plexus_core::NO_CREDENTIAL_REF_ROLE,
            &[],
            &public_ceiling,
        )
        .expect("store call")
        .expect_err("another app's ticket must be refused");
    assert_eq!(
        refusal,
        CeremonyRefusal::ConnectionAppMismatch {
            connection_app: "mock".into(),
            requested_app: "public".into(),
        },
        "the refusal must name the app mismatch"
    );
    assert_eq!(
        store.connection("direct", "conn-a").unwrap().unwrap(),
        before
    );
    assert_eq!(
        store
            .connection_ceiling("direct", "conn-a")
            .unwrap()
            .unwrap(),
        read
    );
    let _ = std::fs::remove_file(path);
}

/// Re-enrollment used to rewrite a live credential before consumption, even
/// though the connection's ceiling could never widen. Live connections now
/// refuse every re-issue, and tickets issued while pending cannot re-enroll them.
#[test]
fn a_re_issued_ticket_never_widens_the_connection_ceiling() {
    let (store, path) = test_store("ticket-no-widening");
    install_manifest(&store, two_action_manifest());
    let read = ceiling(&store, "read", &["search"]);
    let write = ceiling(&store, "write", &["search", "write_item"]);
    let first = issue(&store, "conn-a", "mock", &read).unwrap();
    let early_wide = issue(&store, "conn-a", "mock", &write).unwrap();
    store
        .connect_with_ticket("direct", &first.ticket_id)
        .unwrap()
        .unwrap();
    let before = store.connection("direct", "conn-a").unwrap().unwrap();
    for ceiling in [&read, &write] {
        assert_eq!(
            issue(&store, "conn-a", "mock", ceiling),
            Err(CeremonyRefusal::ConnectionExists),
            "a live connection must refuse re-issue, including an equal ceiling"
        );
    }
    assert!(
        store
            .connect_with_ticket("direct", &early_wide.ticket_id)
            .unwrap()
            .is_none(),
        "a ticket issued while pending must not re-enroll a now-live connection"
    );
    assert_eq!(
        store.connection("direct", "conn-a").unwrap().unwrap(),
        before
    );
    assert_eq!(
        store
            .connection_ceiling("direct", "conn-a")
            .unwrap()
            .unwrap(),
        read
    );
    let _ = std::fs::remove_file(path);
}

/// The grant record a mint returns carries the generation it stored, so a
/// caller comparing generations later is not off by one from the start.
#[test]
fn a_minted_grant_reports_the_generation_it_stored() {
    let (store, path) = test_store("grant-generation");
    install_manifest(&store, two_action_manifest());
    let connection = enroll(&store, "read", &["search"]);
    let minted = store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "direct",
            connection_id: &connection,
            grantee_principal: "direct",
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["search".to_string()],
            expires_at: None,
        })
        .expect("call succeeds")
        .expect("grant within the ceiling");
    let stored = store
        .list_grants("direct", &connection)
        .expect("list grants")
        .into_iter()
        .find(|grant| grant.grant_id == minted.grant_id)
        .expect("the minted grant is stored");
    assert_eq!(minted.generation, stored.generation);
    let _ = std::fs::remove_file(path);
}

/// A vendor's connection count covers connections that can still serve; a
/// revoked one, which never becomes active again, is not counted.
#[test]
fn the_vendor_connection_count_leaves_out_revoked_connections() {
    let (store, path) = test_store("connection-count");
    install_manifest(&store, two_action_manifest());
    let count = |store: &PlexusStore| {
        store
            .list_manifest_summaries("direct")
            .expect("list manifests")
            .into_iter()
            .find(|summary| summary.key == "mock")
            .expect("mock is listed")
            .connection_count
    };
    let connection = enroll(&store, "read", &["search"]);
    assert_eq!(count(&store), 1);
    assert!(store.revoke_connection("direct", &connection).unwrap());
    assert_eq!(count(&store), 0, "a revoked connection must not be counted");
    let _ = std::fs::remove_file(path);
}
