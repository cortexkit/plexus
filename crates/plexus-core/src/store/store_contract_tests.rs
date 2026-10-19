use super::*;
use crate::test_scratch::Scratch;
use cortexkit_store_types::Isolation;
use serde_json::json;
use std::sync::Arc;

fn store(path: &str) -> PlexusStore {
    PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: new_id("store-contract-tests"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite { path: path.into() },
    })
    .unwrap()
}
fn fixture() -> PlexusStore {
    let store = store(":memory:");
    store
        .insert_connection("owner", "connection", "fixture", "active", &json!({}))
        .unwrap();
    store.inner.with_conn_fenced(|conn| conn.execute_batch("UPDATE connections SET ceiling_risk='write',ceiling_selectors='[\"read\",\"write\"]'")).unwrap();
    store.upsert_catalog_action(&action("read")).unwrap();
    store
}
fn action(name: &str) -> CatalogActionInput {
    let schema = json!({"type":"object","additionalProperties":false});
    CatalogActionInput {
        principal: "owner".into(),
        connection_id: "connection".into(),
        name: name.into(),
        title: None,
        schema_hash: jcs_store_hash(&schema).unwrap(),
        schema,
        risk: "read".into(),
        severity: "S1".into(),
        ask_first: false,
        status: "active".into(),
        quarantine_reason: None,
        reconciliation: None,
    }
}
fn grant(store: &PlexusStore, id: &str, grantee: &str, risk: &str) {
    store
        .insert_grant(&GrantInput {
            grant_id: id.into(),
            principal: "owner".into(),
            connection_id: "connection".into(),
            grantee_principal: grantee.into(),
            risk_ceiling: risk.into(),
            action_selectors: vec!["read".into(), "write".into()],
            authority_kind: "poll".into(),
            expires_at: None,
        })
        .unwrap();
}
fn mint(store: &PlexusStore, grantee: &str) -> Result<GrantRecord, CeremonyRefusal> {
    store
        .mint_grant_bounded(&GrantMintRequest {
            principal: "owner",
            connection_id: "connection",
            grantee_principal: grantee,
            authority_kind: "invoke",
            requested_risk: "read",
            requested_selectors: &["read".into()],
            expires_at: None,
        })
        .unwrap()
}
fn probe(store: &PlexusStore) -> Result<TriggerSubscription, SubscriptionRefusal> {
    store
        .register_probe(
            "caller",
            "connection",
            ProbeRegistration {
                name: "probe",
                actions: &["read".into()],
                script_source: "() => true",
                return_schema: &json!({"kind":"bool"}),
                rearm: "once",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({}),
            },
        )
        .unwrap()
}

#[test]
fn grant_mint_rechecks_revocation_at_insert() {
    let store = Arc::new(fixture());
    let other = store.clone();
    RACE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some((
            "grant_insert",
            Box::new(move || {
                other.revoke_connection("owner", "connection").unwrap();
            }),
        ))
    });
    assert_eq!(
        mint(&store, "caller"),
        Err(CeremonyRefusal::ConnectionRevoked),
        "revocation before grant insert must refuse"
    );
    assert!(store.list_grants("owner", "connection").unwrap().is_empty());
}
#[test]
fn grant_mint_allows_nonrevoked_recovery_states() {
    for status in ["pending", "degraded", "auth_required", "active"] {
        let store = fixture();
        store
            .inner
            .with_conn_fenced(|conn| conn.execute("UPDATE connections SET status=?1", [status]))
            .unwrap();
        assert!(
            mint(&store, "caller").is_ok(),
            "nonrevoked state {status} may receive a grant"
        );
    }
}
#[test]
fn grant_matching_selects_a_sufficient_risk_ceiling() {
    let store = fixture();
    grant(&store, "a-read", "caller", "read");
    grant(&store, "z-write", "caller", "write");
    let select = |risk| {
        store
            .matching_grant(
                "owner",
                "connection",
                "caller",
                "write",
                "poll",
                now_ms(),
                Some(risk),
            )
            .unwrap()
            .unwrap()
            .grant_id
    };
    assert_eq!(
        select("write"),
        "z-write",
        "write selection must skip a read-only grant"
    );
    assert_eq!(select("read"), "a-read");
    assert_eq!(
        select("destructive"),
        "a-read",
        "when no ceiling suffices, preserve the old diagnostic candidate"
    );
    let rows=store.inner.with_read(|conn| {
        let mut query=conn.prepare("SELECT grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation FROM grants ORDER BY grant_id")?;
        let rows=query.query_map([],|row|map_grant_row(row,now_ms()))?.collect::<rusqlite::Result<Vec<_>>>()?;Ok(rows)
    }).unwrap();
    assert_eq!(
        grant_candidate(&rows, "write", now_ms(), Some("write"))
            .unwrap()
            .grant_id,
        "z-write",
        "shared candidate selection must prefer a sufficient ceiling"
    );
}
#[test]
fn wildcard_grantee_never_matches_or_mints() {
    let store = fixture();
    grant(&store, "wild", "*", "write");
    store
        .inner
        .with_conn_fenced(|conn| conn.execute("UPDATE grants SET authority_kind='invoke'", []))
        .unwrap();
    assert!(
        store
            .matching_grant(
                "owner",
                "connection",
                "caller",
                "read",
                "invoke",
                now_ms(),
                None
            )
            .unwrap()
            .is_none(),
        "wildcard grantee must not match ordinary calls"
    );
    let connection = store.connection("owner", "connection").unwrap().unwrap();
    assert!(
        store
            .scoped_invoke_grant_rows(&connection, "caller", None)
            .unwrap()
            .is_empty(),
        "wildcard grantee must not match scoped calls"
    );
    assert_eq!(
        mint(&store, "*"),
        Err(CeremonyRefusal::WildcardGrantee),
        "wildcard grantee must not mint"
    );
}
#[test]
fn probe_registration_enforces_source_byte_limit_before_storage() {
    let store = fixture();
    grant(&store, "poll", "caller", "read");
    let register = |source: &str| {
        store
            .register_probe(
                "caller",
                "connection",
                ProbeRegistration {
                    name: "bounded",
                    actions: &["read".into()],
                    script_source: source,
                    return_schema: &json!({"kind":"bool"}),
                    rearm: "once",
                    cadence_s: 30,
                    fixed_args: &json!({}),
                    cursor_state: &json!({}),
                },
            )
            .unwrap()
    };
    let at_limit = "é".repeat(plexus_probe::MAX_SOURCE_BYTES / 2);
    assert_eq!(at_limit.len(), plexus_probe::MAX_SOURCE_BYTES);
    assert_eq!(
        register(&format!("{at_limit}é")),
        Err(SubscriptionRefusal::ProbeSourceTooLarge)
    );
    assert!(store
        .list_subscriptions("owner", None, None)
        .unwrap()
        .is_empty());
    assert!(
        register(&at_limit).is_ok(),
        "the byte limit itself remains admissible"
    );
}

#[test]
fn probe_registration_rechecks_revocation_at_insert() {
    let store = Arc::new(fixture());
    grant(&store, "poll", "caller", "read");
    let other = store.clone();
    RACE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some((
            "probe_insert",
            Box::new(move || {
                other.revoke_grant("owner", "poll").unwrap();
            }),
        ))
    });
    assert_eq!(
        probe(&store),
        Err(SubscriptionRefusal::PollGrantRequired),
        "probe insert must recheck poll authority"
    );
    assert!(store
        .list_subscriptions("owner", None, None)
        .unwrap()
        .is_empty());
}
#[test]
fn ticket_issue_and_old_ticket_consumption_preserve_live_connection() {
    let store = fixture();
    let before = store.connection("owner", "connection").unwrap().unwrap();
    let ceiling = Ceiling {
        risk: Risk::Read,
        action_selectors: vec!["read".into()],
    };
    assert_eq!(
        store
            .issue_binding_ticket(
                "owner",
                "connection",
                "fixture",
                "credential_reference",
                b"new:credential",
                &ceiling
            )
            .unwrap(),
        Err(CeremonyRefusal::ConnectionExists),
        "live connection must refuse ticket issuance"
    );
    assert_eq!(
        store.connection("owner", "connection").unwrap().unwrap(),
        before
    );
    store.inner.with_conn_fenced(|conn| conn.execute("INSERT INTO binding_tickets(ticket_id,principal,connection_id,ref_role,expires_at,status,created_at_ms,risk_ceiling,action_selectors) VALUES ('old','owner','connection','none',?1,'issued',0,'read','[\"read\"]')",[now_ms()+60000])).unwrap();
    assert!(
        store.connect_with_ticket("owner", "old").unwrap().is_none(),
        "old ticket must not re-enroll live connection"
    );
    assert_eq!(
        store.connection("owner", "connection").unwrap().unwrap(),
        before
    );
    let state: String = store
        .inner
        .with_conn(|conn| {
            conn.query_row(
                "SELECT status FROM binding_tickets WHERE ticket_id='old'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(state, "expired");
}
#[test]
fn catalog_reconciliation_is_atomic_and_disables_missing_rows() {
    let store = fixture();
    store.upsert_catalog_action(&action("removed")).unwrap();
    store.inner.with_conn_fenced(|conn|conn.execute_batch("CREATE TRIGGER reject_bad BEFORE INSERT ON catalog_actions WHEN NEW.name='bad' BEGIN SELECT RAISE(ABORT,'injected catalog failure'); END;")).unwrap();
    let before = store
        .list_catalog_actions_all("owner", "connection")
        .unwrap();
    assert!(store
        .reconcile_catalog_actions("owner", "connection", &[action("new"), action("bad")])
        .is_err());
    assert_eq!(
        store
            .list_catalog_actions_all("owner", "connection")
            .unwrap(),
        before,
        "input N failure must roll back the whole catalog observation"
    );
    assert!(store
        .reconcile_catalog_actions("owner", "connection", &[])
        .is_err());
    store
        .reconcile_catalog_actions("owner", "connection", &[action("read"), action("new")])
        .unwrap();
    assert_eq!(
        store
            .catalog_action("owner", "connection", "removed")
            .unwrap()
            .unwrap()
            .status,
        "disabled"
    );
}

#[test]
#[ignore = "controlled writer-fence contention measurement"]
fn measure_writer_fence_read_contention() {
    let scratch = Scratch::database("storage-read-contention");
    let store = Arc::new(store(&scratch.to_string_lossy()));
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = store.clone();
    let writer = std::thread::spawn(move || {
        writer.inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO connections(connection_id,principal,app_key,status,resource_filters,created_at_ms,updated_at_ms) VALUES ('pending','owner','fixture','pending','{}',0,0)",[])?;
        held_tx.send(()).unwrap();
        release_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        Ok(())
    }).unwrap()
    });
    held_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let read_store = store.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let rows = read_store.list_connections("owner").unwrap();
        done_tx.send((started.elapsed(), rows.len())).unwrap();
    });
    let during = done_rx.recv_timeout(std::time::Duration::from_millis(200));
    release_tx.send(()).unwrap();
    let (elapsed, rows) = during.unwrap_or_else(|_| {
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    });
    writer.join().unwrap();
    reader.join().unwrap();
    println!(
        "writer-fence read wait={}us; rows={rows}; controlled hold=200ms",
        elapsed.as_micros()
    );
}

#[test]
#[ignore = "granted-ack scaling measurement"]
fn measure_granted_ack_scaling() {
    let store = fixture();
    store.inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,generation,created_at_ms) VALUES ('sub','owner','connection','read',30,'ordered_timestamp','{}','{}','hash','active',0,0)",[])?;
        for n in 0..40 {
            conn.execute("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,generation,created_at_ms) VALUES (?1,'owner','connection','caller','read','[\"read\"]','events_consume',1,0)",[format!("g{n}")])?;
        }
        for n in 0..500 {
            conn.execute("INSERT INTO trigger_events(event_id,principal,connection_id,subscription_id,vendor_event_id,payload_hash,payload,kind,observed_at_ms,created_at_ms) VALUES (?1,'owner','connection','sub',?1,?1,'{}','event',0,0)",[format!("e{n}")])?;
        }
        Ok(())
    }).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        store
            .ack_events_including_granted("caller", &["e0".into()], now_ms())
            .unwrap(),
        1
    );
    println!(
        "granted ack: grants=40 events=500 targets=1 elapsed={}us",
        start.elapsed().as_micros()
    );
}

#[test]
#[ignore = "subscription-list scaling measurement"]
fn measure_subscription_listing() {
    let store = fixture();
    grant(&store, "poll", "owner", "read");
    store.inner.with_conn_fenced(|conn| {
        for n in 0..500 {
            conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,generation,created_at_ms) VALUES (?1,'owner','connection','read',30,'ordered_timestamp','{}','{}','hash','active',0,0)",[format!("s{n}")])?;
        }
        Ok(())
    }).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        store.list_subscriptions("owner", None, None).unwrap().len(),
        500
    );
    println!(
        "subscription listing: rows=500 grants=1 elapsed={}us",
        start.elapsed().as_micros()
    );
}

fn watch(store: &PlexusStore, id: &str) {
    let hash = store
        .catalog_action("owner", "connection", "read")
        .unwrap()
        .unwrap()
        .schema_hash;
    store.inner.with_conn_fenced(|conn|conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,generation,created_at_ms,last_success_at_ms) VALUES (?1,'owner','connection','read',30,'ordered_timestamp','{}','{}',?2,'active',0,1,10)",rusqlite::params![id,hash])).unwrap();
}
fn manifest() -> crate::manifest::IngestedManifest {
    crate::manifest::ingest_value(json!({
        "schema_version":1,"key":"fixture","name":"Fixture","description":"Storage regression fixture",
        "reuse_path":"mcp_direct","reuse_rationale":"tests","tier":"S1","availability":"ga",
        "transport":{"kind":"mcp_remote","url":"https://example.invalid/mcp"},"auth":{"mode":"api_key"},
        "credential_bindings":[{"ref_role":"api_key","placement":"header","key":"Authorization","prefix":"Bearer ","required":true}],
        "resource_filters":{"required":[],"optional":[],"write_enabling":[]},
        "actions_baseline":[{"name":"read","risk":"read"},{"name":"write","risk":"write"}],
        "defaults":{"ask_first_risk":["write"],"rate_limit":{"calls_per_min":30}}
    })).unwrap()
}
#[test]
fn retirement_records_one_gap_and_safe_return_does_not_add_another() {
    let store = fixture();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    grant(&store, "poll", "owner", "read");
    watch(&store, "sub");
    store
        .retire_absent_manifests(CATALOG_PRINCIPAL, &["other".into()])
        .unwrap();
    let gaps = store.list_events("owner", None, None).unwrap();
    assert_eq!(gaps.len(), 1, "retirement must record a coverage gap");
    assert_eq!(gaps[0].gap_reason.as_deref(), Some("app_retired"));
    assert_eq!(gaps[0].gap_from_ms, Some(10));
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    assert_eq!(
        store.subscription("owner", "sub").unwrap().unwrap().status,
        "active"
    );
    assert_eq!(store.list_events("owner", None, None).unwrap().len(), 1);
}
#[test]
fn returning_manifest_does_not_revive_a_quarantined_watch() {
    let store = fixture();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    grant(&store, "poll", "owner", "read");
    watch(&store, "sub");
    store
        .retire_absent_manifests(CATALOG_PRINCIPAL, &["other".into()])
        .unwrap();
    store
        .quarantine_action("owner", "connection", "read", "review_required")
        .unwrap();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    assert_eq!(
        store.subscription("owner", "sub").unwrap().unwrap().status,
        "suspended",
        "returning app must not revive an unsafe catalog action"
    );
}
fn admin_store() -> Arc<PlexusStore> {
    let store = fixture();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    store
        .insert_grant(&GrantInput {
            grant_id: "admin".into(),
            principal: "owner".into(),
            connection_id: "connection".into(),
            grantee_principal: "owner".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["*".into()],
            authority_kind: "connection_admin".into(),
            expires_at: None,
        })
        .unwrap();
    Arc::new(store)
}
fn revoke_admin_grant_at(store: &Arc<PlexusStore>, point: &'static str) {
    let other = store.clone();
    RACE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some((
            point,
            Box::new(move || {
                assert!(other.revoke_grant("owner", "admin").unwrap());
            }),
        ))
    });
}
/// An admin grant revoked after configure's first check, while the request
/// is validated, must stop the write: the write's own transaction checks
/// the grant again.
#[test]
fn connection_filter_configure_rechecks_admin_inside_its_transaction() {
    let store = admin_store();
    let before = store.connection("owner", "connection").unwrap().unwrap();
    revoke_admin_grant_at(&store, "connection_admin_configure");
    assert_eq!(
        store
            .configure_connection_filters_if_admin(
                "owner",
                "connection",
                "owner",
                &json!({"write_enabling": [], "values": {}})
            )
            .unwrap(),
        ConfigureOutcome::AdminRequired
    );
    assert_eq!(
        store.connection("owner", "connection").unwrap().unwrap(),
        before,
        "a refused configure must not write"
    );
}
/// The same race for revoke: a grant revoked after the first check leaves
/// the connection live.
#[test]
fn connection_revoke_rechecks_admin_inside_its_transaction() {
    let store = admin_store();
    let before = store.connection("owner", "connection").unwrap().unwrap();
    revoke_admin_grant_at(&store, "connection_admin_revoke");
    assert_eq!(
        store
            .revoke_connection_if_admin("owner", "connection", "owner")
            .unwrap(),
        ConnectionAdminRevokeOutcome::AdminRequired
    );
    assert_eq!(
        store.connection("owner", "connection").unwrap().unwrap(),
        before,
        "a refused revoke must not write"
    );
}
/// Positive and refusal controls for the two admin writes when nothing races.
#[test]
fn connection_admin_writes_apply_only_with_a_live_grant() {
    let store = admin_store();
    assert_eq!(
        store
            .configure_connection_filters_if_admin("owner", "connection", "stranger", &json!({}))
            .unwrap(),
        ConfigureOutcome::AdminRequired,
        "a caller without the grant is refused before validation"
    );
    assert_eq!(
        store
            .revoke_connection_if_admin("owner", "connection", "stranger")
            .unwrap(),
        ConnectionAdminRevokeOutcome::AdminRequired
    );
    assert!(matches!(
        store
            .configure_connection_filters_if_admin(
                "owner",
                "connection",
                "owner",
                &json!({"values": {}})
            )
            .unwrap(),
        ConfigureOutcome::Configured(_)
    ));
    assert_eq!(
        store
            .revoke_connection_if_admin("owner", "connection", "owner")
            .unwrap(),
        ConnectionAdminRevokeOutcome::Revoked
    );
    assert_eq!(
        store.connection("owner", "connection").unwrap().unwrap().status,
        "revoked"
    );
    assert_eq!(
        store
            .revoke_connection_if_admin("owner", "connection", "owner")
            .unwrap(),
        ConnectionAdminRevokeOutcome::ConnectionNotFound,
        "an already revoked connection is not revoked again"
    );
}
fn manifest_change_rows(store: &PlexusStore) -> i64 {
    store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM audit_journal WHERE reason_code='manifest_changed'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap()
}
fn edited_manifest(description: &str) -> crate::manifest::IngestedManifest {
    let mut value = manifest().json;
    value["description"] = json!(description);
    crate::manifest::ingest_value(value).unwrap()
}
/// A manifest change and a retirement each write exactly one audit row, and
/// only when something changed: a first ingest and an identical re-ingest
/// write none.
#[test]
fn manifest_changes_and_retirements_are_audited_once_by_the_store() {
    let store = fixture();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    assert_eq!(manifest_change_rows(&store), 0, "a first ingest is not a change");
    assert!(!store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap()
        .changed);
    assert_eq!(manifest_change_rows(&store), 0, "an identical re-ingest is not a change");
    assert!(store
        .upsert_manifest(CATALOG_PRINCIPAL, &edited_manifest("edited"))
        .unwrap()
        .changed);
    assert_eq!(manifest_change_rows(&store), 1);
    assert_eq!(
        store
            .retire_absent_manifests(CATALOG_PRINCIPAL, &["other".into()])
            .unwrap(),
        vec!["fixture".to_string()]
    );
    assert_eq!(manifest_change_rows(&store), 2, "a retirement is recorded");
    assert!(store
        .retire_absent_manifests(CATALOG_PRINCIPAL, &["other".into()])
        .unwrap()
        .is_empty());
    assert_eq!(manifest_change_rows(&store), 2, "an already retired manifest is not retired again");
}
/// The audit row shares the change's transaction: when the row cannot be
/// written, neither the new manifest content nor the retirement is kept.
#[test]
fn a_refused_manifest_audit_row_rolls_back_the_change() {
    let store = fixture();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    store.inner.with_conn_fenced(|conn| conn.execute_batch("CREATE TRIGGER reject_manifest_audit BEFORE INSERT ON audit_journal WHEN NEW.reason_code='manifest_changed' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")).unwrap();
    assert!(store
        .upsert_manifest(CATALOG_PRINCIPAL, &edited_manifest("edited"))
        .is_err());
    assert_eq!(
        store.manifest_json(CATALOG_PRINCIPAL, "fixture").unwrap().unwrap()["description"],
        manifest().json["description"],
        "the unaudited content change must not be kept"
    );
    assert!(store
        .retire_absent_manifests(CATALOG_PRINCIPAL, &["other".into()])
        .is_err());
    assert!(
        !store.manifest_is_retired("fixture").unwrap(),
        "the unaudited retirement must not be kept"
    );
}
#[test]
fn manifest_reingest_repairs_corrupt_stored_json() {
    let store = fixture();
    for principal in [CATALOG_PRINCIPAL, "owner"] {
        store.upsert_manifest(principal, &manifest()).unwrap();
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE app_manifests SET manifest_json='{' WHERE principal=?1",
                    [principal],
                )
            })
            .unwrap();
        assert!(
            store.upsert_manifest(principal, &manifest()).is_ok(),
            "valid re-ingest must repair corrupt previous JSON"
        );
        assert!(store
            .manifest_json(principal, "fixture")
            .unwrap()
            .unwrap()
            .is_object());
    }
}
#[test]
fn repeat_seed_preserves_review_decisions_and_adds_missing_actions() {
    let store = fixture();
    store
        .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
        .unwrap();
    store
        .quarantine_action("owner", "connection", "read", "review_required")
        .unwrap();
    store
        .seed_catalog_from_manifest("owner", "connection", "fixture")
        .unwrap();
    assert_eq!(
        store
            .catalog_action("owner", "connection", "read")
            .unwrap()
            .unwrap()
            .status,
        "quarantined",
        "seed must not erase quarantine"
    );
    assert!(store
        .catalog_action("owner", "connection", "write")
        .unwrap()
        .is_some());
    store
        .disable_catalog_action("owner", "connection", "write")
        .unwrap();
    store
        .seed_catalog_from_manifest("owner", "connection", "fixture")
        .unwrap();
    assert_eq!(
        store
            .catalog_action("owner", "connection", "write")
            .unwrap()
            .unwrap()
            .status,
        "disabled"
    );
}
#[test]
fn inactive_poll_commit_has_a_typed_outcome_and_no_cursor_or_failure_write() {
    let store = fixture();
    watch(&store, "sub");
    let selected = store.subscription("owner", "sub").unwrap().unwrap();
    store.suspend("owner", "sub", "operator_pause").unwrap();
    assert!(
        matches!(
            store.commit_poll_success(
                "owner",
                "connection",
                "sub",
                &json!({"watermark_ms":999}),
                &[],
                now_ms(),
                None
            ),
            Err(PollCommitError::Inactive)
        ),
        "inactive commit must not masquerade as store_failed"
    );
    assert!(matches!(
        store.commit_probe_success(
            "owner",
            "connection",
            "sub",
            &json!({}),
            &[],
            now_ms(),
            false
        ),
        Err(PollCommitError::Inactive)
    ));
    let after = store.subscription("owner", "sub").unwrap().unwrap();
    assert_eq!(after.cursor_state, selected.cursor_state);
    assert_eq!(after.consecutive_vendor_failures, 0);
}
#[test]
fn retired_once_probe_cannot_be_suspended_again() {
    let store = fixture();
    grant(&store, "poll", "caller", "read");
    let probe = probe(&store).unwrap();
    store
        .commit_probe_success(
            "owner",
            "connection",
            &probe.subscription_id,
            &json!({}),
            &[],
            now_ms(),
            true,
        )
        .unwrap();
    assert!(
        !store
            .suspend("owner", &probe.subscription_id, "operator_pause")
            .unwrap(),
        "retired probe must stay terminal"
    );
    assert_eq!(
        store
            .subscription("owner", &probe.subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "retired"
    );
    assert_eq!(
        store
            .resume("owner", &probe.subscription_id)
            .unwrap()
            .unwrap_err()
            .code(),
        "subscription_retired",
        "retired resume must name the terminal state"
    );
    assert!(store.list_events("owner", None, None).unwrap().is_empty());
}
#[test]
fn revocation_snapshot_names_the_actual_actor_without_changing_journal_format() {
    let scratch = Scratch::database("revocation-actor");
    let store = store(&scratch.to_string_lossy());
    grant(&store, "grant", "caller", "read");
    store.revoke_grant_as("owner", "grant", "operator").unwrap();
    let actor: String = store
        .inner
        .with_read(|conn| {
            conn.query_row("SELECT revoked_by FROM grant_revocations", [], |row| {
                row.get(0)
            })
        })
        .unwrap();
    assert_eq!(
        actor, "operator",
        "revocation snapshot must name the actual revoker"
    );
    let bytes = std::fs::read(store.grant_journal.as_ref().unwrap()).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value.as_object().unwrap().len(),
        3,
        "journal line must keep the old three-field format"
    );
}
#[test]
fn scoped_approval_batches_rotate_without_starving_older_or_later_rows() {
    let store = fixture();
    store.inner.with_conn_fenced(|conn| {
        for n in 0..3 { conn.execute("INSERT INTO action_requests(request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,status,expires_at,created_at_ms,scope_outcome) VALUES (?1,'owner','connection','read','{}','hash','owner','approved',?2,?3,'approved_waiting')",rusqlite::params![format!("r{n}"),now_ms()+60000,n])?; }
        Ok(())
    }).unwrap();
    let first = store.waiting_scoped_approvals(1).unwrap();
    let second = store.waiting_scoped_approvals(1).unwrap();
    let third = store.waiting_scoped_approvals(1).unwrap();
    assert_eq!(
        (
            &first[0].request_id,
            &second[0].request_id,
            &third[0].request_id
        ),
        (&"r0".into(), &"r1".into(), &"r2".into()),
        "unreachable scopes must not monopolize the oldest-first batch"
    );
}
#[test]
fn by_id_lookups_and_repository_join_are_scoped() {
    let store = fixture();
    grant(&store, "grant", "caller", "read");
    store
        .insert_policy(&PolicyInput {
            policy_id: "policy".into(),
            principal: "owner".into(),
            connection_id: "connection".into(),
            action_selector: "read".into(),
            effect: "allow".into(),
            expires_at: None,
        })
        .unwrap();
    assert_eq!(
        store
            .grant_by_id("owner", "grant")
            .unwrap()
            .unwrap()
            .grantee_principal,
        "caller"
    );
    assert!(store.grant_by_id("other", "grant").unwrap().is_none());
    assert_eq!(
        store
            .policy_by_id("owner", "policy")
            .unwrap()
            .unwrap()
            .state,
        "until_revoked"
    );
    assert!(store.policy_by_id("other", "policy").unwrap().is_none());
    store
        .put_github_handle(&github_store::GithubHandle {
            app_handle_id: "handle".into(),
            agent_id: "agent".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:test".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: None,
            connection_principal: "owner".into(),
            connection_id: "connection".into(),
        })
        .unwrap();
    store.bind_github_repo("OWNER/Repo", "handle").unwrap();
    assert_eq!(
        store
            .github_handle_for_repo("OwNeR/rEpO")
            .unwrap()
            .unwrap()
            .app_handle_id,
        "handle"
    );
    assert!(store
        .github_handle_for_repo("owner/missing")
        .unwrap()
        .is_none());
}
#[test]
fn relay_rejects_future_ack_and_drops_empty_repository_without_stalling() {
    let store = fixture();
    let hello = relay::Hello {
        v: 1,
        source: "github".into(),
        stream_id: "stream".into(),
        next_seq: 1,
        oldest_seq: 1,
        last_acked_seq: 1,
    };
    assert!(
        store.relay_hello("github", &hello).is_err(),
        "future relay acknowledgement must be refused"
    );
    let hello = relay::Hello {
        last_acked_seq: 0,
        ..hello
    };
    store.relay_hello("github", &hello).unwrap();
    let mut event = relay::Event {
        seq: 1,
        delivery_id: "delivery-1".into(),
        event: "release".into(),
        action: None,
        installation_id: 1,
        received_at: "2026-10-13T00:00:00.000Z".into(),
        stub: None,
        body: json!({"repository":{"full_name":"","id":1}}),
    };
    store
        .commit_relay_event("github", "stream", &event)
        .unwrap();
    let count: i64 = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT COALESCE((SELECT value FROM event_outbox_counters WHERE name='relay_drop_invalid_payload'),0)",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(
        count, 1,
        "empty repository must be a committed invalid-payload drop"
    );
    event.seq = 2;
    event.delivery_id = "delivery-2".into();
    event.body = json!({"repository":{"full_name":"owner/repo","id":1}});
    store
        .commit_relay_event("github", "stream", &event)
        .unwrap();
    assert_eq!(
        store.relay_cursor("github").unwrap().unwrap().committed_seq,
        2
    );
}

#[test]
fn retention_uses_settlement_boundaries_and_keeps_live_requests() {
    let store = fixture();
    let now = now_ms();
    let window = 30 * 86_400_000;
    store.inner.with_conn_fenced(|conn| {
        for (id,state,age) in [("old","denied",window+1),("boundary","expired",window),("pending","pending",window+1),("approved","approved",window+1)] {
            conn.execute("INSERT INTO action_requests(request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,status,expires_at,created_at_ms,settled_at_ms) VALUES (?1,'owner','connection','read','{}','hash','owner',?2,0,0,?3)",rusqlite::params![id,state,now-age])?;
        }
        for (id,state,age) in [("ticket-old","consumed",86_400_001),("ticket-boundary","expired",86_400_000),("ticket-issued","issued",86_400_001)] {
            conn.execute("INSERT INTO binding_tickets(ticket_id,principal,connection_id,ref_role,expires_at,status,created_at_ms,settled_at_ms) VALUES (?1,'owner','connection','none',0,?2,0,?3)",rusqlite::params![id,state,now-age])?;
        }
        for (id,state,age) in [("unknown-old","outcome_unknown",window+1),("unknown-young","outcome_unknown",29*86_400_000),("receipt-pending","pending",window+1),("receipt-boundary","pending",window)] {
            conn.execute("INSERT INTO github_bot_receipt(agent_id,request_nonce,request_fingerprint,state,authority_baseline,effects,created_at,updated_at) VALUES ('agent',?1,'fingerprint',?2,'{}','[]',0,?3)",rusqlite::params![id,state,now-age])?;
        }
        Ok(())
    }).unwrap();
    store.prune_audit(now, window).unwrap();
    assert!(
        store.action_request("owner", "old").unwrap().is_some(),
        "audit retention must not trim ceremony history"
    );
    store.prune_ceremony_history(now, window).unwrap();
    let ids = |table: &str, column: &str| {
        store
            .inner
            .with_read(|conn| {
                let mut q =
                    conn.prepare(&format!("SELECT {column} FROM {table} ORDER BY {column}"))?;
                let rows = q
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap()
    };
    assert_eq!(
        ids("action_requests", "request_id"),
        vec!["approved", "boundary", "pending"],
        "history retention must keep live requests and the exact boundary"
    );
    assert_eq!(
        ids("binding_tickets", "ticket_id"),
        vec!["ticket-boundary", "ticket-issued"]
    );
    assert_eq!(
        ids("github_bot_receipt", "request_nonce"),
        vec![
            "receipt-boundary",
            "receipt-pending",
            "unknown-old",
            "unknown-young"
        ],
        "GitHub receipt retention belongs to its lease-aware sweeper, not audit pruning"
    );
}
#[test]
fn reconciliation_backoff_grows_from_five_seconds_to_sixty() {
    let store = fixture();
    let now = now_ms();
    let record = crate::reconciliation::OutcomeUnknownRecord {
        request_id: "unknown".into(),
        principal: "owner".into(),
        acting_principal: "caller".into(),
        actor: "caller".into(),
        connection_id: "connection".into(),
        action: "write".into(),
        args: json!({}),
        occurred_at_ms: now,
    };
    store.enqueue_write_reconciliation(&record, None).unwrap();
    for delay in [5000, 10000, 20000, 40000, 60000, 60000] {
        store.backoff_write_reconciliation(&record, now).unwrap();
        assert!(
            store
                .pending_write_reconciliations_at(now + delay - 1)
                .unwrap()
                .is_empty(),
            "reconciliation must honor its persisted backoff"
        );
        assert_eq!(
            store
                .pending_write_reconciliations_at(now + delay)
                .unwrap()
                .len(),
            1
        );
    }
}
#[test]
fn ci_cadence_fits_the_same_effective_ceiling_as_admission() {
    for count in [1, 7, 31, 100] {
        let store = fixture();
        store.inner.with_conn_fenced(|conn| {
            for n in 0..count { conn.execute("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,fixed_args,schema_hash,status,generation,created_at_ms) VALUES (?1,'owner','connection','list_workflow_runs',300,'ci_runs','{}',?2,'hash','active',0,0)",rusqlite::params![format!("ci{n}"),json!({"owner":"owner","repo":format!("repo{n}")}).to_string()])?; }
            Ok(())
        }).unwrap();
        store.reconcile_ci_cadence().unwrap();
        let cadence: i64 = store
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT cadence_s FROM trigger_subscriptions WHERE subscription_id='ci0'",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        let spacing = (cadence + count - 1) / count;
        let mut calls = 0;
        for second in (0..3600).step_by(spacing as usize) {
            assert!(
                matches!(
                    store
                        .reserve_github_actions_quota(
                            "owner",
                            "ci0",
                            event_outbox::QuotaRequest::CiCycle,
                            second * 1000
                        )
                        .unwrap(),
                    event_outbox::QuotaAdmission::Reserved { .. }
                ),
                "steady-state cadence must not schedule deferred cycles"
            );
            calls += event_outbox::CI_CYCLE_REQUESTS;
        }
        assert!(calls <= 600 - count);
        assert!(cadence >= 300);
        println!(
            "CI watches={count} ceiling={} cadence={cadence}s calls_in_hour={calls}",
            600 - count
        );
    }
}
#[test]
fn migration_52_indexes_have_before_and_after_query_plan_evidence() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    for migration in MIGRATIONS.iter().filter(|migration| migration.version < 52) {
        conn.execute_batch(migration.statements).unwrap();
    }
    let cases=[
        ("grantee-kind","SELECT * FROM grants WHERE grantee_principal='caller' AND authority_kind='poll'","idx_grants_grantee_kind"),
        ("agent","SELECT * FROM grants WHERE agent_id='agent'","idx_grants_agent_global"),
        ("app","SELECT * FROM connections WHERE app_key='fixture'","idx_connections_app"),
        ("connection-id","SELECT * FROM connections WHERE connection_id='connection'","idx_connections_id"),
        ("request-id","SELECT * FROM action_requests WHERE request_id='request'","idx_action_requests_id"),
        ("call-scope","SELECT * FROM action_requests WHERE call_key='call' AND scope_owner='owner' AND scope_ref='scope' AND scope_epoch=1","idx_action_requests_call_scope"),
        ("shape","SELECT * FROM action_requests WHERE principal='owner' AND connection_id='connection' AND action='read' AND args_hash='hash'","idx_action_requests_shape"),
        ("event-key","SELECT * FROM trigger_events WHERE event_key='key'","idx_trigger_events_global_key"),
        ("acting-principal","SELECT * FROM write_reconciliation_results WHERE acting_principal='caller' ORDER BY updated_at_ms DESC","idx_write_results_actor"),
        ("handle-binding","SELECT * FROM github_repo_binding WHERE app_handle_id='handle'","idx_github_binding_handle"),
        ("repository","SELECT * FROM trigger_subscriptions WHERE lower(json_extract(fixed_args,'$.owner') || '/' || json_extract(fixed_args,'$.repo'))='owner/repo'","idx_subscription_repo"),
    ];
    let plan = |sql: &str| {
        let mut q = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        q.query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("; ")
    };
    let before: Vec<_> = cases.iter().map(|(_, sql, _)| plan(sql)).collect();
    let before_waiting=plan("SELECT * FROM action_requests WHERE status='approved' AND scope_outcome='approved_waiting' ORDER BY created_at_ms LIMIT 16");
    conn.execute_batch(
        MIGRATIONS
            .iter()
            .find(|migration| migration.version == 52)
            .unwrap()
            .statements,
    )
    .unwrap();
    for ((name, sql, index), before) in cases.iter().zip(before) {
        let after = plan(sql);
        println!("index {name}: BEFORE {before}; AFTER {after}");
        assert!(
            after.contains(index) && after.contains("SEARCH"),
            "migration index must turn this growing lookup into a SEARCH: {name}: {after}"
        );
    }
    let after_waiting=plan("SELECT * FROM action_requests WHERE status='approved' AND scope_outcome='approved_waiting' ORDER BY scope_checked_at_ms,created_at_ms,principal,request_id LIMIT 16");
    println!("waiting approval: BEFORE {before_waiting}; AFTER {after_waiting}");
    assert!(
        after_waiting.contains("idx_action_requests_waiting")
            && !after_waiting.contains("TEMP B-TREE")
    );
    for (index,sql) in [
        ("idx_action_request_live_expiry","SELECT * FROM action_requests WHERE status IN ('pending','approved') AND expires_at<=123 ORDER BY expires_at LIMIT 1000"),
        ("idx_action_request_retention","SELECT * FROM action_requests WHERE status IN ('consumed','denied','expired','cancelled') AND settled_at_ms<123 ORDER BY settled_at_ms LIMIT 1000"),
        ("idx_binding_ticket_live_expiry","SELECT * FROM binding_tickets WHERE status='issued' AND expires_at<=123 ORDER BY expires_at LIMIT 1000"),
        ("idx_binding_ticket_retention","SELECT * FROM binding_tickets WHERE status IN ('consumed','expired','revoked') AND settled_at_ms<123 ORDER BY settled_at_ms LIMIT 1000"),
        ("idx_github_receipt_unsettled_retention","SELECT * FROM github_bot_receipt WHERE state IN ('outcome_unknown','pending','pending_approval') AND updated_at<123 ORDER BY updated_at LIMIT 1000"),
        ("idx_reconciliation_next_attempt","SELECT * FROM pending_write_reconciliations WHERE next_attempt_at_ms<=123 OR expires_at_ms<=123 ORDER BY expires_at_ms,principal,request_id LIMIT 1000"),
    ] {
        let ddl:String=conn.query_row("SELECT sql FROM sqlite_master WHERE name=?1",[index],|row|row.get(0)).unwrap();
        conn.execute_batch(&format!("DROP INDEX {index}")).unwrap();let before=plan(sql);conn.execute_batch(&ddl).unwrap();let after=plan(sql);
        println!("maintenance index {index}: BEFORE {before}; AFTER {after}");assert!(after.contains(index)&&after.contains("SEARCH"),"maintenance query must search its due/retention range: {after}");
    }
}

use crate::bounded;
#[path = "../../tests/support/logging.rs"]
mod logging;

#[test]
fn reconciliation_warning_never_renders_sensitive_record_fragments() {
    const BAD_RECORD: &str = r#"{"request_id":"unknown","principal":"owner","acting_principal":"caller","actor":"caller","connection_id":"connection","action":"write","args":{},"occurred_at_ms":"PRIVATE_RECONCILIATION_CANARY"}"#;
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        logging::init_child();
        let store = fixture();
        store.inner.with_conn_fenced(|conn|conn.execute("INSERT INTO pending_write_reconciliations(principal,request_id,record_json,expires_at_ms) VALUES ('owner','unknown',?1,?2)",rusqlite::params![BAD_RECORD,now_ms()+60000])).unwrap();
        assert!(store
            .pending_write_reconciliations_at(now_ms())
            .unwrap()
            .is_empty());
        let count: i64 = store
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT count(*) FROM pending_write_reconciliations",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(count, 0);
        return;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "storage::store_contract_tests::reconciliation_warning_never_renders_sensitive_record_fragments",
            "--nocapture",
        ])
        .env("PLEXUS_LOG_STDERR_CHILD", "1");
    let output = bounded::child_output(
        &mut command,
        std::time::Duration::from_secs(10),
        "reconciliation diagnostic child",
    )
    .expect("diagnostic child must complete within its deadline");
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("PRIVATE_RECONCILIATION_CANARY"),
        "reconciliation warning must not render stored record fragments: {stderr}"
    );
    let line = stderr
        .lines()
        .find(|line| line.contains("write reconciliation record does not decode"))
        .expect("positive control: actual production warning reached stderr");
    let error = serde_json::from_str::<crate::reconciliation::OutcomeUnknownRecord>(BAD_RECORD)
        .unwrap_err();
    let message=format!("write reconciliation record does not decode; settling it as ambiguous: principal={:?} request_id={:?}: class={:?} line={} column={}","owner","unknown",error.classify(),error.line(),error.column());
    logging::assert_diagnostic(
        line,
        cortexkit_log::ParsedLevel::Warn,
        "plexus.storage",
        &message,
    );
}
#[test]
fn direct_reconciliation_finish_updates_intent_and_reenqueue_reuses_result() {
    let store = fixture();
    let now = now_ms();
    store.inner.with_conn_fenced(|conn|conn.execute("INSERT INTO action_requests(request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,status,expires_at,created_at_ms) VALUES ('intent','owner','connection','write','{}','hash','caller','consumed',?1,0)",[now+60000])).unwrap();
    let record = crate::reconciliation::OutcomeUnknownRecord {
        request_id: "reservation".into(),
        principal: "owner".into(),
        acting_principal: "caller".into(),
        actor: "caller".into(),
        connection_id: "connection".into(),
        action: "write".into(),
        args: json!({}),
        occurred_at_ms: now,
    };
    store
        .finish_write_reconciliation_with_intent(
            &record,
            Some("intent"),
            "unreconcilable",
            Some("class_missing"),
        )
        .unwrap();
    let status: Option<String> = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT reconciliation_status FROM action_requests WHERE request_id='intent'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(
        status,
        Some("unreconcilable".to_string()),
        "direct finish must update the action intent atomically"
    );
    assert!(
        store
            .enqueue_write_reconciliation(&record, Some("intent"))
            .is_ok(),
        "re-enqueue must reuse a previously terminal result row"
    );
    assert_eq!(
        store.list_write_reconciliations("owner").unwrap().0[0].status,
        "pending"
    );
}

#[test]
fn probe_authority_deadline_covers_every_declared_action() {
    let store = fixture();
    store.upsert_catalog_action(&action("write")).unwrap();
    grant(&store, "a-read", "caller", "read");
    grant(&store, "b-write", "caller", "read");
    let expiry = now_ms() + 60000;
    store.inner.with_conn_fenced(|conn| { conn.execute("UPDATE grants SET action_selectors='[\"read\"]' WHERE grant_id='a-read'",[])?;conn.execute("UPDATE grants SET action_selectors='[\"write\"]',expires_at=?1 WHERE grant_id='b-write'",[expiry])?;Ok(()) }).unwrap();
    let probe = store
        .register_probe(
            "caller",
            "connection",
            ProbeRegistration {
                name: "union",
                actions: &["read".into(), "write".into()],
                script_source: "() => true",
                return_schema: &json!({"kind":"bool"}),
                rearm: "always",
                cadence_s: 30,
                fixed_args: &json!({}),
                cursor_state: &json!({}),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        probe.authority_expires_at_ms,
        Some(expiry),
        "probe deadline must include every action's authorizing grant"
    );
    assert_eq!(probe.authority_state, "live");
}

#[test]
fn resolver_store_failures_are_retryable_and_never_repository_unbound() {
    use crate::governance::{AuthorizationRequest, Denial, GovernanceSeams, ResolverDenial};
    for table in ["connections", "github_app_handle", "github_repo_binding"] {
        let store = Arc::new(fixture());
        store
            .put_github_handle(&github_store::GithubHandle {
                app_handle_id: "handle".into(),
                agent_id: "agent".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:test".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "owner".into(),
                connection_id: "connection".into(),
            })
            .unwrap();
        store
            .inner
            .with_conn_fenced(|conn| conn.execute_batch(&format!("DROP TABLE {table}")))
            .unwrap();
        let seams = github_store::GithubGovernanceSeams {
            store,
            credential_provider: None,
        };
        let refusal = seams
            .resolve_invoke(&AuthorizationRequest::new(
                "owner",
                "connection",
                "read",
                json!({"repository":"owner/repo"}),
            ))
            .unwrap_err();
        assert_eq!(
            refusal,
            ResolverDenial::StoreFailure,
            "every resolver store read must preserve store-failure classification: {table}"
        );
        let denial = Denial::Resolver(refusal);
        assert_eq!(denial.reason_code(), "store_failure");
        assert_eq!(
            denial.retryability(),
            crate::transport::Retryability::AutoRetryable
        );
        assert!(!format!("{denial:?}").contains(table));
    }
}

#[test]
fn recipient_change_distinguishes_noop_missing_and_real_change() {
    let store = fixture();
    assert_eq!(
        store
            .change_recipient("owner", "connection", None, "a@example.com", true, true)
            .unwrap(),
        RecipientChange::Changed
    );
    store.inner.with_conn_fenced(|conn|conn.execute("INSERT INTO reservations(reservation_id,principal,connection_id,action,snapshot_generations,approved_args_hash,schema_hash,expires_at,status,created_at_ms) VALUES ('reserved','owner','connection','read','{}','hash','hash',?1,'reserved',0)",[now_ms()+60000])).unwrap();
    let generation = store
        .connection("owner", "connection")
        .unwrap()
        .unwrap()
        .generation;
    assert_eq!(
        store
            .change_recipient("owner", "connection", None, "a@example.com", true, true)
            .unwrap(),
        RecipientChange::Unchanged
    );
    assert_eq!(
        store
            .connection("owner", "connection")
            .unwrap()
            .unwrap()
            .generation,
        generation
    );
    let status: String = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT status FROM reservations WHERE reservation_id='reserved'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(
        status, "reserved",
        "an unchanged add must preserve outstanding reservations"
    );
    assert_eq!(
        store
            .change_recipient("owner", "missing", None, "a@example.com", true, true)
            .unwrap(),
        RecipientChange::ConnectionNotFound
    );
    assert_eq!(
        store
            .change_recipient("owner", "connection", None, "b@example.com", true, true)
            .unwrap(),
        RecipientChange::Changed
    );
    let status: String = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT status FROM reservations WHERE reservation_id='reserved'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(status, "invalidated");
    assert!(store
        .list_audit("owner")
        .unwrap()
        .iter()
        .any(|row| row.reason_code == "unchanged"));
}

#[test]
#[ignore = "permission-list lookup measurement"]
fn measure_permission_binding_queries() {
    let store = fixture();
    store
        .put_github_handle(&github_store::GithubHandle {
            app_handle_id: "handle".into(),
            agent_id: "agent".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:test".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: None,
            connection_principal: "owner".into(),
            connection_id: "connection".into(),
        })
        .unwrap();
    store.bind_github_repo("owner/repo", "handle").unwrap();
    store.inner.with_conn_fenced(|conn| {for n in 0..500 {conn.execute("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,generation,created_at_ms,agent_id) VALUES (?1,'owner','connection','caller','read','[\"read\"]','invoke',1,0,'agent')",[format!("g{n}")])?;}Ok(())}).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(store.live_agent_grants(None, now_ms()).unwrap().len(), 500);
    println!(
        "permissions: grants=500 handles=1 bindings=1 elapsed={}us",
        start.elapsed().as_micros()
    );
}

#[test]
fn corrupt_catalog_rows_report_one_content_free_warning_per_action() {
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        logging::init_child();
        let store = fixture();
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &manifest())
            .unwrap();
        store.inner.with_conn_fenced(|conn|conn.execute_batch("DELETE FROM catalog_actions; UPDATE app_manifests SET manifest_json='{\"tier\":\"S1\",\"actions_baseline\":[{\"name\":\"read\",\"risk\":\"PRIVATE_MANIFEST_CANARY\"},{\"name\":\"read\",\"risk\":\"PRIVATE_MANIFEST_CANARY\"}]}'" )).unwrap();
        store
            .seed_catalog_from_manifest("owner", "connection", "fixture")
            .unwrap();
        store.upsert_catalog_action(&action("read")).unwrap();
        store
            .put_github_handle(&github_store::GithubHandle {
                app_handle_id: "handle".into(),
                agent_id: "agent".into(),
                app_id: 1,
                installation_id: None,
                credential_reference: "github_app:test".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "owner".into(),
                connection_id: "connection".into(),
            })
            .unwrap();
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE catalog_actions SET schema_json=?1",
                    ["{\"PRIVATE_SCHEMA_CANARY\":"],
                )
            })
            .unwrap();
        let report = store.pin_handle_placeholder_schemas().unwrap();
        assert_eq!(report.gaps.len(), 1, "corrupt schema must produce a gap");
        assert_eq!(report.gaps[0].reason, "stored schema does not parse");
        return;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "storage::store_contract_tests::corrupt_catalog_rows_report_one_content_free_warning_per_action",
            "--nocapture",
        ])
        .env("PLEXUS_LOG_STDERR_CHILD", "1");
    let output = bounded::child_output(
        &mut command,
        std::time::Duration::from_secs(10),
        "corrupt catalog diagnostic child",
    )
    .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "corrupt catalog diagnostic child failed: {stderr}"
    );
    assert!(
        !stderr.contains("PRIVATE_MANIFEST_CANARY") && !stderr.contains("PRIVATE_SCHEMA_CANARY"),
        "catalog warnings must not echo row content: {stderr}"
    );
    for message in ["catalog action skipped", "catalog schema does not parse"] {
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains(message))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one warning per action per pass: {message}: {stderr}"
        );
        assert!(lines[0].contains("action=\"read\""));
        let parsed = cortexkit_log::parse_line(lines[0]).unwrap();
        assert_eq!(parsed.logger, "plexus.storage");
        assert_eq!(parsed.level, cortexkit_log::ParsedLevel::Warn);
    }
}

#[test]
fn legacy_pending_ticket_never_widens_a_recorded_ceiling() {
    let store = fixture();
    store.inner.with_conn_fenced(|conn| {
        conn.execute("UPDATE connections SET status='pending',ceiling_risk='read',ceiling_selectors='[\"read\"]'",[])?;
        conn.execute("INSERT INTO binding_tickets(ticket_id,principal,connection_id,ref_role,expires_at,status,created_at_ms,risk_ceiling,action_selectors) VALUES ('legacy','owner','connection','none',?1,'issued',0,'write','[\"read\",\"write\"]')",[now_ms()+60000])?;
        Ok(())
    }).unwrap();
    assert!(
        store
            .connect_with_ticket("owner", "legacy")
            .unwrap()
            .is_some(),
        "positive control: a pending legacy ticket reaches consumption"
    );
    assert_eq!(
        store
            .connection_ceiling("owner", "connection")
            .unwrap()
            .unwrap()
            .risk,
        Risk::Read,
        "a recorded ceiling must survive consumption of a wider legacy ticket"
    );
}

#[test]
fn wal_reader_progresses_while_writer_is_fenced() {
    let scratch = Scratch::database("wal-read-progress");
    let store = Arc::new(store(&scratch.to_string_lossy()));
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = store.clone();
    let writer = std::thread::spawn(move || {
        writer
            .inner
            .with_conn_fenced(|_| {
                held_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                Ok(())
            })
            .unwrap()
    });
    held_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let reader = store.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let rows = reader.list_connections("owner").unwrap();
        done_tx.send(rows.len()).unwrap();
    });
    let during = done_rx.recv_timeout(std::time::Duration::from_secs(1));
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    reader.join().unwrap();
    assert!(
        during.is_ok(),
        "WAL readers must progress before the writer fence is released"
    );
}
#[test]
fn event_retention_returns_at_most_one_bounded_batch() {
    let store = fixture();
    watch(&store, "sub");
    store.inner.with_conn_fenced(|conn| {
        for n in 0..1505 {conn.execute("INSERT INTO trigger_events(event_id,principal,connection_id,subscription_id,vendor_event_id,payload_hash,payload,kind,observed_at_ms,created_at_ms,acked_at_ms) VALUES (?1,'owner','connection','sub',?1,?1,'{}','event',0,0,1)",[format!("event{n}")])?;}
        Ok(())
    }).unwrap();
    assert_eq!(
        store.prune("owner", "sub", 0, 0).unwrap(),
        1000,
        "event retention must bound its deletion batch"
    );
    assert_eq!(store.prune("owner", "sub", 0, 0).unwrap(), 505);
}

#[test]
fn webhook_identity_change_updates_cache_before_a_replacement_watch() {
    let store = fixture();
    watch(&store, "old");
    store
        .inner
        .with_conn_fenced(|conn| conn.execute("UPDATE connections SET app_key='github'", []))
        .unwrap();
    store.inner.with_conn_fenced(|conn|conn.execute("UPDATE trigger_subscriptions SET fixed_args='{\"owner\":\"owner\",\"repo\":\"repo\"}'",[])).unwrap();
    store
        .record_repo_id_resolution("owner/repo", Some(1), now_ms())
        .unwrap();
    store
        .relay_hello(
            "github",
            &relay::Hello {
                v: 1,
                source: "github".into(),
                stream_id: "stream".into(),
                next_seq: 1,
                oldest_seq: 1,
                last_acked_seq: 0,
            },
        )
        .unwrap();
    let mut event = relay::Event {
        seq: 1,
        delivery_id: "first".into(),
        event: "release".into(),
        action: None,
        installation_id: 1,
        received_at: "2026-10-13T00:00:00.000Z".into(),
        stub: None,
        body: json!({"repository":{"full_name":"owner/repo","id":2}}),
    };
    store
        .commit_relay_event("github", "stream", &event)
        .unwrap();
    assert_eq!(
        store.repo_id_cache("owner/repo").unwrap().unwrap().repo_id,
        Some(2),
        "identity-changing webhook must replace the stale cache id"
    );
    watch(&store, "replacement");
    store.inner.with_conn_fenced(|conn|conn.execute("UPDATE trigger_subscriptions SET fixed_args='{\"owner\":\"owner\",\"repo\":\"repo\"}' WHERE subscription_id='replacement'",[])).unwrap();
    event.seq = 2;
    event.delivery_id = "second".into();
    store
        .commit_relay_event("github", "stream", &event)
        .unwrap();
    assert_eq!(
        store
            .subscription("owner", "replacement")
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    let count: i64 = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT value FROM event_outbox_counters WHERE name='repository_identity_changed'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn relay_identity_changes_warn_once_per_new_id() {
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        logging::init_child();
        let store = fixture();
        watch(&store, "identity-watch");
        store.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE connections SET app_key='github'",[])?;
            conn.execute("UPDATE trigger_subscriptions SET fixed_args='{\"owner\":\"owner\",\"repo\":\"repo\"}'",[])
        }).unwrap();
        store
            .record_repo_id_resolution("owner/repo", Some(1), 1000)
            .unwrap();
        store
            .relay_hello(
                "github",
                &relay::Hello {
                    v: 1,
                    source: "github".into(),
                    stream_id: "stream".into(),
                    next_seq: 1,
                    oldest_seq: 1,
                    last_acked_seq: 0,
                },
            )
            .unwrap();
        for (seq, id) in [(1, 2), (2, 2), (3, 3), (4, 3)] {
            store
                .commit_relay_event(
                    "github",
                    "stream",
                    &relay::Event {
                        seq,
                        delivery_id: format!("delivery-{seq}"),
                        event: "issues".into(),
                        action: None,
                        installation_id: 1,
                        received_at: "2026-10-14T16:00:00.000Z".into(),
                        stub: None,
                        body: json!({"repository":{"full_name":"owner/repo","id":id}}),
                    },
                )
                .unwrap();
        }
        return;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "storage::store_contract_tests::relay_identity_changes_warn_once_per_new_id",
            "--nocapture",
        ])
        .env("PLEXUS_LOG_STDERR_CHILD", "1");
    let output = bounded::child_output(
        &mut command,
        std::time::Duration::from_secs(10),
        "identity change diagnostic child",
    )
    .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "identity change diagnostic child failed: {stderr}"
    );
    let warnings: Vec<_> = stderr
        .lines()
        .filter_map(|line| cortexkit_log::parse_line(line).ok())
        .filter(|line| line.level == cortexkit_log::ParsedLevel::Warn)
        .collect();
    assert_eq!(
        warnings.len(),
        2,
        "one warning per identity change, not per webhook: {stderr}"
    );
    assert!(warnings.iter().all(|line| line.logger == "plexus.storage"));
    for message in [
        "identity changed from 1 to 2",
        "identity changed from 2 to 3",
    ] {
        assert_eq!(
            stderr.lines().filter(|line| line.contains(message)).count(),
            1,
            "identity warning must include old and new ids: {stderr}"
        );
    }
}

#[test]
fn expired_invoke_grants_do_not_widen_search_candidates() {
    let store = fixture();
    store
        .insert_connection("caller", "own", "fixture", "active", &json!({}))
        .unwrap();
    grant(&store, "expired", "caller", "read");
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE grants SET authority_kind='invoke',expires_at=?1",
                [now_ms() - 1],
            )
        })
        .unwrap();
    assert_eq!(
        store
            .web_search_candidate_connection_ids("caller", "fixture")
            .unwrap(),
        vec!["own"],
        "expired grants must not make a single usable search connection ambiguous"
    );
    store
        .inner
        .with_conn_fenced(|conn| conn.execute("UPDATE grants SET expires_at=NULL", []))
        .unwrap();
    assert_eq!(
        store
            .web_search_candidate_connection_ids("caller", "fixture")
            .unwrap(),
        vec!["connection", "own"]
    );
}

#[test]
fn revoked_connection_ignores_late_health_updates() {
    let store = fixture();
    assert!(store
        .set_connection_health(
            "owner",
            "connection",
            "degraded",
            &json!({"reason":"probe_failure"})
        )
        .unwrap());
    assert!(store.revoke_connection("owner", "connection").unwrap());
    let before = store.connection("owner", "connection").unwrap().unwrap();
    for status in ["active", "degraded", "auth_required", "pending", "disabled"] {
        assert!(
            !store
                .set_connection_health(
                    "owner",
                    "connection",
                    status,
                    &json!({"reason":"late_probe"})
                )
                .unwrap(),
            "a late health update must not change a revoked connection"
        );
        assert_eq!(
            store.connection("owner", "connection").unwrap().unwrap(),
            before,
            "revocation must preserve status, generation and health metadata against late updates"
        );
    }
}

#[test]
fn health_setter_refuses_revocation_without_writing() {
    let store = fixture();
    let before = store.connection("owner", "connection").unwrap().unwrap();
    let error = store
        .set_connection_health(
            "owner",
            "connection",
            "revoked",
            &json!({"reason":"health_attempt"}),
        )
        .expect_err("health status setter must not perform a revocation");
    assert!(error.to_string().contains("revoke_connection"));
    assert_eq!(
        store.connection("owner", "connection").unwrap().unwrap(),
        before
    );
    assert!(
        store.revoke_connection("owner", "connection").unwrap(),
        "positive control: the revocation API remains available"
    );
}

#[test]
fn audit_app_handle_is_explicit_and_independent_of_nonce_or_agent_handle() {
    let store = store(":memory:");
    let mut record = AuditRecord::ceremony("owner", None, None, "inspect", "read", None);
    record.app_handle_id = Some("app-explicit".into());
    record.agent_handle = Some("not-the-app-handle".into());
    store.append_audit(&record).unwrap();
    let row = store.list_audit("owner").unwrap().remove(0);
    assert_eq!(row.app_handle_id.as_deref(), Some("app-explicit"));
    assert!(serde_json::to_value(&row)
        .unwrap()
        .get("claimed_agent_id")
        .is_none());
    record.app_handle_id = None;
    record.idempotency_key_fingerprint = Some("nonce-fingerprint".into());
    store.append_audit(&record).unwrap();
    let rows = store.list_audit("owner").unwrap();
    assert!(
        rows[1].app_handle_id.is_none(),
        "a nonce must not manufacture an App handle id"
    );
}
