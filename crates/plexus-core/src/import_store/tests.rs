use super::*;

const BODY: &str = r#"{"number":1.0,"\ue000":1,"😀":2}"#;
const LEGACY_HASH: &str = "sha256:0c7b15c538e300d7538923c11a6c3bf905197b3d66498688e84a75d4810ff80b";
const CREDENTIAL: &[u8] = b"plexus:vault-reference:v1\0apikey:fixture";

struct Fixture {
    // Under the shared test scratch root, so a killed run's leftovers are swept
    // by age like every other test's and never land in the source tree.
    directory: crate::test_scratch::Scratch,
    from: PathBuf,
    to: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = crate::test_scratch::Scratch::directory("import-store");
        let fixture = Self {
            from: directory.join("old.db"),
            to: directory.join("new.db"),
            directory,
        };
        let source = open_sqlite(&descriptor(&fixture.from).unwrap()).unwrap();
        source.migrate("plexus", &MIGRATIONS[..1]).unwrap();
        source.with_conn(|c| {
            c.execute_batch(r#"
INSERT INTO app_manifests(principal,key,schema_version,content_hash,manifest_json,ingested_at_ms,status) VALUES ('system','app',1,'manifest-byte-hash','{}',1,'retired');
INSERT INTO connections(principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES ('direct','c','app','active',1,2);
INSERT INTO grants(principal,grant_id,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms) VALUES ('direct','g','c','consumer','read','poll',1);
INSERT INTO policies(principal,policy_id,connection_id,action_selector,effect,updated_at_ms) VALUES ('direct','policy','c','a','allow',1);
INSERT INTO catalog_actions(principal,connection_id,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms) VALUES ('direct','c','a','{}','legacy','read','low','active',1,2);
INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,cursor_state,schema_hash,status,created_at_ms,fixed_args,project_id,deliver_to,actor_source_json) VALUES ('sub','direct','c','a',60,'ordered_timestamp','{"watermark":123}','legacy','active',1,'{"x":42}','project','reserved:consumer','{"action":"actors"}');
INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms) VALUES ('probe','direct','c','__probe__',60,'probe','legacy','active',1);
INSERT INTO probe_subscriptions(subscription_id,name,actions,script_source,return_schema,rearm,registered_by) VALUES ('probe','check','["a"]','return true','{}','always','operator');
INSERT INTO trigger_events(event_id,principal,connection_id,subscription_id,vendor_event_id,payload_hash,payload,kind,observed_at_ms,created_at_ms) VALUES ('unacked','direct','c','sub','vendor1','legacy','{}','event',1,1);
INSERT INTO trigger_events(event_id,principal,connection_id,subscription_id,vendor_event_id,payload_hash,payload,kind,observed_at_ms,created_at_ms,acked_at_ms) VALUES ('acked','direct','c','sub','vendor2','legacy','{}','event',1,1,2);
INSERT INTO action_requests(request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,status,expires_at,created_at_ms,reconciliation_status) VALUES ('unknown','direct','c','a','{}','legacy','operator','pending',1,1,'outcome_unknown');
INSERT INTO action_requests(request_id,principal,connection_id,action,args_snapshot,schema_hash,requester,status,expires_at,created_at_ms) VALUES ('approval','direct','c','a','{}','legacy','operator','pending',1,1);
INSERT INTO reservations(reservation_id,principal,connection_id,action,snapshot_generations,approved_args_hash,schema_hash,expires_at,status,created_at_ms) VALUES ('r','direct','c','a','{}','legacy','legacy',1,'reserved',1);
INSERT INTO binding_tickets(ticket_id,principal,connection_id,ref_role,expires_at,status,created_at_ms) VALUES ('ticket','direct','c','credential',1,'issued',1);
INSERT INTO audit_journal(ts,principal,actor,acting_principal,decision,reason_code) VALUES (1,'direct','operator','direct','allow','test');
"#)?;
            c.execute("UPDATE connections SET credential_binding=?1", [CREDENTIAL])?;
            let legacy = LEGACY_HASH;
            c.execute("UPDATE catalog_actions SET schema_json=?1,schema_hash=?2", params![BODY,legacy])?;
            c.execute("UPDATE trigger_subscriptions SET schema_hash=?1", [&legacy])?;
            c.execute("UPDATE trigger_events SET payload=?1,payload_hash=?2", params![BODY,legacy])?;
            c.execute("UPDATE action_requests SET args_snapshot=?1,args_hash=?2,schema_hash=?2", params![BODY,legacy])?;
            c.execute("UPDATE probe_subscriptions SET return_schema=?1", [BODY])?;
            Ok(())
        }).unwrap();
        drop(source);
        fixture
    }

    fn mutate_source(&self, sql: &str) {
        let source = open_sqlite(&descriptor(&self.from).unwrap()).unwrap();
        source.with_conn(|c| c.execute_batch(sql)).unwrap();
    }

    fn import(&self) -> Vec<TableSummary> {
        import_store(&self.from, &self.to).unwrap()
    }
    fn destination(&self) -> Connection {
        Connection::open(&self.to).unwrap()
    }
}

fn scalar<T: rusqlite::types::FromSql>(c: &Connection, sql: &str) -> T {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn recipient_allowlist_is_carried_on_current_store_cutover() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    source.with_conn(|conn|conn.execute_batch("INSERT INTO recipient_allowlist (principal,connection_id,agent_id,recipient) VALUES ('direct','c',NULL,'alice@example.com'),('direct','c','agent','bob@example.com')")).unwrap();
    drop(source);
    let report = f.import();
    let recipients = report
        .iter()
        .find(|r| r.table == "recipient_allowlist")
        .unwrap();
    assert_eq!(
        (recipients.read, recipients.carried, recipients.scrubbed),
        (2, 2, 0)
    );
    let new = f.destination();
    assert_eq!(scalar::<i64>(&new,"SELECT COUNT(*) FROM recipient_allowlist WHERE principal='direct' AND connection_id='c' AND agent_id IS NULL AND recipient='alice@example.com'"),1);
    assert_eq!(scalar::<i64>(&new,"SELECT COUNT(*) FROM recipient_allowlist WHERE principal='direct' AND connection_id='c' AND agent_id='agent' AND recipient='bob@example.com'"),1);
}

#[test]
fn web_search_order_allowances_and_counts_survive_store_cutover() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    source.with_conn_fenced(|conn| conn.execute_batch(r#"
INSERT INTO web_search_order (singleton, providers) VALUES (1, '["tavily","exa"]');
INSERT INTO web_search_allowances (provider, allowance) VALUES ('exa', 2);
INSERT INTO web_search_allowance_counts (principal, provider, month_utc, used) VALUES ('direct','exa','2024-02',2), ('direct','tavily','2024-02',1), ('direct','exa','2024-03',1), ('former-owner','exa','2024-02',1);
"#)).unwrap();
    drop(source);
    let report = f.import();
    for (table, count) in [
        ("web_search_order", 1),
        ("web_search_allowances", 1),
        ("web_search_allowance_counts", 4),
    ] {
        let row = report.iter().find(|row| row.table == table).unwrap();
        assert_eq!((row.read, row.carried, row.scrubbed), (count, count, 0));
    }
    let new = f.destination();
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT providers FROM web_search_order WHERE singleton=1"
        ),
        r#"["tavily","exa"]"#
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT allowance FROM web_search_allowances WHERE provider='exa'"
        ),
        2
    );
    assert_eq!(scalar::<i64>(&new, "SELECT used FROM web_search_allowance_counts WHERE principal='direct' AND provider='exa' AND month_utc='2024-02'"), 2);
    assert_eq!(scalar::<i64>(&new, "SELECT used FROM web_search_allowance_counts WHERE principal='direct' AND provider='exa' AND month_utc='2024-03'"), 1);
    assert_eq!(scalar::<i64>(&new, "SELECT used FROM web_search_allowance_counts WHERE principal='direct' AND provider='tavily' AND month_utc='2024-02'"), 1);
    assert_eq!(scalar::<i64>(&new, "SELECT used FROM web_search_allowance_counts WHERE principal='former-owner' AND provider='exa' AND month_utc='2024-02'"), 1);
}

#[test]
fn outbox_failures_follow_only_retained_publication_markers_on_import() {
    assert_eq!(
        identity(
            "event_outbox_failures",
            &Record::from([
                ("event_key".into(), Value::Text("retained".into())),
                ("version".into(), Value::Integer(2))
            ])
        ),
        "event_outbox_failures [retained, 2]"
    );
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    source.with_conn(|conn| conn.execute_batch("INSERT INTO event_outbox(event_key,event_id,event_name,repo_id,repo,created_at_ms)
        VALUES ('retained','unacked','github_issue_changed',1,'org/repo',1),('orphan','missing','github_issue_changed',1,'org/repo',1);
        INSERT INTO event_outbox_failures(event_key,version,failed_at_ms,failure_reason)
        VALUES ('retained',1,11,'invalid_headers'),('retained',2,12,'invalid_body'),('orphan',1,13,'invalid_body');")).unwrap();
    drop(source);
    f.import();
    let new = f.destination();
    let failures: Vec<(String,i64,i64,String)> = new.prepare("SELECT event_key,version,failed_at_ms,failure_reason FROM event_outbox_failures ORDER BY version").unwrap()
        .query_map([],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    assert_eq!(
        failures,
        vec![
            ("retained".into(), 1, 11, "invalid_headers".into()),
            ("retained".into(), 2, 12, "invalid_body".into())
        ],
        "cutover must retain terminal publication status only for surviving markers"
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT COUNT(*) FROM event_outbox WHERE event_key='orphan'"
        ),
        0
    );
    assert_eq!(
        scalar::<i64>(&new, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
}

/// Durable GitHub handle authority, bot-request receipts, the relay cursor,
/// publishing markers of carried events and writes still being reconciled
/// all survive the cutover; the marker of an acked (dropped) event does not.
#[test]
fn handles_receipts_markers_cursor_and_reconciliations_are_carried() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    source
        .with_conn(|conn| {
            conn.execute_batch(
                r#"
INSERT INTO github_app_handle (app_handle_id, agent_id, app_id, credential_reference, status, connection_principal, connection_id)
    VALUES ('handle', 'agent', 1, 'github_app:handle', 'enabled', 'direct', 'c');
INSERT INTO github_repo_binding (repository, app_handle_id) VALUES ('org/repo', 'handle');
INSERT INTO github_bot_receipt (agent_id, request_nonce, request_fingerprint, state, created_at, updated_at)
    VALUES ('agent', 'nonce-1', 'fingerprint', 'completed', 1, 1);
INSERT INTO event_outbox (event_key, event_id, event_name, repo_id, repo, created_at_ms)
    VALUES ('key-unacked', 'unacked', 'github_issue_changed', 1, 'org/repo', 1),
           ('key-acked', 'acked', 'github_issue_changed', 1, 'org/repo', 1);
INSERT INTO relay_cursor (source, stream_id, committed_seq) VALUES ('github', 'stream', 7);
INSERT INTO pending_write_reconciliations (principal, request_id, record_json, intent_id, expires_at_ms)
    VALUES ('direct', 'unknown-write', '{}', 'unknown', 9);
INSERT INTO write_reconciliation_results (principal, request_id, acting_principal, connection_id, action, status, updated_at_ms)
    VALUES ('direct', 'unknown-write', 'direct', 'c', 'a', 'pending', 1);
"#,
            )
        })
        .unwrap();
    drop(source);
    let report = f.import();
    let carried = |table: &str| {
        let row = report
            .iter()
            .find(|row| row.table == table)
            .unwrap_or_else(|| panic!("{table} must be carried"));
        (row.read, row.carried)
    };
    assert_eq!(carried("github_app_handle"), (1, 1));
    assert_eq!(carried("github_repo_binding"), (1, 1));
    assert_eq!(carried("github_bot_receipt"), (1, 1));
    assert_eq!(
        carried("event_outbox"),
        (2, 2),
        "acked retained bodies still need their pending publication markers"
    );
    assert_eq!(carried("relay_cursor"), (1, 1));
    assert_eq!(carried("pending_write_reconciliations"), (1, 1));
    assert_eq!(carried("write_reconciliation_results"), (1, 1));
    let new = f.destination();
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT COUNT(*) FROM trigger_events WHERE event_id='acked'"
        ),
        1,
        "acked retained body must survive cutover, not just its orphaned marker"
    );
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT event_id FROM event_outbox WHERE event_key='key-unacked'"
        ),
        "unacked"
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT committed_seq FROM relay_cursor WHERE source = 'github'"
        ),
        7
    );
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT app_handle_id FROM github_repo_binding WHERE repository = 'org/repo'"
        ),
        "handle"
    );
}

/// Every table of the current schema is either copied by the import or on the
/// documented exclusion list with a reason, and neither list names a table
/// the schema no longer has. A migration that adds a table fails this until
/// someone decides whether a cutover carries it.
#[test]
fn every_schema_table_is_imported_or_deliberately_excluded() {
    let scratch = crate::test_scratch::Scratch::database("import-table-coverage");
    let store = crate::storage::PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "import-table-coverage".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    // Writes that create SQLite's own bookkeeping tables lazily (for example
    // `sqlite_sequence` on the first AUTOINCREMENT insert).
    store
        .append_audit(&crate::storage::AuditRecord::ceremony(
            "direct", None, None, "coverage", "read", None,
        ))
        .unwrap();
    drop(store);
    let conn = Connection::open(scratch.path()).unwrap();
    let schema: std::collections::BTreeSet<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let excluded: Vec<&str> = EXCLUDED_TABLES.iter().map(|(table, _)| *table).collect();
    let unaccounted: Vec<&String> = schema
        .iter()
        .filter(|table| !TABLES.contains(&table.as_str()) && !excluded.contains(&table.as_str()))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "tables neither imported nor excluded with a reason: {unaccounted:?}"
    );
    let stale: Vec<&&str> = TABLES
        .iter()
        .chain(excluded.iter())
        .filter(|table| !schema.contains(**table))
        .collect();
    assert!(
        stale.is_empty(),
        "listed tables the schema does not have: {stale:?}"
    );
    let both: Vec<&&str> = TABLES
        .iter()
        .filter(|table| excluded.contains(table))
        .collect();
    assert!(
        both.is_empty(),
        "tables both imported and excluded: {both:?}"
    );
    assert!(
        EXCLUDED_TABLES
            .iter()
            .all(|(_, reason)| !reason.trim().is_empty()),
        "every exclusion needs its reason"
    );
}

/// Operator web search limits, the consent-answer cursor, recorded repository
/// ids, the trailing hour's GitHub Actions reservations and the health
/// counters survive the cutover unchanged.
#[test]
fn limits_cursor_repo_ids_quota_and_counters_are_carried() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    const ROWS: &str = r#"
INSERT INTO web_search_limits (backend, per_caller_per_minute, per_backend_per_minute, updated_at_ms) VALUES ('exa', 3, 30, 1);
INSERT INTO elicitation_answers_cursor (singleton, answers_cursor, updated_at_ms) VALUES (1, 42, 1);
INSERT INTO github_repo_id_cache (repo, repo_id, last_attempt_at_ms, resolved_at_ms) VALUES ('org/repo', 101, 1, 1);
INSERT INTO github_actions_quota (reservation_id, reserved_at_ms, requests) VALUES ('quota-1', 5, 8);
INSERT INTO event_outbox_counters (name, value) VALUES ('dropped_on_delete', 3);
"#;
    source.with_conn(|conn| conn.execute_batch(ROWS)).unwrap();
    drop(source);
    let report = f.import();
    for table in [
        "web_search_limits",
        "elicitation_answers_cursor",
        "github_repo_id_cache",
        "github_actions_quota",
        "event_outbox_counters",
    ] {
        let row = report
            .iter()
            .find(|row| row.table == table)
            .unwrap_or_else(|| panic!("{table} must be carried"));
        assert_eq!((row.read, row.carried), (1, 1), "{table} must be carried");
    }
    let new = f.destination();
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT per_backend_per_minute FROM web_search_limits WHERE backend = 'exa'"
        ),
        30
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT answers_cursor FROM elicitation_answers_cursor"
        ),
        42
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT repo_id FROM github_repo_id_cache WHERE repo = 'org/repo'"
        ),
        101
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT requests FROM github_actions_quota WHERE reservation_id = 'quota-1'"
        ),
        8
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT value FROM event_outbox_counters WHERE name = 'dropped_on_delete'"
        ),
        3
    );
}

/// A source from before recipient lists had an owner gives every row to the
/// principal that owns the connection, the same backfill the in-place schema
/// migration does.
#[test]
fn recipient_allowlist_without_an_owner_is_given_to_the_connection_owner_on_import() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    let before_owner = MIGRATIONS.iter().position(|m| m.version == 48).unwrap();
    source
        .migrate("plexus", &MIGRATIONS[..before_owner])
        .unwrap();
    source
        .with_conn(|conn| {
            conn.execute_batch(
                "INSERT INTO recipient_allowlist VALUES ('c',NULL,'alice@example.com')",
            )
        })
        .unwrap();
    drop(source);
    f.import();
    let new = f.destination();
    assert_eq!(
        scalar::<i64>(&new, "SELECT COUNT(*) FROM recipient_allowlist"),
        1
    );
    assert_eq!(
        scalar::<Option<String>>(&new, "SELECT principal FROM recipient_allowlist WHERE connection_id='c' AND recipient='alice@example.com'"),
        Some("direct".to_string()),
        "an owner-less row must be given to the connection's owner"
    );
}

#[test]
fn production_v23_round_trip_dispositions_and_routing() {
    let f = Fixture::new();
    let report = f.import();
    let new = f.destination();
    for row in report {
        let (read, carried, recomputed) = match row.table.as_str() {
            "trigger_subscriptions" => (2, 2, 2),
            // Acknowledged bodies remain dedupe evidence across cutover.
            "trigger_events" => (2, 2, 2),
            "action_requests" => (2, 1, 1),
            "catalog_actions" => (1, 1, 1),
            "reservations" | "binding_tickets" | "audit_journal" => (1, 0, 0),
            // Schema generation 43 added the recipient table. This generation-23
            // fixture therefore has no recipient table or entries to import.
            "recipient_allowlist" => (0, 0, 0),
            // Tables added after generation 23 are absent from this fixture.
            "event_outbox"
            | "event_outbox_failures"
            | "consent_call_keys"
            | "relay_cursor"
            | "github_app_handle"
            | "github_repo_binding"
            | "github_bot_receipt"
            | "pending_write_reconciliations"
            | "write_reconciliation_results"
            | "web_search_limits"
            | "web_search_order"
            | "web_search_allowances"
            | "web_search_allowance_counts"
            | "elicitation_answers_cursor"
            | "github_repo_id_cache"
            | "github_actions_quota"
            | "event_outbox_counters"
            | "gmail_accounts"
            | "sent_text"
            | "sent_text_settings" => (0, 0, 0),
            _ => (1, 1, 0),
        };
        assert_eq!(
            (row.read, row.carried, row.recomputed),
            (read, carried, recomputed),
            "{}",
            row.table
        );
        assert_eq!(row.read, row.carried + row.scrubbed);
        // The destination migration seeds a retention policy even when the
        // source predates sent text; this row is not counted as imported data.
        let stored = if row.table == "sent_text_settings" {
            1
        } else {
            carried
        };
        assert_eq!(
            scalar::<u64>(&new, &format!("SELECT count(*) FROM {}", row.table)),
            stored
        );
    }
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT retention_days FROM sent_text_settings WHERE singleton=1"
        ),
        30
    );
    let old = Connection::open(&f.from).unwrap();
    for column in [
        "cursor_state",
        "fixed_args",
        "project_id",
        "deliver_to",
        "actor_source_json",
    ] {
        let sql = format!("SELECT {column} FROM trigger_subscriptions WHERE subscription_id='sub'");
        assert_eq!(scalar::<String>(&new, &sql), scalar::<String>(&old, &sql));
    }
    assert_eq!(
        scalar::<String>(&new, "SELECT status FROM app_manifests"),
        "retired"
    );
    assert_eq!(
        scalar::<String>(&new, "SELECT content_hash FROM app_manifests"),
        "manifest-byte-hash"
    );
    assert_eq!(
        scalar::<String>(&new, "SELECT request_id FROM action_requests"),
        "unknown"
    );
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT event_id FROM trigger_events WHERE event_id='unacked'"
        ),
        "unacked"
    );
    assert_eq!(scalar::<i64>(&old, "SELECT count(*) FROM audit_journal"), 1);
    assert_eq!(
        std::fs::read_dir(f.directory.path())
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".plexus-import"))
            .count(),
        0
    );
}

#[test]
fn credential_binding_is_byte_identical() {
    let f = Fixture::new();
    f.import();
    let bytes: Vec<u8> = scalar(
        &f.destination(),
        "SELECT credential_binding FROM connections",
    );
    assert_eq!(bytes, CREDENTIAL);
}

#[test]
fn import_refuses_non_revoked_legacy_and_drops_revoked_legacy() {
    for status in ["active", "pending", "degraded", "auth_required", "disabled"] {
        let f = Fixture::new();
        f.mutate_source(&format!(
            "UPDATE connections SET status='{status}',credential_binding=x'00ff804100fe'"
        ));
        let error = import_store(&f.from, &f.to).unwrap_err();
        assert!(error.contains("handle_bindings_removed"), "{error}");
        assert!(error.contains("connection(s) c"), "{error}");
        assert!(
            error.contains("ck-plexus-admin rebind-credential"),
            "{error}"
        );
        assert!(!f.to.exists());
    }
    let f = Fixture::new();
    f.mutate_source("UPDATE connections SET status='revoked',credential_binding=x'00ff804100fe'");
    f.import();
    assert_eq!(
        scalar::<Option<Vec<u8>>>(
            &f.destination(),
            "SELECT credential_binding FROM connections"
        ),
        None
    );
}

#[test]
fn stored_hashes_are_jcs_and_not_legacy() {
    let f = Fixture::new();
    f.import();
    let expected = hash(BODY).unwrap();
    let legacy = LEGACY_HASH;
    assert_ne!(
        expected, legacy,
        "fixture must distinguish the canonicalizers"
    );
    let new = f.destination();
    for sql in [
        "SELECT schema_hash FROM catalog_actions",
        "SELECT payload_hash FROM trigger_events",
        "SELECT schema_hash FROM action_requests",
        "SELECT args_hash FROM action_requests",
    ] {
        let actual: String = scalar(&new, sql);
        assert_eq!(actual, expected, "{sql}");
        assert_ne!(actual, legacy, "{sql}");
    }
}

#[test]
fn subscription_repin_matches_its_action_and_probe_return_schema() {
    let f = Fixture::new();
    f.import();
    let new = f.destination();
    let catalog: String = scalar(&new, "SELECT schema_hash FROM catalog_actions");
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT schema_hash FROM trigger_subscriptions WHERE subscription_id='sub'"
        ),
        catalog
    );
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT schema_hash FROM trigger_subscriptions WHERE subscription_id='probe'"
        ),
        hash(BODY).unwrap()
    );
}

#[test]
fn missing_action_refuses_and_names_subscription() {
    let f = Fixture::new();
    f.mutate_source("INSERT INTO trigger_subscriptions(subscription_id,principal,connection_id,action,cadence_s,cursor_kind,schema_hash,status,created_at_ms) VALUES ('absent-sub','direct','c','absent',60,'ordered_timestamp','legacy','active',1)");
    let error = import_store(&f.from, &f.to).expect_err("missing action must refuse, never skip");
    assert!(
        error.contains("trigger_subscriptions [absent-sub]") && error.contains("absent"),
        "{error}"
    );
    assert!(!f.to.exists());
}

#[test]
fn invalid_json_and_missing_referents_abort_without_publication() {
    for (sql, name) in [
        (
            "UPDATE catalog_actions SET schema_json='not json'",
            "catalog_actions [direct, c, a]",
        ),
        (
            "UPDATE trigger_events SET payload='not json' WHERE event_id='unacked'",
            "trigger_events [unacked]",
        ),
        (
            "UPDATE action_requests SET args_snapshot='not json' WHERE request_id='unknown'",
            "action_requests [direct, unknown]",
        ),
        (
            "UPDATE grants SET connection_id='absent'",
            "grants [direct, g]",
        ),
        (
            "UPDATE connections SET transport_config='not json'",
            "connections [direct, c]",
        ),
        (
            "UPDATE action_requests SET schema_hash='lost-schema' WHERE request_id='unknown'",
            "action_requests [direct, unknown]",
        ),
        (
            "UPDATE trigger_events SET subscription_id='absent' WHERE event_id='unacked'",
            "trigger_events [unacked]",
        ),
    ] {
        let f = Fixture::new();
        f.mutate_source(sql);
        let error = import_store(&f.from, &f.to).unwrap_err();
        assert!(error.contains(name), "{error}");
        assert!(!f.to.exists());
    }
}

#[test]
fn source_lease_refuses_before_reading_and_existing_destination_is_untouched() {
    let f = Fixture::new();
    let lease = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    let error = import_store(&f.from, &f.to).unwrap_err();
    assert!(
        error.to_lowercase().contains("lease") && error.contains("stop the plexus module"),
        "{error}"
    );
    assert!(!f.to.exists());
    drop(lease);
    std::fs::write(&f.to, b"do not overwrite").unwrap();
    assert!(import_store(&f.from, &f.to)
        .unwrap_err()
        .contains("already exists"));
    assert_eq!(std::fs::read(&f.to).unwrap(), b"do not overwrite");
    assert!(import_store(&f.from, &f.from)
        .unwrap_err()
        .contains("already exists"));
}

fn journal_path(f: &Fixture) -> PathBuf {
    f.to.with_file_name(crate::grant_journal::NAME)
}

fn write_revocation(f: &Fixture, id: &str) {
    std::fs::write(
        journal_path(f),
        format!("{{\"principal\":\"direct\",\"grant_id\":\"{id}\",\"revoked_at_ms\":123}}\n"),
    )
    .unwrap();
}

#[test]
fn journal_append_is_durable_before_delete() {
    let f = Fixture::new();
    f.mutate_source("CREATE TRIGGER fail_delete BEFORE DELETE ON grants BEGIN SELECT RAISE(ABORT, 'injected failure after journal sync'); END;");
    let store = crate::storage::PlexusStore::open(&descriptor(&f.from).unwrap()).unwrap();
    assert!(store.revoke_grant("direct", "g").is_err());
    let entries = crate::grant_journal::read(&journal_path(&f)).unwrap();
    assert_eq!(
        entries.len(),
        1,
        "durable append must precede the failing delete"
    );
    assert_eq!(entries[0].grant_id, "g");
    let conn = Connection::open(&f.from).unwrap();
    assert_eq!(scalar::<u64>(&conn, "SELECT count(*) FROM grants"), 1);
    assert_eq!(
        scalar::<u64>(&conn, "SELECT count(*) FROM grant_revocations"),
        0
    );
    conn.execute_batch("DROP TRIGGER fail_delete").unwrap();
    assert!(store.revoke_grant("direct", "g").unwrap());
    assert_eq!(scalar::<u64>(&conn, "SELECT count(*) FROM grants"), 0);
    assert_eq!(
        scalar::<u64>(&conn, "SELECT count(*) FROM grant_revocations"),
        1
    );
    assert_eq!(
        crate::grant_journal::read(&journal_path(&f)).unwrap().len(),
        2
    );
}

#[test]
fn journal_import_reapplies_revocation() {
    let f = Fixture::new();
    write_revocation(&f, "g");
    let report = f.import();
    let conn = f.destination();
    assert_eq!(scalar::<u64>(&conn, "SELECT count(*) FROM grants"), 0);
    assert_eq!(
        scalar::<u64>(&conn, "SELECT count(*) FROM grant_revocations"),
        1
    );
    let grants = report.iter().find(|s| s.table == "grants").unwrap();
    assert_eq!((grants.carried, grants.scrubbed), (0, 1));
}

#[test]
fn cross_directory_import_carries_source_and_destination_revocations() {
    let f = Fixture::new();
    write_revocation(&f, "g");
    let destination = crate::test_scratch::Scratch::directory("import-revocations");
    let journal = destination.join(crate::grant_journal::NAME);
    crate::grant_journal::ensure(&journal).unwrap();
    crate::grant_journal::append(
        &journal,
        &crate::grant_journal::Revocation {
            principal: "direct".into(),
            grant_id: "destination-only".into(),
            revoked_at_ms: 2,
        },
    )
    .unwrap();
    let to = destination.join("store.db");
    import_store(&f.from, &to).unwrap();
    let conn = Connection::open(&to).unwrap();
    assert_eq!(scalar::<u64>(&conn, "SELECT count(*) FROM grants"), 0);
    let entries = crate::grant_journal::read(&journal).unwrap();
    assert!(entries.iter().any(|entry| entry.grant_id == "g"));
    assert!(entries
        .iter()
        .any(|entry| entry.grant_id == "destination-only"));
    assert_eq!(
        crate::grant_journal::read(&journal_path(&f)).unwrap().len(),
        1,
        "source journal is not modified"
    );
}

#[test]
fn journal_malformed_import_leaves_target_untouched() {
    let f = Fixture::new();
    write_revocation(&f, "g");
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(journal_path(&f))
        .unwrap()
        .write_all(b"not json\n")
        .unwrap();
    let before = std::fs::read(&f.from).unwrap();
    let journal = std::fs::read(journal_path(&f)).unwrap();
    let entries_before = std::fs::read_dir(f.directory.path()).unwrap().count();
    let error = import_store(&f.from, &f.to).unwrap_err();
    assert!(error.contains("line 2"), "{error}");
    assert!(!f.to.exists(), "absent target must remain absent");
    assert_eq!(std::fs::read(&f.from).unwrap(), before);
    assert_eq!(std::fs::read(journal_path(&f)).unwrap(), journal);
    assert_eq!(
        std::fs::read_dir(f.directory.path()).unwrap().count(),
        entries_before
    );
}

#[test]
fn journal_absent_grant_is_harmless() {
    let f = Fixture::new();
    write_revocation(&f, "missing");
    f.import();
    assert_eq!(
        scalar::<u64>(&f.destination(), "SELECT count(*) FROM grants"),
        1
    );
}

#[test]
fn journal_fresh_open_creates_empty_file() {
    let f = Fixture::new();
    let store = crate::storage::PlexusStore::open(&descriptor(&f.to).unwrap()).unwrap();
    assert_eq!(std::fs::read(journal_path(&f)).unwrap(), b"");
    drop(store);
}

#[test]
fn journal_canonical_restore_reapplies_before_serving() {
    let f = Fixture::new();
    write_revocation(&f, "g");
    let store = crate::storage::PlexusStore::open(&descriptor(&f.from).unwrap()).unwrap();
    let conn = Connection::open(&f.from).unwrap();
    assert_eq!(scalar::<u64>(&conn, "SELECT count(*) FROM grants"), 0);
    assert_eq!(
        scalar::<u64>(&conn, "SELECT count(*) FROM grant_revocations"),
        1
    );
    drop(store);
    let reopened = crate::storage::PlexusStore::open(&descriptor(&f.from).unwrap()).unwrap();
    assert_eq!(
        scalar::<u64>(&conn, "SELECT count(*) FROM grant_revocations"),
        1
    );
    drop(reopened);
}

#[test]
fn journal_malformed_canonical_restore_leaves_database_unchanged() {
    let f = Fixture::new();
    std::fs::write(journal_path(&f), b"bad\n").unwrap();
    let before = std::fs::read(&f.from).unwrap();
    let error = crate::storage::PlexusStore::open(&descriptor(&f.from).unwrap())
        .err()
        .expect("must refuse malformed journal");
    assert!(error.to_string().contains("line 1"));
    assert_eq!(std::fs::read(&f.from).unwrap(), before);
}

#[test]
fn journal_absent_or_empty_open_takes_no_write_fence() {
    for empty_file in [false, true] {
        let f = Fixture::new();
        f.mutate_source("CREATE TABLE cortexkit_fence (id INTEGER PRIMARY KEY CHECK (id = 0), epoch INTEGER NOT NULL); INSERT INTO cortexkit_fence VALUES (0, 98);");
        std::fs::copy(&f.from, &f.to).unwrap();
        assert!(!journal_path(&f).exists());
        if empty_file {
            std::fs::write(journal_path(&f), b"").unwrap();
        }
        // A database copy keeps its fence epoch (98). Opening a store with no
        // revocations to replay must write nothing, so that epoch must still
        // read 98 afterwards: any fenced write stamps the writer's own epoch.
        let store = crate::storage::PlexusStore::open(&descriptor(&f.to).unwrap())
            .expect("opening without revocations must not take the write fence");
        let conn = f.destination();
        assert_eq!(
            scalar::<u64>(&conn, "SELECT epoch FROM cortexkit_fence WHERE id=0"),
            98
        );
        assert_eq!(scalar::<u64>(&conn, "SELECT count(*) FROM grants"), 1);
        assert_eq!(std::fs::read(journal_path(&f)).unwrap(), b"");
        drop(conn);
        drop(store);
        // Prove the epoch check above can fail: a real fenced write on the same
        // copy succeeds (the store raises a copied lease past the database's
        // epoch on open) and moves the epoch past 98.
        let raw = open_sqlite(&descriptor(&f.to).unwrap()).unwrap();
        raw.with_conn_fenced(|_| Ok(()))
            .expect("a fenced write on a copied store succeeds");
        drop(raw);
        let conn = f.destination();
        assert!(
            scalar::<u64>(&conn, "SELECT epoch FROM cortexkit_fence WHERE id=0") > 98,
            "a fenced write must move the copied epoch, or the check above proves nothing"
        );
    }
}

#[test]
fn cutover_keeps_receipt_approvals_and_unreconcilable_deleted_handle_results() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    source.with_conn(|conn|conn.execute_batch("INSERT INTO github_bot_receipt(agent_id,request_nonce,request_fingerprint,state,action_request_id,created_at,updated_at) VALUES ('agent','nonce','fingerprint','pending_approval','approval',1,1); INSERT INTO write_reconciliation_results(principal,request_id,acting_principal,connection_id,action,status,reason,updated_at_ms) VALUES ('reserved:aft','orphan','reserved:aft','','github.issue_create','unreconcilable','reconciliation_class_missing',1);")).unwrap();
    drop(source);
    f.import();
    let destination = f.destination();
    assert_eq!(scalar::<i64>(&destination,"SELECT COUNT(*) FROM action_requests WHERE request_id='approval' AND reconciliation_status IS NULL"),1,"a carried pending receipt must retain its approval row");
    assert_eq!(scalar::<i64>(&destination,"SELECT COUNT(*) FROM write_reconciliation_results WHERE request_id='orphan' AND connection_id=''"),1,"deleted-handle results must not abort the cutover");
}

#[test]
fn gmail_sent_text_mailbox_pacing_and_retention_survive_cutover() {
    let f = Fixture::new();
    let source = open_sqlite(&descriptor(&f.from).unwrap()).unwrap();
    source.migrate("plexus", MIGRATIONS).unwrap();
    source.with_conn(|conn|conn.execute_batch("INSERT INTO gmail_accounts(principal,connection_id,mailbox,next_send_ms) VALUES ('direct','c','owner@example.com',123456); INSERT INTO sent_text(row_id,principal,connection_id,recipient_hash,key_id,enc,ciphertext,expires_at_ms,created_at_ms) VALUES ('sent-row','direct','c','recipient-hash','fixture-key',x'010203',x'040506',777777,1000); UPDATE sent_text_settings SET retention_days=17 WHERE singleton=1;")).unwrap();
    drop(source);
    let report = f.import();
    for table in ["gmail_accounts", "sent_text", "sent_text_settings"] {
        let row = report.iter().find(|r| r.table == table).unwrap();
        assert_eq!((row.read, row.carried, row.scrubbed), (1, 1, 0), "{table}");
    }
    let new = f.destination();
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT mailbox FROM gmail_accounts WHERE principal='direct' AND connection_id='c'"
        ),
        "owner@example.com"
    );
    assert_eq!(scalar::<i64>(&new,"SELECT next_send_ms FROM gmail_accounts WHERE principal='direct' AND connection_id='c'"),123456);
    assert_eq!(
        scalar::<String>(
            &new,
            "SELECT recipient_hash FROM sent_text WHERE row_id='sent-row'"
        ),
        "recipient-hash"
    );
    assert_eq!(
        scalar::<String>(&new, "SELECT key_id FROM sent_text WHERE row_id='sent-row'"),
        "fixture-key"
    );
    assert_eq!(
        scalar::<Vec<u8>>(&new, "SELECT enc FROM sent_text WHERE row_id='sent-row'"),
        vec![1, 2, 3]
    );
    assert_eq!(
        scalar::<Vec<u8>>(
            &new,
            "SELECT ciphertext FROM sent_text WHERE row_id='sent-row'"
        ),
        vec![4, 5, 6]
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT expires_at_ms FROM sent_text WHERE row_id='sent-row'"
        ),
        777777
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT created_at_ms FROM sent_text WHERE row_id='sent-row'"
        ),
        1000
    );
    assert_eq!(
        scalar::<i64>(
            &new,
            "SELECT retention_days FROM sent_text_settings WHERE singleton=1"
        ),
        17
    );
}
