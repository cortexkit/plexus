use super::*;

fn store() -> PlexusStore {
    PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: new_id("sent-text"),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    })
    .unwrap()
}

#[test]
fn gmail_retention_deletes_ciphertext_and_keeps_audit_hash() {
    let store = store();
    store
        .append_audit(&AuditRecord {
            args_redaction_summary: Some("args_hash:independent-original-text-hash".into()),
            ..AuditRecord::ceremony(
                "direct",
                Some("gmail"),
                Some("mail"),
                "gmail.send",
                "write",
                None,
            )
        })
        .unwrap();
    let row = SentTextRow {
        row_id: "row".into(),
        connection_id: "mail".into(),
        recipient_hash: "recipient-hash".into(),
        sealed: Sealed {
            key_id: "key".into(),
            enc: vec![1; 32],
            ciphertext: vec![2; 64],
        },
    };
    store.save_sent_text("direct", &row, 1000).unwrap();
    assert_eq!(store.prune_sent_text(1000 + 30 * 86400000 - 1).unwrap(), 0);
    assert_eq!(store.prune_sent_text(1000 + 30 * 86400000).unwrap(), 1);
    assert!(store.sent_text("direct", "row", 1001).unwrap().is_none());
    assert_eq!(
        store.list_audit("direct").unwrap()[0]
            .args_redaction_summary
            .as_deref(),
        Some("args_hash:independent-original-text-hash")
    );
}

#[test]
fn gmail_archive_requires_retention_configuration_and_a_written_row() {
    let store = store();
    store
        .inner
        .with_conn_fenced(|conn| conn.execute_batch("DELETE FROM sent_text_settings"))
        .unwrap();
    let row = SentTextRow {
        row_id: "row".into(),
        connection_id: "mail".into(),
        recipient_hash: "hash".into(),
        sealed: Sealed {
            key_id: "key".into(),
            enc: vec![1; 32],
            ciphertext: vec![2; 64],
        },
    };
    assert!(store.save_sent_text("direct", &row, 1000).is_err());
}

#[test]
fn gmail_terminal_snapshot_scrubs_content_for_every_terminal_status() {
    let store = store();
    let args = serde_json::json!({"to":["alice@example.com"],"cc":[],"bcc":[],"subject":"subject plaintext","body":"body plaintext","other":"kept"});
    for status in ["consumed", "denied", "expired", "cancelled"] {
        let id = store
            .create_action_request(
                "direct",
                "mail",
                "gmail.send",
                &args,
                "schema",
                "direct",
                now_ms() + 60000,
                None,
                None,
            )
            .unwrap();
        let before = store.action_request("direct", &id).unwrap().unwrap();
        assert_eq!(before.args_snapshot, args);
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE action_requests SET status=?1 WHERE request_id=?2",
                    [status, &id],
                )?;
                Ok(())
            })
            .unwrap();
        let after = store.action_request("direct", &id).unwrap().unwrap();
        assert_eq!(after.args_snapshot["to"], args["to"]);
        assert_eq!(after.args_snapshot["other"], "kept");
        assert_eq!(
            after.args_snapshot["subject"],
            "sha256:0f1846bae4a6982bbd00d7ac94e506cf3e5771f60ee6dee10cef5cfdd225c11a"
        );
        assert!(after.args_snapshot["body"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(after.args_hash, before.args_hash);
        let pending_copy: Option<String> = store
            .inner
            .with_read(|conn| {
                conn.query_row(
                    "SELECT terminal_args_snapshot FROM action_requests WHERE request_id=?1",
                    [&id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(pending_copy.is_none());
    }
}

#[test]
fn gmail_migration_58_forward_rollback_and_reforward() {
    let descriptor = cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "gmail-migration".into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    };
    let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 58).unwrap();
    let prior = &MIGRATIONS[..boundary];
    inner.migrate("plexus", prior).unwrap();
    inner.with_conn_fenced(|c| c.execute_batch("INSERT INTO connections(principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES ('direct','before','fixture','active',1,1)")).unwrap();
    assert_eq!(inner.migrate("plexus", MIGRATIONS).unwrap().applied, 1);
    inner.with_conn_fenced(|c| c.execute_batch("INSERT INTO gmail_accounts(principal,connection_id,mailbox) VALUES ('direct','mail','owner@example.com'); INSERT INTO sent_text VALUES ('row','direct','mail','hash','key',x'01',x'02',999999,1);")).unwrap();
    let rollback = inner.migrate("plexus", prior).unwrap();
    assert!(rollback.store_ahead());
    assert_eq!(rollback.applied, 0);
    inner.with_conn_fenced(|c| c.execute_batch("INSERT INTO connections(principal,connection_id,app_key,status,created_at_ms,updated_at_ms) VALUES ('direct','older-write','fixture','active',1,1)")).unwrap();
    assert_eq!(inner.migrate("plexus", MIGRATIONS).unwrap().applied, 0);
    let counts: (i64, i64) = inner
        .with_read(|c| {
            Ok((
                c.query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))?,
                c.query_row("SELECT COUNT(*) FROM sent_text", [], |r| r.get(0))?,
            ))
        })
        .unwrap();
    assert_eq!(counts, (2, 1));
}
