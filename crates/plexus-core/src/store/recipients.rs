use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientChange {
    Changed,
    Unchanged,
    ConnectionNotFound,
}

impl PlexusStore {
    /// Read the action's recipient declaration from the reviewed manifest rather
    /// than the vendor's live tool list, so only reviewed argument positions
    /// identify recipients.
    pub fn recipient_pointers(
        &self,
        app_key: &str,
        action: &str,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(None);
        };
        let manifest = document.map_err(StoreError::Backend)?;
        Ok(manifest
            .actions_baseline
            .iter()
            .find(|baseline| baseline.name == action)
            .and_then(|baseline| baseline.recipients.clone()))
    }

    /// A NULL agent id selects the module-only list for a connection, separate
    /// from every agent's own list. SQLite's ordinary unique index allows
    /// duplicate NULL keys, so a partial unique index prevents duplicate
    /// recipients in the module-only list.
    ///
    /// `owner` is the principal that owns the connection: connection ids are
    /// unique only per owner, so two owners' connections may share an id and
    /// must not share a list.
    pub fn list_recipients(
        &self,
        owner: &str,
        connection: &str,
        agent: Option<&str>,
    ) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            conn.prepare("SELECT recipient FROM recipient_allowlist WHERE principal=?1 AND connection_id=?2 AND agent_id IS ?3 ORDER BY recipient")?
                .query_map(rusqlite::params![owner, connection, agent], |row| row.get(0))?
                .collect()
        })
    }

    /// Preview or apply adding or removing a recipient on `owner`'s connection,
    /// and record the audit in the same transaction. Every applied change
    /// invalidates that connection's outstanding reservations so calls must be
    /// authorized against the updated allowlist rather than sending under the
    /// previous list. Another owner's connection with the same id is untouched.
    pub fn change_recipient(
        &self,
        owner: &str,
        connection: &str,
        agent: Option<&str>,
        recipient: &str,
        add: bool,
        apply: bool,
    ) -> Result<RecipientChange, StoreError> {
        let recipient = crate::recipients::normalize_recipient(recipient);
        if recipient.is_empty() {
            return Err(StoreError::Backend("recipient must not be empty".into()));
        }
        self.inner.with_conn_fenced(|conn| {
            if !conn.query_row("SELECT EXISTS(SELECT 1 FROM connections WHERE principal=?1 AND connection_id=?2)",[owner, connection],|row|row.get::<_,bool>(0))? {
                return Ok(RecipientChange::ConnectionNotFound);
            }
            let changed=if apply {
                if add {
                    conn.execute("INSERT OR IGNORE INTO recipient_allowlist(principal,connection_id,agent_id,recipient) VALUES (?1,?2,?3,?4)", rusqlite::params![owner, connection, agent, recipient])?
                } else {
                    conn.execute("DELETE FROM recipient_allowlist WHERE principal=?1 AND connection_id=?2 AND agent_id IS ?3 AND recipient=?4", rusqlite::params![owner, connection, agent, recipient])?
                }
            } else { 0 };
            if changed != 0 {
                conn.execute("UPDATE connections SET generation=generation+1 WHERE principal=?1 AND connection_id=?2", [owner, connection])?;
                conn.execute("UPDATE reservations SET status='invalidated' WHERE principal=?1 AND connection_id=?2 AND status='reserved'", [owner, connection])?;
            }
            conn.execute("INSERT INTO audit_journal(principal,actor,acting_principal,connection_id,agent_id,action,risk,severity,decision,reason_code,gate,args_redaction_summary,ts) VALUES (?1,'direct','direct',?2,?3,?4,?5,'S1','allow',?6,'ceremony',?7,?8)", rusqlite::params![owner, connection, agent, if add {"recipients_add"} else {"recipients_remove"}, if add {"write"} else {"read"}, if apply {if changed==0 {"unchanged"} else {"applied"}} else {"preview"}, serde_json::json!({"recipient":recipient,"widening":add}).to_string(), now_ms()])?;
            Ok(if changed==0 {RecipientChange::Unchanged} else {RecipientChange::Changed})
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_scratch::Scratch;

    #[test]
    fn migration_43_is_additive_version_guarded_and_null_keys_are_unique() {
        let scratch = Scratch::database("recipient-migration");
        let descriptor = cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "recipient-migration".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
        let boundary = MIGRATIONS.iter().position(|m| m.version == 43).unwrap();
        inner.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
        inner.with_conn_fenced(|conn|conn.execute_batch("INSERT INTO connections(connection_id,principal,app_key,status,resource_filters,created_at_ms,updated_at_ms) VALUES ('mail','direct','fixture','active','{}',1,1)")).unwrap();
        let counts = |conn: &rusqlite::Connection| -> Vec<(String, i64)> {
            conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('cortexkit_schema_version','recipient_allowlist') ORDER BY name").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().map(|name| {
                let name = name.unwrap(); let count = conn.query_row(&format!("SELECT COUNT(*) FROM {name}"),[],|r|r.get(0)).unwrap(); (name,count)
            }).collect()
        };
        let before = inner.with_conn(|conn| Ok(counts(conn))).unwrap();
        let first = inner.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
        assert_eq!((first.applied, first.recorded), (1, 43));
        let second = inner.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
        assert_eq!((second.applied, second.recorded), (0, 43));
        assert_eq!(before, inner.with_conn(|conn| Ok(counts(conn))).unwrap());
        inner.with_conn_fenced(|conn| {
            conn.execute("INSERT INTO recipient_allowlist VALUES ('mail',NULL,'alice@example.com')",[])?;
            assert!(conn.execute("INSERT INTO recipient_allowlist VALUES ('mail',NULL,'alice@example.com')",[]).is_err());
            conn.execute("INSERT INTO recipient_allowlist VALUES ('mail','agent','alice@example.com')",[])?;
            assert!(conn.execute("INSERT INTO recipient_allowlist VALUES ('mail','agent','alice@example.com')",[]).is_err());
            Ok(())
        }).unwrap();
    }

    fn open(label: &str) -> (Scratch, cortexkit_store::SqliteStore) {
        let scratch = Scratch::database(label);
        let descriptor = cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: label.into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        };
        let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
        (scratch, inner)
    }

    /// A list written before lists had an owner is copied to every owner of a
    /// connection with that id, so neither owner loses what it could send to,
    /// and from then on each owner's list is its own.
    #[test]
    fn migration_48_gives_each_owner_its_own_copy_of_a_shared_list() {
        let (_scratch, inner) = open("recipient-owner-migration");
        let boundary = MIGRATIONS.iter().position(|m| m.version == 48).unwrap();
        inner.migrate("plexus", &MIGRATIONS[..boundary]).unwrap();
        inner.with_conn_fenced(|conn| conn.execute_batch(
            "INSERT INTO connections(connection_id,principal,app_key,status,resource_filters,created_at_ms,updated_at_ms)
                VALUES ('conn-mail','owner-a','fixture','active','{}',1,1),
                       ('conn-mail','owner-b','fixture','active','{}',1,1),
                       ('conn-solo','owner-a','fixture','active','{}',1,1);
             INSERT INTO recipient_allowlist VALUES
                ('conn-mail',NULL,'alice@example.com'),
                ('conn-mail','agent','bob@example.com'),
                ('conn-solo',NULL,'carol@example.com'),
                ('conn-gone',NULL,'dave@example.com');")).unwrap();
        let first = inner.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
        assert_eq!((first.applied, first.recorded), (1, 48));
        let rows = |inner: &cortexkit_store::SqliteStore| -> Vec<(Option<String>, String, Option<String>, String)> {
            inner.with_conn(|conn| {
                conn.prepare("SELECT principal, connection_id, agent_id, recipient FROM recipient_allowlist ORDER BY 1,2,3,4")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect()
            }).unwrap()
        };
        let owned = |principal: &str, connection: &str, agent: Option<&str>, recipient: &str| {
            (
                Some(principal.to_string()),
                connection.to_string(),
                agent.map(str::to_string),
                recipient.to_string(),
            )
        };
        let expected = vec![
            owned("owner-a", "conn-mail", None, "alice@example.com"),
            owned("owner-a", "conn-mail", Some("agent"), "bob@example.com"),
            owned("owner-a", "conn-solo", None, "carol@example.com"),
            owned("owner-b", "conn-mail", None, "alice@example.com"),
            owned("owner-b", "conn-mail", Some("agent"), "bob@example.com"),
        ];
        assert_eq!(
            rows(&inner),
            expected,
            "one copy per owner; the list of a deleted connection is dropped"
        );
        let second = inner.migrate("plexus", &MIGRATIONS[..=boundary]).unwrap();
        assert_eq!((second.applied, second.recorded), (0, 48));
        assert_eq!(rows(&inner), expected);
        inner.with_conn_fenced(|conn| {
            assert!(conn.execute("INSERT INTO recipient_allowlist (principal,connection_id,agent_id,recipient) VALUES ('owner-a','conn-mail',NULL,'alice@example.com')",[]).is_err());
            assert!(conn.execute("INSERT INTO recipient_allowlist (principal,connection_id,agent_id,recipient) VALUES ('owner-a','conn-mail','agent','bob@example.com')",[]).is_err());
            conn.execute("INSERT INTO recipient_allowlist (principal,connection_id,agent_id,recipient) VALUES ('owner-c','conn-mail',NULL,'alice@example.com')",[])?;
            Ok(())
        }).unwrap();
    }

    /// Two owners whose connections share an id keep separate lists: adding,
    /// listing, invalidating reservations and deleting the connection all stay
    /// on the one owner named.
    #[test]
    fn owners_sharing_a_connection_id_never_share_a_recipient_list() {
        let scratch = Scratch::database("recipient-owners");
        let store = PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "recipient-owners-store".into(),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: cortexkit_store_types::StorageBackend::Sqlite {
                path: scratch.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        for owner in ["owner-a", "owner-b"] {
            store
                .insert_connection(
                    owner,
                    "conn-mail",
                    "fixture",
                    "active",
                    &serde_json::json!({}),
                )
                .unwrap();
        }
        store.inner.with_conn_fenced(|conn| conn.execute_batch(
            "INSERT INTO reservations(reservation_id,principal,connection_id,action,snapshot_generations,approved_args_hash,schema_hash,expires_at,status,created_at_ms)
                VALUES ('r-b','owner-b','conn-mail','send','{}','h','h',9007199254740991,'reserved',1)")).unwrap();
        let generation = |owner: &str| {
            store
                .connection(owner, "conn-mail")
                .unwrap()
                .unwrap()
                .generation
        };
        let b_generation = generation("owner-b");
        store
            .change_recipient("owner-a", "conn-mail", None, "x@example.com", true, true)
            .unwrap();
        assert_eq!(
            store.list_recipients("owner-a", "conn-mail", None).unwrap(),
            vec!["x@example.com"]
        );
        assert!(
            store
                .list_recipients("owner-b", "conn-mail", None)
                .unwrap()
                .is_empty(),
            "owner-a's entry must not let owner-b send there"
        );
        assert_eq!(
            generation("owner-b"),
            b_generation,
            "owner-b's connection is untouched"
        );
        let b_reservation: String = store
            .inner
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT status FROM reservations WHERE reservation_id='r-b'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(b_reservation, "reserved");
        assert_eq!(
            store
                .change_recipient("owner-c", "conn-mail", None, "x@example.com", true, true)
                .unwrap(),
            RecipientChange::ConnectionNotFound,
            "an owner without that connection cannot write a list for it"
        );

        store
            .change_recipient("owner-b", "conn-mail", None, "y@example.com", true, true)
            .unwrap();
        assert!(matches!(
            store
                .delete_connection("owner-a", "conn-mail", true)
                .unwrap(),
            DeleteConnectionOutcome::Deleted { .. }
        ));
        assert_eq!(
            store.list_recipients("owner-b", "conn-mail", None).unwrap(),
            vec!["y@example.com"],
            "deleting owner-a's connection keeps owner-b's list"
        );
    }
}
