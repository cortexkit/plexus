use super::*;
use crate::storage::MIGRATIONS;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

#[test]
fn migration_60_forward_rollback_and_reforward_preserves_proposals() {
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "manifest-migration".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    };
    let inner = cortexkit_store::open_sqlite(&descriptor).unwrap();
    let boundary = MIGRATIONS.iter().position(|m| m.version == 60).unwrap();
    let older = &MIGRATIONS[..boundary];
    inner.migrate("plexus", older).unwrap();
    let old_write = |id: &str| {
        inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO github_app_handle(app_handle_id,agent_id,app_id,credential_reference,status,connection_principal,connection_id) VALUES (?1,?1,7,'github_app:'||?1,'enabled','direct',?1)",[id])?;
        Ok(())
    }).unwrap()
    };
    old_write("before");
    assert_eq!(inner.migrate("plexus", MIGRATIONS).unwrap().applied, 1);
    inner.with_conn_fenced(|conn| {
        conn.execute("INSERT INTO github_manifest_binding(app_handle_id,repository,agent_id,proposal_id,manifest_version,manifest_sha256,statement_b64url,expires_at_ms,state,card_id,present,revision) VALUES ('before','org/repo','before','proposal',29,'hash','statement',12345,'pending','card',1,7)",[])?;
        Ok(())
    }).unwrap();
    let expected = inner.with_read(|conn|conn.query_row("SELECT app_handle_id,repository,agent_id,proposal_id,manifest_version,manifest_sha256,statement_b64url,expires_at_ms,state,card_id,present,revision FROM github_manifest_binding",[],row)).unwrap();
    let rollback = inner.migrate("plexus", older).unwrap();
    assert!(rollback.store_ahead());
    assert_eq!(rollback.applied, 0);
    old_write("during-rollback");
    assert_eq!(inner.migrate("plexus", MIGRATIONS).unwrap().applied, 0);
    let actual = inner.with_read(|conn|conn.query_row("SELECT app_handle_id,repository,agent_id,proposal_id,manifest_version,manifest_sha256,statement_b64url,expires_at_ms,state,card_id,present,revision FROM github_manifest_binding",[],row)).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        inner
            .with_read(|conn| conn
                .query_row("SELECT count(*) FROM github_app_handle", [], |r| r
                    .get::<_, i64>(0)))
            .unwrap(),
        2
    );
}
