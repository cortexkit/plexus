use super::{GithubHandle, PlexusStore};
use cortexkit_store::StoreError;
use rusqlite::{params, OptionalExtension};

pub(crate) struct ImportedIdentity {
    pub(crate) app_id: i64,
    pub(crate) agent: String,
    pub(crate) enabled: bool,
    pub(crate) next_probe_at_ms: Option<i64>,
}

pub(crate) struct ProbeClaim {
    pub(crate) credential_generation: i64,
    handle_generation: i64,
    next_probe_at_ms: i64,
}

impl PlexusStore {
    /// Reserve the next interval before contacting GitHub so another wake or a
    /// restart cannot cause a second attempt during that interval.
    pub(crate) fn claim_attested_probe(
        &self,
        handle: &GithubHandle,
        now: i64,
        next_probe_at_ms: i64,
        held: &dyn Fn() -> bool,
    ) -> Result<Option<ProbeClaim>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            if !held() {
                return Ok(None);
            }
            let claim = conn.query_row(
                "SELECT h.credential_generation,h.app_handle_generation
                 FROM github_attested_probe p JOIN github_app_handle h USING (app_handle_id)
                 JOIN connections c ON c.principal=h.connection_principal AND c.connection_id=h.connection_id
                 WHERE p.app_handle_id=?1 AND h.credential_reference=?2 AND h.app_id=?3 AND h.agent_id=?4
                       AND h.status='disabled' AND c.status='active' AND p.next_probe_at_ms<=?5",
                params![handle.app_handle_id, handle.credential_reference, handle.app_id, handle.agent_id, now],
                |row| Ok(ProbeClaim {
                    credential_generation: row.get(0)?, handle_generation: row.get(1)?, next_probe_at_ms,
                }),
            ).optional()?;
            if claim.is_some() {
                conn.execute(
                    "UPDATE github_attested_probe SET next_probe_at_ms=?2 WHERE app_handle_id=?1",
                    params![handle.app_handle_id, next_probe_at_ms],
                )?;
                if !held() {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            Ok(claim)
        })
    }

    /// A successful read cannot undo an intentional disable or an intervening
    /// handle/credential replacement. Publish proof and consume the marker together.
    pub(crate) fn complete_attested_probe(
        &self,
        handle: &GithubHandle,
        claim: ProbeClaim,
        proven_at: i64,
        held: &dyn Fn() -> bool,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            if !held() {
                return Ok(false);
            }
            let wrote = conn.execute(
                "UPDATE github_app_handle SET status='enabled',proven_at=?2
                 WHERE app_handle_id=?1 AND app_handle_generation=?3 AND credential_generation=?4
                   AND status='disabled' AND credential_reference=?5 AND app_id=?6 AND agent_id=?7
                   AND EXISTS (SELECT 1 FROM github_attested_probe p WHERE p.app_handle_id=?1 AND p.next_probe_at_ms=?8)
                   AND EXISTS (SELECT 1 FROM connections c WHERE c.principal=github_app_handle.connection_principal
                                 AND c.connection_id=github_app_handle.connection_id AND c.status='active')",
                params![handle.app_handle_id, proven_at, claim.handle_generation, claim.credential_generation,
                    handle.credential_reference, handle.app_id, handle.agent_id, claim.next_probe_at_ms],
            )? != 0;
            if wrote {
                conn.execute("DELETE FROM github_attested_probe WHERE app_handle_id=?1", [&handle.app_handle_id])?;
                if !held() {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            Ok(wrote)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    #[test]
    fn intentional_disable_removes_retry_eligibility_even_during_a_probe() {
        let scratch = crate::test_scratch::Scratch::database("attested-probe-disable");
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "attested-probe-disable".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        let handle = GithubHandle {
            app_handle_id: "pending".into(),
            agent_id: "agent-pending".into(),
            app_id: 42,
            installation_id: None,
            credential_reference: "github_app:pending".into(),
            credential_generation: 0,
            status: "disabled".into(),
            proven_at: None,
            connection_principal: "direct".into(),
            connection_id: "github-handle-pending".into(),
        };
        store
            .insert_connection(
                "direct",
                &handle.connection_id,
                "github_rest",
                "active",
                &serde_json::json!({}),
            )
            .unwrap();
        let seed_pending = || {
            store.put_github_handle(&handle).unwrap();
            store
                .inner
                .with_conn_fenced(|conn| {
                    conn.execute("INSERT INTO github_attested_probe VALUES ('pending',1)", [])
                })
                .unwrap();
        };
        fn assert_no_marker(store: &PlexusStore) {
            let markers: i64 = store
                .inner
                .with_read(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM github_attested_probe", [], |row| {
                        row.get(0)
                    })
                })
                .unwrap();
            assert_eq!(markers, 0);
        }

        seed_pending();
        let claim = store
            .claim_attested_probe(&handle, 1, 901, &|| true)
            .unwrap()
            .unwrap();
        // An operator may disable a handle before its first successful proof.
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "UPDATE github_app_handle SET status='disabled' WHERE app_handle_id='pending'",
                    [],
                )
            })
            .unwrap();
        assert_no_marker(&store);
        assert!(!store
            .complete_attested_probe(&handle, claim, 2, &|| true)
            .unwrap());
        assert!(store
            .claim_attested_probe(&handle, 1_000, 1_900, &|| true)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .github_handle_and_bindings("pending")
                .unwrap()
                .unwrap()
                .0
                .status,
            "disabled"
        );

        seed_pending();
        store.retire_github_agent(&handle.agent_id).unwrap();
        assert_no_marker(&store);

        seed_pending();
        store
            .inner
            .with_conn_fenced(|conn| {
                conn.execute(
                    "DELETE FROM github_app_handle WHERE app_handle_id='pending'",
                    [],
                )
            })
            .unwrap();
        assert_no_marker(&store);
    }
}
