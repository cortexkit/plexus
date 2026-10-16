use super::*;

/// Extend a concrete ceiling in the caller's transaction. The generation is the
/// connection's authority version: calls already authorized but not yet sent must
/// revalidate when it changes. Operator widening and handle-grant share this path
/// so neither can change a ceiling without that revalidation.
pub(super) fn extend_connection_ceiling_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    current: &[String],
    added: &[String],
    now: i64,
) -> rusqlite::Result<()> {
    if added.is_empty() {
        return Ok(());
    }
    let mut resulting = current.to_vec();
    resulting.extend_from_slice(added);
    conn.execute(
        "UPDATE connections SET ceiling_selectors=?3, generation=generation+1, updated_at_ms=?4
         WHERE principal=?1 AND connection_id=?2",
        rusqlite::params![
            principal,
            connection_id,
            serde_json::to_string(&resulting)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
            now
        ],
    )?;
    Ok(())
}

impl PlexusStore {
    /// Preview or apply an additive, explicitly named widening. One transaction
    /// protects validation, the ceiling update, the authority-version bump and the
    /// audit from concurrent changes and partial writes. Previews, refusals and
    /// idempotent repeats write nothing. This raises only what may be granted;
    /// the operator must still mint a grant before a caller can use an added action.
    pub fn widen_connection_ceiling(
        &self,
        principal: &str,
        connection_id: &str,
        actions: &[String],
        dry_run: bool,
    ) -> Result<Result<Value, CeremonyRefusal>, StoreError> {
        if actions.is_empty() || actions.iter().any(|action| action.trim().is_empty()) {
            return Ok(Err(CeremonyRefusal::EmptyActionSelectors));
        }
        if actions.iter().any(|action| action.contains('*')) {
            return Ok(Err(CeremonyRefusal::ExplicitActionsRequired));
        }
        let actions: std::collections::BTreeSet<_> = actions.iter().collect();
        self.inner.with_conn_fenced(|conn| {
            let ceiling = match grant_ceiling_on_conn(conn, principal, connection_id)? {
                Ok(ceiling) => ceiling,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let backs_handle: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM github_app_handle
                 WHERE connection_principal=?1 AND connection_id=?2)",
                (principal, connection_id), |row| row.get(0),
            )?;
            if backs_handle || connection_id.starts_with(GITHUB_HANDLE_CONNECTION_PREFIX) {
                return Ok(Err(CeremonyRefusal::HandleCeilingRequiresHandleGrant));
            }
            let mut added = Vec::new();
            let mut unchanged = Vec::new();
            for action in actions {
                let reviewed: Option<String> = conn.query_row(
                    "SELECT risk FROM catalog_actions WHERE principal=?1 AND connection_id=?2
                     AND name=?3 AND status='active' AND quarantine_reason IS NULL",
                    (principal, connection_id, action), |row| row.get(0),
                ).optional()?;
                let Some(risk) = reviewed else {
                    return Ok(Err(CeremonyRefusal::UnreviewedAction(action.clone())));
                };
                let Some(risk) = Risk::parse(&risk) else {
                    return Ok(Err(CeremonyRefusal::InvalidRisk(risk)));
                };
                if !risk.within(ceiling.risk) {
                    return Ok(Err(CeremonyRefusal::RiskAboveCeiling {
                        requested: risk.to_string(), ceiling: ceiling.risk.to_string(),
                    }));
                }
                if ceiling.action_selectors.iter().any(|selector| selector == action || selector == "*") {
                    unchanged.push(action.clone());
                } else {
                    added.push(action.clone());
                }
            }
            let mut resulting = ceiling.action_selectors.clone();
            resulting.extend_from_slice(&added);
            let applied = !dry_run && !added.is_empty();
            if applied {
                let now = now_ms();
                extend_connection_ceiling_on_conn(conn, principal, connection_id, &ceiling.action_selectors, &added, now)?;
                conn.execute(
                    "INSERT INTO audit_journal(principal,actor,acting_principal,connection_id,action,risk,decision,reason_code,gate,args_redaction_summary,outcome,ts)
                     VALUES (?1,'operator',?1,?2,'widen_ceiling',?3,'allow','ceremony_widen_ceiling','operator_ceremony',?4,'applied',?5)",
                    rusqlite::params![principal, connection_id, ceiling.risk.to_string(),
                        serde_json::json!({"connection_id":connection_id,"added_actions":added,"operator":principal}).to_string(), now],
                )?;
            }
            Ok(Ok(serde_json::json!({
                "connection_id":connection_id,"ceiling_risk":ceiling.risk.to_string(),
                "dry_run":dry_run,"applied":applied,"current_ceiling":ceiling.action_selectors,
                "added_actions":added,"unchanged_actions":unchanged,"resulting_ceiling":resulting,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> PlexusStore {
        let store = PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: new_id("widen-ceiling"),
            isolation: cortexkit_store_types::Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap();
        store
            .insert_connection("direct", "ci", "github_actions", "active", &json!({}))
            .unwrap();
        store.inner.with_conn_fenced(|conn| conn.execute_batch(
            "UPDATE connections SET ceiling_risk='read',ceiling_selectors='[\"poll\"]',updated_at_ms=1;"
        )).unwrap();
        for (name, risk, status, quarantine) in [
            ("poll", "read", "active", None),
            ("get_job", "read", "active", None),
            ("outside", "read", "active", None),
            ("write_job", "write", "active", None),
            ("delete_job", "destructive", "active", None),
            ("quarantined", "read", "quarantined", Some("schema_drift")),
            ("disabled", "read", "disabled", None),
            ("quarantine_reason", "read", "active", Some("schema_drift")),
        ] {
            store
                .upsert_catalog_action(&CatalogActionInput {
                    principal: "direct".into(),
                    connection_id: "ci".into(),
                    name: name.into(),
                    title: None,
                    schema: json!({"type":"object"}),
                    schema_hash: format!("sha256:{name}"),
                    risk: risk.into(),
                    severity: "S1".into(),
                    ask_first: false,
                    status: status.into(),
                    quarantine_reason: quarantine.map(str::to_owned),
                    reconciliation: None,
                })
                .unwrap();
        }
        store
    }

    fn snapshot(store: &PlexusStore) -> (String, i64, i64, i64, i64) {
        store.inner.with_read(|conn| conn.query_row(
            "SELECT ceiling_selectors,generation,updated_at_ms,(SELECT COUNT(*) FROM audit_journal),(SELECT COUNT(*) FROM grants) FROM connections WHERE principal='direct' AND connection_id='ci'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )).unwrap()
    }

    fn widen(
        store: &PlexusStore,
        actions: &[&str],
        dry_run: bool,
    ) -> Result<Value, CeremonyRefusal> {
        store
            .widen_connection_ceiling(
                "direct",
                "ci",
                &actions
                    .iter()
                    .map(|action| (*action).into())
                    .collect::<Vec<_>>(),
                dry_run,
            )
            .unwrap()
    }

    fn mint(store: &PlexusStore, action: &str) -> Result<GrantRecord, CeremonyRefusal> {
        store
            .mint_grant_bounded(&GrantMintRequest {
                principal: "direct",
                connection_id: "ci",
                grantee_principal: "reserved:basal",
                authority_kind: "invoke",
                requested_risk: "read",
                requested_selectors: &[action.into()],
                expires_at: None,
            })
            .unwrap()
    }

    #[test]
    fn widen_ceiling_preview_writes_nothing() {
        let store = fixture();
        let before = snapshot(&store);
        let plan = widen(&store, &["get_job", "poll", "get_job"], true).unwrap();
        assert_eq!(plan["current_ceiling"], json!(["poll"]));
        assert_eq!(plan["added_actions"], json!(["get_job"]));
        assert_eq!(plan["unchanged_actions"], json!(["poll"]));
        assert_eq!(plan["resulting_ceiling"], json!(["poll", "get_job"]));
        assert_eq!(plan["applied"], false);
        assert_eq!(snapshot(&store), before);
        assert!(matches!(
            mint(&store, "get_job"),
            Err(CeremonyRefusal::OutsideConnectionCeiling { .. })
        ));
    }

    #[test]
    fn widen_ceiling_apply_is_atomic_idempotent_and_bounds_later_grants() {
        let store = fixture();
        let before = snapshot(&store);
        assert!(matches!(
            mint(&store, "get_job"),
            Err(CeremonyRefusal::OutsideConnectionCeiling { .. })
        ));
        let plan = widen(&store, &["get_job", "poll"], false).unwrap();
        assert_eq!(plan["applied"], true);
        let after = snapshot(&store);
        assert_eq!(after.0, r#"["poll","get_job"]"#);
        assert_eq!(after.1, before.1 + 1);
        assert!(after.2 > before.2);
        assert_eq!(after.3, before.3 + 1);
        assert_eq!(after.4, before.4);
        let audit: (String,String,String,String,String) = store.inner.with_read(|conn|conn.query_row(
            "SELECT principal,actor,acting_principal,connection_id,args_redaction_summary FROM audit_journal WHERE action='widen_ceiling'", [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))).unwrap();
        assert_eq!(
            (
                audit.0.as_str(),
                audit.1.as_str(),
                audit.2.as_str(),
                audit.3.as_str()
            ),
            ("direct", "operator", "direct", "ci")
        );
        assert_eq!(
            serde_json::from_str::<Value>(&audit.4).unwrap(),
            json!({"connection_id":"ci","added_actions":["get_job"],"operator":"direct"})
        );
        let repeat = widen(&store, &["get_job", "poll", "get_job"], false).unwrap();
        assert_eq!(repeat["added_actions"], json!([]));
        assert_eq!(repeat["unchanged_actions"], json!(["get_job", "poll"]));
        assert_eq!(repeat["applied"], false);
        assert_eq!(snapshot(&store), after);
        assert_eq!(
            mint(&store, "get_job").unwrap().action_selectors,
            vec!["get_job"]
        );
        assert!(matches!(
            mint(&store, "outside"),
            Err(CeremonyRefusal::OutsideConnectionCeiling { .. })
        ));
    }

    #[test]
    fn widen_ceiling_requires_active_reviewed_actions() {
        let store = fixture();
        for action in ["unknown", "quarantined", "disabled", "quarantine_reason"] {
            let before = snapshot(&store);
            assert_eq!(
                widen(&store, &["get_job", action], false),
                Err(CeremonyRefusal::UnreviewedAction(action.into())),
                "widening requires an active reviewed action: {action}"
            );
            assert_eq!(snapshot(&store), before);
        }
    }

    #[test]
    fn widen_ceiling_never_raises_risk() {
        let store = fixture();
        for (action, risk) in [("write_job", "write"), ("delete_job", "destructive")] {
            let before = snapshot(&store);
            assert_eq!(
                widen(&store, &["get_job", action], false),
                Err(CeremonyRefusal::RiskAboveCeiling {
                    requested: risk.into(),
                    ceiling: "read".into()
                }),
                "widening must enforce the existing risk ceiling"
            );
            assert_eq!(snapshot(&store), before);
        }
        assert_eq!(
            store
                .connection_ceiling("direct", "ci")
                .unwrap()
                .unwrap()
                .risk,
            Risk::Read
        );
    }

    #[test]
    fn widen_ceiling_requires_named_actions_and_a_live_non_handle_connection() {
        let store = fixture();
        for (actions, expected) in [
            (vec![], CeremonyRefusal::EmptyActionSelectors),
            (vec![" "], CeremonyRefusal::EmptyActionSelectors),
            (vec!["*"], CeremonyRefusal::ExplicitActionsRequired),
            (
                vec!["get_job", "*"],
                CeremonyRefusal::ExplicitActionsRequired,
            ),
        ] {
            let before = snapshot(&store);
            assert_eq!(widen(&store, &actions, false), Err(expected));
            assert_eq!(snapshot(&store), before);
        }
        store
            .inner
            .with_conn_fenced(|conn| conn.execute("UPDATE connections SET status='revoked'", []))
            .unwrap();
        let before = snapshot(&store);
        assert_eq!(
            widen(&store, &["get_job"], false),
            Err(CeremonyRefusal::ConnectionRevoked)
        );
        assert_eq!(snapshot(&store), before);
        store.inner.with_conn_fenced(|conn|conn.execute_batch("UPDATE connections SET status='active'; INSERT INTO github_app_handle(app_handle_id,agent_id,app_id,credential_reference,status,connection_principal,connection_id) VALUES ('handle','agent',1,'github_app:fixture','enabled','direct','ci');")).unwrap();
        let before = snapshot(&store);
        let refusal = widen(&store, &["get_job"], false).unwrap_err();
        assert_eq!(refusal, CeremonyRefusal::HandleCeilingRequiresHandleGrant);
        assert!(refusal.to_string().contains("handle-grant"));
        assert_eq!(snapshot(&store), before);
        store
            .insert_connection(
                "direct",
                "github-handle-unimported",
                "github",
                "active",
                &json!({}),
            )
            .unwrap();
        store.inner.with_conn_fenced(|conn|conn.execute("UPDATE connections SET ceiling_risk='read',ceiling_selectors='[]' WHERE connection_id='github-handle-unimported'",[])).unwrap();
        assert_eq!(
            store
                .widen_connection_ceiling(
                    "direct",
                    "github-handle-unimported",
                    &["get_job".into()],
                    false
                )
                .unwrap(),
            Err(CeremonyRefusal::HandleCeilingRequiresHandleGrant)
        );
    }

    #[test]
    fn widen_ceiling_allows_degraded_and_reauth_and_rolls_back_on_audit_failure() {
        for status in ["degraded", "auth_required"] {
            let store = fixture();
            store
                .inner
                .with_conn_fenced(|conn| conn.execute("UPDATE connections SET status=?1", [status]))
                .unwrap();
            assert_eq!(widen(&store, &["get_job"], false).unwrap()["applied"], true);
        }
        let store = fixture();
        store.inner.with_conn_fenced(|conn|conn.execute_batch("CREATE TRIGGER reject_widen_audit BEFORE INSERT ON audit_journal BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")).unwrap();
        let before = snapshot(&store);
        assert!(store
            .widen_connection_ceiling("direct", "ci", &["get_job".into()], false)
            .is_err());
        assert_eq!(snapshot(&store), before);
    }
}
