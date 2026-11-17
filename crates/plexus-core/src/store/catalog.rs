//! Reviewed catalog observations, manifests, and schema pinning.

use super::*;

/// The open-object schema a catalog row holds before anything has pinned a
/// reviewed argument schema on it. Governance's undeclared-argument check
/// treats a schema without `properties` as open, so a row holding this refuses
/// no argument at all.
fn placeholder_catalog_schema() -> Value {
    serde_json::json!({"type": "object", "additionalProperties": true})
}

/// The refusal for a ticket whose ceiling reaches beyond the ceiling a
/// connection already records, or `None` when it fits inside. A connection's
/// ceiling is permanent once set, so a later ticket may only restate it or ask
/// for less.
pub(super) fn wider_than_recorded(
    requested: &Ceiling,
    recorded_risk: &str,
    recorded_selectors: &str,
) -> rusqlite::Result<Option<CeremonyRefusal>> {
    let Some(risk) = Risk::parse(recorded_risk) else {
        return Ok(Some(CeremonyRefusal::InvalidRisk(
            recorded_risk.to_string(),
        )));
    };
    let selectors = parse_string_list(recorded_selectors)?;
    if !requested.risk.within(risk) {
        return Ok(Some(CeremonyRefusal::RiskAboveCeiling {
            requested: requested.risk.to_string(),
            ceiling: risk.to_string(),
        }));
    }
    // A stored wildcard admits everything, as it does when a grant is minted.
    if selectors.iter().any(|selector| selector == "*") {
        return Ok(None);
    }
    Ok(requested
        .action_selectors
        .iter()
        .find(|selector| !selectors.contains(selector))
        .map(|outside| CeremonyRefusal::OutsideConnectionCeiling {
            action: outside.clone(),
            ceiling: selectors.clone(),
        }))
}

/// Apply one catalog observation inside the caller's transaction, preserving
/// review decisions and cascading reservation and subscription invalidation.
fn refresh_catalog_action_on_conn(
    conn: &rusqlite::Connection,
    mut input: CatalogActionInput,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    let schema = serde_json::to_string(&input.schema)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    let reconciliation = input
        .reconciliation
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    type PreviousCatalogObservation = (String, String, String, Option<String>, Option<String>);
    let previous: Option<PreviousCatalogObservation> = conn
        .query_row(
            "SELECT schema_hash, schema_json, status, quarantine_reason, reviewed_schema_json
                     FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
            (&input.principal, &input.connection_id, &input.name),
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let mut reviewed_schema = None;
    if let Some((
        previous_schema_hash,
        previous_schema,
        previous_status,
        previous_reason,
        previous_reviewed_schema,
    )) = previous
    {
        // Active rows carry the approved schema, including immediately after
        // repin. Disabled rows retain that authority in their snapshot instead:
        // the last observed schema may still be awaiting review.
        let approved_schema = if previous_status == "disabled" {
            previous_reviewed_schema
                .as_deref()
                .unwrap_or(&previous_schema)
        } else {
            &previous_schema
        };
        let approved_hash = if previous_status == "disabled" && previous_reviewed_schema.is_some() {
            jcs_sqlite_hash(&parse_json_column::<Value>(approved_schema)?)?
        } else {
            previous_schema_hash.clone()
        };
        let is_placeholder =
            parse_json_column(approved_schema).ok() == Some(placeholder_catalog_schema());
        if previous_status == "quarantined" {
            input.status = "quarantined".to_string();
            input.quarantine_reason = previous_reason;
        } else if approved_hash != input.schema_hash && !is_placeholder && input.status == "active"
        {
            input.status = "quarantined".to_string();
            input.quarantine_reason = Some("schema_changed_requires_review".to_string());
        }
        if previous_status != "quarantined" && input.status == "quarantined" {
            reviewed_schema = Some(approved_schema.to_string());
        }
    } else if matches!(input.risk.as_str(), "write" | "destructive") && input.status == "active" {
        input.status = "quarantined".to_string();
        input.quarantine_reason = Some("new_write_requires_review".to_string());
    }
    upsert_catalog_action_row(
        conn,
        &input,
        &schema,
        reconciliation.as_deref(),
        reviewed_schema.as_deref(),
        observed_at_ms,
    )?;
    if input.status == "quarantined" {
        conn.execute(
            "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
            (&input.principal, &input.connection_id, &input.name),
        )?;
    }
    suspend_subscriptions_for_action(
        conn,
        &input.principal,
        &input.connection_id,
        &input.name,
        catalog_suspension_reason(&input),
        observed_at_ms,
    )?;
    Ok(())
}

fn disable_catalog_action_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    observed_at_ms: i64,
) -> rusqlite::Result<bool> {
    // A disabled row's snapshot must identify the approved schema. For an
    // active row that is the current schema (repin need not clear an older
    // snapshot); for a quarantined row the current schema is not approved.
    let changed = conn.execute(
        "UPDATE catalog_actions SET status = 'disabled',
                        reviewed_schema_json = CASE WHEN status = 'active' THEN schema_json
                            ELSE reviewed_schema_json END,
                        quarantine_reason = NULL, generation = generation + 1,
                        last_seen_at_ms = ?1
                 WHERE principal = ?2 AND connection_id = ?3 AND name = ?4
                   AND status != 'disabled'",
        rusqlite::params![observed_at_ms, principal, connection_id, action],
    )?;
    if changed != 0 {
        conn.execute(
            "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
            (principal, connection_id, action),
        )?;
    }
    suspend_subscriptions_for_action(
        conn,
        principal,
        connection_id,
        action,
        Some("disabled"),
        observed_at_ms,
    )?;
    Ok(changed != 0)
}

/// Whether a manifest seed may overwrite catalog rows that already exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedMode {
    /// Write every declared action, replacing an existing row (a new
    /// connection's first seed).
    UpsertAll,
    /// Insert missing actions and refresh reviewed policy metadata, preserving
    /// existing operator status and schema-pin decisions.
    AddMissing,
}

/// Seed reviewed manifest declarations in the caller's transaction. UpsertAll
/// is reserved for new connections; repeat seeds preserve pins and operator state
/// while updating the reviewed policy metadata of existing rows.
pub(crate) fn seed_catalog_from_manifest_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    app_key: &str,
    mode: SeedMode,
) -> rusqlite::Result<usize> {
    seed_catalog_actions_from_manifest_on_conn(conn, principal, connection_id, app_key, mode, None)
}

/// Use the reviewed seeder for a bounded set of actions without reconciling
/// unrelated catalog rows during an operator grant.
pub(crate) fn seed_catalog_actions_from_manifest_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    app_key: &str,
    mode: SeedMode,
    only: Option<&[String]>,
) -> rusqlite::Result<usize> {
    let source: Option<String> = conn.query_row(
        "SELECT manifest_json FROM app_manifests WHERE principal=?1 AND key=?2 AND status='active'",
        (CATALOG_PRINCIPAL, app_key), |row| row.get(0),
    ).optional()?;
    let Some(source) = source else { return Ok(0) };
    let manifest: Value = parse_json_column(&source)?;
    let tier = manifest.get("tier").and_then(Value::as_str).unwrap_or("S4");
    let declared_ask_first: Vec<Risk> = manifest
        .get("defaults")
        .and_then(|defaults| defaults.get("ask_first_risk"))
        .and_then(Value::as_array)
        .map(|risks| {
            risks
                .iter()
                .filter_map(|risk| risk.as_str().and_then(Risk::parse))
                .collect()
        })
        .unwrap_or_default();
    let actions = manifest.get("actions_baseline").and_then(Value::as_array);
    let mut inserted = 0;
    let mut skipped = std::collections::BTreeMap::new();
    for action in actions.into_iter().flatten() {
        let Some(name) = action.get("name").and_then(Value::as_str) else {
            skipped.insert("<unnamed>".to_string(), "action_name_missing");
            continue;
        };
        if only.is_some_and(|names| !names.iter().any(|listed| listed == name)) {
            continue;
        }
        // An unclassified risk must not be seeded as a permissive read.
        let Some(parsed_risk) = action
            .get("risk")
            .and_then(Value::as_str)
            .and_then(Risk::parse)
        else {
            skipped.insert(
                name.chars()
                    .take(MAX_DIAGNOSTIC_ACTION_CHARS)
                    .filter(|ch| !ch.is_control())
                    .collect::<String>(),
                "risk_unclassified",
            );
            continue;
        };
        let risk = parsed_risk.to_string();
        let ask_first = crate::manifest::action_asks_first(
            parsed_risk,
            &declared_ask_first,
            action
                .get("ask_first")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            action.get("recipients").is_some(),
        );
        if mode == SeedMode::AddMissing {
            let reconciliation = action
                .get("reconciliation")
                .filter(|value| !value.is_null())
                .map(serde_json::to_string)
                .transpose()
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
            // A reviewed policy change must reach handle connections even when
            // they never perform discovery. Do not repin or reactivate a row:
            // those are separate operator decisions, not catalog policy.
            let updated = conn.execute(
                "UPDATE catalog_actions SET risk=?4, severity=?5, ask_first=?6,
                 reconciliation_json=?7, generation=generation + CASE
                   WHEN risk IS NOT ?4 OR severity IS NOT ?5 OR ask_first IS NOT ?6
                     OR reconciliation_json IS NOT ?7 THEN 1 ELSE 0 END
                 WHERE principal=?1 AND connection_id=?2 AND name=?3",
                rusqlite::params![
                    principal,
                    connection_id,
                    name,
                    risk,
                    tier,
                    ask_first,
                    reconciliation
                ],
            )?;
            if updated != 0 {
                suspend_subscriptions_for_action(
                    conn,
                    principal,
                    connection_id,
                    name,
                    (parsed_risk != Risk::Read).then_some("risk_drift"),
                    now_ms(),
                )?;
                continue;
            }
        }
        // Pin a reviewed http.args_schema or input_schema when declared. An
        // action with neither starts open until discovery supplies its schema.
        let schema = action
            .pointer("/http/args_schema")
            .or_else(|| action.get("input_schema"))
            .cloned()
            .unwrap_or_else(placeholder_catalog_schema);
        // A malformed schema hash cannot become a usable catalog action.
        let Ok(schema_hash) = crate::jcs::jcs_sha256(&schema) else {
            skipped.insert(
                name.chars()
                    .take(MAX_DIAGNOSTIC_ACTION_CHARS)
                    .filter(|ch| !ch.is_control())
                    .collect::<String>(),
                "schema_unhashable",
            );
            continue;
        };
        let input = CatalogActionInput {
            connection_id: connection_id.to_string(),
            principal: principal.to_string(),
            name: name.to_string(),
            title: Some(name.to_string()),
            schema,
            schema_hash,
            risk: risk.to_string(),
            severity: tier.to_string(),
            ask_first,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: action.get("reconciliation").cloned(),
        };
        let schema = serde_json::to_string(&input.schema)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
        let reconciliation = input
            .reconciliation
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
        upsert_catalog_action_row(
            conn,
            &input,
            &schema,
            reconciliation.as_deref(),
            None,
            now_ms(),
        )?;
        inserted += 1;
    }
    for (action, reason) in skipped {
        crate::diag!(warn storage: "catalog action skipped: app={app_key:?} action={action:?} reason={reason}");
    }
    Ok(inserted)
}

fn upsert_catalog_action_row(
    conn: &rusqlite::Connection,
    input: &CatalogActionInput,
    schema: &str,
    reconciliation: Option<&str>,
    reviewed_schema: Option<&str>,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO catalog_actions
            (connection_id, principal, name, title, schema_json, schema_hash,
             risk, severity, status, quarantine_reason, reconciliation_json,
             ask_first, first_seen_at_ms, last_seen_at_ms, generation,
             reviewed_schema_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, 1, ?14)
         ON CONFLICT(principal, connection_id, name) DO UPDATE SET
            title = excluded.title, schema_json = excluded.schema_json,
            schema_hash = excluded.schema_hash, risk = excluded.risk,
            severity = excluded.severity, status = excluded.status,
            quarantine_reason = excluded.quarantine_reason,
            reconciliation_json = excluded.reconciliation_json,
            ask_first = excluded.ask_first,
            reviewed_schema_json = COALESCE(
                excluded.reviewed_schema_json, catalog_actions.reviewed_schema_json
            ),
            last_seen_at_ms = excluded.last_seen_at_ms,
            generation = CASE
                WHEN catalog_actions.schema_hash IS NOT excluded.schema_hash
                  OR catalog_actions.risk IS NOT excluded.risk
                  OR catalog_actions.severity IS NOT excluded.severity
                  OR catalog_actions.status IS NOT excluded.status
                  OR catalog_actions.quarantine_reason IS NOT excluded.quarantine_reason
                  OR catalog_actions.reconciliation_json IS NOT excluded.reconciliation_json
                  OR catalog_actions.ask_first IS NOT excluded.ask_first
                THEN catalog_actions.generation + 1
                ELSE catalog_actions.generation
            END",
        rusqlite::params![
            input.connection_id,
            input.principal,
            input.name,
            input.title,
            schema,
            input.schema_hash,
            input.risk,
            input.severity,
            input.status,
            input.quarantine_reason,
            reconciliation,
            input.ask_first,
            observed_at_ms,
            reviewed_schema,
        ],
    )?;
    Ok(())
}

fn catalog_suspension_reason(input: &CatalogActionInput) -> Option<&'static str> {
    match input.status.as_str() {
        "quarantined" => Some("quarantined"),
        "disabled" => Some("disabled"),
        _ if input.risk != "read" => Some("risk_drift"),
        _ => None,
    }
}

/// Suspend active subscriptions when the refreshed catalog no longer confirms
/// that their action is read-only. The catalog caller invokes this helper inside
/// its write transaction, and this helper records the suspension reason before
/// that transaction commits.
fn suspend_subscriptions_for_action(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    base_reason: Option<&str>,
    observed_at_ms: i64,
) -> rusqlite::Result<()> {
    let subscriptions = {
        let mut statement = conn.prepare(
            "SELECT subscription_id, CASE WHEN cursor_kind='probe' THEN ?4 ELSE schema_hash END,
                    last_success_at_ms, created_at_ms
             FROM trigger_subscriptions
              WHERE principal = ?1 AND connection_id = ?2
                AND status = 'active'
                AND (action = ?3 OR (cursor_kind = 'probe' AND EXISTS (
                    SELECT 1 FROM probe_subscriptions p, json_each(p.actions) a
                    WHERE p.subscription_id = trigger_subscriptions.subscription_id AND a.value = ?3)))",
        )?;
        let current_hash = action_schema_hash(conn, principal, connection_id, action)?;
        let rows =
            statement.query_map((principal, connection_id, action, current_hash), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let current_hash = if subscriptions.is_empty() {
        None
    } else {
        Some(action_schema_hash(conn, principal, connection_id, action)?)
    };
    for (subscription_id, pinned_schema_hash, last_success_at_ms, created_at_ms) in subscriptions {
        let reason = if Some(&pinned_schema_hash) != current_hash.as_ref() {
            Some("schema_changed")
        } else {
            base_reason
        };
        let Some(reason) = reason else {
            continue;
        };
        let changed = conn.execute(
            "UPDATE trigger_subscriptions
             SET status = 'suspended', suspended_reason = ?1,
                 generation = generation + 1
             WHERE subscription_id = ?2 AND status = 'active'",
            (reason, &subscription_id),
        )?;
        if changed != 0 {
            insert_gap_row(
                conn,
                principal,
                connection_id,
                &subscription_id,
                last_success_at_ms.unwrap_or(created_at_ms),
                observed_at_ms,
                reason,
                observed_at_ms,
            )?;
        }
    }
    Ok(())
}

fn action_schema_hash(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
) -> rusqlite::Result<String> {
    conn.query_row(
        "SELECT schema_hash FROM catalog_actions
         WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
        (principal, connection_id, action),
        |row| row.get(0),
    )
}

/// The column list every `catalog_actions` read selects, in the order
/// [`map_catalog_action_row`] expects.
///
/// Kept beside the mapper because the two are one unit: the mapper reads by
/// POSITIONAL index, so a query that selects the same columns in a different
/// order silently mis-assigns fields of the same type rather than failing.
pub(super) const CATALOG_ACTION_COLUMNS: &str = concat!(
    "connection_id, principal, name, title, schema_json, schema_hash,
     risk, severity, status, quarantine_reason, reconciliation_json, ask_first, generation, ",
    app_retired_predicate!()
);

/// Build a [`CatalogAction`] from a row selecting [`CATALOG_ACTION_COLUMNS`].
///
/// Shared by the active-only list projection and the single-action accessor,
/// which had identical twenty-line bodies. The duplication was a live hazard
/// rather than an aesthetic one: adding a column means updating both, and the
/// one that is missed keeps returning a stale default for that field while
/// every test of the other path passes. Migration 8 added `ask_first` with a
/// fail-closed default of true, so exactly that miss would have made an action
/// ask for approval through one read and not the other.
pub(super) fn map_catalog_action_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CatalogAction> {
    let schema: String = row.get(4)?;
    let reconciliation: Option<String> = row.get(10)?;
    // Retirement is projected once without rewriting the reviewed action row.
    let retired: bool = row.get(13)?;
    Ok(CatalogAction {
        connection_id: row.get(0)?,
        principal: row.get(1)?,
        name: row.get(2)?,
        title: row.get(3)?,
        schema: parse_json_column(&schema)?,
        schema_hash: row.get(5)?,
        risk: row.get(6)?,
        severity: row.get(7)?,
        status: if retired {
            "disabled".into()
        } else {
            row.get(8)?
        },
        quarantine_reason: if retired {
            Some("app_retired".into())
        } else {
            row.get(9)?
        },
        reconciliation: reconciliation
            .as_deref()
            .map(parse_json_column)
            .transpose()?,
        ask_first: row.get(11)?,
        generation: row.get(12)?,
    })
}

impl PlexusStore {
    /// Mark an observed action quarantined and invalidate outstanding invokes
    /// that were authorized against the previous catalog generation. A trigger
    /// on the action is suspended in this same fenced transaction, so the
    /// catalog cannot expose a quarantined action while its subscription remains
    /// active.
    #[cfg(any(test, feature = "test-support"))]
    pub fn quarantine_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let observed_at_ms = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE catalog_actions SET status = 'quarantined',
                        quarantine_reason = ?1,
                        reviewed_schema_json = CASE
                            WHEN status <> 'quarantined' THEN schema_json
                            ELSE reviewed_schema_json
                        END,
                        generation = generation + 1, last_seen_at_ms = ?2
                 WHERE principal = ?3 AND connection_id = ?4 AND name = ?5",
                rusqlite::params![reason, observed_at_ms, principal, connection_id, action],
            )?;
            if changed != 0 {
                conn.execute(
                    "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
                    (principal, connection_id, action),
                )?;
            }
            suspend_subscriptions_for_action(
                conn,
                principal,
                connection_id,
                action,
                Some("quarantined"),
                observed_at_ms,
            )?;
            Ok(changed != 0)
        })
    }

    /// Re-activate one quarantined read action after a human has reviewed the
    /// current schema. The action transition, subscription re-pins, and
    /// generation invalidation share one fence so an in-flight poll or reservation
    /// cannot survive a review against the prior catalog generation.
    pub fn repin_reviewed_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        expected_schema_hash: &str,
    ) -> Result<Result<CatalogAction, RepinActionRefusal>, StoreError> {
        self.repin_reviewed_action_with(
            principal,
            connection_id,
            action,
            expected_schema_hash,
            None,
        )
    }

    /// [`Self::repin_reviewed_action`] with its audit row, built from the
    /// re-activated action, appended in the re-pin's own fenced transaction.
    /// A refusal writes neither the re-pin nor a row.
    pub fn repin_reviewed_action_audited(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        expected_schema_hash: &str,
        audit: &dyn Fn(&CatalogAction) -> AuditRecord,
    ) -> Result<Result<CatalogAction, RepinActionRefusal>, StoreError> {
        self.repin_reviewed_action_with(
            principal,
            connection_id,
            action,
            expected_schema_hash,
            Some(audit),
        )
    }

    fn repin_reviewed_action_with(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        expected_schema_hash: &str,
        audit: AuditFor<'_, CatalogAction>,
    ) -> Result<Result<CatalogAction, RepinActionRefusal>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let current: Option<(String, String, String)> = conn
                .query_row(
                    "SELECT schema_hash, risk, status FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
                    (principal, connection_id, action),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((current_schema_hash, risk, status)) = current else {
                return Ok(Err(RepinActionRefusal::ActionNotFound));
            };
            if risk != "read" {
                return Ok(Err(RepinActionRefusal::RiskNotRead(risk)));
            }
            if current_schema_hash != expected_schema_hash {
                return Ok(Err(RepinActionRefusal::ExpectedHashMismatch {
                    expected: expected_schema_hash.to_string(),
                    current: current_schema_hash,
                }));
            }

            // The status predicate belongs in this statement rather than only in
            // the read above: a disable that lands between the read and write must
            // remain disabled, not be laundered into active by this review path.
            let activated = conn.execute(
                "UPDATE catalog_actions
                 SET status = 'active', quarantine_reason = NULL, generation = generation + 1
                 WHERE principal = ?1 AND connection_id = ?2 AND name = ?3
                   AND status = 'quarantined'",
                (principal, connection_id, action),
            )?;
            if activated == 0 {
                return Ok(Err(RepinActionRefusal::ActionNotQuarantined(status)));
            }
            conn.execute(
                "UPDATE reservations SET status = 'invalidated'
                 WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                   AND status = 'reserved'",
                (principal, connection_id, action),
            )?;

            // Every subscription now pins the reviewed current shape. Only schema
            // drift is resolved by this ceremony; another suspension reason is a
            // separate safety decision and remains suspended with its cursor intact.
            conn.execute(
                "UPDATE trigger_subscriptions
                 SET schema_hash = ?1,
                     status = CASE
                         WHEN status = 'suspended' AND suspended_reason = 'schema_changed'
                             THEN 'active'
                         ELSE status
                     END,
                     suspended_reason = CASE
                         WHEN status = 'suspended' AND suspended_reason = 'schema_changed'
                             THEN NULL
                         ELSE suspended_reason
                     END,
                     generation = generation + 1
                 WHERE principal = ?2 AND connection_id = ?3 AND action = ?4
                   AND (schema_hash IS NOT ?1
                        OR (status = 'suspended' AND suspended_reason = 'schema_changed'))",
                (expected_schema_hash, principal, connection_id, action),
            )?;

            let reactivated = conn.query_row(
                &format!(
                    "SELECT {CATALOG_ACTION_COLUMNS}
                     FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                (principal, connection_id, action),
                map_catalog_action_row,
            )?;
            append_audit_for(conn, audit, &reactivated)?;
            Ok(Ok(reactivated))
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn upsert_catalog_action(&self, input: &CatalogActionInput) -> Result<(), StoreError> {
        let schema = serde_json::to_string(&input.schema)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let reconciliation = input
            .reconciliation
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let observed_at_ms = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let reviewed_schema: Option<String> = if input.status == "quarantined" {
                conn.query_row(
                    "SELECT schema_json, status FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3",
                    (&input.principal, &input.connection_id, &input.name),
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .and_then(|(schema, status)| (status != "quarantined").then_some(schema))
            } else {
                None
            };
            upsert_catalog_action_row(
                conn,
                input,
                &schema,
                reconciliation.as_deref(),
                reviewed_schema.as_deref(),
                observed_at_ms,
            )?;
            if input.status == "quarantined" {
                conn.execute(
                    "UPDATE reservations SET status = 'invalidated'
                     WHERE principal = ?1 AND connection_id = ?2 AND action = ?3
                       AND status = 'reserved'",
                    (&input.principal, &input.connection_id, &input.name),
                )?;
            }
            suspend_subscriptions_for_action(
                conn,
                &input.principal,
                &input.connection_id,
                &input.name,
                catalog_suspension_reason(input),
                observed_at_ms,
            )?;
            Ok(())
        })
    }

    /// Seed the observed catalog from the reviewed manifest for a new connection.
    /// Keeping the seeder connection-scoped lets handle import use the same
    /// catalog logic within its transaction, without publishing partial handles.
    pub fn seed_catalog_from_manifest(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
    ) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            seed_catalog_from_manifest_on_conn(
                conn,
                principal,
                connection_id,
                app_key,
                SeedMode::AddMissing,
            )
        })
    }

    /// Apply a transport catalog refresh. New or schema-changed write actions
    /// are quarantined until a reviewer explicitly reactivates them. The
    /// catalog write and any trigger suspension happen in one fenced
    /// transaction, so a refresh cannot leave a risky action pollable.
    #[cfg(any(test, feature = "test-support"))]
    pub fn refresh_catalog_action(&self, input: CatalogActionInput) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| refresh_catalog_action_on_conn(conn, input, now_ms()))
    }

    /// Commit a complete catalog observation, including missing-action cascades,
    /// atomically. An empty observation cannot erase a live catalog.
    pub fn reconcile_catalog_actions(
        &self,
        principal: &str,
        connection_id: &str,
        actions: &[CatalogActionInput],
    ) -> Result<(), StoreError> {
        if actions
            .iter()
            .any(|input| input.principal != principal || input.connection_id != connection_id)
        {
            return Err(StoreError::Backend(
                "catalog observation refused: scope mismatch".into(),
            ));
        }
        let accepted = self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare("SELECT name FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND status <> 'disabled'")?;
            let existing: Vec<String> = statement.query_map((principal, connection_id), |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            if actions.is_empty() && !existing.is_empty() {
                return Ok(false);
            }
            let now = now_ms();
            for input in actions {
                refresh_catalog_action_on_conn(conn, input.clone(), now)?;
            }
            for name in existing {
                if !actions.iter().any(|input| input.name == name) {
                    disable_catalog_action_on_conn(conn, principal, connection_id, &name, now)?;
                }
            }
            Ok(true)
        })?;
        if !accepted {
            return Err(StoreError::Backend(
                "catalog observation refused: empty observation".into(),
            ));
        }
        Ok(())
    }

    pub fn list_catalog_actions(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<CatalogAction>, StoreError> {
        self.list_catalog_actions_with_status(principal, connection_id, true)
    }

    /// Return every observed action, including quarantined and disabled rows.
    /// The public catalog projection above remains active-only for callers that
    /// are selecting actions to invoke.
    pub fn list_catalog_actions_all(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<CatalogAction>, StoreError> {
        self.list_catalog_actions_with_status(principal, connection_id, false)
    }

    fn list_catalog_actions_with_status(
        &self,
        principal: &str,
        connection_id: &str,
        active_only: bool,
    ) -> Result<Vec<CatalogAction>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT {CATALOG_ACTION_COLUMNS}
                  FROM catalog_actions
                  WHERE principal = ?1 AND connection_id = ?2
                    AND (?3 = 0 OR (status = 'active' AND NOT {APP_RETIRED_PREDICATE}))
                  ORDER BY name"
            ))?;
            let rows = statement.query_map(
                (principal, connection_id, if active_only { 1 } else { 0 }),
                map_catalog_action_row,
            )?;
            rows.collect()
        })
    }

    /// Disable an action missing from a successful catalog refresh and consume
    /// any reservation that was approved against it. Any trigger on the action
    /// is suspended in this same fenced transaction.
    #[cfg(any(test, feature = "test-support"))]
    pub fn disable_catalog_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            disable_catalog_action_on_conn(conn, principal, connection_id, action, now_ms())
        })
    }

    pub fn catalog_last_seen_at(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT MAX(last_seen_at_ms) FROM catalog_actions
                 WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| row.get(0),
            )
        })
    }

    /// Read one catalog action INCLUDING quarantined and disabled rows. The
    /// public `list_catalog_actions` projection is active-only because callers
    /// use it to choose an action to invoke; this accessor exists for operators
    /// and tests that need to see why an action is not available.
    pub fn catalog_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<CatalogAction>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {CATALOG_ACTION_COLUMNS}
                 FROM catalog_actions
                 WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                (principal, connection_id, action),
                map_catalog_action_row,
            )
            .optional()
        })
    }

    /// Read the current and last approved schemas for an operator reviewing a
    /// quarantined action. Ordinary catalog listings omit the approval snapshot.
    pub fn catalog_action_review(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<CatalogActionReview>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {CATALOG_ACTION_COLUMNS}, reviewed_schema_json
                     FROM catalog_actions
                     WHERE principal = ?1 AND connection_id = ?2 AND name = ?3"
                ),
                (principal, connection_id, action),
                |row| {
                    let reviewed_schema: Option<String> = row.get(14)?;
                    Ok(CatalogActionReview {
                        action: map_catalog_action_row(row)?,
                        reviewed_schema: reviewed_schema
                            .as_deref()
                            .map(parse_json_column)
                            .transpose()?,
                    })
                },
            )
            .optional()
        })
    }

    /// Read the reviewed manifest's declared poll shape. Missing manifests,
    /// actions and poll declarations return None.
    pub fn poll_shape(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<PollShape>, StoreError> {
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(None);
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(None);
        };
        let manifest = document.map_err(StoreError::Backend)?;
        Ok(manifest
            .actions_baseline
            .iter()
            .find(|candidate| candidate.name == action)
            .and_then(|baseline| baseline.poll.clone()))
    }

    /// The top-level argument names an action's reviewed manifest declares in
    /// `http.args_schema.properties`, read from the manifest rather than the
    /// pinned catalog row because a row seeded before the manifest's schema was
    /// pinned may still hold the open placeholder schema. `None` when the
    /// connection, its manifest, the action or its REST schema is missing.
    ///
    /// Plexus code that builds vendor arguments for a REST action uses this to
    /// send each call only the arguments that action declares: the REST
    /// transport sends every non-path argument to the vendor.
    pub fn reviewed_arg_names(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
    ) -> Result<Option<std::collections::BTreeSet<String>>, StoreError> {
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(None);
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(None);
        };
        let manifest = document.map_err(StoreError::Backend)?;
        Ok(manifest
            .actions_baseline
            .iter()
            .find(|candidate| candidate.name == action)
            .and_then(|baseline| baseline.http.as_ref())
            .and_then(|http| http.args_schema.get("properties"))
            .and_then(Value::as_object)
            .map(|properties| properties.keys().cloned().collect()))
    }

    /// List the app manifests available to connect. This is the only
    /// pre-connection discovery surface: every other catalog projection is
    /// scoped to an existing connection, so without this an operator on a
    /// fresh install cannot see which vendors the module even carries.
    /// Returns catalog metadata only — no transport URLs, credential
    /// bindings, or connection state.
    ///
    /// Manifests are ingested module-wide under [`CATALOG_PRINCIPAL`], not per
    /// caller, so the listing is shared; `principal` scopes only the
    /// per-vendor connection count, which is caller-private.
    pub fn list_manifest_summaries(
        &self,
        principal: &str,
    ) -> Result<Vec<ManifestSummary>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT m.key, m.schema_version, m.manifest_json, m.ingested_at_ms,
                        (SELECT COUNT(*) FROM connections c
                          WHERE c.principal = ?2 AND c.app_key = m.key
                            AND c.status <> 'revoked')
                 FROM app_manifests m
                 WHERE m.principal = ?1 AND m.status = 'active' ORDER BY m.key",
            )?;
            let rows = statement.query_map([CATALOG_PRINCIPAL, principal], |row| {
                let key: String = row.get(0)?;
                let schema_version: u32 = row.get(1)?;
                let document: String = row.get(2)?;
                let ingested_at_ms: i64 = row.get(3)?;
                let connection_count: i64 = row.get(4)?;
                let manifest: crate::manifest::AppManifest = parse_json_column(&document)?;
                Ok(ManifestSummary {
                    key,
                    name: manifest.name,
                    description: manifest.description,
                    tier: manifest.tier.catalog_label().to_string(),
                    reuse_path: manifest.reuse_path.catalog_label().to_string(),
                    auth_mode: manifest.auth.mode.catalog_label().to_string(),
                    availability: manifest.availability.catalog_label().to_string(),
                    action_count: manifest.actions_baseline.len(),
                    required_filters: manifest.resource_filters.required.clone(),
                    schema_version,
                    ingested_at_ms,
                    connection_count,
                })
            })?;
            rows.collect()
        })
    }

    /// Return the reviewed catalog manifest, checking its stored content hash even
    /// on a cache hit. The hash, rather than a per-action generation, also detects
    /// manifest replacement by another writer or by a rollback.
    pub fn cached_manifest(
        &self,
        app_key: &str,
    ) -> Result<std::sync::Arc<AppManifest>, StoreError> {
        self.parsed_manifest(CATALOG_PRINCIPAL, app_key)?
            .ok_or_else(|| StoreError::Backend(format!("manifest missing: {app_key}")))?
            .map_err(StoreError::Backend)
    }

    /// Preserve missing documents and parse errors separately from storage
    /// failures so tolerant projections can fail closed without hiding I/O errors.
    pub(crate) fn parsed_manifest(
        &self,
        principal: &str,
        key: &str,
    ) -> Result<Option<Result<std::sync::Arc<AppManifest>, String>>, StoreError> {
        let hash: Option<String> = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT content_hash FROM app_manifests WHERE principal=?1 AND key=?2",
                (principal, key),
                |row| row.get(0),
            )
            .optional()
        })?;
        let Some(hash) = hash else {
            return Ok(None);
        };
        let mut cache = self
            .manifest_cache
            .lock()
            .map_err(|_| StoreError::Backend("manifest cache poisoned".into()))?;
        let cache_key = (principal.to_owned(), key.to_owned());
        if let Some((cached_hash, manifest)) = cache.get(&cache_key) {
            if cached_hash == &hash {
                return Ok(Some(Ok(manifest.clone())));
            }
        }
        // Re-read hash and document together on a miss; the row may have changed
        // since the cheap hash lookup, and that newer document needs its own key.
        let row: Option<(String, String)> = self.inner.with_read(|conn| {
            conn.query_row("SELECT content_hash,manifest_json FROM app_manifests WHERE principal=?1 AND key=?2",
                (principal, key), |row| Ok((row.get(0)?,row.get(1)?))).optional()
        })?;
        let Some((hash, json)) = row else {
            return Ok(None);
        };
        let manifest = match serde_json::from_str::<AppManifest>(&json) {
            Ok(manifest) => std::sync::Arc::new(manifest),
            Err(error) => return Ok(Some(Err(error.to_string()))),
        };
        cache.insert(cache_key, (hash, manifest.clone()));
        Ok(Some(Ok(manifest)))
    }

    pub fn manifest_json(&self, principal: &str, key: &str) -> Result<Option<Value>, StoreError> {
        self.inner.with_read(|conn| {
            let json: Option<String> = conn
                .query_row(
                    "SELECT manifest_json FROM app_manifests WHERE principal = ?1 AND key = ?2",
                    (principal, key),
                    |row| row.get(0),
                )
                .optional()?;
            json.map(|value| parse_json_column(&value)).transpose()
        })
    }

    /// Store a manifest, and when it replaces a stored one with different
    /// content, append its `manifest_changed` audit row in the same fenced
    /// transaction. `changed` in the outcome is exactly whether that row was
    /// written.
    pub fn upsert_manifest(
        &self,
        principal: &str,
        ingested: &crate::manifest::IngestedManifest,
    ) -> Result<ManifestWriteOutcome, StoreError> {
        let json = serde_json::to_string(&ingested.json)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let key = &ingested.manifest.key;
        let schema_version = ingested.manifest.schema_version;
        let hash = &ingested.content_hash;
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let previous_row: Option<(String,String)> = conn.query_row(
                "SELECT content_hash,manifest_json FROM app_manifests WHERE principal=?1 AND key=?2",
                (principal,key), |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional()?;
            let previous = previous_row.as_ref().map(|row| row.0.clone());
            let recipient_declarations = |value: &Value| -> Value {
                serde_json::json!(value["actions_baseline"].as_array().into_iter().flatten()
                    .filter(|action| action.get("recipients").is_some())
                    .map(|action| serde_json::json!([action["name"],action["recipients"],action["input_schema"],action.pointer("/http/args_schema")]))
                    .collect::<Vec<_>>())
            };
            let old = if principal == CATALOG_PRINCIPAL {
                previous_row.as_ref().map(|row| serde_json::from_str::<Value>(&row.1)).transpose()
            } else { Ok(None) };
            let corrupt_old = old.is_err();
            let old = old.ok().flatten().unwrap_or(Value::Null);
            if principal == CATALOG_PRINCIPAL
                && (corrupt_old || recipient_declarations(&old) != recipient_declarations(&ingested.json))
            {
                // If the reviewed manifest changes an action's recipient
                // declaration, invalidate outstanding reservations so they
                // cannot send under the old declaration. The catalog manifest
                // is shared by every owner's connections to the app, so every
                // such connection is affected; a reservation is matched by its
                // owner as well as its connection id, so another app's
                // connection that shares an id is not.
                conn.execute("UPDATE connections SET generation=generation+1 WHERE app_key=?1", [key])?;
                conn.execute("UPDATE reservations SET status='invalidated' WHERE status='reserved' AND (principal, connection_id) IN (SELECT principal, connection_id FROM connections WHERE app_key=?1)", [key])?;
            }
            if principal == CATALOG_PRINCIPAL {
                // An action that declares recipients always asks first (the
                // seed sets it), and that must hold for connections that
                // existed before the declaration too, or old and new
                // connections to one app would disagree.
                let recipient_actions: Vec<String> = ingested
                    .json["actions_baseline"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|action| action.get("recipients").is_some())
                    .filter_map(|action| action["name"].as_str().map(str::to_string))
                    .collect();
                for action in &recipient_actions {
                    conn.execute(
                        "UPDATE catalog_actions SET ask_first = 1, generation = generation + 1
                         WHERE name = ?2 AND ask_first = 0 AND (principal, connection_id) IN
                            (SELECT principal, connection_id FROM connections WHERE app_key = ?1)",
                        (key, action),
                    )?;
                }
                // A manifest coming back un-retires its app (below), so the
                // watches its retirement suspended resume with their cursors.
                // Only that reason: a watch suspended for anything else stays
                // suspended for its own review.
                conn.execute(
                    "UPDATE trigger_subscriptions
                     SET status = 'active', suspended_reason = NULL, generation = generation + 1
                     WHERE status = 'suspended' AND suspended_reason = 'app_retired'
                        AND ((cursor_kind <> 'probe'
                        AND EXISTS (
                            SELECT 1 FROM catalog_actions ca
                            WHERE ca.principal=trigger_subscriptions.principal AND ca.connection_id=trigger_subscriptions.connection_id
                            AND ca.name=trigger_subscriptions.action AND ca.status='active' AND ca.risk='read'
                            AND ca.schema_hash=trigger_subscriptions.schema_hash)
                        AND EXISTS (SELECT 1 FROM grants g JOIN json_each(g.action_selectors) selector
                            WHERE g.principal=trigger_subscriptions.principal AND g.connection_id=trigger_subscriptions.connection_id
                            AND g.grantee_principal=trigger_subscriptions.principal AND g.authority_kind='poll'
                            AND (g.expires_at IS NULL OR g.expires_at>?2)
                            AND (selector.value=trigger_subscriptions.action OR selector.value='*')))
                        OR (cursor_kind='probe' AND EXISTS (
                            SELECT 1 FROM probe_subscriptions p WHERE p.subscription_id=trigger_subscriptions.subscription_id
                            AND NOT EXISTS (SELECT 1 FROM json_each(p.actions) a
                                WHERE NOT EXISTS (SELECT 1 FROM catalog_actions ca WHERE ca.principal=trigger_subscriptions.principal
                                    AND ca.connection_id=trigger_subscriptions.connection_id AND ca.name=a.value
                                    AND ca.status='active' AND ca.risk='read')
                                OR NOT EXISTS (SELECT 1 FROM grants g JOIN json_each(g.action_selectors) selector
                                    WHERE g.principal=trigger_subscriptions.principal AND g.connection_id=trigger_subscriptions.connection_id
                                    AND g.grantee_principal=p.registered_by AND g.authority_kind='poll'
                                    AND (g.expires_at IS NULL OR g.expires_at>?2) AND (selector.value=a.value OR selector.value='*'))))))
                        AND (principal, connection_id) IN
                         (SELECT principal, connection_id FROM connections
                           WHERE app_key = ?1 AND status <> 'revoked')",
                    rusqlite::params![key,now],
                )?;
            }
            conn.execute(
                "INSERT INTO app_manifests
                    (principal, key, schema_version, content_hash, manifest_json, ingested_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(principal, key) DO UPDATE SET
                    schema_version = excluded.schema_version,
                    content_hash = excluded.content_hash,
                    manifest_json = excluded.manifest_json,
                    ingested_at_ms = excluded.ingested_at_ms,
                    -- Re-ingesting a manifest un-retires it. A file returning to
                    -- the catalog directory is a reviewer's decision to offer it
                    -- again, and without this a vendor could never come back.
                    status = 'active'",
                rusqlite::params![principal, key, schema_version, hash, json, now],
            )?;
            // A REST connection's catalog IS its reviewed manifest, but nothing
            // else re-reads the manifest for a connection that already exists:
            // catalog refresh needs a stored credential binding, which GitHub
            // handle connections do not have (their token comes from the App
            // vault). So an action added to the manifest after a connection was
            // created would never reach that connection's catalog. Add the
            // missing rows here, in the same transaction as the manifest write.
            // Existing rows are left exactly as they are: their status
            // (quarantine, disablement) and schema pins are review decisions.
            if principal == CATALOG_PRINCIPAL
                && ingested.manifest.transport.kind == crate::manifest::TransportKind::RestApi
            {
                let mut statement = conn.prepare(
                    "SELECT principal, connection_id FROM connections
                     WHERE app_key = ?1 AND status != 'revoked'
                     ORDER BY principal, connection_id",
                )?;
                let connections: Vec<(String, String)> = statement
                    .query_map([key], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                drop(statement);
                for (owner, connection_id) in connections {
                    seed_catalog_from_manifest_on_conn(
                        conn,
                        &owner,
                        &connection_id,
                        key,
                        SeedMode::AddMissing,
                    )?;
                }
            }
            let changed = previous.is_some_and(|old_hash| old_hash != *hash);
            // The change record commits with the change. Appending it after
            // this transaction left a window where a crash kept the new
            // manifest and lost its record. A first ingest and an identical
            // re-ingest are not changes, so neither writes a row.
            if changed {
                append_audit_on_conn(
                    conn,
                    &AuditRecord::manifest_changed(principal, key),
                    None,
                    None,
                    None,
                    None,
                )?;
            }
            Ok(ManifestWriteOutcome { changed })
        })
    }

    /// Whether a stored manifest has been withdrawn from the reviewed catalog.
    ///
    /// A missing row reports `false` rather than an error: absence is
    /// `UnknownApp`'s business, and callers check that first.
    pub fn manifest_is_retired(&self, app_key: &str) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            let status: Option<String> = conn
                .query_row(
                    "SELECT status FROM app_manifests WHERE principal = ?1 AND key = ?2",
                    (CATALOG_PRINCIPAL, app_key),
                    |row| row.get(0),
                )
                .optional()?;
            Ok(status.is_some_and(|value| value == "retired"))
        })
    }

    /// Retire every stored manifest whose key is absent from the reviewed set,
    /// and return the keys retired.
    ///
    /// Called once per boot with the keys the catalog directory yielded, because
    /// ingestion alone cannot express a withdrawal: it upserts the files it
    /// finds and never consults the store, so a deleted manifest would otherwise
    /// remain connectable forever. Retiring for safety is the response to
    /// discovering a vendor surface cannot be governed, so a retirement that
    /// does not take effect defeats the remedy rather than merely leaving a
    /// stale row.
    ///
    /// REFUSES TO ACT ON AN EMPTY SET, and this is the load-bearing part. An
    /// empty `reviewed` means the catalog directory yielded nothing, which is a
    /// mis-set `PLEXUS_CATALOG_DIR` or a half-finished sync far more often than
    /// a deliberate withdrawal of every vendor. Since this runs at boot, before
    /// anything is served, acting on it would retire the entire catalog from one
    /// bad path. Same reasoning as the empty-discovery guard in
    /// `reconcile_actions`: refusing to destroy known state on an unbelievable
    /// observation.
    ///
    /// Marks rather than deletes: the row is the only record of what an existing
    /// connection was minted against, so removing it would orphan live
    /// connections and their audit history.
    ///
    /// Each retirement appends its `manifest_changed` audit row in the same
    /// fenced transaction, so the retirements and their records commit or roll
    /// back together.
    pub fn retire_absent_manifests(
        &self,
        principal: &str,
        reviewed: &[String],
    ) -> Result<Vec<String>, StoreError> {
        if reviewed.is_empty() {
            return Ok(Vec::new());
        }
        self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare(
                "SELECT key FROM app_manifests
                 WHERE principal = ?1 AND status = 'active' ORDER BY key",
            )?;
            let stored: Vec<String> = statement
                .query_map([principal], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);

            let mut retired = Vec::new();
            for key in stored {
                if reviewed.iter().any(|name| name == &key) {
                    continue;
                }
                conn.execute(
                    "UPDATE app_manifests SET status = 'retired'
                     WHERE principal = ?1 AND key = ?2",
                    (principal, &key),
                )?;
                if principal == CATALOG_PRINCIPAL {
                    // Retirement must stop live traffic, not only new tickets:
                    // in-flight reservations are invalidated, every connection
                    // of the app moves to a new generation, and active watches
                    // are suspended as `app_retired` (catalog reads already
                    // report the actions disabled). A returning manifest
                    // resumes exactly those watches; see `upsert_manifest`.
                    conn.execute(
                        "UPDATE reservations SET status = 'invalidated'
                         WHERE status = 'reserved' AND (principal, connection_id) IN
                            (SELECT principal, connection_id FROM connections WHERE app_key = ?1)",
                        [&key],
                    )?;
                    conn.execute(
                        "UPDATE connections SET generation = generation + 1 WHERE app_key = ?1",
                        [&key],
                    )?;
                    let mut gap_query=conn.prepare("SELECT s.principal,s.connection_id,s.subscription_id,COALESCE(s.last_success_at_ms,s.created_at_ms) FROM trigger_subscriptions s JOIN connections c ON c.principal=s.principal AND c.connection_id=s.connection_id WHERE c.app_key=?1 AND s.status='active'")?;
                    let gaps:Vec<(String,String,String,i64)>=gap_query.query_map([&key],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?.collect::<rusqlite::Result<_>>()?;
                    let retired_at=now_ms();
                    for (owner,connection,subscription,from) in gaps {
                        insert_gap_row(conn,&owner,&connection,&subscription,from,retired_at,"app_retired",retired_at)?;
                    }
                    conn.execute(
                        "UPDATE trigger_subscriptions
                         SET status = 'suspended', suspended_reason = 'app_retired',
                             generation = generation + 1
                         WHERE status = 'active' AND (principal, connection_id) IN
                            (SELECT principal, connection_id FROM connections WHERE app_key = ?1)",
                        [&key],
                    )?;
                }
                // Recorded in the retirement's own transaction, so a retired
                // manifest always has its record and a failed record undoes
                // the retirement.
                append_audit_on_conn(
                    conn,
                    &AuditRecord::manifest_changed(principal, &key),
                    None,
                    None,
                    None,
                    None,
                )?;
                retired.push(key);
            }
            Ok(retired)
        })
    }

    /// Replace the open placeholder schema on GitHub handle catalog rows with
    /// the reviewed `http.args_schema` from the stored manifest, and report
    /// what moved and what could not.
    ///
    /// Handle rows seeded before the seeder read `http.args_schema` still hold
    /// the placeholder, and nothing else ever rewrites them: the startup seed
    /// in `upsert_manifest` only adds missing rows, the handle health probe
    /// skips discovery, and catalog refresh needs a stored credential binding
    /// that handle connections do not have. Governance treats a schema without
    /// `properties` as open, so until a row moves, the undeclared-argument
    /// check refuses nothing on that bot action. Run at every boot, after the
    /// catalog ingest.
    ///
    /// Only a row whose stored schema is EXACTLY the placeholder moves, and
    /// only while it is active. Any other schema is a pin a reviewer made (or
    /// a changed schema awaiting review), and quarantined or disabled rows carry
    /// a review decision, so those are never touched. Once a row moves it no
    /// longer matches, so a second pass changes nothing.
    ///
    /// The move does not quarantine, for the same reason catalog refresh
    /// exempts the placeholder from its schema-change quarantine: the
    /// placeholder was never a reviewed schema, so replacing it discards no
    /// review. The replacement is also not a vendor observation but Plexus's
    /// own reviewed manifest, which is the reviewed source a schema is judged
    /// against in the first place.
    ///
    /// Revoked connections are skipped, as in the startup seed. A revoked
    /// connection refuses every call before its catalog is consulted, and it
    /// never becomes active again: recovery is a fresh connection, whose first
    /// seed pins the reviewed schemas anyway.
    ///
    /// Records what catalog refresh records for a schema change on an active
    /// row: the schema, its hash, the observation time, and a generation bump.
    pub fn pin_handle_placeholder_schemas(&self) -> Result<HandleSchemaPinReport, StoreError> {
        let placeholder = placeholder_catalog_schema();
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let mut statement = conn.prepare(
                "SELECT ca.principal, ca.connection_id, ca.name, ca.schema_json, c.app_key
                 FROM catalog_actions ca
                 JOIN connections c
                   ON c.principal = ca.principal AND c.connection_id = ca.connection_id
                 JOIN github_app_handle h
                   ON h.connection_principal = c.principal AND h.connection_id = c.connection_id
                 WHERE c.status != 'revoked' AND ca.status = 'active'
                 ORDER BY ca.principal, ca.connection_id, ca.name",
            )?;
            type Row = (String, String, String, String, String);
            let rows: Vec<Row> = statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?;
            drop(statement);

            // One manifest read per app key, not per row.
            let mut manifests: std::collections::HashMap<String, Option<Value>> =
                std::collections::HashMap::new();
            let mut report = HandleSchemaPinReport::default();
            let mut corrupt_logged=BTreeSet::new();
            for (principal, connection_id, action, stored, app_key) in rows {
                let schema=match serde_json::from_str::<Value>(&stored) {
                    Ok(schema)=>schema,
                    Err(error)=> {
                        report.gaps.push(HandleSchemaGap{principal:principal.clone(),connection_id:connection_id.clone(),action:action.clone(),reason:"stored schema does not parse"});
                        if corrupt_logged.insert((app_key.clone(),action.clone())) {
                            crate::diag!(warn storage: "catalog schema does not parse: app={app_key:?} action={action:?}: class={:?} line={} column={}",error.classify(),error.line(),error.column());
                        }
                        continue;
                    }
                };
                // Parse JSON because stored object key order is not significant.
                if schema != placeholder {
                    continue;
                }
                if !manifests.contains_key(&app_key) {
                    let source: Option<String> = conn
                        .query_row(
                            "SELECT manifest_json FROM app_manifests
                             WHERE principal = ?1 AND key = ?2 AND status = 'active'",
                            (CATALOG_PRINCIPAL, &app_key),
                            |row| row.get(0),
                        )
                        .optional()?;
                    let manifest = source
                        .map(|source| parse_json_column::<Value>(&source))
                        .transpose()?;
                    manifests.insert(app_key.clone(), manifest);
                }
                let gap = |reason| HandleSchemaGap {
                    principal: principal.clone(),
                    connection_id: connection_id.clone(),
                    action: action.clone(),
                    reason,
                };
                let Some(manifest) = manifests.get(&app_key).and_then(Option::as_ref) else {
                    report.gaps.push(gap("no active reviewed manifest"));
                    continue;
                };
                let declared = manifest
                    .get("actions_baseline")
                    .and_then(Value::as_array)
                    .and_then(|actions| {
                        actions.iter().find(|declared| {
                            declared.get("name").and_then(Value::as_str) == Some(action.as_str())
                        })
                    });
                let Some(declared) = declared else {
                    report.gaps.push(gap("action not in the reviewed manifest"));
                    continue;
                };
                let Some(schema) = declared.pointer("/http/args_schema") else {
                    report
                        .gaps
                        .push(gap("reviewed manifest declares no http.args_schema"));
                    continue;
                };
                // A manifest whose reviewed schema is itself the placeholder
                // has nothing to pin, and writing it would bump the generation
                // on every boot.
                if *schema == placeholder {
                    report
                        .gaps
                        .push(gap("reviewed http.args_schema is the open placeholder"));
                    continue;
                }
                let Ok(schema_hash) = crate::jcs::jcs_sha256(schema) else {
                    report
                        .gaps
                        .push(gap("reviewed http.args_schema cannot be hashed"));
                    continue;
                };
                let schema_json = serde_json::to_string(schema)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
                // The row's current text and status are repeated in the
                // WHERE clause so the write cannot land on anything other
                // than the placeholder row just read.
                let changed = conn.execute(
                    "UPDATE catalog_actions
                     SET schema_json = ?1, schema_hash = ?2, last_seen_at_ms = ?3,
                         generation = generation + 1
                     WHERE principal = ?4 AND connection_id = ?5 AND name = ?6
                       AND status = 'active' AND schema_json = ?7",
                    rusqlite::params![
                        schema_json,
                        schema_hash,
                        now,
                        principal,
                        connection_id,
                        action,
                        stored
                    ],
                )?;
                if changed != 0 {
                    // A subscription stores the schema hash of the action it
                    // polls. Before review, the action can have a placeholder
                    // schema that imposes no argument constraints. Replacing it
                    // changes the hash. Suspend affected subscriptions so they
                    // require review against the actual schema before polling
                    // again, just as any catalog schema change requires.
                    suspend_subscriptions_for_action(
                        conn,
                        &principal,
                        &connection_id,
                        &action,
                        None,
                        now,
                    )?;
                    report.pinned.push(PinnedHandleSchema {
                        principal,
                        connection_id,
                        action,
                        schema_hash,
                    });
                }
            }
            Ok(report)
        })
    }
}
