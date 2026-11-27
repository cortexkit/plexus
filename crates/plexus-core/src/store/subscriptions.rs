//! Subscription authority, probe registration, and polling schedules.

use super::*;

macro_rules! trigger_subscription_columns {
    () => {
        "subscription_id, principal, connection_id, action, cadence_s,
         cursor_kind, cursor_state, fixed_args, schema_hash, status, suspended_reason,
         last_polled_at_ms, last_success_at_ms, consecutive_vendor_failures, generation,
         created_at_ms, project_id, deliver_to, actor_source_json"
    };
}
const TRIGGER_SUBSCRIPTION_COLUMNS: &str = trigger_subscription_columns!();
pub(super) const DUE_SUBSCRIPTIONS_SELECT: &str = concat!(
    "SELECT ", trigger_subscription_columns!(), " FROM trigger_subscriptions
    WHERE principal = ?1 AND status = 'active'
    AND (last_polled_at_ms IS NULL OR last_polled_at_ms > ?2 OR (?2 - last_polled_at_ms) >= cadence_s * 1000)
    ORDER BY created_at_ms, subscription_id");

fn poll_grants_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection: Option<&str>,
    now: i64,
) -> rusqlite::Result<PollGrants> {
    let mut statement=conn.prepare("SELECT grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation FROM grants WHERE principal=?1 AND (?2 IS NULL OR connection_id=?2) AND authority_kind='poll' AND grantee_principal<>'*' ORDER BY grant_id")?;
    let rows = statement.query_map(rusqlite::params![principal, connection], |row| {
        map_grant_row(row, now)
    })?;
    let mut grouped = PollGrants::new();
    for row in rows {
        let row = row?;
        grouped
            .entry((row.connection_id.clone(), row.grantee_principal.clone()))
            .or_default()
            .push(row);
    }
    Ok(grouped)
}
fn subscription_authority_from_grants(
    subscription: &TriggerSubscription,
    grants: &PollGrants,
    now: i64,
) -> (Option<i64>, &'static str) {
    let (grantee, actions) = if subscription.cursor_kind == "probe" {
        (
            subscription
                .registered_by
                .as_deref()
                .unwrap_or(&subscription.principal),
            subscription.actions.clone().unwrap_or_default(),
        )
    } else {
        (
            subscription.principal.as_str(),
            vec![subscription.action.clone()],
        )
    };
    if actions.is_empty() {
        return (None, "absent");
    }
    let rows = grants
        .get(&(subscription.connection_id.clone(), grantee.to_string()))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut expires_at: Option<i64> = None;
    let mut saw_expired = false;
    let mut saw_other = false;
    for action in actions {
        match grant_candidate(rows, &action, now, None) {
            Some(grant) if grant.authorizes(&action, now) => {
                expires_at = match (expires_at, grant.expires_at) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (None, b) => b,
                    (a, None) => a,
                };
            }
            Some(grant) if grant.expires_at.is_some_and(|at| at <= now) => {
                saw_expired = true;
                expires_at = grant.expires_at;
            }
            Some(_) => saw_other = true,
            None => return (None, "absent"),
        }
    }
    if saw_expired {
        (expires_at, "expired")
    } else if saw_other {
        (None, "absent")
    } else {
        (expires_at, "live")
    }
}

/// Validate connection status and read-only action availability in the writer
/// snapshot, treating a retired app as disabled without rewriting its actions.
/// A scripted probe may call several vendor actions and pins its own return
/// schema, so only an ordinary single-action watch has a vendor-schema pin.
pub(super) fn recheck_watch_preconditions(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    actions: &[(&str, Option<&str>)],
) -> rusqlite::Result<Option<SubscriptionRefusal>> {
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM connections WHERE principal=?1 AND connection_id=?2",
            (principal, connection_id),
            |row| row.get(0),
        )
        .optional()?;
    match status {
        None => return Ok(Some(SubscriptionRefusal::ConnectionNotFound)),
        Some(status) if status != "active" => {
            return Ok(Some(SubscriptionRefusal::ConnectionInactive(status)))
        }
        _ => {}
    }
    for (action, pin) in actions {
        let row = conn.query_row(
            &format!("SELECT {CATALOG_ACTION_COLUMNS} FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3"),
            (principal, connection_id, action), map_catalog_action_row,
        ).optional()?;
        let Some(row) = row else {
            return Ok(Some(SubscriptionRefusal::ActionNotFound));
        };
        if row.risk != "read" {
            return Ok(Some(SubscriptionRefusal::ActionRiskNotRead));
        }
        if row.status != "active" {
            return Ok(Some(SubscriptionRefusal::ActionUnavailable(
                row.quarantine_reason.unwrap_or(row.status),
            )));
        }
        if pin.is_some_and(|pin| pin != row.schema_hash) {
            return Ok(Some(SubscriptionRefusal::ActionUnavailable(
                "schema_changed".into(),
            )));
        }
    }
    Ok(None)
}

fn map_probe_subscription_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProbeSubscription> {
    let actions: String = row.get(2)?;
    let return_schema: String = row.get(4)?;
    Ok(ProbeSubscription {
        subscription_id: row.get(0)?,
        name: row.get(1)?,
        actions: parse_string_list(&actions)?,
        script_source: row.get(3)?,
        return_schema: parse_json_column(&return_schema)?,
        rearm: row.get(5)?,
        registered_by: row.get(6)?,
    })
}

/// The sandbox's closed grammar, checked at registration so a bad schema is a
/// refused watch rather than a poll that never completes.
///
/// Delegates to the probe crate's own validator rather than re-encoding its
/// limits. An earlier revision duplicated the 256-byte and 16-field caps here,
/// which is two sources of truth for one grammar: they drift silently, and the
/// symptom is a registration this store accepted producing a poll-time
/// `probe_return_invalid` forever, on a watch that never retires.
fn validate_probe_return_schema(schema: &Value) -> Result<(), String> {
    let parsed: plexus_probe::ReturnSchema =
        serde_json::from_value(schema.clone()).map_err(|error| error.to_string())?;
    parsed
        .validate_declaration()
        .map_err(|error| error.to_string())
}

fn map_trigger_subscription_row(
    row: &rusqlite::Row<'_>,
    now: i64,
) -> rusqlite::Result<TriggerSubscription> {
    let cursor_state: String = row.get(6)?;
    let fixed_args: String = row.get(7)?;
    let last_success_at_ms: Option<i64> = row.get(12)?;
    let actor_source_json: Option<String> = row.get(18)?;
    Ok(TriggerSubscription {
        subscription_id: row.get(0)?,
        principal: row.get(1)?,
        connection_id: row.get(2)?,
        action: row.get(3)?,
        cadence_s: row.get(4)?,
        cursor_kind: row.get(5)?,
        cursor_state: parse_json_column(&cursor_state)?,
        fixed_args: parse_json_column(&fixed_args)?,
        schema_hash: row.get(8)?,
        status: row.get(9)?,
        suspended_reason: row.get(10)?,
        last_polled_at_ms: row.get(11)?,
        last_success_at_ms,
        cursor_age_ms: last_success_at_ms.map(|value| now.saturating_sub(value)),
        consecutive_vendor_failures: row.get(13)?,
        generation: row.get(14)?,
        created_at_ms: row.get(15)?,
        project_id: row.get(16)?,
        deliver_to: row.get(17)?,
        actor_source: actor_source_json
            .as_deref()
            .map(parse_json_column)
            .transpose()?,
        // Authority lives in the grants table, not this row. `list_subscriptions`
        // resolves it per subscription after mapping; every other reader gets
        // `absent` rather than a guess, because a row mapper that invented a
        // liveness value would be asserting something it cannot see.
        authority_expires_at_ms: None,
        authority_state: "absent".to_string(),
        name: None,
        registered_by: None,
        rearm: None,
        actions: None,
    })
}

/// Validate fixed arguments against the schema snapshot pinned to a subscription.
/// This is intentionally shallow: presence and JSON type are enough to reject a
/// misspelled container argument without pretending to implement JSON Schema.
///
/// Checks both directions, because they catch opposite mistakes. Every supplied
/// key must be DECLARED, which rejects a typo. Every REQUIRED key must be
/// supplied, which rejects a subscription the vendor will refuse on every
/// poll -- the poller builds its request from the cursor strategy and
/// `fixed_args` alone, so an argument absent here can never appear later.
///
/// Without the required check the failure is deferred rather than prevented,
/// and deferral is expensive here: the subscription is accepted, polls on its
/// cadence, and fails at the vendor every time. That reads as a flaky
/// integration rather than a subscription that was never viable, and the
/// backoff makes it quieter the longer it runs.
pub(super) fn validate_fixed_args(
    fixed_args: &Value,
    schema: &Value,
    supplied_elsewhere: &BTreeSet<String>,
) -> Result<(), SubscriptionRefusal> {
    let Some(fixed_args) = fixed_args.as_object() else {
        return Err(SubscriptionRefusal::FixedArgsMustBeObject);
    };
    let properties = schema.get("properties").and_then(Value::as_object);

    // Supplied keys are checked before required ones: a misspelled required
    // key is both "not declared" and leaves the real one "missing", and only
    // the first names the typo the caller has to fix.
    for (key, value) in fixed_args {
        let Some(property) = properties.and_then(|properties| properties.get(key)) else {
            return Err(SubscriptionRefusal::FixedArgNotDeclared(key.clone()));
        };
        let Some(declared_type) = property.get("type") else {
            return Err(SubscriptionRefusal::FixedArgTypeMismatch {
                key: key.clone(),
                expected: "a declared JSON type".to_string(),
                actual: json_type_name(value).to_string(),
            });
        };
        if !json_type_matches(value, declared_type) {
            return Err(SubscriptionRefusal::FixedArgTypeMismatch {
                key: key.clone(),
                expected: schema_type_name(declared_type),
                actual: json_type_name(value).to_string(),
            });
        }
    }
    // Accept required keys that the poller supplies outside `fixed_args`.
    // Cursor-based pagination adds request arguments, and the manifest supplies
    // constant arguments on every poll. The checks above reject both kinds in
    // `fixed_args`, so requiring them there would prevent subscribing to an
    // action even though each poll supplies them.
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for entry in required {
            let Some(key) = entry.as_str() else { continue };
            if fixed_args.contains_key(key) || supplied_elsewhere.contains(key) {
                continue;
            }
            return Err(SubscriptionRefusal::FixedArgRequiredMissing(
                key.to_string(),
            ));
        }
    }
    Ok(())
}

fn json_type_matches(value: &Value, declared_type: &Value) -> bool {
    let actual_type = json_type_name(value);
    // JSON Schema counts any number with a zero fractional part, such as
    // `5.0`, as an integer; serde reads it as a float.
    let whole_number = value
        .as_f64()
        .is_some_and(|number| number.is_finite() && number.fract() == 0.0);
    let matches = |declared_type: &str| {
        type_names_match(declared_type, actual_type) || (declared_type == "integer" && whole_number)
    };
    match declared_type {
        Value::String(declared_type) => matches(declared_type.as_str()),
        Value::Array(types) => types
            .iter()
            .any(|declared_type| declared_type.as_str().is_some_and(matches)),
        _ => false,
    }
}

fn type_names_match(declared_type: &str, actual_type: &str) -> bool {
    declared_type == actual_type || (declared_type == "number" && actual_type == "integer")
}

fn schema_type_name(declared_type: &Value) -> String {
    match declared_type {
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" or "),
        _ => declared_type.to_string(),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl PlexusStore {
    #[cfg(any(test, feature = "test-support"))]
    pub fn subscribe(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        cadence_s: i64,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        self.subscribe_with_cursor_state(
            principal,
            connection_id,
            action,
            cadence_s,
            &Value::Object(Default::default()),
            &Value::Object(Default::default()),
        )
    }

    pub fn subscribe_with_cursor_state(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        cadence_s: i64,
        cursor_state: &Value,
        fixed_args: &Value,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        self.prepare_subscription(
            principal,
            connection_id,
            action,
            cadence_s,
            cursor_state,
            fixed_args,
            false,
        )
    }

    // Validates a watch without inserting it. The repository-ownership pass
    // creates each repository's watches as a set, so it prepares every one
    // first and inserts none if any is refused.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_subscription(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        cadence_s: i64,
        cursor_state: &Value,
        fixed_args: &Value,
        prepare_only: bool,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        if cadence_s <= 0 {
            return Ok(Err(SubscriptionRefusal::InvalidCadence));
        }
        if !fixed_args.is_object() {
            return Ok(Err(SubscriptionRefusal::FixedArgsMustBeObject));
        }
        let Some(connection) = self.connection(principal, connection_id)? else {
            return Ok(Err(SubscriptionRefusal::ConnectionNotFound));
        };
        if connection.status != "active" {
            return Ok(Err(SubscriptionRefusal::ConnectionInactive(
                connection.status,
            )));
        }
        let Some(catalog_action) = self.catalog_action(principal, connection_id, action)? else {
            return Ok(Err(SubscriptionRefusal::ActionNotFound));
        };
        if catalog_action.risk != "read" {
            return Ok(Err(SubscriptionRefusal::ActionRiskNotRead));
        }
        if catalog_action.status != "active" {
            let reason = catalog_action
                .quarantine_reason
                .unwrap_or_else(|| catalog_action.status.clone());
            return Ok(Err(SubscriptionRefusal::ActionUnavailable(reason)));
        }
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, &connection.app_key)? else {
            return Ok(Err(SubscriptionRefusal::ManifestMissing));
        };
        let manifest = match document {
            Ok(manifest) => manifest,
            Err(error) => return Ok(Err(SubscriptionRefusal::ManifestInvalid(error))),
        };
        let Some(baseline) = manifest
            .actions_baseline
            .iter()
            .find(|candidate| candidate.name == action)
        else {
            return Ok(Err(SubscriptionRefusal::CursorShapeMissing));
        };
        let Some(poll) = baseline.poll.as_ref() else {
            return Ok(Err(SubscriptionRefusal::CursorShapeMissing));
        };
        if matches!(poll.cursor_kind, CursorKind::SnapshotDiff)
            && poll.item_count_ceiling.unwrap_or(0) == 0
        {
            return Ok(Err(SubscriptionRefusal::SnapshotItemCountCeilingRequired));
        }
        // Collected while refusing collisions, so the two uses cannot disagree
        // about which keys the poller supplies: the same set that a
        // subscription may not set is the set it need not set.
        let mut supplied_elsewhere: BTreeSet<String> = BTreeSet::new();
        if let Some(strategy) = crate::poller::strategy_for(poll.cursor_kind.as_str(), Some(poll)) {
            // A seeded starting state must be one this strategy will actually
            // READ. Seeding is how a threshold watch is expressed -- a scalar
            // seeded with a value the subscriber has already seen reports on its
            // first poll rather than baselining -- and every strategy resolves
            // its state by key, so a seed under the wrong key silently resolves
            // to "no previous value".
            //
            // That failure is invisible in the worst way: the subscription is
            // accepted, polls happily, and behaves exactly like an UNSEEDED
            // watch, so the one event the subscriber asked for is the one that
            // never arrives. Refusing at subscribe time turns a typo at a console
            // into an immediate error naming the accepted keys.
            if let Some(seeded) = cursor_state.as_object() {
                let readable = strategy.state_keys();
                for key in seeded.keys() {
                    if !readable.contains(key) {
                        return Ok(Err(SubscriptionRefusal::CursorStateKeyUnknown {
                            key: key.clone(),
                            accepted: readable,
                        }));
                    }
                }
            }
            for key in strategy.owned_keys() {
                supplied_elsewhere.insert(key.clone());
                if fixed_args.get(&key).is_some() {
                    // A fixed value here pins the watermark forever: the poller
                    // keeps re-reading one window, dedupe hides the repeats, and
                    // the subscription looks healthy while delivering nothing.
                    return Ok(Err(SubscriptionRefusal::FixedArgCursorOwned(key)));
                }
            }
        }
        if let Some(request_constants) = poll.request_constants.as_ref() {
            for key in request_constants.keys() {
                supplied_elsewhere.insert(key.clone());
                if fixed_args.get(key).is_some() {
                    // A subscription silently losing to a manifest constant is
                    // indistinguishable from its value being honoured, so refuse
                    // it here rather than letting precedence decide quietly.
                    return Ok(Err(SubscriptionRefusal::FixedArgRequestConstant(
                        key.clone(),
                    )));
                }
            }
        }
        if let Err(refusal) =
            validate_fixed_args(fixed_args, &catalog_action.schema, &supplied_elsewhere)
        {
            return Ok(Err(refusal));
        }
        // `matching_grant` is a DIAGNOSTIC resolver, not an authorization check.
        // When nothing authorizes the action it still returns the nearest grant
        // on the connection so a caller can report a specific reason, so a
        // `Some` means "a poll grant exists here", never "this action is
        // authorized". The returned grant must therefore be checked before it
        // is trusted -- governance's `authorize` does exactly that, and rejects
        // with a selector or expiry denial.
        //
        // Reading it as a boolean let ANY poll grant on the connection
        // authorize a subscription to ANY other action with a declared poll
        // shape: a grant scoped to one read action would raise a standing
        // background poll of a different one, which is precisely the narrowing
        // the per-action selector exists to enforce.
        let now = now_ms();
        let authorizing = self
            .matching_grant(
                principal,
                connection_id,
                principal,
                action,
                crate::governance::AUTHORITY_POLL,
                now,
                None,
            )?
            .filter(|grant| grant.authorizes(action, now));
        let Some(authorizing) = authorizing else {
            return Ok(Err(SubscriptionRefusal::PollGrantRequired));
        };
        let authorizing_expiry = authorizing.expires_at;
        let cursor_value = cursor_state.clone();
        let fixed_value = fixed_args.clone();
        let cursor_state = serde_json::to_string(cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let fixed_args = serde_json::to_string(fixed_args)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let subscription_id = new_id("subscription");
        let created_at_ms = now_ms();
        let cursor_kind = poll.cursor_kind.as_str().to_string();
        if !prepare_only {
            race_point("subscription_insert");
            // The checks above ran outside this transaction, so a quarantine,
            // a revoked connection or a revoked grant may have landed since.
            // Check the facts they established again here, where nothing can
            // change before the insert commits.
            let refusal = self.inner.with_conn_fenced(|conn| {
                if let Some(refusal) = recheck_watch_preconditions(
                    conn,
                    principal,
                    connection_id,
                    &[(action, Some(catalog_action.schema_hash.as_str()))],
                )? {
                    return Ok(Some(refusal));
                }
                let grant_live: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM grants
                        WHERE principal = ?1 AND grant_id = ?2
                          AND (expires_at IS NULL OR expires_at > ?3))",
                    rusqlite::params![principal, authorizing.grant_id, now_ms()],
                    |row| row.get(0),
                )?;
                if !grant_live {
                    return Ok(Some(SubscriptionRefusal::PollGrantRequired));
                }
                conn.execute(
                    "INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s,
                     cursor_kind, cursor_state, fixed_args, schema_hash, status,
                     generation, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', 0, ?10)",
                    rusqlite::params![
                        subscription_id,
                        principal,
                        connection_id,
                        action,
                        cadence_s,
                        cursor_kind,
                        cursor_state,
                        fixed_args,
                        catalog_action.schema_hash,
                        created_at_ms,
                    ],
                )?;
                Ok(None)
            })?;
            if let Some(refusal) = refusal {
                return Ok(Err(refusal));
            }
        }
        Ok(Ok(TriggerSubscription {
            subscription_id,
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            action: action.to_string(),
            cadence_s,
            cursor_kind,
            cursor_state: cursor_value,
            fixed_args: fixed_value,
            schema_hash: catalog_action.schema_hash,
            status: "active".to_string(),
            suspended_reason: None,
            last_polled_at_ms: None,
            last_success_at_ms: None,
            cursor_age_ms: None,
            consecutive_vendor_failures: 0,
            generation: 0,
            created_at_ms,
            // The grant that just authorized this subscription is live by
            // construction -- `authorizes` returned true two statements ago, so
            // re-resolving it here would only introduce a way for the two to
            // disagree.
            authority_expires_at_ms: authorizing_expiry,
            authority_state: "live".to_string(),
            // Never set at subscribe. Binding a project is a SEPARATE operator
            // act via `set_subscription_project`, because the 59 watches already
            // running were minted before this field existed and a mint-only path
            // would force unsubscribe-and-resubscribe to bind them -- discarding
            // every cursor and re-backfilling each repo against the vendor.
            project_id: None,
            deliver_to: None,
            actor_source: None,
            name: None,
            registered_by: None,
            rearm: None,
            actions: None,
        }))
    }

    /// Register a probe against a connection the caller is already allowed to poll.
    ///
    /// THE SUBSCRIPTION ROW BELONGS TO THE CONNECTION OWNER. The caller is
    /// recorded as `registered_by` provenance and is not the owner. This is
    /// forced: every poll-time lookup (connection, catalog action, credential)
    /// is owner-scoped, so a row owned by the registrant would fail at the
    /// first lookup because the registrant owns no connection.
    ///
    /// Authority is the existing `poll` grant naming the caller as grantee.
    /// Registration mints nothing -- every declared action must already be
    /// covered by that grant.
    pub fn register_probe(
        &self,
        registrant: &str,
        connection_id: &str,
        request: ProbeRegistration<'_>,
    ) -> Result<Result<TriggerSubscription, SubscriptionRefusal>, StoreError> {
        let name = request.name.trim();
        if name.is_empty() {
            return Ok(Err(SubscriptionRefusal::ProbeNameRequired));
        }
        if request.script_source.len() > plexus_probe::MAX_SOURCE_BYTES {
            return Ok(Err(SubscriptionRefusal::ProbeSourceTooLarge));
        }
        if request.script_source.trim().is_empty() {
            return Ok(Err(SubscriptionRefusal::ProbeScriptRequired));
        }
        if request.cadence_s <= 0 {
            return Ok(Err(SubscriptionRefusal::InvalidCadence));
        }
        let rearm = request.rearm.trim();
        if rearm != "once" && rearm != "always" {
            return Ok(Err(SubscriptionRefusal::ProbeRearmInvalid));
        }
        let mut actions: BTreeSet<String> = BTreeSet::new();
        for action in request.actions {
            let action = action.trim();
            if action.is_empty() {
                continue;
            }
            actions.insert(action.to_string());
        }
        if actions.is_empty() {
            return Ok(Err(SubscriptionRefusal::ProbeActionsRequired));
        }
        if let Err(reason) = validate_probe_return_schema(request.return_schema) {
            return Ok(Err(SubscriptionRefusal::ProbeReturnSchemaInvalid(reason)));
        }
        let Some(fixed_args) = request.fixed_args.as_object() else {
            return Ok(Err(SubscriptionRefusal::FixedArgsMustBePerActionMap));
        };
        for key in fixed_args.keys() {
            if !actions.contains(key) {
                return Ok(Err(SubscriptionRefusal::FixedArgNotDeclared(key.clone())));
            }
            if !fixed_args[key].is_object() {
                return Ok(Err(SubscriptionRefusal::FixedArgsMustBePerActionMap));
            }
        }
        if !request.cursor_state.is_object() {
            return Ok(Err(SubscriptionRefusal::FixedArgsMustBeObject));
        }

        let now = now_ms();
        let granted = self.poll_connections(registrant, now)?;
        let matching: Vec<&(String, String, Vec<String>)> = granted
            .iter()
            .filter(|(_, granted_connection, _)| granted_connection == connection_id)
            .collect();
        // Grants are additive: two poll grants from one owner together cover
        // the union of their selectors. Each poll of each action is authorized
        // separately and any one live grant naming it suffices, so the probe
        // may rely on the union too.
        let (owner, selectors): (&str, Vec<String>) = match matching.as_slice() {
            [] => return Ok(Err(SubscriptionRefusal::PollGrantRequired)),
            [first, rest @ ..] => {
                if rest.iter().any(|(owner, _, _)| owner != &first.0) {
                    return Ok(Err(SubscriptionRefusal::AmbiguousConnectionOwner));
                }
                (
                    first.0.as_str(),
                    matching
                        .iter()
                        .flat_map(|(_, _, selectors)| selectors.iter().cloned())
                        .collect(),
                )
            }
        };

        let Some(connection) = self.connection(owner, connection_id)? else {
            return Ok(Err(SubscriptionRefusal::ConnectionNotFound));
        };
        if connection.status != "active" {
            return Ok(Err(SubscriptionRefusal::ConnectionInactive(
                connection.status,
            )));
        }

        let empty_elsewhere = BTreeSet::new();
        let mut pinned_actions = std::collections::BTreeMap::new();
        for action in &actions {
            let covered = selectors
                .iter()
                .any(|selector| selector == action || selector == "*");
            if !covered {
                return Ok(Err(SubscriptionRefusal::ActionNotCoveredByGrant {
                    action: action.clone(),
                }));
            }
            let Some(catalog_action) = self.catalog_action(owner, connection_id, action)? else {
                return Ok(Err(SubscriptionRefusal::ActionNotFound));
            };
            if catalog_action.risk != "read" {
                return Ok(Err(SubscriptionRefusal::ActionRiskNotRead));
            }
            if catalog_action.status != "active" {
                let reason = catalog_action
                    .quarantine_reason
                    .unwrap_or_else(|| catalog_action.status.clone());
                return Ok(Err(SubscriptionRefusal::ActionUnavailable(reason)));
            }
            pinned_actions.insert(action.clone(), catalog_action.schema_hash.clone());
            let action_args = fixed_args
                .get(action)
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default()));
            if let Err(refusal) =
                validate_fixed_args(&action_args, &catalog_action.schema, &empty_elsewhere)
            {
                return Ok(Err(refusal));
            }
        }

        // Pin the return schema, not a vendor action schema: a probe has no
        // single action whose hash would describe the watch.
        let action_list: Vec<String> = actions.into_iter().collect();
        let schema_hash = jcs_store_hash(request.return_schema)?;
        let cursor_state = serde_json::to_string(request.cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let fixed_args_json = serde_json::to_string(request.fixed_args)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let actions_json = serde_json::to_string(&action_list)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let return_schema_json = serde_json::to_string(request.return_schema)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let subscription_id = new_id("subscription");
        let created_at_ms = now_ms();
        race_point("probe_insert");
        let refusal = self.inner.with_conn_fenced(|conn| {
            let pins: Vec<_> = pinned_actions.iter().map(|(action, hash)| (action.as_str(), Some(hash.as_str()))).collect();
            if let Some(refusal) = recheck_watch_preconditions(conn, owner, connection_id, &pins)? {
                return Ok(Some(refusal));
            }
            let mut grants = conn.prepare("SELECT action_selectors FROM grants WHERE principal=?1 AND connection_id=?2 AND grantee_principal=?3 AND authority_kind='poll' AND (expires_at IS NULL OR expires_at>?4)")?;
            let selectors: Vec<Vec<String>> = grants.query_map(rusqlite::params![owner,connection_id,registrant,now_ms()], |row| parse_string_list(&row.get::<_, String>(0)?))?.collect::<rusqlite::Result<_>>()?;
            for action in pinned_actions.keys() {
                if !selectors.iter().flatten().any(|selector| selector == action || selector == "*") {
                    return Ok(Some(SubscriptionRefusal::PollGrantRequired));
                }

            }
            conn.execute(
                "INSERT INTO trigger_subscriptions
                    (subscription_id, principal, connection_id, action, cadence_s,
                     cursor_kind, cursor_state, fixed_args, schema_hash, status,
                     generation, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'probe', ?6, ?7, ?8, 'active', 0, ?9)",
                rusqlite::params![
                    subscription_id,
                    owner,
                    connection_id,
                    PROBE_SUBSCRIPTION_ACTION,
                    request.cadence_s,
                    cursor_state,
                    fixed_args_json,
                    schema_hash,
                    created_at_ms,
                ],
            )?;
            conn.execute(
                "INSERT INTO probe_subscriptions
                    (subscription_id, name, actions, script_source, return_schema,
                     rearm, registered_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    subscription_id,
                    name,
                    actions_json,
                    request.script_source,
                    return_schema_json,
                    rearm,
                    registrant,
                ],
            )?;
            Ok(None)
        })?;
        if let Some(refusal) = refusal {
            return Ok(Err(refusal));
        }
        let mut subscription = TriggerSubscription {
            subscription_id,
            principal: owner.to_string(),
            connection_id: connection_id.to_string(),
            action: PROBE_SUBSCRIPTION_ACTION.to_string(),
            cadence_s: request.cadence_s,
            cursor_kind: "probe".to_string(),
            cursor_state: request.cursor_state.clone(),
            fixed_args: request.fixed_args.clone(),
            schema_hash,
            status: "active".to_string(),
            suspended_reason: None,
            last_polled_at_ms: None,
            last_success_at_ms: None,
            cursor_age_ms: None,
            consecutive_vendor_failures: 0,
            generation: 0,
            created_at_ms,
            authority_expires_at_ms: None,
            authority_state: "live".to_string(),
            project_id: None,
            deliver_to: None,
            actor_source: None,
            name: Some(name.to_string()),
            registered_by: Some(registrant.to_string()),
            rearm: Some(rearm.to_string()),
            actions: Some(action_list),
        };
        let (expiry, state) = self.subscription_authority(&subscription, now_ms())?;
        subscription.authority_expires_at_ms = expiry;
        subscription.authority_state = state.to_string();
        Ok(Ok(subscription))
    }

    /// Connections whose actions `grantee` may poll, by explicit grant.
    ///
    /// Same shape as [`Self::events_consume_connections`]: owner, connection,
    /// and the grant's action selectors, with expiry enforced here so a lapsed
    /// grant cannot authorize a registration through a path that forgot to
    /// check it.
    pub(super) fn poll_connections(
        &self,
        grantee: &str,
        now_ms: i64,
    ) -> Result<Vec<(String, String, Vec<String>)>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal, connection_id, action_selectors, expires_at
                 FROM grants
                 WHERE authority_kind = ?1
                   AND grantee_principal = ?2 AND grantee_principal <> '*'
                 ORDER BY grant_id",
            )?;
            let rows =
                statement.query_map((crate::governance::AUTHORITY_POLL, grantee), |row| {
                    let selectors: String = row.get(2)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        parse_string_list(&selectors)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })?;
            let mut granted = Vec::new();
            for row in rows {
                let (owner, connection_id, selectors, expires_at) = row?;
                if expires_at.is_some_and(|deadline| deadline <= now_ms) {
                    continue;
                }
                granted.push((owner, connection_id, selectors));
            }
            Ok(granted)
        })
    }

    /// Probe-only fields for one subscription, if it is a probe.
    pub fn probe_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<ProbeSubscription>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT subscription_id, name, actions, script_source, return_schema,
                        rearm, registered_by
                 FROM probe_subscriptions
                 WHERE subscription_id = ?1",
                [subscription_id],
                map_probe_subscription_row,
            )
            .optional()
        })
    }

    fn attach_probe_fields(
        &self,
        subscriptions: &mut [TriggerSubscription],
    ) -> Result<(), StoreError> {
        let ids: Vec<_> = subscriptions
            .iter()
            .filter(|subscription| subscription.cursor_kind == "probe")
            .map(|subscription| subscription.subscription_id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let probes=self.inner.with_read(|conn| {
            let mut probes=std::collections::BTreeMap::new();
            for chunk in ids.chunks(900) {
                let placeholders=vec!["?";chunk.len()].join(",");
                let mut query=conn.prepare(&format!("SELECT subscription_id,name,registered_by,rearm,actions FROM probe_subscriptions WHERE subscription_id IN ({placeholders})"))?;
                let rows=query.query_map(rusqlite::params_from_iter(chunk),|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,parse_string_list(&row.get::<_,String>(4)?)?)))?;
                for row in rows { let (id,name,registrant,rearm,actions)=row?; probes.insert(id,(name,registrant,rearm,actions)); }
            }
            Ok(probes)
        })?;
        for subscription in subscriptions {
            if let Some((name, registrant, rearm, actions)) =
                probes.get(&subscription.subscription_id)
            {
                subscription.name = Some(name.clone());
                subscription.registered_by = Some(registrant.clone());
                subscription.rearm = Some(rearm.clone());
                subscription.actions = Some(actions.clone());
            }
        }
        Ok(())
    }

    fn subscription_authority(
        &self,
        subscription: &TriggerSubscription,
        now: i64,
    ) -> Result<(Option<i64>, &'static str), StoreError> {
        self.inner.with_read(|conn| {
            let grants = poll_grants_on_conn(
                conn,
                &subscription.principal,
                Some(&subscription.connection_id),
                now,
            )?;
            Ok(subscription_authority_from_grants(
                subscription,
                &grants,
                now,
            ))
        })
    }

    /// Bind (or clear) the project a subscription's events belong to.
    ///
    /// A SEPARATE operator act rather than a mint parameter, because the watches
    /// that need it most already exist: binding a project at mint only would mean
    /// unsubscribe-and-resubscribe for every running watch, which discards each
    /// cursor and re-backfills its repository against the vendor. One
    /// pull-request backfill on a busy repository can take tens of seconds of
    /// sequential polling and hundreds of events, so that cost is real rather
    /// than theoretical.
    ///
    /// `None` CLEARS the binding, and clearing is deliberately expressible: an
    /// operator who bound the wrong project must be able to say "no project"
    /// again rather than being stuck choosing between two wrong answers. A
    /// consumer reads the cleared state as loudly unroutable, which is the
    /// correct reading of "nobody has decided".
    ///
    /// Scoped to the caller's principal like every other write here, so one
    /// principal cannot re-route another's watch. Returns whether a row changed,
    /// so a caller naming an unknown subscription learns it did nothing instead
    /// of assuming success.
    ///
    /// Routing metadata leaves the subscription change counter unchanged.
    /// This counter is not part of governance's reservation snapshot.
    pub fn set_subscription_project(
        &self,
        principal: &str,
        subscription_id: &str,
        project_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        // An empty or whitespace-only string is treated as CLEARING rather than
        // stored as a project named "". A stored empty string would satisfy a
        // consumer's "is it present" check while carrying no routing
        // information, which is worse than absence because it silently passes
        // the gate that exists to catch absence.
        let normalized = project_id.map(str::trim).filter(|value| !value.is_empty());
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE trigger_subscriptions SET project_id = ?1,
                     project_source = CASE WHEN ?1 IS NULL THEN NULL ELSE 'hand' END
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![normalized, principal, subscription_id],
            )?;
            Ok(changed > 0)
        })
    }

    /// Bind (or clear) the registry agent that should receive a subscription's events.
    ///
    /// Delivery routing gives `deliver_to` precedence over project-derived routing;
    /// `project_id` remains attribution and the consumer's fallback. This stores
    /// routing metadata only: a consumer handles an agent that retires later.
    ///
    /// Scoped to the caller's principal like every other write here, so one
    /// principal cannot re-route another's watch. Returns whether a row changed.
    ///
    /// Delivery metadata leaves the subscription change counter unchanged.
    /// This counter is not a reservation fence.
    pub fn set_subscription_deliver_to(
        &self,
        principal: &str,
        subscription_id: &str,
        deliver_to: Option<&str>,
    ) -> Result<bool, StoreError> {
        // An empty or blank target clears the binding, as it does for a
        // project label: a stored "" would read as "routed somewhere" while
        // naming no agent.
        let deliver_to = deliver_to.map(str::trim).filter(|value| !value.is_empty());
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE trigger_subscriptions SET deliver_to = ?1
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![deliver_to, principal, subscription_id],
            )?;
            Ok(changed > 0)
        })
    }

    /// Bind (or clear) the separately governed source used for actor enrichment.
    ///
    /// This is a separate operator act so an existing watch keeps its cursor and
    /// vendor history. Replacing the watch's connection would unsubscribe and
    /// re-subscribe under a different dedupe identity, re-backfilling every item;
    /// the actor read instead needs only its own permanently narrowed connection.
    ///
    /// `None` clears the binding. The write is principal-scoped and reports
    /// whether the named subscription row exists, matching
    /// [`Self::set_subscription_project`].
    ///
    /// The subscription change counter is not advanced for enrichment metadata.
    /// Actor reads are authorized independently against the source connection;
    /// this counter is not used to fence governance reservations.
    pub fn set_subscription_actor_source(
        &self,
        principal: &str,
        subscription_id: &str,
        actor_source: Option<&ActorSource>,
    ) -> Result<bool, StoreError> {
        let actor_source_json = actor_source
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE trigger_subscriptions SET actor_source_json = ?1
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![actor_source_json, principal, subscription_id],
            )?;
            Ok(changed > 0)
        })
    }

    /// Corrupt a stored subscription only in unit tests, so poll-path tests can
    /// prove the runtime precedence guard against legacy rows that predate it.
    #[cfg(test)]
    pub(crate) fn replace_fixed_args_for_test(
        &self,
        principal: &str,
        subscription_id: &str,
        fixed_args: &Value,
    ) -> Result<(), StoreError> {
        let fixed_args = serde_json::to_string(fixed_args)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE trigger_subscriptions SET fixed_args = ?1
                 WHERE principal = ?2 AND subscription_id = ?3",
                rusqlite::params![fixed_args, principal, subscription_id],
            )?;
            Ok(())
        })
    }

    pub fn subscription(
        &self,
        principal: &str,
        subscription_id: &str,
    ) -> Result<Option<TriggerSubscription>, StoreError> {
        let mut found = self.inner.with_read(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions
                  WHERE principal = ?1 AND subscription_id = ?2"
                ),
                (principal, subscription_id),
                |row| map_trigger_subscription_row(row, now_ms()),
            )
            .optional()
        })?;
        if let Some(subscription) = found.as_mut() {
            self.attach_probe_fields(std::slice::from_mut(subscription))?;
        }
        Ok(found)
    }

    /// Count and longest cadence of subscriptions the scheduler can still act on.
    ///
    /// Suspended subscriptions remain stored so their reason and cursor can be
    /// inspected or resumed, but they are not work waiting for the scheduler.
    /// The optional result makes an empty active set explicit: there is no maximum
    /// cadence to invent when there is no work.
    pub fn active_subscription_schedule(&self) -> Result<Option<(u64, u64)>, StoreError> {
        let (count, max_cadence_s): (i64, Option<i64>) = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT COUNT(*), MAX(cadence_s)
                   FROM trigger_subscriptions
                  WHERE status = 'active'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })?;

        match (count, max_cadence_s) {
            (0, None) => Ok(None),
            (count, Some(max_cadence_s)) if count > 0 && max_cadence_s > 0 => {
                Ok(Some((count as u64, max_cadence_s as u64)))
            }
            unexpected => Err(StoreError::Backend(format!(
                "active subscription schedule is inconsistent: {unexpected:?}"
            ))),
        }
    }

    pub fn list_subscriptions(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
    ) -> Result<Vec<TriggerSubscription>, StoreError> {
        let now = now_ms();
        let mut subscriptions = self.inner.with_read(|conn| {
            let mut sql = format!("SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions WHERE principal=?1");
            if connection_id.is_some() { sql.push_str(" AND connection_id=?2"); }
            if subscription_id.is_some() { sql.push_str(" AND subscription_id=?3"); }
            sql.push_str(" ORDER BY created_at_ms,subscription_id");
            let mut statement = conn.prepare(&sql)?;
            statement.raw_bind_parameter(1, principal)?;
            if let Some(connection) = connection_id { statement.raw_bind_parameter(2, connection)?; }
            if let Some(subscription) = subscription_id { statement.raw_bind_parameter(3, subscription)?; }
            let rows = statement.raw_query().mapped(|row| map_trigger_subscription_row(row, now));
            let subscriptions: Vec<TriggerSubscription> = rows.collect::<rusqlite::Result<_>>()?;
            Ok(subscriptions)
        })?;
        self.attach_probe_fields(&mut subscriptions)?;

        let grants = self
            .inner
            .with_read(|conn| poll_grants_on_conn(conn, principal, connection_id, now))?;
        for subscription in &mut subscriptions {
            let (expires_at, state) =
                subscription_authority_from_grants(subscription, &grants, now);
            subscription.authority_expires_at_ms = expires_at;
            subscription.authority_state = state.to_string();
        }
        Ok(subscriptions)
    }

    /// List owned and granted watches, filtering selectors before decoding rows.
    /// Probe metadata and poll authority are loaded once for the selected lanes,
    /// rather than once per overlapping consume grant.
    pub fn list_subscriptions_including_granted(
        &self,
        principal: &str,
        connection_id: Option<&str>,
        subscription_id: Option<&str>,
        now_ms_value: i64,
    ) -> Result<Vec<TriggerSubscription>, StoreError> {
        let mut subscriptions = self.inner.with_read(|conn| {
            let mut statement = conn.prepare(&format!(
                "SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions
                 WHERE (?2 IS NULL OR connection_id=?2) AND (?3 IS NULL OR subscription_id=?3)
                 AND (principal=?1 OR EXISTS (
                    SELECT 1 FROM grants g, json_each(g.action_selectors) selector
                    WHERE g.principal=trigger_subscriptions.principal
                    AND g.connection_id=trigger_subscriptions.connection_id
                    AND g.grantee_principal=?1 AND g.grantee_principal<>'*'
                    AND g.authority_kind='events_consume' AND (g.expires_at IS NULL OR g.expires_at>?4)
                    AND (selector.value=trigger_subscriptions.action OR selector.value='*')))
                 ORDER BY created_at_ms,subscription_id"
            ))?;
            let rows = statement.query_map(rusqlite::params![principal, connection_id, subscription_id, now_ms_value],
                |row| map_trigger_subscription_row(row, now_ms_value))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })?;
        self.attach_probe_fields(&mut subscriptions)?;
        let lanes: BTreeSet<_> = subscriptions
            .iter()
            .map(|sub| (&sub.principal, &sub.connection_id))
            .collect();
        let lanes = serde_json::to_string(&lanes)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let grants = self.inner.with_read(|conn| {
            let mut query = conn.prepare(
                "SELECT grant_id,principal,connection_id,grantee_principal,risk_ceiling,
                 action_selectors,authority_kind,expires_at,generation FROM grants
                 WHERE authority_kind='poll' AND grantee_principal<>'*'
                 AND (principal,connection_id) IN (SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]') FROM json_each(?1))
                 ORDER BY grant_id"
            )?;
            let rows = query.query_map([lanes], |row| map_grant_row(row, now_ms_value))?;
            let mut owners: std::collections::BTreeMap<String, PollGrants> = Default::default();
            for row in rows {
                let row = row?;
                owners.entry(row.principal.clone()).or_default()
                    .entry((row.connection_id.clone(), row.grantee_principal.clone())).or_default().push(row);
            }
            Ok(owners)
        })?;
        let empty = PollGrants::new();
        for sub in &mut subscriptions {
            let (expiry, state) = subscription_authority_from_grants(
                sub,
                grants.get(&sub.principal).unwrap_or(&empty),
                now_ms_value,
            );
            sub.authority_expires_at_ms = expiry;
            sub.authority_state = state.into();
        }
        Ok(subscriptions)
    }

    /// Subscriptions eligible to poll at `now_ms`: `active`, and either never
    /// polled (`last_polled_at_ms IS NULL`) or last polled at least `cadence_s`
    /// ago.
    ///
    /// This is the BASE cadence bound only. It deliberately knows nothing about
    /// failure backoff or the circuit breaker: those are scheduler-layer
    /// decisions that read `consecutive_vendor_failures` off the returned rows.
    /// Keeping the SQL to the cadence rule means a healthy subscription is
    /// selected at exactly its declared cadence and nothing else, while a
    /// failing one is still returned here and then held back (or suspended) by
    /// the scheduler rather than by a second, divergent notion of "due" baked
    /// into the query.
    ///
    /// Principal-scoped like every other query in this table. The scheduler
    /// calls this once per principal it acts for; it never reaches across
    /// principals in a single query.
    pub fn due_subscriptions(
        &self,
        principal: &str,
        now_ms: i64,
    ) -> Result<Vec<TriggerSubscription>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(DUE_SUBSCRIPTIONS_SELECT)?;
            let rows = statement.query_map((principal, now_ms), |row| {
                map_trigger_subscription_row(row, now_ms)
            })?;
            rows.collect()
        })
    }

    /// Suspend one subscription and record the coverage gap the suspension
    /// creates.
    ///
    /// Limited to the given principal's subscriptions, like every other query
    /// in this store. A subscription id is an unguessable
    /// `subscription_<24 hex characters>`, but ids do reach log lines and
    /// error messages, and being hard to guess is not an authorization check:
    /// without the principal condition, anyone who saw an id could suspend
    /// another principal's subscription. The condition is in this method
    /// itself rather than in a separate checked wrapper, because a safe wrapper
    /// beside an unchecked method stays safe only while every future caller
    /// picks the wrapper.
    pub fn suspend(
        &self,
        principal: &str,
        subscription_id: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Ok(false);
        }
        self.inner.with_conn_fenced(|conn| {
            let row: Option<(String, Option<i64>, i64)> = conn
                .query_row(
                    "SELECT connection_id, last_success_at_ms, created_at_ms
                     FROM trigger_subscriptions
                     WHERE subscription_id = ?1 AND principal = ?2",
                    (subscription_id, principal),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((connection_id, last_success_at_ms, created_at_ms)) = row else {
                return Ok(false);
            };
            let changed = conn.execute(
                "UPDATE trigger_subscriptions
                 SET status = 'suspended', suspended_reason = ?1, generation = generation + 1
                 WHERE subscription_id = ?2 AND principal = ?3
                   AND status <> 'retired' AND (status <> 'suspended' OR suspended_reason IS NOT ?1)",
                (reason, subscription_id, principal),
            )?;
            if changed != 0 {
                let observed_at_ms = now_ms();
                insert_gap_row(
                    conn,
                    principal,
                    &connection_id,
                    subscription_id,
                    last_success_at_ms.unwrap_or(created_at_ms),
                    observed_at_ms,
                    reason,
                    observed_at_ms,
                )?;
            }
            Ok(changed != 0)
        })
    }

    /// Resume an operational pause without replacing the vendor cursor.
    /// Catalog, schema, connection and grant checks share the write snapshot;
    /// reconciliation and authorization suspensions still require review.
    pub fn resume(
        &self,
        principal: &str,
        subscription_id: &str,
    ) -> Result<Result<TriggerSubscription, SubscriptionResumeRefusal>, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let now = now_ms();
            let Some(mut subscription) = conn.query_row(
                &format!("SELECT {TRIGGER_SUBSCRIPTION_COLUMNS} FROM trigger_subscriptions
                          WHERE principal=?1 AND subscription_id=?2"),
                (principal, subscription_id), |row| map_trigger_subscription_row(row, now),
            ).optional()? else {
                return Ok(Err(SubscriptionResumeRefusal::SubscriptionNotFound));
            };
            if subscription.status == "retired" {
                return Ok(Err(SubscriptionResumeRefusal::SubscriptionRetired));
            }
            let resumable = subscription.suspended_reason.as_deref().is_some_and(|reason| {
                reason == CIRCUIT_BREAKER_SUSPENSION_REASON
                    || reason == crate::poller::CONNECTOR_HOME_NOT_HELD
                    || reason == "response_shape_invalid"
                    || reason.starts_with("response_shape_invalid:")
            });
            if subscription.status != "active" && !resumable {
                return Ok(Err(SubscriptionResumeRefusal::SuspensionNotResumable(subscription.suspended_reason)));
            }
            if subscription.cursor_kind == "probe" {
                let probe = conn.query_row(
                    "SELECT subscription_id,name,actions,script_source,return_schema,rearm,registered_by
                     FROM probe_subscriptions WHERE subscription_id=?1",
                    [subscription_id], map_probe_subscription_row,
                )?;
                subscription.name = Some(probe.name);
                subscription.registered_by = Some(probe.registered_by);
                subscription.rearm = Some(probe.rearm);
                subscription.actions = Some(probe.actions);
            }
            let actions = if let Some(actions) = &subscription.actions {
                actions.iter().map(|action| (action.as_str(), None)).collect::<Vec<_>>()
            } else {
                vec![(subscription.action.as_str(), Some(subscription.schema_hash.as_str()))]
            };
            if let Some(refusal) = recheck_watch_preconditions(conn, principal, &subscription.connection_id, &actions)? {
                return Ok(Err(SubscriptionResumeRefusal::SuspensionNotResumable(Some(refusal.to_string()))));
            }
            let grants = poll_grants_on_conn(conn, principal, Some(&subscription.connection_id), now)?;
            let (expiry, state) = subscription_authority_from_grants(&subscription, &grants, now);
            if state != "live" {
                return Ok(Err(SubscriptionResumeRefusal::PollGrantRequired));
            }
            subscription.authority_expires_at_ms = expiry;
            subscription.authority_state = state.to_string();
            if subscription.status == "suspended" {
                conn.execute(
                    "UPDATE trigger_subscriptions SET status='active', consecutive_vendor_failures=0,
                         suspended_reason=NULL, generation=generation+1
                     WHERE principal=?1 AND subscription_id=?2",
                    (principal, subscription_id),
                )?;
                subscription.status = "active".into();
                subscription.suspended_reason = None;
                subscription.consecutive_vendor_failures = 0;
                subscription.generation += 1;
            }
            Ok(Ok(subscription))
        })
    }

    pub fn unsubscribe(&self, principal: &str, subscription_id: &str) -> Result<bool, StoreError> {
        // The owner may always withdraw a watch on their connection. A probe's
        // registrant may also withdraw it, INCLUDING AFTER ITS GRANT IS REVOKED:
        // narrowing must stay frictionless, and a registrant that cannot clean
        // up its own probe after losing authority leaves rows only an operator
        // ceremony can remove.
        let probe = self.probe_subscription(subscription_id)?;
        let owner = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT principal FROM trigger_subscriptions WHERE subscription_id = ?1",
                [subscription_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
        })?;
        let Some(owner) = owner else {
            return Ok(false);
        };
        let registrant = probe.as_ref().map(|probe| probe.registered_by.as_str());
        if principal != owner && registrant != Some(principal) {
            return Ok(false);
        }
        self.inner.with_conn_fenced(|conn| {
            event_outbox::count_dropped(
                conn,
                SUBSCRIPTION_EVENTS_PREDICATE,
                (owner.as_str(), subscription_id),
                "dropped_on_unsubscribe",
            )?;
            conn.execute(
                &format!(
                    "DELETE FROM event_outbox WHERE event_id IN
                (SELECT event_id FROM trigger_events WHERE {SUBSCRIPTION_EVENTS_PREDICATE})"
                ),
                (owner.as_str(), subscription_id),
            )?;
            conn.execute(
                &format!("DELETE FROM trigger_events WHERE {SUBSCRIPTION_EVENTS_PREDICATE}"),
                (owner.as_str(), subscription_id),
            )?;
            conn.execute(
                "DELETE FROM probe_subscriptions WHERE subscription_id = ?1",
                [subscription_id],
            )?;
            let changed = conn.execute(
                "DELETE FROM trigger_subscriptions WHERE subscription_id = ?1",
                [subscription_id],
            )?;
            Ok(changed != 0)
        })
    }

    /// Stamp a poll attempt. Principal-scoped like every other write in this
    /// table, so the poller's bookkeeping cannot reach across principals.
    pub fn record_poll_attempt(
        &self,
        principal: &str,
        subscription_id: &str,
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE trigger_subscriptions
                 SET last_polled_at_ms = ?1, generation = generation + 1
                 WHERE subscription_id = ?2 AND principal = ?3 AND status = 'active'",
                (at_ms, subscription_id, principal),
            )? != 0)
        })
    }

    /// Commit a successful poll: advance the cursor, clear the vendor-failure
    /// streak, and stamp the success time.
    ///
    /// The principal scope matters most HERE. Cursor state decides which vendor
    /// records the next poll asks for, so an unscoped write is a silent
    /// data-loss primitive rather than a bookkeeping error: advancing another
    /// principal's cursor makes their poller skip the window it jumped over,
    /// and nothing downstream can tell the difference between "no events" and
    /// "we stopped looking".
    #[cfg(any(test, feature = "test-support"))]
    pub fn record_poll_success(
        &self,
        principal: &str,
        subscription_id: &str,
        cursor_state: &Value,
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let cursor_state = serde_json::to_string(cursor_state)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE trigger_subscriptions
                 SET cursor_state = ?1, last_success_at_ms = ?2,
                     consecutive_vendor_failures = 0, generation = generation + 1
                 WHERE subscription_id = ?3 AND principal = ?4 AND status = 'active'",
                (cursor_state, at_ms, subscription_id, principal),
            )? != 0)
        })
    }

    /// Count one vendor-side failure toward the backoff streak. Vendor failure
    /// only — an authorization denial must suspend instead, since backing off
    /// a revoked subscription leaves it claiming coverage it no longer has.
    pub fn record_vendor_failure(
        &self,
        principal: &str,
        subscription_id: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            Ok(conn.execute(
                "UPDATE trigger_subscriptions
                 SET consecutive_vendor_failures = consecutive_vendor_failures + 1,
                     generation = generation + 1
                 WHERE subscription_id = ?1 AND principal = ?2 AND status = 'active'",
                (subscription_id, principal),
            )? != 0)
        })
    }

    /// The principals that own state the scheduler can poll or health-probe.
    ///
    /// Subscriptions and connections are the authoritative ownership records.
    /// Audit history can outlive both until its retention window lapses, so
    /// consulting it would retain principals for which the scheduler has no work
    /// while making every one-second pass scan unrelated journal history.
    pub fn poll_and_probe_principals(&self) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal FROM trigger_subscriptions
                 UNION
                 SELECT principal FROM connections
                 ORDER BY principal",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect()
        })
    }
}
