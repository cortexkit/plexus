//! Grant authority, bounded minting, and governing policies.

use super::*;

/// Select the single policy governing an action at `now`.
///
/// Authorization and reservation claiming must use this same query so expiry
/// and selector priority cannot drift between the snapshot's writer and reader.
pub(super) fn governing_policy(
    conn: &Connection,
    principal: &str,
    connection_id: &str,
    action: &str,
    now: i64,
) -> rusqlite::Result<Option<PolicyRecord>> {
    conn.query_row(
        "SELECT policy_id, principal, connection_id, action_selector, effect,
                expires_at, generation
         FROM policies
         WHERE principal = ?1 AND connection_id = ?2
           AND (action_selector = ?3 OR action_selector = '*')
           AND (expires_at IS NULL OR expires_at > ?4)
         ORDER BY action_selector = '*' ASC, policy_id LIMIT 1",
        (principal, connection_id, action, now),
        |row| {
            Ok(PolicyRecord {
                policy_id: row.get(0)?,
                principal: row.get(1)?,
                connection_id: row.get(2)?,
                action_selector: row.get(3)?,
                effect: row.get(4)?,
                expires_at: row.get(5)?,
                generation: row.get(6)?,
            })
        },
    )
    .optional()
}

/// Mint every request on `conn`, the caller's transaction, each bounded by the
/// connection ceiling as it stands in that transaction, with one audit row per
/// grant. Every request is checked before any row is written, so a refusal
/// writes nothing. The caller commits, which lets a ceiling widening and the
/// grants that use it commit together.
pub(crate) fn mint_grants_bounded_on_conn(
    conn: &Connection,
    requests: &[GrantMintRequest],
    audit: AuditFor<'_, GrantRecord>,
) -> rusqlite::Result<Result<Vec<GrantRecord>, CeremonyRefusal>> {
    // The ceiling is read inside the insert transaction for every request, so
    // a revocation or narrowing committed before this transaction cannot be
    // outrun by a ceiling read earlier.
    let mut checked = Vec::with_capacity(requests.len());
    for request in requests {
        match bounded_grant_on_conn(conn, request)? {
            Ok(input) => checked.push(input),
            Err(refusal) => return Ok(Err(refusal)),
        }
    }
    let now = now_ms();
    let mut minted = Vec::with_capacity(checked.len());
    for input in checked {
        insert_grant_on_conn(conn, &input)?;
        let record = GrantRecord {
            state: grant_state(input.expires_at, None, now).to_string(),
            grant_id: input.grant_id,
            principal: input.principal,
            connection_id: input.connection_id,
            grantee_principal: input.grantee_principal,
            risk_ceiling: input.risk_ceiling,
            action_selectors: input.action_selectors,
            authority_kind: input.authority_kind,
            expires_at: input.expires_at,
            // `insert_grant` stores a new grant at generation 1.
            generation: 1,
            revoked_at_ms: None,
            revoked_by: None,
        };
        append_audit_for(conn, audit, &record)?;
        minted.push(record);
    }
    Ok(Ok(minted))
}

fn grant_summary_on_conn(
    conn: &Connection,
    principal: &str,
    grant_id: &str,
    now: i64,
) -> rusqlite::Result<Option<GrantSummary>> {
    conn.query_row(
        "SELECT g.grant_id,g.connection_id,c.app_key,g.grantee_principal,g.risk_ceiling,g.action_selectors,g.authority_kind,g.expires_at,g.created_at_ms,NULL,NULL FROM grants g LEFT JOIN connections c ON c.principal=g.principal AND c.connection_id=g.connection_id WHERE g.principal=?1 AND g.grant_id=?2",
        (principal, grant_id),
        |row| map_grant_summary_row(row, now),
    )
    .optional()
}

fn policy_summary_on_conn(
    conn: &Connection,
    principal: &str,
    policy_id: &str,
    now: i64,
) -> rusqlite::Result<Option<PolicySummary>> {
    conn.query_row(
        "SELECT p.policy_id,p.connection_id,c.app_key,p.action_selector,p.effect,p.expires_at FROM policies p LEFT JOIN connections c ON c.principal=p.principal AND c.connection_id=p.connection_id WHERE p.principal=?1 AND p.policy_id=?2",
        (principal, policy_id),
        |row| map_policy_summary_row(row, now),
    )
    .optional()
}

fn map_grant_summary_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<GrantSummary> {
    let expires_at = row.get(7)?;
    Ok(GrantSummary {
        grant_id: row.get(0)?,
        connection_id: row.get(1)?,
        app_key: row.get(2)?,
        grantee_principal: row.get(3)?,
        risk_ceiling: row.get(4)?,
        action_selectors: parse_string_list(&row.get::<_, String>(5)?)?,
        authority_kind: row.get(6)?,
        expires_at,
        created_at_ms: row.get(8)?,
        revoked_at_ms: row.get(9)?,
        revoked_by: row.get(10)?,
        state: grant_state(expires_at, row.get(9)?, now).into(),
    })
}
fn map_policy_summary_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<PolicySummary> {
    let expires_at = row.get(5)?;
    Ok(PolicySummary {
        policy_id: row.get(0)?,
        connection_id: row.get(1)?,
        app_key: row.get(2)?,
        action_selector: row.get(3)?,
        effect: row.get(4)?,
        expires_at,
        state: grant_state(expires_at, None, now).into(),
    })
}

pub(super) fn map_grant_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<GrantRecord> {
    Ok(GrantRecord {
        grant_id: row.get(0)?,
        principal: row.get(1)?,
        connection_id: row.get(2)?,
        grantee_principal: row.get(3)?,
        risk_ceiling: row.get(4)?,
        action_selectors: parse_string_list(&row.get::<_, String>(5)?)?,
        authority_kind: row.get(6)?,
        expires_at: row.get(7)?,
        generation: row.get(8)?,
        revoked_at_ms: None,
        revoked_by: None,
        state: grant_state(row.get(7)?, None, now).into(),
    })
}

pub(super) type PollGrants = std::collections::BTreeMap<(String, String), Vec<GrantRecord>>;

pub(super) fn grant_ceiling_on_conn(
    conn: &rusqlite::Connection,
    principal: &str,
    connection_id: &str,
) -> rusqlite::Result<Result<Ceiling, CeremonyRefusal>> {
    let row: Option<(String, Option<String>, Option<String>)> = conn.query_row(
        "SELECT status, ceiling_risk, ceiling_selectors FROM connections WHERE principal=?1 AND connection_id=?2",
        (principal, connection_id),
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let Some((status, risk, selectors)) = row else {
        return Ok(Err(CeremonyRefusal::ConnectionNotFound));
    };
    if status == "revoked" {
        return Ok(Err(CeremonyRefusal::ConnectionRevoked));
    }
    let (Some(risk), Some(selectors)) = (risk, selectors) else {
        return Ok(Err(CeremonyRefusal::CeilingAbsent));
    };
    let Some(risk) = Risk::parse(&risk) else {
        return Ok(Err(CeremonyRefusal::InvalidRisk(risk)));
    };
    Ok(Ok(Ceiling {
        risk,
        action_selectors: parse_string_list(&selectors)?,
    }))
}

/// Check one grant request against its connection's ceiling, read on `conn`,
/// and return the row to insert. Writes nothing.
fn bounded_grant_on_conn(
    conn: &rusqlite::Connection,
    request: &GrantMintRequest,
) -> rusqlite::Result<Result<GrantInput, CeremonyRefusal>> {
    let GrantMintRequest {
        principal,
        connection_id,
        grantee_principal,
        authority_kind,
        requested_risk,
        requested_selectors,
        expires_at,
    } = request;
    // Expiry is OPTIONAL for every authority kind, poll included.
    //
    // This deliberately reverses a rule that made poll expiry mandatory. The
    // old comment here claimed expiry was "the only mechanism that makes
    // inattention STOP polling rather than continue it", and that was untrue:
    // VISIBILITY PLUS EASY REVOCATION is another mechanism, and a better one.
    // Mandatory expiry puts the cost on the common case -- the operator still
    // wants the watch -- to defend against the rare one, and collects it
    // forever, on a schedule, from someone who already consented.
    //
    // The hidden assumption was that inattention should default to REVOKING.
    // For a personal fleet, where the grant was given deliberately, it should
    // default to CONTINUING; the remedy for "I forgot this existed" is a
    // surface listing every live grant with one-click revoke, not a deadline.
    //
    // SILENTLY is why the old rule was harmful rather than merely annoying:
    // when a poll grant lapsed the watches just stopped collecting. No error,
    // no alarm -- the feed went quiet and looked like a quiet week.
    //
    // An operator who WANTS a bounded grant still passes an expiry and it is
    // still enforced on every poll. What is gone is the refusal to mint
    // without one.
    let expires_at = *expires_at;
    let ceiling = match grant_ceiling_on_conn(conn, principal, connection_id)? {
        Ok(ceiling) => ceiling,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(risk) = Risk::parse(requested_risk) else {
        return Ok(Err(CeremonyRefusal::InvalidRisk(
            requested_risk.to_string(),
        )));
    };
    // Expand a requested wildcard against the connection's ceiling,
    // which may name fewer actions than the app manifest.
    let selectors = if requested_selectors.iter().any(|value| value == "*") {
        ceiling.action_selectors.clone()
    } else {
        requested_selectors.to_vec()
    };
    // Wildcards expand to the connection's actions; an empty expansion is
    // just as unusable as an explicitly empty request, not unrestricted.
    if selectors.is_empty() {
        return Ok(Err(CeremonyRefusal::EmptyActionSelectors));
    }
    if !risk.within(ceiling.risk) {
        return Ok(Err(CeremonyRefusal::RiskAboveCeiling {
            requested: risk.to_string(),
            ceiling: ceiling.risk.to_string(),
        }));
    }
    // A stored '*' selector admits any action. Match Ceiling::within's
    // subset rule so minting and later grant checks interpret it identically.
    let ceiling_is_open = ceiling.action_selectors.iter().any(|value| value == "*");
    if !ceiling_is_open {
        if let Some(outside) = selectors
            .iter()
            .find(|selector| !ceiling.action_selectors.contains(selector))
        {
            // Distinct from `UndeclaredAction`, which belongs to the
            // manifest link of the chain. Reusing it here sends an operator
            // to the manifest to look for an action that is sitting in the
            // manifest, fully declared -- so the message denies something
            // they can see is true, and the natural conclusion is that the
            // module is broken.
            //
            // The two also have completely different remedies. An undeclared
            // action is fixed by editing a manifest; a ceiling breach cannot
            // be fixed by minting a grant or issuing another ticket. It
            // requires an explicit operator ceiling-widening ceremony.
            return Ok(Err(CeremonyRefusal::OutsideConnectionCeiling {
                action: outside.clone(),
                ceiling: ceiling.action_selectors.clone(),
            }));
        }
    }
    Ok(Ok(GrantInput {
        grant_id: new_id("grant"),
        principal: principal.to_string(),
        connection_id: connection_id.to_string(),
        grantee_principal: grantee_principal.to_string(),
        risk_ceiling: risk.to_string(),
        action_selectors: selectors,
        authority_kind: authority_kind.to_string(),
        expires_at,
    }))
}

fn insert_grant_on_conn(conn: &rusqlite::Connection, input: &GrantInput) -> rusqlite::Result<()> {
    let selectors = serde_json::to_string(&input.action_selectors)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    conn.execute(
        "INSERT INTO grants
        (grant_id, principal, connection_id, grantee_principal, risk_ceiling,
        action_selectors, authority_kind, expires_at, generation, created_at_ms)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)",
        rusqlite::params![
            input.grant_id,
            input.principal,
            input.connection_id,
            input.grantee_principal,
            input.risk_ceiling,
            selectors,
            input.authority_kind,
            input.expires_at,
            now_ms()
        ],
    )?;
    Ok(())
}

/// Insert a policy in the caller's transaction alongside related grant writes.
pub(crate) fn insert_policy_on_conn(
    conn: &rusqlite::Connection,
    input: &PolicyInput,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO policies
            (policy_id, principal, connection_id, action_selector, effect,
             expires_at, generation, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
        rusqlite::params![
            input.policy_id,
            input.principal,
            input.connection_id,
            input.action_selector,
            input.effect,
            input.expires_at,
            now_ms(),
        ],
    )?;
    Ok(())
}

impl PlexusStore {
    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_grant(&self, input: &GrantInput) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| insert_grant_on_conn(conn, input))
    }

    /// Find a grant authorizing this call. `authority_kind` is the kind the
    /// CALLER claims, so an interactive request can never be satisfied by a
    /// poll grant nor a poll by an interactive one.
    // Separate arguments rather than a struct, so every authorization call
    // site spells out the grant lookup key (owner, connection, grantee, action
    // and authority kind) and whether a risk ceiling is checked
    // (`requested_risk`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matching_grant(
        &self,
        owner: &str,
        connection_id: &str,
        grantee: &str,
        action: &str,
        authority_kind: &str,
        now: i64,
        requested_risk: Option<&str>,
    ) -> Result<Option<GrantRecord>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                        action_selectors, authority_kind, expires_at, generation
                 FROM grants
                 WHERE principal = ?1 AND connection_id = ?2
                   AND authority_kind = ?4
                   AND grantee_principal = ?3 AND grantee_principal <> '*'
                   AND agent_id IS NULL
                 ORDER BY grant_id",
            )?;
            let rows = statement
                .query_map((owner, connection_id, grantee, authority_kind), |row| {
                    map_grant_row(row, now)
                })?;
            let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(grant_candidate(&rows, action, now, requested_risk).cloned())
        })
    }

    pub fn has_connection_admin_grant(
        &self,
        owner: &str,
        connection_id: &str,
        grantee: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_read(|conn| {
            connection_admin_grant_on_conn(conn, owner, connection_id, grantee, now_ms())
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn update_policy_effect(
        &self,
        principal: &str,
        policy_id: &str,
        effect: &str,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let changed = conn.execute(
                "UPDATE policies SET effect = ?1, generation = generation + 1,
                        updated_at_ms = ?2
                 WHERE principal = ?3 AND policy_id = ?4",
                (effect, now_ms(), principal, policy_id),
            )?;
            Ok(changed != 0)
        })
    }

    /// Create a policy, or update the policy scope an operator named.
    ///
    /// The lookup and the write share one transaction, and the effect and
    /// expiry change in one statement, so a reader never sees the new effect
    /// with the old expiry and two concurrent calls cannot both insert. The
    /// returned generation is the one stored.
    pub fn set_policy(
        &self,
        principal: &str,
        connection_id: &str,
        action_selector: &str,
        effect: &str,
        expires_at: Option<i64>,
    ) -> Result<PolicyRecord, StoreError> {
        self.set_policy_with(
            principal,
            connection_id,
            action_selector,
            effect,
            expires_at,
            None,
        )
    }

    /// [`Self::set_policy`] with its audit row, built from the stored policy,
    /// appended in the same fenced transaction: the policy and its record
    /// commit together, or neither does.
    pub fn set_policy_audited(
        &self,
        principal: &str,
        connection_id: &str,
        action_selector: &str,
        effect: &str,
        expires_at: Option<i64>,
        audit: &dyn Fn(&PolicyRecord) -> AuditRecord,
    ) -> Result<PolicyRecord, StoreError> {
        self.set_policy_with(
            principal,
            connection_id,
            action_selector,
            effect,
            expires_at,
            Some(audit),
        )
    }

    fn set_policy_with(
        &self,
        principal: &str,
        connection_id: &str,
        action_selector: &str,
        effect: &str,
        expires_at: Option<i64>,
        audit: AuditFor<'_, PolicyRecord>,
    ) -> Result<PolicyRecord, StoreError> {
        let candidate_id = new_id("policy");
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let existing: Option<String> = conn
                .query_row(
                    "SELECT policy_id FROM policies
                     WHERE principal = ?1 AND connection_id = ?2 AND action_selector = ?3
                     ORDER BY policy_id LIMIT 1",
                    (principal, connection_id, action_selector),
                    |row| row.get(0),
                )
                .optional()?;
            let policy_id = match existing {
                Some(policy_id) => {
                    conn.execute(
                        "UPDATE policies SET effect = ?1, expires_at = ?2,
                                generation = generation + 1, updated_at_ms = ?3
                         WHERE principal = ?4 AND policy_id = ?5",
                        rusqlite::params![effect, expires_at, now, principal, policy_id],
                    )?;
                    policy_id
                }
                None => {
                    insert_policy_on_conn(
                        conn,
                        &PolicyInput {
                            policy_id: candidate_id.clone(),
                            principal: principal.to_string(),
                            connection_id: connection_id.to_string(),
                            action_selector: action_selector.to_string(),
                            effect: effect.to_string(),
                            expires_at,
                        },
                    )?;
                    candidate_id.clone()
                }
            };
            let policy = conn.query_row(
                "SELECT policy_id, principal, connection_id, action_selector, effect,
                        expires_at, generation
                 FROM policies WHERE principal = ?1 AND policy_id = ?2",
                (principal, &policy_id),
                |row| {
                    Ok(PolicyRecord {
                        policy_id: row.get(0)?,
                        principal: row.get(1)?,
                        connection_id: row.get(2)?,
                        action_selector: row.get(3)?,
                        effect: row.get(4)?,
                        expires_at: row.get(5)?,
                        generation: row.get(6)?,
                    })
                },
            )?;
            append_audit_for(conn, audit, &policy)?;
            Ok(policy)
        })
    }

    /// Remove a policy. Returning false for an absent id makes retried operator
    /// removals safe.
    pub fn remove_policy(&self, principal: &str, policy_id: &str) -> Result<bool, StoreError> {
        self.remove_policy_with(principal, policy_id, None)
    }

    /// [`Self::remove_policy`] with its audit row, built from the policy as it
    /// stood just before the delete, appended in the delete's own fenced
    /// transaction. An absent policy removes nothing and writes no row.
    pub fn remove_policy_audited(
        &self,
        principal: &str,
        policy_id: &str,
        audit: &dyn Fn(&PolicySummary) -> AuditRecord,
    ) -> Result<bool, StoreError> {
        self.remove_policy_with(principal, policy_id, Some(audit))
    }

    fn remove_policy_with(
        &self,
        principal: &str,
        policy_id: &str,
        audit: AuditFor<'_, PolicySummary>,
    ) -> Result<bool, StoreError> {
        let now = now_ms();
        self.inner.with_conn_fenced(|conn| {
            let removed = match audit {
                Some(_) => policy_summary_on_conn(conn, principal, policy_id, now)?,
                None => None,
            };
            let changed = conn.execute(
                "DELETE FROM policies WHERE principal = ?1 AND policy_id = ?2",
                (principal, policy_id),
            )?;
            if let (true, Some(removed)) = (changed != 0, removed) {
                append_audit_for(conn, audit, &removed)?;
            }
            Ok(changed != 0)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_policy(&self, input: &PolicyInput) -> Result<(), StoreError> {
        self.inner
            .with_conn_fenced(|conn| insert_policy_on_conn(conn, input))
    }

    pub(crate) fn matching_policy(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        now: i64,
    ) -> Result<Option<PolicyRecord>, StoreError> {
        self.inner
            .with_read(|conn| governing_policy(conn, principal, connection_id, action, now))
    }

    /// Mint a grant, refused unless it is a subset of the connection's ceiling.
    /// The refusal path writes nothing.
    pub fn mint_grant_bounded(
        &self,
        request: &GrantMintRequest,
    ) -> Result<Result<GrantRecord, CeremonyRefusal>, StoreError> {
        self.mint_grant_bounded_with(request, None)
    }

    /// [`Self::mint_grant_bounded`] with its audit row, built from the minted
    /// grant, appended in the mint's own fenced transaction. A refusal writes
    /// neither a grant nor a row.
    pub fn mint_grant_bounded_audited(
        &self,
        request: &GrantMintRequest,
        audit: &dyn Fn(&GrantRecord) -> AuditRecord,
    ) -> Result<Result<GrantRecord, CeremonyRefusal>, StoreError> {
        self.mint_grant_bounded_with(request, Some(audit))
    }

    /// Mint several grants in one fenced transaction, each bounded exactly as
    /// [`Self::mint_grant_bounded_audited`] bounds one, with one audit row per
    /// grant. Every request is checked before any row is written, so a refusal
    /// of any one of them writes no grant and no row at all.
    pub fn mint_grants_bounded_audited(
        &self,
        requests: &[GrantMintRequest],
        audit: &dyn Fn(&GrantRecord) -> AuditRecord,
    ) -> Result<Result<Vec<GrantRecord>, CeremonyRefusal>, StoreError> {
        self.mint_grants_bounded_with(requests, Some(audit))
    }

    fn mint_grant_bounded_with(
        &self,
        request: &GrantMintRequest,
        audit: AuditFor<'_, GrantRecord>,
    ) -> Result<Result<GrantRecord, CeremonyRefusal>, StoreError> {
        Ok(self
            .mint_grants_bounded_with(std::slice::from_ref(request), audit)?
            .map(|mut minted| minted.remove(0)))
    }

    fn mint_grants_bounded_with(
        &self,
        requests: &[GrantMintRequest],
        audit: AuditFor<'_, GrantRecord>,
    ) -> Result<Result<Vec<GrantRecord>, CeremonyRefusal>, StoreError> {
        if requests
            .iter()
            .any(|request| request.grantee_principal == "*")
        {
            return Ok(Err(CeremonyRefusal::WildcardGrantee));
        }
        race_point("grant_insert");
        self.inner
            .with_conn_fenced(|conn| mint_grants_bounded_on_conn(conn, requests, audit))
    }

    /// Read one live grant by its owner-scoped id for revocation audit attribution.
    pub fn grant_by_id(
        &self,
        principal: &str,
        grant_id: &str,
    ) -> Result<Option<GrantSummary>, StoreError> {
        self.inner
            .with_read(|conn| grant_summary_on_conn(conn, principal, grant_id, now_ms()))
    }

    /// Read one policy without loading the owner's unrelated policy history.
    pub fn policy_by_id(
        &self,
        principal: &str,
        policy_id: &str,
    ) -> Result<Option<PolicySummary>, StoreError> {
        self.inner
            .with_read(|conn| policy_summary_on_conn(conn, principal, policy_id, now_ms()))
    }

    /// Every grant this principal holds, across all connections, shaped for an
    /// operator deciding what to revoke.
    ///
    /// WHY THIS EXISTS SEPARATELY from `list_grants`: that one answers "what is
    /// granted on THIS connection", which requires already knowing the connection
    /// id. An operator asking "what have I granted?" has no such starting point —
    /// and that is the question that matters, because the grant you need to
    /// revoke is by definition the one you forgot about.
    ///
    /// It carries `app_key` rather than only the connection id, because a
    /// connection id identifies a row and a vendor name identifies a decision.
    ///
    /// STATE IS DERIVED HERE, not left to the caller. A client recomputing
    /// liveness from a deadline and its own clock will eventually disagree with
    /// this module, silently and in the direction that shows a dead grant as
    /// live. One emitter, one answer.
    pub fn list_all_grants(&self, principal: &str) -> Result<Vec<GrantSummary>, StoreError> {
        let now = now_ms();
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT g.grant_id, g.connection_id, c.app_key, g.grantee_principal,
                        g.risk_ceiling, g.action_selectors, g.authority_kind,
                         g.expires_at, g.created_at_ms, g.revoked_at_ms, g.revoked_by
                 FROM (
                     SELECT grant_id, principal, connection_id, grantee_principal,
                            risk_ceiling, action_selectors, authority_kind, expires_at,
                            created_at_ms, NULL AS revoked_at_ms, NULL AS revoked_by FROM grants
                     UNION ALL
                     SELECT grant_id, principal, connection_id, grantee_principal,
                            risk_ceiling, action_selectors, authority_kind, expires_at,
                            created_at_ms, revoked_at_ms, revoked_by FROM grant_revocations
                 ) g
                 LEFT JOIN connections c
                   ON c.connection_id = g.connection_id AND c.principal = g.principal
                 WHERE g.principal = ?1
                 ORDER BY g.created_at_ms DESC",
            )?;
            let rows = statement.query_map((principal,), |row| map_grant_summary_row(row, now))?;
            rows.collect()
        })
    }

    /// List policies for a principal, optionally narrowed to one connection.
    ///
    /// Policies outlive a removed connection until an operator removes them, so
    /// this is deliberately a left join: hiding an orphaned policy would hide the
    /// row most likely to need cleanup.
    pub fn list_policies(
        &self,
        principal: &str,
        connection_id: Option<&str>,
    ) -> Result<Vec<PolicySummary>, StoreError> {
        let now = now_ms();
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT p.policy_id, p.connection_id, c.app_key, p.action_selector,
                        p.effect, p.expires_at
                 FROM policies p
                 LEFT JOIN connections c
                   ON c.connection_id = p.connection_id AND c.principal = p.principal
                 WHERE p.principal = ?1 AND (?2 IS NULL OR p.connection_id = ?2)
                 ORDER BY p.updated_at_ms DESC, p.policy_id",
            )?;
            let rows = statement.query_map((principal, connection_id), |row| {
                map_policy_summary_row(row, now)
            })?;
            rows.collect()
        })
    }

    /// List the grants recorded against a connection. An operator cannot decide
    /// what to revoke without seeing what exists, so this is part of the
    /// ceremony surface rather than an internal query.
    pub fn list_grants(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<GrantRecord>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                        action_selectors, authority_kind, expires_at, generation,
                        revoked_at_ms, revoked_by
                 FROM (
                     SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                            action_selectors, authority_kind, expires_at, generation, created_at_ms,
                            NULL AS revoked_at_ms, NULL AS revoked_by FROM grants
                     UNION ALL
                     SELECT grant_id, principal, connection_id, grantee_principal, risk_ceiling,
                            action_selectors, authority_kind, expires_at, generation, created_at_ms,
                            revoked_at_ms, revoked_by FROM grant_revocations
                 ) WHERE principal = ?1 AND connection_id = ?2 ORDER BY created_at_ms",
            )?;
            let rows = statement.query_map((principal, connection_id), |row| {
                let selectors: String = row.get(5)?;
                Ok(GrantRecord {
                    grant_id: row.get(0)?,
                    principal: row.get(1)?,
                    connection_id: row.get(2)?,
                    grantee_principal: row.get(3)?,
                    risk_ceiling: row.get(4)?,
                    action_selectors: parse_string_list(&selectors)?,
                    authority_kind: row.get(6)?,
                    expires_at: row.get(7)?,
                    generation: row.get(8)?,
                    revoked_at_ms: row.get(9)?,
                    revoked_by: row.get(10)?,
                    state: grant_state(row.get(7)?, row.get(9)?, now_ms()).to_string(),
                })
            })?;
            rows.collect()
        })
    }

    /// Durably journal before deleting authority in the fenced transaction.
    /// A failed transaction may leave an extra revocation, never an unjournalled
    /// deletion. The immutable SQL snapshot separately survives audit retention.
    /// Retries return false without creating another snapshot.
    pub fn revoke_grant(&self, principal: &str, grant_id: &str) -> Result<bool, StoreError> {
        self.revoke_grant_as(principal, grant_id, principal)
    }

    /// Revoke on the owner's authority while recording the actual revoking actor.
    pub fn revoke_grant_as(
        &self,
        principal: &str,
        grant_id: &str,
        actor: &str,
    ) -> Result<bool, StoreError> {
        self.revoke_grant_with(principal, grant_id, actor, None)
    }

    /// [`Self::revoke_grant_as`] with its audit row, built from the grant as
    /// it stood just before the revoke, appended in the revoke's own fenced
    /// transaction. An absent grant revokes nothing and writes no row.
    pub fn revoke_grant_audited(
        &self,
        principal: &str,
        grant_id: &str,
        actor: &str,
        audit: &dyn Fn(&GrantSummary) -> AuditRecord,
    ) -> Result<bool, StoreError> {
        self.revoke_grant_with(principal, grant_id, actor, Some(audit))
    }

    fn revoke_grant_with(
        &self,
        principal: &str,
        grant_id: &str,
        actor: &str,
        audit: AuditFor<'_, GrantSummary>,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let Some(revoked) = grant_summary_on_conn(conn, principal, grant_id, now_ms())? else {
                return Ok(false);
            };
            let entry = crate::grant_journal::Revocation {
                principal: principal.into(),
                grant_id: grant_id.into(),
                revoked_at_ms: now_ms(),
            };
            if let Some(path) = &self.grant_journal {
                crate::grant_journal::append(path, &entry)?;
            }
            let applied = crate::grant_journal::apply_as(conn, &entry, actor)? != 0;
            if applied {
                append_audit_for(conn, audit, &revoked)?;
            }
            Ok(applied)
        })
    }

    /// Every distinct agent id that holds at least one grant row, across all
    /// principals. A revoked grant has already left `grants`, so an agent whose
    /// grants were all revoked is not listed again.
    pub fn agents_holding_grants(&self) -> Result<Vec<String>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT DISTINCT agent_id FROM grants
                 WHERE agent_id IS NOT NULL ORDER BY agent_id",
            )?;
            let rows = statement.query_map([], |row| row.get(0))?;
            rows.collect()
        })
    }

    /// The grant rows held by one agent, whichever principal owns them.
    pub fn grants_held_by_agent(&self, agent_id: &str) -> Result<Vec<AgentHeldGrant>, StoreError> {
        self.inner.with_read(|conn| {
            let mut statement = conn.prepare(
                "SELECT principal, grant_id, connection_id FROM grants
                 WHERE agent_id = ?1 ORDER BY principal, grant_id",
            )?;
            let rows = statement.query_map([agent_id], |row| {
                Ok(AgentHeldGrant {
                    principal: row.get(0)?,
                    grant_id: row.get(1)?,
                    connection_id: row.get(2)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Test-only: insert a grant and attribute it to an agent, the shape a
    /// GitHub handle import or handle grant writes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_agent_grant_for_test(
        &self,
        input: &GrantInput,
        agent_id: &str,
    ) -> Result<(), StoreError> {
        self.insert_grant(input)?;
        self.inner.with_conn_fenced(|conn| {
            conn.execute(
                "UPDATE grants SET agent_id = ?3 WHERE principal = ?1 AND grant_id = ?2",
                rusqlite::params![input.principal, input.grant_id, agent_id],
            )?;
            Ok(())
        })
    }
}
