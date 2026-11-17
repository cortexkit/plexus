//! Bounded binding tickets and manifest-derived connection ceilings.

use super::*;

impl PlexusStore {
    /// Enroll a vault credential reference and return a single-use ticket.
    /// Public connect consumes the ticket, never credential material.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        credential_id_bytes: &[u8],
    ) -> Result<BindingTicket, StoreError> {
        self.create_binding_ticket_with_role(
            principal,
            connection_id,
            "credential_reference",
            credential_id_bytes,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket_with_role(
        &self,
        principal: &str,
        connection_id: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
    ) -> Result<BindingTicket, StoreError> {
        self.create_binding_ticket_bounded(
            principal,
            connection_id,
            ref_role,
            credential_id_bytes,
            &Ceiling::unrestricted_for_tests(),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket_with_instance(
        &self,
        principal: &str,
        connection_id: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        instance: Option<&crate::instance_url::InstanceUrl>,
    ) -> Result<BindingTicket, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            None,
            ref_role,
            credential_id_bytes,
            &Ceiling::unrestricted_for_tests(),
            None,
            instance,
        )?
        .map_err(|refusal| StoreError::Backend(format!("binding ticket refused: {refusal}")))
    }

    /// Store a validated vault id under `credential_reference`, or NULL under
    /// `none` for a manifest-reviewed credential-free vendor. The ticket carries
    /// the permanent authority ceiling; no resolved secret enters SQLite.
    ///
    /// The connection must already exist. Its refusals (revoked, or a ceiling
    /// wider than the one already recorded) surface as a store error; the
    /// operator ceremony uses [`Self::issue_binding_ticket`], which reports
    /// them by name.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_binding_ticket_bounded(
        &self,
        principal: &str,
        connection_id: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
    ) -> Result<BindingTicket, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            None,
            ref_role,
            credential_id_bytes,
            ceiling,
            None,
            None,
        )?
        .map_err(|refusal| StoreError::Backend(format!("binding ticket refused: {refusal}")))
    }

    /// Issue the ticket that enrolls `connection_id` for `app_key`, creating the
    /// connection as `pending` when the principal has none with that id.
    ///
    /// A ticket may re-enroll an existing connection of the same app that is
    /// not revoked, but it never changes that connection's ceiling, which is
    /// permanent once set: a wider request is refused by name, and an equal or
    /// narrower one is accepted and the recorded ceiling stays as it was. It is
    /// refused for a connection of a different app, whose ceiling would
    /// otherwise be judged against the wrong vendor, and for a revoked
    /// connection, which never becomes active again. The checks and the writes
    /// share one transaction, and a refusal writes nothing.
    pub fn issue_binding_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            Some(app_key),
            ref_role,
            credential_id_bytes,
            ceiling,
            None,
            None,
        )
    }

    /// [`Self::issue_binding_ticket`] with its audit row, built from the issued
    /// ticket, appended in the issue's own fenced transaction. A refusal writes
    /// neither a ticket nor a row.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_binding_ticket_audited(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
        audit: &dyn Fn(&BindingTicket) -> AuditRecord,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            Some(app_key),
            ref_role,
            credential_id_bytes,
            ceiling,
            Some(audit),
            None,
        )
    }

    /// Issue an operator-approved destination with its ticket, never through
    /// the agent-facing connect arguments. The address stays out of the audit.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_binding_ticket_audited_at_instance(
        &self,
        principal: &str,
        connection_id: &str,
        app_key: &str,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
        audit: &dyn Fn(&BindingTicket) -> AuditRecord,
        instance: Option<&crate::instance_url::InstanceUrl>,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        self.write_binding_ticket(
            principal,
            connection_id,
            Some(app_key),
            ref_role,
            credential_id_bytes,
            ceiling,
            Some(audit),
            instance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_binding_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        create_for_app: Option<&str>,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
        audit: AuditFor<'_, BindingTicket>,
        instance: Option<&crate::instance_url::InstanceUrl>,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        self.write_binding_ticket_with_mailbox(
            principal,
            connection_id,
            create_for_app,
            ref_role,
            credential_id_bytes,
            ceiling,
            audit,
            instance,
            None,
        )
    }

    /// Gmail enrollment records the verified mailbox in the ticket transaction.
    pub fn issue_gmail_ticket(
        &self,
        principal: &str,
        connection_id: &str,
        mailbox: &str,
        ceiling: &Ceiling,
        audit: &dyn Fn(&BindingTicket) -> AuditRecord,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        self.write_binding_ticket_with_mailbox(
            principal,
            connection_id,
            Some("gmail"),
            "credential_reference",
            b"oauth:gmail",
            ceiling,
            Some(audit),
            None,
            Some(mailbox),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_binding_ticket_with_mailbox(
        &self,
        principal: &str,
        connection_id: &str,
        create_for_app: Option<&str>,
        ref_role: &str,
        credential_id_bytes: &[u8],
        ceiling: &Ceiling,
        audit: AuditFor<'_, BindingTicket>,
        instance: Option<&crate::instance_url::InstanceUrl>,
        mailbox: Option<&str>,
    ) -> Result<Result<BindingTicket, CeremonyRefusal>, StoreError> {
        if create_for_app == Some("gmail") && mailbox.is_none() {
            return Err(StoreError::Backend(
                "gmail_account_unconfirmed: verified mailbox required".into(),
            ));
        }
        if let Some(app_key) = create_for_app {
            match (
                self.manifest_takes_instance_url(app_key)?,
                instance.is_some(),
            ) {
                (true, false) => {
                    return Err(StoreError::Backend(
                        "this provider requires instance_url".into(),
                    ))
                }
                (false, true) => {
                    return Err(StoreError::Backend(
                        "this provider takes no instance_url".into(),
                    ))
                }
                _ => {}
            }
        }
        let credential_free = ref_role == NO_CREDENTIAL_REF_ROLE;
        if credential_free != credential_id_bytes.is_empty() {
            return Err(StoreError::Backend(
                "binding ticket: a credential-free enrollment must supply no credential id, and a \
                 credentialed one must supply a credential id"
                    .to_string(),
            ));
        }
        let binding = if credential_free {
            None
        } else if ref_role == "credential_reference" {
            let id = std::str::from_utf8(credential_id_bytes)
                .map_err(|_| StoreError::Backend("invalid credential id".into()))?;
            Some(encode_reference_binding(id).map_err(StoreError::Backend)?)
        } else {
            return Err(StoreError::Backend(
                "handle_bindings_removed: use credential_id with credential_reference".into(),
            ));
        };
        let ticket_id = new_id("ticket");
        let expires_at = now_ms().saturating_add(BINDING_TICKET_TTL_MS);
        let selectors = serde_json::to_string(&ceiling.action_selectors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let risk = ceiling.risk.to_string();
        let now = now_ms();
        let ticket = BindingTicket {
            ticket_id: ticket_id.clone(),
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            ref_role: ref_role.to_string(),
            expires_at,
            status: "issued".to_string(),
            instance_url: instance.cloned(),
        };
        let refusal = self.inner.with_conn_fenced(|conn| {
            let existing: Option<(String, String, Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT app_key, status, ceiling_risk, ceiling_selectors FROM connections
                     WHERE principal = ?1 AND connection_id = ?2",
                    (principal, connection_id),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            match (existing, create_for_app) {
                (None, None) => return Ok(Some(CeremonyRefusal::ConnectionNotFound)),
                (None, Some(app_key)) => {
                    conn.execute(
                        "INSERT INTO connections
                            (connection_id, principal, app_key, status, resource_filters,
                             created_at_ms, updated_at_ms)
                         VALUES (?1, ?2, ?3, 'pending', '{}', ?4, ?4)",
                        rusqlite::params![connection_id, principal, app_key, now],
                    )?;
                }
                (Some((app_key, status, ceiling_risk, ceiling_selectors)), requested_app) => {
                    if let Some(requested_app) = requested_app.filter(|app| *app != app_key) {
                        return Ok(Some(CeremonyRefusal::ConnectionAppMismatch {
                            connection_app: app_key,
                            requested_app: requested_app.to_string(),
                        }));
                    }
                    if status == "revoked" {
                        return Ok(Some(CeremonyRefusal::ConnectionRevoked));
                    }
                    if status != "pending" {
                        return Ok(Some(CeremonyRefusal::ConnectionExists));
                    }
                    if let (Some(recorded_risk), Some(recorded_selectors)) =
                        (ceiling_risk, ceiling_selectors)
                    {
                        if let Some(refusal) =
                            wider_than_recorded(ceiling, &recorded_risk, &recorded_selectors)?
                        {
                            return Ok(Some(refusal));
                        }
                    }
                }
            }
            if let Some(mailbox) = mailbox {
                conn.execute("INSERT INTO gmail_accounts(principal,connection_id,mailbox) VALUES (?1,?2,?3) ON CONFLICT(principal,connection_id) DO UPDATE SET mailbox=CASE WHEN mailbox=excluded.mailbox THEN mailbox ELSE NULL END", [principal,connection_id,mailbox])?;
            }
            // The pending binding belongs only to the newest ticket. Superseded
            // tickets must not pair their ceiling with that newer credential.
            conn.execute(
                "UPDATE binding_tickets SET status='expired', settled_at_ms=?3
                 WHERE principal=?1 AND connection_id=?2 AND status='issued'",
                (principal, connection_id, now),
            )?;
            conn.execute(
                "UPDATE connections SET credential_binding = ?1, updated_at_ms = ?2,
                        generation = generation + 1
                 WHERE principal = ?3 AND connection_id = ?4 AND status <> 'revoked'",
                rusqlite::params![binding, now, principal, connection_id],
            )?;
            conn.execute(
                "INSERT INTO binding_tickets
                    (ticket_id, principal, connection_id, ref_role, expires_at, status,
                     created_at_ms, risk_ceiling, action_selectors, instance_url)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'issued', ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    ticket_id,
                    principal,
                    connection_id,
                    ref_role,
                    expires_at,
                    now,
                    risk,
                    selectors,
                    instance.map(|url| url.as_str())
                ],
            )?;
            append_audit_for(conn, audit, &ticket)?;
            Ok(None)
        })?;
        if let Some(refusal) = refusal {
            return Ok(Err(refusal));
        }
        Ok(Ok(ticket))
    }

    /// Resolve a requested ceiling against the vendor's reviewed manifest.
    ///
    /// This is the first link of the authority chain: no ticket may authorize an
    /// action the vendor never declared, nor a risk above the highest risk the
    /// vendor's own action set contains. A `"*"` selector expands here to the
    /// manifest's declared action names, so the stored ceiling is concrete.
    pub fn ceiling_within_manifest(
        &self,
        app_key: &str,
        requested_risk: &str,
        requested_selectors: &[String],
    ) -> Result<Result<Ceiling, CeremonyRefusal>, StoreError> {
        let Some(risk) = Risk::parse(requested_risk) else {
            return Ok(Err(CeremonyRefusal::InvalidRisk(
                requested_risk.to_string(),
            )));
        };
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(Err(CeremonyRefusal::UnknownApp(app_key.to_string())));
        };
        // A retired manifest is refused here, at the FIRST link of the authority
        // chain, so no ticket can be minted against a vendor withdrawn from the
        // reviewed catalog. Hiding it from the connectable list is not enough on
        // its own: an operator working from a remembered app key, a script, or a
        // scrollback would otherwise still reach it, and the retirement exists
        // precisely because someone decided the vendor must not be used.
        if self.manifest_is_retired(app_key)? {
            return Ok(Err(CeremonyRefusal::RetiredApp(app_key.to_string())));
        }
        let manifest = document.map_err(StoreError::Backend)?;
        let declared: Vec<String> = manifest
            .actions_baseline
            .iter()
            .map(|action| action.name.clone())
            .collect();
        let manifest_max = manifest
            .actions_baseline
            .iter()
            .map(|action| action.risk)
            .max()
            .unwrap_or(Risk::Read);
        if !risk.within(manifest_max) {
            return Ok(Err(CeremonyRefusal::RiskAboveCeiling {
                requested: risk.to_string(),
                ceiling: manifest_max.to_string(),
            }));
        }
        let selectors = if requested_selectors.iter().any(|value| value == "*") {
            declared
        } else {
            for selector in requested_selectors {
                if !declared.contains(selector) {
                    return Ok(Err(CeremonyRefusal::UndeclaredAction(selector.clone())));
                }
            }
            requested_selectors.to_vec()
        };
        Ok(Ok(Ceiling {
            risk,
            action_selectors: selectors,
        }))
    }

    /// True when the vendor's reviewed manifest declares `auth.mode = none`.
    /// An unknown or unparseable manifest reports `false`, so a catalog problem
    /// makes a vendor look credentialed rather than credential-free — the
    /// direction that fails closed.
    pub fn manifest_requires_no_credential(&self, app_key: &str) -> Result<bool, StoreError> {
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(false);
        };
        let manifest = match document {
            Ok(manifest) => manifest,
            Err(_) => return Ok(false),
        };
        Ok(matches!(
            manifest.auth.mode,
            crate::manifest::AuthMode::None
        ))
    }

    /// Whether the reviewed manifest requires an operator-selected destination.
    /// A missing manifest declares no destination. Malformed documents and
    /// storage failures refuse rather than silently allowing a fixed endpoint.
    pub fn manifest_takes_instance_url(&self, app_key: &str) -> Result<bool, StoreError> {
        let Some(document) = self.parsed_manifest(CATALOG_PRINCIPAL, app_key)? else {
            return Ok(false);
        };
        let manifest = document
            .map_err(|_| StoreError::Backend("reviewed manifest could not be read".into()))?;
        Ok(manifest.transport.url_from_connection)
    }

    /// Whether the catalog's manifest for `app_key` declares an optional API key
    /// (`auth.mode = optional_api_key`). Only such a vendor may be enrolled
    /// either with an API-key reference or without one.
    pub fn manifest_has_optional_credential(&self, app_key: &str) -> Result<bool, StoreError> {
        Ok(matches!(
            self.parsed_manifest(CATALOG_PRINCIPAL, app_key)?,
            Some(Ok(manifest)) if manifest.auth.mode == crate::manifest::AuthMode::OptionalApiKey
        ))
    }

    /// The ceiling recorded on a connection, or `CeilingAbsent` when the
    /// connection predates ceilings (fail closed: nothing may be minted).
    pub fn connection_ceiling(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Result<Ceiling, CeremonyRefusal>, StoreError> {
        let row: Option<(Option<String>, Option<String>)> = self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT ceiling_risk, ceiling_selectors FROM connections
                 WHERE principal = ?1 AND connection_id = ?2",
                (principal, connection_id),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
        })?;
        let Some((risk, selectors)) = row else {
            return Ok(Err(CeremonyRefusal::ConnectionNotFound));
        };
        let (Some(risk), Some(selectors)) = (risk, selectors) else {
            return Ok(Err(CeremonyRefusal::CeilingAbsent));
        };
        let Some(risk) = Risk::parse(&risk) else {
            return Ok(Err(CeremonyRefusal::InvalidRisk(risk)));
        };
        let action_selectors = parse_string_list(&selectors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(Ok(Ceiling {
            risk,
            action_selectors,
        }))
    }
}
