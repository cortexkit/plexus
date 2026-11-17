//! Dispatch preparation, credential resolution, outcome reporting and governance audit records.

use super::*;

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    /// Dispatch an authorized reservation after confirming its target is
    /// still current. A failed check refuses the call as not sent, audited
    /// like every other pre-dispatch refusal. Used by facade invokes and by
    /// approved requests, which may run long after they were raised.
    pub(super) fn dispatch_checked(&self, reservation: &Reservation) -> DispatchOutcome {
        if let Some(check) = &self.freshness_check {
            if let Err((code, message)) = check(reservation) {
                return self.refuse_before_transmit(reservation, &code, &message);
            }
        }
        self.revalidate_and_dispatch(reservation)
    }

    pub(super) fn report_unsent_plane_allow(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        args_hash: &str,
        decision_id: &str,
        denial: &Denial,
    ) {
        let Some(plane) = self.decision_plane.as_ref() else {
            return;
        };
        let report = OutcomeReport {
            decision_id: decision_id.into(),
            terminal: OutcomeTerminal::Refused {
                reason: denial.reason_code().into(),
            },
        };
        if !(0..OUTCOME_REPORT_ATTEMPTS).any(|_| plane.report_outcome(&report).is_ok()) {
            self.audit_authorization_decision(
                request,
                args_hash,
                Some(connection),
                Some(action),
                None,
                "decision_plane",
                "deny",
                "outcome_report_failed",
                None,
            );
        }
    }

    /// Nothing was sent, so undo the dispatch marker `pre_transmit` wrote.
    /// Without this a transient credential refusal could not release its
    /// receipt claim for a same-nonce retry.
    pub(super) fn abandon_marked_transmit(&self, reservation: &Reservation) {
        if let Some(seams) = self.seams.as_ref() {
            seams.abandon_transmit(reservation);
        }
    }

    /// Everything dispatch needs before it may claim: the connection, what it
    /// presents to the vendor, and for a vault-bound credential the secret
    /// itself. On a refusal the reservation is abandoned unclaimed, so an
    /// approval behind it is not consumed, and the returned outcome says why.
    pub(super) fn prepare_dispatch_credential(
        &self,
        reservation: &Reservation,
    ) -> Result<PreparedCredential, Box<DispatchOutcome>> {
        let refuse = |denial: CredentialDenial| {
            self.abandon_unsent_reservation(reservation);
            let reason = denial.reason_code().to_string();
            let outcome = self.dispatch_credential_denial(reservation, denial);
            Box::new(self.maybe_report_decision_outcome(
                reservation,
                outcome,
                OutcomeTerminal::Refused { reason },
            ))
        };
        let connection = match self
            .store
            .connection(&reservation.principal, &reservation.connection_id)
        {
            Ok(Some(connection)) => connection,
            Ok(None) => return Err(refuse(CredentialDenial::Missing)),
            Err(error) => {
                // A failed read is not a missing credential: the connection
                // may be fine, and a retry can succeed.
                eprintln!(error governance:
                    "connection {} unreadable at dispatch: {error}",
                    reservation.connection_id
                );
                self.abandon_unsent_reservation(reservation);
                self.audit_dispatch_denial(reservation, "store_failure");
                return Err(Box::new(self.maybe_report_decision_outcome(
                    reservation,
                    DispatchOutcome::not_sent(
                        reservation,
                        "store_failure".to_string(),
                        "the connection could not be read".to_string(),
                        Retryability::AutoRetryable,
                    ),
                    OutcomeTerminal::Refused {
                        reason: "store_failure".to_string(),
                    },
                )));
            }
        };
        // A Gmail send is prepared by its own backend, not by the ordinary
        // token exchange. The backend checks that the vault's credential still
        // belongs to the mailbox this connection was set up for, composes the
        // message itself, and on a 401 reports the exact credential version it
        // was served so the vault refreshes the right login.
        if connection.app_key == "gmail" && reservation.action == "gmail.send" {
            let request = TransportRequest {
                request_id: reservation.request_id.clone(),
                connection_id: reservation.connection_id.clone(),
                action: reservation.action.clone(),
                args: reservation.args.clone(),
                credential_fingerprint: reservation.credential_fingerprint.clone(),
            };
            let prepared = match self.gmail.as_ref() {
                Some(backend) => {
                    backend.prepare(&self.store, &reservation.principal, &request, self.now_ms())
                }
                None => Err(Box::new(crate::gmail::refusal(
                    "gmail_vault_unavailable",
                    true,
                ))),
            };
            let gmail = match prepared {
                Ok(prepared) => prepared,
                Err(response) => {
                    self.abandon_unsent_reservation(reservation);
                    let code = response
                        .error_code
                        .clone()
                        .unwrap_or_else(|| "gmail_preparation_failed".into());
                    self.audit_dispatch_denial(reservation, &code);
                    return Err(Box::new(self.maybe_report_decision_outcome(
                        reservation,
                        DispatchOutcome::not_sent(
                            reservation,
                            code.clone(),
                            "Gmail preparation was refused".into(),
                            response.retryability,
                        ),
                        OutcomeTerminal::Refused { reason: code },
                    )));
                }
            };
            return Ok(PreparedCredential {
                connection,
                material: CredentialMaterial::Waived,
                vault_credential: None,
                gmail: Some(gmail),
            });
        }
        let material = self.credential_material(&connection).map_err(refuse)?;
        let vault_credential = match &material {
            CredentialMaterial::Bound(handle) => {
                match handle.resolve(self.credential_source.as_ref()) {
                    Ok(credential) => Some(credential),
                    Err(error) => {
                        self.abandon_unsent_reservation(reservation);
                        let denial = credential_denial(&error);
                        self.audit_dispatch_denial_with_fingerprint(
                            reservation,
                            denial.reason_code(),
                            &handle.fingerprint(),
                        );
                        // A transient vault failure is worth retrying: this
                        // runs before the claim, so the approval behind the
                        // reservation, if any, was not consumed and a retry
                        // can still use it. A permanent failure stays terminal.
                        let retryability = if matches!(error, CredentialError::Transient(_)) {
                            Retryability::AutoRetryable
                        } else {
                            Retryability::Terminal
                        };
                        return Err(Box::new(self.maybe_report_decision_outcome(
                            reservation,
                            DispatchOutcome {
                                retry_after_ms: None,
                                error_signal: None,
                                reconciliation: None,
                                reservation_id: reservation.reservation_id.clone(),
                                transmission: TransmissionState::NotSent,
                                retryability,
                                outcome: TransportOutcome::NotSent {
                                    code: denial.reason_code().to_string(),
                                    message: "credential could not be resolved".to_string(),
                                },
                            },
                            OutcomeTerminal::Refused {
                                reason: denial.reason_code().to_string(),
                            },
                        )));
                    }
                }
            }
            CredentialMaterial::Waived | CredentialMaterial::GithubApp => None,
        };
        Ok(PreparedCredential {
            connection,
            material,
            vault_credential,
            gmail: None,
        })
    }
    /// Refuse an authorized reservation before anything is transmitted, with
    /// `code` and `message`, audited like every other pre-dispatch refusal.
    /// For checks the caller runs between authorization and dispatch.
    pub(super) fn refuse_before_transmit(
        &self,
        reservation: &Reservation,
        code: &str,
        message: &str,
    ) -> DispatchOutcome {
        let mut outcome = self.deny_before_transmit(reservation, code.to_string());
        if let TransportOutcome::NotSent { message: text, .. } = &mut outcome.outcome {
            *text = message.to_string();
        }
        outcome
    }

    pub(super) fn deny_before_transmit(
        &self,
        reservation: &Reservation,
        code: String,
    ) -> DispatchOutcome {
        self.abandon_unsent_reservation(reservation);
        self.audit_dispatch_denial(reservation, &code);
        self.maybe_report_decision_outcome(
            reservation,
            DispatchOutcome::not_sent(
                reservation,
                code.clone(),
                "authority changed before transmission".into(),
                Retryability::Terminal,
            ),
            OutcomeTerminal::Refused { reason: code },
        )
    }

    pub(super) fn maybe_report_decision_outcome(
        &self,
        reservation: &Reservation,
        outcome: DispatchOutcome,
        terminal: OutcomeTerminal,
    ) -> DispatchOutcome {
        let Some(decision_id) = reservation.decision_id.as_ref() else {
            return outcome;
        };
        let Some(plane) = self.decision_plane.as_ref() else {
            return outcome;
        };
        let report = OutcomeReport {
            decision_id: decision_id.clone(),
            terminal,
        };
        // Count what actually happened rather than reporting the constant. The
        // two agree today only because the loop always runs to exhaustion
        // before reaching the audit — a coupling nothing enforces, so the first
        // early `break` (a permanent error not worth retrying, say) would leave
        // the audit claiming three attempts for a report tried once. An audit
        // row is read during reconciliation with the decision plane, where the
        // number of attempts is evidence about how hard the outcome was chased.
        let mut last_error = None;
        let mut attempts = 0_i64;
        for _ in 0..OUTCOME_REPORT_ATTEMPTS {
            attempts += 1;
            match plane.report_outcome(&report) {
                Ok(()) => return outcome,
                Err(error) => last_error = Some(error),
            }
        }
        let detail = last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        if let Err(error) = self.store.append_audit(&AuditRecord {
            risk: Some(risk_str(reservation.risk).to_string()),
            severity: Some(reservation.severity.as_str().to_string()),
            args_redaction_summary: Some(format!("decision_id:{decision_id}; detail:{detail}")),
            outcome: Some("report_failed".to_string()),
            credential_fingerprint: Some(reservation.credential_fingerprint.clone()),
            attempt_no: Some(attempts),
            idempotency_key_fingerprint: self.receipt_request_fingerprint(reservation),
            ..AuditRecord::for_reservation(
                reservation,
                if matches!(
                    report.terminal,
                    OutcomeTerminal::Executed { .. } | OutcomeTerminal::OutcomeUnknown { .. }
                ) {
                    "allow"
                } else {
                    "deny"
                },
                "outcome_report_failed",
                "decision_plane",
            )
        }) {
            eprintln!(error governance: "audit append failed: outcome_report_failed principal={:?} actor={:?} request_id={:?}: {error}", reservation.principal, reservation.actor, reservation.request_id);
        }
        outcome
    }

    /// True when the vendor's reviewed manifest declares `auth.mode = none`.
    ///
    /// Delegates to the store rather than re-deriving it, because the ceremony
    /// asks the same question when deciding whether to demand a credential reference. Two
    /// implementations of "does this vendor need a credential" can drift, and
    /// the drift would be silent and asymmetric: an enrollment that skipped the
    /// credential while dispatch still demanded one produces a permanently unusable
    /// connection, and the reverse would call a credentialed vendor
    /// anonymously.
    ///
    /// A manifest that cannot be read or parsed reports `false` — requiring a
    /// credential — so a catalog problem can never widen access.
    fn manifest_is_credential_free(&self, app_key: &str) -> bool {
        self.store
            .manifest_requires_no_credential(app_key)
            .unwrap_or(false)
    }

    /// What a call on this connection must present to the vendor: either the
    /// stored vault reference, or the waiver for a vendor that needs none.
    ///
    /// Authorization and dispatch both ask this question, and this is the only
    /// place either of them answers it. Two implementations would drift, and
    /// the drift is silent in both directions: a dispatch that demanded a
    /// credential an enrollment never stored leaves a connectable vendor
    /// permanently uncallable, and the reverse calls a credentialed vendor
    /// anonymously.
    ///
    /// Only the vendor's REVIEWED MANIFEST may waive the credential. A missing
    /// binding alone never permits anonymous access: the manifest must declare
    /// no auth or an optional key. If an optional key is bound, it must resolve;
    /// a vault failure must not silently downgrade that connection to anonymous.
    pub(super) fn credential_material(
        &self,
        connection: &ConnectionRecord,
    ) -> Result<CredentialMaterial, CredentialDenial> {
        if self.manifest_is_credential_free(&connection.app_key) {
            return Ok(CredentialMaterial::Waived);
        }
        if !connection.has_credential_binding
            && self
                .store
                .manifest_has_optional_credential(&connection.app_key)
                .unwrap_or(false)
        {
            return Ok(CredentialMaterial::Waived);
        }
        if let Some(seams) = &self.seams {
            match seams.handle_row(connection) {
                // GitHub App authority is prepared by the dedicated App provider,
                // not by the connection's vault-reference binding resolver.
                Ok(Some(_)) => return Ok(CredentialMaterial::GithubApp),
                Err(error) => {
                    eprintln!(error governance: "handle authority unreadable: {error:?}");
                    return Err(CredentialDenial::StoreUnavailable);
                }
                Ok(None) => {}
            }
        }
        match self
            .store
            .connection_credential_binding(&connection.principal, &connection.connection_id)
        {
            Ok(Some(binding)) => Ok(CredentialMaterial::Bound(binding)),
            Ok(None) => Err(CredentialDenial::Missing),
            Err(error) => {
                eprintln!(error governance: "connection credential binding unreadable: {error}");
                Err(CredentialDenial::StoreUnavailable)
            }
        }
    }

    pub(super) fn resolve_credential(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
    ) -> Result<(String, ResolvedCredential), Denial> {
        if let Some(seams) = &self.seams {
            if let Some(handle) = seams.handle_row(connection)? {
                let encoded = serde_json::to_vec(&(
                    &handle.credential_reference,
                    handle.credential_generation,
                ))
                .map_err(|_| Denial::StoreFailure)?;
                return Ok((fingerprint(&encoded), ResolvedCredential::anonymous()));
            }
            if request.origin == RequestOrigin::Facade {
                return Err(Denial::Credential(CredentialDenial::Missing));
            }
        }
        let handle = match self
            .credential_material(connection)
            .map_err(Denial::Credential)?
        {
            CredentialMaterial::GithubApp => {
                return Err(Denial::Credential(CredentialDenial::Missing))
            }
            CredentialMaterial::Waived => {
                return Ok((
                    anonymous_credential_fingerprint(),
                    ResolvedCredential::anonymous(),
                ));
            }
            CredentialMaterial::Bound(handle) => handle,
        };
        let handle_fingerprint = handle.fingerprint();
        // Authorization binds the reservation to the reference, not a token
        // snapshot. Read the vault only at dispatch so rotation or revocation
        // since authorization is observed before sending to the vendor.
        Ok((handle_fingerprint, ResolvedCredential::anonymous()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn audit_authorization_decision(
        &self,
        request: &AuthorizationRequest,
        args_hash: &str,
        connection: Option<&ConnectionRecord>,
        action: Option<&CatalogAction>,
        grant: Option<&GrantRecord>,
        gate: &str,
        decision: &str,
        reason: &str,
        credential_fingerprint: Option<String>,
    ) {
        let record = AuditRecord {
            principal: connection
                .map(|value| value.principal.clone())
                .unwrap_or_else(|| request.principal.clone()),
            actor: request.actor.clone(),
            acting_principal: request.principal.clone(),
            agent_id: request.attributed_agent_id.clone(),
            app_handle_id: if request.origin == RequestOrigin::Facade {
                request.bound_agent_handle.clone()
            } else {
                None
            },
            agent_handle: request.bound_agent_handle.clone(),
            connection_id: connection.map(|value| value.connection_id.clone()),
            app_key: connection.map(|value| value.app_key.clone()),
            action: Some(request.action.clone()),
            risk: action.map(|value| value.risk.clone()),
            severity: action
                .and_then(|action| {
                    connection.and_then(|connection| {
                        effective_severity(action, &connection.app_key, &self.store).ok()
                    })
                })
                .map(|severity| severity.as_str().to_string()),
            decision: decision.to_string(),
            reason_code: reason.to_string(),
            gate: Some(gate.to_string()),
            args_redaction_summary: Some(self.recipient_audit_summary(
                args_hash,
                connection.map(|connection| connection.app_key.as_str()),
                &request.action,
                &request.args,
            )),
            outcome: None,
            latency_ms: None,
            request_id: Some(request.request_id.clone()),
            credential_fingerprint,
            provider_account_fingerprint: None,
            attempt_no: Some(1),
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: grant.map(|value| value.authority_kind.clone()),
            reconciliation_of: None,
        };
        let result = if let Some(caller) = request.federated_caller.as_ref() {
            self.store.append_audit_federated(
                &record,
                request.scope.as_ref(),
                request.relay_origin.as_ref(),
                caller,
                request.federated_row_id.as_deref(),
                request.federated_card_ref.as_deref(),
            )
        } else {
            self.store.append_audit_relayed(
                &record,
                request.scope.as_ref(),
                request.relay_origin.as_ref(),
                request.on_behalf_of_agent.as_deref(),
            )
        };
        if let Err(error) = result {
            eprintln!(error governance: "audit append failed: authorization decision={decision:?} reason={reason:?} principal={:?} actor={:?} acting_principal={:?} request_id={:?} action={:?}: {error}", connection.map(|value| value.principal.as_str()).unwrap_or(&request.principal), request.actor, request.principal, request.request_id, request.action);
        }
    }

    pub(super) fn audit_denial(
        &self,
        request: &AuthorizationRequest,
        args_hash: &str,
        connection: Option<&ConnectionRecord>,
        action: Option<&CatalogAction>,
        grant: Option<&GrantRecord>,
        denial: &Denial,
    ) {
        self.audit_authorization_decision(
            request,
            args_hash,
            connection,
            action,
            grant,
            gate_for_denial(denial),
            "deny",
            denial.reason_code(),
            None,
        );
    }

    pub(super) fn audit_dispatch_denial(&self, reservation: &Reservation, reason: &str) {
        self.audit_dispatch_denial_with_fingerprint(
            reservation,
            reason,
            &reservation.credential_fingerprint,
        );
    }

    fn audit_dispatch_denial_with_fingerprint(
        &self,
        reservation: &Reservation,
        reason: &str,
        credential_fingerprint: &str,
    ) {
        if let Err(error) = self.append_reservation_audit(
            reservation,
            &AuditRecord {
                risk: Some(risk_str(reservation.risk).to_string()),
                severity: Some(reservation.severity.as_str().to_string()),
                args_redaction_summary: Some(self.recipient_audit_summary(
                    &reservation.approved_args_hash,
                    Some(&reservation.app_key),
                    &reservation.action,
                    &reservation.approved_args,
                )),
                outcome: Some("not_sent".to_string()),
                credential_fingerprint: Some(credential_fingerprint.to_string()),
                attempt_no: Some(1),
                ..AuditRecord::for_reservation(reservation, "deny", reason, "dispatch")
            },
        ) {
            eprintln!(error governance: "audit append failed: dispatch denial reason={reason:?} principal={:?} actor={:?} request_id={:?}: {error}", reservation.principal, reservation.actor, reservation.request_id);
        }
    }

    fn dispatch_credential_denial(
        &self,
        reservation: &Reservation,
        denial: CredentialDenial,
    ) -> DispatchOutcome {
        self.audit_dispatch_denial(reservation, denial.reason_code());
        DispatchOutcome::not_sent(
            reservation,
            denial.reason_code().to_string(),
            "credential could not be resolved".to_string(),
            if matches!(
                denial,
                CredentialDenial::Transient(_) | CredentialDenial::StoreUnavailable
            ) {
                Retryability::AutoRetryable
            } else {
                Retryability::Terminal
            },
        )
    }

    /// The request fingerprint of the GitHub receipt a reservation claimed, for
    /// the audit row's idempotency column. An unreadable receipt is logged and
    /// leaves the column empty rather than failing the audit write.
    fn receipt_request_fingerprint(&self, reservation: &Reservation) -> Option<String> {
        reservation.receipt.as_ref().and_then(|claim| {
            self.store
                .github_receipt(&claim.agent_id, &claim.request_nonce)
                .inspect_err(
                    |error| eprintln!(error governance: "receipt fingerprint unreadable: {error}"),
                )
                .ok()
                .flatten()
                .map(|row| row.request_fingerprint)
        })
    }

    pub(super) fn audit_dispatch_result(
        &self,
        reservation: &Reservation,
        response: &TransportResponse,
    ) {
        let outcome = match response.transmission {
            TransmissionState::NotSent => "not_sent",
            TransmissionState::Sent => {
                if response.response.is_some() {
                    "completed"
                } else {
                    "failed"
                }
            }
            TransmissionState::OutcomeUnknown => "unknown",
        };
        if let Err(error) = self.append_reservation_audit(
            reservation,
            &AuditRecord {
                risk: Some(risk_str(reservation.risk).to_string()),
                severity: Some(reservation.severity.as_str().to_string()),
                args_redaction_summary: Some(self.recipient_audit_summary(
                    &reservation.approved_args_hash,
                    Some(&reservation.app_key),
                    &reservation.action,
                    &reservation.approved_args,
                )),
                outcome: Some(outcome.to_string()),
                credential_fingerprint: Some(reservation.credential_fingerprint.clone()),
                attempt_no: Some(1),
                vendor_request_id: response.vendor_request_id.clone(),
                idempotency_key_fingerprint: self.receipt_request_fingerprint(reservation),
                response_class: response.error_code.clone(),
                ..AuditRecord::for_reservation(reservation, "allow", "dispatched", "dispatch")
            },
        ) {
            eprintln!(error governance: "audit append failed: dispatch result outcome={outcome:?} principal={:?} actor={:?} request_id={:?}: {error}", reservation.principal, reservation.actor, reservation.request_id);
        }
    }

    /// Keep the message text out of the audit: only normalized recipients are
    /// recorded beside the existing argument hash, preserving recipient
    /// accountability without storing the private message text.
    fn recipient_audit_summary(
        &self,
        hash: &str,
        app_key: Option<&str>,
        action: &str,
        args: &Value,
    ) -> String {
        let mut summary = format!("args_hash:{hash}");
        if let Some(app_key) = app_key {
            if let Ok(Some(pointers)) = self.store.recipient_pointers(app_key, action) {
                match crate::recipients::collect_recipients(&pointers, args) {
                    Ok(recipients) => {
                        summary.push_str(&format!(" recipients:{}", serde_json::json!(recipients)))
                    }
                    Err(_) => summary.push_str(" recipients:invalid"),
                }
            }
        }
        summary
    }
}
