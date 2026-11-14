use super::*;
use crate::federated::matcher::{Call, Effect};
use crate::storage::federated_store::FederatedReservationInput;

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    /// Resolve standing authority or collect a search card after the backing gates.
    /// The daemon liveness query does not hold the store's write lock. Re-read
    /// the row afterwards so a revocation committed during that query wins.
    pub(crate) fn apply_federated_search(
        &self,
        request: &AuthorizationRequest,
        authority: &mut crate::web_search::federated::SearchAuthorization,
    ) -> Result<(), Denial> {
        let caller = request
            .federated_caller
            .as_ref()
            .ok_or(Denial::StoreFailure)?;
        let binding = request
            .federated_search
            .as_ref()
            .ok_or(Denial::StoreFailure)?;
        let call = Call {
            peer_fingerprint: &caller.attributes.peer_fingerprint,
            pairing_id: &caller.attributes.pairing_id,
            peer_class: "computer",
            claim: caller.attributes.remote_claim.as_ref(),
            owner_principal: &binding.owner_principal,
            subject: &binding.subject,
            scope: "read",
        };
        let unavailable = || Denial::ConsentUnavailable {
            action: binding.action.clone(),
        };
        if authority.used.is_some() || authority.answer.is_some() {
            return Ok(());
        }
        if self
            .store
            .matching_federated_row(&call, self.now_ms())
            .map_err(|_| Denial::StoreFailure)?
            .is_none()
        {
            if !request.federated_held_reply || matches!(caller.claim.claim_kind, "flow" | "run") {
                return Err(unavailable());
            }
            let scope = request.scope.as_ref().ok_or_else(unavailable)?;
            let search = match binding.action.as_str() {
                "web_search" => crate::federated::card::Search::Web,
                "code_search" => crate::federated::card::Search::Code,
                _ => return Err(unavailable()),
            };
            let prepared = crate::federated::card::PreparedCard::search(
                &crate::federated::card::Context {
                    caller,
                    filed_scope: scope,
                    expires_in_ms: APPROVAL_TTL_MS,
                    per_call_only: false,
                },
                search,
                &authority.arguments,
            )
            .map_err(|_| unavailable())?;
            authority.answer = Some(self.collect_federated_card(
                request,
                prepared,
                if binding.action == "web_search" {
                    "Web search"
                } else {
                    "Code search"
                },
                &binding.action,
            )?);
            self.federated_live(caller)?;
            return Ok(());
        }
        self.federated_live(caller)?;
        match self
            .store
            .matching_federated_row(&call, self.now_ms())
            .map_err(|_| Denial::StoreFailure)?
        {
            Some(row) if row.effect == Effect::Allow => Ok(()),
            Some(_) => Err(Denial::FederatedConsentDenied),
            None => Err(unavailable()),
        }
    }

    /// Settle a collected answer only after the search gates pass and the backend
    /// and caller rate buckets are charged together.
    /// Cache hits and all fallback attempts then share this in-memory use.
    pub(crate) fn consume_federated_search(
        &self,
        authority: &mut crate::web_search::federated::SearchAuthorization,
    ) -> Result<(), Denial> {
        use crate::storage::federated_store::commit::{CommitInput, CommitOutcome};
        let Some((mut record, answer)) = authority.answer.take() else {
            if let Some(used) = &authority.used {
                self.federated_live(&authority.caller)?;
                self.store
                    .validate_federated_search_use(&authority.caller, used, self.now_ms())
                    .map_err(|_| Denial::StoreFailure)??;
            }
            return Ok(());
        };
        if answer.standing_effect().is_some() {
            match self
                .store
                .commit_federated_standing_answer(
                    self.scope_reader.as_deref(),
                    &CommitInput {
                        caller: &authority.caller,
                        record: &record,
                        answer,
                        standing_choices_offered: record.standing_choices_offered,
                        now_ms: self.now_ms(),
                    },
                )
                .map_err(|failure| failure.denial)?
            {
                CommitOutcome::Committed {
                    effect: Effect::Deny,
                    ..
                } => return Err(Denial::FederatedConsentDenied),
                CommitOutcome::Committed { .. } => {
                    record.state = crate::federated::card::State::Committed
                }
                _ => {
                    return Err(Denial::ConsentUnavailable {
                        action: authority.binding.action.clone(),
                    })
                }
            }
        }
        self.federated_live(&authority.caller)?;
        authority.used = Some(
            self.store
                .consume_federated_search(&authority.caller, &record, answer, self.now_ms())
                .map_err(|_| Denial::StoreFailure)??,
        );
        Ok(())
    }

    /// Standing rows and call-bound cards replace local grants only after all
    /// non-grant invoke gates have passed.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn authorize_federated_invoke(
        &self,
        mut request: AuthorizationRequest,
        connection: ConnectionRecord,
        action: CatalogAction,
        policy: Option<crate::storage::PolicyRecord>,
        policy_effect: &str,
        severity: Severity,
        args_hash: String,
    ) -> Result<Reservation, Denial> {
        request.federated_row_id = None;
        request.federated_card_ref = None;
        let result = (|| {
            let caller = request
                .federated_caller
                .clone()
                .ok_or(Denial::StoreFailure)?;
            let call = Call {
                peer_fingerprint: &caller.attributes.peer_fingerprint,
                pairing_id: &caller.attributes.pairing_id,
                peer_class: "computer",
                claim: caller.attributes.remote_claim.as_ref(),
                owner_principal: request
                    .federated_search
                    .as_ref()
                    .map_or(connection.principal.as_str(), |binding| {
                        binding.owner_principal.as_str()
                    }),
                subject: request
                    .federated_search
                    .as_ref()
                    .map_or(connection.connection_id.as_str(), |binding| {
                        binding.subject.as_str()
                    }),
                // Catalog risk, never the tool execution mode, selects scope.
                scope: if request.federated_search.is_some() {
                    "read"
                } else {
                    &action.risk
                },
            };
            let unavailable = || Denial::ConsentUnavailable {
                action: request
                    .federated_search
                    .as_ref()
                    .map_or_else(|| request.action.clone(), |binding| binding.action.clone()),
            };
            let mut card_use = request.federated_answer.take();
            if let Some(used) = &request.federated_search_use {
                if request.federated_search.as_ref() != Some(&used.binding) {
                    return Err(unavailable());
                }
                self.federated_live(&caller)?;
                request.federated_card_ref = Some(used.card_ref.clone());
            } else if card_use.is_none() {
                // Rows decide new arrivals before even a pending-card lookup.
                let row = self
                    .store
                    .matching_federated_row(&call, self.now_ms())
                    .map_err(|_| Denial::StoreFailure)?;
                if row.is_some() {
                    self.federated_live(&caller)?;
                    let row = self
                        .store
                        .matching_federated_row(&call, self.now_ms())
                        .map_err(|_| Denial::StoreFailure)?
                        .ok_or_else(unavailable)?;
                    request.federated_row_id = Some(row.id);
                    if row.effect == Effect::Deny {
                        return Err(Denial::FederatedConsentDenied);
                    }
                }
                if request.federated_row_id.is_none() || policy_effect == "ask_first" {
                    if request.federated_search.is_some() {
                        return Err(unavailable());
                    }
                    let answer = self.collect_federated_invoke(&request, &connection, &action)?;
                    request.federated_answer = Some(answer);
                    // A held answer must pass fresh catalog, policy and connection
                    // gates before it can create a standing row or authorize execution.
                    return self.authorize(request.clone());
                }
            } else if let Some((record, _)) = &card_use {
                if record.binding.args_digest != args_hash
                    || record.binding.action != action.name
                    || record.schema_hash.as_deref() != Some(&action.schema_hash)
                    || record.scope.as_str() != action.risk
                {
                    return self.authorize(request.clone());
                }
            }
            if let Some((record, answer)) = card_use.as_mut() {
                use crate::storage::federated_store::commit::{CommitInput, CommitOutcome};
                if answer.standing_effect().is_some() {
                    match self
                        .store
                        .commit_federated_standing_answer(
                            self.scope_reader.as_deref(),
                            &CommitInput {
                                caller: &caller,
                                record,
                                answer: *answer,
                                standing_choices_offered: record.standing_choices_offered,
                                now_ms: self.now_ms(),
                            },
                        )
                        .map_err(|failure| {
                            debug_assert_eq!(failure.transmission, TransmissionState::NotSent);
                            failure.denial
                        })? {
                        CommitOutcome::Committed {
                            effect: Effect::Deny,
                            ..
                        } => return Err(Denial::FederatedConsentDenied),
                        CommitOutcome::Committed { .. } => {
                            record.state = crate::federated::card::State::Committed
                        }
                        CommitOutcome::Reask => return self.authorize(request.clone()),
                        CommitOutcome::PerCall(_) => return Err(unavailable()),
                    }
                }
                self.federated_live(&caller)?;
                request.federated_card_ref = record.card_ref.clone();
            }
            let credential_fingerprint = if card_use.as_ref().is_none_or(|(_, answer)| {
                matches!(
                    answer,
                    crate::storage::federated_store::commit::Answer::AllowOnce
                        | crate::storage::federated_store::commit::Answer::AllowAlways
                )
            }) {
                let (fingerprint, credential) = self.resolve_credential(&request, &connection)?;
                drop(credential);
                fingerprint
            } else {
                String::new()
            };
            let now = self.now_ms();
            let snapshot = SnapshotGenerations {
                connection: connection.generation,
                catalog_action: action.generation,
                // There is no local grant. The dispatch claim instead pins the
                // stored federated row and uses zero only while it still exists.
                grant: 0,
                policy: policy.as_ref().map_or(0, |row| row.generation),
                policy_id: policy.as_ref().map(|row| row.policy_id.clone()),
            };
            let expires_at_ms = now.saturating_add(RESERVATION_TTL_MS);
            let input = FederatedReservationInput {
                principal: &connection.principal,
                connection_id: &connection.connection_id,
                action: &action.name,
                snapshot: &snapshot,
                args_hash: &args_hash,
                schema_hash: &action.schema_hash,
                expires_at: expires_at_ms,
                now,
                ask_first: policy_effect == "ask_first",
            };
            let (row, reservation_id) = if let Some(used) = &request.federated_search_use {
                let (row, id) = self
                    .store
                    .reserve_federated_search_use(&call, &input, used)
                    .map_err(|_| Denial::StoreFailure)??;
                (row, Some(id))
            } else if let Some((record, answer)) = &card_use {
                let (row, id) = self
                    .store
                    .reserve_federated_card(&call, &input, record, *answer)
                    .map_err(|_| Denial::StoreFailure)??;
                (row, Some(id))
            } else {
                self.store
                    .reserve_federated_invoke(&call, &input)
                    .map_err(|_| Denial::StoreFailure)?
            };
            request.federated_row_id = row.as_ref().map(|row| row.id.clone());
            if row.as_ref().is_some_and(|row| row.effect == Effect::Deny) {
                return Err(Denial::FederatedConsentDenied);
            }
            let reservation_id = reservation_id.ok_or_else(unavailable)?;
            self.audit_authorization_decision(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                None,
                "credential",
                "allow",
                "credential_resolved",
                Some(credential_fingerprint.clone()),
            );
            Ok(Reservation {
                reservation_id,
                principal: connection.principal.clone(),
                acting_principal: request.principal.clone(),
                actor: request.actor.clone(),
                attributed_agent_id: None,
                bound_agent_handle: None,
                connection_id: request.connection_id.clone(),
                app_key: connection.app_key.clone(),
                action: request.action.clone(),
                args: request.args.clone(),
                grant_id: String::new(),
                approved_args: request.args.clone(),
                approved_args_hash: args_hash.clone(),
                args_snapshot_hash: args_hash.clone(),
                schema_hash: action.schema_hash.clone(),
                risk: parse_risk(&action.risk),
                severity,
                snapshot,
                expires_at_ms,
                request_id: request.request_id.clone(),
                credential_fingerprint,
                decision_id: None,
                grant_hash: None,
                intent_id: None,
                authority_baseline: None,
                receipt: None,
                origin: RequestOrigin::Ordinary,
                scope: request.scope.clone(),
                relay_origin: request.relay_origin.clone(),
                on_behalf_of_agent: None,
                agent_grant: None,
                approval_scope: None,
                federated_caller: request.federated_caller.clone(),
                federated_row_id: request.federated_row_id.clone(),
                federated_card_ref: request.federated_card_ref.clone(),
                federated_search_use: request.federated_search_use.is_some(),
            })
        })();
        if let Err(denial) = &result {
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                None,
                denial,
            );
        }
        result
    }

    pub(super) fn append_reservation_audit(
        &self,
        reservation: &Reservation,
        record: &AuditRecord,
    ) -> Result<(), cortexkit_store::StoreError> {
        if let Some(caller) = &reservation.federated_caller {
            self.store.append_audit_federated(
                record,
                reservation.scope.as_ref(),
                reservation.relay_origin.as_ref(),
                caller,
                reservation.federated_row_id.as_deref(),
                reservation.federated_card_ref.as_deref(),
            )
        } else {
            self.store.append_audit_relayed(
                record,
                reservation.scope.as_ref(),
                reservation.relay_origin.as_ref(),
                reservation.on_behalf_of_agent.as_deref(),
            )
        }
    }
}
