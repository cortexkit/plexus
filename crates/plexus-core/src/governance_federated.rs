use super::*;
use crate::federated::matcher::{Call, Effect};
use crate::storage::federated_store::FederatedReservationInput;

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    /// Standing authority replaces local grants only after every non-grant
    /// invoke gate has passed. Cards are deliberately unavailable until the
    /// federated card path can bind and consume its own answers.
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
        let result = (|| {
            let caller = request
                .federated_caller
                .as_ref()
                .ok_or(Denial::StoreFailure)?;
            let call = Call {
                peer_fingerprint: &caller.attributes.peer_fingerprint,
                pairing_id: &caller.attributes.pairing_id,
                peer_class: "computer",
                claim: caller.attributes.remote_claim.as_ref(),
                owner_principal: &connection.principal,
                subject: &connection.connection_id,
                // Catalog risk, never the tool execution mode, selects scope.
                scope: &action.risk,
            };
            let unavailable = || Denial::ConsentUnavailable {
                action: request.action.clone(),
            };
            if self
                .store
                .matching_federated_row(&call, self.now_ms())
                .map_err(|_| Denial::StoreFailure)?
                .is_none()
            {
                return Err(unavailable());
            }

            // No store writer fence is held across this blocking daemon call.
            // Selection and reservation below re-read authority under the fence.
            let base = format!("fed-base:{}:{}", call.peer_fingerprint, call.pairing_id);
            let description = self
                .scope_reader
                .as_ref()
                .ok_or(Denial::FederatedLivenessUnavailable)?
                .describe("reserved:callosum", &base)
                .map_err(|_| Denial::FederatedLivenessUnavailable)?;
            match description.status {
                crate::scope::ScopeStatus::Live => {}
                crate::scope::ScopeStatus::Ended => return Err(Denial::FederatedPairingEnded),
                crate::scope::ScopeStatus::NotLive
                    if description.owner_synced && description.owner_configured =>
                {
                    return Err(Denial::FederatedPairingEnded);
                }
                _ => return Err(Denial::FederatedLivenessUnavailable),
            }

            // A denial or a call still needing consent must not reach credential
            // preparation. Re-read under the fence: a revoked row cannot refuse
            // the call or authorize credential preparation.
            let row = self
                .store
                .matching_federated_row(&call, self.now_ms())
                .map_err(|_| Denial::StoreFailure)?
                .ok_or_else(unavailable)?;
            request.federated_row_id = Some(row.id);
            if row.effect == Effect::Deny {
                return Err(Denial::FederatedConsentDenied);
            }
            if policy_effect == "ask_first" {
                return Err(unavailable());
            }

            let (credential_fingerprint, credential) =
                self.resolve_credential(&request, &connection)?;
            drop(credential);
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
            let (row, reservation_id) = self
                .store
                .reserve_federated_invoke(
                    &call,
                    &FederatedReservationInput {
                        action: &action.name,
                        snapshot: &snapshot,
                        args_hash: &args_hash,
                        schema_hash: &action.schema_hash,
                        expires_at: expires_at_ms,
                        now,
                        ask_first: policy_effect == "ask_first",
                    },
                )
                .map_err(|_| Denial::StoreFailure)?;
            let row = row.ok_or_else(unavailable)?;
            request.federated_row_id = Some(row.id.clone());
            if row.effect == Effect::Deny {
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
                federated_row_id: Some(row.id),
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
                None,
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
