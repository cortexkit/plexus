//! Reservation snapshots, abandonment and pre-dispatch approval and facade authority rechecks.

use super::*;

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    /// Read authorization state when the facade request starts and again just
    /// before sending, so an intervening handle, grant or policy change stops it.
    pub(super) fn capture_authority_baseline(
        &self,
        connection: &ConnectionRecord,
        request: &AuthorizationRequest,
        action: &CatalogAction,
    ) -> Result<AuthorityBaseline, Denial> {
        let seams = self.seams.as_ref().ok_or(Denial::StoreFailure)?;
        let agent_id = request
            .attributed_agent_id
            .as_deref()
            .ok_or(Denial::Grant(GrantDenial::Missing))?;
        let handle = seams
            .handle_row(connection)?
            .ok_or(Denial::Credential(CredentialDenial::Missing))?;
        let (agent_grant_generation, module_grant_generation) =
            seams.grant_generations(connection, &request.principal, agent_id, &request.action)?;
        let inputs = seams.policy_inputs(connection, agent_id, action)?;
        let policy_effect_hash = policy_effect_hash(
            inputs.module_effect.as_deref(),
            inputs.agent_effect.as_deref(),
            action.ask_first,
        )
        .map_err(|_| Denial::StoreFailure)?;
        Ok(AuthorityBaseline {
            app_handle_generation: handle.app_handle_generation,
            repo_binding_generation: handle.repo_binding_generation,
            credential_generation: handle.credential_generation,
            handle_enabled: handle.enabled,
            agent_grant_generation,
            module_grant_generation,
            policy_effect_hash,
        })
    }

    /// Invalidate a reservation that will not be claimed, so it can never be
    /// claimed later. The approval behind it, if any, is left untouched: only
    /// the claim consumes an approval.
    pub(super) fn abandon_unsent_reservation(&self, reservation: &Reservation) {
        if let Err(error) = self
            .store
            .abandon_reservation(&reservation.principal, &reservation.reservation_id)
        {
            eprintln!(error governance:
                "could not abandon unsent reservation {}: {error}",
                reservation.reservation_id
            );
        }
    }

    /// Re-check a stored approval's scope with the daemon at the point of
    /// execution, before the claim that would consume the approval and send.
    /// `None` means the same session is live with the authority the request
    /// was raised under, and the claim may proceed.
    ///
    /// Otherwise nothing is sent and this reservation is abandoned. A refusal
    /// retires the approval with its reason. A hold (the scope has not been
    /// confirmed after a daemon restart, or the daemon did not answer) keeps
    /// the approval `approved` and marks it waiting, for the scheduler to try
    /// again, until the approval's own expiry; past that the hold becomes a
    /// `scope_unverifiable` refusal.
    pub(super) fn recheck_approval_scope(
        &self,
        reservation: &Reservation,
        bound: &ApprovalScope,
    ) -> Option<DispatchOutcome> {
        let answer = match self.scope_reader.as_ref() {
            Some(reader) => reader.describe(&bound.owner, &bound.scope_ref),
            None => Err(ScopeReadError(
                "no daemon scope reader is configured".to_string(),
            )),
        };
        let verdict = approval_scope_verdict(bound, answer.as_ref());
        let (code, held) = match verdict {
            ApprovalScopeVerdict::Run => return None,
            ApprovalScopeVerdict::Refuse(code) => (code, false),
            ApprovalScopeVerdict::Hold(_) if self.now_ms() >= bound.expires_at => {
                (SCOPE_UNVERIFIABLE, false)
            }
            ApprovalScopeVerdict::Hold(reason) => (reason, true),
        };
        if let Err(error) = &answer {
            eprintln!(warn governance:
                "scope read for approval {} failed: {}",
                bound.request_id, error.0
            );
        }
        if let Err(error) = self
            .store
            .abandon_reservation(&reservation.principal, &reservation.reservation_id)
        {
            eprintln!(error governance:
                "could not abandon reservation {} after its approval's scope check: {error}",
                reservation.reservation_id
            );
        }
        if held {
            eprintln!(info governance:
                "approval {} held unsent ({code}): scope {}/{}@{} not confirmed yet",
                bound.request_id, bound.owner, bound.scope_ref, bound.scope_epoch
            );
            if let Err(error) = self
                .store
                .hold_scoped_approval(&reservation.principal, &bound.request_id)
            {
                eprintln!(error governance:
                    "could not mark approval {} as waiting: {error}",
                    bound.request_id
                );
            }
            self.audit_dispatch_denial(reservation, crate::scope::APPROVED_WAITING);
            return Some(DispatchOutcome::not_sent(
                reservation,
                crate::scope::APPROVED_WAITING.to_string(),
                format!("the approval is kept unsent until its scope is confirmed ({code})"),
                Retryability::AutoRetryable,
            ));
        }
        eprintln!(warn governance:
            "approval {} not run ({code}): scope {}/{}@{}",
            bound.request_id, bound.owner, bound.scope_ref, bound.scope_epoch
        );
        if let Err(error) =
            self.store
                .refuse_scoped_approval(&reservation.principal, &bound.request_id, code)
        {
            eprintln!(error governance:
                "could not retire approval {} after its scope refused it: {error}",
                bound.request_id
            );
        }
        self.audit_dispatch_denial(reservation, code);
        Some(self.maybe_report_decision_outcome(
            reservation,
            DispatchOutcome::not_sent(
                reservation,
                code.to_string(),
                "the approval's scope no longer allows it to run".to_string(),
                Retryability::Terminal,
            ),
            OutcomeTerminal::Refused {
                reason: code.to_string(),
            },
        ))
    }

    pub(super) fn revalidate_receipt_authority(
        &self,
        reservation: &Reservation,
        connection: &ConnectionRecord,
    ) -> Option<DispatchOutcome> {
        let baseline = reservation.authority_baseline.as_ref()?;
        let current = self
            .store
            .catalog_action(
                &connection.principal,
                &connection.connection_id,
                &reservation.action,
            )
            .inspect_err(|error| eprintln!(error governance: "catalog unreadable during authority recheck: {error}"))
            .ok()
            .flatten()
            .and_then(|action| {
                let mut request = AuthorizationRequest::new(
                    &reservation.acting_principal,
                    &reservation.connection_id,
                    &reservation.action,
                    reservation.args.clone(),
                );
                request.attributed_agent_id.clone_from(&reservation.attributed_agent_id);
                self.capture_authority_baseline(connection, &request, &action)
                    .inspect_err(|error| eprintln!(error governance: "authority snapshot unreadable: {error:?}"))
                    .ok()
            });
        let dimension = current
            .as_ref()
            .map(|current| compare_authority_baseline(baseline, current))
            .unwrap_or(Err("authorization_snapshot_stale"));
        dimension.err().map(|dimension| {
            self.deny_before_transmit(reservation, format!("stale_authority{{{dimension}}}"))
        })
    }
}

pub(super) fn reservation_record(reservation: &Reservation) -> ReservationRecord {
    ReservationRecord {
        reservation_id: reservation.reservation_id.clone(),
        principal: reservation.principal.clone(),
        connection_id: reservation.connection_id.clone(),
        action: reservation.action.clone(),
        grant_id: reservation.grant_id.clone(),
        snapshot: reservation.snapshot.clone(),
        approved_args_hash: reservation.approved_args_hash.clone(),
        schema_hash: reservation.schema_hash.clone(),
        expires_at: reservation.expires_at_ms,
        status: "reserved".to_string(),
        agent_grant: reservation.agent_grant.clone(),
    }
}

/// The scope a stored approval request was raised under, in the form the
/// execution-time re-check takes. `None` for a request raised with no scope.
pub(super) fn approval_scope_of(request: &ActionRequestRecord) -> Option<ApprovalScope> {
    let scope = request.scope.as_ref()?;
    Some(ApprovalScope {
        request_id: request.request_id.clone(),
        owner: scope.owner.clone(),
        scope_ref: scope.scope_ref.clone(),
        scope_epoch: scope.scope_epoch,
        agent_id: scope.agent_id.clone(),
        acted_as_agent: scope.to_call_scope().acting_agent().is_some(),
        expires_at: request.expires_at,
    })
}
