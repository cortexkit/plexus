//! Held approval execution, consent-card filing and waits, and consent resolution.

use super::*;

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    pub(super) fn wait_for_consent(
        &self,
        cards: &ConsentCards,
        scope: &CallScope,
        id: &str,
        deadline: std::time::Instant,
    ) -> Result<Value, crate::consent_card::ElicitationCallError> {
        struct Restore<'a>(Option<&'a dyn ConsentWaitHook>);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                if let Some(hook) = self.0 {
                    hook.after_wait();
                }
            }
        }
        let hook = self.consent_wait_hook.as_deref();
        if let Some(hook) = hook {
            hook.before_wait();
        }
        let _restore = Restore(hook);
        cards.wait_until(scope, id, deadline)
    }

    /// Re-authorize an approved request in full and dispatch it through the
    /// reservation claim. A request raised under a scope is re-authorized under
    /// that scope, so a call that was made as an agent still needs the
    /// agent's grant, and its scope is re-checked before the claim.
    pub(super) fn dispatch_approved(
        &self,
        request: ActionRequestRecord,
        decider: &str,
    ) -> Result<DispatchOutcome, Denial> {
        let request_id = request.request_id.clone();
        let routing = self
            .store
            .action_request_routing(&request.principal, &request_id)
            .map_err(|_| Denial::StoreFailure)?;
        let mut authorization = AuthorizationRequest::new(
            request.requester,
            request.connection_id,
            request.action,
            request.args_snapshot,
        )
        .with_actor(decider)
        .with_schema_hash(request.schema_hash)
        .approved_from(request_id.clone());
        if let Some(routing) = routing {
            authorization.resolved_repository = routing["repository"].as_str().map(str::to_owned);
            authorization.diagnostic_tool = routing["tool"].as_str().unwrap_or("invoke").to_owned();
            authorization.supports_per_call_approval = routing["supports_per_call_approval"]
                .as_bool()
                .unwrap_or(true);
        }
        if let Some(scope) = request.scope.as_ref() {
            if let Some(agent_id) = scope.agent_id.as_deref() {
                authorization = authorization.with_attributed_agent(agent_id);
            }
            authorization = authorization.with_scope(scope.to_call_scope());
        }
        // The approved send is still the relayed call, so its audit rows name
        // the same original call as the approval request does.
        if let Some(relay_origin) = request.relay_origin {
            authorization = authorization.with_relay_origin(relay_origin);
        }
        let reservation = match self.authorize(authorization) {
            Ok(reservation) => reservation,
            Err(denial) => {
                // A caller's deadline cannot recover in the scheduler. Preserve
                // the approval without queuing a send after the caller has
                // moved on.
                let recall_only = matches!(&denial, Denial::ConnectorHomeNotHeld { state }
                    if state.pointer("/error/code").and_then(Value::as_str) == Some("request_deadline_exceeded"));
                if denial.clears_by_waiting() && !recall_only {
                    self.hold_approval_for_retry(&request.principal, &request_id);
                }
                return Err(denial);
            }
        };
        // The target may have changed while the request waited for approval,
        // so it is checked again here, after re-authorization.
        let outcome = self.dispatch_checked(&reservation);
        // Any pre-claim refusal leaves consent unspent. Retry from full
        // authorization instead of stranding an approved request forever.
        if matches!(&outcome.outcome, TransportOutcome::NotSent { code, .. }
                if code != crate::scope::APPROVED_WAITING)
        {
            self.hold_approval_for_retry(&request.principal, &request_id);
        }
        Ok(outcome)
    }

    pub(super) fn request_admin(
        &self,
        request: &ActionRequestRecord,
        decider: &str,
    ) -> Result<bool, Denial> {
        let action = self
            .store
            .catalog_action(&request.principal, &request.connection_id, &request.action)
            .map_err(|_| Denial::StoreFailure)?
            .ok_or(Denial::Catalog(CatalogDenial::NotFound))?;
        let now = self.now_ms();
        let grant = self
            .store
            .matching_grant(
                &request.principal,
                &request.connection_id,
                decider,
                &request.action,
                "connection_admin",
                now,
                Some(&action.risk),
            )
            .map_err(|_| Denial::StoreFailure)?;
        Ok(scoped_grant_refusal(grant.as_ref(), &request.action, &action.risk, now).is_none())
    }

    pub(super) fn audit_approval_resolution(
        &self,
        request: &ActionRequestRecord,
        actor: &str,
        reason: &str,
    ) {
        let mut authorization = AuthorizationRequest::new(
            &request.requester,
            &request.connection_id,
            &request.action,
            request.args_snapshot.clone(),
        )
        .with_actor(actor);
        authorization.request_id = request.request_id.clone();
        authorization.scope = request.scope.as_ref().map(|scope| scope.to_call_scope());
        authorization.relay_origin = request.relay_origin.clone();
        let connection = self
            .store
            .connection(&request.principal, &request.connection_id)
            .ok()
            .flatten();
        let action = self
            .store
            .catalog_action(&request.principal, &request.connection_id, &request.action)
            .ok()
            .flatten();
        self.audit_authorization_decision(
            &authorization,
            &request.args_hash,
            connection.as_ref(),
            action.as_ref(),
            None,
            "policy",
            "deny",
            reason,
            None,
        );
    }

    pub(super) fn audited_refusal(&self, request: &AuthorizationRequest, denial: Denial) -> Denial {
        let connection = self
            .store
            .connection_for_invoke(&request.principal, &request.connection_id)
            .ok()
            .flatten();
        let action = connection.as_ref().and_then(|connection| {
            self.store
                .catalog_action(
                    &connection.principal,
                    &request.connection_id,
                    &request.action,
                )
                .ok()
                .flatten()
        });
        if let Ok(hash) = jcs::jcs_sha256(&request.args) {
            self.audit_denial(
                request,
                &hash,
                connection.as_ref(),
                action.as_ref(),
                None,
                &denial,
            );
        }
        denial
    }

    /// Mark an approved request as waiting, so `retry_waiting_approvals` runs
    /// it again (until its own expiry). Only a request still `approved` is
    /// marked; one the claim already consumed is left alone.
    fn hold_approval_for_retry(&self, principal: &str, request_id: &str) {
        if let Err(error) = self.store.hold_scoped_approval(principal, request_id) {
            eprintln!(error governance:
                "could not hold approval {request_id} for retry: {error}"
            );
        }
    }

    /// File the consent card for a call just held for approval, or refresh
    /// the card when the same call is held again under its existing request.
    /// A failure is logged and changes nothing else: the request stays
    /// pending for the operator and the call's reply is the same.
    pub(super) fn file_consent_card(
        &self,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        scope: Option<&CallScope>,
        request_id: &str,
        complete_preview: bool,
    ) {
        let Some(cards) = self.consent_cards.as_ref() else {
            return;
        };
        let request = match self.store.action_request(&connection.principal, request_id) {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(error) => {
                eprintln!(warn consent:
                    "consent card for request {request_id} was not filed (store_failure): {error}"
                );
                return;
            }
        };
        // The call may have reused a request the operator already approved;
        // that request needs no card.
        if RequestStatus::of(&request.status) != RequestStatus::Pending {
            return;
        }
        let expires_in_ms = request.expires_at.saturating_sub(self.now_ms());
        if expires_in_ms <= 0 {
            return;
        }
        let service_label = self.service_label(&connection.app_key);
        let action_label = action_label(action, &request.action);
        let parked = ParkedApproval {
            request_id,
            dedup_key: &request
                .call_key
                .as_ref()
                .map(|key| format!("{}:{key}", request.requester))
                .unwrap_or_else(|| request_id.to_string()),
            action_label,
            service_label: &service_label,
            risk: &action.risk,
            args: &request.args_snapshot,
            complete_preview,
            args_digest: &request.args_hash,
            expires_in_ms,
        };
        let Some(scope) = scope else {
            return;
        };
        if let Err(error) = cards.file(&self.store, &connection.principal, scope, &parked) {
            eprintln!(warn consent:
                "consent card for request {request_id} was not filed ({}); it stays pending for the operator",
                error.code()
            );
        }
    }

    /// The service's catalog name for a card: the app manifest's `name`,
    /// else its key.
    pub(super) fn service_label(&self, app_key: &str) -> String {
        crate::consent_card::service_label(&self.store, app_key)
    }

    pub(super) fn withdraw_consent_card(&self, request: &ActionRequestRecord) {
        if let Some(cards) = self.consent_cards.as_ref() {
            cards.withdraw(request);
        }
    }

    pub(super) fn consent_route_denial(
        &self,
        action: &str,
        error: &crate::consent_card::ElicitationCallError,
    ) -> Denial {
        eprintln!(warn consent: "consent_unavailable for action {action} ({})", error.code());
        Denial::ConsentUnavailable {
            action: action.into(),
        }
    }

    pub(super) fn finish_consent(
        &self,
        request: ActionRequestRecord,
        scope: &CallScope,
        record: Value,
    ) -> Result<DispatchOutcome, Denial> {
        let id = request
            .elicitation_id
            .as_deref()
            .ok_or(Denial::StoreFailure)?;
        if record["elicitation_id"] != id
            || record["kind"] != "consent"
            || record["args_digest"] != request.args_hash
        {
            self.audit_approval_resolution(&request, &request.requester, "consent_unavailable");
            return Err(Denial::ConsentUnavailable {
                action: request.action,
            });
        }
        match (
            record.get("state").and_then(Value::as_str),
            record.get("answered_choice_id").and_then(Value::as_str),
        ) {
            (Some("pending"), _) => {
                let service = self
                    .store
                    .connection(&request.principal, &request.connection_id)
                    .ok()
                    .flatten()
                    .map(|conn| self.service_label(&conn.app_key))
                    .unwrap_or_else(|| request.connection_id.clone());
                let action = self
                    .store
                    .catalog_action(&request.principal, &request.connection_id, &request.action)
                    .ok()
                    .flatten()
                    .and_then(|action| action.title)
                    .map(|title| title.trim().to_string())
                    .filter(|title| !title.is_empty())
                    .unwrap_or_else(|| request.action.clone());
                Err(Denial::AccessPending {
                    elicitation_id: id.to_string(),
                    service,
                    action,
                })
            }
            (Some("answered"), Some(crate::consent_card::OPTION_APPROVE)) => {
                let cards = self.consent_cards.as_ref().ok_or(Denial::StoreFailure)?;
                let decider = format!("{CONSENT_CARD_DECIDER_PREFIX}{id}");
                if RequestStatus::of(&request.status) == RequestStatus::Pending {
                    self.store
                        .decide_action_request(
                            &request.principal,
                            &request.request_id,
                            true,
                            &decider,
                        )
                        .map_err(|_| Denial::StoreFailure)?;
                }
                let current = self
                    .store
                    .action_request(&request.principal, &request.request_id)
                    .map_err(|_| Denial::StoreFailure)?
                    .ok_or(Denial::StoreFailure)?;
                if RequestStatus::of(&current.status) == RequestStatus::Consumed {
                    return Err(Denial::Policy(PolicyDenial::ApprovalConsumed));
                }
                let result = if current.args_snapshot != request.args_snapshot
                    || current.args_hash != request.args_hash
                    || current.schema_hash != request.schema_hash
                {
                    Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch))
                } else if RequestStatus::of(&current.status) == RequestStatus::Approved
                    && current.decider.as_deref() == Some(&decider)
                {
                    self.dispatch_approved(current, &decider)
                } else {
                    Err(Denial::Policy(
                        if RequestStatus::of(&current.status) == RequestStatus::Cancelled {
                            PolicyDenial::ApprovalWithdrawn
                        } else if current.expires_at <= self.now_ms()
                            || RequestStatus::of(&current.status) == RequestStatus::Expired
                        {
                            PolicyDenial::ApprovalExpired
                        } else {
                            PolicyDenial::ApprovalAlreadyDecided
                        },
                    ))
                };
                let execution = result
                    .as_ref()
                    .map(execution_from_dispatch)
                    .unwrap_or(APPROVED_NOT_EXECUTED);
                if let Err(error) = cards.report_execution(scope, id, execution) {
                    eprintln!(warn consent: "could not report execution for {id} ({})", error.code());
                }
                if let Err(denial) = &result {
                    if !denial.clears_by_waiting() {
                        self.store
                            .refuse_scoped_approval(
                                &request.principal,
                                &request.request_id,
                                denial.reason_code(),
                            )
                            .map_err(|_| Denial::StoreFailure)?;
                    }
                }
                result
            }
            (Some(state @ ("answered" | "expired" | "withdrawn")), _) => {
                let code = match state {
                    "answered" => "consent_denied",
                    "expired" => "consent_expired",
                    _ => "consent_withdrawn",
                };
                self.store
                    .settle_consent_request(
                        &request.principal,
                        &request.request_id,
                        state,
                        &format!("{CONSENT_CARD_DECIDER_PREFIX}{id}"),
                    )
                    .map_err(|_| Denial::StoreFailure)?;
                self.audit_approval_resolution(
                    &request,
                    &format!("{CONSENT_CARD_DECIDER_PREFIX}{id}"),
                    code,
                );
                Err(Denial::ConsentRefused {
                    code,
                    elicitation_id: id.to_string(),
                })
            }
            _ => Err(Denial::ConsentUnavailable {
                action: request.action,
            }),
        }
    }
}
