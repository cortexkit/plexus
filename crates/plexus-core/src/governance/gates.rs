//! Authorization gates for connection, catalog, grants, policy, resources and the decision plane.

use super::*;

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    /// Pure grant and policy evaluation shared by dispatch and restoration checks.
    pub(super) fn evaluate_authority(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        now: i64,
    ) -> Result<AuthorityEvaluation, Denial> {
        let acting_agent = request.acting_agent();
        let agent = if request.origin == RequestOrigin::Facade {
            request.attributed_agent_id.as_deref()
        } else {
            acting_agent
        };
        if request.origin == RequestOrigin::Facade && agent.is_none() {
            return Err(grant_denial(
                request,
                crate::grant_refusal::Layer::Agent,
                GrantDenial::Missing,
            ));
        }
        let (grant, agent_grant_pin) = if request.federated_caller.is_some() {
            (None, None)
        } else {
            let rows = if request.origin == RequestOrigin::Facade {
                self.seams
                    .as_ref()
                    .ok_or(Denial::StoreFailure)?
                    .grant_rows(connection, request)?
            } else if agent.is_some() {
                self.store
                    .scoped_invoke_grant_rows(connection, &request.principal, agent)
                    .map_err(|_| Denial::StoreFailure)?
            } else {
                Vec::new()
            };
            let module = if request.origin == RequestOrigin::Facade || agent.is_some() {
                scoped_grant(
                    &rows,
                    connection,
                    &request.principal,
                    None,
                    &request.authority_kind,
                    &request.action,
                    now,
                    Some(&action.risk),
                )
            } else {
                self.store
                    .matching_grant(
                        &connection.principal,
                        &request.connection_id,
                        &request.principal,
                        &request.action,
                        &request.authority_kind,
                        now,
                        Some(&action.risk),
                    )
                    .map_err(|_| Denial::StoreFailure)?
            };
            if let Some(reason) =
                scoped_grant_refusal(module.as_ref(), &request.action, &action.risk, now)
            {
                return Err(grant_denial(
                    request,
                    crate::grant_refusal::Layer::Module,
                    reason,
                ));
            }
            let grant = module.ok_or(Denial::StoreFailure)?;
            let mut agent_grant_pin = None;
            if let Some(agent) = agent {
                let row = scoped_grant(
                    &rows,
                    connection,
                    &request.principal,
                    Some(agent),
                    &request.authority_kind,
                    &request.action,
                    now,
                    Some(&action.risk),
                );
                if let Some(reason) =
                    scoped_grant_refusal(row.as_ref(), &request.action, &action.risk, now)
                {
                    return Err(grant_denial(
                        request,
                        crate::grant_refusal::Layer::Agent,
                        reason,
                    ));
                }
                if acting_agent.is_some() {
                    agent_grant_pin = row.map(|row| PinnedGrant {
                        grant_id: row.grant_id,
                        generation: row.generation,
                    });
                }
            }
            (Some(grant), agent_grant_pin)
        };
        let policy = self
            .store
            .matching_policy(
                &connection.principal,
                &request.connection_id,
                &request.action,
                now,
            )
            .map_err(|_| Denial::StoreFailure)?;
        let policy_inputs = if request.origin == RequestOrigin::Facade {
            Some(
                self.seams
                    .as_ref()
                    .ok_or(Denial::StoreFailure)?
                    .policy_inputs(connection, agent.ok_or(Denial::StoreFailure)?, action)?,
            )
        } else {
            None
        };
        let module_effect = policy_inputs
            .as_ref()
            .map(|inputs| inputs.module_effect.as_deref())
            .unwrap_or_else(|| policy.as_ref().map(|p| p.effect.as_str()))
            .unwrap_or(if action.ask_first {
                "ask_first"
            } else {
                "allow"
            });
        let policy_effect = catalog_policy_effect(
            action,
            Some(module_effect),
            policy_inputs
                .as_ref()
                .and_then(|p| p.agent_effect.as_deref()),
        );
        Ok(AuthorityEvaluation {
            grant,
            agent_grant_pin,
            policy,
            policy_inputs,
            policy_effect,
        })
    }

    pub(super) fn authorize_inner(
        &self,
        mut request: AuthorizationRequest,
        preflight: bool,
    ) -> Result<Option<Reservation>, Denial> {
        if let Some(denial) = self.connector_home_denial() {
            return Err(denial);
        }
        let mut args_hash = jcs::jcs_sha256(&request.args).map_err(|_| Denial::StoreFailure)?;
        if crate::secret_input::contains_secret_input(&request.args) {
            let denial = Denial::CredentialMaterialForbidden;
            self.audit_denial(&request, &args_hash, None, None, None, &denial);
            return Err(denial);
        }
        if request.authority_kind == AUTHORITY_INVOKE && request.federated_caller.is_none() {
            if let Some(seams) = &self.seams {
                let original_args = request.args.clone();
                if let Err(reason) = seams
                    .prepare_invoke(&mut request)
                    .and_then(|()| seams.resolve_invoke(&request))
                {
                    let denial = Denial::Resolver(reason);
                    let mut unattributed = request.clone();
                    unattributed.attributed_agent_id = None;
                    unattributed.bound_agent_handle = None;
                    self.audit_denial(&unattributed, &args_hash, None, None, None, &denial);
                    return Err(denial);
                }
                if request.args != original_args {
                    args_hash = jcs::jcs_sha256(&request.args).map_err(|_| Denial::StoreFailure)?;
                }
            }
        }
        let args_snapshot_hash = args_hash.clone();
        let connection = match if request.federated_caller.is_some() {
            self.store.connection("direct", &request.connection_id)
        } else if let Some(owner) = &request.poll_connection_owner {
            self.store.connection(owner, &request.connection_id)
        } else if request.authority_kind == AUTHORITY_INVOKE {
            self.store
                .connection_for_invoke(&request.principal, &request.connection_id)
        } else {
            self.store
                .connection(&request.principal, &request.connection_id)
        } {
            Ok(Some(connection)) => connection,
            Ok(None) => {
                let denial = if request.federated_caller.is_none()
                    && request
                        .scope
                        .as_ref()
                        .is_some_and(|scope| scope.flow_id.is_some())
                    && self
                        .store
                        .connection_id_exists(&request.connection_id)
                        .map_err(|_| Denial::StoreFailure)?
                {
                    grant_denial(
                        &request,
                        crate::grant_refusal::Layer::Module,
                        GrantDenial::Missing,
                    )
                } else {
                    Denial::Connection(ConnectionDenial::NotFound)
                };
                self.audit_denial(&request, &args_hash, None, None, None, &denial);
                return Err(denial);
            }
            Err(_) => return Err(Denial::StoreFailure),
        };
        let mut refusal = connection_denial(&connection);
        if refusal.is_none()
            && self
                .store
                .other_transport_owner(&connection.principal, &connection.connection_id)
                .map_err(|_| Denial::StoreFailure)?
                .is_some()
        {
            refusal = Some(ConnectionDenial::Unhealthy);
        }
        if let Some(reason) = refusal {
            let denial = Denial::Connection(reason);
            self.audit_denial(&request, &args_hash, Some(&connection), None, None, &denial);
            return Err(denial);
        }
        // Bot credentials belong to this computer's local agents. A remote
        // caller cannot use a bot by invoking its backing connection directly.
        if request.federated_caller.is_some()
            && self
                .store
                .is_github_handle_connection(&connection.principal, &connection.connection_id)
                .map_err(|_| Denial::StoreFailure)?
        {
            let denial = Denial::BotActionRequiresFacade;
            self.audit_denial(&request, &args_hash, Some(&connection), None, None, &denial);
            return Err(denial);
        }
        let action = match self.store.catalog_action(
            &connection.principal,
            &request.connection_id,
            &request.action,
        ) {
            Ok(Some(action)) => action,
            Ok(None) => {
                let denial = Denial::Catalog(CatalogDenial::NotFound);
                self.audit_denial(&request, &args_hash, Some(&connection), None, None, &denial);
                return Err(denial);
            }
            Err(_) => return Err(Denial::StoreFailure),
        };
        if request.authority_kind == AUTHORITY_INVOKE
            && request.origin != RequestOrigin::Facade
            && self
                .seams
                .as_ref()
                .is_some_and(|seams| seams.facade_only(&action))
        {
            let denial = Denial::BotActionRequiresFacade;
            let mut unattributed = request.clone();
            unattributed.attributed_agent_id = None;
            unattributed.bound_agent_handle = None;
            self.audit_denial(
                &unattributed,
                &args_hash,
                Some(&connection),
                Some(&action),
                None,
                &denial,
            );
            return Err(denial);
        }
        if let Some(reason) = catalog_denial(&action, request.expected_schema_hash.as_deref()) {
            let denial = Denial::Catalog(reason);
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                None,
                &denial,
            );
            return Err(denial);
        }
        // Every argument must be one the reviewed schema declares. The REST
        // transport sends every non-path argument to the vendor, so an argument
        // no reviewer saw would otherwise reach it. Checked for every origin
        // (invoke, poll, facade) before any reservation or approval exists.
        if let Some(field) = undeclared_argument(&action.schema, &request.args) {
            let denial = Denial::ArgumentUndeclared { field };
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                None,
                &denial,
            );
            return Err(denial);
        }
        let now = self.now_ms();
        // Every declaration must resolve, even when policy would allow or an
        // approval is presented. Missing arguments never disable this gate.
        let recipient_pointers = self
            .store
            .recipient_pointers(&connection.app_key, &action.name)
            .map_err(|_| Denial::StoreFailure)?;
        let recipients = match recipient_pointers
            .as_ref()
            .map(|pointers| crate::recipients::collect_recipients(pointers, &request.args))
            .transpose()
        {
            Ok(recipients) => recipients,
            Err(pointer) => {
                let denial = Denial::RecipientArgumentInvalid { pointer };
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    None,
                    &denial,
                );
                return Err(denial);
            }
        };
        let AuthorityEvaluation {
            grant,
            agent_grant_pin,
            policy,
            policy_inputs: _,
            policy_effect,
        } = match self.evaluate_authority(&request, &connection, &action, now) {
            Ok(value) => value,
            Err(denial) => {
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    None,
                    &denial,
                );
                return Err(denial);
            }
        };
        // The allowlist only narrows policy and cannot override a block. A NULL
        // agent key selects the module-only list, separate from each agent's own
        // list, so module-only calls cannot use an agent's recipient authority.
        let unlisted = if request.federated_caller.is_some() {
            recipients.is_some()
        } else if let Some(recipients) = recipients.as_ref() {
            let listed = self
                .store
                .list_recipients(
                    &connection.principal,
                    &request.connection_id,
                    if request.origin == RequestOrigin::Facade {
                        request.attributed_agent_id.as_deref()
                    } else {
                        request.acting_agent()
                    },
                )
                .map_err(|_| Denial::StoreFailure)?;
            recipients
                .iter()
                .any(|recipient| !listed.contains(recipient))
        } else {
            false
        };
        let policy_effect = if unlisted && policy_effect != "block" {
            "ask_first"
        } else {
            policy_effect
        };
        // A block is a current narrowing, including approved-but-unsent calls.
        // Refuse before claiming the reservation that consumes an approval.
        if policy_effect == "block" {
            let denial = Denial::Policy(PolicyDenial::Blocked);
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                grant.as_ref(),
                &denial,
            );
            return Err(denial);
        }
        let severity = effective_severity(&action, &connection.app_key, &self.store)
            .map_err(|_| Denial::StoreFailure)?;
        if request.federated_caller.is_some() {
            let denial = if matches!(severity, Severity::S3 | Severity::S4)
                || !matches!(action.risk.as_str(), "read" | "write")
            {
                Some(Denial::NeedsDecisionPlane(Box::new(
                    DecisionPlaneEnvelope {
                        request_id: request.request_id.clone(),
                        connection_id: request.connection_id.clone(),
                        action: request.action.clone(),
                        args_hash: args_snapshot_hash.clone(),
                        schema_hash: action.schema_hash.clone(),
                        severity,
                        expires_at_ms: now.saturating_add(APPROVAL_TTL_MS),
                    },
                )))
            } else if let Some(reason) = resource_denial_with_repositories(
                &connection,
                &action,
                &request.args,
                request.resolved_github_search_repositories(),
            ) {
                Some(Denial::ResourceFilter(reason))
            } else {
                match self
                    .store
                    .connection_ceiling(&connection.principal, &request.connection_id)
                    .map_err(|_| Denial::StoreFailure)?
                {
                    Ok(ceiling)
                        if !Risk::parse(&action.risk).is_some_and(|risk| risk <= ceiling.risk) =>
                    {
                        Some(Denial::Grant(GrantDenial::RiskCeiling))
                    }
                    Ok(ceiling) if !ceiling.action_selectors.contains(&action.name) => {
                        Some(Denial::Grant(GrantDenial::ActionSelector))
                    }
                    Err(_) => Some(Denial::Grant(GrantDenial::RiskCeiling)),
                    Ok(_) => None,
                }
            };
            if let Some(denial) = denial {
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    None,
                    &denial,
                );
                return Err(denial);
            }
            if request.federated_search.is_some() && policy_effect != "allow" {
                return Err(Denial::Policy(PolicyDenial::AskFirst));
            }
            if preflight {
                return Ok(None);
            }
            return self
                .authorize_federated_invoke(
                    request,
                    connection,
                    action,
                    policy,
                    policy_effect,
                    severity,
                    args_hash,
                )
                .map(Some);
        }
        // Federated calls have their own consent and reservation path and never
        // read local approvals. Local authorization always supplies a grant.
        let grant = grant.ok_or(Denial::StoreFailure)?;
        if matches!(severity, Severity::S3 | Severity::S4) && self.decision_plane.is_none() {
            let denial = self
                .evaluate_decision_plane(
                    &request,
                    &connection,
                    &action,
                    severity,
                    &args_snapshot_hash,
                    now,
                )
                .err()
                .unwrap_or(Denial::StoreFailure);
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                Some(&grant),
                &denial,
            );
            return Err(denial);
        }
        let approval_id = request
            .receipt_approval
            .as_ref()
            .map(|value| value.action_request_id.as_str())
            .or(request.approved_request_id.as_deref());
        let facade_approval = if request.origin == RequestOrigin::Facade {
            match approval_id {
                Some(id) => self
                    .seams
                    .as_ref()
                    .ok_or(Denial::StoreFailure)?
                    .receipt_approval(&connection, id)?,
                None => None,
            }
        } else {
            None
        };
        let ordinary_approval = match approval_id {
            Some(id) if request.origin == RequestOrigin::Ordinary => self
                .store
                .action_request(&connection.principal, id)
                .map_err(|error| {
                    // A failed read is not a missing approval: reporting it as
                    // `approval_missing` would tell the caller its approval is
                    // gone when the store merely could not be read.
                    eprintln!(error governance: "approval {id} unreadable: {error}");
                    Denial::StoreFailure
                })?,
            _ => None,
        };
        let routing_matches = if let Some(row) = ordinary_approval.as_ref() {
            self.store
                .action_request_routing(&connection.principal, &row.request_id)
                .map_err(|_| Denial::StoreFailure)?
                .is_none_or(|routing| routing == request.routing_context())
        } else {
            true
        };
        // True when an ordinary approval was already consumed by an earlier
        // dispatch of this very call (same schema, same arguments). That retry
        // is refused by name so the caller does not mistake it for a lapsed
        // window. A consumed approval presented for a different call is still a
        // shape mismatch, since it never authorized that call at all.
        let mut ordinary_approval_consumed = false;
        // True when the ordinary approval presented was withdrawn: it can
        // never authorize a call, and the refusal says so by name.
        let mut ordinary_approval_withdrawn = false;
        let approved = if request.origin == RequestOrigin::Facade {
            facade_approval.as_ref().is_some_and(|approved| {
                request.receipt_approval.as_ref().is_some_and(|receipt| {
                    approved.action_request_id == receipt.action_request_id
                        && approved.agent_id == receipt.agent_id
                        && request.attributed_agent_id.as_deref() == Some(receipt.agent_id.as_str())
                        && RequestStatus::of(&approved.status) == RequestStatus::Approved
                        && approved.expires_at_ms > now
                })
            })
        } else {
            // An approval authorizes exactly the call it was raised for: the
            // same requester, connection and action, as well as the same schema
            // and arguments. The schema hash covers only the input schema, so
            // without the action check an approval for one action would cover
            // a different action with an identical schema.
            let same_call = |row: &ActionRequestRecord| {
                row.connection_id == request.connection_id
                    && row.action == request.action
                    && row.requester == request.principal
                    && row.schema_hash == action.schema_hash
                    && routing_matches
            };
            match ordinary_approval.as_ref() {
                Some(approved)
                    if RequestStatus::of(&approved.status) == RequestStatus::Approved
                        && same_call(approved)
                        && approved.expires_at > now =>
                {
                    approved.args_snapshot == request.args
                }
                Some(consumed)
                    if RequestStatus::of(&consumed.status) == RequestStatus::Consumed
                        && same_call(consumed) =>
                {
                    ordinary_approval_consumed = consumed.args_snapshot == request.args;
                    false
                }
                Some(withdrawn)
                    if RequestStatus::of(&withdrawn.status) == RequestStatus::Cancelled =>
                {
                    ordinary_approval_withdrawn = true;
                    false
                }
                _ => false,
            }
        };
        if approval_id.is_some() && !approved {
            let expires_at = facade_approval
                .as_ref()
                .map(|row| row.expires_at_ms)
                .or_else(|| ordinary_approval.as_ref().map(|row| row.expires_at));
            let reason = match expires_at {
                None => PolicyDenial::ApprovalMissing,
                Some(_) if ordinary_approval_withdrawn => PolicyDenial::ApprovalWithdrawn,
                Some(_) if ordinary_approval_consumed => PolicyDenial::ApprovalConsumed,
                Some(expires_at) if expires_at <= now => PolicyDenial::ApprovalExpired,
                Some(_) => PolicyDenial::ApprovalShapeMismatch,
            };
            let denial = Denial::Policy(reason);
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                Some(&grant),
                &denial,
            );
            return Err(denial);
        }
        if policy_effect == "ask_first" && !approved {
            // Flows have no interactive consent surface; refuse before holding
            // an approval or reserving a dispatch, while retaining the decision audit.
            if request
                .scope
                .as_ref()
                .is_some_and(|scope| scope.flow_id.is_some())
            {
                let denial = Denial::ConsentUnavailable {
                    action: request.action.clone(),
                };
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    Some(&grant),
                    &denial,
                );
                return Err(denial);
            }
            if per_call_approval_unsupported(
                policy_effect,
                request.supports_per_call_approval && request.authority_kind == AUTHORITY_INVOKE,
            ) {
                let denial = Denial::Policy(PolicyDenial::AskFirst);
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    Some(&grant),
                    &denial,
                );
                return Err(denial);
            }
            // Flow calls never get a card: they were refused
            // `consent_unavailable` above. This check, that the route
            // carries a head or worker session to file the card under,
            // applies only to interactive calls.
            if request.origin != RequestOrigin::Facade
                && !request
                    .scope
                    .as_ref()
                    .is_some_and(|scope| scope.flow_id.is_some())
                && (request.requires_session_consent
                    || request.attributed_agent_id.is_some()
                    || self.consent_cards.is_some())
                && !ConsentCards::available_scope(request.scope.as_ref())
            {
                let denial = Denial::ConsentUnavailable {
                    action: request.action.clone(),
                };
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    Some(&grant),
                    &denial,
                );
                return Err(denial);
            }
            if request.origin == RequestOrigin::Facade {
                let denial = Denial::Policy(PolicyDenial::ApprovalMissing);
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    Some(&grant),
                    &denial,
                );
                return Err(denial);
            }
            let expires_at = now.saturating_add(APPROVAL_TTL_MS);
            if recipient_pointers.is_some() {
                let service_label = self.service_label(&connection.app_key);
                let action_label = action_label(&action, &request.action);
                let preview_id = crate::storage::new_id("req");
                let dedup_key = request
                    .call_key
                    .as_ref()
                    .map(|key| format!("{}:{key}", request.principal))
                    .unwrap_or_else(|| preview_id.clone());
                let preview = ParkedApproval {
                    request_id: &preview_id,
                    dedup_key: &dedup_key,
                    action_label,
                    service_label: &service_label,
                    risk: &action.risk,
                    args: &request.args,
                    complete_preview: true,
                    args_digest: &args_hash,
                    expires_in_ms: APPROVAL_TTL_MS,
                };
                let length = crate::consent_card::consent_request_wire_len(&preview);
                let limit = subc_protocol::MAX_FRAME_BODY_LEN as usize;
                if length > limit {
                    let denial = Denial::ApprovalPreviewTooLong {
                        action: request.action.clone(),
                        length,
                        limit,
                    };
                    self.audit_denial(
                        &request,
                        &args_hash,
                        Some(&connection),
                        Some(&action),
                        Some(&grant),
                        &denial,
                    );
                    return Err(denial);
                }
            }
            // The approval request stores the call's daemon scope, with its
            // `delegates` flag cleared when this kind of call cannot act as
            // the scope's agent (`scope_grants_agent` is false). Such calls use
            // the scope's agent for attribution only (a search, a GitHub read)
            // and are judged on the calling module's grants alone. When their
            // approval is re-checked before it runs, it must not then demand
            // the agent's own grant, nor be refused because the scope has since
            // stopped delegating. The audit rows still record the scope exactly
            // as the call carried it.
            let held_scope = request.scope.as_ref().map(|scope| {
                let mut held = scope.clone();
                held.delegates = held.delegates && request.scope_grants_agent;
                held
            });
            let ensured = match request.call_key.as_deref() {
                // A call that arrived with a key is stored under the pair
                // (carrier, call_key), where the carrier is the module that
                // sent the call. Either that module or the owner of the call's
                // daemon scope can then withdraw it by that key.
                Some(call_key) => self.store.ensure_keyed_action_request(
                    &connection.principal,
                    &request.connection_id,
                    &request.action,
                    &request.args,
                    &action.schema_hash,
                    &request.principal,
                    call_key,
                    expires_at,
                    held_scope.as_ref(),
                    request.relay_origin.as_ref(),
                ),
                None => self
                    .store
                    .ensure_action_request(
                        &connection.principal,
                        &request.connection_id,
                        &request.action,
                        &request.args,
                        &action.schema_hash,
                        &request.principal,
                        expires_at,
                        held_scope.as_ref(),
                        request.relay_origin.as_ref(),
                    )
                    .map(EnsuredRequest::Held),
            };
            let request_id = match ensured {
                Ok(EnsuredRequest::Held(request_id)) => request_id,
                Ok(EnsuredRequest::KeyTaken(held)) => {
                    let denial = Denial::Policy(if held.status == REQUEST_CANCELLED {
                        PolicyDenial::ApprovalWithdrawn
                    } else {
                        PolicyDenial::CallKeyReused
                    });
                    self.audit_denial(
                        &request,
                        &args_hash,
                        Some(&connection),
                        Some(&action),
                        Some(&grant),
                        &denial,
                    );
                    return Err(denial);
                }
                Err(_) => return Err(Denial::StoreFailure),
            };
            if !self
                .store
                .bind_action_request_routing(
                    &connection.principal,
                    &request_id,
                    &request.routing_context(),
                )
                .map_err(|_| Denial::StoreFailure)?
            {
                return Err(self.audited_refusal(
                    &request,
                    Denial::Policy(PolicyDenial::ApprovalShapeMismatch),
                ));
            }
            self.file_consent_card(
                &connection,
                &action,
                request.scope.as_ref(),
                &request_id,
                recipient_pointers.is_some(),
            );
            let denial = Denial::ActionRequestCreated { request_id };
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                Some(&grant),
                &denial,
            );
            return Err(denial);
        }
        if let Some(reason) = resource_denial_with_repositories(
            &connection,
            &action,
            &request.args,
            request.resolved_github_search_repositories(),
        ) {
            let denial = Denial::ResourceFilter(reason);
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                Some(&grant),
                &denial,
            );
            return Err(denial);
        }
        let (credential_fingerprint, credential) =
            match self.resolve_credential(&request, &connection) {
                Ok(value) => value,
                Err(denial) => {
                    self.audit_denial(
                        &request,
                        &args_hash,
                        Some(&connection),
                        Some(&action),
                        Some(&grant),
                        &denial,
                    );
                    return Err(denial);
                }
            };
        drop(credential);

        let authority_baseline = if request.origin == RequestOrigin::Facade {
            match self.capture_authority_baseline(&connection, &request, &action) {
                Ok(baseline) => Some(baseline),
                Err(denial) => {
                    self.audit_denial(
                        &request,
                        &args_hash,
                        Some(&connection),
                        Some(&action),
                        Some(&grant),
                        &denial,
                    );
                    return Err(denial);
                }
            }
        } else {
            None
        };
        let policy_generation = policy.as_ref().map_or(0, |value| value.generation);
        let snapshot = SnapshotGenerations {
            connection: connection.generation,
            catalog_action: action.generation,
            grant: grant.generation,
            policy: policy_generation,
            policy_id: policy.as_ref().map(|value| value.policy_id.clone()),
        };
        if request.origin == RequestOrigin::Facade
            && is_write(&action.risk)
            && !self
                .seams
                .as_ref()
                .is_some_and(|seams| seams.ownership_reads_complete(&request))
        {
            let denial = Denial::OwnershipProofMissing;
            self.audit_denial(
                &request,
                &args_hash,
                Some(&connection),
                Some(&action),
                Some(&grant),
                &denial,
            );
            return Err(denial);
        }
        let mut decision_id = None;
        let mut grant_hash = None;
        let mut intent_id = None;
        if matches!(severity, Severity::S3 | Severity::S4) {
            match self.evaluate_decision_plane(
                &request,
                &connection,
                &action,
                severity,
                &args_snapshot_hash,
                now,
            ) {
                Ok(authorization) => {
                    decision_id = Some(authorization.decision_id);
                    grant_hash = Some(authorization.grant_hash);
                    intent_id = Some(authorization.intent_id);
                }
                Err(denial) => {
                    self.audit_denial(
                        &request,
                        &args_hash,
                        Some(&connection),
                        Some(&action),
                        Some(&grant),
                        &denial,
                    );
                    return Err(denial);
                }
            }
        }
        let stored = match self.store.create_reservation(
            &connection.principal,
            &request.connection_id,
            &request.action,
            &grant.grant_id,
            &snapshot,
            &args_hash,
            &action.schema_hash,
            now.saturating_add(RESERVATION_TTL_MS),
            // Only an ordinary approval is consumed by the reservation claim.
            // The GitHub facade consumes its approval together with the bot
            // receipt's terminal outcome, in its own store.
            if request.origin == RequestOrigin::Ordinary {
                intent_id
                    .as_deref()
                    .or(if approved { approval_id } else { None })
            } else {
                None
            },
            agent_grant_pin.as_ref(),
        ) {
            Ok(stored) => stored,
            Err(_) => {
                if let Some(id) = decision_id.as_deref() {
                    self.report_unsent_plane_allow(
                        &request,
                        &connection,
                        &action,
                        &args_hash,
                        id,
                        &Denial::StoreFailure,
                    );
                }
                self.audit_denial(
                    &request,
                    &args_hash,
                    Some(&connection),
                    Some(&action),
                    Some(&grant),
                    &Denial::StoreFailure,
                );
                return Err(Denial::StoreFailure);
            }
        };
        self.audit_authorization_decision(
            &request,
            &args_hash,
            Some(&connection),
            Some(&action),
            Some(&grant),
            "credential",
            "allow",
            "credential_resolved",
            Some(credential_fingerprint.clone()),
        );
        // A stored approval raised under a scope runs only after that scope is
        // re-checked with the daemon, just before the claim that consumes it.
        let approval_scope = if request.origin == RequestOrigin::Ordinary && approved {
            ordinary_approval.as_ref().and_then(approval_scope_of)
        } else {
            None
        };
        Ok(Some(Reservation {
            reservation_id: stored.reservation_id,
            principal: connection.principal,
            acting_principal: request.principal,
            actor: request.actor,
            attributed_agent_id: request.attributed_agent_id,
            bound_agent_handle: request.bound_agent_handle,
            connection_id: request.connection_id,
            app_key: connection.app_key,
            action: request.action,
            approved_args: request.args.clone(),
            args: request.args,
            grant_id: grant.grant_id.clone(),
            approved_args_hash: args_hash,
            args_snapshot_hash,
            schema_hash: action.schema_hash,
            risk: parse_risk(&action.risk),
            severity,
            snapshot,
            expires_at_ms: stored.expires_at,
            request_id: request.request_id,
            credential_fingerprint,
            decision_id,
            grant_hash,
            intent_id,
            authority_baseline,
            receipt: request.receipt,
            origin: request.origin,
            scope: request.scope,
            relay_origin: request.relay_origin,
            on_behalf_of_agent: request.on_behalf_of_agent,
            agent_grant: agent_grant_pin,
            approval_scope,
            federated_caller: None,
            federated_row_id: None,
            federated_card_ref: None,
            federated_search_use: false,
        }))
    }

    fn evaluate_decision_plane(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        severity: Severity,
        args_snapshot_hash: &str,
        now: i64,
    ) -> Result<DecisionAuthorization, Denial> {
        let Some(plane) = self.decision_plane.as_ref() else {
            let envelope = DecisionPlaneEnvelope {
                request_id: request.request_id.clone(),
                connection_id: request.connection_id.clone(),
                action: request.action.clone(),
                args_hash: args_snapshot_hash.to_string(),
                schema_hash: action.schema_hash.clone(),
                severity,
                expires_at_ms: now.saturating_add(APPROVAL_TTL_MS),
            };
            return Err(Denial::NeedsDecisionPlane(Box::new(envelope)));
        };

        // intent_id = action_request row: create-or-reuse BEFORE the verdict call.
        let intent_id = if let Some(approved_id) = request
            .receipt_approval
            .as_ref()
            .map(|value| &value.action_request_id)
            .or(request.approved_request_id.as_ref())
        {
            approved_id.clone()
        } else {
            if request.origin == RequestOrigin::Facade {
                return Err(Denial::Policy(PolicyDenial::ApprovalMissing));
            }
            let held_scope = request.scope.as_ref().map(|scope| {
                let mut held = scope.clone();
                held.delegates = held.delegates && request.scope_grants_agent;
                held
            });
            let ensured = if let Some(key) = request.call_key.as_deref() {
                self.store.ensure_keyed_action_request(
                    &connection.principal,
                    &request.connection_id,
                    &request.action,
                    &request.args,
                    &action.schema_hash,
                    &request.principal,
                    key,
                    now.saturating_add(APPROVAL_TTL_MS),
                    held_scope.as_ref(),
                    request.relay_origin.as_ref(),
                )
            } else {
                self.store
                    .ensure_action_request(
                        &connection.principal,
                        &request.connection_id,
                        &request.action,
                        &request.args,
                        &action.schema_hash,
                        &request.principal,
                        now.saturating_add(APPROVAL_TTL_MS),
                        held_scope.as_ref(),
                        request.relay_origin.as_ref(),
                    )
                    .map(EnsuredRequest::Held)
            };
            match ensured.map_err(|_| Denial::StoreFailure)? {
                EnsuredRequest::Held(id) => id,
                EnsuredRequest::KeyTaken(held) => {
                    return Err(Denial::Policy(if held.status == REQUEST_CANCELLED {
                        PolicyDenial::ApprovalWithdrawn
                    } else {
                        PolicyDenial::CallKeyReused
                    }))
                }
            }
        };

        if request.origin != RequestOrigin::Facade
            && !self
                .store
                .bind_action_request_routing(
                    &connection.principal,
                    &intent_id,
                    &request.routing_context(),
                )
                .map_err(|_| Denial::StoreFailure)?
        {
            return Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch));
        }
        let risk = parse_risk(&action.risk);
        let envelope = DecisionEnvelope {
            acting_principal: request.principal.clone(),
            connection_fingerprint: connection_fingerprint(&connection.connection_id),
            app_key: connection.app_key.clone(),
            action: request.action.clone(),
            risk,
            severity,
            args_snapshot: request.args.clone(),
            args_snapshot_hash: args_snapshot_hash.to_string(),
            schema_hash: action.schema_hash.clone(),
            reversibility_class: reversibility_class_for_risk(risk).to_string(),
            intent_id: intent_id.clone(),
            requested_at_ms: now,
        };

        let verdict = match plane.request_verdict(&envelope) {
            Ok(verdict) => verdict,
            Err(_) => {
                return Err(Denial::Severity(Box::new(
                    SeverityDenial::DecisionPlaneFailure,
                )));
            }
        };

        match verdict {
            Verdict::Allow {
                decision_id,
                grant_hash,
            } => {
                if let Err(error) = verify_grant_hash(
                    GrantHashInput {
                        decision_id: &decision_id,
                        app_key: &connection.app_key,
                        action: &request.action,
                        args_snapshot_hash,
                        schema_hash: &action.schema_hash,
                    },
                    &grant_hash,
                ) {
                    let reason = match error {
                        DecisionPlaneError::GrantHashMismatch { .. } => {
                            SeverityDenial::GrantHashMismatch
                        }
                        _ => SeverityDenial::DecisionPlaneFailure,
                    };
                    let denial = Denial::Severity(Box::new(reason));
                    self.report_unsent_plane_allow(
                        request,
                        connection,
                        action,
                        args_snapshot_hash,
                        &decision_id,
                        &denial,
                    );
                    return Err(denial);
                }
                let recorded = self.store.record_decision_plane_verdict(
                    &connection.principal,
                    &intent_id,
                    crate::storage::PlaneVerdict::Approved,
                    "decision-plane",
                    Some(&decision_id),
                ).map_err(|error| {
                    eprintln!(error governance: "could not record decision {decision_id} on request {intent_id}: {error}");
                    self.report_unsent_plane_allow(request, connection, action, args_snapshot_hash, &decision_id, &Denial::StoreFailure);
                    Denial::StoreFailure
                })?;
                if !recorded {
                    let denial = Denial::Policy(PolicyDenial::ApprovalAlreadyDecided);
                    self.report_unsent_plane_allow(
                        request,
                        connection,
                        action,
                        args_snapshot_hash,
                        &decision_id,
                        &denial,
                    );
                    return Err(denial);
                }
                Ok(DecisionAuthorization {
                    decision_id,
                    grant_hash,
                    intent_id,
                })
            }
            Verdict::Deny { reason } => {
                self.store
                    .record_decision_plane_verdict(
                        &connection.principal,
                        &intent_id,
                        crate::storage::PlaneVerdict::Denied,
                        "decision-plane",
                        None,
                    )
                    .map_err(|_| Denial::StoreFailure)?;
                Err(Denial::Severity(Box::new(SeverityDenial::DecisionDenied {
                    reason,
                })))
            }
            Verdict::NeedsQuorum { decision_id } => {
                let recorded = self.store.record_decision_plane_verdict(
                    &connection.principal,
                    &intent_id,
                    crate::storage::PlaneVerdict::Pending,
                    "decision-plane",
                    Some(&decision_id),
                ).map_err(|error| {
                    eprintln!(error governance:
                        "could not record decision {decision_id} on request {intent_id}: {error}"
                    );
                    Denial::StoreFailure
                })?;
                if !recorded {
                    return Err(Denial::Policy(PolicyDenial::ApprovalAlreadyDecided));
                }
                // Decision plane deferred the action; return ActionRequestCreated so
                // clients see a pending request the same way as ask-first approvals.
                Err(Denial::ActionRequestCreated {
                    request_id: intent_id,
                })
            }
        }
    }
}
