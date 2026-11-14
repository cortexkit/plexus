use super::*;
use crate::federated::card::{Context, PreparedCard, Record};
use crate::storage::federated_store::commit::Answer;
use serde_json::json;

impl<C: CredentialSource + ?Sized, T: Transport + ?Sized> GovernanceEngine<C, T> {
    pub(super) fn federated_live(
        &self,
        caller: &crate::federated::FederatedCaller,
    ) -> Result<(), Denial> {
        let base = format!(
            "fed-base:{}:{}",
            caller.attributes.peer_fingerprint, caller.attributes.pairing_id
        );
        let description = self
            .scope_reader
            .as_ref()
            .ok_or(Denial::FederatedLivenessUnavailable)?
            .describe("reserved:callosum", &base)
            .map_err(|_| Denial::FederatedLivenessUnavailable)?;
        match description.status {
            crate::scope::ScopeStatus::Live => Ok(()),
            crate::scope::ScopeStatus::Ended => Err(Denial::FederatedPairingEnded),
            crate::scope::ScopeStatus::NotLive
                if description.owner_synced && description.owner_configured =>
            {
                Err(Denial::FederatedPairingEnded)
            }
            _ => Err(Denial::FederatedLivenessUnavailable),
        }
    }

    pub(super) fn collect_federated_invoke(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
        action: &CatalogAction,
    ) -> Result<(Record, Answer), Denial> {
        let unavailable = || Denial::ConsentUnavailable {
            action: request.action.clone(),
        };
        let caller = request.federated_caller.as_ref().ok_or_else(unavailable)?;
        if !request.federated_held_reply || matches!(caller.claim.claim_kind, "flow" | "run") {
            return Err(unavailable());
        }
        let scope = request.scope.as_ref().ok_or_else(unavailable)?;
        let prepared = PreparedCard::invoke(
            &self.store,
            &Context {
                caller,
                filed_scope: scope,
                expires_in_ms: APPROVAL_TTL_MS,
                per_call_only: request.federated_row_id.is_some(),
            },
            connection,
            action,
            &request.args,
            self.store
                .recipient_pointers(&connection.app_key, &action.name)
                .map_err(|_| Denial::StoreFailure)?
                .is_some(),
        )
        .map_err(|_| unavailable())?;
        self.collect_federated_card(
            request,
            prepared,
            &self.service_label(&connection.app_key),
            action_label(action, &action.name),
        )
    }

    pub(super) fn collect_federated_card(
        &self,
        request: &AuthorizationRequest,
        prepared: PreparedCard,
        service: &str,
        action: &str,
    ) -> Result<(Record, Answer), Denial> {
        let unavailable = || Denial::ConsentUnavailable {
            action: action.into(),
        };
        let scope = request.scope.as_ref().ok_or_else(unavailable)?;
        let deadline = request.federated_deadline.ok_or_else(unavailable)?;
        let client = self.consent_cards.as_ref().ok_or_else(unavailable)?;
        let mut record = self
            .store
            .ensure_federated_card(&prepared.record)
            .map_err(|_| unavailable())?;
        if record.card_ref.is_none() {
            let mut body = prepared.body;
            body["requester_ref"] = json!(record.id);
            if !record.standing_choices_offered {
                body["options"]
                    .as_array_mut()
                    .ok_or_else(unavailable)?
                    .retain(|option| {
                        matches!(option["id"].as_str(), Some("allow_once" | "deny_once"))
                    });
            }
            // Identical concurrent arrivals file the same requester correlation;
            // The consent service's pending-card dedup keeps filing idempotent.
            let id = client
                .file_federated(scope, body)
                .map_err(|_| unavailable())?;
            self.store
                .attach_federated_card(&record.id, &id)
                .map_err(|_| unavailable())?;
            record.card_ref = Some(id);
        }
        let id = record.card_ref.as_deref().ok_or_else(unavailable)?;
        let mut reply = client.get(scope, id).map_err(|_| unavailable())?;
        if reply["state"] == "pending" {
            reply = self
                .wait_for_consent(client, scope, id, deadline)
                .map_err(|_| unavailable())?;
        }
        if reply["elicitation_id"] != id
            || reply["kind"] != "consent"
            || reply["args_digest"] != record.binding.args_digest
            || reply["requester_ref"] != record.id
        {
            return Err(unavailable());
        }
        let answer = match (
            reply["state"].as_str(),
            reply["answered_choice_id"].as_str(),
        ) {
            (Some("pending"), _) => {
                return Err(Denial::AccessPending {
                    elicitation_id: id.into(),
                    service: service.into(),
                    action: action.into(),
                })
            }
            (Some("answered"), Some("allow_once")) => Answer::AllowOnce,
            (Some("answered"), Some("deny_once")) => Answer::DenyOnce,
            (Some("answered"), Some("allow_always")) if record.standing_choices_offered => {
                Answer::AllowAlways
            }
            (Some("answered"), Some("deny_always")) if record.standing_choices_offered => {
                Answer::DenyAlways
            }
            (Some("expired"), _) => Answer::Expired,
            (Some("withdrawn"), _) => Answer::Withdrawn,
            _ => return Err(unavailable()),
        };
        if reply["state"] == "answered" && reply["answered_choice_id"] != answer.choice_id() {
            return Err(unavailable());
        }
        Ok((record, answer))
    }
}
