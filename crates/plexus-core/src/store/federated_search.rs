use super::{
    cards, commit::Answer, matching_row_on_conn, FederatedReservationInput, FederatedStandingRow,
    PlexusStore, StoreError,
};
use crate::federated::{
    card::{CallerIdentity, Record, Scope, State},
    matcher::{Call, Effect},
    FederatedCaller,
};
use crate::governance::Denial;
use crate::web_search::federated::SearchUse;

impl PlexusStore {
    pub(crate) fn validate_federated_search_use(
        &self,
        caller: &FederatedCaller,
        used: &SearchUse,
        now: i64,
    ) -> Result<Result<(), Denial>, StoreError> {
        self.inner.with_conn_fenced(|tx| {
            let call = Call {
                peer_fingerprint: &caller.attributes.peer_fingerprint,
                pairing_id: &caller.attributes.pairing_id,
                peer_class: "computer",
                claim: caller.attributes.remote_claim.as_ref(),
                owner_principal: "",
                subject: &used.binding.subject,
                scope: "read",
            };
            let row = matching_row_on_conn(tx, &call, now)?;
            Ok(check_use(&row, used))
        })
    }

    /// Consume in the serialized store transaction, after confirming the caller's
    /// base scope is live and charging both rate buckets. A revoke or competing
    /// collector must win over the previously read answer.
    pub(crate) fn consume_federated_search(
        &self,
        caller: &FederatedCaller,
        expected: &Record,
        answer: Answer,
        now: i64,
    ) -> Result<Result<SearchUse, Denial>, StoreError> {
        self.inner.with_conn_fenced(|tx| {
            let binding = &expected.binding;
            let unavailable = || Denial::ConsentUnavailable {
                action: binding.action.clone(),
            };
            if binding.caller != CallerIdentity::from(caller)
                || !binding.owner_principal.is_empty()
                || !matches!(binding.subject.as_str(), "web_search" | "code_search")
                || binding.action != binding.subject
                || expected.scope != Scope::Read
                || expected.schema_hash.is_some()
            {
                return Ok(Err(unavailable()));
            }
            let call = Call {
                peer_fingerprint: &caller.attributes.peer_fingerprint,
                pairing_id: &caller.attributes.pairing_id,
                peer_class: "computer",
                claim: caller.attributes.remote_claim.as_ref(),
                owner_principal: "",
                subject: &binding.subject,
                scope: "read",
            };
            let row = matching_row_on_conn(tx, &call, now)?;
            if row.as_ref().is_some_and(|r| r.effect == Effect::Deny) {
                return Ok(Err(Denial::FederatedConsentDenied));
            }
            let Some(record) = cards::read_on_conn(tx, &expected.id)? else {
                return Ok(Err(unavailable()));
            };
            if record != *expected {
                return Ok(Err(unavailable()));
            }
            let Some(card_ref) = record.card_ref.as_deref() else {
                return Ok(Err(unavailable()));
            };
            let processed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM federated_processed_cards WHERE card_ref=?1)",
                [card_ref],
                |r| r.get(0),
            )?;
            if answer == Answer::AllowAlways {
                if record.state != State::Committed || !processed || row.is_none() {
                    return Ok(Err(unavailable()));
                }
            } else if record.state != State::Pending || processed {
                return Ok(Err(unavailable()));
            }
            let (state, refusal) = match answer {
                Answer::AllowOnce | Answer::AllowAlways => (State::Consumed, None),
                Answer::Expired => (State::Expired, Some("consent_expired")),
                Answer::Withdrawn => (State::Withdrawn, Some("consent_withdrawn")),
                _ => (State::Declined, Some("consent_denied")),
            };
            tx.execute(
                "UPDATE federated_card_records SET state=?2 WHERE id=?1",
                (&record.id, state.as_str()),
            )?;
            if let Some(code) = refusal {
                return Ok(Err(Denial::ConsentRefused {
                    code,
                    elicitation_id: card_ref.into(),
                }));
            }
            Ok(Ok(SearchUse {
                binding: binding.clone(),
                row_id: row.map(|r| r.id),
                card_ref: card_ref.into(),
            }))
        })
    }

    /// A carried use is already single-use at the search boundary. Do not read
    /// the consumed card here: several provider attempts belong to that one call.
    pub(crate) fn reserve_federated_search_use(
        &self,
        call: &Call<'_>,
        input: &FederatedReservationInput<'_>,
        used: &SearchUse,
    ) -> Result<Result<(Option<FederatedStandingRow>, String), Denial>, StoreError> {
        self.inner.with_conn_fenced(|tx| {
            let row = matching_row_on_conn(tx, call, input.now)?;
            if let Err(denial) = check_use(&row, used) { return Ok(Err(denial)); }
            let id = crate::storage::new_id("res");
            let snapshot = serde_json::to_string(input.snapshot).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            tx.execute("INSERT INTO reservations (reservation_id,principal,connection_id,action,snapshot_generations,approved_args_hash,schema_hash,expires_at,status,created_at_ms,federated_row_id,card_ref)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'reserved',?9,?10,?11)", rusqlite::params![id,input.principal,input.connection_id,input.action,snapshot,input.args_hash,input.schema_hash,input.expires_at,input.now,row.as_ref().map(|r| &r.id),used.card_ref])?;
            Ok(Ok((row, id)))
        })
    }
}

fn check_use(row: &Option<FederatedStandingRow>, used: &SearchUse) -> Result<(), Denial> {
    if row.as_ref().is_some_and(|r| r.effect == Effect::Deny) {
        return Err(Denial::FederatedConsentDenied);
    }
    if used
        .row_id
        .as_ref()
        .is_some_and(|id| row.as_ref().is_none_or(|r| &r.id != id))
    {
        return Err(Denial::ConsentUnavailable {
            action: used.binding.action.clone(),
        });
    }
    Ok(())
}
