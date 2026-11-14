use super::{cards, FederatedRowKey};
use crate::federated::card::{CallerIdentity, Record, State};
use crate::federated::matcher::Effect;
use crate::federated::{canonicalize_claim, new_row_id, FederatedCaller};
use crate::governance::Denial;
use crate::scope::{ScopeReader, ScopeStatus};
use crate::storage::PlexusStore;
use crate::transport::TransmissionState;
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;

/// Requester outcomes remain distinct from choices: a default decline must
/// never be mistaken for an explicit standing denial, even on a stale readback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    AllowOnce,
    AllowAlways,
    DenyOnce,
    DenyAlways,
    Expired,
    TimedOut,
    Withdrawn,
    Dismissed,
}

impl Answer {
    pub(crate) fn standing_effect(self) -> Option<Effect> {
        match self {
            Self::AllowAlways => Some(Effect::Allow),
            Self::DenyAlways => Some(Effect::Deny),
            _ => None,
        }
    }

    pub(crate) fn choice_id(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow_once",
            Self::AllowAlways => "allow_always",
            Self::DenyAlways => "deny_always",
            _ => "deny_once",
        }
    }
}

pub(crate) struct CommitInput<'a> {
    pub caller: &'a FederatedCaller,
    /// The record found for the current binding, scope and schema, not merely
    /// any record whose requester ref appeared in the answer.
    pub record: &'a Record,
    pub answer: Answer,
    /// Collection validates that the original card offered standing choices.
    /// In particular a per-call-only ask under a standing allow cannot mint.
    pub standing_choices_offered: bool,
    pub now_ms: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommitOutcome {
    Committed {
        row_id: String,
        effect: Effect,
    },
    /// No authority from this answer may serve a call. File a new card.
    Reask,
    /// Per-call settlement/consumption belongs to the collecting transaction.
    PerCall(Answer),
}

#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub denial: Denial,
    pub transmission: TransmissionState,
}

impl From<Denial> for CommitFailure {
    fn from(denial: Denial) -> Self {
        Self {
            denial,
            transmission: TransmissionState::NotSent,
        }
    }
}

impl PlexusStore {
    /// Each standing answer needs its own live describe before acquiring the
    /// store's `with_conn_fenced` transaction. Re-read the record in that
    /// transaction so a concurrent revocation or connection deletion wins.
    /// A successful transaction writes the row,
    /// processed ref and committed state together; reading it again asks anew.
    /// The collector must validate the requester answer and run every non-grant
    /// gate before calling this boundary. This does not reserve or send a call.
    pub(crate) fn commit_federated_standing_answer(
        &self,
        reader: Option<&dyn ScopeReader>,
        input: &CommitInput<'_>,
    ) -> Result<CommitOutcome, CommitFailure> {
        let Some(effect) = input.answer.standing_effect() else {
            return Ok(CommitOutcome::PerCall(input.answer));
        };
        let unavailable = || Denial::ConsentUnavailable {
            action: input.record.binding.action.clone(),
        };
        let attributes = &input.caller.attributes;
        // Normalize the stamp again instead of trusting separately supplied key
        // or display data, including the caller's cached normalized claim.
        let claim = canonicalize_claim(attributes.remote_claim.as_ref())
            .map_err(|_| CommitFailure::from(unavailable()))?;
        let selector = if claim.claim_kind.is_empty() {
            "claimless"
        } else {
            "exact_claim"
        };
        let identity = CallerIdentity {
            peer_fingerprint: attributes.peer_fingerprint.clone(),
            pairing_id: attributes.pairing_id.clone(),
            peer_class: "computer".into(),
            claim_kind: claim.claim_kind.into(),
            canonical_claim_identity: claim.canonical_claim_identity.clone(),
        };
        if !input.standing_choices_offered
            || attributes.peer_class != subc_protocol::scope::FederatedPeerClass::Computer
            || !matches!(claim.claim_kind, "" | "agent" | "flow")
            || input.record.binding.caller != identity
            || input.record.selector != selector
            || input.record.card_ref.as_deref().is_none_or(str::is_empty)
        {
            return Err(unavailable().into());
        }

        let base = format!(
            "fed-base:{}:{}",
            attributes.peer_fingerprint, attributes.pairing_id
        );
        let description = reader
            .ok_or(Denial::FederatedLivenessUnavailable)?
            .describe("reserved:callosum", &base)
            .map_err(|_| Denial::FederatedLivenessUnavailable)?;
        match description.status {
            ScopeStatus::Live => {}
            ScopeStatus::Ended => return Err(Denial::FederatedPairingEnded.into()),
            ScopeStatus::NotLive if description.owner_synced && description.owner_configured => {
                return Err(Denial::FederatedPairingEnded.into());
            }
            _ => return Err(Denial::FederatedLivenessUnavailable.into()),
        }

        self.inner
            .with_conn_fenced(|tx| {
                let Some(record) = cards::read_on_conn(tx, &input.record.id)? else {
                    return Ok(CommitOutcome::Reask);
                };
                if record.binding != input.record.binding
                    || record.scope != input.record.scope
                    || record.schema_hash != input.record.schema_hash
                    || record.selector != selector
                    || record.card_ref != input.record.card_ref
                {
                    return Ok(CommitOutcome::Reask);
                }
                let card_ref = record
                    .card_ref
                    .as_deref()
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let processed: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM federated_processed_cards WHERE card_ref=?1)",
                    [card_ref],
                    |row| row.get(0),
                )?;
                if processed {
                    tx.execute(
                        "UPDATE federated_card_records SET state='retired' WHERE id=?1",
                        [&record.id],
                    )?;
                    return Ok(CommitOutcome::Reask);
                }
                if record.state != State::Pending {
                    return Ok(CommitOutcome::Reask);
                }
                let key = FederatedRowKey {
                    peer_fingerprint: identity.peer_fingerprint,
                    pairing_id: identity.pairing_id,
                    peer_class: identity.peer_class,
                    selector: selector.into(),
                    claim_kind: identity.claim_kind,
                    canonical_claim_identity: identity.canonical_claim_identity,
                    owner_principal: record.binding.owner_principal.clone(),
                    subject: record.binding.subject.clone(),
                    scope: record.scope.as_str().into(),
                };
                let existing: Option<(String, String, String)> = tx
                    .query_row(
                        "SELECT id,effect,card_refs_json FROM federated_rows
                 WHERE peer_fingerprint=?1 AND pairing_id=?2 AND peer_class=?3 AND selector=?4
                   AND claim_kind=?5 AND canonical_claim_identity=?6 AND owner_principal=?7
                   AND subject=?8 AND scope=?9",
                        key.params(),
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let effect_text = match effect {
                    Effect::Allow => "allow",
                    Effect::Deny => "deny",
                };
                let row_id = if let Some((id, _, refs)) =
                    existing.as_ref().filter(|(_, old, _)| old == effect_text)
                {
                    let mut refs: BTreeSet<String> = super::super::parse_json_column(refs)?;
                    refs.insert(card_ref.into());
                    tx.execute(
                        "UPDATE federated_rows SET card_refs_json=?2 WHERE id=?1",
                        params![
                            id,
                            serde_json::to_string(&refs).expect("string set is JSON")
                        ],
                    )?;
                    id.clone()
                } else {
                    if let Some((id, _, _)) = existing {
                        self.delete_federated_row_on_conn(tx, &id, Some(&record.id), input.now_ms)?;
                    }
                    let id = new_row_id();
                    let claim_json = claim
                        .claim
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                        })?;
                    tx.execute(
                    "INSERT INTO federated_rows (id,peer_fingerprint,pairing_id,peer_class,selector,
                     claim_kind,canonical_claim_identity,owner_principal,subject,scope,claim_json,
                     peer_name,effect,granted_at_ms,card_ref,card_refs_json)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                    params![id,key.peer_fingerprint,key.pairing_id,key.peer_class,key.selector,
                        key.claim_kind,key.canonical_claim_identity,key.owner_principal,key.subject,
                        key.scope,claim_json,attributes.peer_name,effect_text,input.now_ms,card_ref,
                        serde_json::to_string(&[card_ref]).expect("string array is JSON")],
                )?;
                    id
                };
                tx.execute(
                    "INSERT INTO federated_processed_cards(card_ref) VALUES (?1)",
                    [card_ref],
                )?;
                tx.execute(
                    "UPDATE federated_card_records SET state='committed' WHERE id=?1",
                    [&record.id],
                )?;
                Ok(CommitOutcome::Committed { row_id, effect })
            })
            .map_err(|_| Denial::StoreFailure.into())
    }
}

#[cfg(test)]
#[path = "federated_commit/tests.rs"]
mod tests;
