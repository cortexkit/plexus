//! Pure standing-row selection. The caller separately checks route admission
//! and whether the paired peer's base scope is still live. Selecting an allow
//! row alone does not dispatch a call.

use super::canonicalize_claim;
use subc_protocol::scope::RemoteClaim;

/// Stored effects are distinct from the permission-list wire representation,
/// where grants omit the effect member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// The matching fields of a standing row, independent of storage or wire shape.
/// The permissions/v1 contract permits broad selectors and expiry, which Plexus
/// does not mint, and requires missing selectors to match nothing.
#[derive(Debug, Clone, Copy)]
pub struct Row<'a> {
    pub peer_fingerprint: &'a str,
    pub pairing_id: &'a str,
    pub peer_class: &'a str,
    pub selector: Option<&'a str>,
    pub claim: Option<&'a RemoteClaim>,
    pub owner_principal: &'a str,
    pub subject: &'a str,
    pub scope: &'a str,
    pub effect: Effect,
    pub expires_at_ms: Option<i64>,
}

/// Facts from the admitted caller and the resource being authorized. Search
/// subjects use an empty owner, unlike connections in a principal's namespace.
#[derive(Debug, Clone, Copy)]
pub struct Call<'a> {
    pub peer_fingerprint: &'a str,
    pub pairing_id: &'a str,
    pub peer_class: &'a str,
    pub claim: Option<&'a RemoteClaim>,
    pub owner_principal: &'a str,
    pub subject: &'a str,
    pub scope: &'a str,
}

/// Return the index of a deciding row, or no standing answer. Specific rows
/// decide before broad rows; within either group a denial wins. Equal-effect
/// ties select the first row, so the caller can pin the selected stored row id.
/// No clock, store, liveness reader or display metadata participates in selection.
pub fn match_rows(rows: &[Row<'_>], call: &Call<'_>, now_ms: i64) -> Option<usize> {
    let call_claim = canonicalize_claim(call.claim).ok()?;
    if call_claim.claim_kind == "run" {
        return None;
    }

    let mut winner = None;
    let mut winning_rank = None;
    for (index, row) in rows.iter().enumerate() {
        if row.peer_fingerprint != call.peer_fingerprint
            || row.pairing_id != call.pairing_id
            || row.peer_class != call.peer_class
            || row.owner_principal != call.owner_principal
            || row.subject != call.subject
            || row.scope != call.scope
            || row.expires_at_ms.is_some_and(|expiry| now_ms >= expiry)
        {
            continue;
        }

        let specific = match row.selector {
            Some("exact_claim") if call.claim.is_some() => {
                let Ok(row_claim) = canonicalize_claim(row.claim) else {
                    continue;
                };
                if row_claim.claim_kind != call_claim.claim_kind
                    || row_claim.canonical_claim_identity != call_claim.canonical_claim_identity
                {
                    continue;
                }
                true
            }
            Some("claimless") if row.claim.is_none() && call.claim.is_none() => true,
            Some("all_claims") if row.claim.is_none() => false,
            _ => continue,
        };

        // Lexicographic rank gives specificity priority over either effect.
        // Only after selecting that group does a denial take precedence.
        let rank = (specific, row.effect == Effect::Deny);
        if winning_rank.is_none_or(|previous| rank > previous) {
            winner = Some(index);
            winning_rank = Some(rank);
        }
    }
    winner
}

#[cfg(test)]
mod tests;
