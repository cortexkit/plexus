//! `tool.withdraw`: withdrawing a call that plexus holds as an approval
//! request, by the key its carrier gave it.
//!
//! A call that needs approval is held as an approval request until someone
//! decides it. If the call carried a `call_key`, the request is stored under
//! `(carrier, call_key)`, where the carrier is the module that sent the call.
//! The carrier, or the owner of the daemon scope the call was raised under,
//! may withdraw it; a withdrawn request is never sent.
//!
//! The answer is read from the stored request, so it is the same for every
//! permitted caller, on every repeat, and across a restart. Plexus never
//! answers `completed` with a result: once the approval has been claimed for
//! sending, the answer is `already_started` with the outcome plexus recorded.

use serde_json::{json, Value};

use crate::scope::CallScope;
use crate::storage::PlexusStore;

/// `refused` reason: the request was denied.
pub const WITHDRAW_REFUSED_DENIED: &str = "denied";
/// `refused` reason: the request expired before anyone decided or sent it.
pub const WITHDRAW_REFUSED_EXPIRED: &str = "expired";
/// `refused` reason: the scope re-check retired the approved request because
/// its session, or the authority it was raised under, had ended.
pub const WITHDRAW_REFUSED_SCOPE_ENDED: &str = "scope_ended";
/// `already_started` outcome when plexus cannot tell how the call settled.
pub const WITHDRAW_OUTCOME_UNKNOWN: &str = "unknown";
/// The route error for a caller that may not withdraw the named call.
pub const WITHDRAW_NOT_PERMITTED: &str = "withdraw_not_permitted";

/// Where a withdrawn call stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WithdrawAnswer {
    /// The call will never run.
    Withdrawn,
    /// The approval was already claimed for sending. `outcome` is how that
    /// attempt's send settled (`completed`, `failed`, `not_sent`, `unknown`),
    /// as recorded on the request itself or, for a request that settled before
    /// the request kept it, on the attempt's `dispatch` audit row; `unknown`
    /// when neither is recorded yet.
    AlreadyStarted { outcome: String },
    /// The call will never run, for a reason other than this withdrawal.
    Refused { reason: &'static str },
    /// Plexus holds nothing under this key for this carrier. That includes a
    /// call that was sent in its own request and never became an approval
    /// request, so this means "held nothing", never "not sent".
    UnknownCall,
}

impl WithdrawAnswer {
    /// The reply body a `tool.withdraw` request returns.
    pub fn to_wire(&self) -> Value {
        match self {
            Self::Withdrawn => json!({"answer": "withdrawn"}),
            Self::AlreadyStarted { outcome } => {
                json!({"answer": "already_started", "outcome": outcome})
            }
            Self::Refused { reason } => json!({"answer": "refused", "reason": reason}),
            Self::UnknownCall => json!({"answer": "unknown_call"}),
        }
    }
}

/// Why a withdrawal produced no answer.
#[derive(Debug)]
pub enum WithdrawRefusal {
    /// The caller is neither the call's carrier nor its scope's owner under
    /// the same scope. The text says which check failed, for the log.
    NotPermitted(&'static str),
    /// The store could not be read or written.
    Store(cortexkit_store::StoreError),
}

impl From<cortexkit_store::StoreError> for WithdrawRefusal {
    fn from(error: cortexkit_store::StoreError) -> Self {
        Self::Store(error)
    }
}

/// One `tool.withdraw` request, as the route presented it.
#[derive(Debug, Clone, Copy)]
pub struct WithdrawCall<'a> {
    /// The principal of the route the request arrived on.
    pub caller: &'a str,
    /// `arguments.call_key`: the key of the call to withdraw.
    pub call_key: &'a str,
    /// `arguments.carrier`: which carrier's call, when the scope's owner is
    /// withdrawing a call another module carried.
    pub carrier: Option<&'a str>,
    /// The scope stamped on the route the request arrived on.
    pub scope: Option<&'a CallScope>,
}

/// Check that the caller may withdraw the named call, then withdraw it.
///
/// Who may withdraw: the carrier that raised the call, or the owner of the
/// scope the call was raised under, and in both cases only from a route
/// stamped with that same scope (owner, ref and epoch; or no scope at all for
/// a call raised without one).
///
/// - A carrier withdraws its own call. It may name itself as `carrier`, but
///   naming any other carrier is refused.
/// - The scope's owner names the carrier whose call it withdraws. Without a
///   `carrier` it can only withdraw a call it carried itself; if another
///   carrier holds the key in its scope, the request is refused rather than
///   answered `unknown_call`, since plexus does hold that call.
pub fn withdraw_call(
    store: &PlexusStore,
    call: &WithdrawCall<'_>,
) -> Result<WithdrawAnswer, WithdrawRefusal> {
    let caller_is_owner = call.scope.is_some_and(|scope| scope.owner == call.caller);
    let carrier = match call.carrier {
        Some(named) if named == call.caller || caller_is_owner => named,
        Some(_) => {
            return Err(WithdrawRefusal::NotPermitted(
                "a caller that is not the scope's owner may only withdraw its own calls",
            ))
        }
        None => call.caller,
    };
    let Some(request) = store.keyed_action_request(carrier, call.call_key)? else {
        if let (true, None, Some(scope)) = (caller_is_owner, call.carrier, call.scope) {
            if store.call_key_held_in_scope(
                call.call_key,
                &scope.owner,
                &scope.scope_ref,
                scope.scope_epoch,
            )? {
                return Err(WithdrawRefusal::NotPermitted(
                    "the scope's owner must name the carrier of a call it did not carry",
                ));
            }
        }
        return Ok(WithdrawAnswer::UnknownCall);
    };
    let same_scope = match (request.scope.as_ref(), call.scope) {
        (None, None) => true,
        (Some(held), Some(route)) => {
            held.owner == route.owner
                && held.scope_ref == route.scope_ref
                && held.scope_epoch == route.scope_epoch
        }
        _ => false,
    };
    if !same_scope {
        return Err(WithdrawRefusal::NotPermitted(
            "the call was raised under a different scope than this route's",
        ));
    }
    Ok(store.withdraw_keyed_request(carrier, call.call_key)?)
}
