//! Scope stamps: the session identity the daemon stamps on a route bind.
//!
//! A scope is a record the subc daemon holds for one session, identified by
//! `(owner, ref)` and pinned to one session by `scope_epoch` (the design is
//! `docs/designs/daemon-scopes.md` in the subconscious repository, which holds
//! the daemon). When a route is opened
//! under a scope, the daemon stamps the bind with the scope's fields. Plexus
//! reads identity from that stamp and never from a request payload.
//!
//! Three things here:
//! - [`CallScope`], the stamp as Plexus carries it through authorization and
//!   into the audit journal;
//! - [`resolve_call_agent`], which decides the agent a call is attributed to
//!   and the agent (if any) it acts as;
//! - [`approval_scope_verdict`], the rule a stored approval is re-checked by
//!   at the moment it would execute, against a fresh `scope.describe`.

use serde::Serialize;
use subc_protocol::scope::{ParentState, ScopeKind, ScopeStamp};
use subc_protocol::Principal;

/// A stored approval's (or a running bot write's) scope is gone: ended, replaced by a new session under
/// the same ref (a different epoch), or left out of the complete scope list
/// its owner registered with the daemon after the daemon started.
pub const SCOPE_ENDED: &str = "scope_ended";
/// A stored approval's (or a running bot write's) scope is live, but the authority the request was raised
/// under is not: `delegates` was turned off, the owner is no longer
/// authorized, or the scope now names a different agent.
pub const DELEGATION_WITHDRAWN: &str = "delegation_withdrawn";
/// A stored approval's scope could not be confirmed live before the approval
/// itself expired, or its owner is not a module the daemon will ever hear from.
/// A running bot write refuses with it as soon as its scope cannot be
/// confirmed, and sends nothing further.
pub const SCOPE_UNVERIFIABLE: &str = "scope_unverifiable";
/// Hold reason: the scope's owner has not re-synced since the daemon started.
pub const SCOPE_NOT_SYNCED: &str = "scope_not_synced";
/// Hold reason: the daemon did not answer `scope.describe`.
pub const SCOPE_UNAVAILABLE: &str = "scope_unavailable";
/// The outcome recorded on an approval that is kept, unsent, while its scope
/// cannot yet be confirmed.
pub const APPROVED_WAITING: &str = "approved_waiting";

/// The principal as Plexus writes it in its store: `direct`,
/// `reserved:<module_id>` or `unverified`.
pub fn principal_label(principal: &Principal) -> String {
    match principal {
        Principal::Direct => "direct".to_string(),
        Principal::Reserved { module_id } => format!("reserved:{module_id}"),
        Principal::Unverified => "unverified".to_string(),
    }
}

/// The inverse of [`principal_label`] for a scope owner. Only a registered
/// module can own a scope, so only `reserved:<module_id>` parses.
pub fn parse_scope_owner(label: &str) -> Option<Principal> {
    label
        .strip_prefix("reserved:")
        .filter(|module_id| !module_id.is_empty())
        .map(|module_id| Principal::Reserved {
            module_id: module_id.to_string(),
        })
}

/// The scope a route was bound under, as the daemon stamped it.
///
/// Every field is copied from the stamp; none is computed by Plexus. A scope
/// rebuilt from a stored approval has no `kind`, `parent` or `parent_state`,
/// because the approval keeps only what its re-check needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallScope {
    /// The owning module, as [`principal_label`] writes it.
    pub owner: String,
    #[serde(rename = "ref")]
    pub scope_ref: String,
    pub scope_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The parent link as `owner/ref@epoch`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    pub delegates: bool,
    pub owner_authorized: bool,
}

impl CallScope {
    /// Session identity excludes attribution and delegation, which are checked
    /// separately before authority is exercised.
    pub fn same_session(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.scope_ref == other.scope_ref
            && self.scope_epoch == other.scope_epoch
    }

    pub fn from_stamp(stamp: &ScopeStamp) -> Self {
        Self {
            owner: principal_label(&stamp.owner),
            scope_ref: stamp.scope_ref.clone(),
            scope_epoch: stamp.scope_epoch,
            kind: Some(
                match stamp.kind {
                    ScopeKind::Head => "head",
                    ScopeKind::Worker => "worker",
                    ScopeKind::Ephemeral => "ephemeral",
                }
                .to_string(),
            ),
            parent: stamp.parent.as_ref().map(|parent| {
                format!(
                    "{}/{}@{}",
                    principal_label(&parent.owner),
                    parent.scope_ref,
                    parent.scope_epoch
                )
            }),
            parent_state: stamp.parent_state.map(|state| {
                match state {
                    ParentState::Linked => "linked",
                    ParentState::Pending => "pending",
                    ParentState::Ended => "ended",
                }
                .to_string()
            }),
            agent_id: stamp.attributes.agent_id.clone(),
            flow_id: stamp.attributes.flow_id.clone(),
            delegates: stamp.attributes.delegates,
            owner_authorized: stamp.owner_authorized,
        }
    }

    /// The agent a call under this scope may act as. All three must hold:
    /// `delegates` is true, the scope names an agent, and the daemon says the
    /// owner is one allowed to set those attributes (`owner_authorized`).
    /// Otherwise the scope gives module-level authority only, and its
    /// `agent_id` is attribution.
    pub fn acting_agent(&self) -> Option<&str> {
        if self.delegates && self.owner_authorized {
            self.agent_id.as_deref()
        } else {
            None
        }
    }
}

/// Who a call is attributed to, and who (if anyone) it acts as.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallAgent {
    /// The agent written on the audit row and used as the rate key.
    pub attributed: Option<String>,
    /// The agent whose own grants the call must also hold. `None` means the
    /// call is judged on the carrying module's grants alone.
    pub acting_as: Option<String>,
}

/// Only Basal's agent-stamped flows use bot repository visibility. An agent
/// stamp on another module's route must not widen that module's read access.
pub fn basal_flow_read_agent<'a>(principal: &str, scope: Option<&'a CallScope>) -> Option<&'a str> {
    scope
        .filter(|scope| principal == "reserved:basal" && scope.flow_id.is_some())
        .and_then(|scope| scope.agent_id.as_deref())
}

/// Decide a call's agent only from its route's daemon scope stamp. Without a
/// stamp there is no agent; attribution alone never grants agent authority.
pub fn resolve_call_agent(scope: Option<&CallScope>) -> CallAgent {
    let Some(scope) = scope else {
        return CallAgent::default();
    };
    CallAgent {
        attributed: scope.agent_id.clone(),
        acting_as: scope.acting_agent().map(str::to_owned),
    }
}

/// `scope.describe`'s status, as Plexus reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeStatus {
    Live,
    /// Ended in this daemon incarnation, and still remembered.
    Ended,
    /// Neither live nor remembered as ended.
    NotLive,
}

/// One `scope.describe` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDescription {
    pub status: ScopeStatus,
    /// Whether the owner has synced since this daemon incarnation started.
    pub owner_synced: bool,
    /// Whether the owner is a module the daemon supervises.
    pub owner_configured: bool,
    /// The current stamp fields, present only when `status` is `Live`.
    pub live: Option<CallScope>,
}

/// The daemon did not answer `scope.describe`: the request failed, timed out,
/// or no daemon connection is available to ask on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeReadError(pub String);

/// Reads a scope's current state from the daemon.
///
/// Blocking: governance runs synchronously, and the one call site (just before
/// a stored approval is claimed for sending) must have its answer before it
/// decides whether to send.
pub trait ScopeReader: Send + Sync {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError>;
}

/// The scope an approval request was raised under, as stored with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalScope {
    pub request_id: String,
    pub owner: String,
    pub scope_ref: String,
    pub scope_epoch: u64,
    /// The scope's agent when the request was raised.
    pub agent_id: Option<String>,
    /// Whether the raising call acted as that agent (`delegates` and
    /// `owner_authorized` were both true). Only then must the scope still
    /// delegate, with the owner still authorized, when the approval executes.
    pub acted_as_agent: bool,
    /// When the approval itself lapses. A hold never outlasts it.
    pub expires_at: i64,
}

/// What to do with a stored approval, given a fresh read of its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalScopeVerdict {
    /// The same session is live with the same authority: execute.
    Run,
    /// The binding is dead; refuse by this name and send nothing.
    Refuse(&'static str),
    /// Not decidable yet; keep the approval, send nothing, and ask again later
    /// (until the approval expires). The code says why.
    Hold(&'static str),
}

/// The reader rule of the daemon's scope note (section 5), applied to a stored
/// approval at execution. A failed read is a hold: when the daemon cannot
/// answer, nothing is sent.
pub fn approval_scope_verdict(
    bound: &ApprovalScope,
    answer: Result<&ScopeDescription, &ScopeReadError>,
) -> ApprovalScopeVerdict {
    let described = match answer {
        Ok(described) => described,
        Err(_) => return ApprovalScopeVerdict::Hold(SCOPE_UNAVAILABLE),
    };
    match described.status {
        ScopeStatus::Live => {
            let live = match described.live.as_ref() {
                Some(live) => live,
                // A live answer without its stamp fields cannot be checked.
                None => return ApprovalScopeVerdict::Hold(SCOPE_UNAVAILABLE),
            };
            if live.scope_epoch != bound.scope_epoch {
                return ApprovalScopeVerdict::Refuse(SCOPE_ENDED);
            }
            if live.agent_id != bound.agent_id {
                return ApprovalScopeVerdict::Refuse(DELEGATION_WITHDRAWN);
            }
            if bound.acted_as_agent && live.acting_agent().is_none() {
                return ApprovalScopeVerdict::Refuse(DELEGATION_WITHDRAWN);
            }
            ApprovalScopeVerdict::Run
        }
        ScopeStatus::Ended => ApprovalScopeVerdict::Refuse(SCOPE_ENDED),
        // An owner's first sync of an incarnation is its full set, so a ref
        // missing from it has ended even if its tombstone was lost.
        ScopeStatus::NotLive if described.owner_synced => ApprovalScopeVerdict::Refuse(SCOPE_ENDED),
        ScopeStatus::NotLive if described.owner_configured => {
            ApprovalScopeVerdict::Hold(SCOPE_NOT_SYNCED)
        }
        // The owner is not a module the daemon runs, so it will never sync.
        ScopeStatus::NotLive => ApprovalScopeVerdict::Refuse(SCOPE_UNVERIFIABLE),
    }
}

/// Re-check the scope a running call was bound under, against a fresh
/// `scope.describe`, just before the call sends a write it has not sent yet.
///
/// The rule is the stored-approval rule ([`approval_scope_verdict`]) applied
/// to the route's stamp: the same session must still be live, naming the same
/// agent, and a stamp that let the call act as its agent must still delegate
/// under an authorized owner. `Err` names why the write must not be sent:
/// [`SCOPE_ENDED`] or [`DELEGATION_WITHDRAWN`] when the answer is definitive,
/// [`SCOPE_NOT_SYNCED`] when the configured owner has not re-synced yet, and
/// [`SCOPE_UNVERIFIABLE`] when the daemon cannot answer or the owner is not
/// configured. Carriers back off and retry `scope_not_synced`, but treat
/// `scope_unverifiable` as final. A call cannot wait the way a stored approval
/// does, so an undecidable answer refuses rather than holds.
pub fn recheck_call_scope(
    stamp: &CallScope,
    answer: Result<&ScopeDescription, &ScopeReadError>,
) -> Result<(), &'static str> {
    let bound = ApprovalScope {
        request_id: String::new(),
        owner: stamp.owner.clone(),
        scope_ref: stamp.scope_ref.clone(),
        scope_epoch: stamp.scope_epoch,
        agent_id: stamp.agent_id.clone(),
        acted_as_agent: stamp.acting_agent().is_some(),
        expires_at: i64::MAX,
    };
    match approval_scope_verdict(&bound, answer) {
        ApprovalScopeVerdict::Run => Ok(()),
        ApprovalScopeVerdict::Refuse(code) => Err(code),
        ApprovalScopeVerdict::Hold(SCOPE_NOT_SYNCED) => Err(SCOPE_NOT_SYNCED),
        ApprovalScopeVerdict::Hold(_) => Err(SCOPE_UNVERIFIABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(agent: Option<&str>, delegates: bool, owner_authorized: bool) -> CallScope {
        CallScope {
            owner: "reserved:prefrontal-core".into(),
            scope_ref: "head-1".into(),
            scope_epoch: 3,
            kind: Some("head".into()),
            parent: None,
            parent_state: None,
            agent_id: agent.map(str::to_owned),
            delegates,
            owner_authorized,
            flow_id: None,
        }
    }

    fn bound(acted_as_agent: bool) -> ApprovalScope {
        ApprovalScope {
            request_id: "req-1".into(),
            owner: "reserved:prefrontal-core".into(),
            scope_ref: "head-1".into(),
            scope_epoch: 3,
            agent_id: Some("agent-a".into()),
            acted_as_agent,
            expires_at: i64::MAX,
        }
    }

    fn live(scope: CallScope) -> ScopeDescription {
        ScopeDescription {
            status: ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(scope),
        }
    }

    fn not_live(owner_synced: bool, owner_configured: bool) -> ScopeDescription {
        ScopeDescription {
            status: ScopeStatus::NotLive,
            owner_synced,
            owner_configured,
            live: None,
        }
    }

    #[test]
    fn a_scope_acts_as_its_agent_only_when_it_delegates_under_an_authorized_owner() {
        assert_eq!(
            scope(Some("a"), true, true).acting_agent(),
            Some("a"),
            "delegating, authorized, named agent"
        );
        assert_eq!(scope(Some("a"), false, true).acting_agent(), None);
        assert_eq!(scope(Some("a"), true, false).acting_agent(), None);
        assert_eq!(scope(None, true, true).acting_agent(), None);
    }

    #[test]
    fn a_delegating_stamp_attributes_and_acts_as_its_agent() {
        let stamped = scope(Some("agent-a"), true, true);
        let agent = resolve_call_agent(Some(&stamped));
        assert_eq!(agent.attributed.as_deref(), Some("agent-a"));
        assert_eq!(agent.acting_as.as_deref(), Some("agent-a"));
    }

    #[test]
    fn without_a_stamp_there_is_no_agent() {
        assert_eq!(resolve_call_agent(None), CallAgent::default());
    }

    #[test]
    fn a_non_delegating_stamp_attributes_its_agent_without_acting_as_it() {
        let stamped = scope(Some("agent-a"), false, true);
        let agent = resolve_call_agent(Some(&stamped));
        assert_eq!(agent.attributed.as_deref(), Some("agent-a"));
        assert_eq!(agent.acting_as, None);
    }

    #[test]
    fn the_approval_reader_rule_separates_every_case() {
        let run = live(scope(Some("agent-a"), true, true));
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&run)),
            ApprovalScopeVerdict::Run
        );
        let mut new_session = scope(Some("agent-a"), true, true);
        new_session.scope_epoch = 4;
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&live(new_session))),
            ApprovalScopeVerdict::Refuse(SCOPE_ENDED)
        );
        let withdrawn = live(scope(Some("agent-a"), false, true));
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&withdrawn)),
            ApprovalScopeVerdict::Refuse(DELEGATION_WITHDRAWN)
        );
        assert_eq!(
            approval_scope_verdict(&bound(false), Ok(&withdrawn)),
            ApprovalScopeVerdict::Run,
            "a request raised without acting as the agent does not need delegation"
        );
        let unauthorized = live(scope(Some("agent-a"), true, false));
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&unauthorized)),
            ApprovalScopeVerdict::Refuse(DELEGATION_WITHDRAWN)
        );
        let other_agent = live(scope(Some("agent-b"), true, true));
        assert_eq!(
            approval_scope_verdict(&bound(false), Ok(&other_agent)),
            ApprovalScopeVerdict::Refuse(DELEGATION_WITHDRAWN)
        );
        let ended = ScopeDescription {
            status: ScopeStatus::Ended,
            owner_synced: true,
            owner_configured: true,
            live: None,
        };
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&ended)),
            ApprovalScopeVerdict::Refuse(SCOPE_ENDED)
        );
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&not_live(true, true))),
            ApprovalScopeVerdict::Refuse(SCOPE_ENDED)
        );
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&not_live(false, true))),
            ApprovalScopeVerdict::Hold(SCOPE_NOT_SYNCED)
        );
        assert_eq!(
            approval_scope_verdict(&bound(true), Ok(&not_live(false, false))),
            ApprovalScopeVerdict::Refuse(SCOPE_UNVERIFIABLE)
        );
        assert_eq!(
            approval_scope_verdict(&bound(true), Err(&ScopeReadError("down".into()))),
            ApprovalScopeVerdict::Hold(SCOPE_UNAVAILABLE)
        );
    }

    #[test]
    fn a_running_call_recheck_refuses_every_undecidable_answer() {
        let stamp = scope(Some("agent-a"), true, true);
        let run = live(scope(Some("agent-a"), true, true));
        assert_eq!(recheck_call_scope(&stamp, Ok(&run)), Ok(()));
        let withdrawn = live(scope(Some("agent-a"), false, true));
        assert_eq!(
            recheck_call_scope(&stamp, Ok(&withdrawn)),
            Err(DELEGATION_WITHDRAWN)
        );
        assert_eq!(
            recheck_call_scope(&scope(Some("agent-a"), false, true), Ok(&withdrawn)),
            Ok(()),
            "a stamp that never delegated does not need delegation later"
        );
        assert_eq!(
            recheck_call_scope(&stamp, Ok(&not_live(true, true))),
            Err(SCOPE_ENDED)
        );
        assert_eq!(
            recheck_call_scope(&stamp, Ok(&not_live(false, true))),
            Err(SCOPE_NOT_SYNCED)
        );
        assert_eq!(
            recheck_call_scope(&stamp, Ok(&not_live(false, false))),
            Err(SCOPE_UNVERIFIABLE)
        );
        assert_eq!(
            recheck_call_scope(&stamp, Err(&ScopeReadError("down".into()))),
            Err(SCOPE_UNVERIFIABLE)
        );
    }

    #[test]
    fn owner_labels_round_trip_and_only_modules_own_scopes() {
        let owner = Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        assert_eq!(parse_scope_owner(&principal_label(&owner)), Some(owner));
        assert_eq!(parse_scope_owner("direct"), None);
        assert_eq!(parse_scope_owner("reserved:"), None);
    }
}
