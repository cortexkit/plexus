//! Who acted on an issue or pull-request event, or why that could not be told.
//!
//! Actor enrichment reads the item's comments through a separate governed read
//! (and, when that window is empty, the item's timeline) and either names who
//! acted in the observation window or gives up. Webhooks can name the actor
//! directly from the sender's GitHub account. A
//! consumer deciding whether an event deserves a wake needs to know which of
//! those happened and, when enrichment gave up, whether asking again could
//! help. This module holds the closed set of reasons enrichment can give up
//! for, the class each reason belongs to, and the rule the event readers use to
//! put exactly one of "these logins" or "unknown, because" on the wire.

use serde::{Deserialize, Serialize};

/// Every reason actor enrichment can report an event's actors as unknown.
///
/// The stored and served form is [`ActorUnknownCode::as_str`]: a bare code,
/// never the diagnostic detail logged alongside it, which can carry vendor
/// messages or other arbitrary text.
///
/// Adding a variant forces a decision in [`ActorUnknownCode::class`], because
/// that `match` has no wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorUnknownCode {
    /// The watch has no bound actor source. Used only by v2 envelopes;
    /// legacy event responses still carry neither actor field for this case.
    ActorSourceUnbound,
    /// A later observation found no comment activity in its window, and the
    /// issue timeline found no entry after the previous observation either, so
    /// nothing names who caused the change.
    EmptyActorWindow,
    /// A comment was created or edited in the same vendor-reported second as
    /// the previous observation, so it cannot be placed on either side of it.
    SameSecondAmbiguity,
    /// The comment page came back full (or a review-thread count disagreed with
    /// the comments returned), so the page cannot prove it holds every actor.
    CommentPageSaturation,
    /// The issue timeline window holds a commit whose git author carries no
    /// GitHub login. A git name is free text, so it is never used as a login;
    /// the whole window is unknown rather than a partial login set.
    UnresolvedCommitAuthor,
    /// The issue timeline walk hit its page cap without reaching a short last
    /// page, so the newest entries (which GitHub serves last) were not read.
    TimelinePageSaturation,
    /// The governed actor read did not complete: the vendor failed, the call
    /// was not sent, its outcome is unknown, or it returned no body.
    TransportFailure,
    /// This poll cycle's enrichment call budget ran out before the event's reads.
    CallCapExhausted,
    /// Governance refused the actor read (authority, credential, or catalog
    /// state). Clears once the operator restores the enrichment connection.
    GovernedReadRefusal,
    /// The store could not say when this item was last observed.
    PreviousObservationLookupFailed,
    /// The store could not read the actor action's catalog row.
    CatalogLookupFailed,
    /// The actor data has a shape the extractor does not recognise (including
    /// a webhook without a usable sender login).
    UnrecognizedResponseShape,
    /// The actor read arguments could not be built from the subscription and
    /// event (missing owner, repo, or item number).
    ActorReadArgsUnbuildable,
    /// The actor source names a method the extractor has no reader for.
    ActorMethodUnrecognized,
    /// The actor source's action is not in the enrichment connection's catalog.
    CatalogActionMissing,
    /// The watched action has no reviewed poll shape saying what item it yields.
    ItemKindUnknown,
    /// The actor source's methods do not cover the watched item kind.
    ActorMethodsIncomplete,
    /// Never produced by enrichment. Served for event rows written before the
    /// reason was recorded, so every actor-sourced event still carries exactly
    /// one of a login list or a reason.
    Unrecorded,
}

/// What a consumer can do about an unknown actor set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorUnknownClass {
    /// The vendor data cannot answer the question; reading it again will not help.
    Undeterminable,
    /// A later read may succeed; the cause was capacity, authority, or transport.
    Transient,
    /// Enrichment met something it was not built for; worth an operator's look.
    Unexpected,
}

impl ActorUnknownCode {
    /// Test vectors for known stored values; production parsing is generated
    /// from the enum variants rather than depending on this test list.
    #[cfg(test)]
    pub const ALL: [ActorUnknownCode; 18] = [
        ActorUnknownCode::ActorSourceUnbound,
        ActorUnknownCode::EmptyActorWindow,
        ActorUnknownCode::SameSecondAmbiguity,
        ActorUnknownCode::CommentPageSaturation,
        ActorUnknownCode::UnresolvedCommitAuthor,
        ActorUnknownCode::TimelinePageSaturation,
        ActorUnknownCode::TransportFailure,
        ActorUnknownCode::CallCapExhausted,
        ActorUnknownCode::GovernedReadRefusal,
        ActorUnknownCode::PreviousObservationLookupFailed,
        ActorUnknownCode::CatalogLookupFailed,
        ActorUnknownCode::UnrecognizedResponseShape,
        ActorUnknownCode::ActorReadArgsUnbuildable,
        ActorUnknownCode::ActorMethodUnrecognized,
        ActorUnknownCode::CatalogActionMissing,
        ActorUnknownCode::ItemKindUnknown,
        ActorUnknownCode::ActorMethodsIncomplete,
        ActorUnknownCode::Unrecorded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ActorUnknownCode::ActorSourceUnbound => "actor_source_unbound",
            ActorUnknownCode::EmptyActorWindow => "empty_actor_window",
            ActorUnknownCode::SameSecondAmbiguity => "same_second_ambiguity",
            ActorUnknownCode::CommentPageSaturation => "comment_page_saturation",
            ActorUnknownCode::UnresolvedCommitAuthor => "unresolved_commit_author",
            ActorUnknownCode::TimelinePageSaturation => "timeline_page_saturation",
            ActorUnknownCode::TransportFailure => "transport_failure",
            ActorUnknownCode::CallCapExhausted => "call_cap_exhausted",
            ActorUnknownCode::GovernedReadRefusal => "governed_read_refusal",
            ActorUnknownCode::PreviousObservationLookupFailed => {
                "previous_observation_lookup_failed"
            }
            ActorUnknownCode::CatalogLookupFailed => "catalog_lookup_failed",
            ActorUnknownCode::UnrecognizedResponseShape => "unrecognized_response_shape",
            ActorUnknownCode::ActorReadArgsUnbuildable => "actor_read_args_unbuildable",
            ActorUnknownCode::ActorMethodUnrecognized => "actor_method_unrecognized",
            ActorUnknownCode::CatalogActionMissing => "catalog_action_missing",
            ActorUnknownCode::ItemKindUnknown => "item_kind_unknown",
            ActorUnknownCode::ActorMethodsIncomplete => "actor_methods_incomplete",
            ActorUnknownCode::Unrecorded => "unrecorded",
        }
    }

    /// The code a stored value names, or `None` for a value this binary does
    /// not know (for example one written by a newer binary before a downgrade).
    pub fn from_stored(value: &str) -> Option<Self> {
        Self::deserialize(serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value))
            .ok()
    }

    pub fn class(self) -> ActorUnknownClass {
        // Deliberately exhaustive with no wildcard: a new code must be placed.
        match self {
            ActorUnknownCode::EmptyActorWindow
            | ActorUnknownCode::SameSecondAmbiguity
            | ActorUnknownCode::CommentPageSaturation
            | ActorUnknownCode::UnresolvedCommitAuthor
            | ActorUnknownCode::TimelinePageSaturation => ActorUnknownClass::Undeterminable,
            ActorUnknownCode::TransportFailure
            | ActorUnknownCode::CallCapExhausted
            | ActorUnknownCode::GovernedReadRefusal
            | ActorUnknownCode::PreviousObservationLookupFailed
            | ActorUnknownCode::CatalogLookupFailed => ActorUnknownClass::Transient,
            ActorUnknownCode::UnrecognizedResponseShape
            | ActorUnknownCode::ActorReadArgsUnbuildable
            | ActorUnknownCode::ActorMethodUnrecognized
            | ActorUnknownCode::CatalogActionMissing
            | ActorUnknownCode::ItemKindUnknown
            | ActorUnknownCode::ActorMethodsIncomplete
            | ActorUnknownCode::ActorSourceUnbound
            | ActorUnknownCode::Unrecorded => ActorUnknownClass::Unexpected,
        }
    }
}

/// The wire form of an unknown actor set: `{"reason": "<code>", "class": "<class>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActorUnknown {
    pub reason: String,
    pub class: ActorUnknownClass,
}

impl ActorUnknown {
    pub fn from_code(code: ActorUnknownCode) -> Self {
        ActorUnknown {
            reason: code.as_str().to_string(),
            class: code.class(),
        }
    }

    /// Rebuild the wire form from a stored reason. A value this binary does not
    /// recognise is served as stored and classed `unexpected`, rather than
    /// being dropped, which would break the one-of-two rule for that event.
    fn from_stored(value: &str) -> Self {
        match ActorUnknownCode::from_stored(value) {
            Some(code) => ActorUnknown::from_code(code),
            None => ActorUnknown {
                reason: value.to_string(),
                class: ActorUnknownClass::Unexpected,
            },
        }
    }
}

/// What a poll cycle or webhook learned about an event's actors, as it is
/// written to the event row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorAttribution {
    /// No actor enrichment applies: the subscription has no actor source (for
    /// example a release watch), or the row did not come from a vendor poll.
    NotEnriched,
    /// GitHub account logins from a governed read or webhook sender. An empty
    /// list is a known-empty first poll window.
    Known(Vec<String>),
    /// Enrichment gave up. Only the closed code is stored and served;
    /// pollers log their private diagnostic before constructing attribution.
    Unknown { code: ActorUnknownCode },
}

/// Decide which actor field an event row serves.
///
/// Returns at most one of the two. A row with a login list serves it; a row
/// with a stored reason serves that reason. A row with neither serves
/// `unrecorded` only when it is an event (not a coverage gap) whose
/// subscription has an actor source, because those rows predate the stored
/// reason; every other row carries neither field, as before.
pub(crate) fn served_actor_fields(
    actor_logins: Option<Vec<String>>,
    stored_reason: Option<&str>,
    is_event: bool,
    subscription_has_actor_source: bool,
) -> (Option<Vec<String>>, Option<ActorUnknown>) {
    match (actor_logins, stored_reason) {
        (Some(logins), _) => (Some(logins), None),
        (None, Some(reason)) => (None, Some(ActorUnknown::from_stored(reason))),
        (None, None) if is_event && subscription_has_actor_source => (
            None,
            Some(ActorUnknown::from_code(ActorUnknownCode::Unrecorded)),
        ),
        (None, None) => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_reason_vectors_remain_known_and_unknown_is_refused() {
        for (stored, expected) in [
            ("empty_actor_window", ActorUnknownCode::EmptyActorWindow),
            (
                "unresolved_commit_author",
                ActorUnknownCode::UnresolvedCommitAuthor,
            ),
            (
                "same_second_ambiguity",
                ActorUnknownCode::SameSecondAmbiguity,
            ),
        ] {
            assert_eq!(
                ActorUnknownCode::from_stored(stored),
                Some(expected),
                "persisted actor reason must parse: {stored}"
            );
        }
        assert_eq!(
            ActorUnknownCode::from_stored("unknown_future_actor_reason"),
            None,
            "unrecognized actor reasons must not become a known code"
        );
    }

    #[test]
    fn every_code_round_trips_through_its_stored_form() {
        for code in ActorUnknownCode::ALL {
            assert_eq!(ActorUnknownCode::from_stored(code.as_str()), Some(code));
        }
        assert_eq!(ActorUnknownCode::from_stored("unknown_future_reason"), None);
    }

    #[test]
    fn classes_serialize_lowercase() {
        assert_eq!(
            serde_json::to_value(ActorUnknown::from_code(
                ActorUnknownCode::GovernedReadRefusal
            ))
            .unwrap(),
            serde_json::json!({"reason": "governed_read_refusal", "class": "transient"})
        );
    }

    #[test]
    fn an_unknown_stored_reason_is_served_as_unexpected() {
        assert_eq!(
            served_actor_fields(None, Some("from_a_newer_binary"), true, true),
            (
                None,
                Some(ActorUnknown {
                    reason: "from_a_newer_binary".to_string(),
                    class: ActorUnknownClass::Unexpected,
                })
            )
        );
    }

    #[test]
    fn rows_without_an_actor_source_or_that_are_gaps_carry_neither() {
        assert_eq!(served_actor_fields(None, None, true, false), (None, None));
        assert_eq!(served_actor_fields(None, None, false, true), (None, None));
    }
}
