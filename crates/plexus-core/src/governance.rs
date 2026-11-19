//! Complete-mediation governance and RESERVE → REVALIDATE → DISPATCH.
//!
//! This module is deliberately transport-agnostic. It reads only redacted
//! projections from the store, resolves a credential through the trait seam,
//! and hands the short-lived payload to a transport implementation.

mod dispatch;
mod gates;
mod held_approvals;
mod reservation;

use reservation::{approval_scope_of, reservation_record};

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::consent_card::{
    execution_from_dispatch, ConsentCards, ParkedApproval, APPROVED_NOT_EXECUTED,
    CONSENT_CARD_DECIDER_PREFIX,
};
use crate::credentials::{
    CredentialError, CredentialSource, PermanentCredentialError, ResolvedCredential,
    TransientCredentialError,
};
use crate::decision_plane::{
    compute_grant_hash, reversibility_class_for_risk, verify_grant_hash, DecisionEnvelope,
    DecisionPlane, DecisionPlaneError, GrantHashInput, OutcomeReport, OutcomeTerminal, Verdict,
};
use crate::fingerprint;
use crate::jcs;
use crate::manifest::{Risk, Tier};
use crate::scope::{
    approval_scope_verdict, ApprovalScope, ApprovalScopeVerdict, CallScope, ScopeReadError,
    ScopeReader, SCOPE_UNVERIFIABLE,
};
use crate::storage::{
    ActionRequestRecord, AuditRecord, CatalogAction, ConnectionRecord, EnsuredRequest, GrantRecord,
    PinnedGrant, PlexusStore, RelayOrigin, ReservationRecord, SnapshotGenerations,
    REQUEST_CANCELLED,
};
use crate::transport::{
    Retryability, TransmissionState, Transport, TransportRequest, TransportResponse,
};

/// Bounded retries when the decision plane rejects an outcome report.
/// How many times a decision-outcome report is attempted before the failure is
/// audited instead. Exported so a test can derive its fixture from the real
/// value rather than hardcoding 3 — a test that hardcodes the count silently
/// stops reaching the exhausted path when the constant changes.
pub const OUTCOME_REPORT_ATTEMPTS: usize = 3;

const APPROVAL_TTL_MS: i64 = 300_000;
const RESERVATION_TTL_MS: i64 = 60_000;
const PROJECTION_PRINCIPAL: &str = "reserved:basal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    S1,
    S2,
    S3,
    S4,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::S3 => "S3",
            Self::S4 => "S4",
        }
    }
}

/// Receipt-claim metadata stays separate from catalog arguments so internal
/// lease details cannot become part of a GitHub request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptClaim {
    pub agent_id: String,
    pub request_nonce: String,
    pub claim_owner: String,
    pub effect_index: usize,
}

/// Origin is internal authority, never decoded from caller arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOrigin {
    Ordinary,
    Facade,
}

/// Identifies the agent's approval associated with a facade operation. The
/// original facade request, not each mapped catalog call, owns its snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptApproval {
    pub action_request_id: String,
    pub agent_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub request_id: String,
    pub actor: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub args: Value,
    /// Agent attribution from a daemon stamp or a trusted repository binding.
    /// It does not replace the module principal used by policy and grant gates.
    pub attributed_agent_id: Option<String>,
    pub bound_agent_handle: Option<String>,
    pub expected_schema_hash: Option<String>,
    pub approved_request_id: Option<String>,
    /// Which kind of authority this call is claiming. An interactive call
    /// claims `invoke`; a scheduled poll claims `poll`. The gates only ever
    /// consider grants of the claimed kind, which is the only place the
    /// distinction between "you may read when you ask" and "a timer may read
    /// every N seconds" can live — no gate reads `actor`, so attribution
    /// alone cannot express it.
    authority_kind: String,
    /// The daemon scope the call's route was bound under. Written on the
    /// call's audit rows and on any approval request it raises.
    scope: Option<CallScope>,
    /// Whether the scope may make an ordinary invoke act as its agent. False
    /// for calls such as `web_search` where the scope's agent is attribution
    /// only.
    scope_grants_agent: bool,
    /// A tool call that arrives over a route can file an approval card only
    /// when the daemon has stamped the route with a head or worker session,
    /// because the card is filed under that session. Authorization called from
    /// inside plexus can hold a cardless request only when consent cards are
    /// not configured; a composed daemon refuses unscoped approval requests.
    requires_session_consent: bool,
    supports_per_call_approval: bool,
    /// The key the carrier (`principal`) gave this call. Stored on the
    /// approval request the call raises, so the carrier or its scope's owner
    /// can withdraw the call by it.
    call_key: Option<String>,
    /// The call from which this call was relayed, as the relay stated it.
    /// Written on the call's audit rows and on any approval request it raises, for
    /// attribution only: no gate, key or lookup reads it.
    relay_origin: Option<RelayOrigin>,
    /// The agent a worker scope says it is working for (the stamp's
    /// `on_behalf_of_agent`). Written on the call's audit rows, for
    /// attribution only: no gate, grant or credential lookup reads it, and it
    /// never becomes `attributed_agent_id` or an acting agent.
    on_behalf_of_agent: Option<String>,
    origin: RequestOrigin,
    receipt_approval: Option<ReceiptApproval>,
    receipt: Option<ReceiptClaim>,
    ownership_proof: Option<crate::github::facade::effects::OwnershipProof>,
    /// The bound repository a crate-internal GitHub read already resolved from
    /// the binding table, used by the repository resolver in place of a
    /// `repository` argument. It lives here so the routing field is not sent
    /// to the vendor, which does not declare it. No caller argument or wire
    /// field can set it.
    resolved_repository: Option<String>,
    resolved_github_search_repositories: Option<Vec<String>>,
    diagnostic_tool: String,
    federated_caller: Option<crate::federated::FederatedCaller>,
    federated_row_id: Option<String>,
    federated_card_ref: Option<String>,
    pub(crate) federated_held_reply: bool,
    pub(crate) federated_deadline: Option<std::time::Instant>,
    pub(crate) federated_search_use: Option<crate::web_search::federated::SearchUse>,
    federated_answer: Option<(
        crate::federated::card::Record,
        crate::storage::federated_store::commit::Answer,
    )>,
    federated_search: Option<crate::federated::card::CallBinding>,
}

/// Authority claimed by an interactive call an agent or operator made.
pub const AUTHORITY_INVOKE: &str = "invoke";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestStatus {
    Pending,
    Approved,
    Consumed,
    Denied,
    Expired,
    Cancelled,
    Unknown,
}

impl RequestStatus {
    fn of(status: &str) -> Self {
        match status {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "consumed" => Self::Consumed,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            REQUEST_CANCELLED => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PolicyEffect {
    Allow,
    AskFirst,
    Block,
}

impl PolicyEffect {
    fn of(effect: &str) -> Self {
        match effect {
            "allow" => Self::Allow,
            "ask_first" => Self::AskFirst,
            _ => Self::Block,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AskFirst => "ask_first",
            Self::Block => "block",
        }
    }
}

/// Web search and code search can't wait for a per-call approval, so an
/// `ask_first` policy on them is refused rather than filing a card. The search
/// tools check this before they start, and authorization checks it again with
/// this same predicate, so a policy changed between the two checks still can't
/// file a card that no tool call would ever wait for.
pub(crate) fn per_call_approval_unsupported(effect: &str, supports_per_call: bool) -> bool {
    effect == "ask_first" && !supports_per_call
}

/// Authority claimed by a scheduled poll that nobody asked for. Kept distinct
/// from `invoke` because the authority chain gates a call's SHAPE (who, which
/// connection, which action, what risk) and says nothing about its frequency or
/// lifetime — which is exactly the dimension a timer adds. Without a separate
/// kind, one interactive consent silently authorizes unbounded unattended
/// invocations for unbounded time.
pub const AUTHORITY_POLL: &str = "poll";

/// Authority to CONSUME the events another principal's subscriptions already
/// collected: read them, and acknowledge them.
///
/// Every other read in this store is scoped to the principal that owns the row,
/// which is correct and is also why a consumer could not exist. The operator
/// ceremony runs as `Principal::Direct`, so subscriptions are owned by `direct`,
/// while a supervised consumer authenticates as `Principal::Reserved` and sees a
/// correctly empty lane. Without this kind the only way for a consumer to see
/// anything is to run its own parallel ceremony -- its own connection, its own
/// credential binding, its own duplicate subscriptions -- which doubles the
/// polling of the same vendor to deliver the same rows twice.
///
/// STRICTLY LESS AUTHORITY THAN THE KINDS BESIDE IT. It cannot poll, invoke,
/// subscribe, or reach a credential; the vendor call already happened and was
/// already paid for under someone else's authority. What it grants is sight of
/// the result.
///
/// IT INCLUDES ACK, and the naming says so, because a consumer that cannot
/// acknowledge is not a consumer. `list_events` returns unacked rows only, so a
/// read-only grantee would re-read the same rows on every pass forever and would
/// have to rebuild a cursor that this store already keeps. The cost is real and
/// worth stating: ack clears the payload, so a grantee draining a lane removes
/// those rows from the OWNER's view too. That is the correct reading of the
/// grant -- minting it designates who drains the lane -- but it means the grant
/// is not a passive observer's capability, and two independent consumers of one
/// subscription would need per-consumer cursors rather than a second grant.
///
/// Kept as its OWN kind rather than folded into `poll` for the same reason poll
/// is not folded into invoke: a distinct kind cannot be satisfied by authority
/// minted for a different purpose. An operator granting a background poll is not
/// thereby exporting its results to a third party.
pub const AUTHORITY_EVENTS_CONSUME: &str = "events_consume";

impl AuthorizationRequest {
    fn routing_context(&self) -> Value {
        serde_json::json!({"repository": self.resolved_repository, "tool": self.diagnostic_tool, "supports_per_call_approval": self.supports_per_call_approval})
    }
    pub fn new(
        principal: impl Into<String>,
        connection_id: impl Into<String>,
        action: impl Into<String>,
        args: Value,
    ) -> Self {
        let principal = principal.into();
        Self {
            request_id: new_request_id(),
            actor: principal.clone(),
            principal,
            connection_id: connection_id.into(),
            action: action.into(),
            args,
            attributed_agent_id: None,
            bound_agent_handle: None,
            expected_schema_hash: None,
            approved_request_id: None,
            authority_kind: AUTHORITY_INVOKE.to_string(),
            scope: None,
            scope_grants_agent: false,
            requires_session_consent: false,
            supports_per_call_approval: true,
            call_key: None,
            relay_origin: None,
            on_behalf_of_agent: None,
            origin: RequestOrigin::Ordinary,
            receipt_approval: None,
            receipt: None,
            ownership_proof: None,
            resolved_repository: None,
            resolved_github_search_repositories: None,
            diagnostic_tool: "invoke".into(),
            federated_caller: None,
            federated_search: None,
            federated_row_id: None,
            federated_card_ref: None,
            federated_held_reply: false,
            federated_deadline: None,
            federated_search_use: None,
            federated_answer: None,
        }
    }

    /// Claim scheduled-poll authority instead of interactive invoke authority.
    /// This low-level transition is private so callers must use the checked
    /// poll constructor on [`GovernanceEngine`].
    fn for_poll(mut self, subscription_id: &str) -> Self {
        self.authority_kind = AUTHORITY_POLL.to_string();
        self.actor = format!("trigger:{subscription_id}");
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    pub(crate) fn with_diagnostic_tool(mut self, tool: &str) -> Self {
        self.diagnostic_tool = tool.into();
        self
    }

    pub fn with_schema_hash(mut self, schema_hash: impl Into<String>) -> Self {
        self.expected_schema_hash = Some(schema_hash.into());
        self
    }

    pub(crate) fn without_per_call_approval(mut self) -> Self {
        self.supports_per_call_approval = false;
        self
    }

    /// Attribute a trusted, resolved bot binding to its agent and handle.
    pub fn with_bound_agent(
        mut self,
        agent_id: impl Into<String>,
        handle: impl Into<String>,
    ) -> Self {
        self.attributed_agent_id = Some(agent_id.into());
        self.bound_agent_handle = Some(handle.into());
        self
    }

    pub fn approved_from(mut self, request_id: impl Into<String>) -> Self {
        self.approved_request_id = Some(request_id.into());
        self
    }

    /// Attribute the call to the agent named by the route's daemon scope stamp.
    pub fn with_attributed_agent(mut self, agent_id: impl Into<String>) -> Self {
        self.attributed_agent_id = Some(agent_id.into());
        self.bound_agent_handle = None;
        self
    }

    /// The call was made on a route bound under `scope`. When the scope
    /// delegates to its agent under an authorized owner
    /// ([`CallScope::acting_agent`]), an ordinary invoke is judged as that
    /// agent: it needs the agent's own grant on top of the module grant.
    pub fn with_scope(mut self, scope: CallScope) -> Self {
        self.scope = Some(scope);
        self.scope_grants_agent = true;
        self
    }

    /// The call was made under `scope`, but the scope's agent is attribution
    /// only: no agent grant is ever required. The scope is still written on
    /// the audit rows.
    pub fn with_scope_attribution_only(mut self, scope: CallScope) -> Self {
        self.scope = Some(scope);
        self.scope_grants_agent = false;
        self
    }

    pub fn scope(&self) -> Option<&CallScope> {
        self.scope.as_ref()
    }

    /// The carrier gave this call `call_key`. If the call is held for
    /// approval, the request is stored under `(carrier, call_key)` and can be
    /// withdrawn by that key. A call without a key still runs as before, but
    /// cannot be withdrawn.
    pub fn with_call_key(mut self, call_key: impl Into<String>) -> Self {
        self.call_key = Some(call_key.into());
        self
    }

    /// The call was relayed from `relay_origin`. It is recorded on the audit
    /// rows and on any approval request the call raises, and changes nothing
    /// else: the request is still keyed by [`Self::with_call_key`].
    pub fn with_relay_origin(mut self, relay_origin: RelayOrigin) -> Self {
        self.relay_origin = Some(relay_origin);
        self
    }

    /// Record the agent a worker scope works for on this call's audit rows.
    /// Attribution only: it grants nothing and is never the acting agent.
    pub fn with_on_behalf_of_agent(mut self, agent: impl Into<String>) -> Self {
        self.on_behalf_of_agent = Some(agent.into());
        self
    }

    /// The agent an ordinary invoke must also hold a grant for, if any.
    fn acting_agent(&self) -> Option<&str> {
        if self.federated_caller.is_some()
            || self.origin != RequestOrigin::Ordinary
            || self.authority_kind != AUTHORITY_INVOKE
            || !self.scope_grants_agent
        {
            return None;
        }
        self.scope.as_ref().and_then(CallScope::acting_agent)
    }

    /// Attach facts from an admitted federated bind, never from tool arguments.
    pub fn with_federated_caller(mut self, caller: crate::federated::FederatedCaller) -> Self {
        self.federated_caller = Some(caller);
        self.attributed_agent_id = None;
        self.bound_agent_handle = None;
        self
    }

    /// Record whether the federated route declared that it can hold a reply.
    /// This is not a tool argument or an authority grant.
    pub fn with_federated_held_reply(mut self, declared: bool) -> Self {
        self.federated_held_reply = declared;
        self
    }

    pub(crate) fn with_federated_search(
        mut self,
        binding: crate::federated::card::CallBinding,
    ) -> Self {
        self.federated_search = Some(binding);
        self
    }

    pub fn origin(&self) -> RequestOrigin {
        self.origin
    }

    pub(crate) fn ownership_proof(
        &self,
    ) -> Option<&crate::github::facade::effects::OwnershipProof> {
        self.ownership_proof.as_ref()
    }

    /// Route by a repository the caller already resolved from the binding
    /// table instead of a `repository` argument. Crate-internal: only plexus's
    /// own GitHub read path may state the route out of band.
    pub(crate) fn with_resolved_repository(mut self, repository: impl Into<String>) -> Self {
        self.resolved_repository = Some(repository.into());
        self
    }

    pub(crate) fn resolved_repository(&self) -> Option<&str> {
        self.resolved_repository.as_deref()
    }

    pub(crate) fn with_resolved_github_search(mut self, repositories: Vec<String>) -> Self {
        self.resolved_github_search_repositories = Some(repositories);
        self
    }

    pub(crate) fn resolved_github_search(&self) -> bool {
        self.resolved_github_search_repositories().is_some()
    }

    pub(crate) fn resolved_github_search_repositories(&self) -> Option<&[String]> {
        self.resolved_github_search_repositories.as_deref()
    }
}

/// Only the facade router can mint this internal origin; ordinary invoke
/// arguments have no path to it.
pub(crate) mod facade_origin {
    use super::{AuthorizationRequest, ReceiptApproval, ReceiptClaim, RequestOrigin};

    /// Trusted crate-internal facade routing calls this after scope checks;
    /// no request argument or wire field can construct this origin.
    pub(crate) fn request(
        mut request: AuthorizationRequest,
        approval: Option<ReceiptApproval>,
    ) -> AuthorizationRequest {
        request.origin = RequestOrigin::Facade;
        request.receipt_approval = approval;
        request
    }

    /// Only the verified facade can attach an effect's durable claim. The
    /// catalog args remain untouched and are safe to hand to the transport.
    pub(crate) fn receipt_request(
        mut request: AuthorizationRequest,
        approval: Option<ReceiptApproval>,
        claim: ReceiptClaim,
        proof: crate::github::facade::effects::OwnershipProof,
    ) -> AuthorizationRequest {
        request.origin = RequestOrigin::Facade;
        request.receipt_approval = approval;
        request.receipt = Some(claim);
        request.ownership_proof = Some(proof);
        request
    }
}

/// Refusal returned before a poll request can claim scheduled authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollAuthorizationRefusal {
    ActionNotFound,
    ActionRiskNotRead,
    ActionQuarantined,
    ActionDisabled,
    ActionUnavailable(String),
    StoreFailure,
}

/// The call carried by [`Denial::NeedsDecisionPlane`]. No decision plane is
/// configured in production, so every S3/S4 call is refused with this
/// envelope; [`DecisionEnvelope`] is what a configured plane would be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPlaneEnvelope {
    pub request_id: String,
    pub connection_id: String,
    pub action: String,
    pub args_hash: String,
    pub schema_hash: String,
    pub severity: Severity,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionDenial {
    NotFound,
    Disabled,
    Revoked,
    Pending,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogDenial {
    NotFound,
    Quarantined,
    Disabled,
    SchemaMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDenial {
    Missing,
    Expired,
    RiskCeiling,
    ActionSelector,
    ConnectionAdminRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDenial {
    Blocked,
    AskFirst,
    ApprovalMissing,
    ApprovalExpired,
    ApprovalShapeMismatch,
    /// The approval already authorized a dispatch. An ordinary approval is
    /// single-use: it is consumed when its reservation is claimed for sending,
    /// so a retry with the same approval must not send the call again.
    ApprovalConsumed,
    /// An operator tried to approve a request that was already approved or
    /// denied. Distinct from an expired request, which was never decided.
    ApprovalAlreadyDecided,
    /// The request was withdrawn by its carrier or its scope's owner, so it
    /// can never be approved or sent.
    ApprovalWithdrawn,
    /// The carrier already used this call's `call_key` for a request that
    /// cannot take this call: another call, or this call after its request
    /// was decided, withdrawn, sent or expired. A key names one call, so no
    /// second request is raised under it.
    CallKeyReused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeverityDenial {
    DecisionDenied { reason: String },
    GrantHashMismatch,
    DecisionPlaneFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceDenial {
    MissingRequiredFilter(String),
    ValueNotAllowed(String),
    WriteFiltersAbsent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialDenial {
    Missing,
    StoreUnavailable,
    Permanent(PermanentCredentialError),
    AuthRequired,
    Transient(TransientCredentialError),
}

impl CredentialDenial {
    fn reason_code(&self) -> &'static str {
        match self {
            Self::Missing => "credential_missing",
            Self::StoreUnavailable => "credential_store_unavailable",
            Self::Permanent(_) => "credential_permanent",
            Self::AuthRequired => "credential_auth_required",
            Self::Transient(reason) => transient_credential_code(*reason),
        }
    }
}

/// Name WHICH transient credential failure occurred, rather than collapsing
/// them into one code.
///
/// All three used to render as `credential_transient`, and they are diagnosed
/// in opposite directions. A vault that is briefly locked is the vault's
/// problem and clears itself. A route that could not be carried is OUR
/// problem: the commonest cause is this module dialling a credential-module id
/// that no longer answers, which is what a rename of the vault module leaves
/// behind in any caller that has not moved yet.
///
/// The failure this distinction exists for is a routing fault wearing the
/// costume of a policy decision. Credential resolution REFUSES rather than
/// degrades, so a stale route target does not produce a slow connector — it
/// produces a denial that reads as though authority was evaluated and
/// withheld. An operator seeing `credential_route_failed` knows to check the
/// route target; one seeing `credential_transient` has no reason to suspect
/// configuration at all.
fn transient_credential_code(reason: TransientCredentialError) -> &'static str {
    match reason {
        TransientCredentialError::RefreshFailed => "credential_route_failed",
        TransientCredentialError::VaultLocked => "credential_vault_locked",
        TransientCredentialError::ContextOverflow => "credential_context_overflow",
    }
}

/// Authorization denials are typed and carry no vendor or credential text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverDenial {
    StoreFailure,
    RepositoryUnbound,
    RequestFieldForbidden { field: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    ConnectorHomeNotHeld {
        state: Value,
    },
    Connection(ConnectionDenial),
    Catalog(CatalogDenial),
    Resolver(ResolverDenial),
    BotActionRequiresFacade,
    OwnershipProofMissing,
    CredentialMaterialForbidden,
    ConsentUnavailable {
        action: String,
    },
    FederatedConsentDenied,
    FederatedPairingEnded,
    FederatedLivenessUnavailable,
    AccessPending {
        elicitation_id: String,
        service: String,
        action: String,
    },
    ConsentRefused {
        code: &'static str,
        elicitation_id: String,
    },
    Grant(GrantDenial),
    GrantRefusal(crate::grant_refusal::GrantRefusal),
    Policy(PolicyDenial),
    Severity(Box<SeverityDenial>),
    NeedsDecisionPlane(Box<DecisionPlaneEnvelope>),
    ResourceFilter(ResourceDenial),
    Credential(CredentialDenial),
    ActionRequestCreated {
        request_id: String,
    },
    /// A top-level argument the action's pinned schema does not declare. The
    /// field is the argument's name, never its value.
    ArgumentUndeclared {
        field: String,
    },
    RecipientArgumentInvalid {
        pointer: String,
    },
    ApprovalPreviewTooLong {
        action: String,
        length: usize,
        limit: usize,
    },
    StoreFailure,
}

pub struct AuthorityEvaluation {
    pub grant: Option<GrantRecord>,
    pub agent_grant_pin: Option<PinnedGrant>,
    pub policy: Option<crate::storage::PolicyRecord>,
    pub policy_inputs: Option<PolicyInputs>,
    pub policy_effect: &'static str,
}

fn grant_denial(
    request: &AuthorizationRequest,
    layer: crate::grant_refusal::Layer,
    reason: GrantDenial,
) -> Denial {
    use crate::grant_refusal::{Cause, GrantRefusal, GrantTarget, Layer};
    let flow = request
        .scope
        .as_ref()
        .is_some_and(|scope| scope.flow_id.is_some());
    let layered_missing = reason == GrantDenial::Missing && request.acting_agent().is_some();
    if !flow && !layered_missing {
        return Denial::Grant(reason);
    }
    let cause = match reason {
        GrantDenial::Missing => Cause::Missing,
        GrantDenial::Expired => Cause::Expired,
        GrantDenial::ActionSelector => Cause::ActionSelector,
        GrantDenial::RiskCeiling => Cause::RiskCeiling,
        other => return Denial::Grant(other),
    };
    let grantee = match layer {
        Layer::Module => &request.principal,
        Layer::Agent => request
            .acting_agent()
            .or(request.attributed_agent_id.as_deref())
            .unwrap_or(""),
    };
    let tool = if request.origin == RequestOrigin::Facade {
        "github"
    } else {
        request.diagnostic_tool.as_str()
    };
    Denial::GrantRefusal(GrantRefusal::new(
        GrantTarget::new(
            layer,
            grantee,
            tool,
            Some(&request.connection_id),
            &request.action,
        ),
        cause,
    ))
}

impl Denial {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::ConnectorHomeNotHeld { .. } => "connector_home_not_held",
            Self::BotActionRequiresFacade => "bot_action_requires_facade",
            Self::OwnershipProofMissing => "ownership_proof_missing",
            Self::CredentialMaterialForbidden => "credential_material_forbidden",
            Self::ConsentUnavailable { .. } => "consent_unavailable",
            Self::FederatedConsentDenied => "consent_denied",
            Self::FederatedPairingEnded => "federated_pairing_ended",
            Self::FederatedLivenessUnavailable => "federated_liveness_unavailable",
            Self::AccessPending { .. } => "access_pending",
            Self::ConsentRefused { code, .. } => code,
            Self::RecipientArgumentInvalid { .. } => "recipient_argument_invalid",
            Self::ApprovalPreviewTooLong { .. } => "approval_preview_too_long",
            Self::Resolver(reason) => match reason {
                ResolverDenial::StoreFailure => "store_failure",
                ResolverDenial::RepositoryUnbound => "repository_unbound",
                ResolverDenial::RequestFieldForbidden { .. } => "request_field_forbidden",
            },
            Self::Connection(reason) => match reason {
                ConnectionDenial::NotFound => "connection_not_found",
                ConnectionDenial::Disabled => "connection_disabled",
                ConnectionDenial::Revoked => "connection_revoked",
                ConnectionDenial::Pending => "connection_pending",
                ConnectionDenial::Unhealthy => "connection_unhealthy",
            },
            Self::Catalog(reason) => match reason {
                CatalogDenial::NotFound => "catalog_action_not_found",
                CatalogDenial::Quarantined => "catalog_action_quarantined",
                CatalogDenial::Disabled => "catalog_action_disabled",
                CatalogDenial::SchemaMismatch => "catalog_schema_mismatch",
            },
            Self::GrantRefusal(refusal) => refusal.code(),
            Self::Grant(reason) => match reason {
                GrantDenial::Missing => "grant_missing",
                GrantDenial::Expired => "grant_expired",
                GrantDenial::RiskCeiling => "grant_risk_ceiling",
                GrantDenial::ActionSelector => "grant_action_selector",
                GrantDenial::ConnectionAdminRequired => "connection_admin_required",
            },
            Self::Policy(reason) => match reason {
                PolicyDenial::Blocked => "policy_blocked",
                PolicyDenial::AskFirst => "policy_ask_first",
                PolicyDenial::ApprovalMissing => "approval_missing",
                PolicyDenial::ApprovalExpired => "approval_expired",
                PolicyDenial::ApprovalShapeMismatch => "approval_shape_mismatch",
                PolicyDenial::ApprovalConsumed => "approval_consumed",
                PolicyDenial::ApprovalAlreadyDecided => "approval_already_decided",
                PolicyDenial::ApprovalWithdrawn => "approval_withdrawn",
                PolicyDenial::CallKeyReused => "call_key_reused",
            },
            Self::Severity(reason) => match reason.as_ref() {
                SeverityDenial::DecisionDenied { .. } => "decision_denied",
                SeverityDenial::GrantHashMismatch => "grant_hash_mismatch",
                SeverityDenial::DecisionPlaneFailure => "decision_plane_failure",
            },
            Self::NeedsDecisionPlane(_) => "needs_decision_plane",
            Self::ResourceFilter(reason) => match reason {
                ResourceDenial::MissingRequiredFilter(_) => "resource_filter_missing",
                ResourceDenial::ValueNotAllowed(_) => "resource_filter_value_denied",
                ResourceDenial::WriteFiltersAbsent => "write_filters_absent",
            },
            Self::Credential(reason) => match reason {
                CredentialDenial::Missing => "credential_missing",
                CredentialDenial::StoreUnavailable => "credential_store_unavailable",
                CredentialDenial::Permanent(_) => "credential_permanent",
                CredentialDenial::AuthRequired => "credential_auth_required",
                CredentialDenial::Transient(reason) => transient_credential_code(*reason),
            },
            Self::ActionRequestCreated { .. } => "action_request_created",
            Self::ArgumentUndeclared { .. } => "argument_undeclared",
            Self::StoreFailure => "store_failure",
        }
    }

    /// Gate decisions are terminal. Credential transient failures are exposed
    /// as bounded-retryable only by the dispatch outcome, never by replaying a
    /// previously denied reservation.
    pub fn terminal(&self) -> bool {
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn retryability(&self) -> Retryability {
        if self.clears_by_waiting() {
            Retryability::AutoRetryable
        } else {
            Retryability::Terminal
        }
    }

    /// Return true when a temporary failure, not missing authority, caused the
    /// refusal. The store or vault may be unreadable, this instance may lack
    /// the lease to serve connector calls, the approval service may not answer,
    /// or the connection may be unhealthy. Keep the user's approved request
    /// pending and retry until its approval expires, rather than retiring a
    /// request whose approval remains valid.
    pub(crate) fn clears_by_waiting(&self) -> bool {
        match self {
            Self::StoreFailure
            | Self::FederatedLivenessUnavailable
            | Self::Resolver(ResolverDenial::StoreFailure)
            | Self::ConnectorHomeNotHeld { .. }
            | Self::Credential(CredentialDenial::Transient(_))
            | Self::Credential(CredentialDenial::StoreUnavailable)
            | Self::Connection(ConnectionDenial::Unhealthy) => true,
            Self::Severity(reason) => {
                matches!(reason.as_ref(), SeverityDenial::DecisionPlaneFailure)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportOutcome {
    Completed { response: Option<Value> },
    VendorFailed { code: String, message: String },
    OutcomeUnknown,
    NotSent { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct DispatchOutcome {
    pub reservation_id: String,
    pub reconciliation: Option<crate::reconciliation::WriteReconciliationStatus>,
    pub transmission: TransmissionState,
    pub retryability: Retryability,
    /// Optional vendor retry delay in milliseconds, when the transport supplied one.
    pub retry_after_ms: Option<u64>,
    pub error_signal: Option<crate::manifest::ErrorSignal>,
    pub outcome: TransportOutcome,
}

impl DispatchOutcome {
    fn not_sent(
        reservation: &Reservation,
        code: String,
        message: String,
        retryability: Retryability,
    ) -> Self {
        Self {
            retry_after_ms: None,
            error_signal: None,
            reconciliation: None,
            reservation_id: reservation.reservation_id.clone(),
            transmission: TransmissionState::NotSent,
            retryability,
            outcome: TransportOutcome::NotSent { code, message },
        }
    }
}

/// In-memory portion of a persisted single-use reservation. It contains args
/// only for the current call and never serializes them into audit output.
#[derive(Debug, Clone, PartialEq)]
pub struct Reservation {
    pub reservation_id: String,
    /// Principal that owns the connection and every persisted invoke row.
    pub principal: String,
    /// Principal that submitted the call authorized by the owner's grant.
    pub acting_principal: String,
    pub actor: String,
    pub attributed_agent_id: Option<String>,
    pub bound_agent_handle: Option<String>,
    pub connection_id: String,
    pub app_key: String,
    pub action: String,
    pub args: Value,
    /// The grant that authorized this reservation, carried so revalidation can
    /// pin that exact row rather than a maximum across matching grants.
    pub grant_id: String,
    /// Keep the exact authorized arguments to detect dispatch-time changes:
    /// JSON Canonicalization Scheme hashes can round distinct large integers
    /// to the same binary64 value.
    pub approved_args: Value,
    pub approved_args_hash: String,
    /// Strict JCS hash of args used to recompute the decision plane's grant_hash.
    pub args_snapshot_hash: String,
    pub schema_hash: String,
    pub risk: Risk,
    pub severity: Severity,
    pub snapshot: SnapshotGenerations,
    pub expires_at_ms: i64,
    pub request_id: String,
    pub credential_fingerprint: String,
    /// Present when this reservation was authorized by the decision plane.
    pub decision_id: Option<String>,
    pub grant_hash: Option<String>,
    /// Stable logical-write id (`action_request` row) when decision-authorized.
    pub intent_id: Option<String>,
    /// For a facade-originated call, save authorization state before ownership
    /// reads so a later change can prevent transmission.
    pub authority_baseline: Option<AuthorityBaseline>,
    pub receipt: Option<ReceiptClaim>,
    pub origin: RequestOrigin,
    /// The daemon scope the call's route was bound under, written on the
    /// dispatch audit row as it was on the authorization row.
    pub scope: Option<CallScope>,
    /// The call from which the reserved call was relayed, written on the
    /// dispatch audit row as it was on the authorization row.
    pub relay_origin: Option<RelayOrigin>,
    /// The worker scope's `on_behalf_of_agent`, written on the dispatch audit
    /// row as it was on the authorization row. Attribution only.
    pub on_behalf_of_agent: Option<String>,
    /// For a call made as an agent, the agent grant that authorized it.
    pub agent_grant: Option<PinnedGrant>,
    /// When this reservation runs a stored approval raised under a scope, that
    /// scope. It is re-checked with the daemon just before the claim.
    pub approval_scope: Option<ApprovalScope>,
    pub federated_caller: Option<crate::federated::FederatedCaller>,
    pub federated_row_id: Option<String>,
    pub federated_card_ref: Option<String>,
    pub(crate) federated_search_use: bool,
}

impl AuditRecord {
    /// An audit row about a reservation, with the fields every such row records
    /// the same way: owner, caller, agent, connection, app key, action and
    /// request id, plus the given decision, reason code and gate. The bound
    /// handle is recorded as the app handle only for facade calls, where it is
    /// the app's own identity; for other calls it is only the agent's handle.
    /// Risk, severity, outcome and the remaining fields are left unset for the
    /// caller to fill.
    pub fn for_reservation(
        reservation: &Reservation,
        decision: &str,
        reason_code: &str,
        gate: &str,
    ) -> Self {
        Self {
            principal: reservation.principal.clone(),
            actor: reservation.actor.clone(),
            acting_principal: reservation.acting_principal.clone(),
            agent_id: reservation.attributed_agent_id.clone(),
            app_handle_id: if reservation.origin == RequestOrigin::Facade {
                reservation.bound_agent_handle.clone()
            } else {
                None
            },
            agent_handle: reservation.bound_agent_handle.clone(),
            connection_id: Some(reservation.connection_id.clone()),
            app_key: Some(reservation.app_key.clone()),
            action: Some(reservation.action.clone()),
            risk: None,
            severity: None,
            decision: decision.to_string(),
            reason_code: reason_code.to_string(),
            gate: Some(gate.to_string()),
            args_redaction_summary: None,
            outcome: None,
            latency_ms: None,
            request_id: Some(reservation.request_id.clone()),
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        }
    }
}

/// A grant selector distinguishes module rows from agent-specific rows.
/// An agent-specific grant never substitutes for a module grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrantKey<'a> {
    pub connection_id: &'a str,
    pub principal: &'a str,
    pub agent_id: Option<&'a str>,
}

/// A module row (no agent) must name the calling module. An agent row states
/// what that agent may do, so it matches on connection and agent alone,
/// whichever module carries the agent's call.
pub fn grant_key_matches(row: &AgentGrantKey<'_>, sought: &AgentGrantKey<'_>) -> bool {
    row.principal != "*"
        && sought.principal != "*"
        && row.connection_id == sought.connection_id
        && row.agent_id == sought.agent_id
        && (row.agent_id.is_some() || row.principal == sought.principal)
}

/// Pick one layer's grant for `action` out of a connection's scoped grant rows:
/// the module layer when `agent_id` is `None`, the named agent's own layer
/// otherwise. Only rows owned by the connection's principal and of the
/// requested authority kind count.
///
/// Grants are additive: among the rows of one layer, any live row naming the
/// action admits it. `grant_candidate` is the same selection `matching_grant`
/// uses for ordinary invokes, so refusal reasons read the same on every path.
/// The returned row is the most relevant one, not a verdict; pass it to
/// [`scoped_grant_refusal`] for that.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scoped_grant(
    rows: &[ScopedGrantRow],
    connection: &ConnectionRecord,
    principal: &str,
    agent_id: Option<&str>,
    authority_kind: &str,
    action: &str,
    now: i64,
    requested_risk: Option<&str>,
) -> Option<GrantRecord> {
    crate::storage::grant_candidate(
        rows.iter()
            .filter(|row| {
                grant_key_matches(
                    &AgentGrantKey {
                        connection_id: &row.grant.connection_id,
                        principal: &row.grant.grantee_principal,
                        agent_id: row.agent_id.as_deref(),
                    },
                    &AgentGrantKey {
                        connection_id: &connection.connection_id,
                        principal,
                        agent_id,
                    },
                ) && row.grant.principal == connection.principal
                    && row.grant.authority_kind == authority_kind
            })
            .map(|row| &row.grant),
        action,
        now,
        requested_risk,
    )
    .cloned()
}

/// Why the grant [`scoped_grant`] picked does not admit `action` at `now`, or
/// `None` when it does.
pub(crate) fn scoped_grant_refusal(
    grant: Option<&GrantRecord>,
    action: &str,
    action_risk: &str,
    now: i64,
) -> Option<GrantDenial> {
    match grant {
        None => Some(GrantDenial::Missing),
        Some(grant) if grant.expires_at.is_some_and(|expires| expires <= now) => {
            Some(GrantDenial::Expired)
        }
        Some(grant) if !grant.authorizes(action, now) => Some(GrantDenial::ActionSelector),
        Some(grant) if !risk_within_ceiling(action_risk, &grant.risk_ceiling) => {
            Some(GrantDenial::RiskCeiling)
        }
        Some(_) => None,
    }
}

/// Select the stricter effect; without a module policy the catalog default
/// remains in force even if an agent policy explicitly allows the operation.
pub fn catalog_policy_effect(
    action: &CatalogAction,
    module: Option<&str>,
    agent: Option<&str>,
) -> &'static str {
    compose_policy_effect(
        module.unwrap_or(if action.ask_first {
            "ask_first"
        } else {
            "allow"
        }),
        agent,
    )
}

pub fn compose_policy_effect(module_or_default: &str, agent_effect: Option<&str>) -> &'static str {
    PolicyEffect::of(module_or_default)
        .max(agent_effect.map_or(PolicyEffect::Allow, PolicyEffect::of))
        .as_str()
}

/// Authority state captured when a facade receipt is claimed, compared again
/// before its governed reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityBaseline {
    pub app_handle_generation: i64,
    pub repo_binding_generation: i64,
    pub credential_generation: i64,
    pub handle_enabled: bool,
    pub agent_grant_generation: i64,
    pub module_grant_generation: i64,
    pub policy_effect_hash: String,
}

/// Hash of the policy state an authority baseline pins: the module policy's
/// stored effect (absent when no module policy row exists), the agent policy's
/// effect, and the catalog action's ask_first flag. Facade receipts persist
/// this value, so its inputs and their order must not change.
pub fn policy_effect_hash(
    module_effect: Option<&str>,
    agent_effect: Option<&str>,
    ask_first: bool,
) -> Result<String, jcs::JcsError> {
    jcs::jcs_sha256(&serde_json::json!([module_effect, agent_effect, ask_first]))
}

/// Each authority dimension's baseline field and the refusal it produces, in
/// the order they are checked: the first changed dimension names the refusal.
/// [`compare_authority_baseline`] checks these on typed values, and the GitHub
/// facade checks them on the JSON baseline it persisted in a receipt.
pub(crate) const AUTHORITY_DIMENSIONS: [(&str, &str); 7] = [
    ("handle_enabled", "handle_disabled"),
    ("repo_binding_generation", "repository_rebound"),
    ("agent_grant_generation", "agent_grant_revoked"),
    ("module_grant_generation", "module_grant_revoked"),
    ("policy_effect_hash", "policy_changed"),
    ("credential_generation", "credential_rotated"),
    ("app_handle_generation", "handle_row_changed"),
];

/// The first changed dimension determines the refusal even when several move.
///
/// This compares live typed baselines and refuses a disabled handle whatever
/// was captured; the facade's receipt check compares persisted JSON instead,
/// where any difference, including a key the stored row lacks, refuses.
pub fn compare_authority_baseline(
    original: &AuthorityBaseline,
    current: &AuthorityBaseline,
) -> Result<(), &'static str> {
    if !current.handle_enabled {
        return Err("handle_disabled");
    }
    if original.repo_binding_generation != current.repo_binding_generation {
        return Err("repository_rebound");
    }
    if original.agent_grant_generation != current.agent_grant_generation {
        return Err("agent_grant_revoked");
    }
    if original.module_grant_generation != current.module_grant_generation {
        return Err("module_grant_revoked");
    }
    if original.policy_effect_hash != current.policy_effect_hash {
        return Err("policy_changed");
    }
    if original.credential_generation != current.credential_generation {
        return Err("credential_rotated");
    }
    if original.app_handle_generation != current.app_handle_generation {
        return Err("handle_row_changed");
    }
    Ok(())
}

/// Known pre-transmit refusal codes emitted by governed reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
pub enum FacadeNotSentCode {
    AbortedStaleAuthorization,
    GrantHashMismatch,
    ReservationExpired,
    CredentialMissing,
}

#[cfg(any(test, feature = "test-support"))]
impl FacadeNotSentCode {
    #[cfg(any(test, feature = "test-support"))]
    pub fn transport_code(self) -> &'static str {
        match self {
            Self::AbortedStaleAuthorization => "aborted_stale_authorization",
            Self::GrantHashMismatch => "grant_hash_mismatch",
            Self::ReservationExpired => "reservation_expired",
            Self::CredentialMissing => "credential_missing",
        }
    }

    pub fn refusal(self) -> &'static str {
        match self {
            Self::AbortedStaleAuthorization => "stale_authority{authorization_snapshot_stale}",
            Self::GrantHashMismatch => "stale_authority{grant_hash_mismatch}",
            Self::ReservationExpired => "stale_authority{reservation_expired}",
            Self::CredentialMissing => "handle_credential_unresolvable",
        }
    }
}

/// Convert a transport refusal code to a stable facade error without exposing
/// the provider's response message.
#[cfg(any(test, feature = "test-support"))]
pub fn facade_not_sent(code: &str) -> Option<&'static str> {
    let parsed = match code {
        "aborted_stale_authorization" => FacadeNotSentCode::AbortedStaleAuthorization,
        "grant_hash_mismatch" => FacadeNotSentCode::GrantHashMismatch,
        "reservation_expired" => FacadeNotSentCode::ReservationExpired,
        "credential_missing" => FacadeNotSentCode::CredentialMissing,
        _ => return None,
    };
    Some(parsed.refusal())
}

/// Explicitly match every inner denial variant so new variants require a
/// deliberate facade refusal mapping.
pub fn pipeline_denial(denial: &Denial, gate: &str) -> String {
    if let Denial::GrantRefusal(refusal) = denial {
        return refusal.code().into();
    }
    let name = match denial {
        Denial::GrantRefusal(_) => unreachable!(),
        Denial::ConnectorHomeNotHeld { .. } => "connector_home_not_held",
        Denial::ConsentUnavailable { .. } => "consent_unavailable",
        Denial::AccessPending { .. } => "access_pending",
        Denial::ConsentRefused { code, .. } => code,
        Denial::FederatedConsentDenied => "consent_denied",
        Denial::FederatedPairingEnded => "federated_pairing_ended",
        Denial::FederatedLivenessUnavailable => "federated_liveness_unavailable",
        Denial::RecipientArgumentInvalid { .. } => "recipient_argument_invalid",
        Denial::ApprovalPreviewTooLong { .. } => "approval_preview_too_long",
        Denial::Connection(reason) => match reason {
            ConnectionDenial::NotFound => "Connection(NotFound)",
            ConnectionDenial::Disabled => "Connection(Disabled)",
            ConnectionDenial::Revoked => "Connection(Revoked)",
            ConnectionDenial::Pending => "Connection(Pending)",
            ConnectionDenial::Unhealthy => "Connection(Unhealthy)",
        },
        Denial::Catalog(reason) => match reason {
            CatalogDenial::NotFound => "Catalog(NotFound)",
            CatalogDenial::Quarantined => "Catalog(Quarantined)",
            CatalogDenial::Disabled => "Catalog(Disabled)",
            CatalogDenial::SchemaMismatch => "Catalog(SchemaMismatch)",
        },
        Denial::Resolver(reason) => match reason {
            ResolverDenial::StoreFailure => "StoreFailure",
            ResolverDenial::RepositoryUnbound => "Resolver(RepositoryUnbound)",
            ResolverDenial::RequestFieldForbidden { .. } => "Resolver(RequestFieldForbidden)",
        },
        Denial::BotActionRequiresFacade => "BotActionRequiresFacade",
        Denial::OwnershipProofMissing => "OwnershipProofMissing",
        Denial::CredentialMaterialForbidden => "CredentialMaterialForbidden",
        Denial::Grant(reason) => match reason {
            GrantDenial::Missing => "Grant(Missing)",
            GrantDenial::Expired => "Grant(Expired)",
            GrantDenial::RiskCeiling => "Grant(RiskCeiling)",
            GrantDenial::ActionSelector => "Grant(ActionSelector)",
            GrantDenial::ConnectionAdminRequired => "Grant(ConnectionAdminRequired)",
        },
        Denial::Policy(reason) => match reason {
            PolicyDenial::Blocked => "Policy(Blocked)",
            PolicyDenial::AskFirst => "Policy(AskFirst)",
            PolicyDenial::ApprovalMissing => "Policy(ApprovalMissing)",
            PolicyDenial::ApprovalExpired => "Policy(ApprovalExpired)",
            PolicyDenial::ApprovalShapeMismatch => "Policy(ApprovalShapeMismatch)",
            PolicyDenial::ApprovalConsumed => "Policy(ApprovalConsumed)",
            PolicyDenial::ApprovalAlreadyDecided => "Policy(ApprovalAlreadyDecided)",
            PolicyDenial::ApprovalWithdrawn => "Policy(ApprovalWithdrawn)",
            PolicyDenial::CallKeyReused => "Policy(CallKeyReused)",
        },
        Denial::Severity(reason) => match reason.as_ref() {
            SeverityDenial::DecisionDenied { .. } => "Severity(DecisionDenied)",
            SeverityDenial::GrantHashMismatch => "Severity(GrantHashMismatch)",
            SeverityDenial::DecisionPlaneFailure => "Severity(DecisionPlaneFailure)",
        },
        Denial::NeedsDecisionPlane(_) => "NeedsDecisionPlane",
        Denial::ResourceFilter(reason) => match reason {
            ResourceDenial::MissingRequiredFilter(_) => "ResourceFilter(MissingRequiredFilter)",
            ResourceDenial::ValueNotAllowed(_) => "ResourceFilter(ValueNotAllowed)",
            ResourceDenial::WriteFiltersAbsent => "ResourceFilter(WriteFiltersAbsent)",
        },
        Denial::Credential(reason) => match reason {
            CredentialDenial::Missing => "Credential(Missing)",
            CredentialDenial::StoreUnavailable => "Credential(StoreUnavailable)",
            CredentialDenial::Permanent(_) => "Credential(Permanent)",
            CredentialDenial::AuthRequired => "Credential(AuthRequired)",
            CredentialDenial::Transient(_) => "Credential(Transient)",
        },
        Denial::ActionRequestCreated { .. } => "ActionRequestCreated",
        Denial::StoreFailure => "StoreFailure",
        // The only denial that names its field, so the caller learns which
        // argument to drop. It is an argument name, never a value.
        Denial::ArgumentUndeclared { field } => {
            return format!(
                "pipeline_denied{{gate: {gate}, denial: ArgumentUndeclared, field: {field}}}"
            )
        }
    };
    format!("pipeline_denied{{gate: {gate}, denial: {name}}}")
}

/// One grant table projection; a null agent_id is exclusively a module grant.
#[derive(Debug, Clone)]
pub struct ScopedGrantRow {
    pub grant: GrantRecord,
    pub agent_id: Option<String>,
}

/// Handle authority projection contains a credential reference, not a secret.
#[derive(Debug, Clone)]
pub struct HandleAuthority {
    pub app_handle_generation: i64,
    pub repo_binding_generation: i64,
    pub credential_generation: i64,
    pub enabled: bool,
    pub credential_reference: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PolicyInputs {
    pub module_effect: Option<String>,
    pub agent_effect: Option<String>,
    pub module_generation: i64,
}

/// Bind an existing approval to the agent that claimed the facade receipt;
/// a mapped catalog action may have different arguments from that receipt.
#[derive(Debug, Clone)]
pub struct ReceiptApprovalRow {
    pub action_request_id: String,
    pub agent_id: String,
    pub status: String,
    pub expires_at_ms: i64,
}

/// Resolve repository bindings and handle catalog authority before loading a
/// connection. Reject repository fields that could select a different wire path.
pub trait GovernanceSeams: Send + Sync {
    /// Build vendor arguments from checked internal routing, never caller queries.
    fn prepare_invoke(&self, _request: &mut AuthorizationRequest) -> Result<(), ResolverDenial> {
        Ok(())
    }
    fn resolve_invoke(&self, request: &AuthorizationRequest) -> Result<(), ResolverDenial>;
    fn facade_only(&self, action: &CatalogAction) -> bool;

    /// Read the current handle state, including only its credential reference.
    fn handle_row(
        &self,
        _connection: &ConnectionRecord,
    ) -> Result<Option<HandleAuthority>, Denial> {
        Ok(None)
    }

    /// Return both module (null agent_id) and agent-keyed rows for this call.
    fn grant_rows(
        &self,
        _connection: &ConnectionRecord,
        _request: &AuthorizationRequest,
    ) -> Result<Vec<ScopedGrantRow>, Denial> {
        Ok(Vec::new())
    }

    /// Read the current generations for the same two grant selectors.
    fn grant_generations(
        &self,
        _connection: &ConnectionRecord,
        _principal: &str,
        _agent_id: &str,
        _action: &str,
    ) -> Result<(i64, i64), Denial> {
        Err(Denial::Grant(GrantDenial::Missing))
    }

    /// Read module and agent policy inputs for this action, without replacing
    /// the catalog's ask_first default when no module policy exists.
    fn policy_inputs(
        &self,
        _connection: &ConnectionRecord,
        _agent_id: &str,
        _action: &CatalogAction,
    ) -> Result<PolicyInputs, Denial> {
        Err(Denial::StoreFailure)
    }

    /// Return an existing approval. Creating one belongs to the worker that
    /// claimed the receipt, not to an inner catalog invoke.
    fn receipt_approval(
        &self,
        _connection: &ConnectionRecord,
        _id: &str,
    ) -> Result<Option<ReceiptApprovalRow>, Denial> {
        Ok(None)
    }

    /// A facade effect may reserve only after all required ownership reads
    /// have returned. Read actions do not require this barrier.
    fn ownership_reads_complete(&self, _request: &AuthorizationRequest) -> bool {
        false
    }

    /// Compare the receipt's claim owner before sending. Return false if
    /// another worker took over while the first worker performed reads.
    fn pre_transmit(&self, _reservation: &Reservation) -> bool {
        false
    }

    /// Called when a send that `pre_transmit` marked will not happen after all
    /// (the handle credential could not be prepared), so the receipt does not
    /// claim a GitHub write may have occurred.
    fn abandon_transmit(&self, _reservation: &Reservation) {}

    /// Called after the final authority check, before a handle's first vendor
    /// request. A missing implementation refuses rather than using legacy get.
    /// The error is the caller-facing refusal code, including its failure
    /// class, so it reaches the facade reply unchanged.
    fn prepare_handle_credential(
        &self,
        _connection: &ConnectionRecord,
        _handle: &HandleAuthority,
    ) -> Result<ResolvedCredential, &'static str> {
        Err(crate::github::credential::UNRESOLVABLE_PERMANENT)
    }

    fn handle_auth_failure(&self, _connection: &ConnectionRecord, _handle: &HandleAuthority) {}
}

pub struct GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    store: Arc<PlexusStore>,
    credential_source: Arc<C>,
    transport: Arc<T>,
    gmail: Option<Arc<crate::gmail::GmailBackend>>,
    decision_plane: Option<Arc<dyn DecisionPlane>>,
    seams: Option<Arc<dyn GovernanceSeams>>,
    /// Asks the daemon for a scope's current state when a stored approval
    /// raised under a scope is about to execute. Without one, such an
    /// approval is held unsent: its scope cannot be confirmed.
    scope_reader: Option<Arc<dyn ScopeReader>>,
    /// Files a consent card with Cingulate, the fleet's consent module that
    /// puts approval questions on the user's phone, for each call held for
    /// approval (`ask_first`), and acts on the user's answers to those cards.
    /// Without one, only the operator can decide a held call, through the
    /// `requests` tool.
    consent_cards: Option<Arc<ConsentCards>>,
    consent_wait_hook: Option<Arc<dyn ConsentWaitHook>>,
    connector_home_guard: Option<Arc<dyn Fn() -> Option<Value> + Send + Sync>>,
    /// Confirms an authorized write's target is still current before it is
    /// sent; see [`Self::with_freshness_check`].
    freshness_check: Option<FreshnessCheck>,
    /// The wall clock, in Unix milliseconds, that every expiry this engine
    /// judges is read on: grants, policies, approvals, approval holds and
    /// reservations, including the reservation claim in the store. It is
    /// [`crate::storage::now_ms`] unless a test replaces it with a clock it
    /// moves itself; see [`Self::with_clock`].
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// The pre-dispatch check that an authorized call's target is still current.
/// `Err((code, message))` refuses the call as not sent with that code.
pub type FreshnessCheck = Arc<dyn Fn(&Reservation) -> Result<(), (String, String)> + Send + Sync>;

/// Lets an executor yield scarce work capacity while the user decides. The
/// after-wait callback runs before consent revalidation or vendor dispatch.
pub trait ConsentWaitHook: Send + Sync {
    fn before_wait(&self);
    fn after_wait(&self);
}

impl<C, T> Clone for GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            credential_source: Arc::clone(&self.credential_source),
            transport: Arc::clone(&self.transport),
            gmail: self.gmail.clone(),
            decision_plane: self.decision_plane.clone(),
            seams: self.seams.clone(),
            scope_reader: self.scope_reader.clone(),
            consent_cards: self.consent_cards.clone(),
            consent_wait_hook: self.consent_wait_hook.clone(),
            connector_home_guard: self.connector_home_guard.clone(),
            freshness_check: self.freshness_check.clone(),
            now_ms: Arc::clone(&self.now_ms),
        }
    }
}

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    pub fn new(store: Arc<PlexusStore>, credential_source: Arc<C>, transport: Arc<T>) -> Self {
        Self {
            store,
            credential_source,
            transport,
            gmail: None,
            decision_plane: None,
            seams: None,
            scope_reader: None,
            consent_cards: None,
            consent_wait_hook: None,
            connector_home_guard: None,
            freshness_check: None,
            now_ms: Arc::new(crate::storage::now_ms),
        }
    }

    pub fn with_gmail_backend(mut self, backend: Arc<crate::gmail::GmailBackend>) -> Self {
        self.gmail = Some(backend);
        self
    }

    pub fn gmail_mailbox(&self) -> Result<String, &'static str> {
        self.gmail
            .as_ref()
            .ok_or("gmail_vault_unavailable")?
            .mailbox()
    }

    pub fn read_sent_text(
        &self,
        owner: &str,
        row_id: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
        match self.gmail.as_ref() {
            Some(backend) => backend.read_sent_text(&self.store, owner, row_id, self.now_ms()),
            None => {
                self.store
                    .audit_sent_text_read(owner, row_id, "vault_unavailable")
                    .map_err(|_| "store_failure")?;
                Err("gmail_vault_unavailable")
            }
        }
    }

    /// Judge every expiry on `now_ms` instead of the real wall clock, so a
    /// test can move time past a deadline instead of sleeping until it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_clock(mut self, now_ms: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.now_ms = now_ms;
        self
    }

    /// The engine's clock reading, in Unix milliseconds.
    fn now_ms(&self) -> i64 {
        (self.now_ms)()
    }

    /// Attach the freshness check [`Self::dispatch_checked`] runs between
    /// authorization and dispatch. It runs only for a call that has already
    /// been authorized, so a caller without authority never causes the vendor
    /// contact the check may make.
    pub fn with_freshness_check(mut self, check: FreshnessCheck) -> Self {
        self.freshness_check = Some(check);
        self
    }

    /// Recheck connector ownership before reservations, approvals and dispatches.
    /// This closes the window where ownership changes during a scheduler pass.
    pub fn with_connector_home_guard(
        mut self,
        guard: Arc<dyn Fn() -> Option<Value> + Send + Sync>,
    ) -> Self {
        self.connector_home_guard = Some(guard);
        self
    }

    fn connector_home_denial(&self) -> Option<Denial> {
        self.connector_home_guard
            .as_ref()
            .and_then(|guard| guard())
            .map(|state| Denial::ConnectorHomeNotHeld { state })
    }

    /// Attach the consent-card filer: every call held for approval from now
    /// on is also filed as a card the user can answer from their phone.
    pub fn with_consent_cards(mut self, cards: Arc<ConsentCards>) -> Self {
        self.consent_cards = Some(cards);
        self
    }

    pub fn consent_card_client(&self) -> Option<&ConsentCards> {
        self.consent_cards.as_deref()
    }

    /// Attach executor capacity management around pending consent waits.
    pub fn with_consent_wait_hook(mut self, hook: Arc<dyn ConsentWaitHook>) -> Self {
        self.consent_wait_hook = Some(hook);
        self
    }

    /// Attach the daemon scope reader used to re-check a stored approval's
    /// scope just before the approval is claimed for sending.
    pub fn with_scope_reader(mut self, reader: Arc<dyn ScopeReader>) -> Self {
        self.scope_reader = Some(reader);
        self
    }

    /// Ask the daemon for a scope's current state, uncached. Without a scope
    /// reader the answer is a read error, so a caller that must confirm the
    /// scope before sending sends nothing.
    pub fn describe_scope(
        &self,
        owner: &str,
        scope_ref: &str,
    ) -> Result<crate::scope::ScopeDescription, ScopeReadError> {
        match self.scope_reader.as_ref() {
            Some(reader) => reader.describe(owner, scope_ref),
            None => Err(ScopeReadError(
                "no daemon scope reader is configured".to_string(),
            )),
        }
    }

    /// Attach an external decision-plane implementation. Without one, S3/S4 still
    /// deny with [`Denial::NeedsDecisionPlane`] (module composition decides).
    pub fn with_decision_plane(mut self, plane: Arc<dyn DecisionPlane>) -> Self {
        self.decision_plane = Some(plane);
        self
    }

    /// Attach the repository/handle resolver and handle catalog projection.
    /// These run before connection load and before module grant matching.
    pub fn with_governance_seams(mut self, seams: Arc<dyn GovernanceSeams>) -> Self {
        self.seams = Some(seams);
        self
    }

    pub fn store(&self) -> &Arc<PlexusStore> {
        &self.store
    }

    /// List operator permissions using this engine's daemon scope reader.
    pub fn list_permissions(
        &self,
        agent_id: Option<&str>,
        now: i64,
    ) -> Result<Vec<Value>, crate::permissions::ListError> {
        crate::permissions::list_with_scope_reader(
            &self.store,
            self.scope_reader.as_deref(),
            agent_id,
            now,
        )
    }

    /// Construct the only kind of request a poller may submit. The catalog is
    /// read at construction time, before authorization gates run, so a timer
    /// cannot manufacture a request for an action that is no longer an active
    /// read. The caller supplies the subscription's pinned schema hash; the
    /// normal catalog gate then rejects a concurrent schema change as well.
    pub fn poll_authorization_request(
        &self,
        principal: impl Into<String>,
        connection_id: impl Into<String>,
        action: impl Into<String>,
        args: Value,
        subscription_id: &str,
        expected_schema_hash: impl Into<String>,
    ) -> Result<AuthorizationRequest, PollAuthorizationRefusal> {
        let principal = principal.into();
        let connection_id = connection_id.into();
        let action = action.into();
        let catalog_action = self
            .store
            .catalog_action(&principal, &connection_id, &action)
            .map_err(|_| PollAuthorizationRefusal::StoreFailure)?
            .ok_or(PollAuthorizationRefusal::ActionNotFound)?;
        match catalog_action.status.as_str() {
            "active" => {}
            "quarantined" => return Err(PollAuthorizationRefusal::ActionQuarantined),
            "disabled" => return Err(PollAuthorizationRefusal::ActionDisabled),
            status => {
                return Err(PollAuthorizationRefusal::ActionUnavailable(
                    status.to_string(),
                ));
            }
        }
        if catalog_action.risk != "read" {
            return Err(PollAuthorizationRefusal::ActionRiskNotRead);
        }
        Ok(
            AuthorizationRequest::new(principal, connection_id, action, args)
                .with_schema_hash(expected_schema_hash)
                .for_poll(subscription_id),
        )
    }

    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    pub fn credential_source(&self) -> &Arc<C> {
        &self.credential_source
    }

    /// Inspect grant and policy authority for a proposed flow, without authorizing
    /// or reserving a call. The proposed scope is never persisted as a daemon stamp.
    /// This is only a grant- and policy-level projection: it does not check
    /// arguments, recipients, resource filters, credentials or severity. An
    /// `allow` here is not permission to dispatch; execution runs every gate.
    pub fn would_ask(
        &self,
        agent: Option<&str>,
        flow: &str,
        stamped_scope: Option<&CallScope>,
        tool: &str,
        connection_id: &str,
        action_name: &str,
    ) -> Result<&'static str, Denial> {
        let scope = stamped_scope.cloned().unwrap_or_else(|| CallScope {
            owner: PROJECTION_PRINCIPAL.into(),
            scope_ref: "grant-projection".into(),
            scope_epoch: 0,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: agent.map(str::to_owned),
            flow_id: Some(flow.into()),
            delegates: agent.is_some(),
            owner_authorized: true,
        });
        let mut request = AuthorizationRequest::new(
            PROJECTION_PRINCIPAL,
            connection_id,
            action_name,
            serde_json::json!({}),
        )
        .with_scope(scope)
        .with_diagnostic_tool(tool);
        if tool == "github" && crate::github::reads::ACTIONS.contains(&action_name) {
            request.scope_grants_agent = false;
        } else if tool == "github" {
            request.origin = RequestOrigin::Facade;
            let agent = agent.ok_or_else(|| {
                grant_denial(
                    &request,
                    crate::grant_refusal::Layer::Agent,
                    GrantDenial::Missing,
                )
            })?;
            request = request.with_bound_agent(agent, "grant-projection");
        }
        let connection = self
            .store
            .connection_for_invoke(PROJECTION_PRINCIPAL, connection_id)
            .map_err(|_| Denial::StoreFailure)?;
        let Some(connection) = connection else {
            if self
                .store
                .connection_id_exists(connection_id)
                .map_err(|_| Denial::StoreFailure)?
            {
                return Err(Denial::GrantRefusal(
                    crate::grant_refusal::GrantRefusal::new(
                        crate::grant_refusal::GrantTarget::new(
                            crate::grant_refusal::Layer::Module,
                            PROJECTION_PRINCIPAL,
                            tool,
                            Some(connection_id),
                            action_name,
                        ),
                        crate::grant_refusal::Cause::Missing,
                    ),
                ));
            }
            return Err(Denial::Connection(ConnectionDenial::NotFound));
        };
        let action = self
            .store
            .catalog_action(&connection.principal, connection_id, action_name)
            .map_err(|_| Denial::StoreFailure)?
            .ok_or(Denial::Catalog(CatalogDenial::NotFound))?;
        if let Some(reason) = catalog_denial(&action, None) {
            return Err(Denial::Catalog(reason));
        }
        self.evaluate_authority(&request, &connection, &action, self.now_ms())
            .map(|value| value.policy_effect)
    }

    pub fn authorize(&self, request: AuthorizationRequest) -> Result<Reservation, Denial> {
        self.authorize_inner(request, false)?
            .ok_or(Denial::StoreFailure)
    }

    /// Run the dispatch gates without reserving, reading consent or credentials.
    /// Search must pass these even when a shared cache can answer the call.
    pub(crate) fn preflight_federated_search(
        &self,
        request: AuthorizationRequest,
    ) -> Result<(), Denial> {
        if request.federated_caller.is_none() || request.federated_search.is_none() {
            return Err(Denial::StoreFailure);
        }
        self.authorize_inner(request, true).map(|_| ())
    }

    pub fn revalidate_and_dispatch(&self, reservation: &Reservation) -> DispatchOutcome {
        if let Some(Denial::ConnectorHomeNotHeld { state }) = self.connector_home_denial() {
            // Nothing is sent, so release the reservation (an approval behind
            // it stays usable), record the refusal, and tell the decision
            // plane the decision it authorized will not run.
            self.abandon_unsent_reservation(reservation);
            self.audit_dispatch_denial(reservation, "connector_home_not_held");
            return self.maybe_report_decision_outcome(
                reservation,
                DispatchOutcome {
                    retry_after_ms: None,
                    error_signal: None,
                    reservation_id: reservation.reservation_id.clone(),
                    reconciliation: None,
                    transmission: TransmissionState::NotSent,
                    retryability: Retryability::Terminal,
                    outcome: TransportOutcome::NotSent {
                        code: "connector_home_not_held".into(),
                        message: format!("connector home not held: {state}"),
                    },
                },
                OutcomeTerminal::Refused {
                    reason: "connector_home_not_held".to_string(),
                },
            );
        }
        // Decision-authorized path: recompute grant_hash over args about to dispatch.
        if let (Some(decision_id), Some(expected_grant_hash)) =
            (&reservation.decision_id, &reservation.grant_hash)
        {
            let args_hash = match jcs::jcs_sha256(&reservation.args) {
                Ok(hash) => hash,
                Err(_) => {
                    self.abandon_unsent_reservation(reservation);
                    self.audit_dispatch_denial(reservation, "grant_hash_mismatch");
                    return self.maybe_report_decision_outcome(
                        reservation,
                        DispatchOutcome::not_sent(
                            reservation,
                            "grant_hash_mismatch".to_string(),
                            "args could not be canonicalized before dispatch".to_string(),
                            Retryability::Terminal,
                        ),
                        OutcomeTerminal::Refused {
                            reason: "grant_hash_mismatch".to_string(),
                        },
                    );
                }
            };
            match compute_grant_hash(GrantHashInput {
                decision_id,
                app_key: &reservation.app_key,
                action: &reservation.action,
                args_snapshot_hash: &args_hash,
                schema_hash: &reservation.schema_hash,
            }) {
                Ok(computed) if computed == *expected_grant_hash => {}
                _ => {
                    self.abandon_unsent_reservation(reservation);
                    self.audit_dispatch_denial(reservation, "grant_hash_mismatch");
                    return self.maybe_report_decision_outcome(
                        reservation,
                        DispatchOutcome::not_sent(
                            reservation,
                            "grant_hash_mismatch".to_string(),
                            "grant_hash no longer matches dispatch args".to_string(),
                            Retryability::Terminal,
                        ),
                        OutcomeTerminal::Refused {
                            reason: "grant_hash_mismatch".to_string(),
                        },
                    );
                }
            }
        }

        if let Some(bound) = reservation.approval_scope.as_ref() {
            if let Some(outcome) = self.recheck_approval_scope(reservation, bound) {
                return outcome;
            }
        }

        let stale = reservation.args != reservation.approved_args;
        // Read the connection and fetch a vault-bound credential BEFORE the
        // claim. The claim consumes the reservation and any approval behind
        // it, so a store or vault failure found only after it would spend the
        // user's approval on a call that never left, and a retry would meet
        // `approval_consumed`. Found here, the reservation is abandoned and the
        // approval stays usable. A reservation that cannot be claimed anyway
        // (stale or expired) skips this and is refused by the claim below.
        let claimable = !stale && self.now_ms() < reservation.expires_at_ms;
        if !claimable {
            self.abandon_unsent_reservation(reservation);
        }
        let prepared = if claimable {
            match self.prepare_dispatch_credential(reservation) {
                Ok(prepared) => Some(prepared),
                Err(outcome) => return *outcome,
            }
        } else {
            None
        };
        // Credential preparation can block on the vault or a token exchange.
        // An approval's scope or a paired computer's pairing that ends during
        // that wait must stop the send, so read it again now, before the claim
        // consumes the approval. No store transaction is open here, so the
        // daemon read does not hold the store writer.
        if prepared.is_some() {
            if let Some(outcome) = self.recheck_live_authority(reservation) {
                return outcome;
            }
        }
        let claimed = if claimable {
            match self.store.claim_reservation(
                &reservation_record(reservation),
                &reservation.request_id,
                &*self.now_ms,
                reservation.federated_search_use,
            ) {
                Ok(claimed) => claimed,
                Err(error) => {
                    // The claim's transaction did not commit, so neither the
                    // reservation nor an approval behind it was consumed.
                    // Reporting this as stale or expired would misname it.
                    eprintln!(error governance:
                        "claim of reservation {} failed: {error}",
                        reservation.reservation_id
                    );
                    self.abandon_unsent_reservation(reservation);
                    self.audit_dispatch_denial(reservation, "store_failure");
                    return self.maybe_report_decision_outcome(
                        reservation,
                        DispatchOutcome::not_sent(
                            reservation,
                            "store_failure".to_string(),
                            "the reservation could not be claimed".to_string(),
                            Retryability::AutoRetryable,
                        ),
                        OutcomeTerminal::Refused {
                            reason: "store_failure".to_string(),
                        },
                    );
                }
            }
        } else {
            false
        };
        if !claimed {
            let expired = self.now_ms() >= reservation.expires_at_ms;
            let reason = if expired {
                "reservation_expired"
            } else {
                "aborted_stale_authorization"
            };
            self.audit_dispatch_denial(reservation, reason);
            let terminal = if expired {
                OutcomeTerminal::Expired
            } else {
                OutcomeTerminal::Refused {
                    reason: "stale_authorization".to_string(),
                }
            };
            return self.maybe_report_decision_outcome(
                reservation,
                DispatchOutcome::not_sent(
                    reservation,
                    reason.to_string(),
                    if expired {
                        "reservation expired".to_string()
                    } else {
                        "authorization changed before dispatch".to_string()
                    },
                    Retryability::Terminal,
                ),
                terminal,
            );
        }

        // Every claimed reservation was prepared above; the refusal here only
        // keeps a future reordering from sending without a credential.
        let Some(PreparedCredential {
            connection,
            material,
            vault_credential,
            gmail,
        }) = prepared
        else {
            return self.deny_before_transmit(reservation, "credential_missing".into());
        };
        // Refuse authority movement before credential preparation, then check
        // again after it: a slow token exchange must not reopen the send window.
        if let Some(outcome) = self.revalidate_receipt_authority(reservation, &connection) {
            return outcome;
        }
        let (handle, app_credential) = match material {
            CredentialMaterial::Bound(handle) => (Some(handle), false),
            // A vendor whose reviewed manifest waives the credential is called
            // anonymously: there is no handle to exchange for a secret here,
            // and none to report a provider auth failure against below.
            CredentialMaterial::Waived => (None, false),
            CredentialMaterial::GithubApp => (None, true),
        };
        let request = TransportRequest {
            request_id: reservation.request_id.clone(),
            connection_id: reservation.connection_id.clone(),
            action: reservation.action.clone(),
            args: reservation.args.clone(),
            credential_fingerprint: reservation.credential_fingerprint.clone(),
        };
        if reservation.authority_baseline.is_some()
            && self
                .seams
                .as_ref()
                .is_some_and(|seams| !seams.pre_transmit(reservation))
        {
            return self.deny_before_transmit(
                reservation,
                if reservation.receipt.is_some() {
                    "nonce_in_flight"
                } else {
                    "aborted_stale_authorization"
                }
                .into(),
            );
        }
        let handle_authority = match self
            .seams
            .as_ref()
            .map(|seams| seams.handle_row(&connection))
        {
            Some(Ok(handle)) => handle,
            // A store read failure, not a vault answer: retrying can clear it.
            Some(Err(_)) => {
                self.abandon_marked_transmit(reservation);
                return self.deny_before_transmit(
                    reservation,
                    crate::github::credential::UNRESOLVABLE_TRANSIENT.into(),
                );
            }
            None => None,
        };
        let credential = match (handle_authority.as_ref(), handle.as_ref()) {
            (Some(authority), _) => match self
                .seams
                .as_ref()
                .expect("handle came from seams")
                .prepare_handle_credential(&connection, authority)
            {
                Ok(token) => token,
                Err(code) => {
                    self.abandon_marked_transmit(reservation);
                    return self.deny_before_transmit(reservation, code.into());
                }
            },
            // Losing an App authority row during preparation must not turn an
            // authenticated App call into an anonymous vendor request.
            (None, None) if app_credential => {
                self.abandon_marked_transmit(reservation);
                return self.deny_before_transmit(reservation, "credential_missing".into());
            }
            (None, None) => ResolvedCredential::anonymous(),
            // Fetched from the vault before the claim (see above).
            (None, Some(_)) => match vault_credential {
                Some(credential) => credential,
                None => return self.deny_before_transmit(reservation, "credential_missing".into()),
            },
        };
        if let Some(outcome) = self.revalidate_receipt_authority(reservation, &connection) {
            self.abandon_marked_transmit(reservation);
            return outcome;
        }
        let response = if connection.app_key == "gmail" && reservation.action == "gmail.send" {
            match (&self.gmail, gmail) {
                (Some(backend), Some(prepared)) => backend.send_prepared(
                    &self.store,
                    &reservation.principal,
                    request,
                    self.transport.as_ref(),
                    || self.now_ms(),
                    prepared,
                ),
                _ => crate::gmail::refusal("gmail_vault_unavailable", true),
            }
        } else if reservation.origin == RequestOrigin::Facade {
            self.transport.dispatch_github_facade(request, &credential)
        } else {
            self.transport.dispatch(request, &credential)
        };
        if response.provider_auth_status() == Some(401) {
            if let Some(authority) = handle_authority.as_ref() {
                self.seams
                    .as_ref()
                    .expect("handle came from seams")
                    .handle_auth_failure(&connection, authority);
                self.audit_dispatch_result(reservation, &response);
                // The request reached the vendor, which refused the token: for
                // the decision plane that is an executed call that failed, the
                // same as any other vendor failure below.
                return self.maybe_report_decision_outcome(
                    reservation,
                    DispatchOutcome {
                        retry_after_ms: response.retry_after_ms,
                        error_signal: response.error_signal,
                        reconciliation: None,
                        reservation_id: reservation.reservation_id.clone(),
                        transmission: response.transmission,
                        retryability: Retryability::Terminal,
                        outcome: TransportOutcome::VendorFailed {
                            code: "handle_credential_rejected".into(),
                            message: "installation token rejected".into(),
                        },
                    },
                    OutcomeTerminal::Executed {
                        outcome_ref: format!("req:{}", reservation.request_id),
                    },
                );
            }
            if let Some(handle) = handle.as_ref() {
                handle.report_auth_failure(self.credential_source.as_ref());
            }
        }
        let outcome = outcome_from_transport(&response);
        self.audit_dispatch_result(reservation, &response);

        let reconciliation = if matches!(outcome, TransportOutcome::OutcomeUnknown)
            && reservation.risk != Risk::Read
        {
            Some(self.queue_unknown_write(reservation))
        } else {
            None
        };
        let terminal = match &outcome {
            TransportOutcome::Completed { .. } | TransportOutcome::VendorFailed { .. } => {
                OutcomeTerminal::Executed {
                    outcome_ref: format!("req:{}", reservation.request_id),
                }
            }
            TransportOutcome::OutcomeUnknown => OutcomeTerminal::OutcomeUnknown {
                outcome_ref: format!("req:{}", reservation.request_id),
            },
            TransportOutcome::NotSent { code, .. } => OutcomeTerminal::Refused {
                reason: code.clone(),
            },
        };

        let dispatch = DispatchOutcome {
            retry_after_ms: response.retry_after_ms,
            error_signal: response.error_signal,
            reconciliation,
            reservation_id: reservation.reservation_id.clone(),
            transmission: response.transmission,
            retryability: response.retryability,
            outcome,
        };
        self.maybe_report_decision_outcome(reservation, dispatch, terminal)
    }

    pub fn approve_request(
        &self,
        principal: &str,
        request_id: &str,
        decider: &str,
    ) -> Result<DispatchOutcome, Denial> {
        if let Some(denial) = self.connector_home_denial() {
            return Err(denial);
        }
        let request = self
            .store
            .action_request(principal, request_id)
            .map_err(|_| Denial::StoreFailure)?
            .ok_or(Denial::Policy(PolicyDenial::ApprovalMissing))?;
        if !self.request_admin(&request, decider)? {
            return Err(Denial::Grant(GrantDenial::ConnectionAdminRequired));
        }
        if !self
            .store
            .decide_action_request(principal, request_id, true, decider)
            .map_err(|_| Denial::StoreFailure)?
        {
            // Only a live pending request can be decided. Re-read the row so
            // the refusal names the state it is actually in rather than calling
            // every non-pending request expired.
            let current = self
                .store
                .action_request(principal, request_id)
                .map_err(|_| Denial::StoreFailure)?
                .ok_or(Denial::Policy(PolicyDenial::ApprovalMissing))?;
            let reason = match RequestStatus::of(&current.status) {
                RequestStatus::Consumed => PolicyDenial::ApprovalConsumed,
                RequestStatus::Approved | RequestStatus::Denied => {
                    PolicyDenial::ApprovalAlreadyDecided
                }
                RequestStatus::Cancelled => PolicyDenial::ApprovalWithdrawn,
                _ => PolicyDenial::ApprovalExpired,
            };
            return Err(Denial::Policy(reason));
        }
        // The operator decided through the `requests` tool before the user
        // answered the request's card on their phone: withdraw the card so
        // the phone no longer offers a decision.
        self.withdraw_consent_card(&request);
        self.dispatch_approved(request, decider)
    }

    /// Try again every approval held unsent because its scope could not be
    /// confirmed, at most `limit` per call. Each runs the same full
    /// re-authorization and scope re-check as when it was approved, so one
    /// whose scope is now live is sent once, one whose scope has ended is
    /// retired, and one past its own expiry is refused `scope_unverifiable`.
    /// Returns how many were tried.
    pub fn retry_waiting_approvals(&self, limit: usize) -> usize {
        self.retry_waiting_approvals_until(limit, None)
    }

    /// As [`Self::retry_waiting_approvals`], but start no retry once
    /// `deadline` has passed. Each retry can wait on a daemon read, so a batch
    /// of unanswered scopes must not use up the scheduler pass that follows.
    /// Approvals selected but not reached go back to the front of the
    /// rotation, so the next pass tries them first.
    pub(crate) fn retry_waiting_approvals_until(
        &self,
        limit: usize,
        deadline: Option<std::time::Instant>,
    ) -> usize {
        let waiting = match self.store.waiting_scoped_approvals(limit) {
            Ok(waiting) => waiting,
            Err(error) => {
                eprintln!(error governance: "could not list approvals waiting on a scope: {error}");
                return 0;
            }
        };
        let mut tried = 0;
        let mut waiting = std::collections::VecDeque::from(waiting);
        while let Some(request) = waiting.pop_front() {
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                let untried: Vec<(String, String)> = std::iter::once(request)
                    .chain(waiting.drain(..))
                    .map(|request| (request.principal, request.request_id))
                    .collect();
                if let Err(error) = self.store.release_untried_scoped_approvals(&untried) {
                    eprintln!(error governance:
                        "could not return {} untried waiting approval(s) to the front of the retry order: {error}",
                        untried.len()
                    );
                }
                break;
            }
            tried += 1;
            let principal = request.principal.clone();
            let request_id = request.request_id.clone();
            if request.expires_at <= self.now_ms() {
                // The approval lapsed while held: nothing will ever send it.
                if let Err(error) =
                    self.store
                        .refuse_scoped_approval(&principal, &request_id, SCOPE_UNVERIFIABLE)
                {
                    eprintln!(error governance:
                        "could not retire lapsed approval {request_id}: {error}"
                    );
                }
                eprintln!(warn governance:
                    "approval {request_id} not run (scope_unverifiable): its scope was not confirmed before it expired"
                );
                continue;
            }
            let decider = request.decider.clone().unwrap_or_else(|| principal.clone());
            if let Some(bound) = approval_scope_of(&request) {
                let answer = self
                    .scope_reader
                    .as_ref()
                    .map(|reader| reader.describe(&bound.owner, &bound.scope_ref))
                    .unwrap_or_else(|| {
                        Err(ScopeReadError(
                            "no daemon scope reader is configured".into(),
                        ))
                    });
                match approval_scope_verdict(&bound, answer.as_ref()) {
                    ApprovalScopeVerdict::Run => {}
                    ApprovalScopeVerdict::Hold(_) => continue,
                    ApprovalScopeVerdict::Refuse(code) => {
                        let _ = self
                            .store
                            .refuse_scoped_approval(&principal, &request_id, code);
                        self.audit_approval_resolution(&request, &decider, code);
                        continue;
                    }
                }
            }
            if let Err(denial) = self.dispatch_approved(request, &decider) {
                if denial.clears_by_waiting() {
                    // A passing condition (store, vault, connector home, ...)
                    // refused it, not its authority: keep it waiting so a
                    // later pass sends it, until its own expiry above.
                    eprintln!(warn governance:
                        "held approval {request_id} still waiting: re-authorization hit a passing failure ({})",
                        denial.reason_code()
                    );
                    continue;
                }
                // Full re-authorization refused the call (a grant revoked, the
                // schema re-pinned, ...). That will not clear by waiting, so
                // the approval is retired with the refusal's name.
                eprintln!(warn governance:
                    "held approval {request_id} not run: re-authorization refused it ({})",
                    denial.reason_code()
                );
                if let Err(error) =
                    self.store
                        .refuse_scoped_approval(&principal, &request_id, denial.reason_code())
                {
                    eprintln!(error governance:
                        "could not retire refused approval {request_id}: {error}"
                    );
                }
            }
        }
        tried
    }

    pub fn deny_request(
        &self,
        principal: &str,
        request_id: &str,
        decider: &str,
    ) -> Result<bool, Denial> {
        let request = self
            .store
            .action_request(principal, request_id)
            .map_err(|_| Denial::StoreFailure)?
            .ok_or(Denial::Policy(PolicyDenial::ApprovalMissing))?;
        if !self.request_admin(&request, decider)? {
            return Err(Denial::Grant(GrantDenial::ConnectionAdminRequired));
        }
        let denied = self
            .store
            .decide_action_request(principal, request_id, false, decider)
            .map_err(|_| Denial::StoreFailure)?;
        if denied {
            self.audit_approval_resolution(&request, decider, "approval_denied");
            self.withdraw_consent_card(&request);
        }
        if !denied
            && self
                .store
                .action_request(principal, request_id)
                .map_err(|_| Denial::StoreFailure)?
                .is_some_and(|current| {
                    RequestStatus::of(&current.status) == RequestStatus::Cancelled
                })
        {
            // Named rather than reported as merely no longer pending, so the
            // approver learns the call was withdrawn.
            return Err(Denial::Policy(PolicyDenial::ApprovalWithdrawn));
        }
        Ok(denied)
    }

    /// Withdraw the call a `tool.withdraw` request names (see
    /// [`crate::withdraw::withdraw_call`]), and retract its consent card when
    /// the withdrawal took effect.
    pub fn withdraw_call(
        &self,
        call: &crate::withdraw::WithdrawCall<'_>,
    ) -> Result<crate::withdraw::WithdrawAnswer, crate::withdraw::WithdrawRefusal> {
        let answer = crate::withdraw::withdraw_call(&self.store, call)?;
        if matches!(answer, crate::withdraw::WithdrawAnswer::Withdrawn)
            && self.consent_cards.is_some()
        {
            // `withdraw_call` answers `withdrawn` only for the call held under
            // the named carrier (the module that made the call), or under the
            // caller itself when it named no carrier; look that request up.
            let carrier = call.carrier.unwrap_or(call.caller);
            match self.store.keyed_action_request(carrier, call.call_key) {
                Ok(Some(request)) => self.withdraw_consent_card(&request),
                Ok(None) => {}
                Err(error) => {
                    eprintln!(warn consent:
                        "could not read withdrawn call {} to retract its consent card: {error}",
                        call.call_key
                    );
                }
            }
        }
        Ok(answer)
    }

    /// Keep the tool call open while waiting for the user's answer to its
    /// consent card. Only an explicit approval on that card can authorize the
    /// stored call. An operator who approves through the `requests` tool takes
    /// a separate path that does not use this function.
    pub fn invoke_held(
        &self,
        mut request: AuthorizationRequest,
        deadline: std::time::Instant,
    ) -> Result<DispatchOutcome, Denial> {
        request.requires_session_consent = true;
        if let Some(denial) = self.connector_home_denial() {
            return Err(denial);
        }
        if request.federated_caller.is_some() {
            request.federated_deadline = Some(deadline);
            return self
                .authorize(request)
                .map(|reservation| self.dispatch_checked(&reservation));
        }
        if let (Some(cards), Some(scope)) = (&self.consent_cards, request.scope.as_ref()) {
            if let Some(key) = request.call_key.as_deref() {
                if let Some(held) = self
                    .store
                    .keyed_action_request(&request.principal, key)
                    .map_err(|_| Denial::StoreFailure)?
                {
                    let same_scope = held
                        .scope
                        .as_ref()
                        .is_some_and(|bound| scope.same_session(&bound.to_call_scope()));
                    if held.args_snapshot != request.args
                        || held.connection_id != request.connection_id
                        || held.action != request.action
                        || !same_scope
                    {
                        return Err(self.audited_refusal(
                            &request,
                            Denial::Policy(PolicyDenial::CallKeyReused),
                        ));
                    }
                }
            }
            if ConsentCards::available_scope(Some(scope)) {
                if let Some(held) = self
                    .store
                    .matching_consent_request(&request)
                    .map_err(|_| Denial::StoreFailure)?
                {
                    if request
                        .expected_schema_hash
                        .as_deref()
                        .is_some_and(|pin| pin != held.schema_hash)
                    {
                        return Err(self.audited_refusal(
                            &request,
                            Denial::Catalog(CatalogDenial::SchemaMismatch),
                        ));
                    }
                    let id = held.elicitation_id.as_deref().ok_or(Denial::StoreFailure)?;
                    match cards.get(scope, id) {
                        Ok(mut record) => {
                            if RequestStatus::of(&held.status) == RequestStatus::Consumed {
                                return Err(self.audited_refusal(
                                    &request,
                                    Denial::Policy(PolicyDenial::ApprovalConsumed),
                                ));
                            }
                            if let Some(key) = request.call_key.as_deref() {
                                if !self
                                    .store
                                    .remember_consent_call_key(&held, key)
                                    .map_err(|_| Denial::StoreFailure)?
                                {
                                    return Err(self.audited_refusal(
                                        &request,
                                        Denial::Policy(PolicyDenial::CallKeyReused),
                                    ));
                                }
                            }
                            if record["state"] == "pending" {
                                record =
                                    self.wait_for_consent(cards, scope, id, deadline).map_err(
                                        |error| self.consent_route_denial(&request.action, &error),
                                    )?;
                            }
                            return self.finish_consent(held, scope, record);
                        }
                        Err(crate::consent_card::ElicitationCallError::Refused {
                            code, ..
                        }) if code == "elicitation_not_found" => {}
                        Err(error) => {
                            return Err(self.audited_refusal(
                                &request,
                                self.consent_route_denial(&request.action, &error),
                            ))
                        }
                    }
                }
            }
        }
        let scope = request.scope.clone();
        match self.authorize(request) {
            Ok(reservation) => Ok(self.dispatch_checked(&reservation)),
            Err(Denial::ActionRequestCreated { request_id }) => {
                let stored = self
                    .store
                    .action_request_by_id(&request_id)
                    .map_err(|_| Denial::StoreFailure)?
                    .ok_or(Denial::StoreFailure)?;
                let Some(id) = stored.elicitation_id.as_deref() else {
                    self.audit_approval_resolution(
                        &stored,
                        &stored.requester,
                        "consent_unavailable",
                    );
                    return Err(Denial::ConsentUnavailable {
                        action: stored.action,
                    });
                };
                let (Some(cards), Some(scope)) = (&self.consent_cards, scope) else {
                    self.audit_approval_resolution(
                        &stored,
                        &stored.requester,
                        "consent_unavailable",
                    );
                    return Err(Denial::ConsentUnavailable {
                        action: stored.action,
                    });
                };
                let record = self
                    .wait_for_consent(cards, &scope, id, deadline)
                    .map_err(|error| self.consent_route_denial(&stored.action, &error))?;
                self.finish_consent(stored, &scope, record)
            }
            Err(denial) => Err(denial),
        }
    }
}

struct DecisionAuthorization {
    decision_id: String,
    grant_hash: String,
    intent_id: String,
}

/// What a governed call presents to a vendor, as decided by the reviewed
/// manifest. `Waived` is reachable only from `credential_material`.
enum CredentialMaterial {
    GithubApp,
    /// The vendor's reviewed manifest declares it needs no credential at all,
    /// so the call goes out anonymously.
    Waived,
    /// Stored authority to resolve into the vendor secret.
    Bound(crate::credentials::ConnectionCredentialBinding),
}

/// Read by dispatch before it claims a reservation; see
/// `prepare_dispatch_credential`.
struct PreparedCredential {
    gmail: Option<crate::gmail::PreparedGmail>,
    connection: ConnectionRecord,
    material: CredentialMaterial,
    /// The secret for `CredentialMaterial::Bound`, fetched from the vault;
    /// `None` for the other kinds.
    vault_credential: Option<ResolvedCredential>,
}

pub(crate) fn action_label<'a>(action: &'a CatalogAction, fallback: &'a str) -> &'a str {
    action
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .unwrap_or(fallback)
}

fn connection_fingerprint(connection_id: &str) -> String {
    fingerprint(connection_id.as_bytes())
}

/// The fingerprint an audit row carries for a call that presented no
/// credential. It is derived from the reserved `"none"` ref role rather than
/// from any secret, so it cannot collide with the fingerprint of a real
/// handle and a reader can tell an anonymous call from a credentialed one.
fn anonymous_credential_fingerprint() -> String {
    fingerprint(crate::storage::NO_CREDENTIAL_REF_ROLE.as_bytes())
}

fn outcome_from_transport(response: &TransportResponse) -> TransportOutcome {
    if response.response.is_some() {
        return TransportOutcome::Completed {
            response: response.response.clone(),
        };
    }
    match response.transmission {
        TransmissionState::OutcomeUnknown => TransportOutcome::OutcomeUnknown,
        TransmissionState::NotSent => TransportOutcome::NotSent {
            code: response
                .error_code
                .clone()
                .unwrap_or_else(|| "not_sent".to_string()),
            message: response
                .error_message
                .clone()
                .unwrap_or_else(|| "request was not sent".to_string()),
        },
        TransmissionState::Sent => TransportOutcome::VendorFailed {
            code: response
                .error_code
                .clone()
                .unwrap_or_else(|| "vendor_error".to_string()),
            message: response
                .error_message
                .clone()
                .unwrap_or_else(|| crate::transport::OPERATOR_DIAGNOSTIC_MESSAGE.to_string()),
        },
    }
}

pub(crate) fn connection_denial(connection: &ConnectionRecord) -> Option<ConnectionDenial> {
    match connection.status.as_str() {
        "active" | "degraded" => {
            let healthy_enough = connection
                .health_state
                .get("healthy_enough")
                .or_else(|| connection.health_state.get("healthy"))
                .and_then(Value::as_bool);
            if healthy_enough == Some(false) {
                Some(ConnectionDenial::Unhealthy)
            } else {
                None
            }
        }
        "pending" => Some(ConnectionDenial::Pending),
        "revoked" => Some(ConnectionDenial::Revoked),
        // Every other status, including the retired `auth_required` and
        // `disabled` the schema still admits, is refused as disabled.
        _ => Some(ConnectionDenial::Disabled),
    }
}

/// The first top-level argument, in sorted order, that the action's pinned
/// schema does not declare, or `None` when every argument is declared or the
/// schema does not close its top level.
///
/// Declared means a key of the schema's top-level `properties` object. Only the
/// top level is checked: a declared object argument's own keys are the
/// vendor's schema to validate, and the REST transport places whole top-level
/// arguments, so the top level is where an unreviewed field would reach the
/// vendor.
///
/// A schema is treated as OPEN, and nothing is refused, when it has no
/// `properties` object, when `additionalProperties` is `true` or a schema
/// object, or when it declares `patternProperties`: each of those states that
/// keys beyond the listed ones are part of what was reviewed. An absent
/// `additionalProperties` does not open the schema, because vendor tool schemas
/// routinely omit it while listing every argument they take.
///
/// The open case exists for rows pinned to the placeholder
/// `{"type":"object","additionalProperties":true}`: MCP actions before their
/// first discovery, and REST handle connections seeded before the manifest's
/// `http.args_schema` was pinned at seed time. Startup re-seeding leaves an
/// existing row alone and a handle connection is never refreshed by discovery,
/// so the boot ingest moves an active handle row off the placeholder with
/// `PlexusStore::pin_handle_placeholder_schemas`. A handle row stays open only
/// when its reviewed manifest offers no `http.args_schema`, which the boot logs
/// as a catalog gap. No other governed path relies on an open schema.
fn undeclared_argument(schema: &Value, args: &Value) -> Option<String> {
    if !args.is_object() && !args.is_null() {
        return Some("<arguments must be an object or null>".into());
    }
    let schema = schema.as_object()?;
    let properties = schema.get("properties")?.as_object()?;
    if schema
        .get("additionalProperties")
        .is_some_and(|additional| additional != &Value::Bool(false))
        || schema.contains_key("patternProperties")
    {
        return None;
    }
    args.as_object()?
        .keys()
        .filter(|key| !properties.contains_key(key.as_str()))
        .min()
        .cloned()
}

fn catalog_denial(
    action: &CatalogAction,
    expected_schema_hash: Option<&str>,
) -> Option<CatalogDenial> {
    match action.status.as_str() {
        "active" => {
            if expected_schema_hash.is_some_and(|expected| expected != action.schema_hash) {
                Some(CatalogDenial::SchemaMismatch)
            } else {
                None
            }
        }
        "quarantined" => Some(CatalogDenial::Quarantined),
        "disabled" => Some(CatalogDenial::Disabled),
        _ => Some(CatalogDenial::NotFound),
    }
}

/// Compute the severity used for authorization and federated catalog discovery.
pub fn effective_severity(
    action: &CatalogAction,
    app_key: &str,
    store: &PlexusStore,
) -> Result<Severity, cortexkit_store::StoreError> {
    // Missing or unknown reviewed tiers use the strongest severity. Actual
    // store read failures still propagate; they are not a severity decision.
    let tier_floor = store
        .parsed_manifest(crate::storage::CATALOG_PRINCIPAL, app_key)?
        .and_then(Result::ok)
        .map(|manifest| manifest.tier)
        .unwrap_or(Tier::S4);
    let tier_sev = match tier_floor {
        Tier::S1 => Severity::S1,
        Tier::S2 => Severity::S2,
        Tier::S3 => Severity::S3,
        Tier::S4 => Severity::S4,
    };
    Ok(action_severity(&action.risk, tier_sev))
}

/// The severity of one action: its risk's own severity, raised by its app's
/// tier. The one rule shared by authorization and by catalog freshness, so the
/// two never judge the same action differently.
pub(crate) fn action_severity(risk: &str, tier: Severity) -> Severity {
    let Some(risk) = known_risk(risk) else {
        return Severity::S4;
    };
    let base = match risk {
        Risk::Read => Severity::S1,
        Risk::Destructive => Severity::S3,
        Risk::Write => Severity::S2,
    };
    // Writes/destructive take the full tier floor (S3/S4 → decision plane).
    // Reads use a floor-min of S2: elevated tiers raise reads to S2, not to S3+.
    // So Notion search, a read on an elevated-tier provider, is S2, and a read
    // on an S4 provider like Stripe is still S2, not S4; writes take the full
    // tier.
    if risk != Risk::Read {
        base.max(tier)
    } else {
        base.max(tier.min(Severity::S2))
    }
}

fn resource_denial_with_repositories(
    connection: &ConnectionRecord,
    action: &CatalogAction,
    args: &Value,
    repositories: Option<&[String]>,
) -> Option<ResourceDenial> {
    if connection.app_key == "github_rest" && action.name == "github.issue.search" {
        if let Some(repositories) = repositories {
            if repositories.is_empty() {
                return Some(ResourceDenial::MissingRequiredFilter("repositories".into()));
            }
            for repository in repositories {
                let Some((owner, repo)) = repository.split_once('/').filter(|(owner, repo)| {
                    !owner.is_empty() && !repo.is_empty() && !repo.contains('/')
                }) else {
                    return Some(ResourceDenial::ValueNotAllowed("repositories".into()));
                };
                let mut checked = args.clone();
                let Some(object) = checked.as_object_mut() else {
                    return Some(ResourceDenial::MissingRequiredFilter("repositories".into()));
                };
                object.insert("owner".into(), Value::String(owner.into()));
                object.insert("repo".into(), Value::String(repo.into()));
                if let Some(denial) = resource_denial(connection, action, &checked) {
                    return Some(denial);
                }
            }
            return None;
        }
    }
    resource_denial(connection, action, args)
}

fn resource_denial(
    connection: &ConnectionRecord,
    action: &CatalogAction,
    args: &Value,
) -> Option<ResourceDenial> {
    let filters = connection.resource_filters.as_object();
    let required = filters
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let write_enabling = filters
        .and_then(|value| value.get("write_enabling"))
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    // A missing argument must not let vendor defaults escape an allowlist.
    // Dot-delimited paths use the same convention as manifest filter keys.
    // `required` names the resource every call must target, so it binds reads
    // as well as writes; `write_enabling` keys gate writes only.
    let write = is_write(&action.risk);
    if write && write_enabling.is_empty() {
        return Some(ResourceDenial::WriteFiltersAbsent);
    }
    let enabling: &[&str] = if write { &write_enabling } else { &[] };
    for key in required.iter().chain(enabling.iter()) {
        let Some(value) = resource_path(args, key) else {
            return Some(ResourceDenial::MissingRequiredFilter((*key).to_string()));
        };
        if value.is_null() || (value.as_str() == Some("")) {
            return Some(ResourceDenial::MissingRequiredFilter((*key).to_string()));
        }
    }
    if let Some(values) = filters
        .and_then(|value| value.get("values"))
        .and_then(Value::as_object)
    {
        for (key, allowed) in values {
            if let Some(actual) = resource_path(args, key) {
                let matches = |candidate: &Value| {
                    filter_value_matches(&connection.app_key, key, candidate, actual)
                };
                if let Some(allowed_values) = allowed.as_array() {
                    if !allowed_values.iter().any(matches) {
                        return Some(ResourceDenial::ValueNotAllowed(key.clone()));
                    }
                } else if !matches(allowed) {
                    return Some(ResourceDenial::ValueNotAllowed(key.clone()));
                }
            } else {
                return Some(ResourceDenial::MissingRequiredFilter(key.clone()));
            }
        }
    }
    None
}

fn resource_path<'a>(args: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(args, |value, key| value.get(key))
}

/// Whether an argument value equals one allowed by a connection's filter.
/// GitHub owner and repository names are case-insensitive, and the GitHub
/// connections store them lowercase, so `Org/Repo` must match `org/repo`
/// there; every other filter value must match exactly.
fn filter_value_matches(app_key: &str, key: &str, allowed: &Value, actual: &Value) -> bool {
    let github_name = app_key.starts_with("github") && matches!(key, "owner" | "repo");
    match (allowed, actual) {
        (Value::String(allowed), Value::String(actual)) if github_name => {
            allowed.eq_ignore_ascii_case(actual)
        }
        _ => allowed == actual,
    }
}

fn credential_denial(error: &CredentialError) -> Denial {
    Denial::Credential(match error {
        CredentialError::Permanent(reason) => CredentialDenial::Permanent(*reason),
        CredentialError::AuthRequired => CredentialDenial::AuthRequired,
        CredentialError::Transient(reason) => CredentialDenial::Transient(*reason),
    })
}

fn gate_for_denial(denial: &Denial) -> &'static str {
    match denial {
        Denial::Resolver(_) => "resolver",
        Denial::BotActionRequiresFacade => "catalog",
        Denial::OwnershipProofMissing => "facade",
        Denial::CredentialMaterialForbidden => "credential",
        Denial::Connection(_) => "connection",
        // An undeclared argument is judged against the schema pinned on the
        // catalog row, so it is audited as a catalog gate refusal.
        Denial::Catalog(_) | Denial::ArgumentUndeclared { .. } => "catalog",
        Denial::RecipientArgumentInvalid { .. } => "recipients",
        Denial::ApprovalPreviewTooLong { .. } => "policy",
        Denial::Grant(_) | Denial::GrantRefusal(_) => "grant",
        Denial::Policy(_)
        | Denial::ActionRequestCreated { .. }
        | Denial::AccessPending { .. }
        | Denial::ConsentRefused { .. }
        | Denial::FederatedConsentDenied
        | Denial::FederatedPairingEnded
        | Denial::FederatedLivenessUnavailable
        | Denial::ConsentUnavailable { .. } => "policy",
        Denial::Severity(_) | Denial::NeedsDecisionPlane(_) => "severity",
        Denial::ResourceFilter(_) => "resource_filter",
        Denial::Credential(_) => "credential",
        Denial::ConnectorHomeNotHeld { .. } => "connector_home",
        Denial::StoreFailure => "store",
    }
}

fn is_write(risk: &str) -> bool {
    known_risk(risk) != Some(Risk::Read)
}

fn risk_within_ceiling(risk: &str, ceiling: &str) -> bool {
    let (Some(risk), Some(ceiling)) = (known_risk(risk), known_risk(ceiling)) else {
        return false;
    };
    let rank = |risk| match risk {
        Risk::Read => 1,
        Risk::Write => 2,
        Risk::Destructive => 3,
    };
    rank(risk) <= rank(ceiling)
}

fn known_risk(risk: &str) -> Option<Risk> {
    match risk {
        "read" => Some(Risk::Read),
        "write" => Some(Risk::Write),
        "destructive" => Some(Risk::Destructive),
        _ => None,
    }
}

fn parse_risk(risk: &str) -> Risk {
    known_risk(risk).unwrap_or(Risk::Destructive)
}

fn risk_str(risk: Risk) -> &'static str {
    match risk {
        Risk::Read => "read",
        Risk::Write => "write",
        Risk::Destructive => "destructive",
    }
}

fn new_request_id() -> String {
    crate::storage::new_id("req")
}

#[cfg(test)]
#[path = "governance_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "governance_federated_tests.rs"]
mod federated_invoke_tests;

#[path = "governance_federated.rs"]
mod federated_invoke;

#[path = "governance_federated_cards.rs"]
mod federated_cards;
