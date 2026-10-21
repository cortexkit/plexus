//! Complete-mediation governance and RESERVE → REVALIDATE → DISPATCH.
//!
//! This module is deliberately transport-agnostic. It reads only redacted
//! projections from the store, resolves a credential through the trait seam,
//! and hands the short-lived payload to a transport implementation.

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
        if self.origin != RequestOrigin::Ordinary
            || self.authority_kind != AUTHORITY_INVOKE
            || !self.scope_grants_agent
        {
            return None;
        }
        self.scope.as_ref().and_then(CallScope::acting_agent)
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

/// Legacy envelope retained for callers that still match on the unconfigured
/// decision-plane denial. Prefer [`DecisionEnvelope`] when a plane is wired.
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
    pub grant: GrantRecord,
    pub agent_grant_pin: Option<PinnedGrant>,
    pub policy: Option<crate::storage::PolicyRecord>,
    pub policy_inputs: Option<PolicyInputs>,
    pub policy_effect: &'static str,
}

pub(crate) fn grant_denial(
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

/// The first changed dimension determines the refusal even when several move.
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
            decision_plane: self.decision_plane.clone(),
            seams: self.seams.clone(),
            scope_reader: self.scope_reader.clone(),
            consent_cards: self.consent_cards.clone(),
            consent_wait_hook: self.consent_wait_hook.clone(),
            connector_home_guard: self.connector_home_guard.clone(),
            freshness_check: self.freshness_check.clone(),
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
            decision_plane: None,
            seams: None,
            scope_reader: None,
            consent_cards: None,
            consent_wait_hook: None,
            connector_home_guard: None,
            freshness_check: None,
        }
    }

    /// Attach the freshness check [`Self::dispatch_checked`] runs between
    /// authorization and dispatch. It runs only for a call that has already
    /// been authorized, so a caller without authority never causes the vendor
    /// contact the check may make.
    pub fn with_freshness_check(mut self, check: FreshnessCheck) -> Self {
        self.freshness_check = Some(check);
        self
    }

    /// Dispatch an authorized reservation after confirming its target is
    /// still current. A failed check refuses the call as not sent, audited
    /// like every other pre-dispatch refusal. Used by facade invokes and by
    /// approved requests, which may run long after they were raised.
    pub fn dispatch_checked(&self, reservation: &Reservation) -> DispatchOutcome {
        if let Some(check) = &self.freshness_check {
            if let Err((code, message)) = check(reservation) {
                return self.refuse_before_transmit(reservation, &code, &message);
            }
        }
        self.revalidate_and_dispatch(reservation)
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

    /// Attach executor capacity management around pending consent waits.
    pub fn with_consent_wait_hook(mut self, hook: Arc<dyn ConsentWaitHook>) -> Self {
        self.consent_wait_hook = Some(hook);
        self
    }

    fn wait_for_consent(
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

    /// Read authorization state when the facade request starts and again just
    /// before sending, so an intervening handle, grant or policy change stops it.
    fn capture_authority_baseline(
        &self,
        connection: &ConnectionRecord,
        request: &AuthorizationRequest,
        action: &CatalogAction,
    ) -> Result<AuthorityBaseline, Denial> {
        let seams = self.seams.as_ref().ok_or(Denial::StoreFailure)?;
        let agent_id = request
            .attributed_agent_id
            .as_deref()
            .ok_or(Denial::Grant(GrantDenial::Missing))?;
        let handle = seams
            .handle_row(connection)?
            .ok_or(Denial::Credential(CredentialDenial::Missing))?;
        let (agent_grant_generation, module_grant_generation) =
            seams.grant_generations(connection, &request.principal, agent_id, &request.action)?;
        let inputs = seams.policy_inputs(connection, agent_id, action)?;
        let policy_effect_hash = jcs::jcs_sha256(&serde_json::json!([
            inputs.module_effect,
            inputs.agent_effect,
            action.ask_first,
        ]))
        .map_err(|_| Denial::StoreFailure)?;
        Ok(AuthorityBaseline {
            app_handle_generation: handle.app_handle_generation,
            repo_binding_generation: handle.repo_binding_generation,
            credential_generation: handle.credential_generation,
            handle_enabled: handle.enabled,
            agent_grant_generation,
            module_grant_generation,
            policy_effect_hash,
        })
    }

    pub fn store(&self) -> &Arc<PlexusStore> {
        &self.store
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
        self.evaluate_authority(&request, &connection, &action, crate::storage::now_ms())
            .map(|value| value.policy_effect)
    }

    /// Pure grant and policy evaluation shared by dispatch and restoration checks.
    pub fn evaluate_authority(
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

    pub fn authorize(&self, mut request: AuthorizationRequest) -> Result<Reservation, Denial> {
        if let Some(denial) = self.connector_home_denial() {
            return Err(denial);
        }
        let mut args_hash = jcs::jcs_sha256(&request.args).map_err(|_| Denial::StoreFailure)?;
        if crate::secret_input::contains_secret_input(&request.args) {
            let denial = Denial::CredentialMaterialForbidden;
            self.audit_denial(&request, &args_hash, None, None, None, &denial);
            return Err(denial);
        }
        if request.authority_kind == AUTHORITY_INVOKE {
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
        let connection = match if request.authority_kind == AUTHORITY_INVOKE {
            self.store
                .connection_for_invoke(&request.principal, &request.connection_id)
        } else {
            self.store
                .connection(&request.principal, &request.connection_id)
        } {
            Ok(Some(connection)) => connection,
            Ok(None) => {
                let denial = if request
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
        if let Some(reason) = connection_denial(&connection) {
            let denial = Denial::Connection(reason);
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
        let now = crate::storage::now_ms();
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
        let unlisted = if let Some(recipients) = recipients.as_ref() {
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
                Some(&grant),
                &denial,
            );
            return Err(denial);
        }
        let severity = effective_severity(&action, &connection.app_key, &self.store)
            .map_err(|_| Denial::StoreFailure)?;
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
        Ok(Reservation {
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
        })
    }

    fn report_unsent_plane_allow(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        args_hash: &str,
        decision_id: &str,
        denial: &Denial,
    ) {
        let Some(plane) = self.decision_plane.as_ref() else {
            return;
        };
        let report = OutcomeReport {
            decision_id: decision_id.into(),
            terminal: OutcomeTerminal::Refused {
                reason: denial.reason_code().into(),
            },
        };
        if !(0..OUTCOME_REPORT_ATTEMPTS).any(|_| plane.report_outcome(&report).is_ok()) {
            self.audit_authorization_decision(
                request,
                args_hash,
                Some(connection),
                Some(action),
                None,
                "decision_plane",
                "deny",
                "outcome_report_failed",
                None,
            );
        }
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

    /// Nothing was sent, so undo the dispatch marker `pre_transmit` wrote.
    /// Without this a transient credential refusal could not release its
    /// receipt claim for a same-nonce retry.
    fn abandon_marked_transmit(&self, reservation: &Reservation) {
        if let Some(seams) = self.seams.as_ref() {
            seams.abandon_transmit(reservation);
        }
    }

    /// Invalidate a reservation that will not be claimed, so it can never be
    /// claimed later. The approval behind it, if any, is left untouched: only
    /// the claim consumes an approval.
    fn abandon_unsent_reservation(&self, reservation: &Reservation) {
        if let Err(error) = self
            .store
            .abandon_reservation(&reservation.principal, &reservation.reservation_id)
        {
            eprintln!(error governance:
                "could not abandon unsent reservation {}: {error}",
                reservation.reservation_id
            );
        }
    }

    /// Everything dispatch needs before it may claim: the connection, what it
    /// presents to the vendor, and for a vault-bound credential the secret
    /// itself. On a refusal the reservation is abandoned unclaimed, so an
    /// approval behind it is not consumed, and the returned outcome says why.
    fn prepare_dispatch_credential(
        &self,
        reservation: &Reservation,
    ) -> Result<PreparedCredential, Box<DispatchOutcome>> {
        let refuse = |denial: CredentialDenial| {
            self.abandon_unsent_reservation(reservation);
            let reason = denial.reason_code().to_string();
            let outcome = self.dispatch_credential_denial(reservation, denial);
            Box::new(self.maybe_report_decision_outcome(
                reservation,
                outcome,
                OutcomeTerminal::Refused { reason },
            ))
        };
        let connection = match self
            .store
            .connection(&reservation.principal, &reservation.connection_id)
        {
            Ok(Some(connection)) => connection,
            Ok(None) => return Err(refuse(CredentialDenial::Missing)),
            Err(error) => {
                // A failed read is not a missing credential: the connection
                // may be fine, and a retry can succeed.
                eprintln!(error governance:
                    "connection {} unreadable at dispatch: {error}",
                    reservation.connection_id
                );
                self.abandon_unsent_reservation(reservation);
                self.audit_dispatch_denial(reservation, "store_failure");
                return Err(Box::new(self.maybe_report_decision_outcome(
                    reservation,
                    DispatchOutcome::not_sent(
                        reservation,
                        "store_failure".to_string(),
                        "the connection could not be read".to_string(),
                        Retryability::AutoRetryable,
                    ),
                    OutcomeTerminal::Refused {
                        reason: "store_failure".to_string(),
                    },
                )));
            }
        };
        let material = self.credential_material(&connection).map_err(refuse)?;
        let vault_credential = match &material {
            CredentialMaterial::Bound(handle) => {
                match handle.resolve(self.credential_source.as_ref()) {
                    Ok(credential) => Some(credential),
                    Err(error) => {
                        self.abandon_unsent_reservation(reservation);
                        let denial = credential_denial(&error);
                        self.audit_dispatch_denial_with_fingerprint(
                            reservation,
                            denial.reason_code(),
                            &handle.fingerprint(),
                        );
                        // A transient vault failure is worth retrying: this
                        // runs before the claim, so the approval behind the
                        // reservation, if any, was not consumed and a retry
                        // can still use it. A permanent failure stays terminal.
                        let retryability = if matches!(error, CredentialError::Transient(_)) {
                            Retryability::AutoRetryable
                        } else {
                            Retryability::Terminal
                        };
                        return Err(Box::new(self.maybe_report_decision_outcome(
                            reservation,
                            DispatchOutcome {
                                retry_after_ms: None,
                                error_signal: None,
                                reconciliation: None,
                                reservation_id: reservation.reservation_id.clone(),
                                transmission: TransmissionState::NotSent,
                                retryability,
                                outcome: TransportOutcome::NotSent {
                                    code: denial.reason_code().to_string(),
                                    message: "credential could not be resolved".to_string(),
                                },
                            },
                            OutcomeTerminal::Refused {
                                reason: denial.reason_code().to_string(),
                            },
                        )));
                    }
                }
            }
            CredentialMaterial::Waived | CredentialMaterial::GithubApp => None,
        };
        Ok(PreparedCredential {
            connection,
            material,
            vault_credential,
        })
    }
    /// Refuse an authorized reservation before anything is transmitted, with
    /// `code` and `message`, audited like every other pre-dispatch refusal.
    /// For checks the caller runs between authorization and dispatch.
    pub fn refuse_before_transmit(
        &self,
        reservation: &Reservation,
        code: &str,
        message: &str,
    ) -> DispatchOutcome {
        let mut outcome = self.deny_before_transmit(reservation, code.to_string());
        if let TransportOutcome::NotSent { message: text, .. } = &mut outcome.outcome {
            *text = message.to_string();
        }
        outcome
    }

    fn deny_before_transmit(&self, reservation: &Reservation, code: String) -> DispatchOutcome {
        self.abandon_unsent_reservation(reservation);
        self.audit_dispatch_denial(reservation, &code);
        self.maybe_report_decision_outcome(
            reservation,
            DispatchOutcome::not_sent(
                reservation,
                code.clone(),
                "authority changed before transmission".into(),
                Retryability::Terminal,
            ),
            OutcomeTerminal::Refused { reason: code },
        )
    }

    /// Re-check a stored approval's scope with the daemon at the point of
    /// execution, before the claim that would consume the approval and send.
    /// `None` means the same session is live with the authority the request
    /// was raised under, and the claim may proceed.
    ///
    /// Otherwise nothing is sent and this reservation is abandoned. A refusal
    /// retires the approval with its reason. A hold (the owner has not
    /// re-synced since a daemon restart, or the daemon did not answer) keeps
    /// the approval `approved` and marks it waiting, for the scheduler to try
    /// again, until the approval's own expiry; past that the hold becomes a
    /// `scope_unverifiable` refusal.
    fn recheck_approval_scope(
        &self,
        reservation: &Reservation,
        bound: &ApprovalScope,
    ) -> Option<DispatchOutcome> {
        let answer = match self.scope_reader.as_ref() {
            Some(reader) => reader.describe(&bound.owner, &bound.scope_ref),
            None => Err(ScopeReadError(
                "no daemon scope reader is configured".to_string(),
            )),
        };
        let verdict = approval_scope_verdict(bound, answer.as_ref());
        let (code, held) = match verdict {
            ApprovalScopeVerdict::Run => return None,
            ApprovalScopeVerdict::Refuse(code) => (code, false),
            ApprovalScopeVerdict::Hold(_) if crate::storage::now_ms() >= bound.expires_at => {
                (SCOPE_UNVERIFIABLE, false)
            }
            ApprovalScopeVerdict::Hold(reason) => (reason, true),
        };
        if let Err(error) = &answer {
            eprintln!(warn governance:
                "scope read for approval {} failed: {}",
                bound.request_id, error.0
            );
        }
        if let Err(error) = self
            .store
            .abandon_reservation(&reservation.principal, &reservation.reservation_id)
        {
            eprintln!(error governance:
                "could not abandon reservation {} after its approval's scope check: {error}",
                reservation.reservation_id
            );
        }
        if held {
            eprintln!(info governance:
                "approval {} held unsent ({code}): scope {}/{}@{} not confirmed yet",
                bound.request_id, bound.owner, bound.scope_ref, bound.scope_epoch
            );
            if let Err(error) = self
                .store
                .hold_scoped_approval(&reservation.principal, &bound.request_id)
            {
                eprintln!(error governance:
                    "could not mark approval {} as waiting: {error}",
                    bound.request_id
                );
            }
            self.audit_dispatch_denial(reservation, crate::scope::APPROVED_WAITING);
            return Some(DispatchOutcome::not_sent(
                reservation,
                crate::scope::APPROVED_WAITING.to_string(),
                format!("the approval is kept unsent until its scope is confirmed ({code})"),
                Retryability::AutoRetryable,
            ));
        }
        eprintln!(warn governance:
            "approval {} not run ({code}): scope {}/{}@{}",
            bound.request_id, bound.owner, bound.scope_ref, bound.scope_epoch
        );
        if let Err(error) =
            self.store
                .refuse_scoped_approval(&reservation.principal, &bound.request_id, code)
        {
            eprintln!(error governance:
                "could not retire approval {} after its scope refused it: {error}",
                bound.request_id
            );
        }
        self.audit_dispatch_denial(reservation, code);
        Some(self.maybe_report_decision_outcome(
            reservation,
            DispatchOutcome::not_sent(
                reservation,
                code.to_string(),
                "the approval's scope no longer allows it to run".to_string(),
                Retryability::Terminal,
            ),
            OutcomeTerminal::Refused {
                reason: code.to_string(),
            },
        ))
    }

    fn revalidate_receipt_authority(
        &self,
        reservation: &Reservation,
        connection: &ConnectionRecord,
    ) -> Option<DispatchOutcome> {
        let baseline = reservation.authority_baseline.as_ref()?;
        let current = self
            .store
            .catalog_action(
                &connection.principal,
                &connection.connection_id,
                &reservation.action,
            )
            .inspect_err(|error| eprintln!(error governance: "catalog unreadable during authority recheck: {error}"))
            .ok()
            .flatten()
            .and_then(|action| {
                let mut request = AuthorizationRequest::new(
                    &reservation.acting_principal,
                    &reservation.connection_id,
                    &reservation.action,
                    reservation.args.clone(),
                );
                request.attributed_agent_id.clone_from(&reservation.attributed_agent_id);
                self.capture_authority_baseline(connection, &request, &action)
                    .inspect_err(|error| eprintln!(error governance: "authority snapshot unreadable: {error:?}"))
                    .ok()
            });
        let dimension = current
            .as_ref()
            .map(|current| compare_authority_baseline(baseline, current))
            .unwrap_or(Err("authorization_snapshot_stale"));
        dimension.err().map(|dimension| {
            self.deny_before_transmit(reservation, format!("stale_authority{{{dimension}}}"))
        })
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
        let claimable = !stale && crate::storage::now_ms() < reservation.expires_at_ms;
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
        let claimed = if claimable {
            match self
                .store
                .claim_reservation(&reservation_record(reservation), &reservation.request_id)
            {
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
            let expired = crate::storage::now_ms() >= reservation.expires_at_ms;
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
        let response = if reservation.origin == RequestOrigin::Facade {
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

    fn maybe_report_decision_outcome(
        &self,
        reservation: &Reservation,
        outcome: DispatchOutcome,
        terminal: OutcomeTerminal,
    ) -> DispatchOutcome {
        let Some(decision_id) = reservation.decision_id.as_ref() else {
            return outcome;
        };
        let Some(plane) = self.decision_plane.as_ref() else {
            return outcome;
        };
        let report = OutcomeReport {
            decision_id: decision_id.clone(),
            terminal,
        };
        // Count what actually happened rather than reporting the constant. The
        // two agree today only because the loop always runs to exhaustion
        // before reaching the audit — a coupling nothing enforces, so the first
        // early `break` (a permanent error not worth retrying, say) would leave
        // the audit claiming three attempts for a report tried once. An audit
        // row is read during reconciliation with the decision plane, where the
        // number of attempts is evidence about how hard the outcome was chased.
        let mut last_error = None;
        let mut attempts = 0_i64;
        for _ in 0..OUTCOME_REPORT_ATTEMPTS {
            attempts += 1;
            match plane.report_outcome(&report) {
                Ok(()) => return outcome,
                Err(error) => last_error = Some(error),
            }
        }
        let detail = last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        if let Err(error) = self.store.append_audit(&AuditRecord { principal: reservation.principal.clone(),
        actor: reservation.actor.clone(),
        acting_principal: reservation.acting_principal.clone(),
        agent_id: reservation.attributed_agent_id.clone(), app_handle_id: if reservation.origin == RequestOrigin::Facade { reservation.bound_agent_handle.clone() } else { None }, agent_handle: reservation.bound_agent_handle.clone(), connection_id: Some(reservation.connection_id.clone()),
        app_key: Some(reservation.app_key.clone()),
        action: Some(reservation.action.clone()),
        risk: Some(risk_str(reservation.risk).to_string()),
        severity: Some(reservation.severity.as_str().to_string()),
        decision: if matches!(report.terminal, OutcomeTerminal::Executed { .. } | OutcomeTerminal::OutcomeUnknown { .. }) { "allow" } else { "deny" }.to_string(),
        reason_code: "outcome_report_failed".to_string(),
        gate: Some("decision_plane".to_string()),
        args_redaction_summary: Some(format!("decision_id:{decision_id}; detail:{detail}")),
        outcome: Some("report_failed".to_string()),
        latency_ms: None,
        request_id: Some(reservation.request_id.clone()),
        credential_fingerprint: Some(reservation.credential_fingerprint.clone()),
        provider_account_fingerprint: None,
        attempt_no: Some(attempts),
        vendor_request_id: None,
        idempotency_key_fingerprint: reservation.receipt.as_ref().and_then(|claim| {
            self.store
                .github_receipt(&claim.agent_id, &claim.request_nonce)
                .inspect_err(|error| eprintln!(error governance: "receipt fingerprint unreadable: {error}"))
                .ok()
                .flatten()
                .map(|row| row.request_fingerprint)
        }),
        response_class: None,
        reconciliation_of: None, }) {
            eprintln!(error governance: "audit append failed: outcome_report_failed principal={:?} actor={:?} request_id={:?}: {error}", reservation.principal, reservation.actor, reservation.request_id);
        }
        outcome
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

    /// Re-authorize an approved request in full and dispatch it through the
    /// fenced claim. A request raised under a scope is re-authorized under
    /// that scope, so a call that was made as an agent still needs the
    /// agent's grant, and its scope is re-checked before the claim.
    fn dispatch_approved(
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
                // the approval for an explicit recall instead of queuing a send
                // after the caller has moved on.
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

    fn request_admin(&self, request: &ActionRequestRecord, decider: &str) -> Result<bool, Denial> {
        let action = self
            .store
            .catalog_action(&request.principal, &request.connection_id, &request.action)
            .map_err(|_| Denial::StoreFailure)?
            .ok_or(Denial::Catalog(CatalogDenial::NotFound))?;
        let now = crate::storage::now_ms();
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

    fn audit_approval_resolution(&self, request: &ActionRequestRecord, actor: &str, reason: &str) {
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

    fn audited_refusal(&self, request: &AuthorizationRequest, denial: Denial) -> Denial {
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

    /// Try again every approval held unsent because its scope could not be
    /// confirmed, at most `limit` per call. Each runs the same full
    /// re-authorization and scope re-check as when it was approved, so one
    /// whose scope is now live is sent once, one whose scope has ended is
    /// retired, and one past its own expiry is refused `scope_unverifiable`.
    /// Returns how many were tried.
    pub fn retry_waiting_approvals(&self, limit: usize) -> usize {
        let waiting = match self.store.waiting_scoped_approvals(limit) {
            Ok(waiting) => waiting,
            Err(error) => {
                eprintln!(error governance: "could not list approvals waiting on a scope: {error}");
                return 0;
            }
        };
        let tried = waiting.len();
        for request in waiting {
            let principal = request.principal.clone();
            let request_id = request.request_id.clone();
            if request.expires_at <= crate::storage::now_ms() {
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

    /// File the consent card for a call just held for approval, or refresh
    /// the card when the same call is held again under its existing request.
    /// A failure is logged and changes nothing else: the request stays
    /// pending for the operator and the call's reply is the same.
    fn file_consent_card(
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
        let expires_in_ms = request.expires_at.saturating_sub(crate::storage::now_ms());
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
    fn service_label(&self, app_key: &str) -> String {
        self.store
            .cached_manifest(app_key)
            .ok()
            .and_then(|manifest| {
                let name = manifest.name.trim();
                (!name.is_empty()).then(|| name.to_owned())
            })
            .unwrap_or_else(|| app_key.to_string())
    }

    fn withdraw_consent_card(&self, request: &ActionRequestRecord) {
        if let Some(cards) = self.consent_cards.as_ref() {
            cards.withdraw(request);
        }
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

    fn consent_route_denial(
        &self,
        action: &str,
        error: &crate::consent_card::ElicitationCallError,
    ) -> Denial {
        eprintln!(warn consent: "consent_unavailable for action {action} ({})", error.code());
        Denial::ConsentUnavailable {
            action: action.into(),
        }
    }

    fn finish_consent(
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
                        } else if current.expires_at <= crate::storage::now_ms()
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

    /// True when the vendor's reviewed manifest declares `auth.mode = none`.
    ///
    /// Delegates to the store rather than re-deriving it, because the ceremony
    /// asks the same question when deciding whether to demand a credential reference. Two
    /// implementations of "does this vendor need a credential" can drift, and
    /// the drift would be silent and asymmetric: an enrollment that skipped the
    /// credential while dispatch still demanded one produces a permanently unusable
    /// connection, and the reverse would call a credentialed vendor
    /// anonymously.
    ///
    /// A manifest that cannot be read or parsed reports `false` — requiring a
    /// credential — so a catalog problem can never widen access.
    fn manifest_is_credential_free(&self, app_key: &str) -> bool {
        self.store
            .manifest_requires_no_credential(app_key)
            .unwrap_or(false)
    }

    /// What a call on this connection must present to the vendor: either the
    /// stored vault reference, or the waiver for a vendor that needs none.
    ///
    /// Authorization and dispatch both ask this question, and this is the only
    /// place either of them answers it. Two implementations would drift, and
    /// the drift is silent in both directions: a dispatch that demanded a
    /// credential an enrollment never stored leaves a connectable vendor
    /// permanently uncallable, and the reverse calls a credentialed vendor
    /// anonymously.
    ///
    /// Only the vendor's REVIEWED MANIFEST may waive the credential. A missing
    /// binding alone never permits anonymous access: the manifest must declare
    /// no auth or an optional key. If an optional key is bound, it must resolve;
    /// a vault failure must not silently downgrade that connection to anonymous.
    fn credential_material(
        &self,
        connection: &ConnectionRecord,
    ) -> Result<CredentialMaterial, CredentialDenial> {
        if self.manifest_is_credential_free(&connection.app_key) {
            return Ok(CredentialMaterial::Waived);
        }
        if !connection.has_credential_binding
            && self
                .store
                .manifest_has_optional_credential(&connection.app_key)
                .unwrap_or(false)
        {
            return Ok(CredentialMaterial::Waived);
        }
        if let Some(seams) = &self.seams {
            match seams.handle_row(connection) {
                // GitHub App authority is prepared by the dedicated App provider,
                // not by the connection's vault-reference binding resolver.
                Ok(Some(_)) => return Ok(CredentialMaterial::GithubApp),
                Err(error) => {
                    eprintln!(error governance: "handle authority unreadable: {error:?}");
                    return Err(CredentialDenial::StoreUnavailable);
                }
                Ok(None) => {}
            }
        }
        match self
            .store
            .connection_credential_binding(&connection.principal, &connection.connection_id)
        {
            Ok(Some(binding)) => Ok(CredentialMaterial::Bound(binding)),
            Ok(None) => Err(CredentialDenial::Missing),
            Err(error) => {
                eprintln!(error governance: "connection credential binding unreadable: {error}");
                Err(CredentialDenial::StoreUnavailable)
            }
        }
    }

    fn resolve_credential(
        &self,
        request: &AuthorizationRequest,
        connection: &ConnectionRecord,
    ) -> Result<(String, ResolvedCredential), Denial> {
        if let Some(seams) = &self.seams {
            if let Some(handle) = seams.handle_row(connection)? {
                let encoded = serde_json::to_vec(&(
                    &handle.credential_reference,
                    handle.credential_generation,
                ))
                .map_err(|_| Denial::StoreFailure)?;
                return Ok((fingerprint(&encoded), ResolvedCredential::anonymous()));
            }
            if request.origin == RequestOrigin::Facade {
                return Err(Denial::Credential(CredentialDenial::Missing));
            }
        }
        let handle = match self
            .credential_material(connection)
            .map_err(Denial::Credential)?
        {
            CredentialMaterial::GithubApp => {
                return Err(Denial::Credential(CredentialDenial::Missing))
            }
            CredentialMaterial::Waived => {
                return Ok((
                    anonymous_credential_fingerprint(),
                    ResolvedCredential::anonymous(),
                ));
            }
            CredentialMaterial::Bound(handle) => handle,
        };
        let handle_fingerprint = handle.fingerprint();
        // Authorization binds the reservation to the reference, not a token
        // snapshot. Read the vault only at dispatch so rotation or revocation
        // since authorization is observed before sending to the vendor.
        Ok((handle_fingerprint, ResolvedCredential::anonymous()))
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_authorization_decision(
        &self,
        request: &AuthorizationRequest,
        args_hash: &str,
        connection: Option<&ConnectionRecord>,
        action: Option<&CatalogAction>,
        grant: Option<&GrantRecord>,
        gate: &str,
        decision: &str,
        reason: &str,
        credential_fingerprint: Option<String>,
    ) {
        let record = AuditRecord {
            principal: connection
                .map(|value| value.principal.clone())
                .unwrap_or_else(|| request.principal.clone()),
            actor: request.actor.clone(),
            acting_principal: request.principal.clone(),
            agent_id: request.attributed_agent_id.clone(),
            app_handle_id: if request.origin == RequestOrigin::Facade {
                request.bound_agent_handle.clone()
            } else {
                None
            },
            agent_handle: request.bound_agent_handle.clone(),
            connection_id: connection.map(|value| value.connection_id.clone()),
            app_key: connection.map(|value| value.app_key.clone()),
            action: Some(request.action.clone()),
            risk: action.map(|value| value.risk.clone()),
            severity: action
                .and_then(|action| {
                    connection.and_then(|connection| {
                        effective_severity(action, &connection.app_key, &self.store).ok()
                    })
                })
                .map(|severity| severity.as_str().to_string()),
            decision: decision.to_string(),
            reason_code: reason.to_string(),
            gate: Some(gate.to_string()),
            args_redaction_summary: Some(self.recipient_audit_summary(
                args_hash,
                connection.map(|connection| connection.app_key.as_str()),
                &request.action,
                &request.args,
            )),
            outcome: None,
            latency_ms: None,
            request_id: Some(request.request_id.clone()),
            credential_fingerprint,
            provider_account_fingerprint: None,
            attempt_no: Some(1),
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: grant.map(|value| value.authority_kind.clone()),
            reconciliation_of: None,
        };
        if let Err(error) = self.store.append_audit_relayed(
            &record,
            request.scope.as_ref(),
            request.relay_origin.as_ref(),
            request.on_behalf_of_agent.as_deref(),
        ) {
            eprintln!(error governance: "audit append failed: authorization decision={decision:?} reason={reason:?} principal={:?} actor={:?} acting_principal={:?} request_id={:?} action={:?}: {error}", connection.map(|value| value.principal.as_str()).unwrap_or(&request.principal), request.actor, request.principal, request.request_id, request.action);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_denial(
        &self,
        request: &AuthorizationRequest,
        args_hash: &str,
        connection: Option<&ConnectionRecord>,
        action: Option<&CatalogAction>,
        grant: Option<&GrantRecord>,
        denial: &Denial,
    ) {
        self.audit_authorization_decision(
            request,
            args_hash,
            connection,
            action,
            grant,
            gate_for_denial(denial),
            "deny",
            denial.reason_code(),
            None,
        );
    }

    fn audit_dispatch_denial(&self, reservation: &Reservation, reason: &str) {
        self.audit_dispatch_denial_with_fingerprint(
            reservation,
            reason,
            &reservation.credential_fingerprint,
        );
    }

    fn audit_dispatch_denial_with_fingerprint(
        &self,
        reservation: &Reservation,
        reason: &str,
        credential_fingerprint: &str,
    ) {
        if let Err(error) = self.store.append_audit_relayed(
            &AuditRecord {
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
                risk: Some(risk_str(reservation.risk).to_string()),
                severity: Some(reservation.severity.as_str().to_string()),
                decision: "deny".to_string(),
                reason_code: reason.to_string(),
                gate: Some("dispatch".to_string()),
                args_redaction_summary: Some(self.recipient_audit_summary(
                    &reservation.approved_args_hash,
                    Some(&reservation.app_key),
                    &reservation.action,
                    &reservation.approved_args,
                )),
                outcome: Some("not_sent".to_string()),
                latency_ms: None,
                request_id: Some(reservation.request_id.clone()),
                credential_fingerprint: Some(credential_fingerprint.to_string()),
                provider_account_fingerprint: None,
                attempt_no: Some(1),
                vendor_request_id: None,
                idempotency_key_fingerprint: None,
                response_class: None,
                reconciliation_of: None,
            },
            reservation.scope.as_ref(),
            reservation.relay_origin.as_ref(),
            reservation.on_behalf_of_agent.as_deref(),
        ) {
            eprintln!(error governance: "audit append failed: dispatch denial reason={reason:?} principal={:?} actor={:?} request_id={:?}: {error}", reservation.principal, reservation.actor, reservation.request_id);
        }
    }

    fn dispatch_credential_denial(
        &self,
        reservation: &Reservation,
        denial: CredentialDenial,
    ) -> DispatchOutcome {
        self.audit_dispatch_denial(reservation, denial.reason_code());
        DispatchOutcome::not_sent(
            reservation,
            denial.reason_code().to_string(),
            "credential could not be resolved".to_string(),
            if matches!(
                denial,
                CredentialDenial::Transient(_) | CredentialDenial::StoreUnavailable
            ) {
                Retryability::AutoRetryable
            } else {
                Retryability::Terminal
            },
        )
    }

    fn audit_dispatch_result(&self, reservation: &Reservation, response: &TransportResponse) {
        let outcome = match response.transmission {
            TransmissionState::NotSent => "not_sent",
            TransmissionState::Sent => {
                if response.response.is_some() {
                    "completed"
                } else {
                    "failed"
                }
            }
            TransmissionState::OutcomeUnknown => "unknown",
        };
        if let Err(error) = self.store.append_audit_relayed(
            &AuditRecord { principal: reservation.principal.clone(),
            actor: reservation.actor.clone(),
            acting_principal: reservation.acting_principal.clone(),
            agent_id: reservation.attributed_agent_id.clone(), app_handle_id: if reservation.origin == RequestOrigin::Facade { reservation.bound_agent_handle.clone() } else { None }, agent_handle: reservation.bound_agent_handle.clone(), connection_id: Some(reservation.connection_id.clone()),
            app_key: Some(reservation.app_key.clone()),
            action: Some(reservation.action.clone()),
            risk: Some(risk_str(reservation.risk).to_string()),
            severity: Some(reservation.severity.as_str().to_string()),
            decision: "allow".to_string(),
            reason_code: "dispatched".to_string(),
            gate: Some("dispatch".to_string()),
            args_redaction_summary: Some(self.recipient_audit_summary(
                &reservation.approved_args_hash,
                Some(&reservation.app_key),
                &reservation.action,
                &reservation.approved_args,
            )),
            outcome: Some(outcome.to_string()),
            latency_ms: None,
            request_id: Some(reservation.request_id.clone()),
            credential_fingerprint: Some(reservation.credential_fingerprint.clone()),
            provider_account_fingerprint: None,
            attempt_no: Some(1),
            vendor_request_id: response.vendor_request_id.clone(),
            idempotency_key_fingerprint: reservation.receipt.as_ref().and_then(|claim| {
                self.store
                    .github_receipt(&claim.agent_id, &claim.request_nonce)
                    .inspect_err(|error| eprintln!(error governance: "receipt fingerprint unreadable: {error}"))
                    .ok()
                    .flatten()
                    .map(|row| row.request_fingerprint)
            }),
            response_class: response.error_code.clone(),
            reconciliation_of: None, },
            reservation.scope.as_ref(),
            reservation.relay_origin.as_ref(),
            reservation.on_behalf_of_agent.as_deref(),
        ) {
            eprintln!(error governance: "audit append failed: dispatch result outcome={outcome:?} principal={:?} actor={:?} request_id={:?}: {error}", reservation.principal, reservation.actor, reservation.request_id);
        }
    }

    /// Keep the message text out of the audit: only normalized recipients are
    /// recorded beside the existing argument hash, preserving recipient
    /// accountability without storing the private message text.
    fn recipient_audit_summary(
        &self,
        hash: &str,
        app_key: Option<&str>,
        action: &str,
        args: &Value,
    ) -> String {
        let mut summary = format!("args_hash:{hash}");
        if let Some(app_key) = app_key {
            if let Ok(Some(pointers)) = self.store.recipient_pointers(app_key, action) {
                match crate::recipients::collect_recipients(&pointers, args) {
                    Ok(recipients) => {
                        summary.push_str(&format!(" recipients:{}", serde_json::json!(recipients)))
                    }
                    Err(_) => summary.push_str(" recipients:invalid"),
                }
            }
        }
        summary
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
    connection: ConnectionRecord,
    material: CredentialMaterial,
    /// The secret for `CredentialMaterial::Bound`, fetched from the vault;
    /// `None` for the other kinds.
    vault_credential: Option<ResolvedCredential>,
}

fn action_label<'a>(action: &'a CatalogAction, fallback: &'a str) -> &'a str {
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

fn reservation_record(reservation: &Reservation) -> ReservationRecord {
    ReservationRecord {
        reservation_id: reservation.reservation_id.clone(),
        principal: reservation.principal.clone(),
        connection_id: reservation.connection_id.clone(),
        action: reservation.action.clone(),
        grant_id: reservation.grant_id.clone(),
        snapshot: reservation.snapshot.clone(),
        approved_args_hash: reservation.approved_args_hash.clone(),
        schema_hash: reservation.schema_hash.clone(),
        expires_at: reservation.expires_at_ms,
        status: "reserved".to_string(),
        agent_grant: reservation.agent_grant.clone(),
    }
}

/// The scope a stored approval request was raised under, in the form the
/// execution-time re-check takes. `None` for a request raised with no scope.
fn approval_scope_of(request: &ActionRequestRecord) -> Option<ApprovalScope> {
    let scope = request.scope.as_ref()?;
    Some(ApprovalScope {
        request_id: request.request_id.clone(),
        owner: scope.owner.clone(),
        scope_ref: scope.scope_ref.clone(),
        scope_epoch: scope.scope_epoch,
        agent_id: scope.agent_id.clone(),
        acted_as_agent: scope.to_call_scope().acting_agent().is_some(),
        expires_at: request.expires_at,
    })
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

fn effective_severity(
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
mod tests {
    use super::*;
    use crate::credentials::StubCredentialSource;
    use crate::storage::{CatalogActionInput, GrantInput};
    use crate::transport::MockTransport;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    fn ordinary_test_engine() -> GovernanceEngine<StubCredentialSource, MockTransport> {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().facade_only = false;
        engine
    }

    fn ordinary_request() -> AuthorizationRequest {
        AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"repo":"o/r"}),
        )
    }

    fn pending_request(
        engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
        ceiling: &str,
        selectors: Vec<String>,
    ) -> String {
        engine
            .store()
            .insert_grant(&GrantInput {
                grant_id: "admin".into(),
                principal: "direct".into(),
                connection_id: "connection".into(),
                grantee_principal: "operator".into(),
                risk_ceiling: ceiling.into(),
                action_selectors: selectors,
                authority_kind: "connection_admin".into(),
                expires_at: None,
            })
            .unwrap();
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        engine
            .store()
            .create_action_request(
                "direct",
                "connection",
                "write_item",
                &ordinary_request().args,
                &action.schema_hash,
                "direct",
                crate::storage::now_ms() + 60_000,
                None,
                None,
            )
            .unwrap()
    }

    #[test]
    fn severe_ask_first_refuses_before_creating_consent() {
        let engine = ordinary_test_engine();
        install_system_manifest(engine.store(), "mock", "S3");
        engine
            .store()
            .set_policy("direct", "connection", "*", "ask_first", None)
            .unwrap();
        assert!(matches!(
            engine.authorize(ordinary_request()),
            Err(Denial::NeedsDecisionPlane(_))
        ));
        assert!(engine
            .store()
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn poll_authority_cannot_create_interactive_approval() {
        let engine = ordinary_test_engine();
        engine
            .store()
            .insert_grant(&GrantInput {
                grant_id: "poll".into(),
                principal: "direct".into(),
                connection_id: "connection".into(),
                grantee_principal: "direct".into(),
                risk_ceiling: "write".into(),
                action_selectors: vec!["*".into()],
                authority_kind: AUTHORITY_POLL.into(),
                expires_at: None,
            })
            .unwrap();
        engine
            .store()
            .set_policy("direct", "connection", "*", "ask_first", None)
            .unwrap();
        assert_eq!(
            engine.authorize(ordinary_request().for_poll("subscription")),
            Err(Denial::Policy(PolicyDenial::AskFirst))
        );
        assert!(engine
            .store()
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn internal_calls_refuse_recursive_credential_material() {
        let engine = ordinary_test_engine();
        let request = AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"nested":{"api_key":"never-forward"}}),
        );
        assert_eq!(
            engine.authorize(request),
            Err(Denial::CredentialMaterialForbidden)
        );
        assert!(engine.transport().requests().is_empty());
    }

    #[test]
    fn decision_and_dispatch_audit_use_effective_severity() {
        let engine = ordinary_test_engine();
        let reservation = engine.authorize(ordinary_request()).unwrap();
        let rows = engine.store().list_audit("direct").unwrap();
        let row = rows
            .iter()
            .find(|row| row.reason_code == "credential_resolved")
            .unwrap();
        assert_eq!(row.severity.as_deref(), Some(reservation.severity.as_str()));
        assert_eq!(row.severity.as_deref(), Some("S2"));
    }

    #[test]
    fn terminal_preclaim_refusal_keeps_approval_retryable() {
        let engine = ordinary_test_engine().with_freshness_check(Arc::new(|_| {
            Err(("catalog_stale_write".into(), "refresh unavailable".into()))
        }));
        let id = pending_request(&engine, "write", vec!["*".into()]);
        let outcome = engine.approve_request("direct", &id, "operator").unwrap();
        assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
        let row = engine
            .store()
            .action_request("direct", &id)
            .unwrap()
            .unwrap();
        assert_eq!(
            row.scope_outcome.as_deref(),
            Some(crate::scope::APPROVED_WAITING)
        );
    }

    #[test]
    fn admin_approval_and_denial_honor_selector_and_risk() {
        for (risk, selector) in [("read", "*"), ("write", "other_action")] {
            let engine = ordinary_test_engine();
            let id = pending_request(&engine, risk, vec![selector.into()]);
            assert_eq!(
                engine.approve_request("direct", &id, "operator"),
                Err(Denial::Grant(GrantDenial::ConnectionAdminRequired))
            );
            assert_eq!(
                engine.deny_request("direct", &id, "operator"),
                Err(Denial::Grant(GrantDenial::ConnectionAdminRequired))
            );
        }
    }

    #[test]
    fn operator_denial_is_in_append_only_audit() {
        let engine = ordinary_test_engine();
        let id = pending_request(&engine, "write", vec!["*".into()]);
        assert!(engine.deny_request("direct", &id, "operator").unwrap());
        assert!(engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .any(|row| row.reason_code == "approval_denied" && row.actor == "operator"));
    }

    #[test]
    fn consent_denial_expiry_and_withdrawal_are_audited() {
        for (state, code) in [
            ("answered", "consent_denied"),
            ("expired", "consent_expired"),
            ("withdrawn", "consent_withdrawn"),
        ] {
            let engine = ordinary_test_engine();
            let id = pending_request(&engine, "write", vec!["*".into()]);
            let mut request = engine
                .store()
                .action_request("direct", &id)
                .unwrap()
                .unwrap();
            request.elicitation_id = Some("card".into());
            let digest = request.args_hash.clone();
            let scope = CallScope {
                owner: "direct".into(),
                scope_ref: "session".into(),
                scope_epoch: 1,
                kind: None,
                parent: None,
                parent_state: None,
                agent_id: None,
                flow_id: None,
                delegates: false,
                owner_authorized: true,
            };
            let result = engine.finish_consent(request, &scope, serde_json::json!({"elicitation_id":"card", "kind":"consent", "args_digest":digest, "state":state, "answered_choice_id":"deny"}));
            assert!(matches!(result, Err(Denial::ConsentRefused { .. })));
            assert!(engine
                .store()
                .list_audit("direct")
                .unwrap()
                .iter()
                .any(|row| row.reason_code == code && row.actor == "consent_card:card"));
        }
    }

    #[test]
    fn shape_reuse_never_crosses_requesters() {
        let engine = ordinary_test_engine();
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        let mut ids = Vec::new();
        for requester in ["carrier-a", "carrier-b"] {
            ids.push(
                engine
                    .store()
                    .ensure_action_request(
                        "direct",
                        "connection",
                        "write_item",
                        &serde_json::json!({"repo":"o/r"}),
                        &action.schema_hash,
                        requester,
                        crate::storage::now_ms() + 60_000,
                        None,
                        None,
                    )
                    .unwrap(),
            );
        }
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn approved_routing_is_persistent_and_immutable() {
        let engine = ordinary_test_engine();
        let id = pending_request(&engine, "write", vec!["*".into()]);
        let routing = serde_json::json!({"repository":"o/r", "tool":"github_read", "supports_per_call_approval":true});
        assert!(engine
            .store()
            .bind_action_request_routing("direct", &id, &routing)
            .unwrap());
        assert_eq!(
            engine
                .store()
                .action_request_routing("direct", &id)
                .unwrap(),
            Some(routing)
        );
        assert!(!engine
            .store()
            .bind_action_request_routing(
                "direct",
                &id,
                &serde_json::json!({"repository":"other/repo"})
            )
            .unwrap());
        engine
            .store()
            .decide_action_request("direct", &id, true, "operator")
            .unwrap();
        let request = ordinary_request().approved_from(id);
        assert_eq!(
            engine.authorize(request),
            Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch))
        );
    }

    #[test]
    fn approved_dispatch_restores_internal_repository() {
        let (engine, seams) = facade_test_engine();
        {
            let mut state = seams.0.lock().unwrap();
            state.facade_only = false;
            state.expected_repository = Some("o/r".into());
        }
        let id = pending_request(&engine, "write", vec!["*".into()]);
        let routing = serde_json::json!({"repository":"o/r", "tool":"github_read", "supports_per_call_approval":true});
        engine
            .store()
            .bind_action_request_routing("direct", &id, &routing)
            .unwrap();
        let outcome = engine.approve_request("direct", &id, "operator").unwrap();
        assert!(matches!(
            outcome.outcome,
            TransportOutcome::Completed { .. }
        ));
        assert_eq!(engine.transport().requests().len(), 1);
    }

    #[test]
    fn unknown_effects_and_statuses_fail_closed() {
        assert_eq!(compose_policy_effect("misspelled", Some("allow")), "block");
        assert_eq!(RequestStatus::of("approvd"), RequestStatus::Unknown);
        assert_ne!(RequestStatus::of("approvd"), RequestStatus::Approved);
    }

    #[test]
    fn stale_arguments_and_grant_hash_abandon_reservations() {
        for grant_hash in [false, true] {
            let engine = ordinary_test_engine();
            let mut reservation = engine.authorize(ordinary_request()).unwrap();
            if grant_hash {
                reservation.decision_id = Some("decision".into());
                reservation.grant_hash = Some("wrong".into());
            } else {
                reservation.args = serde_json::json!({"repo":"changed"});
            }
            engine.revalidate_and_dispatch(&reservation);
            assert_eq!(
                engine
                    .store()
                    .reservation("direct", &reservation.reservation_id)
                    .unwrap()
                    .unwrap()
                    .status,
                "invalidated"
            );
        }
    }

    #[test]
    fn waiting_approval_batches_back_off_between_attempts() {
        let engine = ordinary_test_engine();
        let id = pending_request(&engine, "write", vec!["*".into()]);
        engine
            .store()
            .decide_action_request("direct", &id, true, "operator")
            .unwrap();
        engine.store().hold_scoped_approval("direct", &id).unwrap();
        assert_eq!(
            engine.store().waiting_scoped_approvals(10).unwrap().len(),
            1
        );
        assert!(engine
            .store()
            .waiting_scoped_approvals(10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn waiting_scope_precheck_does_not_reserve_or_audit_again() {
        let scratch = crate::test_scratch::Scratch::file("waiting-scope-precheck", "store.db");
        let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
        seams.0.lock().unwrap().facade_only = false;
        let scope = CallScope {
            owner: "direct".into(),
            scope_ref: "session".into(),
            scope_epoch: 1,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: None,
            flow_id: None,
            delegates: false,
            owner_authorized: true,
        };
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        let id = engine
            .store()
            .create_action_request(
                "direct",
                "connection",
                "write_item",
                &ordinary_request().args,
                &action.schema_hash,
                "direct",
                crate::storage::now_ms() + 60_000,
                Some(&scope),
                None,
            )
            .unwrap();
        engine
            .store()
            .decide_action_request("direct", &id, true, "operator")
            .unwrap();
        engine.store().hold_scoped_approval("direct", &id).unwrap();
        assert_eq!(engine.retry_waiting_approvals(10), 1);
        let count: i64 = rusqlite::Connection::open(scratch.path())
            .unwrap()
            .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count, 0,
            "an unconfirmed scope must not create another reservation"
        );
        assert!(engine.store().list_audit("direct").unwrap().is_empty());
    }

    #[test]
    fn missing_connection_or_action_invalidates_claim_without_store_error() {
        for table in ["connections", "catalog_actions"] {
            let scratch = crate::test_scratch::Scratch::file("claim-missing-row", "store.db");
            let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
            seams.0.lock().unwrap().facade_only = false;
            let reservation = engine.authorize(ordinary_request()).unwrap();
            rusqlite::Connection::open(scratch.path())
                .unwrap()
                .execute(&format!("DELETE FROM {table}"), [])
                .unwrap();
            assert!(!engine
                .store()
                .claim_reservation(&reservation_record(&reservation), "attempt")
                .unwrap());
            assert_eq!(
                engine
                    .store()
                    .reservation("direct", &reservation.reservation_id)
                    .unwrap()
                    .unwrap()
                    .status,
                "invalidated"
            );
        }
    }

    #[test]
    fn revoked_agent_identity_is_preserved_in_immutable_snapshot() {
        let scratch = crate::test_scratch::Scratch::file("agent-revocation", "store.db");
        let engine = hash_test_engine_at(scratch.path().to_str().unwrap());
        let conn = rusqlite::Connection::open(scratch.path()).unwrap();
        conn.execute(
            "UPDATE grants SET agent_id='agent-a' WHERE grant_id='grant'",
            [],
        )
        .unwrap();
        assert!(engine.store().revoke_grant("direct", "grant").unwrap());
        let agent: String = conn
            .query_row(
                "SELECT agent_id FROM grant_revocations WHERE grant_id='grant'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(agent, "agent-a");
    }

    #[test]
    fn claim_pins_policy_identity_not_only_generation() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().facade_only = false;
        engine
            .store()
            .set_policy("direct", "connection", "*", "allow", None)
            .unwrap();
        let reservation = engine
            .authorize(AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            ))
            .unwrap();
        engine
            .store()
            .set_policy("direct", "connection", "write_item", "block", None)
            .unwrap();
        assert!(!engine
            .store()
            .claim_reservation(&reservation_record(&reservation), "attempt")
            .unwrap());
        assert!(engine.transport().requests().is_empty());
    }

    #[test]
    fn claim_rechecks_module_and_agent_expiry() {
        for agent in [false, true] {
            let scratch = crate::test_scratch::Scratch::file("claim-expiry", "store.db");
            let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
            seams.0.lock().unwrap().facade_only = false;
            let reservation = engine
                .authorize(AuthorizationRequest::new(
                    "direct",
                    "connection",
                    "write_item",
                    serde_json::json!({"repo":"o/r"}),
                ))
                .unwrap();
            let mut record = reservation_record(&reservation);
            if agent {
                record.agent_grant = Some(crate::storage::PinnedGrant {
                    grant_id: "agent-grant".into(),
                    generation: 1,
                });
            }
            let conn = rusqlite::Connection::open(scratch.path()).unwrap();
            if agent {
                conn.execute("INSERT INTO grants(grant_id,principal,connection_id,grantee_principal,risk_ceiling,action_selectors,authority_kind,expires_at,generation,created_at_ms,agent_id) VALUES('agent-grant','direct','connection','direct','write','[\"write_item\"]','invoke',1,1,1,'agent-a')", []).unwrap();
                conn.execute("UPDATE reservations SET agent_grant_id='agent-grant'", [])
                    .unwrap();
            } else {
                conn.execute("UPDATE grants SET expires_at=1 WHERE grant_id='grant'", [])
                    .unwrap();
            }
            assert!(
                !engine
                    .store()
                    .claim_reservation(&record, "attempt")
                    .unwrap(),
                "agent={agent}"
            );
        }
    }

    #[test]
    fn module_matching_never_uses_an_agent_row() {
        let scratch = crate::test_scratch::Scratch::file("module-grant-layer", "store.db");
        let engine = hash_test_engine_at(scratch.path().to_str().unwrap());
        rusqlite::Connection::open(scratch.path())
            .unwrap()
            .execute(
                "UPDATE grants SET agent_id='agent-a' WHERE grant_id='grant'",
                [],
            )
            .unwrap();
        assert!(engine
            .store()
            .matching_grant(
                "direct",
                "connection",
                "direct",
                "write_item",
                AUTHORITY_INVOKE,
                crate::storage::now_ms(),
                Some("write")
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn non_object_arguments_are_not_reviewable() {
        for args in [
            serde_json::json!([]),
            serde_json::json!("value"),
            serde_json::json!(1),
            serde_json::json!(false),
        ] {
            assert!(undeclared_argument(&serde_json::json!({"type":"object"}), &args).is_some());
        }
    }

    #[test]
    fn missing_allowlisted_read_path_is_refused_and_nested_paths_resolve() {
        let engine = hash_test_engine();
        let mut connection = engine
            .store()
            .connection("direct", "connection")
            .unwrap()
            .unwrap();
        let mut action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        action.risk = "read".into();
        connection.resource_filters = serde_json::json!({"values":{"target.repo":["o/r"]}});
        assert_eq!(
            resource_denial(&connection, &action, &serde_json::json!({})),
            Some(ResourceDenial::MissingRequiredFilter("target.repo".into()))
        );
        assert_eq!(
            resource_denial(
                &connection,
                &action,
                &serde_json::json!({"target":{"repo":"o/r"}})
            ),
            None
        );
    }

    #[test]
    fn checked_search_selection_requires_every_repository_to_be_allowed() {
        let engine = hash_test_engine();
        let mut connection = engine
            .store()
            .connection("direct", "connection")
            .unwrap()
            .unwrap();
        let mut action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        connection.app_key = "github_rest".into();
        connection.resource_filters =
            serde_json::json!({"values":{"owner":"org","repo":["a","b"]}});
        action.name = "github.issue.search".into();
        action.risk = "read".into();
        let args = serde_json::json!({"terms":["open"]});
        let allowed = AuthorizationRequest::new("direct", "connection", &action.name, args.clone())
            .with_resolved_github_search(vec!["org/a".into(), "org/b".into()]);
        let outside = AuthorizationRequest::new("direct", "connection", &action.name, args.clone())
            .with_resolved_github_search(vec!["org/a".into(), "other/b".into()]);
        assert_eq!(
            resource_denial_with_repositories(
                &connection,
                &action,
                &args,
                allowed.resolved_github_search_repositories()
            ),
            None
        );
        assert!(resource_denial_with_repositories(
            &connection,
            &action,
            &args,
            outside.resolved_github_search_repositories()
        )
        .is_some());
        assert!(resource_denial_with_repositories(&connection, &action, &args, None).is_some());
        assert!(
            resource_denial_with_repositories(&connection, &action, &args, Some(&[])).is_some()
        );
    }

    /// Which schema shapes close the top level, and which argument is named.
    #[test]
    fn undeclared_argument_checks_only_a_closed_top_level() {
        use serde_json::json;
        let declared = json!({"type": "object", "properties": {"a": {}, "n": {"type": "object"}}});
        let args = json!({"a": 1, "z": 2, "b": 3, "n": {"unknown": true}});
        // The first undeclared key in sorted order; the nested unknown is ignored.
        assert_eq!(undeclared_argument(&declared, &args).as_deref(), Some("b"));
        assert_eq!(
            undeclared_argument(&declared, &json!({"a": 1, "n": {"unknown": true}})),
            None
        );
        let mut closed = declared.clone();
        closed["additionalProperties"] = json!(false);
        assert_eq!(undeclared_argument(&closed, &args).as_deref(), Some("b"));
        for open in [
            json!({"type": "object"}),
            json!({"type": "object", "additionalProperties": true}),
            json!({"type": "object", "properties": {"a": {}}, "additionalProperties": true}),
            json!({"type": "object", "properties": {"a": {}}, "additionalProperties": {"type": "string"}}),
            json!({"type": "object", "properties": {"a": {}}, "patternProperties": {"^x_": {}}}),
            json!({"type": "object", "properties": "not an object"}),
            json!(true),
        ] {
            assert_eq!(undeclared_argument(&open, &args), None, "{open}");
        }
        assert_eq!(undeclared_argument(&declared, &json!(null)), None);
    }

    #[derive(Clone)]
    struct SeamState {
        handle: HandleAuthority,
        module_owner: String,
        agent_owner: String,
        module: bool,
        agent: bool,
        module_effect: Option<String>,
        agent_effect: Option<String>,
        approval: Option<ReceiptApprovalRow>,
        ownership_complete: bool,
        marker: bool,
        receipt_store: Option<Arc<PlexusStore>>,
        auth_failures: usize,
        preparations: usize,
        lose_handle_before_preparation: bool,
        change_during_preparation: Option<&'static str>,
        handle_missing: bool,
        handle_read_failure: bool,
        generation_read_failure: bool,
        facade_only: bool,
        expected_repository: Option<String>,
        abandoned_reservations: Vec<String>,
        /// When set, replaces the single default agent row (or module row) with
        /// one row per entry: its action selectors and optional expiry, in the
        /// order the store would return them.
        agent_rows: Option<Vec<(Vec<&'static str>, Option<i64>)>>,
        module_rows: Option<Vec<(Vec<&'static str>, Option<i64>)>>,
    }

    struct TestHandleSeams(std::sync::Mutex<SeamState>);

    impl GovernanceSeams for TestHandleSeams {
        fn resolve_invoke(&self, request: &AuthorizationRequest) -> Result<(), ResolverDenial> {
            if let Some(expected) = &self.0.lock().unwrap().expected_repository {
                assert_eq!(
                    request.resolved_repository.as_ref(),
                    Some(expected),
                    "approved dispatch lost its routing repository"
                );
            }
            Ok(())
        }
        fn facade_only(&self, action: &CatalogAction) -> bool {
            self.0.lock().unwrap().facade_only && action.name == "write_item"
        }
        fn handle_row(
            &self,
            _connection: &ConnectionRecord,
        ) -> Result<Option<HandleAuthority>, Denial> {
            let state = self.0.lock().unwrap();
            if state.handle_read_failure {
                return Err(Denial::StoreFailure);
            }
            Ok((!state.handle_missing).then(|| state.handle.clone()))
        }
        fn grant_rows(
            &self,
            connection: &ConnectionRecord,
            request: &AuthorizationRequest,
        ) -> Result<Vec<ScopedGrantRow>, Denial> {
            let state = self.0.lock().unwrap();
            let grant = GrantRecord {
                grant_id: "grant".into(),
                principal: state.module_owner.clone(),
                connection_id: connection.connection_id.clone(),
                grantee_principal: request.principal.clone(),
                risk_ceiling: "write".into(),
                action_selectors: vec![request.action.clone()],
                authority_kind: AUTHORITY_INVOKE.into(),
                expires_at: None,
                generation: 1,
                revoked_at_ms: None,
                revoked_by: None,
                state: "active".into(),
            };
            let mut rows = Vec::new();
            let listed = |owner: &str,
                          specs: &[(Vec<&'static str>, Option<i64>)],
                          agent_id: Option<&str>| {
                specs
                    .iter()
                    .enumerate()
                    .map(|(index, (selectors, expires_at))| {
                        let mut row = grant.clone();
                        row.grant_id = format!("grant-{index}");
                        row.principal = owner.into();
                        row.action_selectors = selectors.iter().map(|s| (*s).into()).collect();
                        row.expires_at = *expires_at;
                        ScopedGrantRow {
                            grant: row,
                            agent_id: agent_id.map(str::to_owned),
                        }
                    })
                    .collect::<Vec<_>>()
            };
            if let Some(specs) = &state.module_rows {
                rows.extend(listed(&state.module_owner, specs, None));
            } else if state.module {
                rows.push(ScopedGrantRow {
                    grant: grant.clone(),
                    agent_id: None,
                });
            }
            if let Some(specs) = &state.agent_rows {
                rows.extend(listed(&state.agent_owner, specs, Some("agent-a")));
            } else if state.agent {
                let mut agent_grant = grant;
                agent_grant.principal = state.agent_owner.clone();
                rows.push(ScopedGrantRow {
                    grant: agent_grant,
                    agent_id: Some("agent-a".into()),
                });
            }
            Ok(rows)
        }
        fn grant_generations(
            &self,
            _connection: &ConnectionRecord,
            _principal: &str,
            _agent_id: &str,
            _action: &str,
        ) -> Result<(i64, i64), Denial> {
            let state = self.0.lock().unwrap();
            if state.generation_read_failure {
                return Err(Denial::StoreFailure);
            }
            Ok((
                if state.agent { 1 } else { 2 },
                if state.module { 1 } else { 2 },
            ))
        }
        fn policy_inputs(
            &self,
            _connection: &ConnectionRecord,
            _agent_id: &str,
            _action: &CatalogAction,
        ) -> Result<PolicyInputs, Denial> {
            let state = self.0.lock().unwrap();
            Ok(PolicyInputs {
                module_effect: state.module_effect.clone(),
                agent_effect: state.agent_effect.clone(),
                module_generation: 0,
            })
        }
        fn receipt_approval(
            &self,
            _connection: &ConnectionRecord,
            _id: &str,
        ) -> Result<Option<ReceiptApprovalRow>, Denial> {
            Ok(self.0.lock().unwrap().approval.clone())
        }
        fn ownership_reads_complete(&self, _request: &AuthorizationRequest) -> bool {
            self.0.lock().unwrap().ownership_complete
        }
        fn pre_transmit(&self, reservation: &Reservation) -> bool {
            let mut state = self.0.lock().unwrap();
            let marked =
                if let (Some(store), Some(claim)) = (&state.receipt_store, &reservation.receipt) {
                    store
                        .mark_github_dispatch(
                            &claim.agent_id,
                            &claim.request_nonce,
                            &claim.claim_owner,
                            claim.effect_index,
                            crate::storage::now_ms(),
                            &reservation.request_id,
                        )
                        .unwrap()
                } else {
                    state.marker
                };
            // Lose the row after authority revalidation and receipt marking, but
            // before credential preparation reads it again. Earlier removal is
            // caught by the separate stale-authority fence instead.
            if marked && state.lose_handle_before_preparation {
                state.handle_missing = true;
            }
            marked
        }
        fn abandon_transmit(&self, reservation: &Reservation) {
            let store = {
                let mut state = self.0.lock().unwrap();
                state
                    .abandoned_reservations
                    .push(reservation.reservation_id.clone());
                state.receipt_store.clone()
            };
            if let Some(store) = store {
                crate::storage::github_store::GithubGovernanceSeams {
                    store,
                    credential_provider: None,
                }
                .abandon_transmit(reservation);
            }
        }
        fn prepare_handle_credential(
            &self,
            _connection: &ConnectionRecord,
            _handle: &HandleAuthority,
        ) -> Result<ResolvedCredential, &'static str> {
            let mut state = self.0.lock().unwrap();
            state.preparations += 1;
            match state.change_during_preparation {
                Some("grant") => state.agent = false,
                Some("handle") => state.handle.app_handle_generation += 1,
                Some("repository") => state.handle.repo_binding_generation += 1,
                _ => {}
            }
            Ok(ResolvedCredential::new(b"ghs_test".to_vec(), None, 1))
        }
        fn handle_auth_failure(&self, _connection: &ConnectionRecord, _handle: &HandleAuthority) {
            self.0.lock().unwrap().auth_failures += 1;
        }
    }

    fn facade_test_engine() -> (
        GovernanceEngine<StubCredentialSource, MockTransport>,
        Arc<TestHandleSeams>,
    ) {
        facade_test_engine_at(":memory:")
    }

    fn facade_test_engine_at(
        path: &str,
    ) -> (
        GovernanceEngine<StubCredentialSource, MockTransport>,
        Arc<TestHandleSeams>,
    ) {
        let seams = Arc::new(TestHandleSeams(std::sync::Mutex::new(SeamState {
            handle: HandleAuthority {
                app_handle_generation: 1,
                repo_binding_generation: 1,
                credential_generation: 1,
                enabled: true,
                credential_reference: b"ref".to_vec(),
            },
            module_owner: "direct".into(),
            agent_owner: "direct".into(),
            module: true,
            agent: true,
            module_effect: None,
            agent_effect: None,
            approval: None,
            ownership_complete: true,
            marker: true,
            receipt_store: None,
            auth_failures: 0,
            preparations: 0,
            lose_handle_before_preparation: false,
            change_during_preparation: None,
            handle_missing: false,
            handle_read_failure: false,
            generation_read_failure: false,
            facade_only: true,
            expected_repository: None,
            abandoned_reservations: Vec::new(),
            agent_rows: None,
            module_rows: None,
        })));
        (
            hash_test_engine_at(path).with_governance_seams(seams.clone()),
            seams,
        )
    }

    fn facade_request() -> AuthorizationRequest {
        facade_origin::request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            )
            .with_bound_agent("agent-a", "handle-a"),
            None,
        )
    }

    #[test]
    fn authority_changes_during_token_exchange_stop_transmission() {
        for dimension in ["grant", "handle", "repository"] {
            let (engine, seams) = facade_test_engine();
            let reservation = engine.authorize(facade_request()).expect("authorize");
            seams.0.lock().unwrap().change_during_preparation = Some(dimension);
            let outcome = engine.revalidate_and_dispatch(&reservation);
            assert!(
                matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
                    if code.starts_with("stale_authority{")),
                "{dimension}: {outcome:?}"
            );
            assert_eq!(seams.0.lock().unwrap().preparations, 1);
            assert!(engine.transport().requests().is_empty());
            assert_eq!(
                seams.0.lock().unwrap().abandoned_reservations,
                [reservation.reservation_id]
            );
        }
    }

    #[test]
    fn a_pre_transmit_refusal_invalidates_the_unclaimed_reservation() {
        let (engine, _) = facade_test_engine();
        let reservation = engine.authorize(facade_request()).unwrap();
        engine.refuse_before_transmit(&reservation, "freshness_failed", "target changed");
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(matches!(outcome.outcome, TransportOutcome::NotSent { .. }));
        assert!(
            engine.transport().requests().is_empty(),
            "refused reservation remained claimable"
        );
    }

    #[test]
    fn a_credential_store_failure_keeps_an_approved_call_waiting() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().facade_only = false;
        engine
            .store()
            .insert_grant(&GrantInput {
                grant_id: "approval-admin".into(),
                principal: "direct".into(),
                connection_id: "connection".into(),
                grantee_principal: "operator".into(),
                risk_ceiling: "write".into(),
                action_selectors: vec!["*".into()],
                authority_kind: "connection_admin".into(),
                expires_at: None,
            })
            .unwrap();
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        let id = engine
            .store()
            .create_action_request(
                "direct",
                "connection",
                "write_item",
                &serde_json::json!({"repo":"o/r"}),
                &action.schema_hash,
                "direct",
                crate::storage::now_ms() + 300_000,
                None,
                None,
            )
            .unwrap();
        let fail = seams.clone();
        let engine = engine.with_freshness_check(Arc::new(move |_| {
            fail.0.lock().unwrap().handle_read_failure = true;
            Ok(())
        }));
        let outcome = engine.approve_request("direct", &id, "operator").unwrap();
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "credential_store_unavailable"),
            "{outcome:?}"
        );
        assert_eq!(outcome.retryability, Retryability::AutoRetryable);
        assert!(engine.transport().requests().is_empty());
        let row = engine
            .store()
            .action_request("direct", &id)
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "approved", "store fault consumed approval");
        assert_eq!(
            row.scope_outcome.as_deref(),
            Some(crate::scope::APPROVED_WAITING)
        );
    }

    #[test]
    fn a_binding_read_failure_is_not_a_missing_credential() {
        let scratch = crate::test_scratch::Scratch::database("binding-store-failure");
        let (mut engine, _) = facade_test_engine_at(scratch.path().to_str().unwrap());
        let reservation = engine.authorize(facade_request()).unwrap();
        rusqlite::Connection::open(scratch.path())
            .unwrap()
            .execute(
                "UPDATE connections SET credential_binding = ?1 WHERE connection_id = 'connection'",
                [vec![0xffu8]],
            )
            .unwrap();
        engine.seams = None;
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "credential_store_unavailable"),
            "{outcome:?}"
        );
        assert_eq!(outcome.retryability, Retryability::AutoRetryable);
        assert!(engine.transport().requests().is_empty());
    }

    /// A request built by the trusted internal facade router passes the catalog
    /// guard that refuses ordinary caller-built requests for facade-only actions.
    /// It lives here because only this crate can construct a facade origin; the
    /// refusal side is `ordinary_origin_cannot_be_promoted_by_caller_fields` in
    /// tests/governance_seams.rs, and a guard that refuses everything fails this
    /// test while leaving that one green.
    #[test]
    fn private_facade_origin_passes_catalog_fence() {
        let (engine, _) = facade_test_engine();
        let reservation = engine
            .authorize(facade_request())
            .expect("facade reaches reservation");
        assert!(reservation.authority_baseline.is_some());
        let expected = fingerprint(&serde_json::to_vec(&(b"ref".to_vec(), 1_i64)).unwrap());
        assert_eq!(reservation.credential_fingerprint, expected);
        assert!(engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .any(|row| row.reason_code == "credential_resolved"
                && row.credential_fingerprint.as_deref() == Some(expected.as_str())));
        assert!(engine.transport().requests().is_empty());
    }

    fn claimed_facade_reservation(
        engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
        seams: &Arc<TestHandleSeams>,
        nonce: &str,
        owner: &str,
        claimed_at: i64,
    ) -> Reservation {
        use crate::github::receipt::{Claim, Effect};
        let receipt = engine
            .store()
            .claim_github_receipt(
                "agent-a",
                nonce,
                "canonical-request-fingerprint",
                owner,
                &serde_json::json!({}),
                &[Effect {
                    effect: "write_item".into(),
                    dispatch_attempted_at: None,
                    request_id: None,
                    outcome: None,
                }],
                None,
                claimed_at,
                60,
            )
            .unwrap();
        assert!(matches!(receipt, Claim::Owned(_)));
        seams.0.lock().unwrap().receipt_store = Some(Arc::clone(engine.store()));
        engine
            .authorize(facade_origin::receipt_request(
                facade_request(),
                None,
                ReceiptClaim {
                    agent_id: "agent-a".into(),
                    request_nonce: nonce.into(),
                    claim_owner: owner.into(),
                    effect_index: 0,
                },
                crate::github::facade::effects::OwnershipProof::new("reaction", vec![]),
            ))
            .expect("facade receipt reservation")
    }

    #[test]
    fn superseded_receipt_claim_cas_refuses_nonce_in_flight_without_transport() {
        let (engine, seams) = facade_test_engine();
        let now = crate::storage::now_ms();
        let reservation =
            claimed_facade_reservation(&engine, &seams, "old-nonce", "old-worker", now - 121_000);
        use crate::github::receipt::Claim;
        let takeover = engine
            .store()
            .claim_github_receipt(
                "agent-a",
                "old-nonce",
                "canonical-request-fingerprint",
                "new-worker",
                &serde_json::json!({}),
                &[],
                None,
                now,
                60,
            )
            .unwrap();
        assert!(matches!(takeover, Claim::Owned(_)));
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "nonce_in_flight"),
            "{outcome:?}"
        );
        assert!(engine.transport().requests().is_empty());
        assert_eq!(seams.0.lock().unwrap().preparations, 0);
    }

    /// An App write must not fall through to anonymous transport if its authority
    /// row disappears between the final authority check and credential preparation.
    #[test]
    fn facade_app_authority_loss_refuses_anonymous_dispatch_and_abandons_reservation() {
        let (engine, seams) = facade_test_engine();
        let reservation = claimed_facade_reservation(
            &engine,
            &seams,
            "lost-app-authority",
            "worker",
            crate::storage::now_ms(),
        );
        assert_eq!(reservation.origin, RequestOrigin::Facade);
        assert_eq!(reservation.risk, Risk::Write);
        assert!(reservation.authority_baseline.is_some());
        seams.0.lock().unwrap().lose_handle_before_preparation = true;

        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(&outcome.outcome, TransportOutcome::NotSent { code, .. } if code == "credential_missing"),
            "missing App authority must refuse, not dispatch anonymously: {outcome:?}"
        );
        assert_eq!(outcome.transmission, TransmissionState::NotSent);
        assert!(
            engine.transport().requests().is_empty(),
            "no vendor request may leave"
        );
        assert!(
            engine.transport().authorization_headers().is_empty(),
            "no authenticated or anonymous transport call may leave"
        );
        let state = seams.0.lock().unwrap();
        assert!(
            state.handle_missing,
            "the post-authorization loss must execute"
        );
        assert_eq!(state.preparations, 0);
        assert_eq!(
            state.abandoned_reservations,
            vec![reservation.reservation_id.clone()]
        );
        drop(state);
        let receipt = engine
            .store()
            .github_receipt("agent-a", "lost-app-authority")
            .unwrap()
            .unwrap();
        assert!(
            receipt.effects[0].dispatch_attempted_at.is_none(),
            "abandon must clear the persisted pre-transmit marker"
        );
        assert!(receipt.effects[0].request_id.is_none());
    }

    #[test]
    fn facade_dispatch_audit_uses_the_receipts_request_fingerprint() {
        let (engine, seams) = facade_test_engine();
        let reservation = claimed_facade_reservation(
            &engine,
            &seams,
            "write-nonce",
            "worker",
            crate::storage::now_ms(),
        );
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::Completed { .. }),
            "{outcome:?}"
        );
        assert_eq!(engine.transport().requests().len(), 1);
        let audit = engine.store().list_audit("direct").unwrap();
        let dispatched = audit
            .iter()
            .find(|row| row.reason_code == "dispatched")
            .unwrap();
        assert_eq!(
            dispatched.idempotency_key_fingerprint.as_deref(),
            Some("canonical-request-fingerprint")
        );
        assert_eq!(dispatched.app_handle_id.as_deref(), Some("handle-a"));
    }

    #[test]
    fn receipt_claim_is_private_and_never_enters_transport_args() {
        let ordinary = AuthorizationRequest::new(
            "direct",
            "connection",
            "write_item",
            serde_json::json!({"_receipt": {"claim_owner":"forged"}}),
        );
        assert!(
            ordinary.receipt.is_none(),
            "caller arguments cannot mint a receipt claim"
        );
        assert_eq!(ordinary.origin(), RequestOrigin::Ordinary);
        assert!(ordinary.ownership_proof().is_none());
        let (engine, _) = facade_test_engine();
        engine.credential_source().set_default_response(
            crate::credentials::StubCredentialResponse::Success {
                payload: b"token".to_vec(),
                expires_at_ms: None,
                record_version: 1,
            },
        );
        let request = facade_origin::receipt_request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            )
            .with_bound_agent("agent-a", "handle-a"),
            None,
            ReceiptClaim {
                agent_id: "agent-a".into(),
                request_nonce: "nonce".into(),
                claim_owner: "worker".into(),
                effect_index: 0,
            },
            crate::github::facade::effects::OwnershipProof::new("reaction", vec![]),
        );
        let reservation = engine.authorize(request).expect("facade reservation");
        assert_eq!(reservation.receipt.as_ref().unwrap().claim_owner, "worker");
        assert_eq!(reservation.origin, RequestOrigin::Facade);
        assert_eq!(reservation.args, serde_json::json!({"repo":"o/r"}));
        engine.revalidate_and_dispatch(&reservation);
        let sent = engine.transport().requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].args, serde_json::json!({"repo":"o/r"}));
    }

    #[test]
    fn facade_write_reservation_waits_for_ownership_reads() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().ownership_complete = false;
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::OwnershipProofMissing)
        );
        assert!(engine
            .store()
            .list_audit("direct")
            .unwrap()
            .iter()
            .all(|row| row.reason_code != "credential_resolved"));
        assert!(
            engine
                .store()
                .list_audit("direct")
                .unwrap()
                .iter()
                .any(|row| row.reason_code == "ownership_proof_missing"),
            "ownership refusal went unaudited"
        );
        seams.0.lock().unwrap().ownership_complete = true;
        assert!(engine.authorize(facade_request()).is_ok());
    }

    #[test]
    fn authority_snapshot_read_failure_is_audited() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().generation_read_failure = true;
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::StoreFailure)
        );
        assert!(
            engine
                .store()
                .list_audit("direct")
                .unwrap()
                .iter()
                .any(|row| row.reason_code == "store_failure"),
            "snapshot refusal went unaudited"
        );
        assert!(engine.transport().requests().is_empty());
    }

    #[test]
    fn dispatch_canonicalization_failure_is_audited() {
        let (engine, _) = facade_test_engine();
        let mut reservation = engine.authorize(facade_request()).unwrap();
        reservation.decision_id = Some("decision".into());
        reservation.grant_hash = Some("hash".into());
        let outcome =
            jcs::with_sha256_failure_on_call(0, || engine.revalidate_and_dispatch(&reservation));
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. } if code == "grant_hash_mismatch")
        );
        assert!(
            engine
                .store()
                .list_audit("direct")
                .unwrap()
                .iter()
                .any(|row| row.reason_code == "grant_hash_mismatch"),
            "hash refusal went unaudited"
        );
        assert!(engine.transport().requests().is_empty());
    }

    #[test]
    fn unknown_risks_fail_closed_and_known_risks_keep_their_severity() {
        assert!(is_write("unexpected"));
        assert_eq!(action_severity("unexpected", Severity::S1), Severity::S4);
        assert_eq!(parse_risk("unexpected"), Risk::Destructive);
        for ceiling in ["read", "write", "destructive", "unexpected"] {
            assert!(!risk_within_ceiling("unexpected", ceiling));
        }
        for (text, risk, severity, write) in [
            ("read", Risk::Read, Severity::S1, false),
            ("write", Risk::Write, Severity::S2, true),
            ("destructive", Risk::Destructive, Severity::S3, true),
        ] {
            assert_eq!(known_risk(text), Some(risk));
            assert_eq!(parse_risk(text), risk);
            assert_eq!(is_write(text), write);
            assert_eq!(action_severity(text, Severity::S1), severity);
            assert!(risk_within_ceiling(text, "destructive"));
            assert!(!risk_within_ceiling(text, "unexpected"));
            assert_eq!(
                action_severity(text, Severity::S4),
                if write { Severity::S4 } else { Severity::S2 }
            );
        }
    }

    #[test]
    fn wildcard_grantees_do_not_match_a_module_or_agent() {
        for agent in [None, Some("agent-a")] {
            let row = AgentGrantKey {
                connection_id: "conn",
                principal: "*",
                agent_id: agent,
            };
            let sought = AgentGrantKey {
                principal: "direct",
                ..row
            };
            assert!(!grant_key_matches(&row, &sought));
        }
    }

    #[test]
    fn authority_projection_matches_catalog_and_missing_agent_refusals() {
        let (engine, _) = facade_test_engine();
        engine
            .store()
            .insert_grant(&GrantInput {
                grant_id: "projection".into(),
                principal: "direct".into(),
                connection_id: "connection".into(),
                grantee_principal: PROJECTION_PRINCIPAL.into(),
                risk_ceiling: "write".into(),
                action_selectors: vec!["write_item".into()],
                authority_kind: "invoke".into(),
                expires_at: None,
            })
            .unwrap();
        let projected = engine
            .would_ask(None, "flow", None, "github", "connection", "write_item")
            .unwrap_err();
        let mut real = facade_request();
        real.attributed_agent_id = None;
        real.bound_agent_handle = None;
        real.scope = Some(CallScope {
            owner: PROJECTION_PRINCIPAL.into(),
            scope_ref: "grant-projection".into(),
            scope_epoch: 0,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: None,
            flow_id: Some("flow".into()),
            delegates: false,
            owner_authorized: true,
        });
        let actual = engine.authorize(real).unwrap_err();
        assert_eq!(projected.reason_code(), actual.reason_code());
        assert_eq!(projected.reason_code(), "agent_grant_absent");
        for status in ["quarantined", "disabled"] {
            let action = engine
                .store()
                .catalog_action("direct", "connection", "write_item")
                .unwrap()
                .unwrap();
            engine
                .store()
                .upsert_catalog_action(&CatalogActionInput {
                    connection_id: "connection".into(),
                    principal: "direct".into(),
                    name: "write_item".into(),
                    title: action.title,
                    schema: action.schema,
                    schema_hash: action.schema_hash,
                    risk: action.risk,
                    severity: action.severity,
                    ask_first: action.ask_first,
                    status: status.into(),
                    quarantine_reason: None,
                    reconciliation: None,
                })
                .unwrap();
            let projected = engine
                .would_ask(
                    Some("agent-a"),
                    "flow",
                    None,
                    "github",
                    "connection",
                    "write_item",
                )
                .unwrap_err();
            let actual = engine.authorize(facade_request()).unwrap_err();
            assert_eq!(projected.reason_code(), actual.reason_code(), "{status}");
            assert!(projected.reason_code().starts_with("catalog_action_"));
        }
    }

    #[test]
    fn wrong_owner_module_grant_refuses_despite_valid_agent_grant() {
        let scratch = crate::test_scratch::Scratch::database("governance-module-owner");
        let (engine, seams) = facade_test_engine_at(scratch.path().to_str().unwrap());
        {
            let mut state = seams.0.lock().unwrap();
            state.module_owner = "another-owner".into();
            assert!(state.module && state.agent);
            assert_eq!(state.agent_owner, "direct");
        }
        let denial = engine.authorize(facade_request()).unwrap_err();
        assert_eq!(denial, Denial::Grant(GrantDenial::Missing));
        assert_eq!(denial.reason_code(), "grant_missing");
        let rows = engine.store().list_audit("direct").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason_code, "grant_missing");
        assert_eq!(rows[0].gate.as_deref(), Some("grant"));
        let db = rusqlite::Connection::open(scratch.path()).unwrap();
        let reservations: i64 = db
            .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(reservations, 0);
        assert!(engine.transport().requests().is_empty());
        assert_eq!(seams.0.lock().unwrap().preparations, 0);
    }

    #[test]
    fn facade_agent_grant_and_policy_are_enforced() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().agent = false;
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Grant(GrantDenial::Missing))
        );
        seams.0.lock().unwrap().agent = true;
        let other_agent = facade_origin::request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            )
            .with_bound_agent("agent-b", "handle-b"),
            None,
        );
        assert_eq!(
            engine.authorize(other_agent),
            Err(Denial::Grant(GrantDenial::Missing))
        );
        seams.0.lock().unwrap().module = false;
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Grant(GrantDenial::Missing))
        );
        let mut state = seams.0.lock().unwrap();
        state.module = true;
        state.module_owner = "other".into();
        state.agent_owner = "other".into();
        drop(state);
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Grant(GrantDenial::Missing))
        );
        let mut state = seams.0.lock().unwrap();
        state.module_owner = "direct".into();
        state.agent_owner = "direct".into();
        state.module_effect = Some("block".into());
        drop(state);
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Policy(PolicyDenial::Blocked))
        );
    }

    fn facade_request_for(action: &str) -> AuthorizationRequest {
        facade_origin::request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                action,
                serde_json::json!({"repo":"o/r"}),
            )
            .with_bound_agent("agent-a", "handle-a"),
            None,
        )
    }

    fn add_write_action(
        engine: &GovernanceEngine<StubCredentialSource, MockTransport>,
        name: &str,
    ) {
        let schema = serde_json::json!({"type":"object"});
        engine
            .store()
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".into(),
                principal: "direct".into(),
                name: name.into(),
                title: None,
                schema: schema.clone(),
                schema_hash: jcs::jcs_sha256(&schema).unwrap(),
                risk: "write".into(),
                severity: "S2".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
    }

    // Grants are additive. An imported agent holds one row per granted action,
    // so the row that happens to sort first must not decide for the others.
    #[test]
    fn facade_agent_rows_for_different_actions_each_authorize_their_own_action() {
        let (engine, seams) = facade_test_engine();
        add_write_action(&engine, "write_other");
        seams.0.lock().unwrap().agent_rows = Some(vec![
            (vec!["write_other"], None),
            (vec!["write_item"], None),
        ]);
        engine
            .authorize(facade_request_for("write_item"))
            .expect("second agent row authorizes write_item");
        engine
            .authorize(facade_request_for("write_other"))
            .expect("first agent row authorizes write_other");
    }

    #[test]
    fn facade_module_rows_for_different_actions_each_authorize_their_own_action() {
        let (engine, seams) = facade_test_engine();
        add_write_action(&engine, "write_other");
        seams.0.lock().unwrap().module_rows = Some(vec![
            (vec!["write_other"], None),
            (vec!["write_item"], None),
        ]);
        engine
            .authorize(facade_request_for("write_item"))
            .expect("second module row authorizes write_item");
        engine
            .authorize(facade_request_for("write_other"))
            .expect("first module row authorizes write_other");
    }

    #[test]
    fn facade_agent_grant_expired_row_beside_a_live_row_still_allows() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().agent_rows = Some(vec![
            (vec!["write_item"], Some(1)),
            (vec!["write_item"], None),
        ]);
        engine
            .authorize(facade_request())
            .expect("the live row authorizes despite the expired one");
    }

    #[test]
    fn facade_agent_grant_only_expired_row_naming_the_action_reports_expiry() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().agent_rows = Some(vec![
            (vec!["write_other"], None),
            (vec!["write_item"], Some(1)),
        ]);
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Grant(GrantDenial::Expired))
        );
    }

    #[test]
    fn facade_agent_rows_that_do_not_name_the_action_refuse_action_selector() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().agent_rows = Some(vec![
            (vec!["write_other"], None),
            (vec!["write_third"], None),
        ]);
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Grant(GrantDenial::ActionSelector))
        );
    }

    #[test]
    fn facade_policy_matrix_is_enforced_on_authorize() {
        for (module, agent, expected) in [
            (None, None, "allow"),
            (Some("allow"), Some("ask_first"), "ask_first"),
            (Some("ask_first"), Some("allow"), "ask_first"),
            (Some("block"), Some("allow"), "block"),
            (Some("allow"), Some("block"), "block"),
        ] {
            let (engine, seams) = facade_test_engine();
            let mut state = seams.0.lock().unwrap();
            state.module_effect = module.map(str::to_owned);
            state.agent_effect = agent.map(str::to_owned);
            drop(state);
            let outcome = engine.authorize(facade_request());
            match expected {
                "allow" => assert!(outcome.is_ok()),
                "ask_first" => {
                    assert_eq!(outcome, Err(Denial::Policy(PolicyDenial::ApprovalMissing)))
                }
                "block" => assert_eq!(outcome, Err(Denial::Policy(PolicyDenial::Blocked))),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn catalog_default_ask_first_survives_agent_allow_without_module_policy() {
        let (engine, seams) = facade_test_engine();
        let schema = serde_json::json!({"type":"object"});
        engine
            .store()
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".into(),
                principal: "direct".into(),
                name: "write_item".into(),
                title: None,
                schema: schema.clone(),
                schema_hash: jcs::jcs_sha256(&schema).unwrap(),
                risk: "write".into(),
                severity: "S2".into(),
                ask_first: true,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        seams.0.lock().unwrap().agent_effect = Some("allow".into());
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Policy(PolicyDenial::ApprovalMissing))
        );
        assert!(engine
            .store()
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn facade_ask_first_without_receipt_approval_writes_no_action_request() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().agent_effect = Some("ask_first".into());
        assert_eq!(
            engine.authorize(facade_request()),
            Err(Denial::Policy(PolicyDenial::ApprovalMissing))
        );
        let rows = engine.store().list_audit("direct").unwrap();
        assert!(rows.iter().any(|row| row.reason_code == "approval_missing"));
        assert!(engine
            .store()
            .list_action_requests("direct")
            .unwrap()
            .is_empty());
        assert!(engine.transport().requests().is_empty());
    }

    #[test]
    fn receipt_approval_checks_agent_without_catalog_args_snapshot() {
        let (engine, seams) = facade_test_engine();
        seams.0.lock().unwrap().agent_effect = Some("ask_first".into());
        seams.0.lock().unwrap().approval = Some(ReceiptApprovalRow {
            action_request_id: "approved".into(),
            agent_id: "agent-a".into(),
            status: "approved".into(),
            expires_at_ms: crate::storage::now_ms() + 30_000,
        });
        let approval = ReceiptApproval {
            action_request_id: "approved".into(),
            agent_id: "agent-a".into(),
        };
        let request = facade_origin::request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r", "catalog": "different"}),
            )
            .with_bound_agent("agent-a", "handle-a"),
            Some(approval.clone()),
        );
        assert!(engine.authorize(request).is_ok());
        seams.0.lock().unwrap().approval.as_mut().unwrap().agent_id = "agent-b".into();
        let request = facade_origin::request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            )
            .with_bound_agent("agent-a", "handle-a"),
            Some(approval),
        );
        assert_eq!(
            engine.authorize(request),
            Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch))
        );
        let mut state = seams.0.lock().unwrap();
        state.approval.as_mut().unwrap().agent_id = "agent-a".into();
        state.module_effect = Some("block".into());
        drop(state);
        let request = facade_origin::request(
            AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"repo":"o/r"}),
            )
            .with_bound_agent("agent-a", "handle-a"),
            Some(ReceiptApproval {
                action_request_id: "approved".into(),
                agent_id: "agent-a".into(),
            }),
        );
        assert_eq!(
            engine.authorize(request),
            Err(Denial::Policy(PolicyDenial::Blocked))
        );
    }

    #[test]
    fn policy_hash_change_after_reservation_refuses_transmission() {
        let (engine, seams) = facade_test_engine();
        let reservation = engine.authorize(facade_request()).unwrap();
        seams.0.lock().unwrap().module_effect = Some("block".into());
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "stale_authority{policy_changed}")
        );
        assert!(engine.transport().requests().is_empty());
    }

    #[test]
    fn handle_provider_auth_failure_reports_only_401() {
        let (engine, seams) = facade_test_engine();
        engine.credential_source().set_default_response(
            crate::credentials::StubCredentialResponse::Success {
                payload: b"token".to_vec(),
                expires_at_ms: None,
                record_version: 1,
            },
        );
        engine
            .transport()
            .set_response(crate::transport::MockResponse::VendorError {
                code: "http_403".into(),
                message: "permission denied".into(),
            });
        let reservation = engine.authorize(facade_request()).unwrap();
        engine.revalidate_and_dispatch(&reservation);
        assert!(engine.credential_source().auth_failure_reports().is_empty());
        engine
            .transport()
            .set_response(crate::transport::MockResponse::VendorError {
                code: "http_401".into(),
                message: "unauthorized".into(),
            });
        let reservation = engine.authorize(facade_request()).unwrap();
        engine.revalidate_and_dispatch(&reservation);
        assert_eq!(seams.0.lock().unwrap().auth_failures, 1);
        assert_eq!(engine.transport().requests().len(), 2);
    }

    #[test]
    fn authority_changes_and_claim_marker_stop_transmission() {
        let (engine, seams) = facade_test_engine();
        let reservation = engine.authorize(facade_request()).unwrap();
        seams.0.lock().unwrap().handle.credential_generation += 1;
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "stale_authority{credential_rotated}")
        );
        assert!(engine.transport().requests().is_empty());
        assert_eq!(seams.0.lock().unwrap().preparations, 0);
        let reservation = engine.authorize(facade_request()).unwrap();
        {
            let mut state = seams.0.lock().unwrap();
            state.module = false;
            state.handle.credential_generation += 1;
        }
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "stale_authority{module_grant_revoked}")
        );
        assert!(engine.transport().requests().is_empty());
        assert_eq!(seams.0.lock().unwrap().preparations, 0);
        seams.0.lock().unwrap().module = true;
        engine.credential_source().set_default_response(
            crate::credentials::StubCredentialResponse::Success {
                payload: b"token".to_vec(),
                expires_at_ms: None,
                record_version: 1,
            },
        );
        let reservation = engine.authorize(facade_request()).unwrap();
        seams.0.lock().unwrap().marker = false;
        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert!(
            matches!(outcome.outcome, TransportOutcome::NotSent { ref code, .. }
            if code == "aborted_stale_authorization")
        );
        assert!(engine.transport().requests().is_empty());
        assert_eq!(seams.0.lock().unwrap().preparations, 0);
    }

    fn hash_test_engine() -> GovernanceEngine<StubCredentialSource, MockTransport> {
        hash_test_engine_at(":memory:")
    }

    fn hash_test_engine_at(path: &str) -> GovernanceEngine<StubCredentialSource, MockTransport> {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("governance-hash-test-{}", new_request_id()),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open hash test store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "mock",
                "active",
                &serde_json::json!({"write_enabling":["repo"]}),
            )
            .expect("insert connection");
        let schema = serde_json::json!({"type": "object"});
        let schema_hash = jcs::jcs_sha256(&schema).expect("test schema is JCS-compatible");
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "write_item".to_string(),
                title: None,
                schema,
                schema_hash,
                risk: "write".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("insert action");
        store
            .insert_grant(&GrantInput {
                grant_id: "grant".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "write".to_string(),
                action_selectors: vec!["write_item".to_string()],
                authority_kind: AUTHORITY_INVOKE.to_string(),
                expires_at: None,
            })
            .expect("insert grant");
        install_system_manifest(&store, "mock", "S1");
        GovernanceEngine::new(
            store,
            Arc::new(StubCredentialSource::default()),
            Arc::new(MockTransport::default()),
        )
    }

    /// Install a reviewed system manifest for `app_key` at `tier`. Severity
    /// reads the app's tier from it, and an app without one is gated at the
    /// strongest tier, so every fixture app needs one.
    fn install_system_manifest(store: &PlexusStore, app_key: &str, tier: &str) {
        let manifest = crate::ingest_value(serde_json::json!({
            "schema_version": 1,
            "key": app_key,
            "name": app_key,
            "description": "governance unit-test vendor",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "in-process tests",
            "tier": tier,
            "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": ["repo"]},
            "actions_baseline": [{"name": "write_item", "risk": "write", "input_schema":{"type":"object","properties":{"repo":{"type":"string"}}}}],
            "defaults": {"ask_first_risk": ["write", "destructive"], "rate_limit": {"calls_per_min": 30}},
            "availability": "ga"
        }))
        .expect("test manifest ingests");
        store
            .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
            .expect("store test manifest");
    }

    #[test]
    fn authorization_returns_store_failure_when_argument_hashing_fails() {
        let engine = hash_test_engine();
        let result = jcs::with_sha256_failure_on_call(0, || {
            engine.authorize(AuthorizationRequest::new(
                "direct",
                "connection",
                "write_item",
                serde_json::json!({"team": "core"}),
            ))
        });
        assert_eq!(result, Err(Denial::StoreFailure));
    }

    #[test]
    fn approval_comparison_reaches_credentials_without_hashing_snapshot() {
        let engine = hash_test_engine();
        let args = serde_json::json!({"repo": "core"});
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .expect("query action")
            .expect("action exists");
        let request_id = engine
            .store()
            .create_action_request(
                "direct",
                "connection",
                "write_item",
                &args,
                &action.schema_hash,
                "direct",
                crate::storage::now_ms() + 60_000,
                None,
                None,
            )
            .expect("create approved request");
        assert!(engine
            .store()
            .decide_action_request("direct", &request_id, true, "operator")
            .expect("approve request"));
        let request = AuthorizationRequest::new("direct", "connection", "write_item", args)
            .approved_from(request_id);

        let result = jcs::with_sha256_failure_on_call(1, || engine.authorize(request));
        assert_eq!(result, Err(Denial::Credential(CredentialDenial::Missing)));
    }

    #[test]
    fn reservation_argument_mismatch_aborts_before_dispatch() {
        let engine = hash_test_engine();
        let reservation = Reservation {
            reservation_id: "reservation".to_string(),
            principal: "direct".to_string(),
            acting_principal: "direct".to_string(),
            actor: "direct".to_string(),
            attributed_agent_id: None,
            bound_agent_handle: None,
            connection_id: "connection".to_string(),
            app_key: "mock".to_string(),
            action: "write_item".to_string(),
            args: serde_json::json!({"team": "core"}),
            approved_args: serde_json::json!({"team": "other"}),
            grant_id: "grant".to_string(),
            approved_args_hash: "sha256:approved".to_string(),
            args_snapshot_hash: "sha256:approved".to_string(),
            schema_hash: "sha256:schema".to_string(),
            risk: Risk::Write,
            severity: Severity::S2,
            snapshot: SnapshotGenerations {
                connection: 1,
                catalog_action: 1,
                grant: 1,
                policy: 0,
                policy_id: None,
            },
            expires_at_ms: crate::storage::now_ms() + 60_000,
            request_id: "request".to_string(),
            credential_fingerprint: "credential:test".to_string(),
            decision_id: None,
            grant_hash: None,
            intent_id: None,
            authority_baseline: None,
            receipt: None,
            origin: RequestOrigin::Ordinary,
            scope: None,
            relay_origin: None,
            on_behalf_of_agent: None,
            agent_grant: None,
            approval_scope: None,
        };

        let outcome = engine.revalidate_and_dispatch(&reservation);
        assert_eq!(outcome.transmission, TransmissionState::NotSent);
        assert!(matches!(
            outcome.outcome,
            TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization"
        ));
        assert!(engine.transport().requests().is_empty());
    }

    /// GitHub treats owner and repository names as case-insensitive, and its
    /// connections store those filters in lowercase. Accept a mixed-case name
    /// for the same repository, but refuse a different repository. Keep exact
    /// matching for other vendors' filter values.
    #[test]
    fn github_owner_and_repo_filters_match_case_insensitively() {
        let engine = hash_test_engine_at(":memory:");
        let store = engine.store();
        let filters = serde_json::json!({
            "values": {"owner": "cortexkit", "repo": ["aft"]},
            "write_enabling": ["owner", "repo"]
        });
        store
            .insert_connection("direct", "gh", "github_rest", "active", &filters)
            .expect("github connection");
        store
            .insert_connection("direct", "other", "mock", "active", &filters)
            .expect("non-github connection");
        let github = store.connection("direct", "gh").unwrap().unwrap();
        let other = store.connection("direct", "other").unwrap().unwrap();
        let write = store
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        let mixed_case = serde_json::json!({"owner": "CortexKit", "repo": "AFT"});
        assert_eq!(
            resource_denial(&github, &write, &mixed_case),
            None,
            "a mixed-case GitHub name must pass its lowercase filter"
        );
        assert_eq!(
            resource_denial(
                &github,
                &write,
                &serde_json::json!({"owner": "CortexKit", "repo": "Plexus"})
            ),
            Some(ResourceDenial::ValueNotAllowed("repo".into())),
            "another repository is still refused"
        );
        assert_eq!(
            resource_denial(&other, &write, &mixed_case),
            Some(ResourceDenial::ValueNotAllowed("owner".into())),
            "filter values outside GitHub names stay exact"
        );
    }

    #[test]
    fn an_unknown_severity_string_gates_at_the_strongest_tier() {
        let path = crate::test_scratch::Scratch::database("unknown-tier");
        let engine = hash_test_engine_at(path.to_str().unwrap());
        let action = engine
            .store()
            .catalog_action("direct", "connection", "write_item")
            .unwrap()
            .unwrap();
        let db = rusqlite::Connection::open(&*path).unwrap();
        for tier in ["S5", "", "s1", "S1", "S2", "S3", "S4"] {
            db.execute("UPDATE app_manifests SET manifest_json=json_set(manifest_json,'$.tier',?1),content_hash=?1", [tier]).unwrap();
            let expected = match tier {
                "S1" | "S2" => Severity::S2,
                "S3" => Severity::S3,
                _ => Severity::S4,
            };
            assert_eq!(
                effective_severity(&action, "mock", engine.store()).unwrap(),
                expected,
                "{tier}"
            );
        }
        db.execute("DELETE FROM app_manifests", []).unwrap();
        assert_eq!(
            effective_severity(&action, "mock", engine.store()).unwrap(),
            Severity::S4
        );
        db.execute("DROP TABLE app_manifests", []).unwrap();
        assert!(
            effective_severity(&action, "mock", engine.store()).is_err(),
            "store errors must not become S4"
        );
    }

    /// A ROUTING failure and a VAULT failure must not render as the same code.
    ///
    /// Both are transient credential failures, and both used to surface as
    /// `credential_transient` — so an operator could not tell "the vault is
    /// briefly locked, wait" from "this module is dialling a credential-module
    /// id that no longer answers, fix the config". The second is invisible
    /// precisely when it matters: credential resolution refuses rather than
    /// degrades, so a stale route target produces a denial that reads like a
    /// policy decision.
    ///
    /// Asserts the codes are DISTINCT rather than pinning their spellings, so
    /// a later rename of a code still passes while a collapse fails.
    ///
    /// Mutation-proved: mapping all three variants back to one string fails
    /// this test.
    #[test]
    fn transient_credential_failures_are_distinguishable() {
        let route = Denial::Credential(CredentialDenial::Transient(
            TransientCredentialError::RefreshFailed,
        ));
        let locked = Denial::Credential(CredentialDenial::Transient(
            TransientCredentialError::VaultLocked,
        ));
        let overflow = Denial::Credential(CredentialDenial::Transient(
            TransientCredentialError::ContextOverflow,
        ));

        let codes = [
            route.reason_code(),
            locked.reason_code(),
            overflow.reason_code(),
        ];
        let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(
            distinct.len(),
            3,
            "each transient credential failure needs its own operator-visible code, got {codes:?}"
        );

        // The routing one is named specifically, because it is the case a
        // reader must be able to act on: it means our route target is wrong,
        // not that the vault is having a moment.
        assert_eq!(route.reason_code(), "credential_route_failed");

        // Still terminal for this attempt, and still a credential-gate denial:
        // naming the cause must not change the authority semantics.
        assert_eq!(gate_for_denial(&route), "credential");
    }

    #[test]
    fn denials_are_terminal_and_typed() {
        let denial = Denial::ResourceFilter(ResourceDenial::WriteFiltersAbsent);
        assert!(denial.terminal());
        assert_eq!(denial.retryability(), Retryability::Terminal);
        assert_eq!(denial.reason_code(), "write_filters_absent");
    }

    /// Two request IDs minted back to back, as an agent write and a background
    /// poll can be, must differ: calls sharing an ID interleave their audit
    /// journal rows and become indistinguishable there. IDs are random bytes
    /// (`storage::new_id`) with no clock component, so this holds however the
    /// clock moves; `request_ids_large_batch_are_all_distinct` covers many
    /// mints at once.
    #[test]
    fn back_to_back_request_ids_are_distinct_and_well_formed() {
        let id1 = new_request_id();
        let id2 = new_request_id();
        assert_ne!(id1, id2, "back-to-back request IDs must not collide");
        for id in [&id1, &id2] {
            assert!(
                id.starts_with("req_"),
                "request ID must retain req_ prefix: {id}"
            );
            assert_eq!(
                id.len(),
                28,
                "request ID must be 28 characters (req_ + 24 hex)"
            );
        }
    }

    /// Two authorization requests built back to back (such as an agent write
    /// and a poller read on different connections) receive distinct IDs.
    #[test]
    fn back_to_back_authorization_requests_receive_distinct_ids() {
        let write_req = AuthorizationRequest::new(
            "agent",
            "conn-example-rest",
            "add_reaction",
            serde_json::json!({"reaction": "eyes"}),
        );
        let poll_req = AuthorizationRequest::new(
            "poll",
            "conn-github-prs",
            "list_pull_requests",
            serde_json::json!({}),
        )
        .for_poll("sub-prs");
        assert_ne!(
            write_req.request_id, poll_req.request_id,
            "authorization requests built back to back must not share an ID"
        );
    }

    /// Mint a large batch of request IDs and assert that all generated IDs are distinct.
    #[test]
    fn request_ids_large_batch_are_all_distinct() {
        use std::collections::HashSet;
        const BATCH_SIZE: usize = 10_000;
        let mut seen = HashSet::with_capacity(BATCH_SIZE);
        for _ in 0..BATCH_SIZE {
            let id = new_request_id();
            assert!(
                id.starts_with("req_"),
                "request ID must retain req_ prefix: {id}"
            );
            assert_eq!(
                id.len(),
                28,
                "request ID must be 28 characters (req_ + 24 hex)"
            );
            assert!(
                seen.insert(id),
                "duplicate request ID observed in batch of {BATCH_SIZE}"
            );
        }
        assert_eq!(seen.len(), BATCH_SIZE);
    }
}
