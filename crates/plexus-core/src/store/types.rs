//! Shared storage records, request inputs, and refusal outcomes.

use super::*;

/// A principal-scoped connection projection. Credential bindings are deliberately
/// absent from this projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionSummary {
    pub connection_id: String,
    pub app_key: String,
    pub status: String,
    pub generation: i64,
}

/// Full connection state used by governance. Private instance addresses have a
/// redacted debug projection and are omitted from public connection summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub connection_id: String,
    pub principal: String,
    pub app_key: String,
    pub status: String,
    pub resource_filters: Value,
    pub health_state: Value,
    pub generation: i64,
    pub has_credential_binding: bool,
    pub instance_url: Option<crate::instance_url::InstanceUrl>,
}

/// What `PlexusStore::delete_connection` found, and did when applied.
///
/// `rows` lists, per table, how many rows keyed by the connection the delete
/// removes (dry run) or removed (applied), in deletion order, every table
/// listed even at zero. The connection row itself is not counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteConnectionOutcome {
    /// The principal owns no connection with that id.
    NotFound,
    /// The connection backs a GitHub App handle, whose connection is created
    /// and ended with the handle itself; nothing was written.
    HandleConnection,
    /// This many unexpired grants still reference the connection; nothing
    /// was written.
    HasLiveGrants { count: i64 },
    /// Dry run: what an apply would delete.
    WouldDelete {
        app_key: String,
        status: String,
        rows: Vec<(&'static str, i64)>,
    },
    /// Applied: the connection and these rows are gone.
    Deleted {
        app_key: String,
        status: String,
        rows: Vec<(&'static str, i64)>,
    },
}

/// Result of inserting or replacing a reviewed manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestWriteOutcome {
    pub changed: bool,
}

/// One GitHub handle catalog row moved from the open placeholder to its
/// reviewed argument schema by [`PlexusStore::pin_handle_placeholder_schemas`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHandleSchema {
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub schema_hash: String,
}

/// A GitHub handle catalog row left on the open placeholder because the
/// reviewed manifest offers no argument schema to pin for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleSchemaGap {
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    /// Why nothing could be pinned, e.g. the action has no `http.args_schema`.
    pub reason: &'static str,
}

/// What one [`PlexusStore::pin_handle_placeholder_schemas`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandleSchemaPinReport {
    pub pinned: Vec<PinnedHandleSchema>,
    pub gaps: Vec<HandleSchemaGap>,
}

/// The maximum authority a connection may ever delegate: which actions, and up
/// to what risk. Established at ticket issuance (the one step that proves
/// credential possession) and copied onto the connection when the ticket is
/// consumed. `action_selectors` is always a concrete expanded list — never a
/// stored wildcard — so authority is pinned at mint time and a vendor that
/// later gains actions cannot retroactively widen an existing ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceiling {
    pub risk: Risk,
    pub action_selectors: Vec<String>,
}

impl Ceiling {
    /// Test-only escape hatch preserving the pre-ceiling behaviour of the
    /// legacy ticket helpers: full write authority over every action. Not
    /// reachable from the operator surface, which always supplies an explicit
    /// manifest-bounded ceiling.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unrestricted_for_tests() -> Self {
        Self {
            risk: Risk::Destructive,
            action_selectors: vec!["*".to_string()],
        }
    }

    /// True when `self` authorizes nothing beyond `other`.
    pub fn within(&self, other: &Ceiling) -> bool {
        if !self.risk.within(other.risk) {
            return false;
        }
        // A wildcard in the bounding ceiling is only produced by the test helper
        // above; stored ceilings are always expanded.
        if other.action_selectors.iter().any(|value| value == "*") {
            return true;
        }
        self.action_selectors
            .iter()
            .all(|selector| other.action_selectors.contains(selector))
    }
}

/// One grant-mint request. Bundled rather than passed positionally so a call
/// site cannot silently transpose the principal, the grantee, and the risk.
#[derive(Debug, Clone)]
pub struct GrantMintRequest<'a> {
    /// The connection owner whose authority is being delegated.
    pub principal: &'a str,
    pub connection_id: &'a str,
    /// Who may exercise the grant.
    pub grantee_principal: &'a str,
    /// The grant's authority kind: `invoke`, `connection_admin`, `poll` or `events_consume`.
    pub authority_kind: &'a str,
    pub requested_risk: &'a str,
    pub requested_selectors: &'a [String],
    pub expires_at: Option<i64>,
}

/// Why a privileged ceremony operation was refused. Overreach is always
/// refused rather than clamped: a silent clamp would leave the operator
/// believing they authorized something they did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyRefusal {
    UnknownApp(String),
    /// The vendor is stored but withdrawn from the reviewed catalog.
    ///
    /// Distinct from `UnknownApp` because the two call for different operator
    /// actions: an unknown key is a typo or a vendor never reviewed, while a
    /// retired one was deliberately withdrawn and the operator needs to know a
    /// decision was made rather than hunt for a spelling mistake.
    RetiredApp(String),
    ConnectionNotFound,
    /// The connection predates authority ceilings, so no intent was ever
    /// recorded to bound a grant against.
    CeilingAbsent,
    /// An action the vendor's reviewed manifest never declares.
    UndeclaredAction(String),
    UnreviewedAction(String),
    ExplicitActionsRequired,
    HandleCeilingRequiresHandleGrant,
    /// The action is declared by the vendor, but sits outside the ceiling this
    /// CONNECTION was created with.
    ///
    /// Separate from `UndeclaredAction` because the operator's next step differs
    /// entirely: that one is a manifest problem, this one needs an explicit
    /// operator ceiling widening, not another ticket. Naming the ceiling saves
    /// the operator from querying the store to learn what they are bounded by.
    OutsideConnectionCeiling {
        action: String,
        ceiling: Vec<String>,
    },
    /// A risk above what the bounding ceiling permits.
    RiskAboveCeiling {
        requested: String,
        ceiling: String,
    },
    InvalidRisk(String),
    /// No actions remain after expanding the requested selectors.
    EmptyActionSelectors,
    /// A ticket named an existing connection of a different app. Its ceiling
    /// was resolved against the requested app's manifest, so attaching it to
    /// this connection would bound one vendor by another vendor's actions.
    ConnectionAppMismatch {
        connection_app: String,
        requested_app: String,
    },
    /// A ticket named a revoked connection. Revocation is final; recovery is a
    /// new connection under a new id.
    ConnectionRevoked,
    ConnectionExists,
    WildcardGrantee,
}

impl std::fmt::Display for CeremonyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownApp(key) => write!(f, "app '{key}' is not in the catalog"),
            Self::RetiredApp(key) => write!(
                f,
                "app '{key}' was withdrawn from the reviewed catalog and cannot be connected"
            ),
            Self::ConnectionNotFound => f.write_str("connection was not found"),
            Self::CeilingAbsent => {
                f.write_str("connection has no recorded authority ceiling; re-enroll it")
            }
            Self::UndeclaredAction(action) => {
                write!(
                    f,
                    "action '{action}' is not declared by the vendor manifest"
                )
            }
            Self::UnreviewedAction(action) => write!(f, "action '{action}' has no active reviewed catalog row on this connection"),
            Self::ExplicitActionsRequired => f.write_str("name each action explicitly; wildcard selectors are refused"),
            Self::HandleCeilingRequiresHandleGrant => f.write_str("GitHub bot handle connections must use handle-grant to widen their ceiling"),
            Self::OutsideConnectionCeiling { action, ceiling } => write!(
                f,
                "action '{action}' is outside this connection's ceiling [{}]",
                ceiling.join(", ")
            ),
            Self::RiskAboveCeiling { requested, ceiling } => {
                write!(f, "risk '{requested}' exceeds the ceiling '{ceiling}'")
            }
            Self::InvalidRisk(value) => write!(f, "'{value}' is not a valid risk"),
            Self::EmptyActionSelectors => {
                f.write_str("at least one action is required")
            }
            Self::ConnectionAppMismatch {
                connection_app,
                requested_app,
            } => write!(
                f,
                "this connection id belongs to app '{connection_app}', not '{requested_app}'; choose another connection id"
            ),
            Self::ConnectionExists => f.write_str("connection already exists; use rebind-credential to rotate its credential"),
            Self::WildcardGrantee => f.write_str("a grant must name an exact grantee, not '*'") ,
            Self::ConnectionRevoked => f.write_str(
                "this connection was revoked and cannot be re-enrolled; issue a ticket for a new connection id",
            ),
        }
    }
}

/// Ticket `ref_role` marking an enrollment for a vendor that needs no
/// credential at all. Distinct from any real credential role so a
/// credential-free connection can never be confused with one whose binding
/// simply failed to be written.
pub const NO_CREDENTIAL_REF_ROLE: &str = "none";

/// Outcome of configuring a connection's resource filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigureOutcome {
    /// Filters were replaced; carries the stored document.
    Configured(Value),
    /// The request carried a top-level key this operation does not read.
    ///
    /// Refused rather than ignored: an ignored key produces a success response
    /// beside filters that do not reflect what the caller asked for, and the
    /// operator's next move is to debug the vendor rather than their spelling.
    UnreadFilterKey {
        key: String,
        accepted: Vec<String>,
    },
    ConnectionNotFound,
    /// The connection's vendor manifest is no longer in the catalog, so there
    /// is nothing to bound the request against — refuse rather than trust it.
    ManifestMissing,
    /// A requested key is not declared by the vendor's manifest.
    UndeclaredFilter(String),
    /// A part of the request has the wrong JSON shape (`field` names it,
    /// `expected` says what it must be). Refused rather than dropped: a
    /// dropped part would report success beside filters the caller did not
    /// ask for.
    MalformedFilters {
        field: String,
        expected: String,
    },
    /// The caller holds no live connection-admin grant on the connection.
    /// Only [`PlexusStore::configure_connection_filters_if_admin`] returns it.
    AdminRequired,
}

/// Outcome of [`PlexusStore::revoke_connection_if_admin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionAdminRevokeOutcome {
    /// The connection is revoked and the transaction has committed.
    Revoked,
    /// The caller holds no live connection-admin grant; nothing was written.
    AdminRequired,
    /// No such connection, or it was already revoked.
    ConnectionNotFound,
}

/// App manifests are module-wide catalog DATA, not per-caller state: they are
/// ingested once at boot from the catalog directory and shared by every
/// principal. They are stored under this reserved principal so that
/// connection- and grant-scoped rows (which are genuinely per-caller) never
/// collide with them.
pub const CATALOG_PRINCIPAL: &str = "system";

#[derive(Clone, Copy)]
pub(crate) enum PlaneVerdict {
    Approved,
    Denied,
    Pending,
}

/// Pre-connection discovery view of an ingested app manifest: what an
/// operator needs to choose a vendor to connect, with no transport or
/// credential detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestSummary {
    pub key: String,
    pub name: String,
    pub description: String,
    pub tier: String,
    pub reuse_path: String,
    pub auth_mode: String,
    pub availability: String,
    pub action_count: usize,
    pub required_filters: Vec<String>,
    pub schema_version: u32,
    pub ingested_at_ms: i64,
    /// How many connections this principal already has for the vendor that
    /// can still serve. A revoked connection never becomes active again, so it
    /// is not counted.
    pub connection_count: i64,
}

/// A catalog action projection with no vendor credential state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogAction {
    pub connection_id: String,
    pub principal: String,
    pub name: String,
    pub title: Option<String>,
    pub schema: Value,
    pub schema_hash: String,
    pub risk: String,
    pub severity: String,
    /// Whether this action asks first on the default (no-policy) branch.
    /// Derived at reconcile time as the union of the hardcoded write/destructive
    /// floor and the manifest's declared `ask_first_risk`, so a manifest can
    /// widen but never narrow the floor. Fail-closed: a row with no recorded
    /// value reads as `true`.
    pub ask_first: bool,
    pub status: String,
    pub quarantine_reason: Option<String>,
    /// Declared write reconciliation class from the manifest/catalog, when present.
    pub reconciliation: Option<Value>,
    pub generation: i64,
}

/// The current catalog action together with the schema preserved for its review.
/// This projection is deliberately separate from [`CatalogAction`], which the
/// agent-facing catalog facade serializes and must not turn into a review surface.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatalogActionReview {
    pub action: CatalogAction,
    pub reviewed_schema: Option<Value>,
}

/// Input for inserting or refreshing an observed catalog action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogActionInput {
    pub connection_id: String,
    pub principal: String,
    pub name: String,
    pub title: Option<String>,
    pub schema: Value,
    pub schema_hash: String,
    pub risk: String,
    pub severity: String,
    /// Whether this action asks first on the default (no-policy) branch. The
    /// reconciler computes this from the manifest; see [`CatalogAction::ask_first`].
    pub ask_first: bool,
    pub status: String,
    pub quarantine_reason: Option<String>,
    pub reconciliation: Option<Value>,
}

/// Operator-selected authority used only to enrich a subscription's derived events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorSource {
    pub connection_id: String,
    pub action: String,
    pub methods: Vec<String>,
}

/// Durable state for one agent-configured polling lease.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TriggerSubscription {
    pub subscription_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub cadence_s: i64,
    pub cursor_kind: String,
    pub cursor_state: Value,
    pub fixed_args: Value,
    pub schema_hash: String,
    pub status: String,
    pub suspended_reason: Option<String>,
    pub last_polled_at_ms: Option<i64>,
    pub last_success_at_ms: Option<i64>,
    pub cursor_age_ms: Option<i64>,
    pub consecutive_vendor_failures: i64,
    pub generation: i64,
    pub created_at_ms: i64,
    /// When the authority behind this watch lapses.
    ///
    /// A watch's poll grant may expire or remain live until revoked. Report a
    /// configured deadline even after it lapses so consumers can explain a feed
    /// that stopped. `None` means either no matching grant or an unexpiring grant;
    /// inspect `authority_state` to distinguish those cases.
    pub authority_expires_at_ms: Option<i64>,
    /// Whether that authority currently authorizes this subscription's action:
    /// `live`, `expired`, or `absent`.
    ///
    /// NOT SUFFICIENT ALONE to decide whether a watch is healthy. Revoking a
    /// connection deliberately leaves its grants intact -- authority and health
    /// are separate questions, and revocation answers the second -- so a watch
    /// on a revoked connection reports `live` here while never polling again.
    /// A reader must consult `status` and `suspended_reason` too; the pair is
    /// pinned by a test, because a consumer rendering health from authority
    /// alone would show a healthy watch on a dead connection.
    ///
    /// Derived from `GrantRecord::authorizes` rather than by comparing the
    /// timestamp above against a clock, because that comparison is only half the
    /// predicate -- a grant can be unexpired and still not name this action. A
    /// consumer deriving liveness from the timestamp alone would report a watch
    /// as healthy when its grant covers something else, which is the exact
    /// misreading that made any poll grant authorize any subscription before
    /// `authorizes` existed.
    pub authority_state: String,
    /// The project this watch's events belong to, set by the operator.
    ///
    /// A subscription names a CONNECTION and an ACTION; for a per-repo watch the
    /// repository lives in `fixed_args`, which is vendor request parameters and
    /// nothing more. Neither says which project the work belongs to, so a
    /// consumer routing events to a project's agent has nothing to route ON.
    ///
    /// `None` means the operator named no project, and a consumer must treat
    /// that as LOUDLY UNROUTABLE rather than falling back to a guess. A repo
    /// slug and a checkout path are not project identity -- one project can span
    /// several repositories, and one repository can be checked out at many paths
    /// -- so a derived value routes confidently to the WRONG place, which is
    /// worse than refusing to route at all.
    pub project_id: Option<String>,
    /// The registry agent selected to receive this watch's events.
    ///
    /// `deliver_to` is delivery metadata rather than authority. A consumer reads
    /// it before project-derived routing, while `project_id` remains attribution
    /// and the fallback when no explicit delivery target is stored.
    pub deliver_to: Option<String>,
    /// The separately governed read action used to identify actors on derived
    /// events. `None` means no operator has bound an enrichment source; it never
    /// falls back to the watched connection because that connection may have a
    /// permanently narrower ceiling.
    pub actor_source: Option<ActorSource>,
    /// Probe display name. Vendor watches have none: they are identified by
    /// action. A listing that omitted this would force every consumer to join
    /// the companion table to answer "which probe fired".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Who registered a probe. Provenance, never ownership -- the subscription
    /// row belongs to the connection owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_by: Option<String>,
    /// `once` or `always` for a probe. Absent on vendor watches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rearm: Option<String>,
    /// The granted actions a probe may invoke. Absent on vendor watches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
}

/// Sentinel stored in `trigger_subscriptions.action` for a probe.
///
/// A probe watches a SET of actions, not one vendor endpoint, so the shared
/// column cannot name the thing being polled. The real set lives on the
/// companion row. This value keeps the NOT NULL column honest and lets the
/// poller branch on `cursor_kind` rather than on an action name that could
/// collide with a real vendor action.
pub const PROBE_SUBSCRIPTION_ACTION: &str = "probe";

/// The sole suspension reason an operator may resume.
///
/// A circuit breaker stops repeated vendor calls without changing the watch's
/// authority or reviewed safety. Every other suspension reason records a safety
/// decision and must remain stopped until a separate review resolves it.
pub const CIRCUIT_BREAKER_SUSPENSION_REASON: &str = "circuit_breaker_vendor_failures";

/// Durable probe-only fields, keyed on the subscription they belong to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeSubscription {
    pub subscription_id: String,
    pub name: String,
    pub actions: Vec<String>,
    pub script_source: String,
    pub return_schema: Value,
    pub rearm: String,
    pub registered_by: String,
}

/// Inputs for registering a probe against a connection the caller may poll.
pub struct ProbeRegistration<'a> {
    pub name: &'a str,
    pub actions: &'a [String],
    pub script_source: &'a str,
    pub return_schema: &'a Value,
    pub rearm: &'a str,
    pub cadence_s: i64,
    pub fixed_args: &'a Value,
    pub cursor_state: &'a Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionRefusal {
    InvalidCadence,
    ConnectionNotFound,
    ConnectionInactive(String),
    ActionNotFound,
    ActionRiskNotRead,
    /// A seeded cursor state carries a key the cursor kind does not read.
    ///
    /// Refused rather than ignored because ignoring it produces a working-looking
    /// watch that behaves as though it were never seeded, and the difference is
    /// exactly the first event.
    CursorStateKeyUnknown {
        key: String,
        accepted: Vec<String>,
    },
    ActionUnavailable(String),
    ManifestMissing,
    ManifestInvalid(String),
    CursorShapeMissing,
    SnapshotItemCountCeilingRequired,
    PollGrantRequired,
    FixedArgsMustBeObject,
    FixedArgCursorOwned(String),
    FixedArgRequestConstant(String),
    FixedArgNotDeclared(String),
    /// The action's schema requires an argument the subscription does not supply
    /// and the poller cannot produce.
    FixedArgRequiredMissing(String),
    FixedArgTypeMismatch {
        key: String,
        expected: String,
        actual: String,
    },
    /// A probe named an action the authorizing poll grant does not cover.
    ///
    /// Registration mints nothing: every declared action must already be on
    /// that grant. Refusing here is what keeps a plan that needs new authority
    /// parked as an operator ask rather than silently widening the grant.
    ActionNotCoveredByGrant {
        action: String,
    },
    ProbeNameRequired,
    ProbeScriptRequired,
    ProbeSourceTooLarge,
    ProbeActionsRequired,
    ProbeReturnSchemaInvalid(String),
    ProbeRearmInvalid,
    /// `fixed_args` for a probe is a map of action name to that action's args,
    /// not a single flat object. A flat object would be validated against one
    /// schema and then applied to every action, which is the wrong check.
    FixedArgsMustBePerActionMap,
    /// Two connection owners granted this caller the same connection id.
    AmbiguousConnectionOwner,
}

/// Why a stored subscription cannot be resumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionResumeRefusal {
    SubscriptionNotFound,
    SubscriptionRetired,
    PollGrantRequired,
    /// Only a circuit-breaker suspension is operational. The optional value is
    /// retained so the caller can see the exact safety decision that blocked
    /// resumption; a missing stored reason is itself not safe to override.
    SuspensionNotResumable(Option<String>),
}

/// Why an operator-reviewed action could not be re-pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepinActionRefusal {
    ActionNotFound,
    ActionNotQuarantined(String),
    RiskNotRead(String),
    ExpectedHashMismatch { expected: String, current: String },
}

impl RepinActionRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ActionNotFound => "action_not_found",
            Self::ActionNotQuarantined(_) => "action_not_quarantined",
            Self::RiskNotRead(_) => "action_risk_not_read",
            Self::ExpectedHashMismatch { .. } => "expected_schema_hash_mismatch",
        }
    }
}

impl std::fmt::Display for RepinActionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionNotFound => formatter.write_str("action was not found in the catalog"),
            Self::ActionNotQuarantined(status) => {
                write!(formatter, "action is not quarantined (status: {status})")
            }
            Self::RiskNotRead(risk) => {
                write!(
                    formatter,
                    "action risk is '{risk}', but re-pinning requires read risk"
                )
            }
            Self::ExpectedHashMismatch { expected, current } => write!(
                formatter,
                "reviewed schema hash '{expected}' no longer matches current hash '{current}'"
            ),
        }
    }
}

impl SubscriptionResumeRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SubscriptionNotFound => "subscription_not_found",
            Self::PollGrantRequired => "poll_grant_required",
            Self::SuspensionNotResumable(_) => "suspension_not_resumable",
            Self::SubscriptionRetired => "subscription_retired",
        }
    }
}

impl std::fmt::Display for SubscriptionResumeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubscriptionRetired => {
                formatter.write_str("one-shot probe has finished and cannot be resumed")
            }
            Self::SubscriptionNotFound => formatter.write_str("subscription was not found"),
            Self::PollGrantRequired => {
                formatter.write_str("a poll grant permitting this action is required")
            }
            Self::SuspensionNotResumable(Some(reason)) => write!(
                formatter,
                "subscription suspended for '{reason}' cannot be resumed"
            ),
            Self::SuspensionNotResumable(None) => formatter
                .write_str("subscription has no recorded suspension reason and cannot be resumed"),
        }
    }
}

impl SubscriptionRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidCadence => "invalid_cadence",
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionInactive(_) => "connection_inactive",
            Self::ActionNotFound => "action_not_found",
            Self::ActionRiskNotRead => "trigger_requires_read_action",
            Self::ActionUnavailable(_) => "action_unavailable",
            Self::ManifestMissing => "manifest_missing",
            Self::ManifestInvalid(_) => "manifest_invalid",
            Self::CursorShapeMissing => "cursor_shape_missing",
            Self::SnapshotItemCountCeilingRequired => "snapshot_item_count_ceiling_required",
            Self::PollGrantRequired => "poll_grant_required",
            Self::FixedArgsMustBeObject => "fixed_args_must_be_object",
            Self::FixedArgCursorOwned(_) => "fixed_arg_cursor_owned",
            Self::FixedArgRequestConstant(_) => "fixed_arg_request_constant",
            Self::FixedArgNotDeclared(_) => "fixed_arg_not_declared",
            Self::FixedArgRequiredMissing(_) => "fixed_arg_required_missing",
            Self::FixedArgTypeMismatch { .. } => "fixed_arg_type_mismatch",
            Self::CursorStateKeyUnknown { .. } => "cursor_state_key_unknown",
            Self::ActionNotCoveredByGrant { .. } => "action_not_covered_by_grant",
            Self::ProbeNameRequired => "probe_name_required",
            Self::ProbeScriptRequired => "probe_script_required",
            Self::ProbeSourceTooLarge => "probe_source_too_large",
            Self::ProbeActionsRequired => "probe_actions_required",
            Self::ProbeReturnSchemaInvalid(_) => "probe_return_schema_invalid",
            Self::ProbeRearmInvalid => "probe_rearm_invalid",
            Self::FixedArgsMustBePerActionMap => "fixed_args_must_be_per_action_map",
            Self::AmbiguousConnectionOwner => "ambiguous_connection_owner",
        }
    }
}

impl std::fmt::Display for SubscriptionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCadence => formatter.write_str("cadence_s must be positive"),
            Self::ConnectionNotFound => formatter.write_str("connection was not found"),
            Self::ConnectionInactive(status) => {
                write!(formatter, "connection is not active (status: {status})")
            }
            Self::ActionNotFound => formatter.write_str("action was not found in the catalog"),
            Self::ActionRiskNotRead => {
                formatter.write_str("triggers require an action with read risk")
            }
            // Names the accepted keys, because the caller supplied a starting
            // state on purpose and the useful reply is which spelling this
            // cursor kind reads -- not merely that theirs was wrong.
            Self::CursorStateKeyUnknown { key, accepted } => write!(
                formatter,
                "cursor_state key '{}' is not read by this cursor kind (accepted: {})",
                crate::text::refusal_echo(key),
                accepted.join(", ")
            ),
            Self::ActionUnavailable(reason) => write!(formatter, "action is unavailable: {reason}"),
            Self::ManifestMissing => formatter.write_str("vendor manifest is not in the catalog"),
            Self::ManifestInvalid(reason) => {
                write!(formatter, "vendor manifest is invalid: {reason}")
            }
            Self::CursorShapeMissing => {
                formatter.write_str("action has no usable polling cursor shape")
            }
            Self::SnapshotItemCountCeilingRequired => {
                formatter.write_str("snapshot diff requires a positive item-count ceiling")
            }
            Self::PollGrantRequired => {
                formatter.write_str("a poll grant permitting this action is required")
            }
            Self::FixedArgsMustBeObject => formatter.write_str("fixed_args must be an object"),
            Self::FixedArgCursorOwned(key) => write!(
                formatter,
                "fixed_args key '{}' is owned by the cursor strategy",
                crate::text::refusal_echo(key)
            ),
            Self::FixedArgRequestConstant(key) => write!(
                formatter,
                "fixed_args key '{}' collides with a manifest request constant",
                crate::text::refusal_echo(key)
            ),
            Self::FixedArgNotDeclared(key) => write!(
                formatter,
                "fixed_args key '{}' is not declared by the action schema",
                crate::text::refusal_echo(key)
            ),
            Self::FixedArgRequiredMissing(key) => write!(
                formatter,
                "the action requires '{}', which fixed_args must supply",
                crate::text::refusal_echo(key)
            ),
            Self::FixedArgTypeMismatch {
                key,
                expected,
                actual,
            } => write!(
                formatter,
                "fixed_args key '{}' has type {actual}, expected {expected}",
                crate::text::refusal_echo(key)
            ),
            Self::ActionNotCoveredByGrant { action } => {
                write!(
                    formatter,
                    "poll grant does not cover action '{}'",
                    crate::text::refusal_echo(action)
                )
            }
            Self::ProbeNameRequired => formatter.write_str("probe name must be non-empty"),
            Self::ProbeScriptRequired => {
                formatter.write_str("probe script_source must be non-empty")
            }
            Self::ProbeSourceTooLarge => write!(
                formatter,
                "probe script_source exceeds {} bytes",
                plexus_probe::MAX_SOURCE_BYTES
            ),
            Self::ProbeActionsRequired => {
                formatter.write_str("probe must declare at least one action")
            }
            Self::ProbeReturnSchemaInvalid(reason) => {
                write!(
                    formatter,
                    "probe return_schema is invalid: {}",
                    crate::text::refusal_echo(reason)
                )
            }
            Self::ProbeRearmInvalid => {
                formatter.write_str("probe rearm must be 'once' or 'always'")
            }
            Self::FixedArgsMustBePerActionMap => {
                formatter.write_str("probe fixed_args must be an object keyed by action name")
            }
            Self::AmbiguousConnectionOwner => formatter.write_str(
                "more than one connection owner granted this caller the named connection",
            ),
        }
    }
}

/// One stored `events_consume` grant the caller may exercise.
///
/// This is deliberately grant-scoped rather than collapsed to one caller-wide
/// state. A consumer can be live on one connection while expired on another,
/// and reducing those facts to one scalar would recreate the ambiguity this
/// projection exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventsConsumeAuthority {
    pub principal: String,
    pub connection_id: String,
    /// The grant deadline, retained after lapse so `expired` is actionable.
    pub authority_expires_at_ms: Option<i64>,
    /// Uses the subscription authority vocabulary: `live` or `expired` here.
    /// `absent` is represented by no record in the complete authority list.
    pub authority_state: String,
}

/// Events visible to a caller together with the grants that made widening
/// possible. Keeping both in one result ensures the authority projection comes
/// from the same grant rows used to select events.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventsIncludingGranted {
    pub events: Vec<TriggerEvent>,
    /// Every `events_consume` grant this caller can exercise. A principal and
    /// connection absent from this complete list has no such grant.
    pub consume_authority: Vec<EventsConsumeAuthority>,
}

/// An event, or a marker recording that polling was suspended or otherwise
/// missed part of the vendor history, in the durable log.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TriggerEvent {
    pub event_id: String,
    pub principal: String,
    pub connection_id: String,
    pub subscription_id: String,
    pub vendor_event_id: Option<String>,
    pub payload_hash: String,
    pub payload: Value,
    pub kind: String,
    pub gap_from_ms: Option<i64>,
    pub gap_to_ms: Option<i64>,
    pub gap_reason: Option<String>,
    pub observed_at_ms: i64,
    pub acked_at_ms: Option<i64>,
    pub created_at_ms: i64,
    /// What the vendor's reviewed manifest says this action yields: `issue`,
    /// `pull_request`, `release`.
    ///
    /// DISTINCT FROM `kind` ABOVE, which is `event` or `gap` -- the two answer
    /// different questions and sharing a name would make a misread silent. This
    /// one says what the thing IS; `kind` says whether the row delivers content
    /// or records a hole in coverage.
    ///
    /// `None` on rows written before the manifest carried it, and on the direct
    /// insert path which has no manifest context to classify from.
    pub item_kind: Option<String>,
    /// When the vendor last touched this item, as the cursor strategy parsed it.
    ///
    /// Lets a consumer ask "has anything happened since I saw this?" without
    /// re-parsing a vendor-specific date field out of the payload. `None` for
    /// strategies with no per-item time: sync-token ordering is opaque and a
    /// scalar watch observes a value rather than a dated item.
    pub activity_at_ms: Option<i64>,
    /// GitHub logins that authored comments in this event's observation window.
    ///
    /// Absent means actor identity is unknown. A present empty array is narrower:
    /// the governed read succeeded and the first-observation window contained no
    /// comments. Unknown must stay absent on the wire so a consumer cannot mistake
    /// a failed enrichment for a known empty actor set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_logins: Option<Vec<String>>,
    /// Why the actors are unknown, as `{"reason": "<code>", "class": "<class>"}`.
    ///
    /// For an event whose subscription has an actor source, exactly one of
    /// this and `actor_logins` is present. Events with no actor source (release
    /// watches) and coverage gaps carry neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_unknown: Option<ActorUnknown>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerEventInsertOutcome {
    Inserted {
        event_id: String,
    },
    Duplicate {
        event_id: String,
        payload_hash: String,
    },
}

/// A selected watch may become inactive, or receive invalid poll input,
/// without the database failing.
#[derive(Debug)]
pub enum PollCommitError {
    Inactive,
    InvalidInput(&'static str),
    Store(StoreError),
}
impl From<StoreError> for PollCommitError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
impl std::fmt::Display for PollCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => formatter.write_str("subscription is no longer active"),
            Self::InvalidInput(reason) => formatter.write_str(reason),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for PollCommitError {}

/// One event extracted from a vendor response, borrowed for an atomic poll commit.
#[derive(Clone, Copy)]
pub struct PollEventInput<'a> {
    pub vendor_event_id: &'a str,
    pub payload: &'a Value,
    pub observed_at_ms: i64,
    /// What the reviewed manifest says this action yields. Constant for every
    /// event in one poll, carried per event so the row is self-describing.
    pub item_kind: Option<&'a str>,
    /// When the vendor last touched this item, as the strategy parsed it.
    pub activity_at_ms: Option<i64>,
    /// What the subscription's independent enrichment read learned about this
    /// event's actors: a login list (possibly a known-empty one), the reason
    /// they are unknown, or nothing because no enrichment applies.
    pub actor: &'a ActorAttribution,
}

/// One grant as an operator reads it: what it authorizes, on which vendor, who
/// holds it, and whether it is still in force.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantSummary {
    pub grant_id: String,
    pub connection_id: String,
    /// The vendor this connection speaks to. `None` only if the connection row is
    /// gone, which is itself worth showing rather than hiding.
    pub app_key: Option<String>,
    pub grantee_principal: String,
    pub risk_ceiling: String,
    pub action_selectors: Vec<String>,
    pub authority_kind: String,
    pub expires_at: Option<i64>,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub revoked_by: Option<String>,
    /// `revoked` | `until_revoked` | `live` | `expired`, derived here so no two readers can
    /// disagree about it.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub grant_id: String,
    pub principal: String,
    pub connection_id: String,
    pub grantee_principal: String,
    pub risk_ceiling: String,
    pub action_selectors: Vec<String>,
    pub authority_kind: String,
    pub expires_at: Option<i64>,
    pub generation: i64,
    pub revoked_at_ms: Option<i64>,
    pub revoked_by: Option<String>,
    pub state: String,
}

pub(super) fn grant_state(
    expires_at: Option<i64>,
    revoked_at_ms: Option<i64>,
    now: i64,
) -> &'static str {
    if revoked_at_ms.is_some() {
        "revoked"
    } else {
        match expires_at {
            Some(deadline) if deadline <= now => "expired",
            Some(_) => "live",
            None => "until_revoked",
        }
    }
}

impl GrantRecord {
    /// Whether this grant actually authorizes `action` at time `now`.
    ///
    /// Exists because `matching_grant` returns the NEAREST grant rather than an
    /// authorizing one -- it deliberately falls back to a grant that names the
    /// action but has expired, and then to one that is live but covers
    /// something else, so a caller can report a specific reason for the
    /// refusal. Its `Some` therefore means "here is the most relevant grant",
    /// never "this is allowed".
    ///
    /// A caller reading that `Some` as permission grants everything the
    /// fallbacks were meant to explain. That is not hypothetical: subscription
    /// creation did exactly this, so any poll grant on a connection authorized
    /// a subscription to any other action, and an expired grant authorized one
    /// too. Callers that need a verdict rather than an explanation should ask
    /// here rather than re-deriving the two conditions, since a re-derivation
    /// that omits one looks identical to a correct check at the call site.
    pub fn authorizes(&self, action: &str, now: i64) -> bool {
        let live = !self.expires_at.is_some_and(|expires_at| expires_at <= now);
        let names_action = self
            .action_selectors
            .iter()
            .any(|selector| selector == action || selector == "*");
        self.revoked_at_ms.is_none() && live && names_action
    }
}

/// Pick the one grant that answers "may this action run?" from every grant
/// row that could apply to a request. Grants are additive, so a live grant
/// that names the action wins wherever it sits in the list; the first row in
/// storage order must never decide on its own.
///
/// When no live grant names the action, the remaining fallbacks are ordered
/// by how specifically they answer the operator's question -- "why can this
/// action not run?".
///
/// A grant that NAMES the action and has expired is the most specific answer
/// available, so it outranks a live grant that simply covers something else.
/// The reverse order produces a genuinely misleading denial: a connection
/// watching two actions, where one poll grant lapses, would report the
/// surviving grant's selector mismatch and send an operator hunting a scope
/// problem when the fix is to renew. Poll grants may have a deadline or remain
/// live until revoked; this fallback explains the ones that do expire.
///
/// None of this changes WHETHER the request is refused. All three fallbacks
/// are refusals; the ordering only decides which reason the caller reports.
pub(crate) fn grant_candidate<'a>(
    rows: impl IntoIterator<Item = &'a GrantRecord>,
    action: &str,
    now: i64,
    requested_risk: Option<&str>,
) -> Option<&'a GrantRecord> {
    let mut live_matching = None;
    let mut candidate = None;
    let mut expired_matching = None;
    let mut expired_other = None;
    for grant in rows {
        let names_action = grant
            .action_selectors
            .iter()
            .any(|selector| selector == action || selector == "*");
        if grant.expires_at.is_some_and(|expires_at| expires_at <= now) {
            if names_action {
                expired_matching = Some(grant);
            } else {
                expired_other = Some(grant);
            }
            continue;
        }
        if names_action {
            if live_matching.is_none() {
                live_matching = Some(grant);
            }
            let covers_risk = requested_risk.is_none_or(|risk| {
                Risk::parse(risk)
                    .zip(Risk::parse(&grant.risk_ceiling))
                    .is_some_and(|(requested, ceiling)| requested.within(ceiling))
            });
            if covers_risk {
                return Some(grant);
            }
            continue;
        }
        if candidate.is_none() {
            candidate = Some(grant);
        }
    }
    live_matching
        .or(expired_matching)
        .or(candidate)
        .or(expired_other)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantInput {
    pub grant_id: String,
    pub principal: String,
    pub connection_id: String,
    pub grantee_principal: String,
    pub risk_ceiling: String,
    pub action_selectors: Vec<String>,
    pub authority_kind: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    pub policy_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action_selector: String,
    pub effect: String,
    pub expires_at: Option<i64>,
    pub generation: i64,
}

/// One policy as an operator reads it, with the connection's vendor and its
/// current liveness derived by the store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicySummary {
    pub policy_id: String,
    pub connection_id: String,
    /// The vendor this connection speaks to. `None` means the connection was
    /// removed but the policy remains visible so an operator can remove it.
    pub app_key: Option<String>,
    pub action_selector: String,
    pub effect: String,
    pub expires_at: Option<i64>,
    /// `until_revoked` | `live` | `expired`, derived once by the store.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInput {
    pub policy_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action_selector: String,
    pub effect: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGenerations {
    pub connection: i64,
    pub catalog_action: i64,
    pub grant: i64,
    pub policy: i64,
    #[serde(default)]
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRecord {
    pub reservation_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    /// The grant that authorized this reservation. Revalidation pins THIS row
    /// rather than comparing a maximum across matching grants, so revoking the
    /// authorizing grant invalidates the reservation even when other grants on
    /// the same action survive.
    pub grant_id: String,
    pub snapshot: SnapshotGenerations,
    pub approved_args_hash: String,
    pub schema_hash: String,
    pub expires_at: i64,
    pub status: String,
    /// For a call made as an agent, the agent grant that authorized it and
    /// that grant's generation then. The claim pins it like the module grant,
    /// so revoking the agent grant before the send aborts the call.
    pub agent_grant: Option<PinnedGrant>,
}

/// A grant row and the generation it had when a reservation was authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedGrant {
    pub grant_id: String,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingTicket {
    pub ticket_id: String,
    pub principal: String,
    pub connection_id: String,
    pub ref_role: String,
    pub expires_at: i64,
    pub status: String,
    pub instance_url: Option<crate::instance_url::InstanceUrl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionRequestRecord {
    pub request_id: String,
    pub principal: String,
    pub connection_id: String,
    pub action: String,
    pub args_snapshot: Value,
    pub args_hash: String,
    pub schema_hash: String,
    pub requester: String,
    pub status: String,
    pub decision: Option<String>,
    pub decider: Option<String>,
    pub expires_at: i64,
    /// Decision-plane decision id when the request was decision-authorized, if any.
    pub decision_id: Option<String>,
    /// `pending` | `confirmed` | `not_found` | `ambiguous` for outcome_unknown writes.
    pub reconciliation_status: Option<String>,
    /// The daemon scope the request was raised under; absent for a request
    /// raised on a route bound without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RequestScope>,
    /// What re-checking that scope at execution decided: `approved_waiting`
    /// while the approval is held unsent, `not_run:<reason>` when refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_outcome: Option<String>,
    /// The key the carrier (`requester`) gave the call that raised this
    /// request, by which it can withdraw the call. Absent for a call sent
    /// without a key, which cannot be withdrawn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_key: Option<String>,
    /// True when the request was withdrawn by its carrier or its scope's
    /// owner (status `cancelled`), so whoever reviews the request list sees
    /// that it was withdrawn and will never run, not merely that it is closed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub withdrawn: bool,
    /// The call from which the requesting call was relayed, when the relay
    /// stated one. Kept for attribution and deliberately not serialized: these
    /// are caller-stated identifiers, never shown in a reply to the caller.
    #[serde(skip)]
    pub relay_origin: Option<RelayOrigin>,
    /// The consent card filed with Cingulate for this request, when
    /// filing succeeded. The user can answer the request from that card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elicitation_id: Option<String>,
}

/// How one consent answer settles a still-pending approval request, stored by
/// [`PlexusStore::settle_consent_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentSettlement {
    /// The user declined the request on its card.
    Denied {
        principal: String,
        request_id: String,
        /// Who decided, as written in the request's `decider` column.
        decider: String,
    },
    /// The consent card expired without granting approval.
    Expired {
        principal: String,
        request_id: String,
    },
}

/// The call a relayed tool call came from, as the relay stated it in the
/// call's top-level `origin` member: the principal that carried the original
/// call and that carrier's key for it.
///
/// Caller-stated and recorded for attribution only. Nothing keys, dedupes,
/// authorizes or withdraws on it: every record of the relayed call stays
/// keyed on the principal that carried it here and that call's own
/// `call_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOrigin {
    /// The original carrier as a principal key, the form every principal
    /// column in this store uses, e.g. `reserved:broca`.
    pub carrier: String,
    /// The original carrier's key for the original call.
    pub call_key: String,
}

/// The status of an approval request that was withdrawn with `tool.withdraw`.
/// Terminal: nothing decides, claims or retries a request in this status.
pub const REQUEST_CANCELLED: &str = "cancelled";

/// The scope an approval request was raised under, as stored with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestScope {
    pub owner: String,
    #[serde(rename = "ref")]
    pub scope_ref: String,
    pub scope_epoch: u64,
    /// The scope's agent when the request was raised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    pub delegates: bool,
    pub owner_authorized: bool,
}

impl RequestScope {
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_call_scope(scope: &CallScope) -> Self {
        Self {
            owner: scope.owner.clone(),
            scope_ref: scope.scope_ref.clone(),
            scope_epoch: scope.scope_epoch,
            agent_id: scope.agent_id.clone(),
            flow_id: scope.flow_id.clone(),
            delegates: scope.delegates,
            owner_authorized: scope.owner_authorized,
        }
    }

    /// The scope as a call carries it, for re-authorizing the request. The
    /// stamp fields an approval does not keep (`kind`, `parent`,
    /// `parent_state`) are absent.
    pub fn to_call_scope(&self) -> CallScope {
        CallScope {
            owner: self.owner.clone(),
            scope_ref: self.scope_ref.clone(),
            scope_epoch: self.scope_epoch,
            kind: None,
            parent: None,
            parent_state: None,
            agent_id: self.agent_id.clone(),
            delegates: self.delegates,
            owner_authorized: self.owner_authorized,
            flow_id: self.flow_id.clone(),
        }
    }
}

/// A fully read-back audit row. It intentionally mirrors only redacted columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(any(test, feature = "test-support"))]
pub struct AuditRow {
    pub journal_id: i64,
    pub app_handle_id: Option<String>,
    pub ts: i64,
    pub principal: String,
    pub actor: String,
    pub acting_principal: String,
    pub agent_id: Option<String>,
    pub agent_handle: Option<String>,
    pub connection_id: Option<String>,
    pub app_key: Option<String>,
    pub action: Option<String>,
    pub risk: Option<String>,
    pub severity: Option<String>,
    pub decision: String,
    pub reason_code: String,
    pub gate: Option<String>,
    pub args_redaction_summary: Option<String>,
    pub outcome: Option<String>,
    pub latency_ms: Option<i64>,
    pub request_id: Option<String>,
    pub credential_fingerprint: Option<String>,
    pub provider_account_fingerprint: Option<String>,
    pub attempt_no: Option<i64>,
    pub vendor_request_id: Option<String>,
    pub idempotency_key_fingerprint: Option<String>,
    pub response_class: Option<String>,
    pub reconciliation_of: Option<String>,
    /// The daemon scope the call's route was bound under, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<CallScope>,
    /// The agent the call's worker scope worked for, when it named one.
    /// Attribution only, and never the same thing as `agent_id`.
    pub scope_on_behalf_of_agent: Option<String>,
}

/// One grant row attributed to an agent: what revoking it needs, plus the
/// connection for the audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHeldGrant {
    pub principal: String,
    pub grant_id: String,
    pub connection_id: String,
}

/// The append-only audit input. Optional fields are nullable because startup
/// manifest events do not have a connection, request, or vendor response yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub principal: String,
    pub actor: String,
    pub acting_principal: String,
    pub agent_id: Option<String>,
    pub app_handle_id: Option<String>,
    pub agent_handle: Option<String>,
    pub connection_id: Option<String>,
    pub app_key: Option<String>,
    pub action: Option<String>,
    pub risk: Option<String>,
    pub severity: Option<String>,
    pub decision: String,
    pub reason_code: String,
    pub gate: Option<String>,
    pub args_redaction_summary: Option<String>,
    pub outcome: Option<String>,
    pub latency_ms: Option<i64>,
    pub request_id: Option<String>,
    pub credential_fingerprint: Option<String>,
    pub provider_account_fingerprint: Option<String>,
    pub attempt_no: Option<i64>,
    pub vendor_request_id: Option<String>,
    pub idempotency_key_fingerprint: Option<String>,
    pub response_class: Option<String>,
    pub reconciliation_of: Option<String>,
}

impl AuditRecord {
    /// Record a privileged ceremony operation. The credential handle is recorded
    /// as a fingerprint only, per the secret-dataflow model: the audit journal is
    /// an enumerated prohibited sink for raw handles.
    pub fn ceremony(
        principal: &str,
        app_key: Option<&str>,
        connection_id: Option<&str>,
        operation: &str,
        granted_risk: &str,
        handle_fingerprint: Option<&str>,
    ) -> Self {
        Self {
            principal: principal.to_string(),
            actor: "operator".to_string(),
            acting_principal: principal.to_string(),
            agent_id: None,
            agent_handle: None,
            app_handle_id: None,
            connection_id: connection_id.map(str::to_owned),
            app_key: app_key.map(str::to_owned),
            action: Some(operation.to_string()),
            risk: Some(granted_risk.to_string()),
            severity: None,
            decision: "allow".to_string(),
            reason_code: format!("ceremony_{operation}"),
            gate: Some("operator_ceremony".to_string()),
            args_redaction_summary: Some("privileged ceremony arguments withheld".to_string()),
            outcome: Some("recorded".to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: handle_fingerprint.map(str::to_owned),
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        }
    }

    /// Record one grant removed because prefrontal reports its agent retired.
    ///
    /// The actor is plexus itself: no operator asked for this, the scheduled
    /// retirement sweep did. The grant id goes in the summary because the audit
    /// row has no grant column, and an operator reconciling a revocation needs
    /// to know which row went.
    pub fn agent_retired_revocation(
        principal: &str,
        agent_id: &str,
        connection_id: &str,
        grant_id: &str,
    ) -> Self {
        Self {
            principal: principal.to_string(),
            actor: "plexus".to_string(),
            acting_principal: principal.to_string(),
            agent_id: Some(agent_id.to_string()),
            agent_handle: None,
            app_handle_id: None,
            connection_id: Some(connection_id.to_string()),
            app_key: None,
            action: Some("revoke_grant".to_string()),
            risk: None,
            severity: None,
            decision: "allow".to_string(),
            reason_code: crate::agent_retirement::AGENT_RETIRED_REASON.to_string(),
            gate: Some("agent_retirement_sweep".to_string()),
            args_redaction_summary: Some(format!("grant {grant_id} revoked")),
            outcome: Some("recorded".to_string()),
            latency_ms: None,
            request_id: None,
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: None,
        }
    }

    pub fn manifest_changed(principal: &str, app_key: &str) -> Self {
        Self {
            principal: principal.to_string(),
            actor: "plexus".to_string(),
            acting_principal: principal.to_string(),
            agent_id: None,
            agent_handle: None,
            app_handle_id: None,
            connection_id: None,
            app_key: Some(app_key.to_string()),
            action: Some("manifest_changed".to_string()),
            risk: None,
            severity: None,
            decision: "allow".to_string(),
            reason_code: "manifest_changed".to_string(),
            gate: Some("manifest_ingest".to_string()),
            args_redaction_summary: Some("manifest content hash changed".to_string()),
            outcome: Some("recorded".to_string()),
            latency_ms: None,
            request_id: None,
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
