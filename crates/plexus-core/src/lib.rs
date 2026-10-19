//! Pure domain primitives for the ck-plexus connector substrate.
//!
//! This crate owns the closed AppManifest model, ingest hashing, fingerprint
//! helper, versioned storage schema, MCP transport, catalog reconciler, and
//! credential-vault route adapter. The pure domain portions remain testable without a
//! daemon; the route adapter is only exercised when a route peer is supplied.

#![forbid(unsafe_code)]

/// The `tracing` re-export [`diag!`] reaches through `$crate`.
///
/// The macro expands in whichever crate wrote the diagnostic, so every path it
/// names has to resolve there. Naming this one through `$crate` keeps the fleet
/// event in one place: the daemon crate needs neither a `tracing` dependency of
/// its own nor a second copy of the event.
#[doc(hidden)]
pub use tracing as __diag_tracing;

/// Format a diagnostic's arguments on THIS side of the `tracing` macro that
/// emits it, then hand the result over.
///
/// `tracing`'s macros bring names of their own into scope inside their
/// expansion (`Value`, for one), and `macro_rules!` resolves paths where a
/// macro expands rather than where it was written. A diagnostic whose argument
/// reads `Value::as_str` therefore binds the wrong `Value` if the argument is
/// passed straight through. Formatting through a parameter keeps every
/// call-site expression outside that expansion: the only name crossing the
/// boundary is `args`, which belongs to the macro. The closure is what makes
/// that possible at all, since a `fmt::Arguments` cannot be held in a `let`.
#[doc(hidden)]
pub fn __diag_formatted(args: std::fmt::Arguments<'_>, emit: impl FnOnce(std::fmt::Arguments<'_>)) {
    emit(args);
}

/// Emit one daemon diagnostic with the level and component attribution the
/// shared host log requires.
///
/// A site is written in the order the line renders — level, component, message
/// — so `diag!(warn scheduler: "audit retention pass failed: {error}")` reaches
/// an operator as `<ts> WARN  plexus.scheduler: audit retention pass failed:
/// ...`. Both crate-level `eprintln!` shadows expand into this, and neither
/// accepts a bare message any more: a diagnostic nobody chose a level for is a
/// diagnostic nobody decided the audience of, and that decision belongs to
/// whoever writes the site rather than to whoever later reads a log full of
/// them.
///
/// Choosing a level is answering what an operator DOES when the line appears:
///
/// - `error`: something is broken and needs a person. A guard failed closed, a
///   record was lost, an invariant did not hold.
/// - `warn`: something degraded or was refused and the system continued. Worth
///   noticing during an incident, not worth waking anyone.
/// - `info`: routine work that completed, or a fact about one request that is
///   gone once the moment passes — which principal a bind resolved to, that a
///   frame arrived at all.
/// - `debug`: detail an operator can regenerate on demand, useful only to
///   someone already inside this subsystem.
///
/// The fleet default shows `info` and above, so a `debug` site stays out of an
/// operator's way until they ask for it by component, which is what the
/// component is for: `CK_LOG=plexus.poller=debug`.
#[macro_export]
#[doc(hidden)]
macro_rules! diag {
    (error $component:ident: $($arg:tt)*) => {
        $crate::__diag_formatted(format_args!($($arg)*), |args| {
            $crate::__diag_tracing::error!(
                target: $crate::diag_component!($component),
                "{args}"
            )
        })
    };
    (warn $component:ident: $($arg:tt)*) => {
        $crate::__diag_formatted(format_args!($($arg)*), |args| {
            $crate::__diag_tracing::warn!(
                target: $crate::diag_component!($component),
                "{args}"
            )
        })
    };
    (info $component:ident: $($arg:tt)*) => {
        $crate::__diag_formatted(format_args!($($arg)*), |args| {
            $crate::__diag_tracing::info!(
                target: $crate::diag_component!($component),
                "{args}"
            )
        })
    };
    (debug $component:ident: $($arg:tt)*) => {
        $crate::__diag_formatted(format_args!($($arg)*), |args| {
            $crate::__diag_tracing::debug!(
                target: $crate::diag_component!($component),
                "{args}"
            )
        })
    };
}

/// The closed set of components a diagnostic may name, and the only place the
/// set is written down.
///
/// A component is the part of the module an operator filters on
/// (`CK_LOG=plexus.wire=debug`), so each name here has to correspond to
/// something that exists in the code rather than to a category someone liked.
/// An unlisted name fails to compile, which is the point: the shared log maps a
/// component outside its segment grammar back to the bare `plexus` root, so a
/// typo would otherwise cost the attribution silently.
#[macro_export]
#[doc(hidden)]
macro_rules! diag_component {
    // Publishing event notices to the fleet bus: the outbox drain and the labels
    // each notice carries.
    (bus) => {
        "bus"
    };
    // Hosted webhook connection, sequence gaps, and admission/drop decisions.
    (relay) => {
        "relay"
    };
    // One scheduling pass: due selection, retention trims, per-pass diagnosis.
    (scheduler) => {
        "scheduler"
    };
    // One poll cycle's execution: actor enrichment and the drop ledger.
    (poller) => {
        "poller"
    };
    // Authorization, the audit journal, uncertain-write reconciliation, and the
    // privileged ceremony.
    (governance) => {
        "governance"
    };
    // Vendor catalog discovery and the action inventory it maintains.
    (catalog) => {
        "catalog"
    };
    // The vendor transports: MCP remote, the local MCP route adapter, REST.
    (transport) => {
        "transport"
    };
    // The subc route surface: binds, frames, and call admission.
    (wire) => {
        "wire"
    };
    // The store itself: schema posture, and store faults answered on the facade.
    (storage) => {
        "storage"
    };
    // What the module reports about its own liveness, and the probes behind it.
    (health) => {
        "health"
    };
    // The governed web search tool: its rate limits, cache and backend calls.
    (web_search) => {
        "web_search"
    };
    // Consent cards filed with Prefrontal core for calls held for approval,
    // and the user's answers read back from them.
    (consent) => {
        "consent"
    };
}

// Shadow the standard macro throughout this crate so a new daemon diagnostic is
// attributed even when its author does not know about the shared-log contract.
// There is no bare arm: a site that names no level and no component does not
// compile, which is the only form of that contract a stderr write cannot slip
// past. See `diag!` for what the two choices mean.
macro_rules! eprintln {
    ($level:ident $component:ident: $($arg:tt)*) => {
        $crate::diag!($level $component: $($arg)*)
    };
}

pub mod actor_attribution;
pub mod agent_registry;
pub mod agent_retirement;
#[cfg(test)]
#[path = "../tests/support/bounded.rs"]
pub(crate) mod bounded;
pub mod catalog;
pub mod code_search;
pub mod consent_card;
pub mod credentials;
pub mod decision_plane;
pub mod event_envelope;
pub mod event_key;
pub mod fingerprint;
pub mod github;
pub mod github_identity;
pub mod governance;
mod grant_journal;
pub mod import_store;
pub mod jcs;
pub mod manifest;
mod mcp_payload;
pub mod mcp_remote;
pub mod mcp_route;
pub mod permissions;
pub mod poller;
pub mod recipients;
pub mod reconciliation;
pub mod repository_ownership;
pub mod rest_api;
pub mod scheduler;
pub mod scope;
pub mod storage;
#[cfg(test)]
mod test_http;
#[cfg(any(test, feature = "test-support"))]
pub mod test_scratch;
pub mod transport;
pub mod web_search;
pub mod withdraw;

mod http_support;

pub use actor_attribution::{ActorAttribution, ActorUnknown, ActorUnknownClass, ActorUnknownCode};
#[cfg(any(test, feature = "test-support"))]
pub use agent_registry::StubAgentRegistry;
pub use agent_registry::{
    resolve_agent_lookup_reply, AgentLookup, AgentRegistry, FailClosedAgentRegistry,
    PrefrontalAgentRegistry, AGENT_RESOLVE_OPERATION,
};
pub use catalog::{CatalogError, CatalogReconciler, CatalogRefreshPolicy, Freshness};
pub use consent_card::{
    consent_request_body, ConsentCards, ElicitationCallError, ElicitationRoute, ParkedApproval,
};
pub use credentials::{
    CkcredCredentialSource, CkcredRouteError, CkcredRoutePeer, CredentialError, CredentialSource,
    FailClosedCredentialSource, PermanentCredentialError, ResolvedCredential, SubcCkcredRoutePeer,
    TransientCredentialError,
};
#[cfg(any(test, feature = "test-support"))]
pub use credentials::{StubCredentialResponse, StubCredentialSource};
#[cfg(any(test, feature = "test-support"))]
pub use decision_plane::StubDecisionPlane;
pub use decision_plane::{
    compute_grant_hash, verify_grant_hash, DecisionEnvelope, DecisionPlane, DecisionPlaneError,
    GrantHashInput, OutcomeReport, OutcomeTerminal, Verdict,
};
pub use event_key::{derive_event_key, EventKeyError};
pub use fingerprint::fingerprint;
#[cfg(any(test, feature = "test-support"))]
pub use github_identity::{
    resolve_github_identity_reply, FailClosedGithubIdentitySource, GithubIdentity,
    GithubIdentityRefusal, GithubIdentityResolver, GithubIdentitySource, GithubIdentitySourceError,
    PrefrontalGithubIdentitySource, ResolvedGithubIdentity, StubGithubIdentityResponse,
    StubGithubIdentitySource, AGENT_GITHUB_IDENTITY_OPERATION,
};
pub use github_identity::{PrefrontalRouteError, PrefrontalRoutePeer, SubcPrefrontalRoutePeer};
pub use governance::{
    AuthorizationRequest, CatalogDenial, ConnectionDenial, CredentialDenial, DecisionPlaneEnvelope,
    Denial, DispatchOutcome, GovernanceEngine, GrantDenial, PolicyDenial, PollAuthorizationRefusal,
    Reservation, ResourceDenial, Severity, SeverityDenial, TransportOutcome,
    AUTHORITY_EVENTS_CONSUME, AUTHORITY_INVOKE, AUTHORITY_POLL, OUTCOME_REPORT_ATTEMPTS,
};
pub use jcs::{jcs_sha256, JcsError};
pub use manifest::{
    ingest_value, ActionBaseline, AppManifest, CursorKind, HttpMethod, HttpOperation,
    IngestedManifest, ManifestError, PollPagination, PollShape, Risk, TransportKind,
};
pub use mcp_remote::{
    DiscoveredAction, McpConnection, McpRemoteConfig, McpRemoteError, McpRemoteTransport,
};
pub use mcp_route::{
    McpRouteConnection, McpRouteError, McpRouteFrame, McpRoutePeer, McpRouteServedFrom,
    McpRouteTransport, SubcMcpRoutePeer,
};
pub use poller::{
    CursorAdvance, CursorError, CursorStrategy, DerivedEvent, OrderedTimestampStrategy, PollCycle,
    Poller, SyncTokenStrategy, ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE, ACTOR_TIMELINE_ACTION,
};
pub use reconciliation::{
    parse_reconciliation_class, OutcomeUnknownRecord, ReconcileResult, ReconciliationClass,
};
pub use rest_api::{actions_from_manifest, RestConfig, RestConnection, RestTransport};
pub use scheduler::{PassOutcome, Scheduler};
pub use storage::event_outbox::{
    CanonicalEvent, EventHeaders, EventLookupOutcome, EventReader, KeyedEventIdentity,
    KeyedPollEventInput, OutboxHealth, PollGapInput, QuotaAdmission, QuotaRequest,
    RepoIdCacheEntry, RepoIdUpdate, RepoResolutionAdmission,
};
pub use storage::now_ms;
pub use storage::{
    ActionRequestRecord, ActorSource, AuditRecord, AuditRow, BindingTicket, CatalogAction,
    CatalogActionInput, CatalogActionReview, Ceiling, CeremonyRefusal, ConfigureOutcome,
    ConnectionAdminRevokeOutcome, ConnectionRecord, ConnectionSummary, ConsentSettlement,
    DeleteConnectionOutcome, EventsConsumeAuthority, EventsIncludingGranted, GrantInput,
    GrantMintRequest, GrantRecord, ManifestSummary, ManifestWriteOutcome, PlexusStore, PolicyInput,
    PolicyRecord, PollEventInput, ProbeRegistration, ProbeSubscription, RelayOrigin,
    RepinActionRefusal, ReservationRecord, SnapshotGenerations, SubscriptionRefusal,
    SubscriptionResumeRefusal, TriggerEvent, TriggerEventInsertOutcome, TriggerSubscription,
    CATALOG_PRINCIPAL, CIRCUIT_BREAKER_SUSPENSION_REASON, MIGRATIONS, NO_CREDENTIAL_REF_ROLE,
    PROBE_SUBSCRIPTION_ACTION,
};
#[cfg(any(test, feature = "test-support"))]
pub use transport::{MockResponse, MockTransport};
pub use transport::{
    Retryability, TransmissionState, Transport, TransportRequest, TransportResponse,
};

pub mod secret_input;

pub mod grant_refusal;
