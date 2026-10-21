//! The governance checks web_search and code_search share.
//!
//! Both tools resolve the one connection that backs a caller's search, apply
//! the checks governance would apply to that connection before dispatch,
//! classify an engine denial and a vendor outcome, and write one search audit
//! row per call. Each tool turns the neutral [`SearchDenial`] into its own
//! closed refusal set. The checks run in the order governance's own
//! authorization uses (connection health, then the catalog action's status,
//! then policy), so a search reports the refusal an `invoke` of the same
//! action would.

use serde_json::Value;

use crate::governance::{
    connection_denial, scoped_grant, scoped_grant_refusal, CatalogDenial, Denial, DispatchOutcome,
    GrantDenial, PolicyDenial, TransportOutcome, AUTHORITY_INVOKE,
};
use crate::grant_refusal::{Cause, GrantRefusal, GrantTarget};
use crate::scope::CallScope;
use crate::storage::{AuditRecord, CatalogAction, ConnectionRecord, PlexusStore, RelayOrigin};
use crate::transport::TransmissionState;

/// Which tool a shared check is running for. It picks the log component and
/// the tool name written into log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchTool {
    Web,
    Code,
}

impl SearchTool {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Web => "web_search",
            Self::Code => "code_search",
        }
    }
}

/// Log one line under the component each tool has always logged under.
macro_rules! search_log {
    ($tool:expr, $level:ident, $($arg:tt)*) => {
        match $tool {
            $crate::web_search::facade::SearchTool::Web => eprintln!($level web_search: $($arg)*),
            $crate::web_search::facade::SearchTool::Code => eprintln!($level governance: $($arg)*),
        }
    };
}

/// The catalog app and action a search rides on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SearchTarget {
    pub tool: SearchTool,
    pub app_key: &'static str,
    pub action: &'static str,
}

/// Why a search cannot proceed, before each tool names it in its own
/// refusal set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SearchDenial {
    /// No candidate connection carries a grant that admits the action.
    NotGranted,
    /// A flow's grant refusal, typed so the flow can name the grant to restore.
    Grant(GrantRefusal),
    /// More than one connection could serve the caller.
    Ambiguous,
    /// Policy asks for approval, which a search cannot carry.
    AskFirst,
    /// Policy blocks the action.
    Blocked,
    /// The catalog action is quarantined.
    Quarantined,
    /// The connection cannot serve (pending, disabled, revoked or unhealthy).
    ConnectionUnusable,
    /// The vendor throttled the request.
    Throttled {
        retry_after_ms: u64,
    },
    ConsentUnavailable {
        action: String,
    },
    /// Anything else: a store or transport failure, an unusable action status
    /// or a vendor failure. The cause goes to the log only.
    Unavailable,
}

/// How long to tell a caller to wait after a vendor throttle that named no
/// delay.
pub(crate) const DEFAULT_VENDOR_RETRY_AFTER_MS: u64 = 30_000;

/// The one connection that backs a search for `caller`, with its catalog
/// action. Candidates are resolved through `connection_for_invoke`, the same
/// owner resolution the governance engine applies, so the connection checked
/// here is the one `authorize` will load. A candidate counts only if the
/// caller's module grant on it admits the action. With no eligible candidate,
/// a flow gets a typed grant refusal naming `grant_target` and the cause the
/// last refused grant gave; any other caller gets `NotGranted`.
pub(crate) fn resolve_connection(
    store: &PlexusStore,
    caller: &str,
    now_ms: i64,
    is_flow: bool,
    target: SearchTarget,
    grant_target: GrantTarget,
) -> Result<(ConnectionRecord, CatalogAction), SearchDenial> {
    let tool = target.tool;
    let store_failure = |error: cortexkit_store::StoreError| {
        search_log!(
            tool,
            error,
            "{} connection lookup failed: {error}",
            tool.name()
        );
        SearchDenial::Unavailable
    };
    let mut eligible = Vec::new();
    let mut cause = Cause::Missing;
    for connection_id in store
        .web_search_candidate_connection_ids(caller, target.app_key, now_ms)
        .map_err(store_failure)?
    {
        let Some(connection) = store
            .connection_for_invoke(caller, &connection_id)
            .map_err(store_failure)?
        else {
            continue;
        };
        // Reload after candidate selection: a connection may have changed
        // owner, backend or status between the two store reads.
        if connection.app_key != target.app_key
            || !crate::web_search::connection_status_can_search(&connection.status)
        {
            continue;
        }
        let Some(action) = store
            .catalog_action(
                &connection.principal,
                &connection.connection_id,
                target.action,
            )
            .map_err(store_failure)?
        else {
            continue;
        };
        let rows = store
            .scoped_invoke_grant_rows(&connection, caller, None)
            .map_err(store_failure)?;
        let grant = scoped_grant(
            &rows,
            &connection,
            caller,
            None,
            AUTHORITY_INVOKE,
            target.action,
            now_ms,
            Some(&action.risk),
        );
        match scoped_grant_refusal(grant.as_ref(), target.action, &action.risk, now_ms) {
            None => eligible.push((connection, action)),
            Some(reason) => {
                cause = match reason {
                    GrantDenial::Expired => Cause::Expired,
                    GrantDenial::ActionSelector => Cause::ActionSelector,
                    GrantDenial::RiskCeiling => Cause::RiskCeiling,
                    _ => Cause::Missing,
                }
            }
        }
    }
    match eligible.len() {
        0 if is_flow => Err(SearchDenial::Grant(GrantRefusal::new(grant_target, cause))),
        0 => Err(SearchDenial::NotGranted),
        1 => Ok(eligible.remove(0)),
        _ => {
            search_log!(
                tool,
                warn,
                "{} for {caller} is ambiguous across connections {:?}",
                tool.name(),
                eligible
                    .iter()
                    .map(|(connection, _)| connection.connection_id.as_str())
                    .collect::<Vec<_>>()
            );
            Err(SearchDenial::Ambiguous)
        }
    }
}

/// The policy effect governance would apply to `action` on `connection`:
/// the governing policy's effect, or the action's ask-first default when no
/// policy matches.
pub(crate) fn policy_effect(
    store: &PlexusStore,
    tool: SearchTool,
    connection: &ConnectionRecord,
    action: &CatalogAction,
    now_ms: i64,
) -> Result<&'static str, SearchDenial> {
    let policy = store
        .matching_policy(
            &connection.principal,
            &connection.connection_id,
            &action.name,
            now_ms,
        )
        .map_err(|error| {
            search_log!(tool, error, "{} policy lookup failed: {error}", tool.name());
            SearchDenial::Unavailable
        })?;
    Ok(crate::governance::catalog_policy_effect(
        action,
        policy.as_ref().map(|p| p.effect.as_str()),
        None,
    ))
}

/// The checks governance applies to a resolved connection before it would
/// dispatch, in governance's order: the connection must be able to serve,
/// the catalog action must be active, and policy must allow the action
/// outright. A search can never carry a per-call approval, so `ask_first`
/// refuses like `block` does, under its own name.
pub(crate) fn standing_checks(
    store: &PlexusStore,
    tool: SearchTool,
    connection: &ConnectionRecord,
    action: &CatalogAction,
    now_ms: i64,
) -> Result<(), SearchDenial> {
    if let Some(reason) = connection_denial(connection) {
        search_log!(
            tool,
            warn,
            "{} connection {} cannot serve: {reason:?}",
            tool.name(),
            connection.connection_id
        );
        return Err(SearchDenial::ConnectionUnusable);
    }
    match action.status.as_str() {
        "active" => {}
        "quarantined" => {
            search_log!(
                tool,
                warn,
                "{} action quarantined on {}",
                tool.name(),
                connection.connection_id
            );
            return Err(SearchDenial::Quarantined);
        }
        _ => return Err(SearchDenial::Unavailable),
    }
    let effect = policy_effect(store, tool, connection, action, now_ms)?;
    if crate::governance::per_call_approval_unsupported(effect, false) {
        return Err(SearchDenial::AskFirst);
    }
    if effect != "allow" {
        return Err(SearchDenial::Blocked);
    }
    Ok(())
}

/// Map a governance denial met in `authorize` onto the shared set. A grant
/// refusal names `grant_target`, the module that asked, as the grantee, the
/// same target the preflight reports.
pub(crate) fn denial_for(denial: &Denial, grant_target: GrantTarget) -> SearchDenial {
    match denial {
        Denial::Policy(PolicyDenial::AskFirst) => SearchDenial::AskFirst,
        Denial::GrantRefusal(refusal) => {
            SearchDenial::Grant(GrantRefusal::new(grant_target, refusal.detail().cause))
        }
        Denial::ConsentUnavailable { action } => SearchDenial::ConsentUnavailable {
            action: action.clone(),
        },
        Denial::Catalog(CatalogDenial::Quarantined) => SearchDenial::Quarantined,
        Denial::Policy(PolicyDenial::Blocked) => SearchDenial::Blocked,
        Denial::Grant(_) | Denial::Policy(_) | Denial::ActionRequestCreated { .. } => {
            SearchDenial::NotGranted
        }
        _ => SearchDenial::Unavailable,
    }
}

/// The vendor's reply body from a dispatch, or why there is none. A vendor
/// throttle carries the vendor's retry delay, or a default when it named
/// none; every other failure is logged and reported as unavailable.
pub(crate) fn vendor_body(
    tool: SearchTool,
    backend: &str,
    connection_id: &str,
    dispatched: &DispatchOutcome,
) -> Result<Value, SearchDenial> {
    match &dispatched.outcome {
        TransportOutcome::Completed {
            response: Some(body),
        } => Ok(body.clone()),
        TransportOutcome::VendorFailed { code, .. } | TransportOutcome::NotSent { code, .. }
            if code == "throttled" =>
        {
            Err(SearchDenial::Throttled {
                retry_after_ms: dispatched
                    .retry_after_ms
                    .unwrap_or(DEFAULT_VENDOR_RETRY_AFTER_MS),
            })
        }
        other => {
            // The transport has already logged the vendor's own body; this
            // line ties that failure to the search call.
            search_log!(
                tool,
                warn,
                "{} backend {backend} failed on {connection_id}: {other:?}",
                tool.name()
            );
            Err(SearchDenial::Unavailable)
        }
    }
}

/// What a search call's one audit row records about the call, filled in as
/// the call learns more about itself.
pub(crate) struct SearchAudit {
    pub tool: SearchTool,
    pub caller: String,
    /// The connection owner once resolved; the caller until then.
    pub principal: String,
    pub agent_id: Option<String>,
    pub connection_id: Option<String>,
    pub risk: Option<String>,
    pub severity: Option<String>,
    pub query_text: Option<String>,
    /// The engine's request id once `authorize` admitted the call, so this
    /// row can be joined to the engine's own authorization and dispatch rows.
    pub request_id: Option<String>,
    /// Whether the dispatched request reached the vendor; `None` until the
    /// engine dispatched it.
    pub transmission: Option<TransmissionState>,
    /// The daemon scope the caller's route was bound under, if any.
    pub scope: Option<CallScope>,
    /// The call from which this search was relayed, if the relay stated one.
    pub relay_origin: Option<RelayOrigin>,
}

/// How a search call ended, as its audit row states it.
pub(crate) struct RowOutcome {
    pub decision: &'static str,
    pub reason_code: String,
    pub outcome: &'static str,
    pub response_class: Option<&'static str>,
    pub result_count: Option<i64>,
}

impl SearchAudit {
    pub(crate) fn new(
        tool: SearchTool,
        caller: &str,
        agent_id: Option<String>,
        scope: Option<&CallScope>,
        relay_origin: Option<&RelayOrigin>,
    ) -> Self {
        Self {
            tool,
            caller: caller.to_string(),
            principal: caller.to_string(),
            agent_id,
            connection_id: None,
            risk: None,
            severity: None,
            query_text: None,
            request_id: None,
            transmission: None,
            scope: scope.cloned(),
            relay_origin: relay_origin.cloned(),
        }
    }

    /// Record the connection the call resolved to.
    pub(crate) fn resolved(&mut self, connection: &ConnectionRecord, action: &CatalogAction) {
        self.principal = connection.principal.clone();
        self.connection_id = Some(connection.connection_id.clone());
        self.risk = Some(action.risk.clone());
        self.severity = Some(action.severity.clone());
    }

    /// Forget an earlier provider's dispatch when the ordered walk moves on
    /// to attempt another, so the row describes the attempt it names.
    pub(crate) fn new_attempt(&mut self) {
        self.request_id = None;
        self.transmission = None;
    }

    /// The row for a refused call, named by the tool's refusal code. A call
    /// governance admitted and sent (or may have sent) failed at the vendor:
    /// its decision is `allow`, as on the engine's own rows, and its outcome
    /// says whether the request was sent. Anything refused before a send,
    /// including a dispatch that aborted unsent, is `deny` and `not_sent`.
    pub(crate) fn refused(&self, reason_code: &str) -> RowOutcome {
        let (decision, outcome) = match self.transmission {
            None | Some(TransmissionState::NotSent) => ("deny", "not_sent"),
            Some(TransmissionState::Sent) => ("allow", "failed"),
            Some(TransmissionState::OutcomeUnknown) => ("allow", "unknown"),
        };
        RowOutcome {
            decision,
            reason_code: reason_code.to_string(),
            outcome,
            response_class: None,
            result_count: None,
        }
    }

    /// Append the call's one search audit row. A failure is logged with the
    /// row's identifying fields, never the query.
    pub(crate) fn append(
        &self,
        store: &PlexusStore,
        app_key: Option<String>,
        action: Option<String>,
        summary: String,
        row: RowOutcome,
    ) -> Result<(), cortexkit_store::StoreError> {
        let record = AuditRecord {
            principal: self.principal.clone(),
            actor: self.caller.clone(),
            acting_principal: self.caller.clone(),
            agent_id: self.agent_id.clone(),
            app_handle_id: None,
            agent_handle: None,
            connection_id: self.connection_id.clone(),
            app_key,
            action,
            risk: self.risk.clone(),
            severity: self.severity.clone(),
            decision: row.decision.to_string(),
            reason_code: row.reason_code,
            gate: Some(self.tool.name().to_string()),
            args_redaction_summary: Some(summary),
            outcome: Some(row.outcome.to_string()),
            latency_ms: None,
            request_id: self.request_id.clone(),
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: None,
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: row.response_class.map(str::to_string),
            reconciliation_of: None,
        };
        store
            .append_web_search_audit(
                &record,
                self.query_text.as_deref(),
                row.result_count,
                self.scope.as_ref(),
                self.relay_origin.as_ref(),
            )
            .inspect_err(|error| {
                eprintln!(error governance:
                    "audit append failed: {} reason={:?} principal={:?} actor={:?} connection_id={:?}: {error}",
                    self.tool.name(), record.reason_code, record.principal, record.actor, record.connection_id
                );
            })
    }
}
