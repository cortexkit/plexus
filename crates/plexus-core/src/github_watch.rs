//! Fixed, read-only vendor operations behind Basal's outside-watch tool.

use crate::governance::{
    AuthorizationRequest, Denial, GovernanceEngine, PollAuthorizationRefusal, TransportOutcome,
};
use crate::scope::{basal_flow_read_agent, CallScope};
use crate::storage::{now_ms, AuditRecord, PlexusStore, SubscriptionRefusal};
use crate::{CredentialSource, Transport};
use serde_json::{json, Map, Value};

pub(crate) const BASAL: &str = "reserved:basal";
pub(crate) const OWNER: &str = "direct";
pub(crate) const PUBLIC_CONNECTION: &str = crate::poller::GITHUB_ACTIONS_CONNECTION;
pub(crate) const PUBLIC_CHECK: &str = "get_repository";
pub(crate) const HOUR_MS: i64 = 3_600_000;
pub(crate) const CADENCE_S: i64 = 900;
const MAX_AGE_MS: i64 = 30 * 24 * HOUR_MS;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchKind {
    Issue,
    PullRequest,
    Release,
}

impl WatchKind {
    pub(crate) const ALL: [Self; 3] = [Self::Issue, Self::PullRequest, Self::Release];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::PullRequest => "pull_request",
            Self::Release => "release",
        }
    }

    pub(crate) fn poll(self) -> (&'static str, &'static str) {
        match self {
            Self::Issue => ("conn-github", "list_issues"),
            Self::PullRequest => ("conn-github-prs", "list_pull_requests"),
            Self::Release => ("conn-github-releases", "get_latest_release"),
        }
    }

    pub(crate) fn item_read(self) -> &'static str {
        match self {
            Self::Issue => "issue_read",
            Self::PullRequest => "pull_request_read",
            Self::Release => "get_latest_release",
        }
    }
}

pub(crate) struct WatchKey {
    pub(crate) repository: String,
    pub(crate) kind: WatchKind,
    number: Option<i64>,
}

impl WatchKey {
    fn parse(args: &Map<String, Value>) -> Result<Self, WatchError> {
        let repository = args
            .get("repository")
            .and_then(Value::as_str)
            .map(crate::github::canonical_repository)
            .ok_or(WatchError::InvalidRequest)?;
        let (owner, repo) = crate::github::resolver::split_repository(&repository)
            .map_err(|_| WatchError::InvalidRequest)?;
        if [owner, repo].iter().any(|part| {
            matches!(*part, "." | "..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        }) {
            return Err(WatchError::InvalidRequest);
        }
        let kind = args
            .get("kind")
            .and_then(Value::as_str)
            .and_then(|kind| {
                WatchKind::ALL
                    .into_iter()
                    .find(|value| value.as_str() == kind)
            })
            .ok_or(WatchError::InvalidRequest)?;
        let number = match (kind, args.get("number")) {
            (WatchKind::Release, None) => None,
            (WatchKind::Release, Some(_)) => return Err(WatchError::InvalidRequest),
            (_, Some(value)) => Some(
                value
                    .as_i64()
                    .filter(|n| *n > 0)
                    .ok_or(WatchError::InvalidRequest)?,
            ),
            (_, None) => return Err(WatchError::InvalidRequest),
        };
        Ok(Self {
            repository,
            kind,
            number,
        })
    }

    pub(crate) fn number_key(&self) -> i64 {
        self.number.unwrap_or(0)
    }

    fn ensure_reply(&self, expiry: Option<i64>) -> Value {
        json!({"watch":if expiry.is_some() {"outside"} else {"existing"},
            "repository":self.repository,"kind":self.kind.as_str(),"number":self.number,"expires_at_ms":expiry})
    }
}

#[derive(Debug)]
pub enum WatchError {
    InvalidRequest,
    AgentIdentityRequired,
    RepositoryNotPublic,
    ItemNotFound,
    Limit,
    GrantMissing,
    ReadUnavailable,
    StoreFailure,
    ReadFailed { retryable: bool, item: bool },
    Denied(Denial),
}

impl WatchError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AgentIdentityRequired => "agent_identity_required",
            Self::RepositoryNotPublic => "repository_not_public",
            Self::ItemNotFound => "item_not_found",
            Self::Limit => "outside_watch_limit",
            Self::GrantMissing => "grant_missing",
            Self::ReadUnavailable | Self::ReadFailed { .. } => "read_dispatch_failed",
            Self::StoreFailure => "store_failure",
            Self::Denied(denial) => denial.reason_code(),
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Self::StoreFailure => true,
            Self::ReadFailed { retryable, .. } => *retryable,
            Self::Denied(denial) => denial.clears_by_waiting(),
            _ => false,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "Expected ensure or end, an owner/name repository and kind, a positive number only for issues and pull requests, and a future expiry for ensure (at most 30 days for an outside watch).",
            Self::AgentIdentityRequired => "GitHub watches require reserved:basal on an agent-stamped flow route.",
            Self::RepositoryNotPublic => "The GitHub repository is private, missing, or not confirmed public.",
            Self::ItemNotFound => "The GitHub item was not found.",
            Self::Limit => "Outside GitHub watches are limited to 5 per agent and 25 overall.",
            Self::GrantMissing => "Basal needs the read-only poll grants for this GitHub watch.",
            Self::StoreFailure => "The GitHub watch store could not be accessed.",
            Self::ReadFailed { item: true, .. } => "GitHub refused the item read; the item may not exist, or GitHub failed. Check the repository and number, then retry.",
            Self::ReadUnavailable | Self::ReadFailed { .. } | Self::Denied(_) => "The GitHub watch read did not complete.",
        }
    }
}

fn store_failure(error: cortexkit_store::StoreError) -> WatchError {
    crate::diag!(warn poller: "outside watch store operation failed: {error}");
    WatchError::StoreFailure
}

pub(crate) fn audit_record(
    action: &str,
    carrier: &str,
    scope: Option<&CallScope>,
    outcome: &str,
    allowed: bool,
) -> AuditRecord {
    let mut record = AuditRecord::ceremony(
        OWNER,
        Some("github"),
        None,
        &format!("github_watch.{action}"),
        "read",
        None,
    );
    record.actor = carrier.into();
    record.acting_principal = carrier.into();
    record.agent_id = scope.and_then(|scope| scope.agent_id.clone());
    record.gate = Some("github_watch".into());
    record.args_redaction_summary = None;
    record.decision = if allowed { "allow" } else { "deny" }.into();
    record.reason_code = outcome.into();
    record.outcome = Some(outcome.into());
    record
}

pub fn audit_refusal(
    store: &PlexusStore,
    args: &Map<String, Value>,
    carrier: &str,
    scope: Option<&CallScope>,
    code: &str,
) -> Result<(), WatchError> {
    let Some(action @ ("ensure" | "end")) = args.get("action").and_then(Value::as_str) else {
        return Ok(());
    };
    store
        .append_audit_scoped(&audit_record(action, carrier, scope, code, false), scope)
        .map_err(store_failure)
}

pub fn call<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    args: &Map<String, Value>,
    carrier: &str,
    scope: Option<&CallScope>,
) -> Result<Value, WatchError> {
    let result = match scope
        .filter(|_| basal_flow_read_agent(carrier, scope).is_some_and(|agent| !agent.is_empty()))
    {
        Some(scope) => call_for_flow(engine, args, scope),
        None => Err(WatchError::AgentIdentityRequired),
    };
    if let Err(error) = &result {
        audit_refusal(engine.store(), args, carrier, scope, error.code())?;
    }
    result
}

fn call_for_flow<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    args: &Map<String, Value>,
    scope: &CallScope,
) -> Result<Value, WatchError> {
    if !args.keys().all(|key| {
        matches!(
            key.as_str(),
            "action" | "repository" | "kind" | "number" | "expires_at_ms"
        )
    }) {
        return Err(WatchError::InvalidRequest);
    }
    let key = WatchKey::parse(args)?;
    let now = now_ms();
    match args.get("action").and_then(Value::as_str) {
        Some("end") => {
            if args
                .get("expires_at_ms")
                .is_some_and(|expiry| expiry.as_i64().is_none())
            {
                return Err(WatchError::InvalidRequest);
            }
            Ok(
                json!({"ended":engine.store().outside_watch_end(scope, &key, now).map_err(store_failure)?}),
            )
        }
        Some("ensure") => {
            let expiry = args
                .get("expires_at_ms")
                .and_then(Value::as_i64)
                .filter(|expiry| *expiry > now)
                .ok_or(WatchError::InvalidRequest)?;
            ensure(engine, scope, &key, now, expiry)
        }
        _ => Err(WatchError::InvalidRequest),
    }
}

fn ensure<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    scope: &CallScope,
    key: &WatchKey,
    now: i64,
    expiry: i64,
) -> Result<Value, WatchError> {
    let store = engine.store();
    let audited = |result: &str| {
        store
            .append_audit_scoped(
                &audit_record("ensure", BASAL, Some(scope), result, true),
                Some(scope),
            )
            .map_err(store_failure)
    };
    if store.fleet_has_github_watch(key).map_err(store_failure)? {
        audited("existing")?;
        return Ok(key.ensure_reply(None));
    }
    if expiry > now.saturating_add(MAX_AGE_MS) {
        return Err(WatchError::InvalidRequest);
    }
    if !store
        .outside_watch_check_grants(key, now)
        .map_err(store_failure)?
    {
        return Err(WatchError::GrantMissing);
    }
    if let Some(expiry) = store
        .outside_watch_existing(scope, key, now)
        .map_err(store_failure)?
    {
        audited("outside")?;
        return Ok(key.ensure_reply(Some(expiry)));
    }

    let (owner, repo) = key
        .repository
        .split_once('/')
        .ok_or(WatchError::InvalidRequest)?;
    let fixed = json!({"owner":owner,"repo":repo});
    let (connection, action) = key.kind.poll();
    let mut prepared = store
        .prepare_subscription(
            OWNER,
            connection,
            action,
            CADENCE_S,
            &json!({}),
            &fixed,
            true,
        )
        .map_err(store_failure)?
        .map_err(|refusal| match refusal {
            SubscriptionRefusal::PollGrantRequired => WatchError::GrantMissing,
            _ => WatchError::ReadUnavailable,
        })?;
    let repo_id = match check_public(engine, &key.repository, Some(scope)) {
        Err(WatchError::RepositoryNotPublic) => {
            store
                .outside_watch_end_repository(&key.repository)
                .map_err(store_failure)?;
            return Err(WatchError::RepositoryNotPublic);
        }
        other => other?,
    };
    let checked_at = now_ms();
    let mut item_args = fixed;
    match key.kind {
        WatchKind::Issue => {
            item_args["method"] = json!("get");
            item_args["issue_number"] = json!(key.number);
        }
        WatchKind::PullRequest => {
            item_args["method"] = json!("get");
            item_args["pullNumber"] = json!(key.number);
        }
        WatchKind::Release => {}
    }
    let item = read(
        engine,
        connection,
        key.kind.item_read(),
        item_args,
        Some(scope),
        true,
    )?;
    if key.kind == WatchKind::Release {
        let tag = item["tag_name"]
            .as_str()
            .filter(|tag| !tag.is_empty())
            .ok_or(WatchError::ReadFailed {
                retryable: true,
                item: true,
            })?;
        prepared.cursor_state = json!({"scalar": tag});
    } else if item["number"].as_i64() != key.number
        || (key.kind == WatchKind::Issue && item.get("pull_request").is_some())
    {
        return Err(WatchError::ReadFailed {
            retryable: true,
            item: true,
        });
    }
    let expiry = store
        .outside_watch_insert(scope, key, expiry, repo_id, checked_at, &prepared)
        .map_err(store_failure)??;
    Ok(key.ensure_reply(Some(expiry)))
}

fn check_public<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    repository: &str,
    scope: Option<&CallScope>,
) -> Result<i64, WatchError> {
    let (owner, repo) = repository
        .split_once('/')
        .ok_or(WatchError::InvalidRequest)?;
    let result = read(
        engine,
        PUBLIC_CONNECTION,
        PUBLIC_CHECK,
        json!({"owner":owner,"repo":repo}),
        scope,
        false,
    )?;
    match result.get("private").and_then(Value::as_bool) {
        Some(true) => Err(WatchError::RepositoryNotPublic),
        Some(false)
            if result["visibility"]
                .as_str()
                .is_some_and(|value| value != "public") =>
        {
            Err(WatchError::RepositoryNotPublic)
        }
        Some(false) => result["id"]
            .as_i64()
            .filter(|id| *id > 0)
            .ok_or(WatchError::ReadFailed {
                retryable: true,
                item: false,
            }),
        None => Err(WatchError::ReadFailed {
            retryable: true,
            item: false,
        }),
    }
}

fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    connection: &str,
    action: &str,
    args: Value,
    scope: Option<&CallScope>,
    item: bool,
) -> Result<Value, WatchError> {
    let store = engine.store();
    let catalog = store
        .catalog_action(OWNER, connection, action)
        .map_err(store_failure)?
        .ok_or(WatchError::ReadUnavailable)?;
    let request: AuthorizationRequest = engine
        .github_watch_read_request(connection, action, args, &catalog.schema_hash, scope)
        .map_err(|refusal| match refusal {
            PollAuthorizationRefusal::StoreFailure => WatchError::StoreFailure,
            _ => WatchError::ReadUnavailable,
        })?;
    let reservation = engine.authorize(request).map_err(WatchError::Denied)?;
    if action == PUBLIC_CHECK && connection == PUBLIC_CONNECTION {
        let admission = store.reserve_github_actions_flow_read_quota(now_ms());
        if !matches!(admission, Ok(crate::QuotaAdmission::Reserved { .. })) {
            store
                .abandon_reservation(&reservation.principal, &reservation.reservation_id)
                .map_err(store_failure)?;
            admission.map_err(store_failure)?;
            return Err(WatchError::ReadFailed {
                retryable: true,
                item,
            });
        }
    }
    let dispatch = engine.revalidate_and_dispatch(&reservation);
    match dispatch.outcome {
        TransportOutcome::Completed {
            response: Some(body),
        } => Ok(body),
        TransportOutcome::VendorFailed { code, .. } if code == "http_404" => Err(if item {
            WatchError::ItemNotFound
        } else {
            WatchError::RepositoryNotPublic
        }),
        TransportOutcome::VendorFailed { code, .. } => Err(WatchError::ReadFailed {
            retryable: code == "mcp_tool_error"
                || dispatch.retryability != crate::Retryability::Terminal,
            item,
        }),
        TransportOutcome::NotSent { .. } => Err(WatchError::ReadFailed {
            retryable: dispatch.retryability != crate::Retryability::Terminal,
            item,
        }),
        TransportOutcome::OutcomeUnknown | TransportOutcome::Completed { response: None } => {
            Err(WatchError::ReadFailed {
                retryable: true,
                item,
            })
        }
    }
}

pub(crate) fn housekeeping<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    now: i64,
    stop: impl Fn() -> bool,
) -> Result<(), WatchError> {
    let store = engine.store();
    for repo in store.expire_outside_watches(now).map_err(store_failure)? {
        crate::diag!(warn poller: "ended outside watches for {repo}: no affirmative public check in 24 hours");
    }
    for repo in store
        .outside_watch_rechecks_due(now)
        .map_err(store_failure)?
    {
        if stop() {
            break;
        }
        let Some(first) = store
            .reserve_outside_watch_recheck(&repo, now)
            .map_err(store_failure)?
        else {
            continue;
        };
        match check_public(engine, &repo, None) {
            Ok(id) => store
                .confirm_outside_watch_recheck(&repo, id, now)
                .map_err(store_failure)?,
            Err(WatchError::RepositoryNotPublic) => store
                .outside_watch_end_repository(&repo)
                .map_err(store_failure)?,
            Err(error) if first => {
                crate::diag!(warn poller: "paused outside polling for {repo}: public check inconclusive ({})", error.code())
            }
            Err(_) => {}
        }
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn housekeeping_at_for_test<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    now: i64,
) -> Result<(), WatchError> {
    housekeeping(engine, now, || false)
}
