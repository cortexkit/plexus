//! Add one web search provider under a single operator confirmation.
//!
//! By hand, a provider takes a binding ticket, its redemption with
//! `connections op=connect`, then one grant per caller. The supervisor asks
//! for presence once per ticket and once per grant, so with three callers the
//! operator would confirm four times for one decision. This ceremony plans all of it, asks
//! once with a summary naming every effect, and then runs the same code paths
//! the manual commands use, so it writes the same rows and audit entries.
//!
//! The app key, action, credential name and connection id come from the
//! provider table in `plexus_core::web_search::providers`; the caller names
//! only the provider, the grantees, a SearXNG instance and whether SearXNG
//! uses its optional key.
//!
//! Connecting runs discovery, which can contact the vendor, so it cannot share
//! a transaction with the grants. The ceremony therefore mints grants only
//! after the connection is active and discovery completed, all of them in one
//! transaction, and it is safe to rerun: an existing matching connection is
//! reused and grants that already exist are not minted again.

use std::collections::BTreeSet;
use std::sync::Arc;

use plexus_core::instance_url::InstanceUrl;
use plexus_core::web_search::providers::{
    provider_named, ProviderName, VaultCredential, PROVIDER_NAMES,
};
use plexus_core::{AuditRecord, GrantMintRequest};
use serde_json::{json, Value};
use subc_protocol::Frame;
use tokio::sync::mpsc;

use crate::composite_admin::{
    self, diagnostic, named_principals, prompt_label, refusal, Caller, Composite, ConnectorHome,
};
use crate::{ceremony, manifest, ModuleError, ModuleState, RouteBindings, RouteFrameContext};

/// Every grant this ceremony mints is invoke authority at read risk on exactly
/// the provider's search action, the same grant the rollout guide mints by hand.
const GRANT_KIND: &str = "invoke";
const GRANT_RISK: &str = "read";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    provider: String,
    #[serde(default)]
    grantees: Option<Vec<String>>,
    #[serde(default)]
    instance_url: Option<String>,
    #[serde(default)]
    with_key: bool,
    #[serde(default = "preview_by_default")]
    dry_run: bool,
}

fn preview_by_default() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionStep {
    /// No connection with the provider's id exists yet.
    Create,
    /// A pending connection exists (an earlier ticket was issued but not
    /// redeemed); a new ticket replaces the old one and is redeemed.
    Reenroll,
    /// An active connection with the same app and credential exists; it is
    /// kept and only discovery and the missing grants run.
    Reuse,
}

impl ConnectionStep {
    fn label(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Reenroll => "reenroll",
            Self::Reuse => "reuse",
        }
    }
}

struct Plan {
    provider: &'static ProviderName,
    /// The vault reference name to bind, or `None` for anonymous SearXNG.
    credential: Option<&'static str>,
    instance: Option<InstanceUrl>,
    step: ConnectionStep,
    /// The connection this run creates or reuses: the provider table's id,
    /// unless a connection for the provider already exists under another id.
    connection_id: String,
    grantees: Vec<String>,
    /// `explicit` when the caller named the grantees, otherwise
    /// `existing_search_grants`.
    grantees_source: &'static str,
    /// Grantees that already hold the grant on this connection.
    present: BTreeSet<String>,
    dry_run: bool,
}

/// Serve `plexus.admin.add_web_search_provider`: a preview by default, or, with
/// `dry_run: false`, exactly one operator confirmation followed by the writes.
pub(crate) async fn add(
    route: RouteFrameContext,
    params: &Value,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    principal_key: &str,
) -> Result<Value, ModuleError> {
    // Planning reads the store only: no vault read, no ticket, no vendor
    // request. A refusal here is returned before anyone is asked to confirm.
    composite_admin::run(
        Caller {
            route,
            writer,
            state,
            route_bindings,
            method: manifest::ADMIN_ADD_WEB_SEARCH_PROVIDER_OP,
        },
        ConnectorHome::BeforeApplying,
        || plan(state, principal_key, params),
        |plan| apply(state, principal_key, plan),
    )
    .await
}

fn plan(state: &Arc<ModuleState>, principal: &str, params: &Value) -> Result<Plan, Value> {
    let request = serde_json::from_value::<Request>(params.clone()).map_err(|_| {
        refusal(
            "invalid_request",
            "add_web_search_provider takes provider, optional grantees (an array of \
             principals), instance_url, with_key and dry_run",
        )
    })?;
    let provider = provider_named(&request.provider).ok_or_else(|| {
        refusal(
            "unknown_provider",
            format!(
                "'{}' is not a web search provider; known: {}",
                diagnostic(&request.provider),
                PROVIDER_NAMES
                    .iter()
                    .map(|provider| provider.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;
    let credential = match (provider.credential, request.with_key) {
        (VaultCredential::Required(name), false) => Some(name),
        (VaultCredential::Optional(name), true) => Some(name),
        (VaultCredential::Optional(_), false) => None,
        (VaultCredential::Required(_), true) => {
            return Err(refusal(
                "with_key_not_applicable",
                format!(
                    "--with-key applies only to a provider whose key is optional; {} always uses its key",
                    provider.name
                ),
            ))
        }
    };
    // The reviewed manifest must be installed and must allow a read ceiling on
    // the provider's action; this is the check the ticket itself makes first.
    match state.store().ceiling_within_manifest(
        provider.app_key,
        GRANT_RISK,
        &[provider.action.to_string()],
    ) {
        Ok(Ok(_)) => {}
        Ok(Err(refused)) => return Err(ceremony::refusal_response(&refused)),
        Err(error) => {
            return Err(crate::wire::store_failure(
                "provider manifest read",
                "the provider's manifest could not be read",
                &error,
            ))
        }
    }
    let instance = instance(state, provider, request.instance_url.as_deref())?;
    let (step, connection_id) =
        connection_step(state, principal, provider, credential, instance.as_ref())?;
    let (grantees, grantees_source) = match request.grantees {
        Some(named) => (named_principals(named)?, "explicit"),
        None => (
            default_grantees(state, principal)?,
            "existing_search_grants",
        ),
    };
    if grantees.is_empty() {
        return Err(refusal(
            "grantees_required",
            "no caller holds a search grant on an existing web search provider; name each caller with --grantee",
        ));
    }
    let present = match step {
        ConnectionStep::Create => BTreeSet::new(),
        ConnectionStep::Reenroll | ConnectionStep::Reuse => {
            present_grantees(state, principal, provider, &connection_id)?
        }
    };
    Ok(Plan {
        provider,
        credential,
        instance,
        step,
        connection_id,
        grantees,
        grantees_source,
        present,
        dry_run: request.dry_run,
    })
}

/// The SearXNG instance address is required exactly when the reviewed
/// manifest takes one. It is never echoed: refusals use fixed messages.
fn instance(
    state: &Arc<ModuleState>,
    provider: &ProviderName,
    supplied: Option<&str>,
) -> Result<Option<InstanceUrl>, Value> {
    let takes_instance_url = state
        .store()
        .manifest_takes_instance_url(provider.app_key)
        .map_err(|error| {
            crate::wire::store_failure(
                "manifest read",
                "the provider's manifest could not be read",
                &error,
            )
        })?;
    match (takes_instance_url, supplied) {
        (true, Some(value)) => InstanceUrl::parse(value)
            .map(Some)
            .map_err(|message| refusal("invalid_request", message)),
        (true, None) => Err(refusal(
            "invalid_request",
            format!("{} requires --instance-url", provider.name),
        )),
        (false, Some(_)) => Err(refusal(
            "invalid_request",
            format!("{} takes no --instance-url", provider.name),
        )),
        (false, None) => Ok(None),
    }
}

/// Decide whether to create, re-enroll or reuse the provider's connection,
/// returning the step and the connection id it applies to. The existing
/// connection is found by app, because web search selects a provider's
/// connection by app: one made by hand under another id is reused rather than
/// joined by a second candidate. Refuses, writing nothing, when an existing
/// connection would make this run bind a different vendor, credential or
/// instance, or when the provider already has more than one connection.
fn connection_step(
    state: &Arc<ModuleState>,
    principal: &str,
    provider: &ProviderName,
    credential: Option<&str>,
    instance: Option<&InstanceUrl>,
) -> Result<(ConnectionStep, String), Value> {
    let store = state.store();
    let read_failure = |error: &dyn std::fmt::Display| {
        crate::wire::store_failure(
            "provider connection read",
            "the provider's connection could not be read",
            &error.to_string(),
        )
    };
    let table_id = provider.connection_id;
    let connections = store
        .list_connections(principal)
        .map_err(|error| read_failure(&error))?;
    if let Some(other_app) = connections
        .iter()
        .find(|connection| connection.connection_id == table_id)
        .filter(|connection| connection.app_key != provider.app_key)
    {
        return Err(refusal(
            "provider_connection_mismatch",
            format!(
                "connection {table_id} exists for app {}, not {}; nothing was changed",
                other_app.app_key, provider.app_key
            ),
        ));
    }
    let candidates = connections
        .iter()
        .filter(|connection| {
            connection.app_key == provider.app_key && connection.status != "revoked"
        })
        .collect::<Vec<_>>();
    let existing = match candidates.as_slice() {
        [] => {
            if connections
                .iter()
                .any(|connection| connection.connection_id == table_id)
            {
                return Err(refusal(
                    "connection_revoked",
                    format!(
                        "connection {table_id} is revoked and cannot be enrolled again; nothing was changed"
                    ),
                ));
            }
            return Ok((ConnectionStep::Create, table_id.to_string()));
        }
        [existing] => existing,
        several => {
            return Err(refusal(
                "provider_connection_ambiguous",
                format!(
                    "{} has {} connections ({}); remove all but one first; nothing was changed",
                    provider.name,
                    several.len(),
                    several
                        .iter()
                        .map(|connection| connection.connection_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ))
        }
    };
    let id = existing.connection_id.as_str();
    let bound = store
        .connection_credential_reference(principal, id)
        .map_err(|error| read_failure(&error))?;
    if bound.as_deref() != credential {
        let describe = |credential: Option<&str>| match credential {
            Some(name) => name.to_string(),
            None => "no credential (anonymous)".to_string(),
        };
        return Err(refusal(
            "provider_connection_mismatch",
            format!(
                "connection {id} is bound to {}, but this run asks for {}; nothing was changed",
                describe(bound.as_deref()),
                describe(credential)
            ),
        ));
    }
    if existing.status == "pending" {
        return Ok((ConnectionStep::Reenroll, id.to_string()));
    }
    // An active connection's instance address is fixed by its redeemed
    // ticket. Compare without naming either address.
    let recorded = store
        .connection(principal, id)
        .map_err(|error| read_failure(&error))?
        .and_then(|connection| connection.instance_url);
    if recorded.as_ref().map(InstanceUrl::as_str) != instance.map(InstanceUrl::as_str) {
        return Err(refusal(
            "provider_connection_mismatch",
            format!(
                "connection {id} uses a different instance address than the one supplied; nothing was changed"
            ),
        ));
    }
    Ok((ConnectionStep::Reuse, id.to_string()))
}

/// Whether a stored grant authorizes invoking `action` now.
fn live_search_grant(grant: &plexus_core::storage::GrantSummary, action: &str) -> bool {
    grant.authority_kind == GRANT_KIND
        && matches!(grant.state.as_str(), "live" | "until_revoked")
        && grant
            .action_selectors
            .iter()
            .any(|selector| selector == action || selector == "*")
}

/// With no grantees named, the callers that already search: every grantee
/// holding a live invoke grant on its provider's search action on one of the
/// operator's web search provider connections that is not revoked. A wildcard
/// grantee is never carried over.
fn default_grantees(state: &Arc<ModuleState>, principal: &str) -> Result<Vec<String>, Value> {
    let failure = |error: &dyn std::fmt::Display| {
        crate::wire::store_failure(
            "search grant read",
            "existing search grants could not be read",
            &error.to_string(),
        )
    };
    let connections = state
        .store()
        .list_connections(principal)
        .map_err(|error| failure(&error))?;
    let grants = state
        .store()
        .list_all_grants(principal)
        .map_err(|error| failure(&error))?;
    let mut grantees = BTreeSet::new();
    for grant in &grants {
        let Some(connection) = connections
            .iter()
            .find(|connection| connection.connection_id == grant.connection_id)
        else {
            continue;
        };
        let Some(provider) = PROVIDER_NAMES
            .iter()
            .find(|provider| provider.app_key == connection.app_key)
        else {
            continue;
        };
        if connection.status != "revoked"
            && live_search_grant(grant, provider.action)
            && !grant.grantee_principal.contains('*')
        {
            grantees.insert(grant.grantee_principal.clone());
        }
    }
    Ok(grantees.into_iter().collect())
}

/// Grantees already holding the grant this ceremony would mint on the
/// provider's connection, so a rerun does not mint it twice.
fn present_grantees(
    state: &Arc<ModuleState>,
    principal: &str,
    provider: &ProviderName,
    connection_id: &str,
) -> Result<BTreeSet<String>, Value> {
    let grants = state.store().list_all_grants(principal).map_err(|error| {
        crate::wire::store_failure(
            "provider grant read",
            "the provider connection's grants could not be read",
            &error,
        )
    })?;
    Ok(grants
        .iter()
        .filter(|grant| {
            grant.connection_id == connection_id && live_search_grant(grant, provider.action)
        })
        .map(|grant| grant.grantee_principal.clone())
        .collect())
}

impl Plan {
    fn grants_json(
        &self,
        present: &BTreeSet<String>,
        minted: &[plexus_core::storage::GrantRecord],
    ) -> Vec<Value> {
        self.grantees
            .iter()
            .map(|grantee| {
                let mut grant = json!({
                    "grantee": grantee,
                    "authority_kind": GRANT_KIND,
                    "risk_ceiling": GRANT_RISK,
                    "action_selectors": [self.provider.action],
                    "status": if present.contains(grantee) { "already_present" } else { "to_mint" },
                });
                if let Some(record) = minted
                    .iter()
                    .find(|record| &record.grantee_principal == grantee)
                {
                    grant["status"] = json!("minted");
                    grant["grant_id"] = json!(record.grant_id);
                }
                grant
            })
            .collect()
    }

    /// Everything an apply would do, with the credential named but never
    /// resolved, and the instance address withheld.
    fn json(&self) -> Value {
        let provider = self.provider;
        let mut plan = json!({
            "provider": provider.name,
            "app_key": provider.app_key,
            "connection_id": self.connection_id,
            "connection": self.step.label(),
            "credential": self.credential,
            "auth": if self.credential.is_some() { "keyed" } else { "anonymous" },
            "ceiling": {"risk": GRANT_RISK, "action_selectors": [provider.action]},
            "grantees_source": self.grantees_source,
            "grants": self.grants_json(&self.present, &[]),
            "dry_run": self.dry_run,
            "applied": false,
        });
        if self.step == ConnectionStep::Reuse {
            plan["ceiling_note"] = json!("the existing connection keeps its recorded ceiling");
        }
        if self.instance.is_some() {
            plan["instance_url"] = json!("supplied (not shown)");
        }
        plan
    }
}

impl Composite for Plan {
    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn preview(&self) -> Value {
        self.json()
    }

    /// Name the provider and connection, but count callers so the prompt does
    /// not grow with the grant list. Credentials and instance addresses stay out.
    fn summary(&self) -> String {
        let provider = self.provider;
        let connect = match self.step {
            ConnectionStep::Create => "connect",
            ConnectionStep::Reenroll => "re-enroll",
            ConnectionStep::Reuse => "reuse",
        };
        let auth = match self.credential {
            Some(_) => "stored key",
            None => "anonymous",
        };
        format!(
            "add web search provider {}: {connect} {}, {auth}; ceiling {} on {}; grant {GRANT_KIND} read to {} callers",
            provider.name,
            prompt_label(&self.connection_id),
            GRANT_RISK,
            provider.action,
            self.grantees.len(),
        )
    }
}

/// The reply for a failed step: nothing after it ran, so no grant was minted.
fn step_failure(
    state: &Arc<ModuleState>,
    principal: &str,
    connection_id: &str,
    stage: &str,
    response: &Value,
) -> Value {
    composite_admin::step_failure(
        state,
        principal,
        connection_id,
        stage,
        "no grants were minted",
        "add-web-search-provider",
        response,
    )
}

/// Run the confirmed plan through the paths the manual commands use: the
/// ticket ceremony, the facade connect (with its discovery), then the grants.
fn apply(state: &Arc<ModuleState>, principal: &str, plan: &Plan) -> Value {
    let provider = plan.provider;
    let connection_id = plan.connection_id.as_str();
    let discovery = match plan.step {
        ConnectionStep::Create | ConnectionStep::Reenroll => {
            let mut ticket = json!({
                "app_key": provider.app_key,
                "connection_id": connection_id,
                "risk_ceiling": GRANT_RISK,
                "action_selectors": [provider.action],
            });
            if let Some(credential) = plan.credential {
                ticket["credential_id"] = json!(credential);
            }
            if let Some(instance) = &plan.instance {
                ticket["instance_url"] = json!(instance.as_str());
            }
            match composite_admin::issue_and_connect(state, principal, &ticket) {
                Ok(discovery) => discovery,
                Err((stage, response)) => {
                    return step_failure(state, principal, connection_id, stage, &response)
                }
            }
        }
        ConnectionStep::Reuse => {
            composite_admin::rediscover(state, principal, connection_id, provider.app_key)
        }
    };
    if discovery.outcome != "complete" {
        return composite_admin::discovery_incomplete(
            state,
            principal,
            connection_id,
            &discovery,
            "no grants were minted",
            "add-web-search-provider",
        );
    }
    // Read again after connecting: a grant minted since the plan was made
    // must not be minted a second time.
    let present = match present_grantees(state, principal, provider, connection_id) {
        Ok(present) => present,
        Err(response) => return response,
    };
    let selectors = vec![provider.action.to_string()];
    let requests = plan
        .grantees
        .iter()
        .filter(|grantee| !present.contains(*grantee))
        .map(|grantee| GrantMintRequest {
            principal,
            connection_id,
            grantee_principal: grantee,
            authority_kind: GRANT_KIND,
            requested_risk: GRANT_RISK,
            requested_selectors: &selectors,
            expires_at: None,
        })
        .collect::<Vec<_>>();
    let minted = if requests.is_empty() {
        Vec::new()
    } else {
        // The audit row is the one `grant` writes for each grant it mints.
        match state
            .store()
            .mint_grants_bounded_audited(&requests, &|minted| {
                AuditRecord::ceremony(
                    principal,
                    None,
                    Some(connection_id),
                    "grant",
                    &minted.risk_ceiling,
                    None,
                )
            }) {
            Ok(Ok(minted)) => minted,
            Ok(Err(refused)) => {
                return step_failure(
                    state,
                    principal,
                    connection_id,
                    "grants",
                    &ceremony::refusal_response(&refused),
                )
            }
            Err(error) => {
                let response = crate::wire::store_failure(
                    "web search provider grants minted",
                    "grants could not be minted",
                    &error,
                );
                return step_failure(state, principal, connection_id, "grants", &response);
            }
        }
    };
    let mut result = plan.json();
    result["dry_run"] = json!(false);
    result["applied"] = json!(true);
    result["discovery"] = json!(discovery.outcome);
    result["grants"] = json!(plan.grants_json(&present, &minted));
    json!({ "result": result })
}
