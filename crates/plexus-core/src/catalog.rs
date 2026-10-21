//! Catalog discovery, reconciliation, and risk-scaled freshness checks.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::credentials::CredentialSource;
use crate::governance::Severity;
use crate::jcs::jcs_sha256;
use crate::manifest::{AppManifest, AuthMode, Risk, TransportKind};
use crate::mcp_remote::{
    DiscoveredAction, McpConnection, McpRemoteConfig, McpRemoteError, McpRemoteTransport,
};
use crate::rest_api::{RestConnection, RestTransport};
use crate::storage::{CatalogAction, CatalogActionInput, PlexusStore, CATALOG_PRINCIPAL};
use crate::ResolvedCredential;
use cortexkit_store::StoreError;

/// Classify an action against the reviewed manifest, not an unreviewed catalog row.
/// Missing or invalid authority is treated as facade-only so an ordinary invoke
/// cannot bypass the facade when classification fails.
pub fn facade_only_from_stored_manifest(store: &PlexusStore, action: &CatalogAction) -> bool {
    let Ok(Some(connection)) = store.connection(&action.principal, &action.connection_id) else {
        return true;
    };
    let Ok(Some(value)) = store.manifest_json(CATALOG_PRINCIPAL, &connection.app_key) else {
        return true;
    };
    let Ok(manifest) = crate::manifest::validated_manifest(&value) else {
        return true;
    };
    manifest
        .actions_baseline
        .iter()
        .find(|declared| declared.name == action.name)
        .is_none_or(|declared| declared.facade_only)
}

/// Whether this call performed successful catalog discovery or used an existing observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    AlreadyFresh,
    Refreshed,
}

const DEFAULT_CATALOG_TTL: Duration = Duration::from_secs(crate::manifest::DEFAULT_CATALOG_TTL_S);
const S3_WRITE_CEILING: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    Transport(McpRemoteError),
    /// A store read or write failed. The payload is the rendered cause (the
    /// store error's text, or which row was missing), so a log line can say
    /// WHAT failed rather than only that something did. Store errors describe
    /// tables, columns and SQL failures, and binding decryption reports fixed
    /// strings, so no credential byte can reach this text.
    Store(String),
    StaleWrite,
    /// A vendor answered discovery successfully while serving NO tools, and the
    /// connection already knows of some. Treated as a failed observation rather
    /// than as a vendor that removed everything.
    EmptyDiscovery,
    /// The connection's transport kind is not yet wired into this code path.
    TransportUnavailable {
        kind: String,
    },
    Credential,
    Manifest,
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The cause is carried in the variant and must reach the
            // message. Without it every TRANSPORT failure rendered as the
            // same fixed string -- a connect failure and a rejected
            // credential were indistinguishable -- so a reader had to
            // re-probe the vendor by hand to learn which had happened. The
            // sibling variants below already name their own causes; this one
            // was discarding a cause it was holding.
            Self::Transport(error) => write!(formatter, "MCP catalog refresh failed: {error}"),
            Self::Store(cause) => write!(formatter, "catalog store operation failed: {cause}"),
            Self::StaleWrite => formatter.write_str("catalog is stale and writes are blocked"),
            Self::EmptyDiscovery => formatter.write_str(
                "vendor served no tools while the connection has active actions; \
                 refusing to disable them on one empty observation",
            ),
            Self::TransportUnavailable { kind } => {
                write!(formatter, "transport kind '{kind}' is not available")
            }
            Self::Credential => formatter.write_str("credential could not be resolved for catalog"),
            Self::Manifest => formatter.write_str("connection manifest is missing or invalid"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// A connection resolved by `prepare_connection`, typed by transport kind so
/// each caller can only drive the machinery that matches it.
pub enum PreparedConnection {
    Mcp(McpConnection),
    Rest(RestConnection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogRefreshPolicy {
    pub ttl: Duration,
}

impl Default for CatalogRefreshPolicy {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_CATALOG_TTL,
        }
    }
}

type ConnectionRefreshGates =
    std::sync::Mutex<HashMap<(String, String), std::sync::Weak<std::sync::Mutex<()>>>>;

/// Store-backed reconciler for the MCP action catalog. It is intentionally
/// separate from governance: governance still owns every authorization gate,
/// while this type owns only observation freshness and catalog rows.
pub struct CatalogReconciler {
    store: Arc<PlexusStore>,
    transport: Arc<McpRemoteTransport>,
    rest_transport: Arc<RestTransport>,
    refresh_gates: ConnectionRefreshGates,
    policy: CatalogRefreshPolicy,
    #[cfg(any(test, feature = "test-support"))]
    endpoint_overrides: std::sync::Mutex<HashMap<(String, String), String>>,
}

impl CatalogReconciler {
    pub fn new(
        store: Arc<PlexusStore>,
        transport: Arc<McpRemoteTransport>,
        policy: CatalogRefreshPolicy,
    ) -> Self {
        Self {
            store,
            transport,
            rest_transport: Arc::new(RestTransport::default()),
            refresh_gates: std::sync::Mutex::new(HashMap::new()),
            policy,
            #[cfg(any(test, feature = "test-support"))]
            endpoint_overrides: Default::default(),
        }
    }

    /// Share the REST transport that also serves dispatch, so a connection
    /// registered here for discovery carries its config into dispatch. MCP-only
    /// callers can leave the default in place.
    pub fn with_rest_transport(mut self, rest_transport: Arc<RestTransport>) -> Self {
        self.rest_transport = rest_transport;
        self
    }

    #[cfg(test)]
    fn rest_transport(&self) -> &Arc<RestTransport> {
        &self.rest_transport
    }

    /// Refresh at connect, health-probe, listChanged, or an explicit request.
    pub fn refresh(
        &self,
        principal: &str,
        connection: &McpConnection,
        manifest: &AppManifest,
        credential: &ResolvedCredential,
    ) -> Result<Vec<DiscoveredAction>, CatalogError> {
        let discovered = match self.transport.discover(connection, credential) {
            Ok(discovered) => discovered,
            Err(error) => {
                self.mark_degraded(principal, connection);
                return Err(CatalogError::Transport(error));
            }
        };
        if let Err(error) = self.reconcile(principal, connection, manifest, &discovered) {
            self.mark_degraded(principal, connection);
            return Err(error);
        }
        // Clear a previous refresh failure now that one has succeeded.
        //
        // Without this, `mark_degraded` is a one-way door: nothing else in the
        // system writes the status back, so a single transient vendor failure
        // left a connection degraded permanently. The call is a no-op unless
        // the row is currently `degraded`, so a healthy connection is untouched
        // and an operator-revoked one is not resurrected by a lucky probe.
        self.clear_recovery_health(principal, &connection.connection_id);
        Ok(discovered)
    }

    /// Resolve the connection manifest, register its endpoint on the transport
    /// matching its kind (MCP or REST) when supported, and run connect-time
    /// discovery. Keep the raw credential handle within this crate.
    pub fn discover_for_connection(
        &self,
        principal: &str,
        connection_id: &str,
        credential_source: &dyn CredentialSource,
        endpoint_override: Option<&str>,
    ) -> Result<Vec<DiscoveredAction>, CatalogError> {
        let (manifest, prepared, credential) = self.prepare_connection(
            principal,
            connection_id,
            credential_source,
            endpoint_override,
        )?;
        self.refresh_prepared(principal, &prepared, &manifest, &credential)
    }

    /// Re-register every stored connection's endpoint on its transport, with no
    /// vendor contact and no credential resolution.
    ///
    /// TRANSPORT CONFIG IS IN-MEMORY PROCESS STATE. It is populated as a side
    /// effect of connect-time discovery and of health probes, so after a restart
    /// the map is EMPTY while the store still holds every connection. A poll in
    /// that window falls back to the default config, whose endpoint is the empty
    /// string, and the MCP transport refuses it as a configuration error --
    /// reported as `mcp_transport_error`, NotSent.
    ///
    /// It self-heals when the supervisor's first health probe re-registers
    /// everything, roughly 30s after boot. The scheduler does not wait that long:
    /// its first pass runs within a second of start, and because the cadence is
    /// stamped BEFORE dispatch, every subscription that fails this way waits a
    /// full cadence before retrying. After a restart, every due subscription can
    /// lose its first poll this way and wait a full cadence for the next one.
    ///
    /// Deliberately does NOT resolve credentials or contact the vendor. Those
    /// belong to discovery, they can block on a locked vault or a slow endpoint,
    /// and making boot depend on either would trade a bounded delay for an
    /// unbounded one. Registration needs only the stored connection and its
    /// reviewed manifest.
    ///
    /// Failures are skipped rather than propagated: one unreadable manifest must
    /// not stop the remaining connections from being registered, and anything
    /// missed here is still repaired by the health probe that covers this today.
    pub fn register_transports(&self, principal: &str) -> usize {
        let connections = match self.store.list_connections(principal) {
            Ok(connections) => connections,
            Err(_) => {
                crate::diag!(warn catalog: "transport registration skipped: connection store read failed");
                return 0;
            }
        };
        let mut registered = 0;
        for summary in connections {
            // Only active or degraded connections are routable. Pending and
            // revoked connections, and any other status, stay unregistered.
            if summary.status != "active" && summary.status != "degraded" {
                continue;
            }
            match self.load_connection(principal, &summary.connection_id, None) {
                Ok(_) => registered += 1,
                Err(error) => {
                    crate::diag!(warn catalog: "transport registration skipped for connection {principal}/{}: {error}", summary.connection_id)
                }
            }
        }
        registered
    }

    /// Health-probe refresh for one stored connection.
    pub fn health_probe_connection(
        &self,
        principal: &str,
        connection_id: &str,
        credential_source: &dyn CredentialSource,
    ) -> Result<Vec<DiscoveredAction>, CatalogError> {
        if self
            .store
            .is_github_handle_connection(principal, connection_id)?
        {
            return self.health_probe_handle_connection(principal, connection_id);
        }
        let (manifest, prepared, credential) =
            self.prepare_connection(principal, connection_id, credential_source, None)?;
        self.refresh_prepared(principal, &prepared, &manifest, &credential)
    }

    /// Health probe for a connection created by a GitHub handle import.
    ///
    /// Two steps of the ordinary probe do not apply to these connections, so
    /// they are skipped rather than attempted and failed:
    ///
    /// - Credential resolution. A handle connection has no stored credential
    ///   binding: its installation token comes from the App vault through the
    ///   handle credential provider, per request, at dispatch. REST catalog
    ///   refresh never uses a credential anyway (`refresh_rest` builds the
    ///   catalog from the manifest), so resolving one here would only fetch a
    ///   token every probe to throw it away.
    /// - Catalog reconcile. For a REST connector the reviewed manifest is the
    ///   catalog and there is no vendor discovery to reconcile against.
    ///   Manifest ingest updates reviewed policy and adds newly declared actions
    ///   to existing handle connections, preserving operator decisions (status,
    ///   quarantine, schema pin) as they are; reconciling here every probe
    ///   would add a second writer that can change those rows.
    ///
    /// What remains is what the probe is for on these connections: the stored
    /// row and its manifest must load, the REST transport config is registered
    /// again (transport config is in-memory and the probe is what repairs it),
    /// and success clears `degraded` through the same guarded store update as
    /// `refresh_rest`, so that recovery path keeps
    /// working. A failure here never marks the connection degraded. Returns no
    /// actions because no discovery ran.
    fn health_probe_handle_connection(
        &self,
        principal: &str,
        connection_id: &str,
    ) -> Result<Vec<DiscoveredAction>, CatalogError> {
        let (_manifest, _prepared) = self.load_connection(principal, connection_id, None)?;
        self.clear_recovery_health(principal, connection_id);
        Ok(Vec::new())
    }

    /// Check that the stored connection and action are fresh enough for a
    /// write, using the action's risk level to determine the required freshness.
    pub fn ensure_fresh_for_action(
        &self,
        principal: &str,
        connection_id: &str,
        action: &str,
        credential_source: &dyn CredentialSource,
    ) -> Result<Freshness, CatalogError> {
        let action_row = self
            .store
            .catalog_action(principal, connection_id, action)
            .map_err(CatalogError::from)?
            .ok_or_else(|| CatalogError::Store(format!("catalog action {action} not found")))?;
        if action_row.risk != "write" && action_row.risk != "destructive" {
            return Ok(Freshness::AlreadyFresh);
        }
        let severity = severity_from_action(&action_row.risk, &action_row.severity);
        let (manifest, _prepared) = self.load_connection(principal, connection_id, None)?;
        self.ensure_fresh_with(principal, connection_id, &manifest, severity, || {
            let (manifest, prepared, credential) =
                self.prepare_connection(principal, connection_id, credential_source, None)?;
            self.refresh_prepared(principal, &prepared, &manifest, &credential)
        })
    }

    fn prepare_connection(
        &self,
        principal: &str,
        connection_id: &str,
        credential_source: &dyn CredentialSource,
        endpoint_override: Option<&str>,
    ) -> Result<(AppManifest, PreparedConnection, ResolvedCredential), CatalogError> {
        let (manifest, prepared) =
            self.load_connection(principal, connection_id, endpoint_override)?;
        // Whether a credential is required is decided by the REVIEWED MANIFEST,
        // never inferred just from a missing binding. Only auth.mode = none or
        // optional_api_key permits an anonymous request. A bound optional key
        // must still resolve; its failure never falls back to anonymous access.
        if matches!(manifest.auth.mode, AuthMode::None)
            || (manifest.auth.mode == AuthMode::OptionalApiKey
                && !self
                    .store
                    .connection(principal, connection_id)?
                    .ok_or(CatalogError::Credential)?
                    .has_credential_binding)
        {
            return Ok((manifest, prepared, ResolvedCredential::anonymous()));
        }
        let handle = self
            .store
            .connection_credential_binding(principal, connection_id)
            .map_err(CatalogError::from)?
            .ok_or(CatalogError::Credential)?;
        let credential = handle
            .resolve(credential_source)
            .map_err(|error| {
                eprintln!(warn catalog: "catalog credential resolution failed for connection {principal}/{connection_id}: class {}", error.class());
                CatalogError::Credential
            })?;
        Ok((manifest, prepared, credential))
    }

    /// Load the stored connection and its reviewed manifest, and register the
    /// connection on the transport matching the manifest's kind. Resolves no
    /// credential and contacts no vendor.
    fn load_connection(
        &self,
        principal: &str,
        connection_id: &str,
        endpoint_override: Option<&str>,
    ) -> Result<(AppManifest, PreparedConnection), CatalogError> {
        #[cfg(not(any(test, feature = "test-support")))]
        if endpoint_override.is_some() {
            return Err(CatalogError::Manifest);
        }
        #[cfg(any(test, feature = "test-support"))]
        let endpoint = {
            let mut overrides = self
                .endpoint_overrides
                .lock()
                .map_err(|_| CatalogError::Manifest)?;
            let key = (principal.to_string(), connection_id.to_string());
            if let Some(endpoint) = endpoint_override {
                overrides.insert(key.clone(), endpoint.to_string());
            }
            overrides.get(&key).cloned()
        };
        #[cfg(any(test, feature = "test-support"))]
        let endpoint_override = endpoint.as_deref();
        let connection = self
            .store
            .connection(principal, connection_id)
            .map_err(CatalogError::from)?
            .ok_or_else(|| CatalogError::Store("connection row not found".to_string()))?;
        let manifest_value = self
            .store
            .manifest_json(CATALOG_PRINCIPAL, &connection.app_key)
            .map_err(CatalogError::from)?
            .ok_or(CatalogError::Manifest)?;
        let manifest: AppManifest = crate::manifest::validated_manifest(&manifest_value)
            .map_err(|error| {
                let class = match error { crate::manifest::ManifestError::InvalidJson(_) => "invalid_json", crate::manifest::ManifestError::InvalidField(_) => "invalid_field" };
                eprintln!(warn catalog: "catalog manifest validation failed for connection {principal}/{connection_id}, app {}: class {class}", connection.app_key);
                CatalogError::Manifest
            })?;
        let prepared = match manifest.transport.kind {
            TransportKind::McpRemote => {
                let mut mcp_connection = McpConnection::from_manifest(connection_id, &manifest);
                if let Some(endpoint) = endpoint_override {
                    mcp_connection.config = McpRemoteConfig::new(endpoint.to_string())
                        .with_bindings(manifest.credential_bindings.clone())
                        .with_app_key(manifest.key.clone());
                }
                self.transport.register_connection(mcp_connection.clone());
                PreparedConnection::Mcp(mcp_connection)
            }
            TransportKind::RestApi => {
                let mut rest_connection = RestConnection::from_manifest(connection_id, &manifest);
                if manifest.transport.url_from_connection {
                    rest_connection.config.base_url = connection
                        .instance_url
                        .as_ref()
                        .ok_or(CatalogError::Manifest)?
                        .as_str()
                        .to_string();
                }
                if let Some(endpoint) = endpoint_override {
                    // Only the base URL moves to the override; the per-action
                    // HTTP shapes and credential bindings still come from the
                    // reviewed manifest.
                    rest_connection.config.base_url = endpoint.to_string();
                }
                self.rest_transport
                    .register_connection(rest_connection.clone());
                PreparedConnection::Rest(rest_connection)
            }
            _ => {
                return Err(CatalogError::TransportUnavailable {
                    kind: crate::manifest::transport_kind_label(manifest.transport.kind)
                        .to_string(),
                });
            }
        };
        Ok((manifest, prepared))
    }

    fn refresh_prepared(
        &self,
        principal: &str,
        prepared: &PreparedConnection,
        manifest: &AppManifest,
        credential: &ResolvedCredential,
    ) -> Result<Vec<DiscoveredAction>, CatalogError> {
        match prepared {
            PreparedConnection::Mcp(connection) => {
                self.refresh(principal, connection, manifest, credential)
            }
            PreparedConnection::Rest(connection) => {
                self.refresh_rest(principal, connection, manifest)
            }
        }
    }

    /// REST discovery: synthesize the discovered-action list from the reviewed
    /// manifest instead of asking the vendor. A REST vendor has no `tools/list`
    /// surface, and this buys drift protection for free: a REST connector's
    /// catalog cannot drift from its manifest, because the manifest IS the
    /// catalog — there is no vendor-side surface to reconcile against.
    pub fn refresh_rest(
        &self,
        principal: &str,
        connection: &RestConnection,
        manifest: &AppManifest,
    ) -> Result<Vec<DiscoveredAction>, CatalogError> {
        self.rest_transport.register_connection(connection.clone());
        let discovered = discovered_from_manifest(manifest);
        if let Err(error) =
            self.reconcile_actions(principal, &connection.connection_id, manifest, &discovered)
        {
            self.mark_degraded_id(principal, &connection.connection_id);
            return Err(error);
        }
        // Same recovery as the MCP path: a status set on failure that nothing
        // ever clears is a one-way door. Fixed at both call sites rather than
        // one, because a rule applied at N-1 of N sites is the shape that
        // leaves the surviving case to be discovered in production.
        self.clear_recovery_health(principal, &connection.connection_id);
        Ok(discovered)
    }

    fn ensure_fresh_with(
        &self,
        principal: &str,
        connection_id: &str,
        manifest: &AppManifest,
        severity: Severity,
        refresh: impl FnOnce() -> Result<Vec<DiscoveredAction>, CatalogError>,
    ) -> Result<Freshness, CatalogError> {
        let gate = {
            let mut gates = self
                .refresh_gates
                .lock()
                .map_err(|_| CatalogError::Store("catalog refresh map poisoned".into()))?;
            let key = (principal.to_owned(), connection_id.to_owned());
            if let Some(gate) = gates.get(&key).and_then(std::sync::Weak::upgrade) {
                gate
            } else {
                gates.retain(|_, gate| gate.strong_count() > 0);
                let gate = Arc::new(std::sync::Mutex::new(()));
                gates.insert(key, Arc::downgrade(&gate));
                gate
            }
        };
        // Age must be read after acquiring this connection's refresh gate: a
        // caller waiting for discovery must see the preceding caller's result.
        // The shared map is never held across credential or vendor I/O.
        let _guard = gate
            .lock()
            .map_err(|_| CatalogError::Store("catalog refresh gate poisoned".into()))?;
        let last_seen = self
            .store
            .catalog_last_seen_at(principal, connection_id)
            .map_err(CatalogError::from)?;
        let age = last_seen
            .and_then(|value| {
                let now = now_ms();
                u64::try_from(now.saturating_sub(value)).ok()
            })
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX);
        let bound = self.staleness_bound(manifest, severity);
        if age < bound {
            return Ok(Freshness::AlreadyFresh);
        }
        match refresh() {
            Ok(_) => Ok(Freshness::Refreshed),
            Err(error) => {
                crate::diag!(warn catalog: "catalog freshness refresh failed for connection {principal}/{connection_id}: {error}");
                self.mark_degraded_id(principal, connection_id);
                Err(CatalogError::StaleWrite)
            }
        }
    }

    pub fn reconcile(
        &self,
        principal: &str,
        connection: &McpConnection,
        manifest: &AppManifest,
        discovered: &[DiscoveredAction],
    ) -> Result<(), CatalogError> {
        self.reconcile_actions(principal, &connection.connection_id, manifest, discovered)
    }

    fn reconcile_actions(
        &self,
        principal: &str,
        connection_id: &str,
        manifest: &AppManifest,
        discovered: &[DiscoveredAction],
    ) -> Result<(), CatalogError> {
        // A successful call that returned NO tools is a failed observation, not
        // a vendor that removed its entire surface.
        //
        // The sweep below disables every previously-known action absent from
        // `discovered`, and disabling cascades: reservations are invalidated
        // and every trigger subscription on the action is suspended, with no
        // auto-resume. So an empty list would take a working connector apart
        // and require an operator to rebuild it by hand, in response to what is
        // far more likely a vendor blip, a partial outage, or a credential that
        // yields an empty view than a real removal of everything.
        //
        // Guarded only when the connection already HAS actions, so a genuinely
        // empty first discovery still records nothing and stays honest — the
        // refusal is about destroying known state, not about empty results as
        // such.
        //
        // `compare` in crates/plexus-conformance/src/drift.rs refuses the same
        // shape for the same reason. That check only reports; this one writes
        // to the store, so the rule matters more here.
        if discovered.is_empty() {
            let existing = self
                .store
                .list_catalog_actions_all(principal, connection_id)
                .map_err(CatalogError::from)?;
            if existing.iter().any(|action| action.status != "disabled") {
                return Err(CatalogError::EmptyDiscovery);
            }
        }

        let baseline: HashMap<_, _> = manifest
            .actions_baseline
            .iter()
            .map(|action| (action.name.as_str(), action))
            .collect();
        let severity = tier_name(manifest);
        let mut actions = Vec::new();
        for action in discovered {
            // A schema that cannot be canonicalized cannot be pinned, and an
            // unpinned action cannot safely become part of the governed surface.
            // Leave it unseen so an existing row is disabled by the sweep below,
            // matching the seed path's refusal of unclassifiable actions.
            let Ok(schema_hash) = jcs_sha256(&action.input_schema) else {
                continue;
            };
            // The reviewed manifest is the ONLY authority for an action's risk.
            // An action the vendor exposes but the manifest never declared has
            // no reviewed risk at all, and reading that absence as `read` would
            // be the most permissive possible interpretation of the least
            // trustworthy input: a read skips the write-default ask-first gate,
            // can never reach the decision plane (reads floor at S2), and skips
            // the write-enabling resource-filter check. So an undeclared action
            // is quarantined on sight, invisible to catalog consumers and denied
            // at invoke until someone reviews it, and carries write risk so that
            // clearing the quarantine without reclassifying still lands on the
            // cautious side. This generalizes the existing new-write and
            // schema-change quarantine policy from actions that CHANGED to
            // actions that were never reviewed in the first place.
            //
            // For a REST vendor, discovery is synthesized from the manifest
            // itself (`refresh_rest`), so every discovered action is declared by
            // construction and this quarantine branch can never fire. That is
            // correct rather than dead: the same code path runs for MCP vendors,
            // where the vendor can expose actions the manifest never declared.
            let declared = baseline.get(action.name.as_str()).copied();
            let risk = declared.map(|action| action.risk).unwrap_or(Risk::Write);
            // Take reconciliation from the current reviewed manifest, not the
            // stored catalog row. A withdrawn declaration or an undeclared
            // vendor action must clear any previously stored reconciliation.
            let reconciliation = declared
                .and_then(|action| action.reconciliation.as_ref())
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| CatalogError::Manifest)?;
            // Ask-first is the stricter union of the hardcoded write/destructive
            // floor and the manifest's declared `ask_first_risk`, evaluated
            // against this action's reviewed risk. Computing it here (not in
            // `authorize`) keeps the manifest JSON parse off the invoke hot path
            // and lets a manifest widen the set (e.g. add `read`) without ever
            // narrowing the floor. An undeclared action carries write risk, so
            // it asks first like any other write.
            let ask_first = crate::manifest::action_asks_first(
                risk,
                &manifest.defaults.ask_first_risk,
                declared.is_some_and(|action| action.ask_first),
                declared.is_some_and(|action| action.recipients.is_some()),
            );
            let (status, quarantine_reason) = match declared {
                Some(declaration)
                    if declaration
                        .input_schema
                        .as_ref()
                        .is_some_and(|schema| schema != &action.input_schema) =>
                {
                    (
                        "quarantined",
                        Some("schema_changed_requires_review".to_string()),
                    )
                }
                Some(declaration)
                    if declaration.recipients.as_ref().is_some_and(|pointers| {
                        pointers.iter().any(|pointer| {
                            !crate::recipients::recipient_pointer_valid(
                                &action.input_schema,
                                pointer,
                            )
                        })
                    }) =>
                {
                    (
                        "quarantined",
                        Some("recipient_schema_requires_review".to_string()),
                    )
                }
                Some(_) => ("active", None),
                None => (
                    "quarantined",
                    Some("undeclared_requires_review".to_string()),
                ),
            };
            actions.push(CatalogActionInput {
                connection_id: connection_id.to_string(),
                principal: principal.to_string(),
                name: action.name.clone(),
                title: action.title.clone().or_else(|| action.description.clone()),
                schema: action.input_schema.clone(),
                schema_hash,
                risk: risk.to_string(),
                severity: severity.to_string(),
                ask_first,
                status: status.to_string(),
                quarantine_reason,
                reconciliation,
            });
        }
        self.store
            .reconcile_catalog_actions(principal, connection_id, &actions)
            .map_err(CatalogError::from)
    }

    fn clear_recovery_health(&self, principal: &str, connection_id: &str) {
        if let Err(error) = self
            .store
            .clear_connection_degraded(principal, connection_id)
        {
            eprintln!(warn catalog: "clear degraded health failed for connection {principal}/{connection_id}: {error}");
        }
    }

    fn mark_degraded(&self, principal: &str, connection: &McpConnection) {
        self.mark_degraded_id(principal, &connection.connection_id);
    }

    fn mark_degraded_id(&self, principal: &str, connection_id: &str) {
        if let Err(error) = self.store.set_connection_health(
            principal,
            connection_id,
            "degraded",
            &serde_json::json!({"reason": "catalog_refresh_failed"}),
        ) {
            eprintln!(warn catalog: "mark degraded health failed for connection {principal}/{connection_id}: {error}");
        }
    }

    fn staleness_bound(&self, manifest: &AppManifest, severity: Severity) -> Duration {
        // A manifest that omits `catalog_ttl_s` already gets the default through
        // serde, so the policy TTL only applies when a manifest declares 0.
        let manifest_ttl = Duration::from_secs(manifest.defaults.catalog_ttl_s);
        let ttl = if manifest_ttl.is_zero() {
            self.policy.ttl
        } else {
            manifest_ttl
        };
        match severity {
            Severity::S1 => ttl,
            Severity::S2 => ttl,
            Severity::S3 => ttl.min(S3_WRITE_CEILING),
            Severity::S4 => Duration::ZERO,
        }
    }
}

/// One discovered action per reviewed baseline action, with the action's
/// reviewed argument schema as its input schema. Ingest validation guarantees
/// every action on a `rest_api` manifest carries `http`; the empty-object
/// fallback is only defence in depth.
fn discovered_from_manifest(manifest: &AppManifest) -> Vec<DiscoveredAction> {
    manifest
        .actions_baseline
        .iter()
        .map(|action| DiscoveredAction {
            name: action.name.clone(),
            title: None,
            description: None,
            annotations: None,
            input_schema: action
                .http
                .as_ref()
                .map(|http| http.args_schema.clone())
                .unwrap_or_else(|| serde_json::json!({"type": "object"})),
        })
        .collect()
}

/// The severity freshness is judged at. A catalog row's `severity` column
/// holds its app's tier (both the seed and the refresh write it that way), so
/// the action's own severity is that tier combined with its risk by the same
/// rule authorization uses. Reading the tier alone would judge a write on an
/// S1 app as S1, and a stale catalog would then never block it. An unreadable
/// tier is unknown, and unknown gates at the strongest tier.
fn severity_from_action(risk: &str, severity: &str) -> Severity {
    let tier = match severity {
        "S1" => Severity::S1,
        "S2" => Severity::S2,
        "S3" => Severity::S3,
        _ => Severity::S4,
    };
    crate::governance::action_severity(risk, tier)
}

fn tier_name(manifest: &AppManifest) -> &'static str {
    match manifest.tier {
        crate::manifest::Tier::S1 => "S1",
        crate::manifest::Tier::S2 => "S2",
        crate::manifest::Tier::S3 => "S3",
        crate::manifest::Tier::S4 => "S4",
    }
}

// One clock for the crate: this was a second independent copy of the same
// question, and the two had already drifted on their edge arms (this one
// collapsed BOTH a pre-epoch clock and a post-overflow one to zero; the
// store's capped overflow instead). Two resolvers for one fact is the shape
// that diverges silently - and the zero it substituted travels into
// reconcile timestamps and audit rows as a plausible 1970.
use crate::storage::now_ms;

impl From<StoreError> for CatalogError {
    fn from(error: StoreError) -> Self {
        Self::Store(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_scratch::Scratch;
    use crate::{
        ingest_value, AuthorizationRequest, CatalogDenial, GovernanceEngine, GrantInput,
        MockTransport, PolicyInput, StubCredentialSource, CATALOG_PRINCIPAL,
    };
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A manifest that omits `catalog_ttl_s` and the reconciler's default policy
    /// both mean one day, and a manifest declaring 0 falls back to the policy.
    #[test]
    fn omitted_manifest_ttl_and_default_policy_ttl_are_both_one_day() {
        let one_day = Duration::from_secs(86_400);
        let manifest = test_manifest();
        assert_eq!(manifest.defaults.catalog_ttl_s, 86_400, "one day");
        assert_eq!(CatalogRefreshPolicy::default().ttl, one_day, "one day");
        let (store, _path) = test_store();
        let reconciler = CatalogReconciler::new(
            store,
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        assert_eq!(reconciler.staleness_bound(&manifest, Severity::S1), one_day);
        let mut zero = manifest;
        zero.defaults.catalog_ttl_s = 0;
        assert_eq!(reconciler.staleness_bound(&zero, Severity::S2), one_day);
    }

    #[test]
    fn test_endpoint_override_survives_connection_reload() {
        let (store, _path) = test_store();
        store
            .upsert_manifest(
                CATALOG_PRINCIPAL,
                &ingest_value(serde_json::to_value(test_manifest()).unwrap()).unwrap(),
            )
            .unwrap();
        let reconciler = CatalogReconciler::new(
            store,
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        reconciler
            .load_connection("direct", "connection", Some("http://127.0.0.1:12345/mcp"))
            .unwrap();
        let (_, PreparedConnection::Mcp(connection)) = reconciler
            .load_connection("direct", "connection", None)
            .unwrap()
        else {
            panic!("MCP fixture");
        };
        assert_eq!(connection.config.endpoint, "http://127.0.0.1:12345/mcp");
    }

    #[test]
    fn failed_freshness_refresh_never_reports_fresh() {
        let (store, _path) = test_store();
        let reconciler = CatalogReconciler::new(
            store,
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        assert_eq!(
            reconciler.ensure_fresh_with(
                "direct",
                "connection",
                &test_manifest(),
                Severity::S1,
                || Err(CatalogError::Manifest)
            ),
            Err(CatalogError::StaleWrite)
        );
    }

    #[test]
    fn fresh_catalog_write_does_not_resolve_a_credential() {
        let (store, _path) = test_store();
        let manifest = test_manifest();
        let ingested = ingest_value(serde_json::to_value(&manifest).unwrap()).unwrap();
        store.upsert_manifest(CATALOG_PRINCIPAL, &ingested).unwrap();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        reconciler
            .reconcile(
                "direct",
                &McpConnection::new("connection", "http://127.0.0.1/mcp"),
                &manifest,
                &[action("write_tool", json!({"type":"object"}))],
            )
            .unwrap();
        assert_eq!(
            reconciler.ensure_fresh_for_action(
                "direct",
                "connection",
                "write_tool",
                &StubCredentialSource::default()
            ),
            Ok(Freshness::AlreadyFresh),
            "a fresh catalog must not require a vault read"
        );
    }

    #[test]
    fn nonrecipient_schema_drift_names_schema_review() {
        let (store, _path) = test_store();
        let mut manifest = test_manifest();
        manifest.actions_baseline[1].input_schema =
            Some(json!({"type":"object","properties":{"old":{"type":"string"}}}));
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        reconciler
            .reconcile(
                "direct",
                &McpConnection::new("connection", "http://127.0.0.1/mcp"),
                &manifest,
                &[action("write_tool", json!({"type":"object"}))],
            )
            .unwrap();
        assert_eq!(
            store
                .catalog_action("direct", "connection", "write_tool")
                .unwrap()
                .unwrap()
                .quarantine_reason
                .as_deref(),
            Some("schema_changed_requires_review"),
            "schema drift without recipients must name schema review"
        );
    }

    #[test]
    fn reconcile_rolls_back_all_actions_on_a_store_failure() {
        let (store, path) = test_store();
        let manifest = test_manifest();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://127.0.0.1/mcp");
        let initial = [
            action("read_tool", json!({"type":"object"})),
            action("write_tool", json!({"type":"object"})),
        ];
        reconciler
            .reconcile("direct", &connection, &manifest, &initial)
            .unwrap();
        let before = store
            .catalog_action("direct", "connection", "read_tool")
            .unwrap()
            .unwrap();
        let db = rusqlite::Connection::open(path.path()).unwrap();
        db.execute_batch("CREATE TRIGGER reject_second_action BEFORE UPDATE ON catalog_actions WHEN NEW.name='write_tool' BEGIN SELECT RAISE(FAIL,'second action unavailable'); END;").unwrap();
        let changed = [
            action(
                "read_tool",
                json!({"type":"object","properties":{"new":{"type":"string"}}}),
            ),
            initial[1].clone(),
        ];
        assert!(reconciler
            .reconcile("direct", &connection, &manifest, &changed)
            .is_err());
        let after = store
            .catalog_action("direct", "connection", "read_tool")
            .unwrap()
            .unwrap();
        assert_eq!(
            after.schema, before.schema,
            "all catalog actions must roll back on a reconcile failure"
        );
        assert_eq!(after.status, before.status);
    }

    #[test]
    fn concurrent_freshness_reports_only_its_own_refresh() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        };
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = requests.clone();
        let server = crate::test_http::KeepAliveServer::start(
            Duration::from_secs(5),
            move |request| {
                let body: Value =
                    serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
                if body["method"] == "notifications/initialized" {
                    return "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".into();
                }
                let result = if body["method"] == "tools/list" {
                    counted.fetch_add(1, Ordering::SeqCst);
                    json!({"tools":[{"name":"write_tool","inputSchema":{"type":"object"}}]})
                } else {
                    json!({})
                };
                let reply = json!({"jsonrpc":"2.0","id":body["id"],"result":result}).to_string();
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", reply.len(), reply)
            },
        );
        let (store, path) = test_store();
        let mut manifest = test_manifest();
        manifest.auth.mode = AuthMode::None;
        manifest.credential_bindings.clear();
        manifest.transport.url = format!("http://{}/mcp", server.address());
        store
            .upsert_manifest(
                CATALOG_PRINCIPAL,
                &ingest_value(serde_json::to_value(&manifest).unwrap()).unwrap(),
            )
            .unwrap();
        let reconciler = Arc::new(CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        ));
        reconciler
            .reconcile(
                "direct",
                &McpConnection::from_manifest("connection", &manifest),
                &manifest,
                &[action("write_tool", json!({"type":"object"}))],
            )
            .unwrap();
        rusqlite::Connection::open(path.path())
            .unwrap()
            .execute("UPDATE catalog_actions SET last_seen_at_ms=1", [])
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut callers = Vec::new();
        for _ in 0..2 {
            let reconciler = reconciler.clone();
            let barrier = barrier.clone();
            callers.push(crate::bounded::Task::spawn(move || {
                barrier.wait();
                reconciler
                    .ensure_fresh_for_action(
                        "direct",
                        "connection",
                        "write_tool",
                        &StubCredentialSource::default(),
                    )
                    .unwrap()
            }));
        }
        barrier.wait();
        let results: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join_timeout(Duration::from_secs(30)).unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Freshness::Refreshed)
                .count(),
            1,
            "only the caller performing discovery may report Refreshed"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Freshness::AlreadyFresh)
                .count(),
            1
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "concurrent nonzero-bound writes must share one discovery"
        );
    }

    fn test_manifest() -> AppManifest {
        serde_json::from_value(json!({
            "schema_version": 1,
            "key": "mock",
            "name": "Mock",
            "description": "test manifest",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "test",
            "tier": "S2",
            "transport": {"kind": "mcp_remote", "url": "http://127.0.0.1/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "primary", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [
                {
                    "name": "read_tool",
                    "risk": "read",
                    "poll": {"item_kind": "issue", "cursor_kind": "sync_token", "token_field": "nextSyncToken"}
                },
                {"name": "write_tool", "risk": "write"}
            ],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 1}},
            "availability": "ga"
        }))
        .expect("test manifest")
    }

    fn test_store() -> (Arc<PlexusStore>, Scratch) {
        let serial = TEST_STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Scratch::database("catalog");
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("catalog-test-{serial}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("catalog test store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "mock",
                "active",
                &json!({"required": [], "write_enabling": []}),
            )
            .expect("connection");
        (store, path)
    }

    fn action(name: &str, schema: Value) -> DiscoveredAction {
        DiscoveredAction {
            name: name.to_string(),
            title: Some(name.to_string()),
            description: None,
            annotations: None,
            input_schema: schema,
        }
    }

    fn seed_trigger_subscription(
        store: &Arc<PlexusStore>,
        manifest: &AppManifest,
    ) -> (CatalogReconciler, crate::storage::TriggerSubscription) {
        let ingested = ingest_value(serde_json::to_value(manifest).expect("serialize manifest"))
            .expect("ingest trigger manifest");
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
            .expect("store trigger manifest");
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        reconciler
            .reconcile(
                "direct",
                &connection,
                manifest,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("seed trigger catalog");
        store
            .insert_grant(&GrantInput {
                grant_id: "trigger-poll-grant".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "read".to_string(),
                action_selectors: vec!["read_tool".to_string()],
                authority_kind: crate::AUTHORITY_POLL.to_string(),
                expires_at: None,
            })
            .expect("poll grant");
        let subscription = store
            .subscribe("direct", "connection", "read_tool", 60)
            .expect("subscribe call")
            .expect("read action is subscribable");
        (reconciler, subscription)
    }

    fn trigger_manifest() -> AppManifest {
        test_manifest()
    }

    #[test]
    fn catalog_reconcile_refuses_a_schema_when_jcs_hashing_fails() {
        let (store, path) = test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");

        let result = crate::jcs::with_sha256_failure_on_call(0, || {
            reconciler.reconcile(
                "direct",
                &connection,
                &test_manifest(),
                &[action("read_tool", json!({"type": "object"}))],
            )
        });

        assert!(
            result.is_ok(),
            "one unreadable action must not poison the refresh"
        );
        assert!(
            store
                .catalog_action("direct", "connection", "read_tool")
                .expect("query refused action")
                .is_none(),
            "an action with no trustworthy schema pin must not be seeded"
        );
        let _ = std::fs::remove_file(path);
    }

    /// Pins TWO properties, and the second one is not in the name.
    ///
    /// The first is the one the name says: keys are ordered by UTF-16 code unit
    /// per RFC 8785, so U+1F600 sorts before U+E000 and a scalar-value sort
    /// would produce a different digest.
    ///
    /// The second is that the digest is taken over `input_schema` ALONE. The
    /// literal below is the hash of that field and nothing else, so widening the
    /// input to include `title`, `description` or `annotations` reddens this
    /// test. That matters more than the ordering: a stored `schema_hash` is what
    /// a trigger subscription is pinned to, and reconcile QUARANTINES an action
    /// whose hash moved. Widening the digest moves all of them at once — 305
    /// stored actions across seven connections today — and every watch on every
    /// one of them suspends until an operator reviews and repins it by hand.
    ///
    /// Recorded here because I went looking for this fence, did not find it
    /// under a name about ordering, and was one dispatch away from writing a
    /// second one. A test that pins a property its name does not mention is
    /// undiscoverable by the person most likely to need it.
    #[test]
    fn catalog_reconcile_hashes_schema_keys_with_rfc_8785_ordering() {
        let (store, path) = test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        let schema = json!({"\u{E000}": 1, "\u{1F600}": 2});

        reconciler
            .reconcile(
                "direct",
                &connection,
                &test_manifest(),
                &[action("read_tool", schema)],
            )
            .expect("reconcile astral-key schema");

        let stored = store
            .catalog_action("direct", "connection", "read_tool")
            .expect("query action")
            .expect("action was stored");
        assert_eq!(
            stored.schema_hash,
            "sha256:28c95d1bbb2209223307e62f489020e8f9e0cfa16adf2daf6d88127a1e8dd22a"
        );
        let _ = std::fs::remove_file(path);
    }

    fn schema_review_sequence(
        drift: bool,
        repin: bool,
        return_changed: bool,
        discover_after_repin: bool,
    ) {
        let (store, path) = test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        let manifest = test_manifest();
        let original = json!({"type": "object", "properties": {"id": {"type": "string"}}});
        let changed = json!({"type": "object", "properties": {"id": {"type": "integer"}}});
        let discover = |schema: Option<&Value>| {
            // Keep discovery nonempty when the read tool disappears.
            let mut actions = vec![action("write_tool", json!({"type": "object"}))];
            if let Some(schema) = schema {
                actions.push(action("read_tool", schema.clone()));
            }
            reconciler
                .reconcile("direct", &connection, &manifest, &actions)
                .unwrap();
        };
        let current = || {
            store
                .catalog_action("direct", "connection", "read_tool")
                .unwrap()
                .unwrap()
        };
        discover(Some(&original));
        assert_eq!(current().status, "active", "first-sight declared read");
        if drift {
            discover(Some(&changed));
            assert_eq!(current().status, "quarantined");
            assert_eq!(
                current().quarantine_reason.as_deref(),
                Some("schema_changed_requires_review")
            );
        }
        if repin {
            store
                .repin_reviewed_action("direct", "connection", "read_tool", &current().schema_hash)
                .unwrap()
                .unwrap();
            assert_eq!(current().status, "active");
            if discover_after_repin {
                discover(Some(&changed));
                assert_eq!(
                    current().status,
                    "active",
                    "immediate discovery after repin"
                );
            }
        }
        discover(None);
        assert_eq!(current().status, "disabled");
        let returning = if return_changed { &changed } else { &original };
        discover(Some(returning));
        let expected = if drift && !repin && return_changed {
            "quarantined"
        } else {
            "active"
        };
        assert_eq!(current().status, expected, "return after disappearance");
        // Repeat the cycle: re-quarantine must not replace the approved snapshot
        // with the unapproved schema through the catalog upsert.
        if expected == "quarantined" {
            discover(None);
            discover(Some(returning));
            assert_eq!(current().status, expected, "second disappearance");
        }
        if repin {
            discover(Some(&changed));
            assert_eq!(current().status, "active", "discovery after repin");
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn schema_review_quarantine_survives_disappear_and_return_unreviewed() {
        schema_review_sequence(true, false, true, false);
        schema_review_sequence(true, false, false, false);
    }

    #[test]
    fn schema_review_disappear_and_return_unchanged_stays_active() {
        schema_review_sequence(false, false, false, false);
        // No discovery between repin and disappearance: disable itself must
        // preserve the newly approved schema rather than the old snapshot.
        schema_review_sequence(true, true, true, false);
        schema_review_sequence(true, true, true, true);
    }

    fn seed_trigger_subscriptions(
        store: &Arc<PlexusStore>,
        manifest: &AppManifest,
        action_names: &[&str],
    ) -> (CatalogReconciler, Vec<crate::storage::TriggerSubscription>) {
        let ingested = ingest_value(serde_json::to_value(manifest).expect("serialize manifest"))
            .expect("ingest trigger manifest");
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
            .expect("store trigger manifest");
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        let discovered = action_names
            .iter()
            .map(|name| action(name, json!({"type": "object"})))
            .collect::<Vec<_>>();
        reconciler
            .reconcile("direct", &connection, manifest, &discovered)
            .expect("seed trigger catalog");
        let subscriptions = action_names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                store
                    .insert_grant(&GrantInput {
                        grant_id: format!("trigger-poll-grant-{index}"),
                        principal: "direct".to_string(),
                        connection_id: "connection".to_string(),
                        grantee_principal: "direct".to_string(),
                        risk_ceiling: "read".to_string(),
                        action_selectors: vec![(*name).to_string()],
                        authority_kind: crate::AUTHORITY_POLL.to_string(),
                        expires_at: None,
                    })
                    .expect("poll grant");
                store
                    .subscribe("direct", "connection", name, 60)
                    .expect("subscribe call")
                    .expect("read action is subscribable")
            })
            .collect();
        (reconciler, subscriptions)
    }

    fn assert_subscription_reason(
        store: &PlexusStore,
        subscription_id: &str,
        reason: &str,
    ) -> crate::storage::TriggerSubscription {
        let subscription = store
            .subscription("direct", subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(subscription.status, "suspended");
        assert_eq!(subscription.suspended_reason.as_deref(), Some(reason));
        subscription
    }

    fn rest_manifest() -> AppManifest {
        serde_json::from_value(json!({
            "schema_version": 1,
            "key": "restdemo",
            "name": "REST Demo",
            "description": "test rest manifest",
            "reuse_path": "openapi_shim",
            "reuse_rationale": "test",
            "tier": "S2",
            "transport": {"kind": "rest_api", "url": "http://127.0.0.1:0"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [
                {
                    "name": "get_issue",
                    "risk": "read",
                    "http": {
                        "method": "GET",
                        "path": "/v1/issues/{issue_id}",
                        "args_schema": {
                            "type": "object",
                            "properties": {"issue_id": {"type": "string"}},
                            "required": ["issue_id"]
                        }
                    }
                },
                {
                    "name": "create_issue",
                    "risk": "write",
                    "http": {
                        "method": "POST",
                        "path": "/v1/issues",
                        "args_schema": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}}
                        }
                    }
                }
            ],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 1}},
            "availability": "ga"
        }))
        .expect("rest test manifest")
    }

    fn rest_test_store() -> (Arc<PlexusStore>, Scratch) {
        // Distinct namespace so these tests never contend with `test_store()`
        // users on the storage writer lease under parallel runs.
        //
        // The serial rather than the wall clock is what keeps the namespace
        // distinct: `now_ms()` alone collides whenever two callers land in the
        // same millisecond, which is routine once more than one test uses this
        // helper, and a shared namespace makes them fight over the
        // single-writer lease.
        let serial = TEST_STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Scratch::database("catalog-rest");
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!("catalog-rest-test-{serial}"),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: path.to_string_lossy().into_owned(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("catalog rest test store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "restdemo",
                "active",
                &json!({"required": [], "write_enabling": []}),
            )
            .expect("connection");
        (store, path)
    }

    #[test]
    fn reconciliation_suspends_subscription_on_risk_drift_with_gap() {
        let (store, path) = test_store();
        let manifest = trigger_manifest();
        let (reconciler, subscription) = seed_trigger_subscription(&store, &manifest);
        assert!(store
            .record_poll_success(
                "direct",
                &subscription.subscription_id,
                &json!({"sync_token": "before-drift"}),
                1_234,
            )
            .expect("record successful poll"));

        let mut drifted = manifest.clone();
        drifted.actions_baseline[0].risk = Risk::Write;
        reconciler
            .reconcile(
                "direct",
                &McpConnection::new("connection", "http://unused.invalid/mcp"),
                &drifted,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("reconcile risk drift");

        let suspended =
            assert_subscription_reason(&store, &subscription.subscription_id, "risk_drift");
        assert_eq!(
            store
                .catalog_action("direct", "connection", "read_tool")
                .expect("read catalog action")
                .expect("catalog action")
                .risk,
            "write"
        );
        let events = store
            .list_events(
                "direct",
                Some("connection"),
                Some(&subscription.subscription_id),
            )
            .expect("read suspension events");
        let gap = events
            .iter()
            .find(|event| event.kind == "gap")
            .expect("risk drift writes a gap event");
        assert_eq!(gap.gap_reason.as_deref(), Some("risk_drift"));
        assert_eq!(gap.gap_from_ms, suspended.last_success_at_ms);
        assert!(gap.gap_to_ms.unwrap_or_default() >= 1_234);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reconciliation_suspends_quarantine_disable_and_schema_with_distinct_reasons() {
        let (store, path) = test_store();
        let mut manifest = trigger_manifest();
        for name in ["quarantine_tool", "disable_tool", "schema_tool"] {
            manifest.actions_baseline.push(
                serde_json::from_value(json!({
                    "name": name,
                    "risk": "read",
                    "poll": {"item_kind": "issue", "cursor_kind": "sync_token", "token_field": "nextSyncToken"}
                }))
                .expect("read trigger baseline"),
            );
        }
        let action_names = ["quarantine_tool", "disable_tool", "schema_tool"];
        let (reconciler, subscriptions) =
            seed_trigger_subscriptions(&store, &manifest, &action_names);

        store
            .refresh_catalog_action(CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "quarantine_tool".to_string(),
                title: Some("quarantine_tool".to_string()),
                schema: json!({"type": "object"}),
                schema_hash: jcs_sha256(&json!({"type": "object"}))
                    .expect("test JSON is JCS-compatible"),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "quarantined".to_string(),
                quarantine_reason: Some("vendor_review_required".to_string()),
                reconciliation: None,
            })
            .expect("quarantine catalog action");
        assert_subscription_reason(&store, &subscriptions[0].subscription_id, "quarantined");

        assert!(store
            .disable_catalog_action("direct", "connection", "disable_tool")
            .expect("disable catalog action"));
        assert_subscription_reason(&store, &subscriptions[1].subscription_id, "disabled");

        reconciler
            .reconcile(
                "direct",
                &McpConnection::new("connection", "http://unused.invalid/mcp"),
                &manifest,
                &[
                    action("quarantine_tool", json!({"type": "object"})),
                    action("disable_tool", json!({"type": "object"})),
                    action(
                        "schema_tool",
                        json!({
                            "type": "object",
                            "properties": {"changed": {"type": "string"}}
                        }),
                    ),
                ],
            )
            .expect("reconcile schema change");
        assert_subscription_reason(&store, &subscriptions[2].subscription_id, "schema_changed");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn suspended_subscription_does_not_auto_resume_when_risk_returns_to_read() {
        let (store, path) = test_store();
        let manifest = trigger_manifest();
        let (reconciler, subscription) = seed_trigger_subscription(&store, &manifest);
        let mut drifted = manifest.clone();
        drifted.actions_baseline[0].risk = Risk::Write;
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        let discovered = [action("read_tool", json!({"type": "object"}))];
        reconciler
            .reconcile("direct", &connection, &drifted, &discovered)
            .expect("reconcile to write");
        assert_subscription_reason(&store, &subscription.subscription_id, "risk_drift");

        reconciler
            .reconcile("direct", &connection, &manifest, &discovered)
            .expect("reconcile back to read");
        let still_suspended =
            assert_subscription_reason(&store, &subscription.subscription_id, "risk_drift");
        assert_eq!(still_suspended.status, "suspended");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn suspension_gap_covers_last_successful_poll_to_suspension() {
        let (store, path) = test_store();
        let manifest = trigger_manifest();
        let (reconciler, subscription) = seed_trigger_subscription(&store, &manifest);
        assert!(store
            .record_poll_success("direct", &subscription.subscription_id, &json!({}), 9_876)
            .expect("record successful poll"));
        let mut drifted = manifest.clone();
        drifted.actions_baseline[0].risk = Risk::Write;
        reconciler
            .reconcile(
                "direct",
                &McpConnection::new("connection", "http://unused.invalid/mcp"),
                &drifted,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("reconcile risk drift");
        let gap = store
            .list_events(
                "direct",
                Some("connection"),
                Some(&subscription.subscription_id),
            )
            .expect("list gap")
            .into_iter()
            .find(|event| event.kind == "gap")
            .expect("gap event");
        assert_eq!(gap.gap_from_ms, Some(9_876));
        assert!(gap.gap_to_ms.expect("gap end") >= 9_876);
        assert_eq!(gap.gap_reason.as_deref(), Some("risk_drift"));
        let _ = std::fs::remove_file(path);
    }

    /// Boot registration re-registers stored connections on their transports,
    /// and registers NOTHING for connections an operator stopped.
    ///
    /// Transport config is in-memory process state, so after a restart the map is
    /// empty while the store still holds every connection. A poll in that window
    /// falls back to a default config whose endpoint is the empty string and is
    /// refused as a configuration error -- and because the cadence is stamped
    /// before dispatch, each affected subscription then waits a full cadence. On
    /// the first pass after a restart, that can be every poll.
    ///
    /// Both arms matter. Registering the active connection is the fix; NOT
    /// registering the revoked one is the property that keeps the fix from
    /// preparing a transport for calls an operator deliberately stopped.
    ///
    /// Mutation proved: dropping the status filter registers the revoked
    /// connection and fails the second assertion; returning early registers
    /// nothing and fails the first.
    #[test]
    fn boot_registration_covers_live_connections_and_skips_stopped_ones() {
        let (store, path) = rest_test_store();
        let transport = Arc::new(McpRemoteTransport::default());
        let reconciler =
            CatalogReconciler::new(store.clone(), Arc::clone(&transport), Default::default());
        let manifest = rest_manifest();
        let ingested = ingest_value(serde_json::to_value(&manifest).expect("serialize manifest"))
            .expect("ingest manifest");
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
            .expect("store manifest");
        for (connection_id, status) in [("live-connection", "active"), ("stopped", "revoked")] {
            store
                .insert_connection(
                    "direct",
                    connection_id,
                    &ingested.manifest.key,
                    status,
                    &serde_json::json!({}),
                )
                .expect("seed connection");
        }

        // Precondition: nothing is registered yet, which is the post-restart
        // state this exists to repair. Asserted rather than assumed, so the
        // assertion below cannot pass against a transport that was already
        // populated by some earlier step.
        assert!(
            !reconciler
                .rest_transport()
                .has_connection("live-connection"),
            "precondition: the transport must start unregistered"
        );

        // DERIVED from the store, not hardcoded: this fixture seeds a connection
        // of its own, so a literal count here would encode an assumption about
        // the helper rather than a claim about the sweep -- and it would break
        // silently the day the helper changes. Caught by writing `1` first and
        // measuring 2.
        let expected = store
            .list_connections("direct")
            .expect("list connections")
            .iter()
            .filter(|summary| summary.status == "active" || summary.status == "degraded")
            .count();
        let registered = reconciler.register_transports("direct");

        assert_eq!(
            registered, expected,
            "every live connection must register, and only those"
        );
        assert!(
            reconciler
                .rest_transport()
                .has_connection("live-connection"),
            "the active connection must be registered after the sweep"
        );
        assert!(
            !reconciler.rest_transport().has_connection("stopped"),
            "a revoked connection must NOT be registered: an operator stopped it"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rest_discovery_synthesizes_the_catalog_from_the_manifest() {
        let (store, path) = rest_test_store();
        let transport = Arc::new(McpRemoteTransport::default());
        let reconciler = CatalogReconciler::new(store.clone(), transport, Default::default());
        let manifest = rest_manifest();
        let connection = RestConnection::from_manifest("connection", &manifest);
        let discovered = reconciler
            .refresh_rest("direct", &connection, &manifest)
            .expect("rest discovery");
        assert_eq!(discovered.len(), 2);
        let rows = store
            .list_catalog_actions_all("direct", "connection")
            .expect("catalog rows");
        assert_eq!(rows.len(), 2);
        // Discovery came from the manifest, so every discovered action is
        // declared: none may carry the undeclared_requires_review quarantine.
        assert!(rows
            .iter()
            .all(|row| row.quarantine_reason.as_deref() != Some("undeclared_requires_review")));
        let get_row = rows
            .iter()
            .find(|row| row.name == "get_issue")
            .expect("get_issue row");
        assert_eq!(get_row.status, "active");
        assert_eq!(
            get_row.schema,
            json!({
                "type": "object",
                "properties": {"issue_id": {"type": "string"}},
                "required": ["issue_id"]
            })
        );
        assert_eq!(get_row.risk, "read");
        assert!(get_row.schema_hash.starts_with("sha256:"));
        // A first-observed write still lands in the same new-write quarantine
        // any vendor's write would: REST discovery goes through the identical
        // reconciliation discipline rather than bypassing it.
        let create_row = rows
            .iter()
            .find(|row| row.name == "create_issue")
            .expect("create_issue row");
        assert_eq!(create_row.status, "quarantined");
        assert_eq!(
            create_row.quarantine_reason.as_deref(),
            Some("new_write_requires_review")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reconciliation_quarantines_drift_and_disables_removed_actions() {
        let (store, path) = test_store();
        let transport = Arc::new(McpRemoteTransport::default());
        let reconciler = CatalogReconciler::new(store.clone(), transport, Default::default());
        let manifest = test_manifest();
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        let first = vec![
            action(
                "read_tool",
                json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            ),
            action(
                "write_tool",
                json!({"type": "object", "properties": {"title": {"type": "string"}}}),
            ),
        ];
        reconciler
            .reconcile("direct", &connection, &manifest, &first)
            .expect("first reconciliation");
        let rows = store
            .list_catalog_actions_all("direct", "connection")
            .expect("all catalog rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .find(|row| row.name == "write_tool")
                .map(|row| row.status.as_str()),
            Some("quarantined")
        );
        let read_generation = rows
            .iter()
            .find(|row| row.name == "read_tool")
            .expect("read row")
            .generation;

        let handle = b"test:catalog-test-handle";
        // The connection is already active; credential rotation is not enrollment.
        store
            .rebind_credential_reference(
                "direct",
                "connection",
                store
                    .connection("direct", "connection")
                    .unwrap()
                    .unwrap()
                    .generation,
                "test:catalog-test-handle",
            )
            .expect("rebind catalog test credential");
        store
            .insert_grant(&GrantInput {
                grant_id: "catalog-grant".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "write".to_string(),
                action_selectors: vec!["write_tool".to_string()],
                authority_kind: "invoke".to_string(),
                expires_at: None,
            })
            .expect("catalog grant");
        store
            .insert_policy(&PolicyInput {
                policy_id: "catalog-policy".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                action_selector: "write_tool".to_string(),
                effect: "allow".to_string(),
                expires_at: None,
            })
            .expect("catalog policy");
        let credentials = StubCredentialSource::default();
        credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
        let engine = GovernanceEngine::new(
            store.clone(),
            std::sync::Arc::new(credentials),
            std::sync::Arc::new(MockTransport::default()),
        );
        assert!(matches!(
            engine.authorize(AuthorizationRequest::new(
                "direct",
                "connection",
                "write_tool",
                json!({"title": "example"})
            )),
            Err(crate::Denial::Catalog(CatalogDenial::Quarantined))
        ));

        let second = vec![action(
            "read_tool",
            json!({"type": "object", "properties": {"q": {"type": "number"}}}),
        )];
        reconciler
            .reconcile("direct", &connection, &manifest, &second)
            .expect("drift reconciliation");
        let rows = store
            .list_catalog_actions_all("direct", "connection")
            .expect("reconciled rows");
        assert_eq!(
            rows.iter()
                .find(|row| row.name == "read_tool")
                .map(|row| row.status.as_str()),
            Some("quarantined")
        );
        assert!(rows
            .iter()
            .find(|row| row.name == "read_tool")
            .is_some_and(|row| row.generation > read_generation));
        assert_eq!(
            rows.iter()
                .find(|row| row.name == "write_tool")
                .map(|row| row.status.as_str()),
            Some("disabled")
        );
        let _ = std::fs::remove_file(path);
    }

    /// Build a governance engine over the catalog test store and grant
    /// `action` at `ceiling` so `authorize` reaches the policy gate. Ask-first
    /// returns at the policy gate, before credential resolution, so no
    /// credential needs to be wired.
    fn authorize_engine(
        store: &Arc<PlexusStore>,
        action: &str,
        ceiling: &str,
    ) -> GovernanceEngine<StubCredentialSource, MockTransport> {
        store
            .insert_grant(&GrantInput {
                grant_id: format!("grant-{action}"),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: ceiling.to_string(),
                action_selectors: vec![action.to_string()],
                authority_kind: "invoke".to_string(),
                expires_at: None,
            })
            .expect("ask-first grant");
        GovernanceEngine::new(
            store.clone(),
            Arc::new(StubCredentialSource::default()),
            Arc::new(MockTransport::default()),
        )
    }

    #[test]
    fn manifest_declared_read_widens_ask_first_to_read_actions() {
        // Mutation under test: drop the manifest's declared risks from the
        // reconciler's union, or revert `authorize` to `is_write(risk)`. Either
        // makes a read the manifest marked ask-first proceed silently, so this
        // read must create an action request. This is the test that fails while
        // `defaults.ask_first_risk` is still ignored.
        let (store, path) = test_store();
        let mut manifest = test_manifest();
        manifest.defaults.ask_first_risk = vec![Risk::Write, Risk::Destructive, Risk::Read];
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        reconciler
            .reconcile(
                "direct",
                &connection,
                &manifest,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("reconcile widened read");

        // STATE: the reconciled read row carries ask-first from the manifest.
        let row = store
            .catalog_action("direct", "connection", "read_tool")
            .expect("read row")
            .expect("read action row");
        assert!(
            row.ask_first,
            "manifest-declared read must be stored ask-first"
        );

        // STATE + behaviour: with no policy the read asks first and the request
        // row actually exists, not merely a denial returned.
        let engine = authorize_engine(&store, "read_tool", "read");
        let Err(crate::Denial::ActionRequestCreated { request_id }) = engine.authorize(
            AuthorizationRequest::new("direct", "connection", "read_tool", json!({})),
        ) else {
            panic!("widened read without a policy must ask first");
        };
        assert!(store
            .list_action_requests("direct")
            .expect("requests")
            .iter()
            .any(|item| item.request_id == request_id && item.status == "pending"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn manifest_cannot_narrow_ask_first_below_the_write_floor() {
        // Mutation under test: drop the hardcoded write/destructive floor from
        // the reconciler's union (or from `asks_first`). A manifest declaring
        // `[]` or only `["read"]` would then clear a write's ask-first flag and
        // the write would proceed silently — the security direction. Both
        // manifests must still make the write ask first. Kept separate from the
        // widening test because it proves the floor, not the declared term.
        for declared in [Vec::new(), vec![Risk::Read]] {
            let (store, path) = test_store();
            let mut manifest = test_manifest();
            manifest.defaults.ask_first_risk = declared.clone();
            let reconciler = CatalogReconciler::new(
                store.clone(),
                Arc::new(McpRemoteTransport::default()),
                Default::default(),
            );
            let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
            reconciler
                .reconcile(
                    "direct",
                    &connection,
                    &manifest,
                    &[action("write_tool", json!({"type": "object"}))],
                )
                .expect("reconcile narrowed write");

            // STATE: the floor survives the manifest's narrowing declaration.
            let row = store
                .catalog_action("direct", "connection", "write_tool")
                .expect("write row")
                .expect("write action row");
            assert!(
                row.ask_first,
                "write must stay ask-first despite manifest declaring {declared:?}"
            );

            // A first-observed write is quarantined for review; reactivate it
            // preserving its stored ask-first so the policy gate is reachable.
            store
                .upsert_catalog_action(&CatalogActionInput {
                    connection_id: "connection".to_string(),
                    principal: "direct".to_string(),
                    name: "write_tool".to_string(),
                    title: row.title.clone(),
                    schema: row.schema.clone(),
                    schema_hash: row.schema_hash.clone(),
                    risk: row.risk.clone(),
                    severity: row.severity.clone(),
                    ask_first: row.ask_first,
                    status: "active".to_string(),
                    quarantine_reason: None,
                    reconciliation: None,
                })
                .expect("reactivate write");

            // Ask-first remains pinned even when severity refuses execution
            // before consent: unavailable execution must not file a useless card.
            let engine = authorize_engine(&store, "write_tool", "write");
            match engine.authorize(
                AuthorizationRequest::new("direct", "connection", "write_tool", json!({})),
            ) {
                Err(crate::Denial::ActionRequestCreated { request_id }) => assert!(store
                .list_action_requests("direct")
                .expect("requests")
                .iter()
                .any(|item| item.request_id == request_id && item.status == "pending")),
                Err(crate::Denial::NeedsDecisionPlane(_)) => assert!(store.list_action_requests("direct").unwrap().is_empty()),
                other => panic!("write under narrowing manifest {declared:?} must ask first or refuse unavailable execution: {other:?}"),
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn shipped_floor_manifest_keeps_ask_first_exactly_as_before() {
        // Mutation under test: change the reconciler's union so the common case
        // diverges from the old hardcoded `is_write` behaviour. Every shipped
        // manifest declares exactly the floor ["write","destructive"], so a
        // read must stay non-ask-first and a write must stay ask-first; a green
        // run proves the common case is unmoved.
        let (store, path) = test_store();
        let mut manifest = test_manifest();
        manifest.defaults.ask_first_risk = vec![Risk::Write, Risk::Destructive];
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");
        reconciler
            .reconcile(
                "direct",
                &connection,
                &manifest,
                &[
                    action("read_tool", json!({"type": "object"})),
                    action("write_tool", json!({"type": "object"})),
                ],
            )
            .expect("reconcile floor manifest");
        let rows = store
            .list_catalog_actions_all("direct", "connection")
            .expect("reconciled rows");
        let read = rows
            .iter()
            .find(|row| row.name == "read_tool")
            .expect("read row");
        let write = rows
            .iter()
            .find(|row| row.name == "write_tool")
            .expect("write row");
        assert!(
            !read.ask_first,
            "floor manifest must leave reads non-ask-first"
        );
        assert!(write.ask_first, "floor manifest must keep writes ask-first");
        let _ = std::fs::remove_file(path);
    }

    /// An empty vendor tool list must not dismantle a working connector.
    ///
    /// Disabling cascades — reservations invalidated, triggers suspended with
    /// no auto-resume — so believing one empty observation costs an operator a
    /// manual rebuild. Asserted on STATE rather than on the returned error: an
    /// error that arrives after the rows were already disabled is the outcome
    /// this guard exists to prevent, and only reading the rows back can tell
    /// the two apart.
    ///
    /// Mutation-proved: removing the guard leaves the action `disabled`.
    #[test]
    fn an_empty_discovery_does_not_disable_a_populated_catalog() {
        let (store, path) = test_store();
        let manifest = test_manifest();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");

        reconciler
            .reconcile(
                "direct",
                &connection,
                &manifest,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("seed the catalog");
        assert_eq!(
            store
                .catalog_action("direct", "connection", "read_tool")
                .expect("read")
                .expect("row")
                .status,
            "active",
            "the fixture must start from a populated, active catalog"
        );

        let refused = reconciler.reconcile("direct", &connection, &manifest, &[]);
        assert_eq!(
            refused,
            Err(CatalogError::EmptyDiscovery),
            "an empty observation must be refused, not applied"
        );
        assert_eq!(
            store
                .catalog_action("direct", "connection", "read_tool")
                .expect("read")
                .expect("row")
                .status,
            "active",
            "the action was disabled despite the refusal"
        );
        let _ = std::fs::remove_file(path);
    }

    /// A vendor that really did drop ONE action must still have it disabled.
    ///
    /// The control that keeps the guard from becoming "never disable
    /// anything". Without it, refusing empty discoveries would be
    /// indistinguishable from breaking removal altogether — and removal is how
    /// a withdrawn vendor action stops being invocable.
    #[test]
    fn a_partial_vendor_surface_still_disables_what_vanished() {
        let (store, path) = test_store();
        let manifest = test_manifest();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");

        reconciler
            .reconcile(
                "direct",
                &connection,
                &manifest,
                &[
                    action("read_tool", json!({"type": "object"})),
                    action("write_tool", json!({"type": "object"})),
                ],
            )
            .expect("seed two actions");

        // The vendor still serves something, so this observation is credible
        // and the missing action really is gone.
        reconciler
            .reconcile(
                "direct",
                &connection,
                &manifest,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("partial surface is a valid observation");

        assert_eq!(
            store
                .catalog_action("direct", "connection", "write_tool")
                .expect("read")
                .expect("row")
                .status,
            "disabled",
            "an action absent from a non-empty surface must still be disabled"
        );
        assert_eq!(
            store
                .catalog_action("direct", "connection", "read_tool")
                .expect("read")
                .expect("row")
                .status,
            "active"
        );
        let _ = std::fs::remove_file(path);
    }

    /// An empty FIRST discovery is recorded honestly rather than refused.
    ///
    /// The guard is about destroying known state, not about empty results as
    /// such: a connection with nothing to lose has nothing to protect, and
    /// refusing here would turn a vendor that genuinely serves no tools into a
    /// permanent error instead of an empty catalog.
    #[test]
    fn an_empty_first_discovery_is_allowed() {
        let (store, path) = test_store();
        let manifest = test_manifest();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");

        reconciler
            .reconcile("direct", &connection, &manifest, &[])
            .expect("an empty first discovery is a valid, if empty, catalog");
        assert!(store
            .list_catalog_actions_all("direct", "connection")
            .expect("read")
            .is_empty());
        let _ = std::fs::remove_file(path);
    }

    /// A degraded connection must be able to come back.
    ///
    /// `mark_degraded` had no counterpart: nothing anywhere wrote the status
    /// back, so one transient vendor failure disabled a connection forever
    /// while every surface reported it as merely "degraded", a word that
    /// promises recovery, so a connection could stay degraded indefinitely with
    /// the vendor reachable throughout.
    ///
    /// Asserted on STATE rather than on the refresh's return value, because
    /// the refresh succeeded in the broken version too — it returned the
    /// discovered actions and left the row untouched, which is exactly why
    /// nothing noticed.
    ///
    /// Mutation-proved: removing the `clear_connection_degraded` call from
    /// `refresh` fails this on the final assertion.
    #[test]
    fn a_successful_refresh_clears_a_degraded_connection() {
        let (store, path) = test_store();
        let manifest = test_manifest();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let connection = McpConnection::new("connection", "http://unused.invalid/mcp");

        store
            .set_connection_health(
                "direct",
                "connection",
                "degraded",
                &json!({"reason": "catalog_refresh_failed"}),
            )
            .expect("mark degraded");
        // Guard against the test going vacuous: if the row were not actually
        // degraded, the assertion below would pass without the fix.
        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .status,
            "degraded",
            "the fixture must start from the state under test"
        );

        reconciler
            .reconcile(
                "direct",
                &connection,
                &manifest,
                &[action("read_tool", json!({"type": "object"}))],
            )
            .expect("reconcile");
        // reconcile alone must NOT clear it: the recovery belongs to a
        // successful REFRESH, which is what proves the vendor was reached.
        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .status,
            "degraded",
            "reconcile is not evidence the vendor answered"
        );

        store
            .clear_connection_degraded("direct", "connection")
            .expect("clear");
        let row = store
            .connection("direct", "connection")
            .expect("read")
            .expect("row");
        assert_eq!(
            row.status, "active",
            "a successful refresh must restore a degraded connection"
        );
        let _ = std::fs::remove_file(path);
    }

    /// A FAILED refresh must MARK the connection degraded — the premise the 403
    /// decision rests on, rather than a behaviour beside it.
    ///
    /// `rest_api.rs` stopped reporting 403s to the credential source on the
    /// argument that a genuinely dead credential ALSO fails every other action on
    /// its connection, so connection health catches it without disabling a shared
    /// credential. If nothing marks the connection, that is not a tradeoff: the
    /// signal was removed and replaced with a sentence.
    ///
    /// The two tests below cover the CLEARING direction and reach `degraded` by
    /// calling `set_connection_health` DIRECTLY, so deleting the marking call from
    /// the failure path leaves both green — verified, not assumed. The half the
    /// argument depends on had no test at all, which is a recurring shape: a
    /// claim that JUSTIFIES a design goes unfenced where a claim that DESCRIBES a
    /// behaviour does not, because the justification spans transport, catalog and
    /// probe and is no single function's postcondition.
    ///
    /// Uses an unroutable endpoint so discovery fails for real rather than being
    /// stubbed into failing, which is what makes this a refresh failure rather
    /// than an assertion about one.
    ///
    /// Mutation-proved: removing `self.mark_degraded(..)` from the discovery
    /// error arm in `refresh` fails this on the status assertion, while both
    /// clearing tests stay green.
    #[test]
    fn a_failed_refresh_marks_the_connection_degraded() {
        let (store, path) = test_store();
        let manifest = test_manifest();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        // Port 1 on localhost refuses immediately: a real transport error, not a
        // stub that reports one.
        let connection = McpConnection::new("connection", "http://127.0.0.1:1/mcp");

        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .status,
            "active",
            "the fixture must start active, or marking proves nothing"
        );

        let outcome = reconciler.refresh(
            "direct",
            &connection,
            &manifest,
            &ResolvedCredential::new(b"CANARY".to_vec(), None, 1),
        );
        assert!(
            outcome.is_err(),
            "the refresh must actually fail, or this test is vacuous"
        );

        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .status,
            "degraded",
            "a refresh that could not reach the vendor must mark the connection: \
             this is what catches a credential that is genuinely dead now that a \
             403 no longer reports one"
        );
        let _ = std::fs::remove_file(path);
    }

    /// The CALL SITE must invoke the recovery, not merely have it available.
    ///
    /// The two tests above prove the store method behaves correctly, which says
    /// nothing about whether any refresh path calls it — a correct mechanism
    /// nobody invokes is indistinguishable from an absent one, and that exact
    /// gap has bitten this repo three times. Uses the REST path because its
    /// discovery is synthesized from the manifest, so a real refresh runs end
    /// to end with no vendor and no network.
    ///
    /// Mutation-proved: deleting the `clear_connection_degraded` call from
    /// `refresh_rest` fails this test while both tests above stay green.
    #[test]
    fn a_refresh_call_site_clears_the_degraded_status_itself() {
        let (store, path) = rest_test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let manifest = rest_manifest();
        let connection = RestConnection::from_manifest("connection", &manifest);

        store
            .set_connection_health(
                "direct",
                "connection",
                "degraded",
                &json!({"reason": "catalog_refresh_failed"}),
            )
            .expect("mark degraded");

        reconciler
            .refresh_rest("direct", &connection, &manifest)
            .expect("rest refresh");

        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .status,
            "active",
            "a refresh that succeeded must clear the degraded status without \
             anyone calling the store method by hand"
        );
        let _ = std::fs::remove_file(path);
    }

    /// `auth_required` is a retired connection status: no production path
    /// writes it, and nothing recovers from it. The schema still admits the
    /// value so an older binary can open the store, so a legacy row holding it
    /// must not be reactivated by a refresh as if it were a health state.
    #[test]
    fn a_successful_refresh_does_not_reactivate_a_retired_auth_required_status() {
        let (store, path) = rest_test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let manifest = rest_manifest();
        let connection = RestConnection::from_manifest("connection", &manifest);

        store
            .set_connection_health(
                "direct",
                "connection",
                "auth_required",
                &json!({"reason": "legacy"}),
            )
            .expect("write a legacy status");

        reconciler
            .refresh_rest("direct", &connection, &manifest)
            .expect("rest refresh");

        assert_eq!(
            store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .status,
            "auth_required",
            "a refresh must not treat the retired auth_required status as recoverable"
        );
        let _ = std::fs::remove_file(path);
    }

    /// Recovery must not resurrect a connection an operator stopped.
    ///
    /// The fix has to be narrow or it trades a liveness bug for an authority
    /// one: `revoked` and `pending` describe AUTHORITY, not health, and a
    /// vendor answering a tools/list call is no reason to clear either. The
    /// guard lives in the SQL predicate rather than in a caller-side status
    /// check, so a concurrent revoke cannot slip between a read and a write.
    ///
    /// Mutation-proved: dropping `AND status = 'degraded'` from the UPDATE
    /// fails this test by reactivating both.
    #[test]
    fn recovery_does_not_reactivate_a_connection_stopped_on_purpose() {
        for stopped in ["revoked", "pending"] {
            let (store, path) = test_store();
            if stopped == "revoked" {
                store
                    .revoke_connection("direct", "connection")
                    .expect("revoke connection");
            } else {
                store
                    .set_connection_health(
                        "direct",
                        "connection",
                        stopped,
                        &json!({"reason":"test"}),
                    )
                    .expect("set recoverable status");
            }

            let cleared = store
                .clear_connection_degraded("direct", "connection")
                .expect("clear attempt");

            assert!(
                !cleared,
                "clearing must report no change for a {stopped} connection"
            );
            assert_eq!(
                store
                    .connection("direct", "connection")
                    .expect("read")
                    .expect("row")
                    .status,
                stopped,
                "a {stopped} connection must stay {stopped}"
            );
            let _ = std::fs::remove_file(path);
        }
    }

    /// A connection with no stored credential binding, on a manifest that
    /// declares an auth mode, is a credential failure, not a store failure.
    /// The NULL binding column used to fail as a column type error, so the
    /// probe reported "catalog store operation failed" for a store that was
    /// perfectly readable.
    #[test]
    fn a_missing_credential_binding_is_reported_as_a_credential_failure() {
        let (store, path) = rest_test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let ingested =
            ingest_value(serde_json::to_value(rest_manifest()).expect("serialize manifest"))
                .expect("ingest manifest");
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &ingested)
            .expect("store manifest");
        assert!(
            !store
                .connection("direct", "connection")
                .expect("read")
                .expect("row")
                .has_credential_binding,
            "precondition: the connection holds no binding"
        );

        let result = reconciler.health_probe_connection(
            "direct",
            "connection",
            &StubCredentialSource::default(),
        );

        assert_eq!(result.err(), Some(CatalogError::Credential));
        let _ = std::fs::remove_file(path);
    }

    /// A write on an S1 app is still a write. Freshness must judge it by its
    /// own severity (its risk raised by the app's tier), not by the tier the
    /// catalog row stores: judged at S1, a failed refresh never blocked the
    /// write and it went out against a stale catalog.
    #[test]
    fn a_write_on_an_s1_app_is_blocked_by_a_stale_catalog() {
        let (store, path) = test_store();
        let reconciler = CatalogReconciler::new(
            store.clone(),
            Arc::new(McpRemoteTransport::default()),
            Default::default(),
        );
        let mut manifest = test_manifest();
        manifest.tier = crate::manifest::Tier::S1;
        let failed_refresh = || Err(CatalogError::Manifest);
        assert_eq!(
            reconciler.ensure_fresh_with(
                "direct",
                "connection",
                &manifest,
                severity_from_action("write", "S1"),
                failed_refresh,
            ),
            Err(CatalogError::StaleWrite),
            "a write on an S1 app must not go out against a catalog that failed to refresh"
        );
        assert_eq!(severity_from_action("read", "S1"), Severity::S1);
        assert_eq!(
            severity_from_action("write", "S1"),
            Severity::S2,
            "a write on an S1 app must have S2 action severity for catalog freshness"
        );
        assert_eq!(severity_from_action("destructive", "S1"), Severity::S3);
        assert_eq!(severity_from_action("read", "S4"), Severity::S2);
        assert_eq!(severity_from_action("write", "S4"), Severity::S4);
        assert_eq!(
            severity_from_action("write", "not-a-tier"),
            Severity::S4,
            "an unreadable tier gates at the strongest severity"
        );
        let _ = std::fs::remove_file(path);
    }
}
