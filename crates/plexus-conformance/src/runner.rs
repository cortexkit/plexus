//! Conformance runner: one ordered checklist, typed evidence per step.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{
    ingest_value, AppManifest, AuthorizationRequest, CatalogDenial, CatalogReconciler,
    CatalogRefreshPolicy, ConnectionDenial, CredentialSource, Denial, GovernanceEngine,
    GrantDenial, GrantInput, HttpMethod, McpRemoteTransport, PlexusStore, PolicyDenial,
    PolicyInput, ResolvedCredential, ResourceDenial, RestTransport, StubCredentialSource,
    Transport, TransportKind, TransportOutcome,
};
use serde_json::{json, Value};

use crate::evidence::{elapsed_ms, leak_scan, now_ms, ConformanceStep, RunEvidence, StepEvidence};
use crate::fixture::{ConnectorFixture, CredentialMode, TransportTarget, WritePath};
use crate::rest_stub_server::{ExpectedCredential, StubRestRoute, StubRestServer};
use crate::stub_server::StubMcpServer;

/// Options for a conformance run beyond the fixture's in-code defaults.
///
/// `RunOptions::default()` reproduces the original stub-target behavior exactly:
/// in-process stub transport, in-code stub credential, canary-handle binding.
/// The live-run fields are only populated by the CLI (or an integration test)
/// when exercising a real vendor endpoint with an operator-provisioned handle.
#[derive(Default)]
pub struct RunOptions {
    #[cfg(test)]
    before_store_operation: Option<fn(&str, &Scratch)>,
    /// Transport target override (from `--live` / `--endpoint`). `None` keeps
    /// the fixture's default target.
    pub transport_override: Option<TransportTarget>,
    /// Operator-supplied vault credential id (from `--credential-id`). When present, the
    /// runner binds THIS handle and resolves credentials through
    /// `credential_source` instead of the in-code stub. This is a vault reference,
    /// not the secret payload; never echoed or written to evidence.
    pub operator_credential_id: Option<String>,
    /// Real credential source for live/operator mode. Required whenever
    /// `operator_credential_id` is set.
    pub credential_source: Option<Arc<dyn CredentialSource>>,
    /// Where to write the vendor's observed tool schemas, if anywhere.
    ///
    /// Discovery already fetches every action's `inputSchema` and the store
    /// keeps it, but nothing ever put it in front of an operator: evidence
    /// recorded a COUNT and a hash prefix, which prove a schema existed and
    /// disclose nothing about its shape.
    ///
    /// That gap has a specific cost. Declaring a `poll` shape means naming the
    /// vendor's real request parameter and response fields, and those must come
    /// from the tool's own schema rather than from the vendor's API
    /// documentation — an MCP server may expose a narrower surface than the API
    /// it wraps. Guessing wrong fails silently: the tool ignores the unknown
    /// argument, returns an unfiltered first page every cycle, and dedupe
    /// discards it, so a misconfigured trigger is indistinguishable from a
    /// quiet period.
    pub schema_out: Option<PathBuf>,
}

/// Execute one fixture end-to-end with default (stub) options.
pub fn run_fixture(fixture: &ConnectorFixture) -> Result<RunEvidence, String> {
    run_fixture_with_options(fixture, RunOptions::default())
}

/// Execute one fixture end-to-end and return machine-readable evidence.
pub fn run_fixture_with_options(
    fixture: &ConnectorFixture,
    options: RunOptions,
) -> Result<RunEvidence, String> {
    if fixture.write_path != WritePath::None && fixture.write_action.is_none() {
        return Err("write_path requires write_action".to_string());
    }
    let mut evidence = RunEvidence::new(fixture.name.clone());
    evidence.log(format!("starting fixture {}", fixture.name));

    let live = options.operator_credential_id.is_some();

    // Parse the manifest up front: ManifestEndpoint resolves transport.url from
    // it, and the connect step needs the ingested manifest regardless.
    let manifest_source = fixture.load_manifest_source()?;
    let normalized = subc_jsonc::jsonc_to_json(&manifest_source)
        .map_err(|error| format!("normalize manifest: {error}"))?;
    let manifest_value: Value = serde_json::from_str(&normalized)
        .map_err(|error| format!("parse manifest JSON: {error}"))?;
    let ingested =
        ingest_value(manifest_value).map_err(|error| format!("ingest manifest: {error}"))?;

    let transport_target = options
        .transport_override
        .clone()
        .unwrap_or_else(|| fixture.transport_target.clone());

    // The manifest endpoint is the real vendor; reaching it with the in-code
    // stub credential is never correct, so a live target requires an operator
    // handle. This is the in-runner backstop for the CLI's --live guard.
    if matches!(transport_target, TransportTarget::ManifestEndpoint) && !live {
        return Err(format!(
            "fixture '{}' targets the live manifest endpoint but no operator handle was supplied; \
             live runs require operator credentials",
            fixture.name
        ));
    }

    let stub_server = match &transport_target {
        TransportTarget::InProcessStub => Some(StubServerHandle::Mcp(
            StubMcpServer::start(fixture.stub_tools())
                .map_err(|error| format!("start stub server: {error}"))?,
        )),
        TransportTarget::InProcessRestStub => Some(StubServerHandle::Rest(
            StubRestServer::start(
                rest_stub_routes(&ingested.manifest),
                expected_authorization(fixture, &ingested.manifest)?,
            )
            .map_err(|error| format!("start REST stub server: {error}"))?,
        )),
        TransportTarget::Endpoint(_) | TransportTarget::ManifestEndpoint => None,
    };
    let endpoint = match &transport_target {
        TransportTarget::InProcessStub => match stub_server.as_ref() {
            Some(StubServerHandle::Mcp(server)) => server.endpoint().to_string(),
            _ => return Err("stub server missing".to_string()),
        },
        TransportTarget::InProcessRestStub => match stub_server.as_ref() {
            Some(StubServerHandle::Rest(server)) => server.endpoint().to_string(),
            _ => return Err("REST stub server missing".to_string()),
        },
        TransportTarget::Endpoint(url) => url.clone(),
        TransportTarget::ManifestEndpoint => {
            // Resolve the manifest's transport URL explicitly; a live run fails
            // if the manifest provides none rather than silently dispatching to
            // an empty endpoint.
            let url = ingested.manifest.transport.url.clone();
            if url.is_empty() {
                return Err(format!(
                    "fixture '{}' manifest transport.url is empty; cannot run live",
                    fixture.name
                ));
            }
            url
        }
    };

    let (store_path, store) = open_store(&fixture.name)?;
    let store = Arc::new(store);

    // Choose the credential source and the reference that ticket redemption
    // will bind to the connection. Live mode uses the operator's reference and
    // real credential source. Fixture mode uses a stub keyed by the canary handle.
    //
    // Wrap either source to record the secret bytes it returns. The secret-safety
    // check scans for those bytes as well as the reference, because a leaked
    // payload need not contain the reference that identifies it.
    let served_source: Arc<dyn CredentialSource> = if live {
        match &options.credential_source {
            Some(source) => Arc::clone(source),
            None => return Err("live/operator mode requires a credential source".to_string()),
        }
    } else {
        let stub = Arc::new(StubCredentialSource::default());
        stub.set_success(&fixture.canary_handle, stub_payload(fixture), None, 1);
        stub
    };
    let recording = Arc::new(RecordingCredentialSource::new(served_source));
    let credentials: Arc<dyn CredentialSource> =
        Arc::clone(&recording) as Arc<dyn CredentialSource>;
    let bind_handle: &[u8] = if live {
        options
            .operator_credential_id
            .as_deref()
            .expect("live implies operator_credential_id is set")
            .as_bytes()
    } else {
        &fixture.canary_handle
    };

    let mcp_transport = Arc::new(McpRemoteTransport::default());
    let rest_transport = Arc::new(RestTransport::default());
    // Dispatch follows the transport kind reviewed in the manifest: REST
    // connections go to the REST transport, MCP connections to the MCP
    // transport. The reconciler below receives the SAME Arc<RestTransport>, so
    // the connection config registered at connect-time discovery (base URL plus
    // per-action HTTP shapes) is the one dispatch uses.
    let engine_transport: Arc<dyn Transport> =
        if matches!(ingested.manifest.transport.kind, TransportKind::RestApi) {
            Arc::clone(&rest_transport) as Arc<dyn Transport>
        } else {
            Arc::clone(&mcp_transport) as Arc<dyn Transport>
        };
    let engine = GovernanceEngine::new(
        Arc::clone(&store),
        Arc::clone(&credentials),
        Arc::clone(&engine_transport),
    );
    let reconciler = CatalogReconciler::new(
        Arc::clone(&store),
        Arc::clone(&mcp_transport),
        CatalogRefreshPolicy::default(),
    )
    .with_rest_transport(Arc::clone(&rest_transport));

    let app_key = ingested.manifest.key.clone();
    store
        .upsert_manifest("system", &ingested)
        .map_err(|error| format!("store manifest: {error}"))?;

    let principal = fixture.principal.as_str();
    let connection_id = format!("conn-{}", fixture.name);

    // --- 1. connect ---
    let step_started = now_ms();
    let connect_result = (|| -> Result<(Vec<i64>, String), String> {
        store
            .insert_connection(
                principal,
                &connection_id,
                &app_key,
                "pending",
                &fixture.resource_filters,
            )
            .map_err(|error| format!("insert connection: {error}"))?;
        let ticket = store
            .create_binding_ticket(principal, &connection_id, bind_handle)
            .map_err(|error| format!("create binding ticket: {error}"))?;
        let summary = store
            .connect_with_ticket(principal, &ticket.ticket_id)
            .map_err(|error| format!("connect with ticket: {error}"))?
            .ok_or_else(|| "binding ticket did not activate connection".to_string())?;
        if summary.status != "active" {
            return Err(format!("connection status is {}", summary.status));
        }
        #[cfg(test)]
        if let Some(hook) = options.before_store_operation {
            hook("seed catalog", &store_path);
        }
        store
            .seed_catalog_from_manifest(principal, &connection_id, &app_key)
            .map_err(|error| format!("seed catalog: {error}"))?;
        let endpoint_override = if endpoint.is_empty() {
            None
        } else {
            Some(endpoint.as_str())
        };
        reconciler
            .discover_for_connection(
                principal,
                &connection_id,
                credentials.as_ref(),
                endpoint_override,
            )
            .map_err(|error| format!("connect discovery: {error}"))?;
        grant_defaults(store.as_ref(), fixture, principal, &connection_id)?;
        let audit_ids = audit_ids_since(store.as_ref(), principal, 0)?;
        Ok((
            audit_ids,
            format!(
                "connection {} active for app {app_key}",
                summary.connection_id
            ),
        ))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::Connect,
        step_started,
        connect_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 2. discover catalog ---
    let step_started = now_ms();
    let discover_result = (|| -> Result<(Vec<i64>, String), String> {
        // Fixture ↔ manifest baseline consistency (cheap drift catch).
        // Every fixture expected_action must appear in the reviewed baseline;
        // for in-process stubs the sets must match exactly. Real endpoints may
        // expose extra tools, so only baseline ⊆ discovered is required there.
        let baseline_names: Vec<String> = ingested
            .manifest
            .actions_baseline
            .iter()
            .map(|action| action.name.clone())
            .collect();
        for expected in &fixture.expected_actions {
            if !baseline_names.iter().any(|name| name == expected) {
                return Err(format!(
                    "fixture expected_action '{expected}' missing from manifest actions_baseline; baseline={baseline_names:?}"
                ));
            }
        }
        let is_stub_target = matches!(
            fixture.transport_target,
            TransportTarget::InProcessStub | TransportTarget::InProcessRestStub
        );
        if is_stub_target {
            for baseline in &baseline_names {
                if !fixture.expected_actions.iter().any(|name| name == baseline) {
                    return Err(format!(
                        "manifest actions_baseline '{baseline}' missing from fixture expected_actions (stub target requires exact match); expected={:?}",
                        fixture.expected_actions
                    ));
                }
            }
        }

        let actions = store
            .list_catalog_actions(principal, &connection_id)
            .map_err(|error| format!("list catalog: {error}"))?;
        let names: Vec<_> = actions.iter().map(|action| action.name.clone()).collect();
        for expected in &fixture.expected_actions {
            if !names.iter().any(|name| name == expected) {
                return Err(format!(
                    "expected action '{expected}' missing; have {names:?}"
                ));
            }
        }
        // Reviewed baseline must be a subset of what discovery returned.
        for baseline in &baseline_names {
            if !names.iter().any(|name| name == baseline) {
                return Err(format!(
                    "manifest baseline action '{baseline}' not discovered; have {names:?}"
                ));
            }
        }
        if !actions
            .iter()
            .all(|action| action.schema_hash.starts_with("sha256:"))
        {
            return Err("catalog action hashes missing sha256 prefix".to_string());
        }
        // Hand the observed schemas to the operator when asked. Written here
        // rather than into evidence because they are a WORKING ARTIFACT — the
        // input to writing a manifest poll shape — while evidence is a record
        // of what the run proved.
        let schema_note = match options.schema_out.as_ref() {
            Some(path) => {
                let document = json!({
                    "fixture": fixture.name,
                    "connection": connection_id,
                    "actions": actions
                        .iter()
                        .map(|action| json!({
                            "name": action.name,
                            "title": action.title,
                            "risk": action.risk,
                            "status": action.status,
                            "schema_hash": action.schema_hash,
                            "schema": action.schema,
                        }))
                        .collect::<Vec<_>>(),
                });
                let rendered = serde_json::to_string_pretty(&document)
                    .map_err(|error| format!("serialize schemas: {error}"))?;
                // Owner-only like evidence and the wire trace: a tool schema is
                // not secret, but it names a vendor surface this host can reach.
                crate::open_owner_only(path)
                    .and_then(|mut file| {
                        use std::io::Write;
                        file.write_all(rendered.as_bytes())
                    })
                    .map_err(|error| format!("write schemas to {}: {error}", path.display()))?;
                format!("; schemas written to {}", path.display())
            }
            None => String::new(),
        };
        Ok((
            Vec::new(),
            format!(
                "{} actions present with schema hashes (baseline consistent){schema_note}",
                actions.len()
            ),
        ))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::DiscoverCatalog,
        step_started,
        discover_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 3. allowed read ---
    let step_started = now_ms();
    let mut allowed_read_request_id = None;
    let read_result = (|| -> Result<(Vec<i64>, String), String> {
        let before = latest_audit_id(store.as_ref(), principal)?;
        let request = AuthorizationRequest::new(
            principal,
            &connection_id,
            &fixture.read_action,
            fixture.read_args.clone(),
        );
        let request_id = request.request_id.clone();
        let reservation = engine
            .authorize(request)
            .map_err(|denial| format!("read authorize denied: {}", denial.reason_code()))?;
        allowed_read_request_id = Some(request_id);
        let outcome = engine.revalidate_and_dispatch(&reservation);
        match outcome.outcome {
            TransportOutcome::Completed { .. } => {}
            other => return Err(format!("read dispatch outcome: {other:?}")),
        }
        let ids = audit_ids_since(store.as_ref(), principal, before)?;
        Ok((
            ids,
            format!("read action {} completed", fixture.read_action),
        ))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::AllowedRead,
        step_started,
        read_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 4. write path: ask-first (S2) or s3_escalation (floor-S3) or SKIP ---
    let step_started = now_ms();
    match fixture.write_path {
        WritePath::None => {
            push_step_maybe_skip(
                &mut evidence,
                ConformanceStep::AskFirstWrite,
                step_started,
                Ok((Vec::new(), "fixture has no write action".to_string())),
                Some("no write action in fixture"),
            );
        }
        WritePath::AskFirst => {
            let write_action = fixture
                .write_action
                .as_deref()
                .ok_or_else(|| "write_path=AskFirst requires write_action".to_string())?;
            let write_result = (|| -> Result<(Vec<i64>, String), String> {
                let before = latest_audit_id(store.as_ref(), principal)?;
                // Ensure ask_first policy for the write action. `set_policy`
                // replaces the scope's policy; a second row for one scope is
                // refused by the schema.
                store
                    .set_policy(principal, &connection_id, write_action, "ask_first", None)
                    .map_err(|error| format!("ask_first policy for {write_action}: {error}"))?;
                let denial = engine
                    .authorize(AuthorizationRequest::new(
                        principal,
                        &connection_id,
                        write_action,
                        fixture.write_args.clone(),
                    ))
                    .err()
                    .ok_or_else(|| "write was expected to create an action_request".to_string())?;
                let request_id = match denial {
                    Denial::ActionRequestCreated { request_id } => request_id,
                    other => {
                        return Err(format!(
                            "expected action_request_created, got {}",
                            other.reason_code()
                        ))
                    }
                };

                let outcome = engine
                    .approve_request(principal, &request_id, principal)
                    .map_err(|denial| format!("approve failed: {}", denial.reason_code()))?;
                match outcome.outcome {
                    TransportOutcome::Completed { .. } => {}
                    other => return Err(format!("approved write dispatch: {other:?}")),
                }

                // Dispatch consumed the approval: it authorizes one send. Presenting it
                // again for the identical call must be refused by name, not re-sent.
                let retry = AuthorizationRequest::new(
                    principal,
                    &connection_id,
                    write_action,
                    fixture.write_args.clone(),
                )
                .approved_from(&request_id);
                match engine.authorize(retry) {
                    Err(Denial::Policy(PolicyDenial::ApprovalConsumed)) => {}
                    Err(other) => {
                        return Err(format!(
                            "identical retry expected approval_consumed, got {}",
                            other.reason_code()
                        ))
                    }
                    Ok(_) => return Err("a consumed approval must not reserve".to_string()),
                }

                // This request changes its arguments from the saved snapshot, so the
                // approval never covered it: authorization must reject it through the
                // argument-hash check, which answers before the consumed state does.
                // approve_request cannot create this shape directly. The change is
                // to the VALUE of one of the fixture's own arguments, so every key
                // is still one the action's schema declares and the refusal can
                // only come from the snapshot comparison.
                let mut mutated_args = fixture.write_args.clone();
                let changed = mutated_args.as_object_mut().and_then(|fields| {
                    let key = fields
                        .iter()
                        .filter(|(_, value)| value.is_string())
                        .map(|(key, _)| key.clone())
                        .min()?;
                    fields.insert(key, json!("mutated-args"));
                    Some(())
                });
                if changed.is_none() {
                    return Err("write_args has no string argument to mutate".to_string());
                }
                let mutated = AuthorizationRequest::new(
                    principal,
                    &connection_id,
                    write_action,
                    mutated_args,
                )
                .approved_from(&request_id);
                match engine.authorize(mutated) {
                    Err(Denial::Policy(PolicyDenial::ApprovalShapeMismatch)) => {}
                    Err(other) => {
                        return Err(format!(
                            "mutated-args expected approval_shape_mismatch, got {}",
                            other.reason_code()
                        ))
                    }
                    Ok(_) => return Err("mutated-args approval must not reserve".to_string()),
                }

                let ids = audit_ids_since(store.as_ref(), principal, before)?;
                Ok((
                    ids,
                    format!(
                        "ask-first write {write_action} approved and executed once; identical retry refused (approval consumed); mutated arguments refused (hash-pinned)"
                    ),
                ))
            })();
            push_step(
                &mut evidence,
                ConformanceStep::AskFirstWrite,
                step_started,
                write_result,
            );
        }
        WritePath::S3Escalation => {
            let write_action = fixture
                .write_action
                .as_deref()
                .ok_or_else(|| "write_path=S3Escalation requires write_action".to_string())?;
            let s3_result = (|| -> Result<(Vec<i64>, String), String> {
                let before = latest_audit_id(store.as_ref(), principal)?;
                // Allow policy so the severity gate (not ask-first) is reached.
                store
                    .set_policy(principal, &connection_id, write_action, "allow", None)
                    .map_err(|error| format!("allow policy for {write_action}: {error}"))?;
                let denial = engine
                    .authorize(AuthorizationRequest::new(
                        principal,
                        &connection_id,
                        write_action,
                        fixture.write_args.clone(),
                    ))
                    .err()
                    .ok_or_else(|| {
                        "S3 write was expected to yield NeedsDecisionPlane".to_string()
                    })?;
                let envelope = match denial {
                    Denial::NeedsDecisionPlane(envelope) => envelope,
                    other => {
                        return Err(format!(
                            "expected needs_decision_plane, got {}",
                            other.reason_code()
                        ))
                    }
                };
                if envelope.severity != plexus_core::Severity::S3 {
                    return Err(format!(
                        "envelope severity must be S3, got {}",
                        envelope.severity.as_str()
                    ));
                }
                if !envelope.args_hash.starts_with("sha256:") || envelope.args_hash.len() < 20 {
                    return Err(format!(
                        "envelope args_hash missing/empty: {}",
                        envelope.args_hash
                    ));
                }
                verify_envelope_args_hash(&fixture.write_args, &envelope.args_hash)?;
                if !envelope.schema_hash.starts_with("sha256:") {
                    return Err(format!(
                        "envelope schema_hash missing sha256 prefix: {}",
                        envelope.schema_hash
                    ));
                }
                if envelope.connection_id.is_empty() {
                    return Err("envelope connection_id empty".to_string());
                }
                if envelope.connection_id != connection_id {
                    return Err(format!(
                        "envelope connection_id {} != fixture {connection_id}",
                        envelope.connection_id
                    ));
                }
                if envelope.action != write_action {
                    return Err(format!(
                        "envelope action {} != {write_action}",
                        envelope.action
                    ));
                }
                // Connection identity is the stable connection_id (fingerprint-grade
                // redaction lives on audit sinks; the envelope carries the id).
                let ids = audit_ids_since(store.as_ref(), principal, before)?;
                let rows = store
                    .list_audit(principal)
                    .map_err(|error| format!("list audit for s3 step: {error}"))?;
                let has_decision_plane = rows.iter().any(|row| {
                    row.journal_id > before && row.reason_code == "needs_decision_plane"
                });
                if !has_decision_plane {
                    return Err(
                        "missing audit row reason_code=needs_decision_plane after S3 escalate"
                            .to_string(),
                    );
                }
                Ok((
                    ids,
                    format!(
                        "s3_escalation {write_action}: NeedsDecisionPlane severity=S3 args_hash pinned connection={}",
                        envelope.connection_id
                    ),
                ))
            })();
            push_step(
                &mut evidence,
                ConformanceStep::S3Escalation,
                step_started,
                s3_result,
            );
        }
    }
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 5. denied calls ---
    let step_started = now_ms();
    let denied_result = (|| -> Result<(Vec<i64>, String), String> {
        let before = latest_audit_id(store.as_ref(), principal)?;
        // Ungranted principal.
        let ungranted_request = AuthorizationRequest::new(
            "ungranted-principal",
            &connection_id,
            &fixture.read_action,
            fixture.read_args.clone(),
        );
        let ungranted_request_id = ungranted_request.request_id.clone();
        let ungranted_denial = engine
            .authorize(ungranted_request)
            .err()
            .ok_or_else(|| "ungranted principal must be denied".to_string())?;
        match &ungranted_denial {
            Denial::Connection(ConnectionDenial::NotFound)
            | Denial::Grant(GrantDenial::Missing) => {}
            other => {
                return Err(format!(
                    "ungranted principal unexpected denial {}",
                    other.reason_code()
                ))
            }
        }
        verify_denial_audit(
            store.as_ref(),
            &[principal, "ungranted-principal"],
            &ungranted_request_id,
            &ungranted_denial,
        )?;

        // Disallowed resource via filters. Floor-S3 writes hit the severity gate
        // before the resource gate, so skip the probe for S3Escalation fixtures.
        let resource_probe = fixture
            .resource_filter_action
            .as_ref()
            .or(fixture.write_action.as_ref())
            .filter(|_| fixture.write_path != WritePath::S3Escalation)
            .filter(|_| {
                !fixture
                    .denied_resource_args
                    .as_object()
                    .map(|object| object.is_empty())
                    .unwrap_or(true)
            });
        if let Some(probe_action) = resource_probe {
            // Allow policy so we reach the resource gate (and pass ask-first).
            // `set_policy` replaces the scope's policy; a second row for one
            // scope is refused by the schema.
            store
                .set_policy(principal, &connection_id, probe_action, "allow", None)
                .map_err(|error| format!("allow policy for {probe_action}: {error}"))?;
            let resource_request = AuthorizationRequest::new(
                principal,
                &connection_id,
                probe_action,
                fixture.denied_resource_args.clone(),
            );
            let resource_request_id = resource_request.request_id.clone();
            let resource_denial = engine
                .authorize(resource_request)
                .err()
                .ok_or_else(|| "disallowed resource must be denied".to_string())?;
            match &resource_denial {
                Denial::ResourceFilter(
                    ResourceDenial::ValueNotAllowed(_) | ResourceDenial::MissingRequiredFilter(_),
                ) => {}
                other => {
                    return Err(format!(
                        "disallowed resource unexpected denial {}",
                        other.reason_code()
                    ))
                }
            }
            verify_denial_audit(
                store.as_ref(),
                &[principal],
                &resource_request_id,
                &resource_denial,
            )?;
        }

        // Quarantined action.
        let quarantine_target = fixture
            .expected_actions
            .iter()
            .find(|name| *name != &fixture.read_action)
            .cloned()
            .unwrap_or_else(|| fixture.read_action.clone());
        // Ensure the target exists and is granted for the quarantine check.
        if quarantine_target != fixture.read_action {
            #[cfg(test)]
            if let Some(hook) = options.before_store_operation {
                hook("grant quarantine action", &store_path);
            }
            store
                .insert_grant(&GrantInput {
                    grant_id: format!("grant-quarantine-{quarantine_target}"),
                    principal: principal.to_string(),
                    connection_id: connection_id.clone(),
                    grantee_principal: principal.to_string(),
                    risk_ceiling: "write".to_string(),
                    action_selectors: vec![quarantine_target.clone()],
                    authority_kind: "invoke".to_string(),
                    expires_at: None,
                })
                .map_err(|error| format!("grant quarantine action: {error}"))?;
            // The seeded catalog policies already cover this scope, so the
            // policy is replaced rather than inserted a second time.
            store
                .set_policy(principal, &connection_id, &quarantine_target, "allow", None)
                .map_err(|error| format!("allow policy for {quarantine_target}: {error}"))?;
        }
        store
            .quarantine_action(
                principal,
                &connection_id,
                &quarantine_target,
                "conformance_quarantine",
            )
            .map_err(|error| format!("quarantine action: {error}"))?;
        let quarantine_args = if fixture.write_action.as_deref() == Some(quarantine_target.as_str())
        {
            fixture.write_args.clone()
        } else {
            fixture.read_args.clone()
        };
        let quarantine_request = AuthorizationRequest::new(
            principal,
            &connection_id,
            &quarantine_target,
            quarantine_args,
        );
        let quarantine_request_id = quarantine_request.request_id.clone();
        let quarantine_denial = engine
            .authorize(quarantine_request)
            .err()
            .ok_or_else(|| "quarantined action must be denied".to_string())?;
        match &quarantine_denial {
            Denial::Catalog(CatalogDenial::Quarantined) => {}
            other => {
                return Err(format!(
                    "quarantined action unexpected denial {}",
                    other.reason_code()
                ))
            }
        }
        verify_denial_audit(
            store.as_ref(),
            &[principal],
            &quarantine_request_id,
            &quarantine_denial,
        )?;

        let ids = audit_ids_since(store.as_ref(), principal, before)?;
        Ok((
            ids,
            "ungranted / resource / quarantine denials recorded".to_string(),
        ))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::DeniedCalls,
        step_started,
        denied_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 6. stale-authorization abort ---
    let step_started = now_ms();
    let stale_result = (|| -> Result<(Vec<i64>, String), String> {
        let before = latest_audit_id(store.as_ref(), principal)?;
        // Use the read action: re-activate it if it was quarantined above.
        let action = fixture.read_action.clone();
        // Re-seed / refresh the read action to active for this step.
        let actions = store
            .list_catalog_actions_all(principal, &connection_id)
            .map_err(|error| format!("list all catalog: {error}"))?;
        let read_row = actions
            .iter()
            .find(|row| row.name == action)
            .ok_or_else(|| "read action missing for stale step".to_string())?;
        if read_row.status != "active" {
            #[cfg(test)]
            if let Some(hook) = options.before_store_operation {
                hook("reactivate read action", &store_path);
            }
            reactivate_action(store.as_ref(), principal, &connection_id, read_row)?;
        }
        // The read action's seeded policy covers this scope; replace it.
        store
            .set_policy(principal, &connection_id, &action, "allow", None)
            .map_err(|error| format!("allow policy for {action}: {error}"))?;
        let reservation = engine
            .authorize(AuthorizationRequest::new(
                principal,
                &connection_id,
                &action,
                fixture.read_args.clone(),
            ))
            .map_err(|denial| format!("stale reserve denied: {}", denial.reason_code()))?;
        store
            .quarantine_action(
                principal,
                &connection_id,
                &action,
                "stale_between_reserve_dispatch",
            )
            .map_err(|error| format!("quarantine for stale: {error}"))?;
        let outcome = engine.revalidate_and_dispatch(&reservation);
        match outcome.outcome {
            TransportOutcome::NotSent { ref code, .. } if code == "aborted_stale_authorization" => {
            }
            other => {
                return Err(format!(
                    "expected aborted_stale_authorization, got {other:?}"
                ))
            }
        }
        let ids = audit_ids_since(store.as_ref(), principal, before)?;
        Ok((
            ids,
            "quarantine between reserve and dispatch aborted send".to_string(),
        ))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::StaleAuthorizationAbort,
        step_started,
        stale_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 7. revoke ---
    let step_started = now_ms();
    let revoke_result = (|| -> Result<(Vec<i64>, String), String> {
        let before = latest_audit_id(store.as_ref(), principal)?;
        // Reactivate a fresh action and reserve, then revoke the connection.
        let actions = store
            .list_catalog_actions_all(principal, &connection_id)
            .map_err(|error| format!("list catalog for revoke: {error}"))?;
        let action = fixture.read_action.clone();
        if let Some(row) = actions.iter().find(|row| row.name == action) {
            #[cfg(test)]
            if let Some(hook) = options.before_store_operation {
                hook("reactivate read action", &store_path);
            }
            reactivate_action(store.as_ref(), principal, &connection_id, row)?;
        }
        let reservation = engine
            .authorize(AuthorizationRequest::new(
                principal,
                &connection_id,
                &action,
                fixture.read_args.clone(),
            ))
            .map_err(|denial| format!("pre-revoke reserve: {}", denial.reason_code()))?;
        store
            .revoke_connection(principal, &connection_id)
            .map_err(|error| format!("revoke connection: {error}"))?;
        let stale = engine.revalidate_and_dispatch(&reservation);
        match stale.outcome {
            TransportOutcome::NotSent { .. } => {}
            other => return Err(format!("revoked reservation must not send, got {other:?}")),
        }
        match engine.authorize(AuthorizationRequest::new(
            principal,
            &connection_id,
            &action,
            fixture.read_args.clone(),
        )) {
            Err(Denial::Connection(ConnectionDenial::Revoked | ConnectionDenial::NotFound)) => {}
            Err(other) => {
                return Err(format!(
                    "post-revoke unexpected denial {}",
                    other.reason_code()
                ))
            }
            Ok(_) => return Err("post-revoke invoke must be denied".to_string()),
        }
        // Credential handle is cleared / connection revoked — resolution path
        // is no longer available through an active connection.
        let ids = audit_ids_since(store.as_ref(), principal, before)?;
        Ok((
            ids,
            "revoke invalidated reservation and denied subsequent calls".to_string(),
        ))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::Revoke,
        step_started,
        revoke_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 8. audit completeness ---
    let step_started = now_ms();
    let audit_result = (|| -> Result<(Vec<i64>, String), String> {
        let rows = store
            .list_audit(principal)
            .map_err(|error| format!("list audit: {error}"))?;
        if rows.is_empty() {
            return Err("audit journal is empty".to_string());
        }
        let read_request_id = allowed_read_request_id
            .as_deref()
            .ok_or_else(|| "allowed read request_id was not captured".to_string())?;
        let read_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.request_id.as_deref() == Some(read_request_id))
            .collect();
        if read_rows.len() != 2 {
            return Err(format!(
                "allowed read request {read_request_id} expected exactly 2 audit rows, found {}",
                read_rows.len()
            ));
        }
        let authorization = read_rows
            .iter()
            .find(|row| row.gate.as_deref() == Some("credential") && row.outcome.is_none())
            .ok_or_else(|| "allowed read missing authorization decision row".to_string())?;
        if authorization.decision != "allow" {
            return Err(format!(
                "allowed read authorization decision was {}",
                authorization.decision
            ));
        }
        let credential_fingerprint = authorization
            .credential_fingerprint
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "allowed read authorization missing credential fingerprint".to_string()
            })?;
        let dispatch = read_rows
            .iter()
            .find(|row| row.gate.as_deref() == Some("dispatch"))
            .ok_or_else(|| "allowed read missing dispatch audit row".to_string())?;
        if dispatch.outcome.as_deref() != Some("completed") {
            return Err(format!(
                "allowed read dispatch outcome was {:?}",
                dispatch.outcome
            ));
        }
        if dispatch.credential_fingerprint.as_deref() != Some(credential_fingerprint) {
            return Err("allowed read audit rows disagree on credential fingerprint".to_string());
        }
        if authorization.action != dispatch.action
            || authorization.action.as_deref() != Some(fixture.read_action.as_str())
        {
            return Err("allowed read audit rows disagree on action".to_string());
        }
        if authorization.connection_id != dispatch.connection_id
            || authorization.connection_id.as_deref() != Some(connection_id.as_str())
        {
            return Err("allowed read audit rows disagree on connection".to_string());
        }
        if !rows
            .iter()
            .any(|row| row.reason_code == "aborted_stale_authorization")
        {
            return Err("missing audit reason_code aborted_stale_authorization".to_string());
        }
        // Write path correlation when the fixture exercised ask-first or S3 escalate.
        match fixture.write_path {
            WritePath::AskFirst => {
                let has_request = rows.iter().any(|row| {
                    row.reason_code == "action_request_created" || row.decision.contains("ask")
                });
                if !has_request {
                    return Err("write path missing action_request audit linkage".to_string());
                }
            }
            WritePath::S3Escalation => {
                if !rows
                    .iter()
                    .any(|row| row.reason_code == "needs_decision_plane")
                {
                    return Err(
                        "S3 write path missing needs_decision_plane audit linkage".to_string()
                    );
                }
            }
            WritePath::None => {}
        }
        for row in &rows {
            evidence.audit_dump.push(
                serde_json::to_value(row)
                    .map_err(|error| format!("serialize audit row: {error}"))?,
            );
        }
        let ids = rows.iter().map(|row| row.journal_id).collect();
        Ok((ids, format!("{} audit rows verified", rows.len())))
    })();
    push_step(
        &mut evidence,
        ConformanceStep::AuditCompleteness,
        step_started,
        audit_result,
    );
    if !evidence.steps.last().map(|s| s.passed).unwrap_or(false) {
        return finalize(evidence, store_path, stub_server);
    }

    // --- 9. secret safety ---
    let step_started = now_ms();
    let secret_result = (|| -> Result<(Vec<i64>, String), String> {
        let evidence_json = serde_json::to_string(&evidence.steps)
            .map_err(|error| format!("serialize steps: {error}"))?;
        let audit_json = serde_json::to_string(&evidence.audit_dump)
            .map_err(|error| format!("serialize audit dump: {error}"))?;
        let log_text = evidence.harness_log.join("\n");
        let rendered_transport =
            if matches!(ingested.manifest.transport.kind, TransportKind::RestApi) {
                format!("{rest_transport:?}")
            } else {
                format!("{mcp_transport:?}")
            };

        let needles = secret_needles(
            fixture,
            options.operator_credential_id.as_deref(),
            &recording.served_payloads(),
        );
        let needle_refs: Vec<&str> = needles.iter().map(|needle| needle.as_str()).collect();
        leak_scan(&[&evidence_json, &audit_json, &log_text], &needle_refs)
            .map_err(|hits| hits.join("; "))?;
        // Debug projections of the transport must omit them too
        // (Authorization headers are the only permitted sink and are not part
        // of Debug).
        if needles
            .iter()
            .any(|needle| !needle.is_empty() && rendered_transport.contains(needle.as_str()))
        {
            return Err("credential material present in transport debug projection".to_string());
        }
        let served = recording.served_count();
        if live {
            // The in-code canary sub-run does not apply here (a real
            // credential is the bound reference), so we do not claim it ran.
            Ok((
                Vec::new(),
                format!(
                    "live mode: leak-scan clean for the operator reference and the \
                     {served} payload(s) the vault served (canary sub-run not applicable)"
                ),
            ))
        } else {
            Ok((
                Vec::new(),
                format!(
                    "leak-scan clean; canary handle and the {served} payload(s) served \
                     absent from evidence and debug sinks"
                ),
            ))
        }
    })();
    push_step(
        &mut evidence,
        ConformanceStep::SecretSafety,
        step_started,
        secret_result,
    );

    finalize(evidence, store_path, stub_server)
}

fn verify_envelope_args_hash(args: &Value, actual: &str) -> Result<(), String> {
    verify_envelope_args_hash_with(args, actual, plexus_core::jcs_sha256)
}

fn verify_envelope_args_hash_with<E>(
    args: &Value,
    actual: &str,
    hash: impl FnOnce(&Value) -> Result<String, E>,
) -> Result<(), String>
where
    E: std::fmt::Display,
{
    let expected =
        hash(args).map_err(|error| format!("canonicalize envelope args_hash: {error}"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "envelope args_hash mismatch: got {actual} expected {expected}"
        ))
    }
}

fn grant_defaults(
    store: &PlexusStore,
    fixture: &ConnectorFixture,
    principal: &str,
    connection_id: &str,
) -> Result<(), String> {
    let ceiling = match fixture.write_path {
        WritePath::None => "read",
        WritePath::AskFirst | WritePath::S3Escalation => "write",
    };
    store
        .insert_grant(&GrantInput {
            grant_id: format!("grant-{}", fixture.name),
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            grantee_principal: principal.to_string(),
            risk_ceiling: ceiling.to_string(),
            action_selectors: fixture.expected_actions.clone(),
            authority_kind: "invoke".to_string(),
            expires_at: None,
        })
        .map_err(|error| format!("insert grant: {error}"))?;
    store
        .insert_grant(&GrantInput {
            grant_id: format!("admin-{}", fixture.name),
            principal: principal.to_string(),
            connection_id: connection_id.to_string(),
            grantee_principal: principal.to_string(),
            risk_ceiling: ceiling.to_string(),
            action_selectors: vec!["*".to_string()],
            authority_kind: "connection_admin".to_string(),
            expires_at: None,
        })
        .map_err(|error| format!("insert admin grant: {error}"))?;
    for action in &fixture.expected_actions {
        // Write-path policies are installed by the ask-first / s3_escalation step.
        if fixture.write_action.as_deref() == Some(action.as_str())
            && matches!(
                fixture.write_path,
                WritePath::AskFirst | WritePath::S3Escalation
            )
        {
            continue;
        }
        store
            .insert_policy(&PolicyInput {
                policy_id: format!("policy-{}-{action}", fixture.name),
                principal: principal.to_string(),
                connection_id: connection_id.to_string(),
                action_selector: action.clone(),
                effect: "allow".to_string(),
                expires_at: None,
            })
            .map_err(|error| format!("insert policy: {error}"))?;
    }
    Ok(())
}

fn open_store(label: &str) -> Result<(Scratch, PlexusStore), String> {
    // Unique path + namespace so parallel fixture tests do not contend on the
    // storage writer lease (namespace is part of the lease key).
    static RUN_SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}-{}-{}-{}",
        label,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0),
        RUN_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = Scratch::database(&format!("conformance-{label}"));
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("conformance-{unique}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).map_err(|error| format!("open store: {error}"))?;
    Ok((path, store))
}

fn latest_audit_id(store: &PlexusStore, principal: &str) -> Result<i64, String> {
    let rows = store
        .list_audit(principal)
        .map_err(|error| format!("list audit: {error}"))?;
    Ok(rows.last().map(|row| row.journal_id).unwrap_or(0))
}

fn audit_ids_since(store: &PlexusStore, principal: &str, before: i64) -> Result<Vec<i64>, String> {
    let rows = store
        .list_audit(principal)
        .map_err(|error| format!("list audit: {error}"))?;
    Ok(rows
        .into_iter()
        .filter(|row| row.journal_id > before)
        .map(|row| row.journal_id)
        .collect())
}

fn verify_denial_audit(
    store: &PlexusStore,
    audit_principals: &[&str],
    request_id: &str,
    denial: &Denial,
) -> Result<(), String> {
    let mut rows = Vec::new();
    for (index, principal) in audit_principals.iter().enumerate() {
        if audit_principals[..index].contains(principal) {
            continue;
        }
        rows.extend(
            store
                .list_audit(principal)
                .map_err(|error| format!("list denial audit for {principal}: {error}"))?
                .into_iter()
                .filter(|row| row.request_id.as_deref() == Some(request_id)),
        );
    }
    if rows.len() != 1 {
        return Err(format!(
            "denied request {request_id} expected exactly 1 audit row, found {}",
            rows.len()
        ));
    }

    let expected_gate = match denial {
        Denial::Resolver(_) => "resolver",
        Denial::BotActionRequiresFacade => "catalog",
        Denial::Connection(_) => "connection",
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
    };
    let row = &rows[0];
    if row.decision != "deny" {
        return Err(format!(
            "denied request {request_id} audit decision was {}",
            row.decision
        ));
    }
    if row.gate.as_deref() != Some(expected_gate) {
        return Err(format!(
            "denied request {request_id} audit gate was {:?}, expected {expected_gate}",
            row.gate
        ));
    }
    if row.reason_code != denial.reason_code() {
        return Err(format!(
            "denied request {request_id} audit reason was {}, expected {}",
            row.reason_code,
            denial.reason_code()
        ));
    }
    Ok(())
}

fn push_step(
    evidence: &mut RunEvidence,
    step: ConformanceStep,
    started: i64,
    result: Result<(Vec<i64>, String), String>,
) {
    push_step_maybe_skip(evidence, step, started, result, None);
}

fn push_step_maybe_skip(
    evidence: &mut RunEvidence,
    step: ConformanceStep,
    started: i64,
    result: Result<(Vec<i64>, String), String>,
    skipped: Option<&str>,
) {
    let duration_ms = elapsed_ms(started);
    match result {
        Ok((audit_row_ids, detail)) => {
            evidence.log(format!("step {} pass: {detail}", step.as_str()));
            evidence.steps.push(StepEvidence {
                step,
                passed: true,
                detail,
                audit_row_ids,
                duration_ms,
                skipped: skipped.map(str::to_string),
            });
        }
        Err(detail) => {
            evidence.log(format!("step {} fail: {detail}", step.as_str()));
            evidence.steps.push(StepEvidence {
                step,
                passed: false,
                detail,
                audit_row_ids: Vec::new(),
                duration_ms,
                skipped: None,
            });
        }
    }
}

fn finalize(
    mut evidence: RunEvidence,
    // Taken by value and dropped here: the guard removes the whole scratch
    // directory, which is what takes the store's write-ahead-log pair with it.
    _store_path: Scratch,
    _stub_server: Option<StubServerHandle>,
) -> Result<RunEvidence, String> {
    evidence.finish();
    Ok(evidence)
}

/// Either in-process stub server type the runner may start, unified so the
/// handle can be held (and dropped to stop the accept loop) regardless of kind.
enum StubServerHandle {
    Mcp(StubMcpServer),
    Rest(StubRestServer),
}

/// The routes a REST stub answers for a manifest: one per declared HTTP
/// operation, each answering 200 with a deterministic body.
fn rest_stub_routes(manifest: &AppManifest) -> Vec<StubRestRoute> {
    manifest
        .actions_baseline
        .iter()
        .filter_map(|action| {
            let http = action.http.as_ref()?;
            Some(StubRestRoute::new(
                http_method_name(http.method),
                http.path.clone(),
                200,
                json!({"stub": true, "action": action.name}),
            ))
        })
        .collect()
}

fn http_method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
    }
}

/// The credential bytes the in-code stub source serves for a fixture.
fn stub_payload(fixture: &ConnectorFixture) -> Vec<u8> {
    match &fixture.credential_mode {
        CredentialMode::Stub { payload } => payload.clone(),
    }
}

/// Every value the secret-safety step must find nowhere in evidence: the bound
/// reference (the fixture canary handle, or the operator's credential id in a
/// live run), and every payload the credential
/// source actually served during the run.
///
/// The bound reference names a secret but is not its payload. Scanning only
/// references would miss a token accidentally written to the harness log.
fn secret_needles(
    fixture: &ConnectorFixture,
    operator_credential_id: Option<&str>,
    served_payloads: &[zeroize::Zeroizing<Vec<u8>>],
) -> Vec<zeroize::Zeroizing<String>> {
    let mut needles = vec![zeroize::Zeroizing::new(match operator_credential_id {
        Some(id) => id.to_string(),
        None => String::from_utf8_lossy(&fixture.canary_handle).into_owned(),
    })];
    needles.extend(
        served_payloads
            .iter()
            .map(|payload| zeroize::Zeroizing::new(String::from_utf8_lossy(payload).into_owned())),
    );
    needles.retain(|needle| !needle.is_empty());
    needles.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    needles.dedup_by(|a, b| a.as_str() == b.as_str());
    needles
}

/// A credential source that remembers the payloads it served, in memory only,
/// so the run can prove none of them reached an evidence surface.
struct RecordingCredentialSource {
    inner: Arc<dyn CredentialSource>,
    served: Mutex<Vec<zeroize::Zeroizing<Vec<u8>>>>,
}

impl RecordingCredentialSource {
    fn served_lock(&self) -> std::sync::MutexGuard<'_, Vec<zeroize::Zeroizing<Vec<u8>>>> {
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn new(inner: Arc<dyn CredentialSource>) -> Self {
        Self {
            inner,
            served: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, resolved: &ResolvedCredential) {
        let payload = resolved.payload();
        if payload.is_empty() {
            return;
        }
        let mut served = self.served_lock();
        if !served.iter().any(|seen| seen.as_slice() == payload) {
            served.push(zeroize::Zeroizing::new(payload.to_vec()));
        }
    }

    fn served_payloads(&self) -> Vec<zeroize::Zeroizing<Vec<u8>>> {
        self.served_lock()
            .iter()
            .map(|payload| zeroize::Zeroizing::new(payload.to_vec()))
            .collect()
    }

    fn served_count(&self) -> usize {
        self.served_lock().len()
    }
}

impl CredentialSource for RecordingCredentialSource {
    fn get_by_id(
        &self,
        credential_id: &str,
    ) -> Result<ResolvedCredential, plexus_core::credentials::CredentialError> {
        let resolved = self.inner.get_by_id(credential_id)?;
        self.record(&resolved);
        Ok(resolved)
    }

    fn report_id_auth_failure(&self, credential_id: &str, provider_status: u16) {
        self.inner
            .report_id_auth_failure(credential_id, provider_status);
    }
}

/// What the REST stub must demand on the wire, derived from the vendor's
/// reviewed manifest: the header its credential binding names, carrying that
/// binding's prefix followed by the fixture credential payload -- exactly what
/// the transport builds at dispatch. Taking the header NAME from the manifest
/// rather than assuming `Authorization` is what lets the stub catch a
/// transport that sends the credential under the wrong header.
///
/// `Ok(None)` only when the manifest declares no credential binding at all,
/// so there is no credential to carry. Every other case that cannot be turned
/// into a concrete header expectation is an error, because a stub started with
/// no expectation accepts every request: a binding the stub cannot check, or
/// a payload that cannot be written into a header, used to start the stub
/// with its credential gate silently disabled.
fn expected_authorization(
    fixture: &ConnectorFixture,
    manifest: &AppManifest,
) -> Result<Option<ExpectedCredential>, String> {
    if manifest.credential_bindings.is_empty() {
        return Ok(None);
    }
    let Some(binding) = manifest
        .credential_bindings
        .iter()
        .find(|binding| binding.placement.eq_ignore_ascii_case("header"))
    else {
        return Err(format!(
            "fixture '{}': the REST stub can only verify a header credential, and the manifest \
             binds none",
            fixture.name
        ));
    };
    let payload = stub_payload(fixture);
    if payload.is_empty() {
        return Err(format!(
            "fixture '{}': the manifest binds a credential header but the fixture payload is \
             empty, so the stub could not tell a sent credential from a missing one",
            fixture.name
        ));
    }
    let mut value = binding.prefix.clone().into_bytes();
    value.extend_from_slice(&payload);
    let value = String::from_utf8(value).map_err(|_| {
        format!(
            "fixture '{}': the credential payload is not valid UTF-8, so the stub cannot \
             compare it against a header value",
            fixture.name
        )
    })?;
    Ok(Some(ExpectedCredential {
        header: binding.key.clone(),
        value,
    }))
}

fn reactivate_action(
    store: &PlexusStore,
    principal: &str,
    connection_id: &str,
    row: &plexus_core::storage::CatalogAction,
) -> Result<(), String> {
    store
        .upsert_catalog_action(&plexus_core::CatalogActionInput {
            connection_id: connection_id.to_string(),
            principal: principal.to_string(),
            name: row.name.clone(),
            title: row.title.clone(),
            schema: row.schema.clone(),
            schema_hash: row.schema_hash.clone(),
            risk: row.risk.clone(),
            severity: row.severity.clone(),
            ask_first: row.ask_first,
            status: "active".to_string(),
            quarantine_reason: None,
            reconciliation: row.reconciliation.clone(),
        })
        .map_err(|error| format!("reactivate read action: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_store_errors_name_the_failing_operation() {
        fn drop_table(path: &Scratch, table: &str) {
            rusqlite::Connection::open(&**path)
                .unwrap()
                .execute(&format!("DROP TABLE {table}"), [])
                .unwrap();
        }
        fn seed(operation: &str, path: &Scratch) {
            if operation == "seed catalog" {
                drop_table(path, "catalog_actions");
            }
        }
        fn grant(operation: &str, path: &Scratch) {
            if operation == "grant quarantine action" {
                drop_table(path, "grants");
            }
        }
        fn reactivate(operation: &str, path: &Scratch) {
            if operation == "reactivate read action" {
                drop_table(path, "catalog_actions");
            }
        }
        for (hook, expected) in [
            (seed as fn(&str, &Scratch), "seed catalog:"),
            (grant, "grant quarantine action:"),
            (reactivate, "reactivate read action:"),
        ] {
            let evidence = run_fixture_with_options(
                &ConnectorFixture::stub(),
                RunOptions {
                    before_store_operation: Some(hook),
                    ..RunOptions::default()
                },
            )
            .unwrap();
            assert!(!evidence.passed);
            assert!(
                evidence.steps.last().unwrap().detail.contains(expected),
                "store failure must name its failing operation {expected}: {:?}",
                evidence.steps.last()
            );
        }
    }

    #[test]
    fn poisoned_credential_recording_keeps_served_secrets() {
        let recording = RecordingCredentialSource::new(Arc::new(StubCredentialSource::default()));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut served = recording.served.lock().unwrap();
            served.push(zeroize::Zeroizing::new(b"served-secret".to_vec()));
            panic!("poison fixture");
        }));
        assert_eq!(
            recording.served_count(),
            1,
            "poisoning must not erase served secret evidence"
        );
        assert_eq!(recording.served_payloads()[0].as_slice(), b"served-secret");
    }

    #[test]
    fn incomplete_write_fixture_is_rejected_before_loading_manifest() {
        let mut fixture = ConnectorFixture::stub();
        fixture.write_action = None;
        fixture.manifest_path = PathBuf::from("/nonexistent-conformance-manifest");
        let error = run_fixture(&fixture).unwrap_err();
        assert!(
            error.contains("requires write_action"),
            "invalid fixture must be rejected before any step: {error}"
        );
    }

    #[test]
    fn conformance_runner_returns_an_error_when_argument_hashing_fails() {
        let result =
            verify_envelope_args_hash_with(&json!({"team": "core"}), "sha256:unused", |_| {
                Err::<String, _>("injected JCS failure")
            });

        assert_eq!(
            result,
            Err("canonicalize envelope args_hash: injected JCS failure".to_string())
        );
    }

    /// The secret-safety scan must look for the bytes the credential source
    /// SERVES. The stub fixtures serve their `Stub { payload }`, which is not
    /// the canary payload, so a scan for the handle and the canary alone looked
    /// for strings that never flowed through the run.
    #[test]
    fn the_secret_scan_looks_for_the_payload_actually_served() {
        const CREDENTIAL_ID: &str = "test:served-payload";
        let fixture = ConnectorFixture::stub();
        let served = stub_payload(&fixture);
        assert!(!served.is_empty());
        let recording = RecordingCredentialSource::new({
            let stub = Arc::new(StubCredentialSource::default());
            stub.set_success(CREDENTIAL_ID.as_bytes(), served.clone(), None, 1);
            stub
        });
        recording
            .get_by_id(CREDENTIAL_ID)
            .expect("the stub serves its payload");
        let needles = secret_needles(&fixture, None, &recording.served_payloads());
        let served_text = String::from_utf8(served).expect("utf-8 stub payload");
        assert!(
            needles.iter().any(|needle| needle.as_str() == served_text),
            "the served payload {served_text:?} is not scanned for: {needles:?}"
        );
        // A planted leak of the served bytes is caught by the scan itself.
        let surface = format!("harness log: sent {served_text}");
        let refs: Vec<&str> = needles.iter().map(|needle| needle.as_str()).collect();
        assert!(leak_scan(&[&surface], &refs).is_err());

        // In a live run the operator's reference is scanned for alongside the
        // payload the vault served.
        let live = secret_needles(
            &fixture,
            Some("apikey:vendor"),
            &[zeroize::Zeroizing::new(b"live-secret".to_vec())],
        );
        assert!(live.iter().any(|needle| needle.as_str() == "apikey:vendor"));
        assert!(live.iter().any(|needle| needle.as_str() == "live-secret"));
    }

    /// The REST stub's credential gate must never be silently off for a vendor
    /// that binds a credential.
    #[test]
    fn every_rest_stub_fixture_starts_its_stub_with_a_credential_gate() {
        let mut checked = 0;
        for name in ConnectorFixture::known_names() {
            let fixture = ConnectorFixture::by_name(name).expect("known fixture");
            if !matches!(fixture.transport_target, TransportTarget::InProcessRestStub) {
                continue;
            }
            let manifest = load_manifest(&fixture);
            if manifest.credential_bindings.is_empty() {
                continue;
            }
            let expected = expected_authorization(&fixture, &manifest)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(expected.is_some(), "{name}: the credential gate is off");
            checked += 1;
        }
        assert!(checked > 0, "no REST stub fixture binds a credential");
    }

    /// A payload the stub cannot compare (here, bytes that are not UTF-8)
    /// refuses to start the stub rather than starting it with no gate.
    #[test]
    fn an_uncheckable_payload_refuses_instead_of_disabling_the_gate() {
        let mut fixture = ConnectorFixture::restdemo();
        let manifest = load_manifest(&fixture);
        assert!(
            !manifest.credential_bindings.is_empty(),
            "restdemo must bind a credential for this test to mean anything"
        );
        fixture.credential_mode = CredentialMode::Stub {
            payload: vec![0xff, 0xfe],
        };
        let result = expected_authorization(&fixture, &manifest);
        assert!(
            result.is_err(),
            "an uncheckable payload disabled the credential gate: {result:?}"
        );

        fixture.credential_mode = CredentialMode::Stub {
            payload: Vec::new(),
        };
        assert!(expected_authorization(&fixture, &manifest).is_err());
    }

    fn load_manifest(fixture: &ConnectorFixture) -> AppManifest {
        let source = fixture.load_manifest_source().expect("manifest source");
        let normalized = subc_jsonc::jsonc_to_json(&source).expect("jsonc");
        let value: Value = serde_json::from_str(&normalized).expect("json");
        ingest_value(value).expect("ingest").manifest
    }

    #[test]
    fn conformance_runner_compares_against_rfc_8785_key_ordering() {
        let args = json!({"\u{E000}": 1, "\u{1F600}": 2});
        assert!(verify_envelope_args_hash(
            &args,
            "sha256:28c95d1bbb2209223307e62f489020e8f9e0cfa16adf2daf6d88127a1e8dd22a"
        )
        .is_ok());
    }
}
