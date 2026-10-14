//! Catalog drift check: does a reviewed manifest still describe the vendor?
//!
//! A manifest is a claim about a REMOTE surface at the moment it was reviewed,
//! and the vendor is under no obligation to keep it true. When a vendor renames
//! or consolidates its tools, reconcile disables every declared action it no
//! longer serves and quarantines every served tool the manifest never declared,
//! which leaves an INERT connector — correct, fail-closed, and discovered only
//! by whoever next tries to use it.
//!
//! The conformance suite cannot see this. Its fixtures declare the expected
//! action set and its in-process stub presents exactly that set, so a fixture
//! and a manifest that agree with each other stay green no matter what the
//! vendor does. That is a real property worth having — it proves the governance
//! pipeline end to end without a network — but it measures internal consistency
//! and is easy to read as vendor coverage. A vendor can drift to zero matching
//! actions (Firecrawl once did) while its fixture keeps passing.
//!
//! So this check exists to be RUN, not remembered. Its output is phrased so
//! that silence is suspicious: a manifest that could not be checked is reported
//! as UNCHECKED and never folded into a clean count, and a vendor answering
//! with an empty tool list is an error rather than a pass.

use std::path::{Path, PathBuf};

use plexus_core::manifest::{AuthMode, Risk};
use plexus_core::DiscoveredAction;
use plexus_core::{
    ingest_value, AppManifest, McpConnection, McpRemoteConfig, McpRemoteTransport,
    ResolvedCredential, TransportKind,
};
use serde_json::Value;

/// What a single manifest's check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftVerdict {
    /// Every declared action is served and every served tool is declared.
    Clean { actions: usize },
    /// The vendor's surface no longer matches the manifest.
    Drifted {
        /// Declared here, absent at the vendor. Reconcile disables these.
        missing: Vec<String>,
        /// Served by the vendor, absent here. Reconcile quarantines these.
        undeclared: Vec<String>,
    },
    /// Action names agree, but a declared poll parameter is absent from the
    /// vendor's `inputSchema`.
    ///
    /// Separate from `Drifted` because the remedy is different and so is the
    /// blast radius: a name mismatch disables or quarantines an action, which
    /// reconcile reports and an operator notices. A poll parameter the vendor
    /// ignores fails SILENTLY and in the worst available direction -- the vendor
    /// returns its default page, the strategy reads timestamps off the items and
    /// advances its watermark anyway, dedupe suppresses the repeated rows, and
    /// the feed reads as healthy while everything past the first page is never
    /// seen. It would also survive a first live call, which is what makes it
    /// worse than a shape error: the tail is the part nobody checks.
    PollShapeUnserved {
        /// Every polling action with an unserved parameter, in manifest order.
        /// All of them, not the first: a fix for one would otherwise surface
        /// the next only on the following run.
        actions: Vec<UnservedPollParameters>,
    },
    /// The check could not run. NOT a pass: kept as its own outcome so it can
    /// never be counted as clean, which is the failure mode that makes a sweep
    /// report a vendor nobody looked at as verified.
    Unchecked { reason: String },
    /// Deliberately out of scope, with the reason recorded so a future reader
    /// does not have to re-derive why a vendor is absent from the results.
    Skipped { reason: String },
}

/// One polling action whose declared request parameters the vendor's
/// `inputSchema` does not offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnservedPollParameters {
    pub action: String,
    /// Declared in the poll shape, absent from the vendor's inputSchema.
    pub unserved: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DriftReport {
    pub key: String,
    pub path: PathBuf,
    pub verdict: DriftVerdict,
    /// Advisory vendor observations, excluded from verdict and exit-code decisions.
    pub observations: Vec<String>,
}

/// Check one manifest against its live vendor endpoint.
///
/// `token` is an optional raw bearer credential. Most MCP servers answer
/// `tools/list` without one even when their tools require authentication, so
/// the anonymous attempt is tried first and is enough for a useful sweep; a
/// vendor that refuses is reported UNCHECKED rather than guessed at.
pub fn check_manifest(path: &Path, token: Option<&[u8]>) -> DriftReport {
    let key = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let mut observations = Vec::new();
    let verdict = check_manifest_inner(path, token, &mut observations);
    DriftReport {
        key,
        path: path.to_path_buf(),
        verdict,
        observations,
    }
}

fn check_manifest_inner(
    path: &Path,
    token: Option<&[u8]>,
    observations: &mut Vec<String>,
) -> DriftVerdict {
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            return DriftVerdict::Unchecked {
                reason: format!("read manifest: {error}"),
            }
        }
    };
    let manifest = match parse_manifest(&source) {
        Ok(manifest) => manifest,
        Err(reason) => return DriftVerdict::Unchecked { reason },
    };

    // A REST vendor's discovery is synthesized from the manifest itself, so its
    // declared actions are what discovery returns by construction and drift in
    // this sense cannot happen. Its endpoints can still rot, but that is a
    // different check (each declared path would have to be probed) and calling
    // it clean here would be a claim this check has not earned.
    //
    // Probing them is harder than it looks, which is why this stays SKIPPED
    // rather than becoming a REST branch. An MCP `tools/list` is a read by
    // definition, so the sweep is safe against every vendor; a REST manifest
    // declares arbitrary operations, so the equivalent probe would send a
    // request to a path that may DO something. The obvious way out (send a
    // deliberately wrong method, so the operation cannot execute, and read 404
    // as "gone") does not discriminate against api.exa.ai: GET returns 404 on
    // all three declared POST paths, exactly as it does for a nonsense path. Probing with the DECLARED method does
    // work there (401/402 on real paths, 404 on a nonsense one) but only
    // because Exa's declared actions are all reads, which is a property of that
    // manifest rather than of REST.
    if manifest.transport.kind != TransportKind::McpRemote {
        return DriftVerdict::Skipped {
            reason: format!(
                "transport is {:?}; discovery is manifest-derived, not vendor-reported",
                manifest.transport.kind
            ),
        };
    }

    let credential = match token {
        Some(bytes) => ResolvedCredential::new(bytes.to_vec(), None, 1),
        None => ResolvedCredential::anonymous(),
    };
    let config = McpRemoteConfig::new(manifest.transport.url.clone())
        .with_bindings(manifest.credential_bindings.clone());
    let connection = McpConnection {
        connection_id: format!("drift-{}", manifest.key),
        config,
    };
    let transport = McpRemoteTransport::new(connection.config.clone());

    let discovered = match transport.discover(&connection, &credential) {
        Ok(discovered) => discovered,
        Err(error) => {
            let hint = if token.is_none() && manifest.auth.mode != AuthMode::None {
                " (this vendor requires a credential for tools/list; pass --token-file)"
            } else {
                ""
            };
            return DriftVerdict::Unchecked {
                reason: format!("discovery failed: {error:?}{hint}"),
            };
        }
    };

    *observations = annotation_observations(&manifest, &discovered);

    let served: Vec<String> = discovered.iter().map(|tool| tool.name.clone()).collect();
    let declared: Vec<String> = manifest
        .actions_baseline
        .iter()
        .map(|action| action.name.clone())
        .collect();
    let anonymous = token.is_none() && manifest.auth.mode != AuthMode::None;
    let names = qualify(compare(&declared, &served), anonymous);
    // Names agreeing is a precondition, not the whole check. Only look at poll
    // parameters once the surfaces match: on a drifted manifest the schemas
    // belong to different actions, so a parameter comparison would report a
    // second finding that is really the first one wearing another name.
    if !matches!(names, DriftVerdict::Clean { .. }) {
        return names;
    }
    match compare_poll_parameters(&manifest, &discovered) {
        Some(verdict) => qualify(verdict, anonymous),
        None => names,
    }
}

fn annotation_observations(manifest: &AppManifest, discovered: &[DiscoveredAction]) -> Vec<String> {
    let mut objects = 0;
    let mut absent = 0;
    let mut read_only = 0;
    let mut not_read_only = 0;
    let mut invalid = 0;
    let mut disagreements = Vec::new();
    for tool in discovered {
        objects += usize::from(tool.annotations.is_some());
        let hint = tool
            .annotations
            .as_ref()
            .and_then(|a| a.get("readOnlyHint"));
        match hint {
            None => absent += 1,
            Some(Value::Bool(true)) => read_only += 1,
            Some(Value::Bool(false)) => {
                not_read_only += 1;
                if manifest
                    .actions_baseline
                    .iter()
                    .any(|action| action.name == tool.name && action.risk == Risk::Read)
                {
                    disagreements.push(format!(
                        "action {:?}: manifest risk=read, vendor annotations.readOnlyHint=false",
                        tool.name
                    ));
                }
            }
            // An invalid vendor value is neither absence nor a boolean assertion.
            Some(_) => invalid += 1,
        }
    }
    let mut notes = vec![format!(
        "{} tools, {objects} carried annotations objects; {} carried annotations.readOnlyHint \
         ({read_only} read-only, {not_read_only} not-read-only, {invalid} invalid); {absent} hint absent",
        discovered.len(), read_only + not_read_only + invalid
    )];
    notes.extend(disagreements);
    notes
}

/// Check every declared poll parameter against the vendor's own `inputSchema`.
///
/// A poll shape is a CLAIM ABOUT A VENDOR'S REQUEST SCHEMA, and nothing else
/// validates it: manifest ingestion checks a poll block against our model --
/// required fields per cursor kind, unknown fields refused -- and knows nothing
/// about what the vendor accepts. So a manifest could name a `since` parameter
/// the vendor ignores, ingest clean, and poll forever against its default page.
///
/// MEASURED, which is why this exists: `list_issues` accepts `since`, while
/// `list_pull_requests` accepts sort and direction but NO timestamp bound, and
/// `list_releases` accepts only pagination. All three were about to be declared
/// with the same ordered-timestamp shape on the assumption that one vendor's
/// tools resemble each other.
///
/// Only REQUEST-side fields are checked. Response field names (`items_field`,
/// `token_field`, `timestamp_field`) do not appear in an inputSchema at all, so
/// their absence there means nothing -- asserting on them would manufacture
/// findings. Response shape is caught by the poller, which refuses an item
/// missing its declared timestamp or tie-breaker rather than skipping it.
fn compare_poll_parameters(
    manifest: &AppManifest,
    discovered: &[DiscoveredAction],
) -> Option<DriftVerdict> {
    let mut findings = Vec::new();
    for action in &manifest.actions_baseline {
        // `continue`, never `?`. A `?` here would return from the whole function
        // at the first action WITHOUT a poll shape -- which in a 27-action
        // manifest is the first entry, so the loop would never reach the action
        // that actually declares one. Caught by running this against the live
        // GitHub surface with a deliberately wrong poll shape planted on
        // list_pull_requests: the check reported CLEAN. Unit tests missed it
        // because their fixtures hold exactly one action, which has a poll shape.
        let Some(poll) = action.poll.as_ref() else {
            continue;
        };
        let Some(served) = discovered.iter().find(|tool| tool.name == action.name) else {
            continue;
        };
        let properties = served
            .input_schema
            .get("properties")
            .and_then(Value::as_object);
        // A vendor that publishes no properties has told us nothing about what it
        // accepts, so absence here is not evidence of refusal.
        let Some(properties) = properties else {
            continue;
        };
        let mut declared: Vec<String> = Vec::new();
        if let Some(field) = poll.request_since_field.as_ref() {
            declared.push(field.clone());
        }
        if let Some(field) = poll.request_token_field.as_ref() {
            declared.push(field.clone());
        }
        if let Some(constants) = poll.request_constants.as_ref() {
            declared.extend(constants.keys().cloned());
        }
        let unserved: Vec<String> = declared
            .into_iter()
            .filter(|field| !properties.contains_key(field))
            .collect();
        if !unserved.is_empty() {
            findings.push(UnservedPollParameters {
                action: action.name.clone(),
                unserved,
            });
        }
    }
    if findings.is_empty() {
        None
    } else {
        Some(DriftVerdict::PollShapeUnserved { actions: findings })
    }
}

/// Downgrade a drift verdict reached WITHOUT a credential to `Unchecked`.
///
/// A disagreement observed anonymously is not conclusive, because a vendor that
/// wants a credential may serve a DIFFERENT, SMALLER surface to an anonymous
/// caller rather than refusing. Measured: huggingface.co/mcp answers a
/// credential-free `tools/list` with exactly one tool, `hf_whoami`, whose own
/// description reads "Hugging Face tools are being used anonymously and may be
/// rate limited". A plain comparison then reports ten declared tools missing
/// and one undeclared tool found, which is indistinguishable from the vendor
/// having replaced its entire surface.
///
/// The asymmetry is deliberate. AGREEMENT without a credential is still
/// agreement: the tools are there and the names match. A DISAGREEMENT has two
/// explanations and this run cannot separate them.
///
/// The COST decides the direction. A missed drift persists until the next
/// credentialed run. A false drift invites someone to "fix" a correct manifest
/// to match a logged-out view, deleting ten reviewed action declarations in
/// favour of one placeholder tool -- far more expensive, and it looks like
/// diligence while it happens. The observed difference is kept verbatim in the
/// reason so nothing is hidden from the reader.
///
/// Split out from the network path for the same reason `compare` is: so the
/// rule can be proven without a vendor.
fn qualify(verdict: DriftVerdict, anonymous: bool) -> DriftVerdict {
    if !anonymous {
        return verdict;
    }
    if let DriftVerdict::PollShapeUnserved { actions } = &verdict {
        return DriftVerdict::Unchecked {
            reason: format!("poll schema compared without a credential; re-run with --token-file to decide. Observed: {actions:?}"),
        };
    }
    let DriftVerdict::Drifted {
        missing,
        undeclared,
    } = &verdict
    else {
        return verdict;
    };
    DriftVerdict::Unchecked {
        reason: format!(
            "compared without a credential, so this difference may be an \
             anonymous-visitor surface rather than drift; re-run with \
             --token-file to decide. Observed: declared-but-not-served \
             {missing:?}, served-but-not-declared {undeclared:?}"
        ),
    }
}

#[test]
fn anonymous_poll_schema_drift_is_unchecked() {
    let verdict = DriftVerdict::PollShapeUnserved {
        actions: vec![UnservedPollParameters {
            action: "search".into(),
            unserved: vec!["since".into()],
        }],
    };
    assert!(
        matches!(
            qualify(verdict.clone(), true),
            DriftVerdict::Unchecked { .. }
        ),
        "anonymous poll drift must be inconclusive"
    );
    assert!(matches!(
        qualify(verdict, false),
        DriftVerdict::PollShapeUnserved { .. }
    ));
}

/// Diff a manifest's declared actions against a vendor's served tools.
///
/// Split out from the network path so the comparison itself is testable without
/// a vendor. BOTH directions are reported rather than just the missing one,
/// because they cause different damage and one can hide the other: a rename
/// produces a missing action AND an undeclared tool simultaneously, and seeing
/// only half of that reads as "the vendor dropped a feature" instead of "the
/// vendor renamed it and the replacement is sitting right there".
fn compare(declared: &[String], served: &[String]) -> DriftVerdict {
    // An empty vendor tool list is not a clean result, and it is not drift
    // either — it is a failed observation. A vendor serving nothing would drive
    // reconcile to disable every declared action, so calling it agreement would
    // report the most broken possible state as the healthiest one. Placed in
    // this pure function rather than at the network call so it can be proven by
    // a test; guarding it up there left it reachable only by a vendor that
    // actually answers empty, which is to say never, in practice, on purpose.
    if served.is_empty() {
        return DriftVerdict::Unchecked {
            reason: "vendor returned an empty tool list; nothing to compare".to_string(),
        };
    }

    let missing: Vec<String> = declared
        .iter()
        .filter(|name| !served.contains(name))
        .cloned()
        .collect();
    let undeclared: Vec<String> = served
        .iter()
        .filter(|name| !declared.contains(name))
        .cloned()
        .collect();

    if missing.is_empty() && undeclared.is_empty() {
        DriftVerdict::Clean {
            actions: declared.len(),
        }
    } else {
        DriftVerdict::Drifted {
            missing,
            undeclared,
        }
    }
}

fn parse_manifest(source: &str) -> Result<AppManifest, String> {
    let normalized =
        subc_jsonc::jsonc_to_json(source).map_err(|error| format!("normalize jsonc: {error}"))?;
    let value: Value =
        serde_json::from_str(&normalized).map_err(|error| format!("parse json: {error}"))?;
    ingest_value(value)
        .map(|ingested| ingested.manifest)
        .map_err(|error| format!("ingest manifest: {error}"))
}

/// Every `*.jsonc` manifest in a catalog directory, sorted for stable output.
pub fn catalog_manifests(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read catalog dir '{}': {error}", directory.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read catalog entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("jsonc") {
            paths.push(path);
        }
    }
    // An empty catalog directory means the path is wrong, not that every vendor
    // is fine — the same silence-reads-as-success trap this check exists to
    // avoid, one level up in the file system rather than the network.
    if paths.is_empty() {
        return Err(format!(
            "no .jsonc manifests found under '{}'",
            directory.display()
        ));
    }
    paths.sort();
    Ok(paths)
}

/// Render reports and return the process exit code.
///
/// Exit codes distinguish the three outcomes that call for different actions:
/// 0 every manifest that could drift was compared and none had, 1 real drift
/// found, 2 the check did not run to completion.
///
/// A PARTIAL sweep exits 2, not 0. The earlier rule was "nothing drifted and
/// something was checked", which let a run comparing three of seventeen
/// manifests exit 0 while the text above it said UNCHECKED is not a pass — the
/// printed verdict and the exit status disagreeing about the same run, with
/// the machine-readable half being the optimistic one. Anything reading the
/// status alone got a clean bill of health for a catalog that was 80%
/// unexamined.
///
/// This makes an uncredentialed sweep exit 2 by default, which is the honest
/// answer: those vendors need a credential for `tools/list`, and without one
/// the check genuinely could not run for them. Exit 2 asks for credentials;
/// exit 1 says a manifest is wrong. Different problems, different actions.
///
/// Drift still outranks incompleteness: a sweep that found real drift reports
/// 1 even if other vendors were unreachable, because the drift is actionable
/// now and the missing coverage does not make it less so.
pub fn render(reports: &[DriftReport]) -> u8 {
    let mut clean = 0usize;
    let mut drifted = 0usize;
    let mut unchecked = 0usize;
    let mut skipped = 0usize;

    for report in reports {
        match &report.verdict {
            DriftVerdict::Clean { actions } => {
                clean += 1;
                println!("  CLEAN      {} ({actions} actions)", report.key);
            }
            DriftVerdict::Drifted {
                missing,
                undeclared,
            } => {
                drifted += 1;
                println!("  DRIFTED    {}", report.key);
                if !missing.is_empty() {
                    println!("      declared but not served (would be disabled): {missing:?}");
                }
                if !undeclared.is_empty() {
                    println!(
                        "      served but not declared (would be quarantined): {undeclared:?}"
                    );
                }
            }
            DriftVerdict::PollShapeUnserved { actions } => {
                // Counted as drift because the consequence is worse, not milder:
                // a poll parameter the vendor ignores yields a feed that looks
                // healthy and is blind past its first page. Reporting it as its
                // own softer category would invite treating it as advisory.
                drifted += 1;
                println!("  DRIFTED    {} (poll shape)", report.key);
                for UnservedPollParameters { action, unserved } in actions {
                    println!(
                        "      {action} declares poll parameters the vendor does not accept: \
                         {unserved:?}"
                    );
                }
                println!(
                    "      the vendor would ignore them and return its default page, while the \
                     cursor advanced anyway"
                );
            }
            DriftVerdict::Unchecked { reason } => {
                unchecked += 1;
                println!("  UNCHECKED  {} — {reason}", report.key);
            }
            DriftVerdict::Skipped { reason } => {
                skipped += 1;
                println!("  SKIPPED    {} — {reason}", report.key);
            }
        }
        for observation in &report.observations {
            println!("      INFO observation only; not used for PASS/FAIL: {observation}");
        }
    }

    println!(
        "\n{clean} clean, {drifted} drifted, {unchecked} unchecked, {skipped} skipped \
         (of {} manifests)",
        reports.len()
    );
    if unchecked > 0 {
        println!(
            "UNCHECKED is not a pass: those vendors were not compared against anything, \
             and a manifest nobody looked at is exactly as likely to have drifted."
        );
    }

    if drifted > 0 {
        1
    } else if unchecked > 0 || clean == 0 {
        // Nothing drifted among what was examined -- but the run did not
        // examine everything it was asked to, so it has not earned a success
        // status. `clean == 0` is kept as its own term for the case where every
        // manifest was SKIPPED: skipping is a legitimate verdict (a REST
        // manifest has no vendor tool list to compare against) yet a sweep of
        // nothing but skips has still verified nothing.
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotation_disagreement_preserves_absence_and_exit_codes() {
        let mut manifest = manifest_with_poll("disagrees", "since", &[]);
        let template = manifest.actions_baseline[0].clone();
        let fixture = serde_json::json!([
            {"name": "read_only", "annotations": {"readOnlyHint": true}},
            {"name": "absent"},
            {"name": "disagrees", "annotations": {"readOnlyHint": false}},
            {"name": "write_agrees", "annotations": {"readOnlyHint": false}},
            {"name": "empty", "annotations": {}},
            {"name": "invalid", "annotations": {"readOnlyHint": null}}
        ]);
        let tools: Vec<_> = fixture
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let mut tool = served_action(value["name"].as_str().unwrap(), &[]);
                tool.annotations = value.get("annotations").and_then(Value::as_object).cloned();
                let mut action = template.clone();
                action.name = tool.name.clone();
                if action.name == "write_agrees" {
                    action.risk = Risk::Write;
                    action.poll = None;
                }
                manifest.actions_baseline.push(action);
                tool
            })
            .collect();
        let observations = annotation_observations(&manifest, &tools);
        assert!(
            !observations.iter().any(|line| line.contains("write_agrees")),
            "a write-declared action with readOnlyHint=false agrees with the manifest, not a disagreement: {observations:?}"
        );
        assert!(
            observations.iter().any(|line| line.contains("action \"disagrees\"")),
            "a read-declared action with readOnlyHint=false must still be reported: {observations:?}"
        );
        assert_eq!(observations, vec![
            "6 tools, 5 carried annotations objects; 4 carried annotations.readOnlyHint (1 read-only, 2 not-read-only, 1 invalid); 2 hint absent",
            "action \"disagrees\": manifest risk=read, vendor annotations.readOnlyHint=false",
        ]);
        for (verdict, exit) in [
            (DriftVerdict::Clean { actions: 6 }, 0),
            (
                DriftVerdict::Drifted {
                    missing: names(&["missing"]),
                    undeclared: vec![],
                },
                1,
            ),
            (
                DriftVerdict::Unchecked {
                    reason: "anonymous".into(),
                },
                2,
            ),
        ] {
            let mut report = DriftReport {
                key: "vendor".into(),
                path: PathBuf::new(),
                verdict,
                observations: observations.clone(),
            };
            assert_eq!(render(&[report.clone()]), exit);
            report.observations.clear();
            assert_eq!(render(&[report]), exit);
        }
        let absent = vec![served_action("absent", &[])];
        assert_eq!(annotation_observations(&manifest, &absent), vec![
            "1 tools, 0 carried annotations objects; 0 carried annotations.readOnlyHint (0 read-only, 0 not-read-only, 0 invalid); 1 hint absent"
        ]);
    }

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    /// Build a manifest carrying one action with a poll shape, so the parameter
    /// comparison has something real to read.
    fn manifest_with_poll(action: &str, since: &str, constants: &[&str]) -> AppManifest {
        let constants: serde_json::Map<String, Value> = constants
            .iter()
            .map(|key| ((*key).to_string(), Value::String("ASC".to_string())))
            .collect();
        let source = serde_json::json!({
            "schema_version": 1,
            "key": "pollvendor",
            "name": "Poll Vendor",
            "description": "poll parameter test vendor",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "tests",
            "tier": "S1",
            "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "none"},
            "credential_bindings": [],
            "actions_baseline": [{
                "name": action,
                "risk": "read",
                "poll": {
                    "item_kind": "issue",
                    "cursor_kind": "ordered_timestamp",
                    "timestamp_field": "updated_at",
                    "tiebreaker_id_field": "number",
                    "items_field": "issues",
                    "request_since_field": since,
                    "request_constants": constants
                }
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 30}},
            "availability": "ga"
        });
        serde_json::from_value(source).expect("manifest parses")
    }

    fn served_action(name: &str, properties: &[&str]) -> DiscoveredAction {
        let properties: serde_json::Map<String, Value> = properties
            .iter()
            .map(|key| ((*key).to_string(), serde_json::json!({"type": "string"})))
            .collect();
        DiscoveredAction {
            name: name.to_string(),
            title: None,
            description: None,
            annotations: None,
            input_schema: serde_json::json!({"type": "object", "properties": properties}),
        }
    }

    /// A declared poll parameter the vendor does not accept is reported, and a
    /// vendor that accepts every declared parameter is not.
    ///
    /// This is the check that would have caught a real mistake: `list_issues`
    /// accepts `since` while `list_pull_requests` accepts sort and direction but
    /// NO timestamp bound, and all three GitHub list actions were about to be
    /// declared with the same ordered-timestamp shape on the assumption that one
    /// vendor's tools resemble each other.
    ///
    /// The consequence is why this is drift rather than a warning: the vendor
    /// ignores the parameter, returns its default page, and the strategy still
    /// advances its watermark from the items it did receive -- so the feed reads
    /// as healthy while never seeing past page one. It would survive a first
    /// live call, unlike a shape error.
    ///
    /// Both arms are asserted because a check that only ever reports a problem
    /// cannot be distinguished from one that reports unconditionally.
    ///
    /// Mutation-proved: returning `None` unconditionally from
    /// `compare_poll_parameters` fails the first arm; dropping the
    /// `contains_key` filter so every declared field counts as unserved fails
    /// the second.
    #[test]
    fn a_poll_parameter_the_vendor_does_not_accept_is_reported() {
        // The real specimen: a timestamp bound declared against a tool whose
        // schema offers only ordering and pagination.
        let manifest = manifest_with_poll("list_pull_requests", "since", &["direction"]);
        let served = vec![served_action(
            "list_pull_requests",
            &["owner", "repo", "sort", "direction", "page"],
        )];
        let verdict = compare_poll_parameters(&manifest, &served);
        assert_eq!(
            verdict,
            unserved_poll(&[("list_pull_requests", &["since"])]),
            "a declared timestamp bound absent from the vendor schema must be reported"
        );

        // The shipped shape: every declared parameter is served.
        let manifest = manifest_with_poll("list_issues", "since", &["direction"]);
        let served = vec![served_action(
            "list_issues",
            &["owner", "repo", "since", "direction", "orderBy"],
        )];
        assert_eq!(
            compare_poll_parameters(&manifest, &served),
            None,
            "a fully served poll shape must not be reported"
        );

        // A polling action AFTER non-polling ones, which is the real shape: the
        // GitHub manifest declares 27 actions and only one carries a poll block.
        // Without this arm the loop could stop at the first action lacking a poll
        // shape and still pass every assertion above -- which is exactly the bug
        // a live run caught, reporting CLEAN against a planted bad shape.
        let mut manifest = manifest_with_poll("list_pull_requests", "since", &[]);
        let polling = manifest.actions_baseline.remove(0);
        let mut plain = polling.clone();
        plain.name = "get_me".to_string();
        plain.poll = None;
        manifest.actions_baseline = vec![plain, polling];
        let served = vec![
            served_action("get_me", &[]),
            served_action("list_pull_requests", &["owner", "repo", "sort"]),
        ];
        assert_eq!(
            compare_poll_parameters(&manifest, &served),
            unserved_poll(&[("list_pull_requests", &["since"])]),
            "a polling action after non-polling ones must still be examined"
        );
    }

    fn unserved_poll(findings: &[(&str, &[&str])]) -> Option<DriftVerdict> {
        Some(DriftVerdict::PollShapeUnserved {
            actions: findings
                .iter()
                .map(|(action, unserved)| UnservedPollParameters {
                    action: action.to_string(),
                    unserved: names(unserved),
                })
                .collect(),
        })
    }

    /// Every drifted polling action is reported in one run. Stopping at the
    /// first meant a manifest with two bad poll shapes showed one, and the
    /// second appeared only after the first was fixed and the check re-run.
    #[test]
    fn every_polling_action_with_unserved_parameters_is_reported() {
        let mut manifest = manifest_with_poll("list_issues", "since", &[]);
        let mut second = manifest.actions_baseline[0].clone();
        second.name = "list_pull_requests".to_string();
        let mut served_ok = manifest.actions_baseline[0].clone();
        served_ok.name = "list_releases".to_string();
        manifest.actions_baseline.push(served_ok);
        manifest.actions_baseline.push(second);
        let served = vec![
            served_action("list_issues", &["owner", "repo"]),
            served_action("list_releases", &["since"]),
            served_action("list_pull_requests", &["sort"]),
        ];
        assert_eq!(
            compare_poll_parameters(&manifest, &served),
            unserved_poll(&[
                ("list_issues", &["since"]),
                ("list_pull_requests", &["since"])
            ]),
            "every drifted polling action must be reported"
        );
    }

    /// A vendor publishing no `properties` is not evidence of refusal.
    ///
    /// An inputSchema without properties tells us nothing about what the tool
    /// accepts, so treating that silence as "accepts nothing" would report every
    /// declared parameter as unserved and make the check useless against any
    /// vendor with a sparse schema.
    ///
    /// Mutation-proved: replacing the `continue` with a report fails this.
    #[test]
    fn a_vendor_publishing_no_properties_is_not_reported() {
        let manifest = manifest_with_poll("list_issues", "since", &[]);
        let served = vec![DiscoveredAction {
            name: "list_issues".to_string(),
            title: None,
            description: None,
            annotations: None,
            input_schema: serde_json::json!({"type": "object"}),
        }];
        assert_eq!(
            compare_poll_parameters(&manifest, &served),
            None,
            "an absent properties map must not be read as a refusal"
        );
    }

    /// An exact match in both directions is the only clean result.
    #[test]
    fn identical_sets_are_clean() {
        assert_eq!(
            compare(&names(&["a", "b"]), &names(&["b", "a"])),
            DriftVerdict::Clean { actions: 2 },
            "order must not matter; these are sets"
        );
    }

    /// A rename shows up in BOTH directions at once, and reporting only one
    /// half misdescribes what happened: the replacement tool is right there.
    /// This is the real firecrawl shape reduced to its essentials.
    #[test]
    fn a_rename_is_reported_as_missing_and_undeclared_together() {
        let verdict = compare(&names(&["scrape"]), &names(&["firecrawl_scrape"]));
        assert_eq!(
            verdict,
            DriftVerdict::Drifted {
                missing: names(&["scrape"]),
                undeclared: names(&["firecrawl_scrape"]),
            },
            "a rename must surface both the disabled action and its replacement"
        );
    }

    /// Each direction alone is drift. Asserted separately because a check that
    /// only looked at declared-minus-served would call an undeclared vendor
    /// tool clean — and an undeclared tool is the one that gets quarantined,
    /// which is how a vendor ADDING a capability silently produces a
    /// half-working connector.
    #[test]
    fn each_direction_alone_is_drift() {
        assert_eq!(
            compare(&names(&["a", "b"]), &names(&["a"])),
            DriftVerdict::Drifted {
                missing: names(&["b"]),
                undeclared: Vec::new(),
            }
        );
        assert_eq!(
            compare(&names(&["a"]), &names(&["a", "b"])),
            DriftVerdict::Drifted {
                missing: Vec::new(),
                undeclared: names(&["b"]),
            }
        );
    }

    /// A vendor answering with NO tools is a failed observation, not agreement.
    ///
    /// The dangerous reading is "nothing served, nothing to disagree with,
    /// therefore clean" — which reports the most broken possible connector
    /// state as the healthiest one, since reconcile would disable every
    /// declared action. Asserted with a non-empty declared set so the result
    /// cannot be explained by there being nothing to compare on either side.
    ///
    /// Mutation-proved: removing the guard makes this return Clean.
    #[test]
    fn an_empty_vendor_tool_list_is_unchecked_not_clean() {
        let verdict = compare(&names(&["a", "b"]), &[]);
        assert!(
            matches!(verdict, DriftVerdict::Unchecked { .. }),
            "an empty vendor surface must not read as agreement, got {verdict:?}"
        );
    }

    /// A sweep that verified nothing must not exit 0.
    ///
    /// This is the whole point of keeping `Unchecked` separate from `Clean`:
    /// thirteen vendors we could not reach is the NORMAL result without
    /// credentials, and if that reported success the check would spend most of
    /// its life confidently saying the catalog is fine while looking at almost
    /// none of it.
    #[test]
    fn a_run_that_checked_nothing_does_not_report_success() {
        let reports = vec![DriftReport {
            key: "vendor".to_string(),
            observations: Vec::new(),
            path: PathBuf::from("catalog/vendor.jsonc"),
            verdict: DriftVerdict::Unchecked {
                reason: "needs a credential".to_string(),
            },
        }];
        assert_eq!(render(&reports), 2, "unchecked must not read as clean");
    }

    /// An anonymous disagreement is inconclusive, not drift.
    ///
    /// Guards against the expensive direction of this error. A vendor may serve
    /// a reduced surface to an anonymous caller instead of refusing, so a
    /// difference seen without a credential could be drift OR could be the
    /// logged-out view -- and reporting it as drift invites someone to correct
    /// a manifest that was right.
    ///
    /// Mutation-proved: returning the verdict unchanged fails this.
    #[test]
    fn an_anonymous_disagreement_is_not_reported_as_drift() {
        let drifted = DriftVerdict::Drifted {
            missing: names(&["model_search", "dataset_search"]),
            undeclared: names(&["hf_whoami"]),
        };
        let DriftVerdict::Unchecked { reason } = qualify(drifted, true) else {
            panic!("an anonymous difference must not be reported as drift");
        };
        // The observation is not discarded along with the verdict: a reader has
        // to be able to see WHAT differed without re-running the check.
        assert!(
            reason.contains("model_search") && reason.contains("hf_whoami"),
            "the observed difference must survive into the reason: {reason}"
        );
    }

    /// The same disagreement WITH a credential is real drift.
    ///
    /// The companion that stops the rule above from collapsing into "never
    /// report drift". Without this, softening every difference would look
    /// identical to a check that cannot fail.
    #[test]
    fn a_credentialed_disagreement_is_still_drift() {
        let drifted = DriftVerdict::Drifted {
            missing: names(&["model_search"]),
            undeclared: names(&["hf_whoami"]),
        };
        assert!(
            matches!(qualify(drifted, false), DriftVerdict::Drifted { .. }),
            "a credentialed run must still report drift"
        );
    }

    /// Anonymous AGREEMENT is still clean.
    ///
    /// The asymmetry is the point: matching names are evidence regardless of
    /// whether a credential was used, so the caution applies only to
    /// disagreement. deepwiki and browserbase both verify clean anonymously and
    /// must keep doing so.
    #[test]
    fn anonymous_agreement_is_still_clean() {
        assert!(matches!(
            qualify(DriftVerdict::Clean { actions: 3 }, true),
            DriftVerdict::Clean { actions: 3 }
        ));
    }

    /// A PARTIAL sweep must not exit 0 either, and this is the case the
    /// previous rule missed: some vendors compared and clean, others never
    /// reached at all.
    ///
    /// Measured live before the fix — the real catalog sweep printed
    /// "3 clean, 0 drifted, 12 unchecked" together with a line saying UNCHECKED
    /// is not a pass, and exited 0. The human-readable half and the
    /// machine-readable half disagreed about the same run, and the optimistic
    /// one was the half a script would read.
    ///
    /// Mutation-proved: restoring the `clean > 0` rule makes this return 0.
    #[test]
    fn a_partial_sweep_does_not_report_success() {
        let reports = vec![
            DriftReport {
                key: "reachable".to_string(),
                observations: Vec::new(),
                path: PathBuf::from("catalog/reachable.jsonc"),
                verdict: DriftVerdict::Clean { actions: 3 },
            },
            DriftReport {
                key: "needs-credential".to_string(),
                observations: Vec::new(),
                path: PathBuf::from("catalog/needs-credential.jsonc"),
                verdict: DriftVerdict::Unchecked {
                    reason: "needs a credential".to_string(),
                },
            },
        ];
        assert_eq!(
            render(&reports),
            2,
            "a sweep that reached only part of the catalog has not verified it"
        );
    }

    /// A fully-compared sweep still exits 0, and a SKIPPED manifest does not
    /// spoil it.
    ///
    /// The companion to the test above, and the one that keeps the stricter
    /// rule from collapsing into "always 2": skipping is a legitimate terminal
    /// verdict for a REST manifest, whose actions are manifest-derived and have
    /// no vendor tool list to disagree with. Without this, the fix would be
    /// indistinguishable from a check that can no longer pass.
    #[test]
    fn a_complete_sweep_with_a_skip_still_reports_success() {
        let reports = vec![
            DriftReport {
                key: "mcp-vendor".to_string(),
                observations: Vec::new(),
                path: PathBuf::from("catalog/mcp-vendor.jsonc"),
                verdict: DriftVerdict::Clean { actions: 2 },
            },
            DriftReport {
                key: "rest-vendor".to_string(),
                observations: Vec::new(),
                path: PathBuf::from("catalog/rest-vendor.jsonc"),
                verdict: DriftVerdict::Skipped {
                    reason: "transport is RestApi".to_string(),
                },
            },
        ];
        assert_eq!(
            render(&reports),
            0,
            "a skip is a verdict, not a gap: this sweep examined everything it could"
        );
    }

    /// Drift outranks a clean sibling: one bad connector in a green sweep still
    /// fails, or a batch run would bury it.
    #[test]
    fn drift_anywhere_fails_the_whole_run() {
        let reports = vec![
            DriftReport {
                key: "good".to_string(),
                observations: Vec::new(),
                path: PathBuf::from("catalog/good.jsonc"),
                verdict: DriftVerdict::Clean { actions: 2 },
            },
            DriftReport {
                key: "bad".to_string(),
                observations: Vec::new(),
                path: PathBuf::from("catalog/bad.jsonc"),
                verdict: DriftVerdict::Drifted {
                    missing: names(&["gone"]),
                    undeclared: Vec::new(),
                },
            },
        ];
        assert_eq!(render(&reports), 1);
    }
}
