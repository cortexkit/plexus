//! Every shipped `catalog/*.jsonc` manifest must survive the production ingest.
//!
//! WHY THIS IS A TEST RATHER THAN A BOOT-TIME DISCOVERY: the manifest model is
//! `#[serde(deny_unknown_fields)]` and `ingest_catalog` propagates the FIRST
//! failure with `?`, before the module serves anything. So one manifest carrying
//! a stale field does not disable one vendor — it fails the whole boot, for
//! every vendor, on a module that was healthy a second earlier.
//!
//! That failure is also DELAYED past the point of noticing. Manifests are data,
//! not code, so nothing about editing one drags a compiler across it; the file
//! sits correct-looking in the repo and detonates when a daemon next restarts,
//! which may be days later and will be attributed to whatever else changed that
//! day.
//!
//! Concretely: adding a REQUIRED field to a poll shape is a routine model change
//! that leaves every existing manifest instantly invalid. Two such fields landed
//! in one week (`request_page_size_field`, then `item_kind`), and the only thing
//! that caught the shipped manifest both times was a test that happened to parse
//! that one file for another purpose.
//!
//! It lives in the conformance crate because parsing a real catalog file needs
//! the production JSONC parser, and plexus-core deliberately does not depend on
//! subc-jsonc — its own tests strip comments with a hand-rolled helper, which is
//! fine for documents it authors and wrong for documents whose exact bytes are
//! the thing under test.

use std::path::{Path, PathBuf};

use plexus_conformance::drift::catalog_manifests;
use plexus_core::ingest_value;

fn catalog_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog")
}

/// Every `*.jsonc` manifest `catalog_manifests` finds under `catalog/` parses
/// and ingests.
///
/// Reports EVERY failure rather than the first, because a model change that
/// invalidates one manifest has usually invalidated several, and fixing them one
/// boot-failure at a time is the slowest possible way to learn that.
#[test]
fn every_shipped_manifest_survives_ingest() {
    let directory = catalog_dir();
    let paths =
        catalog_manifests(&directory).expect("the shipped catalog directory must be readable");

    // A guard, not a formality: `catalog_manifests` already refuses an empty
    // directory, and without that this test would PASS by examining nothing —
    // the vacuous-loop shape that makes a green suite meaningless.
    assert!(
        paths.len() >= 10,
        "expected the full shipped catalog, found {} manifest(s) under {} — \
         a suspiciously short list means the path is wrong, not that the fleet shrank",
        paths.len(),
        directory.display()
    );

    let mut failures = Vec::new();
    for path in &paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                failures.push(format!("{name}: unreadable: {error}"));
                continue;
            }
        };
        // The PRODUCTION parser, so a comment or trailing comma the real boot
        // would reject cannot pass here.
        let normalized = match subc_jsonc::jsonc_to_json(&source) {
            Ok(normalized) => normalized,
            Err(error) => {
                failures.push(format!("{name}: not valid JSONC: {error}"));
                continue;
            }
        };
        let value = match serde_json::from_str::<serde_json::Value>(&normalized) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!(
                    "{name}: not valid JSON after comment strip: {error}"
                ));
                continue;
            }
        };
        if let Err(error) = ingest_value(value) {
            failures.push(format!("{name}: refused by ingest: {error}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} shipped manifest(s) would fail the module boot:\n  {}",
        failures.len(),
        paths.len(),
        failures.join("\n  ")
    );
}

#[test]
fn github_actions_is_a_read_only_per_attempt_rest_catalog() {
    use plexus_core::manifest::{AuthMode, CursorKind, HttpMethod, Risk, TransportKind};
    use serde_json::json;

    let source = std::fs::read_to_string(catalog_dir().join("github_actions.jsonc")).unwrap();
    let normalized = subc_jsonc::jsonc_to_json(&source).unwrap();
    let ingested = ingest_value(serde_json::from_str(&normalized).unwrap()).unwrap();
    let manifest = ingested.manifest;
    assert_eq!(manifest.key, "github_actions");
    assert_eq!(manifest.transport.kind, TransportKind::RestApi);
    assert_eq!(manifest.transport.url, "https://api.github.com");
    assert_eq!(manifest.auth.mode, AuthMode::ApiKey);
    assert_eq!(manifest.credential_bindings.len(), 1);
    let binding = &manifest.credential_bindings[0];
    assert_eq!(binding.ref_role, "api_key");
    assert_eq!(binding.placement, "header");
    assert_eq!(binding.key, "Authorization");
    assert_eq!(binding.prefix, "Bearer ");
    assert!(binding.required);

    assert_eq!(manifest.actions_baseline.len(), 10);
    let job = &manifest.actions_baseline[0];
    assert_eq!(job.name, "get_job");
    assert_eq!(
        job.http.as_ref().unwrap().path,
        "/repos/{owner}/{repo}/actions/jobs/{job_id}"
    );
    let log = &manifest.actions_baseline[1];
    assert_eq!(log.name, "github.actions.job_log");
    assert_eq!(log.risk, Risk::Read);
    let http = log.http.as_ref().unwrap();
    assert_eq!(http.method, HttpMethod::Get);
    assert_eq!(
        http.path,
        "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
    );
    assert_eq!(
        http.args_schema["properties"]["max_bytes"]["default"],
        65536
    );
    assert_eq!(
        http.args_schema["properties"]["max_bytes"]["maximum"],
        262144
    );
    assert_eq!(
        http.credentialless_tail.as_ref().unwrap().allowed_hosts,
        [
            "*.blob.core.windows.net",
            "results-receiver.actions.githubusercontent.com"
        ]
    );
    let actions = &manifest.actions_baseline[2..6];
    assert_eq!(
        actions
            .iter()
            .map(|action| action.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "list_workflow_runs",
            "get_workflow_run",
            "list_jobs_for_workflow_run_attempt",
            "get_repository"
        ]
    );
    for action in actions {
        assert_eq!(action.risk, Risk::Read);
        assert_eq!(action.http.as_ref().unwrap().method, HttpMethod::Get);
    }
    let discovery = actions[0].http.as_ref().unwrap();
    assert_eq!(discovery.path, "/repos/{owner}/{repo}/actions/runs");
    assert_eq!(discovery.args_schema["required"], json!(["owner", "repo"]));
    for field in ["created", "status"] {
        assert_eq!(discovery.args_schema["properties"][field]["type"], "string");
    }
    let poll = actions[0].poll.as_ref().unwrap();
    assert_eq!(poll.cursor_kind, CursorKind::CiRuns);
    assert_eq!(poll.item_kind, "ci_run");
    assert_eq!(poll.items_field.as_deref(), Some("workflow_runs"));
    assert!(actions[1..].iter().all(|action| action.poll.is_none()));
    assert_eq!(
        actions[1].http.as_ref().unwrap().path,
        "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}"
    );
    assert_eq!(
        actions[2].http.as_ref().unwrap().path,
        "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs"
    );
    for action in &actions[1..3] {
        assert_eq!(
            action.http.as_ref().unwrap().args_schema["required"],
            json!(["owner", "repo", "run_id", "attempt_number"])
        );
    }
    for action in [&actions[0], &actions[2]] {
        assert!(
            action.http.as_ref().unwrap().args_schema["properties"]
                .get("per_page")
                .is_none(),
            "{} must not advertise the transport-owned page size as a caller argument",
            action.name
        );
        assert_eq!(
            action
                .http
                .as_ref()
                .unwrap()
                .request_constants
                .as_ref()
                .unwrap(),
            &std::collections::BTreeMap::from([("per_page".into(), json!(100))])
        );
    }
    assert_eq!(
        actions[3].http.as_ref().unwrap().path,
        "/repos/{owner}/{repo}"
    );
    assert_eq!(
        actions[3].http.as_ref().unwrap().args_schema["required"],
        json!(["owner", "repo"])
    );
}

#[test]
fn github_actions_superseded_catalog_is_closed_and_read_only() {
    use plexus_core::manifest::{HttpMethod, Risk};
    use serde_json::json;

    let source = std::fs::read_to_string(catalog_dir().join("github_actions.jsonc")).unwrap();
    let normalized = subc_jsonc::jsonc_to_json(&source).unwrap();
    let ingested = ingest_value(serde_json::from_str(&normalized).unwrap()).unwrap();
    for (name, required) in [
        (
            "get_workflow_run_metadata",
            json!(["owner", "repo", "run_id"]),
        ),
        (
            "list_workflow_runs_for_workflow",
            json!(["owner", "repo", "workflow_id", "branch"]),
        ),
    ] {
        let action = ingested
            .manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == name)
            .unwrap();
        assert_eq!(action.risk, Risk::Read, "{name} must remain read-only");
        assert!(action.poll.is_none());
        let http = action.http.as_ref().unwrap();
        assert_eq!(http.method, HttpMethod::Get);
        assert_eq!(http.args_schema["type"], "object");
        assert_eq!(http.args_schema["required"], required);
        assert_eq!(
            http.args_schema["additionalProperties"], false,
            "{name} must have closed arguments"
        );
        assert!(http.args_schema["properties"].get("per_page").is_none());
    }
}

#[test]
fn github_actions_artifact_catalog_is_read_only_and_bounded() {
    use plexus_core::manifest::{HttpMethod, Risk};
    use serde_json::json;
    let source = std::fs::read_to_string(catalog_dir().join("github_actions.jsonc")).unwrap();
    let normalized = subc_jsonc::jsonc_to_json(&source).unwrap();
    let manifest = ingest_value(serde_json::from_str(&normalized).unwrap())
        .unwrap()
        .manifest;
    let action = |name: &str| {
        manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == name)
            .unwrap()
    };
    let list = action("list_workflow_run_artifacts");
    assert_eq!(list.risk, Risk::Read);
    let http = list.http.as_ref().unwrap();
    assert_eq!(http.method, HttpMethod::Get);
    assert_eq!(
        http.path,
        "/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    );
    assert_eq!(
        http.request_constants,
        Some(serde_json::from_value(json!({"per_page":100})).unwrap())
    );
    assert_eq!(
        http.args_schema["required"],
        json!(["owner", "repo", "run_id", "name"])
    );
    assert_eq!(http.args_schema["additionalProperties"], false);
    let download = action("github.actions.artifact_file");
    assert_eq!(download.risk, Risk::Read);
    let http = download.http.as_ref().unwrap();
    assert_eq!(http.method, HttpMethod::Get);
    assert_eq!(
        http.path,
        "/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip"
    );
    assert_eq!(
        http.args_schema["properties"]["max_bytes"],
        json!({"type":"integer","minimum":1,"maximum":262144,"default":65536})
    );
    assert_eq!(
        http.args_schema["required"],
        json!(["owner", "repo", "artifact_id", "path"])
    );
    assert_eq!(http.args_schema["additionalProperties"], false);
    assert_eq!(
        http.credentialless_tail.as_ref().unwrap().allowed_hosts,
        action("github.actions.job_log")
            .http
            .as_ref()
            .unwrap()
            .credentialless_tail
            .as_ref()
            .unwrap()
            .allowed_hosts
    );
}
