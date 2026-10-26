//! CI gate: every registered stub-target fixture must complete every conformance
//! checklist step green.

use plexus_conformance::{run_fixture, run_fixture_with_options, ConnectorFixture, RunOptions};
use plexus_core::test_scratch::Scratch;

fn evidence_for(name: &str) -> &'static plexus_conformance::RunEvidence {
    static RUNS: std::sync::OnceLock<
        std::collections::BTreeMap<String, plexus_conformance::RunEvidence>,
    > = std::sync::OnceLock::new();
    &RUNS.get_or_init(|| {
        ConnectorFixture::known_names()
            .iter()
            .map(|name| {
                let fixture = ConnectorFixture::by_name(name).expect("registered fixture");
                let evidence =
                    run_fixture(&fixture).unwrap_or_else(|error| panic!("fixture {name}: {error}"));
                ((*name).to_owned(), evidence)
            })
            .collect()
    })[name]
}

#[test]
fn all_registered_fixtures_run_end_to_end_green() {
    let names = ConnectorFixture::known_names();
    assert!(!names.is_empty(), "the fixture registry must not be empty");
    assert!(
        names.contains(&"stub"),
        "the stub fixture must be registered"
    );
    assert!(names.contains(&"exa"), "the Exa fixture must be registered");
    for name in names {
        let evidence = evidence_for(name);
        assert!(
            evidence.passed,
            "fixture '{name}' failed at {:?}:\n{}",
            evidence.failed_step,
            evidence.human_summary()
        );
        assert_eq!(
            evidence.steps.len(),
            9,
            "fixture '{name}' must report all 9 conformance steps"
        );
        assert!(
            evidence.steps.iter().all(|step| step.passed),
            "fixture '{name}' has a non-passed step:\n{}",
            evidence.human_summary()
        );
    }
}

/// `--schema-out` writes the vendor's OBSERVED tool schemas, not a summary of
/// them.
///
/// Discovery already fetched every action's `inputSchema` and the store kept
/// it, but evidence recorded only a count and a hash prefix — which prove a
/// schema existed and say nothing about its shape. Declaring a manifest `poll`
/// shape requires naming the vendor's real parameters, and taking those from
/// vendor API documentation instead of the tool's own schema fails silently:
/// the tool ignores an unknown argument, returns an unfiltered first page every
/// cycle, and dedupe discards it, so a misconfigured trigger looks exactly like
/// a quiet period.
///
/// Asserts the FILE CONTENT rather than that the run passed, and asserts a
/// property name from inside a schema rather than merely that a `schema` key
/// exists — an empty object would satisfy the weaker check while being useless
/// for the one job this flag has.
///
/// Mutation-proved: writing `action.schema_hash` in place of `action.schema`
/// fails on the parameter-name assertion.
#[test]
fn schema_out_writes_the_observed_tool_schemas() {
    let fixture = ConnectorFixture::stub();
    let path = Scratch::file("schema-out", "schema.json");

    let evidence = run_fixture_with_options(
        &fixture,
        RunOptions {
            schema_out: Some(path.to_path_buf()),
            ..RunOptions::default()
        },
    )
    .expect("stub fixture run");
    assert!(evidence.passed, "{}", evidence.human_summary());

    let written = std::fs::read_to_string(&path).expect("schema file was written");
    let document: serde_json::Value = serde_json::from_str(&written).expect("schema file is JSON");
    let actions = document["actions"]
        .as_array()
        .expect("schema file lists actions");
    assert!(!actions.is_empty(), "no actions were written");

    // The load-bearing assertion: a real parameter name from inside the
    // schema. A hash, or an empty object, would pass a mere "has a schema key"
    // check and be worthless for writing a poll shape.
    let has_named_parameter = actions.iter().any(|action| {
        action["schema"]["properties"]
            .as_object()
            .is_some_and(|properties| !properties.is_empty())
    });
    assert!(
        has_named_parameter,
        "no action carried a schema with named properties: {written}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("stat schema file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "schema file is not owner-only: {mode:o}");
    }

    let _ = std::fs::remove_file(&path);
}

/// Without `--schema-out`, no file is written and the run is unaffected. The
/// negative direction matters because a flag that writes unconditionally would
/// pass the test above while quietly producing artifacts nobody asked for.
#[test]
fn no_schema_file_is_written_without_the_flag() {
    let dir = Scratch::file("no-schema-output", "unused");
    let directory = dir.parent().unwrap();
    let output = super::bounded::child_output(
        std::process::Command::new(env!("CARGO_BIN_EXE_plexus-conformance"))
            .current_dir(directory)
            .args(["run", "--fixture", "stub"]),
        std::time::Duration::from_secs(30),
        "relocated CLI",
    )
    .expect("run relocated CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "evidence must not default to stdout"
    );
    assert_eq!(
        std::fs::read_dir(directory).unwrap().count(),
        0,
        "a schema artifact appeared without the flag"
    );
}

#[cfg(unix)]
#[test]
fn an_unusable_temp_directory_is_a_reported_error_not_a_panic() {
    let path = Scratch::file("unusable-temp-directory", "not-a-directory");
    std::fs::write(&path, b"not a directory").unwrap();
    let output = super::bounded::child_output(
        std::process::Command::new(env!("CARGO_BIN_EXE_plexus-conformance"))
            .env("TMPDIR", path.to_path_buf())
            .args(["run", "--fixture", "stub"]),
        std::time::Duration::from_secs(30),
        "unusable scratch root",
    )
    .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "scratch failures must be normal CLI errors, not panics"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("create store directory"));
}

#[test]
fn linear_fixture_runs_green_against_stub_server() {
    let evidence = evidence_for("linear");
    assert!(
        evidence.passed,
        "linear fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
    assert!(evidence.steps.iter().all(|step| step.passed));
    // Ask-first write must run (not skip) for Linear create_issue.
    let write_step = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "ask_first_write")
        .expect("ask_first_write step");
    assert!(write_step.skipped.is_none(), "linear write must not skip");
}

#[test]
fn sentry_fixture_runs_green_against_stub_server() {
    let evidence = evidence_for("sentry");
    assert!(
        evidence.passed,
        "sentry fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
    assert!(evidence.steps.iter().all(|step| step.passed));
    let write_step = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "ask_first_write")
        .expect("ask_first_write step");
    assert!(write_step.skipped.is_none(), "sentry write must not skip");
}

#[test]
fn notion_fixture_runs_green_with_s3_escalation() {
    let evidence = evidence_for("notion");
    assert!(
        evidence.passed,
        "notion fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
    assert!(evidence.steps.iter().all(|step| step.passed));
    let s3_step = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "s3_escalation")
        .expect("s3_escalation step");
    assert!(
        s3_step.skipped.is_none(),
        "notion s3_escalation must not skip"
    );
    assert!(
        s3_step.detail.contains("NeedsDecisionPlane") || s3_step.detail.contains("S3"),
        "s3_escalation detail should describe decision-plane handoff: {}",
        s3_step.detail
    );
    assert!(
        evidence
            .steps
            .iter()
            .all(|step| step.step.as_str() != "ask_first_write"),
        "notion must use s3_escalation instead of ask_first_write"
    );
}

#[test]
fn restdemo_fixture_runs_green_against_rest_stub() {
    let evidence = evidence_for("restdemo");
    assert!(
        evidence.passed,
        "restdemo fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
    assert!(evidence.steps.iter().all(|step| step.passed));
    // The ask-first write (POST with a JSON body) must run, not skip.
    let write_step = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "ask_first_write")
        .expect("ask_first_write step");
    assert!(write_step.skipped.is_none(), "restdemo write must not skip");
}

#[test]
fn gcal_fixture_runs_green_read_only_with_allowlist_denial() {
    let evidence = evidence_for("gcal");
    assert!(
        evidence.passed,
        "gcal fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
    assert!(evidence.steps.iter().all(|step| step.passed));
    let write_step = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "ask_first_write")
        .expect("ask_first_write step");
    assert!(
        write_step.skipped.is_some(),
        "gcal write must honest-SKIP (read-only Batch A)"
    );
    let denied = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "denied_calls")
        .expect("denied_calls step");
    assert!(
        denied.detail.contains("resource denial recorded")
            && evidence
                .audit_dump
                .iter()
                .any(|row| row["gate"] == "resource_filter" && row["decision"] == "deny"),
        "gcal denied_calls should cover resource allowlist: {}",
        denied.detail
    );
}
