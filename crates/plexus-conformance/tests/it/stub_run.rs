//! CI gate: every registered stub-target fixture must complete every conformance
//! checklist step green.

use plexus_conformance::{run_fixture, run_fixture_with_options, ConnectorFixture, RunOptions};
use plexus_core::test_scratch::Scratch;

#[test]
fn all_registered_fixtures_run_end_to_end_green() {
    for name in ConnectorFixture::known_names() {
        let fixture = ConnectorFixture::by_name(name).unwrap_or_else(|error| {
            panic!("fixture '{name}' must resolve via by_name: {error}");
        });
        let evidence = run_fixture(&fixture).unwrap_or_else(|error| {
            panic!("fixture '{name}' run errored: {error}");
        });
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
    let fixture = ConnectorFixture::stub();
    let evidence = run_fixture(&fixture).expect("stub fixture run");
    assert!(evidence.passed, "{}", evidence.human_summary());
    assert!(
        !evidence.human_summary().contains("schemas written"),
        "a schema file was written without the flag:\n{}",
        evidence.human_summary()
    );
}

#[test]
fn stub_fixture_runs_end_to_end_green() {
    let fixture = ConnectorFixture::stub();
    let evidence = run_fixture(&fixture).expect("stub fixture run");
    assert!(
        evidence.passed,
        "stub fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
    assert!(evidence.steps.iter().all(|step| step.passed));
}

#[test]
fn exa_fixture_runs_green_against_stub_server() {
    let fixture = ConnectorFixture::exa();
    let evidence = run_fixture(&fixture).expect("exa fixture run");
    assert!(
        evidence.passed,
        "exa fixture failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert_eq!(evidence.steps.len(), 9);
}

#[test]
fn linear_fixture_runs_green_against_stub_server() {
    let fixture = ConnectorFixture::linear();
    let evidence = run_fixture(&fixture).expect("linear fixture run");
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
    let fixture = ConnectorFixture::sentry();
    let evidence = run_fixture(&fixture).expect("sentry fixture run");
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
    let fixture = ConnectorFixture::notion();
    let evidence = run_fixture(&fixture).expect("notion fixture run");
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
    let fixture = ConnectorFixture::restdemo();
    let evidence = run_fixture(&fixture).expect("restdemo fixture run");
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
    let fixture = ConnectorFixture::gcal();
    let evidence = run_fixture(&fixture).expect("gcal fixture run");
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
        denied.detail.contains("resource") || denied.passed,
        "gcal denied_calls should cover resource allowlist: {}",
        denied.detail
    );
}
