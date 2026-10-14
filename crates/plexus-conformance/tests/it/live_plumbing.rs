//! Integration test for the live-run plumbing WITHOUT the network.
//!
//! Runs the exa fixture against an in-process stub MCP server via an explicit
//! `Endpoint` override, binding a fake operator reference and resolving credentials
//! through a mock vault credential route peer wrapped in the wire-trace decorator. This
//! proves the full live plumbing — explicit endpoint, operator-handle binding,
//! a route-peer-backed credential source behind the production seam, and a
//! redacted wire trace — while the evidence leak-scan still passes for the
//! supplied reference.

use std::sync::Arc;

use plexus_conformance::{
    run_fixture_with_options, ConnectorFixture, RunOptions, StubMcpServer, TracingRoutePeer,
    TransportTarget, WireTraceSink,
};
use plexus_core::test_scratch::Scratch;
use plexus_core::{CkcredCredentialSource, CkcredRouteError, CkcredRoutePeer, CredentialSource};
use serde_json::{json, Value};

/// Route peer that always resolves `credential.get_scoped` with a fixed payload. Stands
/// in for the real vault credential route so the live plumbing is exercised without a
/// daemon or network.
#[derive(Clone)]
struct StubCkcredPeer {
    payload: Vec<u8>,
}

impl CkcredRoutePeer for StubCkcredPeer {
    fn call(&self, _operation: &str, _params: Value) -> Result<Value, CkcredRouteError> {
        Ok(json!({
            "result": {
                "payload": self.payload.iter().copied().map(Value::from).collect::<Vec<_>>(),
                "record_version": 1, "credential_id": "apikey:exa-live-plumbing",
            }
        }))
    }
}

fn temp_path(label: &str) -> Scratch {
    Scratch::file(&format!("live-plumbing-{label}"), "trace.jsonl")
}

#[test]
fn exa_live_plumbing_runs_green_with_redacted_wire_trace() {
    let fixture = ConnectorFixture::exa();

    // In-process stub MCP server standing in for the real Exa endpoint.
    let stub_server = StubMcpServer::start(fixture.stub_tools()).expect("start stub server");
    let endpoint = stub_server.endpoint().to_string();

    // Fake operator vault reference plus the vendor token the mock vault serves.
    let operator_credential_id = "apikey:exa-live-plumbing".to_string();
    let vendor_token = b"exa-live-vendor-token".to_vec();

    let trace_path = temp_path("exa");
    let sink = Arc::new(WireTraceSink::open(&trace_path).expect("open wire-trace sink"));
    let tracing = TracingRoutePeer::new(
        Arc::new(StubCkcredPeer {
            payload: vendor_token.clone(),
        }),
        Arc::clone(&sink),
    );
    let credential_source: Arc<dyn CredentialSource> =
        Arc::new(CkcredCredentialSource::new(Arc::new(tracing)));

    let options = RunOptions {
        transport_override: Some(TransportTarget::Endpoint(endpoint)),
        operator_credential_id: Some(operator_credential_id.clone()),
        credential_source: Some(credential_source),
        schema_out: None,
    };

    let evidence = run_fixture_with_options(&fixture, options).expect("live plumbing run");
    assert!(
        evidence.passed,
        "live plumbing run failed at {:?}:\n{}",
        evidence.failed_step,
        evidence.human_summary()
    );
    assert!(
        evidence.steps.iter().all(|step| step.passed),
        "every step must pass:\n{}",
        evidence.human_summary()
    );

    // The SecretSafety step ran the live leak-scan for the supplied reference.
    let secret_step = evidence
        .steps
        .iter()
        .find(|step| step.step.as_str() == "secret_safety")
        .expect("secret_safety step");
    assert!(secret_step.passed);
    assert!(
        secret_step.detail.contains("live mode"),
        "secret_safety should report the live-mode leak-scan: {}",
        secret_step.detail
    );

    // The supplied reference must appear nowhere in the evidence.
    let evidence_json = serde_json::to_string(&evidence).expect("serialize evidence");
    let handle_text = operator_credential_id.as_str();
    assert!(
        !evidence_json.contains(handle_text),
        "operator reference leaked into evidence"
    );

    // The wire trace captured the credential.get_scoped exchange, with vendor payload bytes redacted.
    drop(stub_server);
    let trace_text = std::fs::read_to_string(&trace_path).expect("read wire trace");
    let lines: Vec<Value> = trace_text
        .lines()
        .map(|line| serde_json::from_str(line).expect("trace line is JSON"))
        .collect();
    let credential_gets: Vec<&Value> = lines
        .iter()
        .filter(|line| line["operation"] == "credential.get_scoped")
        .collect();
    assert!(
        !credential_gets.is_empty(),
        "wire trace must contain a credential.get_scoped exchange; got:\n{trace_text}"
    );
    for line in &credential_gets {
        let payload = &line["response"]["result"]["payload"];
        assert_eq!(payload["__redacted"], true, "payload must be redacted");
        assert_eq!(payload["json_type"], "u8_array");
        assert_eq!(payload["len"], json!(vendor_token.len()));
        assert!(payload["fingerprint"]
            .as_str()
            .expect("payload fingerprint")
            .starts_with("sha256:"));
        assert_eq!(line["request"]["credential_id"], operator_credential_id);
    }
    // Raw secret bytes appear nowhere in the trace file.
    let vendor_text = String::from_utf8_lossy(&vendor_token);
    assert!(
        !trace_text.contains(vendor_text.as_ref()),
        "vendor token leaked to trace"
    );

    let _ = std::fs::remove_file(&trace_path);
}

#[test]
fn live_manifest_endpoint_without_operator_credential_id_fails_fast() {
    let fixture = ConnectorFixture::exa();
    let options = RunOptions {
        transport_override: Some(TransportTarget::ManifestEndpoint),
        operator_credential_id: None,
        credential_source: None,
        schema_out: None,
    };
    let error = run_fixture_with_options(&fixture, options)
        .expect_err("live target without an operator reference must fail fast");
    assert!(
        error.contains("operator credentials"),
        "fail-fast message should name operator credentials: {error}"
    );
}
