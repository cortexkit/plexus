use super::tests::{load_catalog, rest_manifest_value};
use super::*;
use serde_json::json;

fn with_rules(rules: Value) -> Value {
    let mut manifest = rest_manifest_value();
    manifest["actions_baseline"][0]["error_signals"] = rules;
    manifest
}

pub(crate) fn json_rule(status: u16, signal: &str, pointer: &str, value: Value) -> Value {
    json!({"status": status, "signal": signal,
        "matches": {"kind": "json", "pointer": pointer, "value": value}})
}

#[test]
fn error_signals_are_closed_at_every_level() {
    let rule = json_rule(422, "no_results", "/code", json!("EMPTY"));
    assert!(ingest_value(with_rules(json!([rule.clone()]))).is_ok());
    for pointer in ["/signal", "/matches/kind"] {
        let mut changed = rule.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("unreviewed");
        assert!(
            ingest_value(with_rules(json!([changed]))).is_err(),
            "unknown signal or matcher must refuse"
        );
    }
    for pointer in ["", "/matches"] {
        let mut changed = rule.clone();
        changed.pointer_mut(pointer).unwrap()["extra"] = json!(true);
        assert!(
            ingest_value(with_rules(json!([changed]))).is_err(),
            "unknown error signal fields must refuse"
        );
    }
    let header = json!({"status":429,"signal":"quota_exhausted","matches":{
        "kind":"header","name":"X-Remaining","condition":{
            "kind":"comma_separated_element","index":1,"value":"0","extra":true}}});
    assert!(
        ingest_value(with_rules(json!([header]))).is_err(),
        "header condition must be closed"
    );
}

#[test]
fn overlapping_error_signals_refuse_before_dispatch() {
    let first = json_rule(422, "no_results", "/code", json!("EMPTY"));
    for second in [
        json_rule(422, "credential_rejected", "/code", json!("EMPTY")),
        json_rule(422, "quota_exhausted", "/other", json!(0)),
        json!({"status":422,"signal":"quota_exhausted","matches":{
            "kind":"header","name":"X-Remaining","condition":{"kind":"exact","value":"0"}}}),
    ] {
        let error = ingest_value(with_rules(json!([first.clone(), second]))).unwrap_err();
        assert!(
            error.to_string().contains("overlapping matches"),
            "overlapping error signals must refuse"
        );
    }
    assert!(ingest_value(with_rules(json!([
        first,
        json_rule(422, "credential_rejected", "/code", json!("BAD_KEY")),
        json_rule(429, "quota_exhausted", "/other", json!(0))
    ])))
    .is_ok());
    let header = |name: &str, index, value: &str| {
        json!({"status":429,"signal":"quota_exhausted","matches":{
        "kind":"header","name":name,"condition":{"kind":"comma_separated_element","index":index,"value":value}}})
    };
    assert!(ingest_value(with_rules(json!([
        header("X-Remaining", 1, "0"),
        header("x-remaining", 1, "0")
    ])))
    .is_err());
    assert!(ingest_value(with_rules(json!([
        header("X-Remaining", 1, "0"),
        header("x-remaining", 0, "0")
    ])))
    .is_err());
    assert!(ingest_value(with_rules(json!([
        header("X-Remaining", 1, "0"),
        header("x-remaining", 1, "1")
    ])))
    .is_ok());
}

#[test]
fn malformed_error_predicates_refuse_at_ingest() {
    for pointer in ["code", "/bad~", "/bad~2"] {
        assert!(ingest_value(with_rules(json!([json_rule(
            422,
            "no_results",
            pointer,
            json!(0)
        )])))
        .is_err());
    }
    for (name, value) in [("bad header", "0"), ("x-left", "0\r\ninjected: yes")] {
        let rule = json!({"status":429,"signal":"quota_exhausted","matches":{
            "kind":"header","name":name,"condition":{"kind":"exact","value":value}}});
        assert!(ingest_value(with_rules(json!([rule]))).is_err());
    }
    assert!(ingest_value(with_rules(json!([json_rule(
        999,
        "no_results",
        "/code",
        json!(0)
    )])))
    .is_err());
}

// Use a separate pre-change action type so this test verifies that older readers
// reject the new field. Deploy the binary before the catalog; restore the previous
// catalog before rolling the binary back.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct LegacyAction {
    name: String,
    risk: Risk,
    #[serde(default)]
    ask_first: bool,
    #[serde(default)]
    facade_only: bool,
    recipients: Option<Vec<String>>,
    input_schema: Option<Value>,
    reconciliation: Option<Reconciliation>,
    idempotency: Option<Idempotency>,
    poll: Option<PollShape>,
    http: Option<HttpOperation>,
}

#[test]
fn binary_before_catalog_and_catalog_before_rollback() {
    let exa = load_catalog("exa_rest.jsonc");
    for action in exa["actions_baseline"].as_array().unwrap() {
        assert!(serde_json::from_value::<LegacyAction>(action.clone()).is_ok());
        let parsed: ActionBaseline = serde_json::from_value(action.clone()).unwrap();
        assert!(parsed.error_signals.is_none());
        assert!(serde_json::to_value(parsed)
            .unwrap()
            .get("error_signals")
            .is_none());
    }
    let brave = load_catalog("brave_rest.jsonc");
    ingest_value(brave.clone()).unwrap();
    let action = brave["actions_baseline"][0].clone();
    assert!(
        action.get("error_signals").is_some(),
        "Brave catalog must declare its monthly quota signal"
    );
    let error = serde_json::from_value::<LegacyAction>(action.clone())
        .err()
        .expect("old binary must refuse new catalog");
    assert!(
        error.to_string().contains("unknown field `error_signals`"),
        "rollback must refuse the new catalog field"
    );
    let mut previous = action;
    previous.as_object_mut().unwrap().remove("error_signals");
    assert!(serde_json::from_value::<LegacyAction>(previous).is_ok());
}

#[test]
fn specialized_rest_shapes_refuse_ignored_signal_declarations() {
    for (catalog, name, shape) in [
        ("github_rest.jsonc", "github.repo.get", "read_envelope"),
        ("github_actions.jsonc", "github.actions.job_log", "job_log"),
        (
            "github_actions.jsonc",
            "github.actions.artifact_file",
            "artifact_file",
        ),
    ] {
        let mut manifest = load_catalog(catalog);
        ingest_value(manifest.clone()).unwrap();
        let action = manifest["actions_baseline"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["name"] == name)
            .unwrap();
        action["error_signals"] = json!([json_rule(
            403,
            "quota_exhausted",
            "/code",
            json!("REVIEWED")
        )]);
        let error = ingest_value(manifest).unwrap_err().to_string();
        assert!(
            error.contains(name)
                && error.contains(shape)
                && error.contains("error_signals are unsupported"),
            "specialized REST signal declarations must name the action and shape: {error}"
        );
    }
}
