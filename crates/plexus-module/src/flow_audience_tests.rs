use super::*;

fn workspace() -> Value {
    json!({"flow_id":"flow-a","audience":{"kind":"workspace","workspace_id":"ws-a","project_ids":["pj-a"]},"revision":"r1"})
}

#[test]
fn malformed_audience_contracts_fail_closed() {
    let mut malformed = Vec::new();
    let mut other_flow = workspace();
    other_flow["flow_id"] = json!("another-flow");
    malformed.push(other_flow);
    let mut absent_revision = workspace();
    absent_revision.as_object_mut().unwrap().remove("revision");
    malformed.push(absent_revision);
    let mut empty_revision = workspace();
    empty_revision["revision"] = json!("");
    malformed.push(empty_revision);
    for projects in [
        json!([]),
        json!(["pj-b", "pj-a"]),
        json!(["pj-a", "pj-a"]),
        json!([""]),
        json!([null]),
        json!([12]),
    ] {
        let mut reply = workspace();
        reply["audience"]["project_ids"] = projects;
        malformed.push(reply);
    }
    for reply in malformed {
        let parsed = parse("flow-a", reply);
        assert!(parsed.is_err(), "invalid audience reply must fail closed");
        assert_eq!(
            parsed.unwrap_err()["error"]["code"],
            "flow_audience_unavailable",
            "invalid audience reply must fail closed"
        );
    }
    assert_eq!(
        FlowAudiences::new(None).lookup("flow-a").unwrap_err()["error"]["code"],
        "flow_audience_unavailable"
    );
}

#[test]
fn explicit_null_audience_is_malformed() {
    let reply = json!({"flow_id":"flow-a","audience":null,"revision":"r1"});
    for reply in [reply.clone(), json!({"result":reply})] {
        let refusal = parse("flow-a", reply).expect_err("explicit null audience must be malformed");
        assert_eq!(refusal["error"]["code"], "flow_audience_unavailable");
        assert_eq!(refusal["error"]["transmission"], "not_sent");
        assert!(refusal["error"]["cause"]
            .as_str()
            .unwrap()
            .contains("malformed reply"));
    }
}
