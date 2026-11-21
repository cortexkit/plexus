use super::*;

const POLICY_HASH: &str = "85f93cc525185d7b40916c2800c0baccf00602262d0766c15f208c5b9e4c1df8";

fn paired_policy() -> Value {
    json!({"version":1,"policy_sha256":POLICY_HASH})
}

fn active_status(name: &str, policy: Option<Value>) -> Value {
    let mut reply = sample(name);
    if let Some(policy) = policy {
        reply["result"]["policy"] = policy;
    }
    reply
}

#[test]
fn active_status_object_form_decodes() {
    let reply = active_status("active_status.ready", Some(paired_policy()));
    let status: ActiveStatus = wire::response(reply).expect("paired policy object must decode");
    assert!(status.ready_for(29, &status.manifest_sha256));
    assert_eq!(
        status.policy,
        wire::PolicyPairing::Paired(wire::PairedPolicy {
            version: 1,
            policy_sha256: POLICY_HASH.into(),
        })
    );
}

#[test]
fn active_status_null_form_is_unpaired() {
    let reply = active_status("active_status.ready", Some(Value::Null));
    let status: ActiveStatus = wire::response(reply).unwrap();
    assert_eq!(status.policy, wire::PolicyPairing::Unpaired);
}

#[test]
fn active_status_rejects_malformed_policy_members() {
    for policy in [
        json!({"version":1,"policy_sha256":POLICY_HASH,"unexpected":true}),
        json!({"version":1.0,"policy_sha256":POLICY_HASH}),
        json!({"version":1,"policy_sha256":POLICY_HASH.to_ascii_uppercase()}),
        json!({"version":1,"policy_sha256":&POLICY_HASH[..63]}),
        json!({"version":1,"policy_sha256":format!("g{}", &POLICY_HASH[1..])}),
        json!([1, POLICY_HASH]),
    ] {
        let reply = active_status("active_status.ready", Some(policy.clone()));
        assert!(
            matches!(
                wire::response::<ActiveStatus>(reply),
                Err(Failure::InvalidReply)
            ),
            "accepted {policy}"
        );
    }
    let mut reply = active_status("active_status.ready", Some(paired_policy()));
    reply["result"]["unexpected"] = json!(true);
    assert!(matches!(
        wire::response::<ActiveStatus>(reply),
        Err(Failure::InvalidReply)
    ));
    let mut reply = active_status("active_status.ready", Some(paired_policy()));
    reply["result"]["computers"][0]["unexpected"] = json!(true);
    assert!(matches!(
        wire::response::<ActiveStatus>(reply),
        Err(Failure::InvalidReply)
    ));
}

#[test]
fn one_tap_binding_decision_is_independent_of_the_policy_member() {
    for policy in [None, Some(Value::Null), Some(paired_policy())] {
        let mut f = Fixture::new();
        f.discover();
        f.notice();
        assert_eq!(f.record().state, "awaiting_active");

        *f.vault.status.lock().unwrap() = active_status("active_status.not_ready", policy.clone());
        f.pass().follow_ready(NOW).unwrap();
        assert!(!f.bound(), "pending manifest with policy member {policy:?}");
        assert_eq!(f.record().state, "awaiting_active");

        *f.vault.status.lock().unwrap() = active_status("active_status.ready", policy.clone());
        f.pass().follow_ready(NOW).unwrap();
        assert!(f.bound(), "ready manifest with policy member {policy:?}");
        assert_eq!(f.record().state, "bound");
    }
}
