use super::*;
use serde_json::json;

fn args(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().expect("object").clone()
}

/// The B1 rule: credential material may only enter through the binding
/// ceremony, never as a tool argument, because an ordinary tool arg puts a
/// bearer capability into request bytes, fleet carriage, deserialization
/// buffers, and span attributes.
///
/// This exists because the guard was previously provable only in the ALLOW
/// direction: a constant-accept mutation making `contains_secret_input`
/// always return false broke NO test, so nothing established that it ever
/// refuses anything. A suite whose vectors all share one expected outcome
/// cannot distinguish a real implementation from a constant returning it.
#[test]
fn secret_shaped_keys_are_rejected_at_the_top_level() {
    for key in [
        "credential_handle",
        "credential",
        "api_token",
        "client_secret",
        "password",
    ] {
        let value = args(json!({ "op": "connect", key: "ckh_pretend_secret" }));
        assert!(
            contains_secret_input(&value),
            "argument key '{key}' must be refused as credential material"
        );
    }
}

/// Nesting is the interesting case: a guard that only inspects top-level
/// keys is trivially bypassed by wrapping the secret one level down.
#[test]
fn secret_shaped_keys_are_rejected_when_nested() {
    let nested = args(json!({
        "op": "connect",
        "config": { "auth": { "token": "ckh_pretend_secret" } }
    }));
    assert!(
        contains_secret_input(&nested),
        "a secret nested inside an object must still be refused"
    );

    let in_array = args(json!({
        "op": "connect",
        "items": [ { "ok": 1 }, { "secret": "ckh_pretend_secret" } ]
    }));
    assert!(
        contains_secret_input(&in_array),
        "a secret nested inside an array element must still be refused"
    );
}

/// The tests above prove `contains_secret_input` refuses secret-shaped
/// keys. This one proves it also accepts ordinary arguments: an
/// implementation that refused everything would pass every test above
/// while making the facade unusable.
#[test]
fn ordinary_arguments_are_not_flagged() {
    let ordinary = args(json!({
        "op": "call",
        "connection": "conn-exa",
        "action": "web_search_exa",
        "args": { "query": "cortexkit", "numResults": 1 },
        "ticket_id": "ticket_abc123"
    }));
    assert!(
        !contains_secret_input(&ordinary),
        "a normal invoke must not be refused as credential material; \
             note ticket_id is deliberately NOT secret-shaped, since the \
             ceremony returns it precisely so the handle never travels"
    );
}
