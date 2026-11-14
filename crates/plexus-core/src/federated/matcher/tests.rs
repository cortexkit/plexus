use super::{match_rows, Call, Effect, Row};
use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::scope::RemoteClaim;

const NOW: i64 = 1_060_000;

fn claim(value: Value) -> RemoteClaim {
    serde_json::from_value(value).unwrap()
}

fn call(claim: Option<&RemoteClaim>) -> Call<'_> {
    Call {
        peer_fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_id: "pairing-invented-1",
        peer_class: "computer",
        claim,
        owner_principal: "direct",
        subject: "connection",
        scope: "read",
    }
}

fn row(claim: Option<&RemoteClaim>) -> Row<'_> {
    let call = call(claim);
    Row {
        peer_fingerprint: call.peer_fingerprint,
        pairing_id: call.pairing_id,
        peer_class: call.peer_class,
        selector: Some(if claim.is_some() {
            "exact_claim"
        } else {
            "claimless"
        }),
        claim,
        owner_principal: call.owner_principal,
        subject: call.subject,
        scope: call.scope,
        effect: Effect::Allow,
        expires_at_ms: None,
    }
}

fn outcome(rows: &[Row<'_>], call: &Call<'_>, now_ms: i64) -> Option<Effect> {
    match_rows(rows, call, now_ms).map(|index| rows[index].effect)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    tag: String,
    cases: Vec<VectorCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorCase {
    name: String,
    call: VectorCall,
    rows: Vec<VectorRow>,
    expected: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorCall {
    pairing_id: String,
    peer_class: String,
    claim: Option<RemoteClaim>,
    now_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorRow {
    pairing_id: String,
    peer_class: String,
    selector: Option<String>,
    claim: Option<RemoteClaim>,
    effect: Option<String>,
    expires_at_ms: Option<i64>,
}

#[test]
fn federated_precedence_vectors() {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../../plexus-module/tests/fixtures/permissions-federated-v1/federated-precedence.json"
    ))
    .unwrap();
    assert_eq!(vectors.tag, "permissions-v1");
    assert_eq!(vectors.cases.len(), 30);
    for case in vectors.cases {
        // The contract vector varies caller/selector/expiry only. Give every
        // row and call the same resource and fingerprint for those cases.
        let call = Call {
            pairing_id: &case.call.pairing_id,
            peer_class: &case.call.peer_class,
            ..call(case.call.claim.as_ref())
        };
        let mut rows: Vec<_> = case
            .rows
            .iter()
            .map(|input| Row {
                pairing_id: &input.pairing_id,
                peer_class: &input.peer_class,
                selector: input.selector.as_deref(),
                effect: match input.effect.as_deref() {
                    None => Effect::Allow,
                    Some("deny") => Effect::Deny,
                    other => panic!("unexpected vector effect {other:?}"),
                },
                expires_at_ms: input.expires_at_ms,
                ..row(input.claim.as_ref())
            })
            .collect();
        let expected = match case.expected.as_str() {
            "admit" => Some(Effect::Allow),
            "refuse" => Some(Effect::Deny),
            "none" => None,
            other => panic!("unexpected vector outcome {other}"),
        };
        assert_eq!(
            outcome(&rows, &call, case.call.now_ms),
            expected,
            "{}",
            case.name
        );
        rows.reverse();
        assert_eq!(
            outcome(&rows, &call, case.call.now_ms),
            expected,
            "{} reversed",
            case.name
        );
    }
}

#[test]
fn rows_require_their_own_caller_owner_subject_and_exact_scope() {
    let agent = claim(json!({"kind":"agent","agent_id":"Sage"}));
    for selector in ["exact_claim", "claimless", "all_claims"] {
        let claimed = (selector == "exact_claim").then_some(&agent);
        for effect in [Effect::Allow, Effect::Deny] {
            for scope in ["read", "write"] {
                let row = Row {
                    selector: Some(selector),
                    effect,
                    scope,
                    ..row(claimed)
                };
                let call = Call {
                    scope,
                    ..call(claimed)
                };
                assert_eq!(outcome(&[row], &call, NOW), Some(effect));
                let others = [
                    Call {
                        peer_fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        ..call
                    },
                    Call {
                        pairing_id: "other-pairing",
                        ..call
                    },
                    Call {
                        peer_class: "phone",
                        ..call
                    },
                    Call {
                        owner_principal: "reserved:callosum",
                        ..call
                    },
                    Call {
                        subject: "other-connection",
                        ..call
                    },
                    Call {
                        scope: if scope == "read" { "write" } else { "read" },
                        ..call
                    },
                ];
                for other in others {
                    assert_eq!(
                        outcome(&[row], &other, NOW),
                        None,
                        "{selector} {effect:?}: {call:?} must not cover {other:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn search_subjects_never_alias_connections_or_each_other() {
    for effect in [Effect::Allow, Effect::Deny] {
        for subject in ["web_search", "code_search"] {
            let row = Row {
                owner_principal: "",
                subject,
                effect,
                ..row(None)
            };
            let search = Call {
                owner_principal: "",
                subject,
                ..call(None)
            };
            let connection = Call {
                owner_principal: "direct",
                ..search
            };
            assert_eq!(outcome(&[row], &search, NOW), Some(effect));
            assert_eq!(outcome(&[row], &connection, NOW), None);
            assert_eq!(
                outcome(
                    &[Row {
                        owner_principal: "direct",
                        ..row
                    }],
                    &search,
                    NOW
                ),
                None
            );
            let other_search = Call {
                subject: if subject == "web_search" {
                    "code_search"
                } else {
                    "web_search"
                },
                ..search
            };
            assert_eq!(outcome(&[row], &other_search, NOW), None);
        }
    }
}

#[test]
fn missing_unknown_or_inconsistent_selectors_match_nothing() {
    let agent = claim(json!({"kind":"agent","agent_id":"Sage"}));
    for effect in [Effect::Allow, Effect::Deny] {
        for selector in [None, Some("future"), Some("")] {
            for stored_claim in [None, Some(&agent)] {
                let row = Row {
                    selector,
                    effect,
                    ..row(stored_claim)
                };
                for call_claim in [None, Some(&agent)] {
                    assert_eq!(outcome(&[row], &call(call_claim), NOW), None);
                }
            }
        }
        for selector in ["claimless", "all_claims"] {
            let row = Row {
                selector: Some(selector),
                effect,
                ..row(Some(&agent))
            };
            for call_claim in [None, Some(&agent)] {
                assert_eq!(outcome(&[row], &call(call_claim), NOW), None);
            }
        }
        let row = Row {
            selector: Some("exact_claim"),
            effect,
            ..row(None)
        };
        for call_claim in [None, Some(&agent)] {
            assert_eq!(outcome(&[row], &call(call_claim), NOW), None);
        }
    }
}

#[test]
fn run_claims_are_never_covered_by_either_effect_or_any_selector() {
    let run = claim(json!({"kind":"run","agent_id":"Sage"}));
    let agent = claim(json!({"kind":"agent","agent_id":"Sage"}));
    for effect in [Effect::Allow, Effect::Deny] {
        for selector in ["exact_claim", "claimless", "all_claims"] {
            for stored_claim in [None, Some(&run), Some(&agent)] {
                let row = Row {
                    selector: Some(selector),
                    effect,
                    ..row(stored_claim)
                };
                assert_eq!(outcome(&[row], &call(Some(&run)), NOW), None);
            }
        }
        assert_eq!(
            outcome(
                &[Row {
                    effect,
                    ..row(Some(&run))
                }],
                &call(Some(&agent)),
                NOW
            ),
            None
        );
    }
}

#[test]
fn expiry_is_exclusive_for_both_effects_and_all_selectors() {
    let agent = claim(json!({"kind":"agent","agent_id":"Sage"}));
    for effect in [Effect::Allow, Effect::Deny] {
        for selector in ["exact_claim", "claimless", "all_claims"] {
            let claimed = (selector == "exact_claim").then_some(&agent);
            let row = Row {
                selector: Some(selector),
                effect,
                expires_at_ms: Some(NOW),
                ..row(claimed)
            };
            assert_eq!(outcome(&[row], &call(claimed), NOW - 1), Some(effect));
            assert_eq!(outcome(&[row], &call(claimed), NOW), None);
            assert_eq!(outcome(&[row], &call(claimed), NOW + 1), None);
            assert_eq!(
                outcome(
                    &[Row {
                        expires_at_ms: None,
                        ..row
                    }],
                    &call(claimed),
                    i64::MAX
                ),
                Some(effect)
            );
        }
    }
}

#[test]
fn exact_claims_ignore_absent_or_changed_display_fields_for_both_effects() {
    for (bare, named, renamed) in [
        (
            json!({"kind":"agent","agent_id":"Sage"}),
            json!({"kind":"agent","agent_id":"Sage","agent_name":"Old name"}),
            json!({"kind":"agent","agent_id":"Sage","agent_name":"New name"}),
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64)}),
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
                "on_behalf_of":"Sage","agent_name":"Old name"}),
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
                "on_behalf_of":"Fern","agent_name":"New name"}),
        ),
        (
            json!({"kind":"flow","flow_id":"digest","flow_version":3,
                "flow_install_id":"install","flow_code_hash":"c".repeat(64)}),
            json!({"kind":"flow","flow_id":"digest","flow_version":3,
                "flow_install_id":"install","flow_code_hash":"c".repeat(64),"flow_name":"Old name"}),
            json!({"kind":"flow","flow_id":"digest","flow_version":3,
                "flow_install_id":"install","flow_code_hash":"c".repeat(64),"flow_name":"New name"}),
        ),
    ] {
        let claims = [claim(bare), claim(named), claim(renamed)];
        for stored in &claims {
            for current in &claims {
                for effect in [Effect::Allow, Effect::Deny] {
                    assert_eq!(
                        outcome(
                            &[Row {
                                effect,
                                ..row(Some(stored))
                            }],
                            &call(Some(current)),
                            NOW
                        ),
                        Some(effect)
                    );
                }
            }
        }
    }
}

#[test]
fn exact_claims_compare_every_identity_field_and_never_inherit_attribution() {
    for (original, changes) in [
        (
            json!({"kind":"agent","agent_id":"Sage"}),
            vec![("agent_id", json!("Fern"))],
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64)}),
            vec![
                ("owner_module_id", json!("other")),
                ("worker_ref", json!("c".repeat(64))),
            ],
        ),
        (
            json!({"kind":"flow","flow_id":"digest","flow_version":3,
                "flow_install_id":"install","flow_code_hash":"c".repeat(64)}),
            vec![
                ("flow_id", json!("other")),
                ("flow_version", json!(4)),
                ("flow_install_id", json!("other")),
                ("flow_code_hash", json!("d".repeat(64))),
            ],
        ),
    ] {
        let stored = claim(original.clone());
        for (field, value) in changes {
            let mut different = original.clone();
            different[field] = value;
            let different = claim(different);
            for effect in [Effect::Allow, Effect::Deny] {
                assert_eq!(
                    outcome(
                        &[Row {
                            effect,
                            ..row(Some(&stored))
                        }],
                        &call(Some(&different)),
                        NOW
                    ),
                    None,
                    "{field}"
                );
            }
        }
    }
    let agent = claim(json!({"kind":"agent","agent_id":"Sage"}));
    let worker = claim(
        json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
        "on_behalf_of":"Sage"}),
    );
    for effect in [Effect::Allow, Effect::Deny] {
        assert_eq!(
            outcome(
                &[Row {
                    effect,
                    ..row(Some(&agent))
                }],
                &call(Some(&worker)),
                NOW
            ),
            None
        );
        assert_eq!(
            outcome(
                &[Row {
                    effect,
                    ..row(Some(&worker))
                }],
                &call(Some(&agent)),
                NOW
            ),
            None
        );
    }
}

#[test]
fn peer_class_is_compared_not_hardcoded_by_the_pure_matcher() {
    for effect in [Effect::Allow, Effect::Deny] {
        let row = Row {
            peer_class: "phone",
            effect,
            ..row(None)
        };
        assert_eq!(
            outcome(
                &[row],
                &Call {
                    peer_class: "phone",
                    ..call(None)
                },
                NOW
            ),
            Some(effect)
        );
    }
}

#[test]
fn selected_index_pins_the_winning_row_and_expired_specific_rows_do_not_shadow() {
    let agent = claim(json!({"kind":"agent","agent_id":"Sage"}));
    let call = call(Some(&agent));
    let broad = Row {
        selector: Some("all_claims"),
        effect: Effect::Deny,
        ..row(None)
    };
    let specific = row(Some(&agent));
    let rows = [
        broad,
        specific,
        specific,
        Row {
            effect: Effect::Deny,
            ..specific
        },
    ];
    assert_eq!(match_rows(&rows, &call, NOW), Some(3));
    assert_eq!(match_rows(&rows[..3], &call, NOW), Some(1));
    assert_eq!(
        match_rows(
            &[
                broad,
                Row {
                    expires_at_ms: Some(NOW),
                    ..specific
                }
            ],
            &call,
            NOW
        ),
        Some(0)
    );
}
