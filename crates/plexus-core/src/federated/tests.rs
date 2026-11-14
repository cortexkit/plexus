use super::*;
use serde_json::Value;
use std::collections::BTreeSet;

fn canonical(claim: Option<&RemoteClaim>) -> CanonicalClaim {
    canonicalize_claim(claim).unwrap()
}

fn claim(value: Value) -> RemoteClaim {
    serde_json::from_value(value).unwrap()
}

#[test]
fn canonical_identities_are_literal_rfc8785_identity_objects() {
    let cases = [
        (
            json!({"kind":"agent","agent_id":"a:|\",","agent_name":"A"}),
            "agent",
            r#"{"agent_id":"a:|\","}"#,
        ),
        (
            json!({"kind":"run","agent_id":"a:|\",","agent_name":"A"}),
            "run",
            r#"{"agent_id":"a:|\","}"#,
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
            "on_behalf_of":"agent","agent_name":"A"}),
            "worker",
            r#"{"owner_module_id":"core","worker_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        ),
        (
            json!({"kind":"flow","flow_id":"flow:|\",","flow_version":9007199254740991_u64,
            "flow_install_id":"install","flow_code_hash":"c".repeat(64),"flow_name":"F"}),
            "flow",
            r#"{"flow_code_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","flow_id":"flow:|\",","flow_install_id":"install","flow_version":9007199254740991}"#,
        ),
    ];
    for (value, kind, expected) in cases {
        let normalized = canonical(Some(&claim(value.clone())));
        assert_eq!(normalized.claim_kind, kind);
        assert_eq!(normalized.canonical_claim_identity, expected);
        assert_eq!(
            serde_json::to_value(normalized.claim.unwrap()).unwrap(),
            value
        );
    }
    let absent = canonical(None);
    assert_eq!(
        (absent.claim_kind, absent.canonical_claim_identity.as_str()),
        ("", "")
    );
    assert!(absent.claim.is_none());
}

#[test]
fn delimiter_bearing_ids_and_agent_run_kinds_never_alias() {
    let ids = [
        "a:b", "a|b", "a\"b", "a,b", "a:b|c", "a|b:c", "a\",b", "a,\"b",
    ];
    let mut identities = BTreeSet::new();
    for kind in ["agent", "run"] {
        for id in ids {
            let normalized = canonical(Some(&claim(json!({"kind":kind,"agent_id":id}))));
            assert!(identities.insert((normalized.claim_kind, normalized.canonical_claim_identity)));
        }
    }
    assert_eq!(identities.len(), ids.len() * 2);
    let mut flows = BTreeSet::new();
    for (id, install) in [
        ("a:b", "c"),
        ("a", "b:c"),
        ("a|b", "c"),
        ("a", "b|c"),
        ("a\",b", "c"),
        ("a", "b\",c"),
        ("a,b", "c"),
        ("a", "b,c"),
    ] {
        let normalized = canonical(Some(&claim(json!({"kind":"flow","flow_id":id,
            "flow_version":1,"flow_install_id":install,"flow_code_hash":"d".repeat(64)}))));
        assert!(flows.insert(normalized.canonical_claim_identity));
    }
    assert_eq!(flows.len(), 8);
}

#[test]
fn display_only_metadata_never_changes_the_key() {
    let original =
        claim(json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64)}));
    let named = claim(
        json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
        "on_behalf_of":"Sage:|\",","agent_name":"Remote Sage"}),
    );
    assert_eq!(
        canonical(Some(&original)).canonical_claim_identity,
        canonical(Some(&named)).canonical_claim_identity
    );
    for kind in ["agent", "run", "flow"] {
        let mut bare = if kind == "flow" {
            json!({"kind":kind,"flow_id":"flow","flow_version":3,
                "flow_install_id":"install","flow_code_hash":"c".repeat(64)})
        } else {
            json!({"kind":kind,"agent_id":"Sage"})
        };
        let before = canonical(Some(&claim(bare.clone())));
        bare[if kind == "flow" {
            "flow_name"
        } else {
            "agent_name"
        }] = json!("Display");
        assert_eq!(
            canonical(Some(&claim(bare))).canonical_claim_identity,
            before.canonical_claim_identity
        );
    }
}

#[test]
fn names_are_dropped_from_storage_and_labels_under_the_plain_text_rule() {
    let mut invalid = vec!["".to_owned(), "x".repeat(81), "🦀".repeat(81)];
    for ch in [
        '\0', '\n', '\u{7f}', '\u{85}', '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}',
        '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ] {
        invalid.push(format!("name{ch}"));
    }
    for name in invalid {
        for (value, name_field, label) in [
            (
                json!({"kind":"agent","agent_id":"Sage","agent_name":name}),
                "agent_name",
                "Juniper · Sage",
            ),
            (
                json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
                "on_behalf_of":"Sage","agent_name":name}),
                "agent_name",
                "Juniper · worker for Sage",
            ),
            (
                json!({"kind":"flow","flow_id":"Morning-digest","flow_version":3,"flow_install_id":"install",
                "flow_code_hash":"c".repeat(64),"flow_name":name}),
                "flow_name",
                "Juniper · flow Morning-digest v3",
            ),
        ] {
            let clean = canonical(Some(&claim(value)));
            assert!(serde_json::to_value(&clean.claim)
                .unwrap()
                .get(name_field)
                .is_none());
            assert_eq!(
                clean.holder_label("Juniper", "exact_claim").as_deref(),
                Some(label)
            );
        }
    }
    let unattributed = canonical(Some(&claim(
        json!({"kind":"worker","owner_module_id":"core",
        "worker_ref":"b".repeat(64),"agent_name":"Must disappear"}),
    )));
    assert!(serde_json::to_value(&unattributed.claim)
        .unwrap()
        .get("agent_name")
        .is_none());
    assert_eq!(
        unattributed.holder_label("Juniper", "exact_claim").unwrap(),
        "Juniper · worker"
    );
    for name in ["x".repeat(80), "🦀".repeat(80), "é".to_owned()] {
        let clean = canonical(Some(&claim(
            json!({"kind":"agent","agent_id":"id","agent_name":name}),
        )));
        assert_eq!(
            serde_json::to_value(&clean.claim).unwrap()["agent_name"],
            name
        );
    }
}

#[test]
fn holder_labels_match_literal_contract_tables_and_cut_at_80_scalars() {
    let cases = [
        (json!({"kind":"agent","agent_id":"Sage"}), "Juniper · Sage"),
        (
            json!({"kind":"agent","agent_id":"Sage","agent_name":"Remote Sage"}),
            "Juniper · “Remote Sage” (Sage)",
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),"on_behalf_of":"Sage"}),
            "Juniper · worker for Sage",
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),"on_behalf_of":"Sage","agent_name":"Remote Sage"}),
            "Juniper · worker for “Remote Sage” (Sage)",
        ),
        (
            json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64)}),
            "Juniper · worker",
        ),
        (
            json!({"kind":"flow","flow_id":"Morning-digest","flow_version":3,"flow_install_id":"install","flow_code_hash":"c".repeat(64)}),
            "Juniper · flow Morning-digest v3",
        ),
        (
            json!({"kind":"flow","flow_id":"Morning-digest","flow_version":3,"flow_install_id":"install","flow_code_hash":"c".repeat(64),"flow_name":"Daily digest"}),
            "Juniper · flow “Daily digest” (Morning-digest) v3",
        ),
    ];
    for (value, expected) in cases {
        let normalized = canonical(Some(&claim(value)));
        assert_eq!(
            normalized.holder_label("Juniper", "exact_claim").as_deref(),
            Some(expected)
        );
        assert!(normalized.holder_label("Juniper", "unknown").is_none());
    }
    let absent = canonical(None);
    assert_eq!(
        absent.holder_label("Juniper", "claimless").unwrap(),
        "Juniper · any program"
    );
    assert_eq!(
        absent.holder_label("Juniper", "all_claims").unwrap(),
        "Juniper · everything on it"
    );
    let run = canonical(Some(&claim(json!({"kind":"run","agent_id":"Sage"}))));
    assert!(run.holder_label("Juniper", "exact_claim").is_none());
    assert!(run.holder_label("Juniper", "all_claims").is_none());
    assert_eq!(
        absent.holder_label(&"🦀".repeat(81), "claimless").unwrap(),
        "🦀".repeat(80)
    );
    // A caller can reconstruct the public value from storage; label rendering
    // must still recheck an old or invalid stored name.
    let reconstructed = CanonicalClaim {
        claim_kind: "agent",
        canonical_claim_identity: String::new(),
        claim: Some(claim(
            json!({"kind":"agent","agent_id":"Sage","agent_name":"bad\nname"}),
        )),
    };
    assert_eq!(
        reconstructed
            .holder_label("Juniper", "exact_claim")
            .unwrap(),
        "Juniper · Sage"
    );
}
