//! RFC 8785 (JCS) golden vectors for parity with the external decision plane.
//!
//! This file is a cross-implementation spec artifact: each vector pins input
//! JSON, expected canonical bytes (hex), and the `sha256:<hex>` digest produced
//! by `plexus_core::jcs`, so another JCS implementation can be checked against
//! the same bytes.

use plexus_core::jcs::{canonicalize, jcs_sha256};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct GoldenVector {
    /// Human-readable name; kept stable so seats can cite vectors by id.
    name: &'static str,
    /// Source of the vector (RFC section or plexus-shaped scenario).
    source: &'static str,
    input: Value,
    /// Expected JCS UTF-8 bytes, encoded as lowercase hex (no spaces).
    expected_hex: String,
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let clean = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).expect("hex nibble"))
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_json(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|error| panic!("fixture JSON: {error}: {raw}"))
}

fn assert_vector(vector: &GoldenVector) {
    let actual = canonicalize(&vector.input)
        .unwrap_or_else(|error| panic!("{}: canonicalize failed: {error}", vector.name));
    let expected = hex_decode(&vector.expected_hex);
    assert_eq!(
        actual,
        expected,
        "{} ({})\n actual utf8: {}\n expected utf8: {}\n actual hex: {}\n expected hex: {}",
        vector.name,
        vector.source,
        String::from_utf8_lossy(&actual),
        String::from_utf8_lossy(&expected),
        hex::encode(&actual),
        vector.expected_hex,
    );
    let digest = jcs_sha256(&vector.input).expect("jcs_sha256");
    assert_eq!(
        digest,
        format!("sha256:{}", sha256_hex(&expected)),
        "{}: sha256 mismatch",
        vector.name
    );
}

fn rfc_vectors() -> Vec<GoldenVector> {
    // Expected hex for the §3.2.2 sample is the cyberphone/RFC reference encoding.
    let rfc_322_expected = "\
        7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e\
        756d62657273223a5b3333333333333333332e333333333333332c31652b33302c\
        342e352c302e3030322c31652d32375d2c22737472696e67223a22e282ac245c75\
        303030665c6e4127425c225c5c5c5c5c222f227d"
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();

    let sorting_expected = hex_of(
        concat!(
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"",
            "\u{0080}",
            "\":\"Control\",\"",
            "ö",
            "\":\"Latin Small Letter O With Diaeresis\",\"",
            "€",
            "\":\"Euro Sign\",\"",
            "😀",
            "\":\"Emoji: Grinning Face\",\"",
            "דּ",
            "\":\"Hebrew Letter Dalet With Dagesh\"}"
        )
        .as_bytes(),
    );

    vec![
        GoldenVector {
            name: "rfc8785_section_3_2_2_primitives",
            source: "RFC 8785 §3.2.2 / §3.2.3 combined sample",
            // Literal RFC input (including the original number spellings).
            input: parse_json(
                r#"{
                  "numbers": [333333333.33333329, 1E30, 4.50,
                              2e-3, 0.000000000000000000000000001],
                  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
                  "literals": [null, true, false]
                }"#,
            ),
            expected_hex: rfc_322_expected,
        },
        GoldenVector {
            name: "rfc8785_section_3_2_3_key_order",
            source: "RFC 8785 §3.2.3 property sorting sample",
            input: parse_json(
                r#"{
                  "\u20ac": "Euro Sign",
                  "\r": "Carriage Return",
                  "\ufb33": "Hebrew Letter Dalet With Dagesh",
                  "1": "One",
                  "\ud83d\ude00": "Emoji: Grinning Face",
                  "\u0080": "Control",
                  "\u00f6": "Latin Small Letter O With Diaeresis"
                }"#,
            ),
            expected_hex: sorting_expected,
        },
        GoldenVector {
            name: "rfc8785_appendix_b_number_series",
            source: "RFC 8785 Appendix B selected samples + task series",
            input: parse_json(
                r#"{
                  "values": [0.0, 1e30, 1e-7, 0.000001, 100000000000000000000, 1e21, 4.5, 0.002]
                }"#,
            ),
            expected_hex: hex_of(
                br#"{"values":[0,1e+30,1e-7,0.000001,100000000000000000000,1e+21,4.5,0.002]}"#,
            ),
        },
        GoldenVector {
            name: "rfc8785_string_escaping",
            source: "RFC 8785 §3.2.2.2 string rules",
            input: parse_json(r#""\"\\\b\t\n\f\r/plain""#),
            expected_hex: hex_of(br#""\"\\\b\t\n\f\r/plain""#),
        },
    ]
}

fn plexus_vectors() -> Vec<GoldenVector> {
    vec![
        GoldenVector {
            name: "plexus_notion_create_page_args",
            source: "Batch A Notion create_page-shaped args",
            input: json!({
                "workspace": "ws_ops",
                "parent": "page_drafts",
                "title": "Weekly status",
                "properties": {
                    "Status": "Draft",
                    "Owner": "agent.alpha"
                }
            }),
            expected_hex: hex_of(
                concat!(
                    r#"{"parent":"page_drafts","properties":{"Owner":"agent.alpha","Status":"Draft"},"#,
                    r#""title":"Weekly status","workspace":"ws_ops"}"#
                )
                .as_bytes(),
            ),
        },
        GoldenVector {
            name: "plexus_linear_create_issue_args",
            source: "Batch A Linear create_issue-shaped args",
            input: json!({
                "team": "ENG",
                "title": "Fix flaky gate",
                "project": "plexus",
                "labels": ["infra", "batch-a"],
                "priority": 2
            }),
            expected_hex: hex_of(
                concat!(
                    r#"{"labels":["infra","batch-a"],"priority":2,"project":"plexus","#,
                    r#""team":"ENG","title":"Fix flaky gate"}"#
                )
                .as_bytes(),
            ),
        },
        GoldenVector {
            name: "plexus_sentry_comment_issue_args",
            source: "Batch A Sentry comment_issue-shaped args",
            input: json!({
                "org": "cortexkit",
                "project": "plexus",
                "issue": "PLEXUS-123",
                "body": "Reproduced on main; attaching logs."
            }),
            expected_hex: hex_of(
                concat!(
                    r#"{"body":"Reproduced on main; attaching logs.","issue":"PLEXUS-123","#,
                    r#""org":"cortexkit","project":"plexus"}"#
                )
                .as_bytes(),
            ),
        },
        GoldenVector {
            name: "plexus_grant_hash_object",
            source: "Decision-plane grant_hash contract object shape (decision_id + pins)",
            input: json!({
                "decision_id": "dec_org_00000001",
                "app_key": "notion",
                "action": "create_page",
                "args_snapshot_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "schema_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }),
            expected_hex: hex_of(
                concat!(
                    r#"{"action":"create_page","app_key":"notion","args_snapshot_hash":"#,
                    r#""sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
                    r#""decision_id":"dec_org_00000001","schema_hash":"#,
                    r#""sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#
                )
                .as_bytes(),
            ),
        },
        GoldenVector {
            name: "plexus_nested_resource_filters",
            source: "Nested object + array args used at resource-filter gate",
            input: json!({
                "team": "core",
                "filters": {
                    "status": ["open", "triage"],
                    "assignee": null
                },
                "limit": 25
            }),
            expected_hex: hex_of(
                br#"{"filters":{"assignee":null,"status":["open","triage"]},"limit":25,"team":"core"}"#,
            ),
        },
        GoldenVector {
            name: "plexus_empty_object_and_array",
            source: "Empty containers remain distinct under JCS",
            input: json!({
                "empty_object": {},
                "empty_array": [],
                "flag": false
            }),
            expected_hex: hex_of(br#"{"empty_array":[],"empty_object":{},"flag":false}"#),
        },
    ]
}

#[test]
fn rfc_8785_golden_vectors() {
    for vector in rfc_vectors() {
        assert_vector(&vector);
    }
}

#[test]
fn plexus_shaped_golden_vectors() {
    for vector in plexus_vectors() {
        assert_vector(&vector);
    }
}

#[test]
fn golden_file_lists_at_least_six_plexus_vectors() {
    assert!(
        plexus_vectors().len() >= 6,
        "parity pack must carry 6+ plexus-shaped vectors"
    );
}
