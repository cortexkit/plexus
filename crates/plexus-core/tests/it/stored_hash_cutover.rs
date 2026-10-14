//! Golden measurements for replacing the stored-value canonicalizer with JCS.

use plexus_core::jcs_sha256;
use serde_json::json;

#[test]
fn stored_catalog_schema_measurement_and_astral_control_remain_pinned() {
    let schema = json!({
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1}
        },
        "required": ["query"],
        "additionalProperties": false
    });
    assert_eq!(
        jcs_sha256(&schema).expect("catalog schema is JCS-compatible"),
        "sha256:fcbfd0211f4151d84cd42ec7b2c9e85cb7ee6d049baab672e3d64ce6f8b50cf7"
    );

    let astral_control = json!({"\u{E000}": 1, "\u{1F600}": 2});
    let jcs_digest = jcs_sha256(&astral_control).expect("astral control is JCS-compatible");
    assert_eq!(
        jcs_digest,
        "sha256:28c95d1bbb2209223307e62f489020e8f9e0cfa16adf2daf6d88127a1e8dd22a"
    );
    assert_ne!(
        jcs_digest, "sha256:871954531859c7572c6279f90eb83a594ddc3a289e8bdc28d2a84ffb8c1a1703",
        "the astral control must distinguish UTF-16 JCS ordering from scalar-value ordering"
    );
}
