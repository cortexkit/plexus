use super::*;

#[test]
fn discovery_retains_optional_vendor_annotations() {
    let tools = serde_json::json!({"result": {"tools": [
        {"name": "read_only", "inputSchema": {}, "annotations": {"readOnlyHint": true}},
        {"name": "absent", "inputSchema": {}},
        {"name": "disagrees", "inputSchema": {}, "annotations": {"readOnlyHint": false}},
        {"name": "empty", "inputSchema": {}, "annotations": {}},
        {"name": "invalid", "inputSchema": {}, "annotations": {"readOnlyHint": null}}
    ]}});
    let discovered: Vec<_> = tools_from_response(&tools)
        .unwrap()
        .iter()
        .map(|value| DiscoveredAction::from_value(value).unwrap())
        .collect();
    assert_eq!(
        discovered[0].annotations.as_ref().unwrap()["readOnlyHint"],
        true
    );
    assert_eq!(discovered[1].annotations, None);
    assert_eq!(
        discovered[2].annotations.as_ref().unwrap()["readOnlyHint"],
        false
    );
    assert_eq!(discovered[3].annotations, Some(serde_json::Map::new()));
    assert_eq!(
        discovered[4].annotations.as_ref().unwrap()["readOnlyHint"],
        Value::Null
    );
}
