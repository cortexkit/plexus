use super::*;
#[test]
fn pending_consent_has_the_exact_content_v1_shape() {
    let reply = with_call_tool_result(
        Some(manifest::INVOKE_TOOL),
        denial_response(&plexus_core::Denial::AccessPending {
            elicitation_id: "el_42".into(),
            service: "Mock Chat".into(),
            action: "Post a message".into(),
        }),
    );
    let text = "Waiting for the user to approve Mock Chat Post a message. The request has gone to them. End your turn now; you will be resumed with the answer, and then you should run this same call again.";
    assert_eq!(
        reply,
        json!({"isError":true, "content":[{"type":"text","text":text}],
            "structuredContent":{"success":false,"code":"access_pending","message":text,"text":text,"elicitation_id":"el_42"}})
    );
}
