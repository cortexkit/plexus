use super::*;
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
use subc_protocol::Principal;

fn reply(ty: FrameType, correlation: u64, body: Vec<u8>) -> Frame {
    Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        ty,
        crate::wire::control_flags(),
        0,
        0,
        correlation,
        body,
    )
    .expect("frame")
}

#[tokio::test(flavor = "multi_thread")]
async fn describe_sends_one_request_and_reads_the_matching_reply() {
    let (writer, mut outbound) = mpsc::channel::<Frame>(4);
    let pending = std::sync::Arc::new(PendingControlReplies::default());
    let reader = DaemonScopeReader::new(
        writer,
        subc_protocol::PROTOCOL_VERSION,
        std::sync::Arc::clone(&pending),
    );
    let answer = tokio::spawn({
        let pending = std::sync::Arc::clone(&pending);
        async move {
            let request = crate::bounded::recv_within(
                outbound.recv(),
                Duration::from_secs(5),
                "scope.describe request frame",
            )
            .await;
            let sent: ModuleControlRequestFromModule =
                serde_json::from_slice(&request.body).expect("request body");
            assert_eq!(
                sent,
                ModuleControlRequestFromModule::ScopeDescribe {
                    owner: Principal::Reserved {
                        module_id: "prefrontal-core".into()
                    },
                    scope_ref: "head-1".into(),
                }
            );
            assert_eq!(request.header.channel, 0);
            let body = serde_json::to_vec(&ModuleControlResponseToModule::ScopeDescribe {
                status: subc_protocol::scope::ScopeStatus::Live,
                scope_epoch: Some(7),
                daemon_incarnation: "inc".into(),
                owner_synced: true,
                owner_configured: true,
                scope: Some(
                    ScopeStamp::new(
                        Principal::Reserved {
                            module_id: "prefrontal-core".into(),
                        },
                        "head-1",
                        7,
                        ScopeKind::Head,
                    )
                    .with_attributes(
                        ScopeAttributes::new()
                            .with_agent_id(Some("agent-a".into()))
                            .with_delegates(true),
                    )
                    .with_owner_authorized(true),
                ),
            })
            .expect("reply body");
            assert!(
                !pending.complete(reply(FrameType::Response, request.header.corr + 1, vec![])),
                "a reply to another correlation id wakes nobody"
            );
            assert!(pending.complete(reply(FrameType::Response, request.header.corr, body)));
        }
    });
    let described = tokio::task::spawn_blocking(move || {
        reader.describe_blocking("reserved:prefrontal-core", "head-1")
    })
    .await
    .expect("join")
    .expect("described");
    answer.await.expect("responder");
    assert_eq!(described.status, ScopeStatus::Live);
    let live = described.live.expect("live stamp");
    assert_eq!(live.scope_epoch, 7);
    assert_eq!(live.acting_agent(), Some("agent-a"));
}

#[test]
fn an_error_reply_is_an_unanswered_read() {
    let body = serde_json::to_vec(&ErrorBody::new("not_registered", "no")).expect("body");
    let error = describe_reply(&reply(FrameType::Error, 9, body)).unwrap_err();
    assert!(error.0.contains("not_registered"), "{error:?}");
}

// The tests below run the reader against each way the daemon can answer,
// or fail to, and then put the outcome through the two rules Plexus
// applies to it: the running-call recheck (`recheck_call_scope`) and the
// stored-approval rule (`approval_scope_verdict`). They pin the mapping at
// the seam the engine sees, not only the decoder's output.

/// What the responder does with the one request the reader sends.
enum Answer {
    /// Complete it with this frame type and body.
    Frame(FrameType, Vec<u8>),
    /// Never answer.
    Silence,
}

/// Run one `describe` against a responder that answers as told. With
/// `closed`, the outbound channel is closed before the reader sends.
async fn describe_against(
    answer: Answer,
    closed: bool,
) -> Result<ScopeDescription, ScopeReadError> {
    let (writer, mut outbound) = mpsc::channel::<Frame>(4);
    let pending = std::sync::Arc::new(PendingControlReplies::default());
    let timeout = Duration::from_millis(200);
    let silence = matches!(answer, Answer::Silence) && !closed;
    let reader = DaemonScopeReader::new(
        writer,
        subc_protocol::PROTOCOL_VERSION,
        std::sync::Arc::clone(&pending),
    )
    .with_timeout(timeout);
    if closed {
        outbound.close();
    }
    let responder = tokio::spawn(async move {
        let Some(request) = crate::bounded::recv_option_within(
            outbound.recv(),
            Duration::from_secs(5),
            "scope.describe responder frame",
        )
        .await
        else {
            return;
        };
        match answer {
            Answer::Frame(ty, body) => {
                pending.complete(reply(ty, request.header.corr, body));
            }
            Answer::Silence => {
                // Held until the reader has given up, so silence is a
                // timeout rather than a closed channel.
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
    });
    let result = tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        let result = reader.describe_blocking("reserved:prefrontal-core", "head-1");
        if silence {
            // Measure before joining the responder, whose keepalive sleep
            // must not masquerade as time spent waiting for the reply.
            assert!(
                started.elapsed() >= timeout,
                "silence must reach the timeout"
            );
        }
        result
    })
    .await
    .expect("join");
    responder.await.expect("responder");
    result
}

fn describe_body(
    status: subc_protocol::scope::ScopeStatus,
    owner_synced: bool,
    owner_configured: bool,
) -> Vec<u8> {
    serde_json::to_vec(&ModuleControlResponseToModule::ScopeDescribe {
        status,
        scope_epoch: None,
        daemon_incarnation: "inc".into(),
        owner_synced,
        owner_configured,
        scope: None,
    })
    .expect("reply body")
}

/// The stamp a running call was bound under, and the same binding as a
/// stored approval.
fn bound_stamp() -> (CallScope, plexus_core::scope::ApprovalScope) {
    let stamp = CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "head-1".into(),
        scope_epoch: 7,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        delegates: false,
        owner_authorized: false,
        flow_id: None,
    };
    let approval = plexus_core::scope::ApprovalScope {
        request_id: "req-1".into(),
        owner: stamp.owner.clone(),
        scope_ref: stamp.scope_ref.clone(),
        scope_epoch: stamp.scope_epoch,
        agent_id: None,
        acted_as_agent: false,
        expires_at: i64::MAX,
    };
    (stamp, approval)
}

/// A read the daemon did not answer: the reader returns an error, never a
/// description, and both rules treat it as undecidable.
fn assert_unanswered(result: Result<ScopeDescription, ScopeReadError>, case: &str) {
    use plexus_core::scope::{
        approval_scope_verdict, recheck_call_scope, ApprovalScopeVerdict, SCOPE_UNAVAILABLE,
        SCOPE_UNVERIFIABLE,
    };
    let error = match result {
        Err(error) => error,
        Ok(described) => panic!("{case}: an unanswered read produced {described:?}"),
    };
    let (stamp, approval) = bound_stamp();
    assert_eq!(
        recheck_call_scope(&stamp, Err(&error)),
        Err(SCOPE_UNVERIFIABLE),
        "{case}"
    );
    assert_eq!(
        approval_scope_verdict(&approval, Err(&error)),
        ApprovalScopeVerdict::Hold(SCOPE_UNAVAILABLE),
        "{case}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_describe_nobody_answers_times_out_as_unverifiable_never_live() {
    let result = describe_against(Answer::Silence, false).await;
    assert!(
        result
            .as_ref()
            .expect_err("silence must time out")
            .0
            .contains("did not answer scope.describe in time"),
        "silence must be a timeout: {result:?}"
    );
    assert_unanswered(result, "timeout");
}

/// A send queue that stays full is bounded by the same deadline as the
/// reply: the read gives up as unverifiable instead of blocking forever.
#[test]
fn a_full_send_queue_is_bounded_by_the_describe_deadline() {
    let (writer, _outbound) = mpsc::channel::<Frame>(1);
    let filler = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        crate::wire::control_flags(),
        0,
        0,
        1,
        Vec::new(),
    )
    .expect("filler frame");
    writer.try_send(filler).expect("fill the queue");
    let reader = DaemonScopeReader::new(
        writer,
        subc_protocol::PROTOCOL_VERSION,
        std::sync::Arc::new(PendingControlReplies::default()),
    )
    .with_timeout(Duration::from_millis(100));
    let (done, finished) = std_mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(reader.describe_blocking("reserved:prefrontal-core", "head-1"));
    });
    let result = finished
        .recv_timeout(Duration::from_secs(5))
        .expect("a full send queue must not block the read past its deadline");
    assert_unanswered(result, "full send queue");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_describe_on_a_closed_connection_is_unverifiable() {
    assert_unanswered(
        describe_against(Answer::Silence, true).await,
        "connection closed",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_or_mismatched_reply_is_unverifiable() {
    assert_unanswered(
        describe_against(
            Answer::Frame(FrameType::Response, b"{not json".to_vec()),
            false,
        )
        .await,
        "unreadable body",
    );
    let other_op =
        serde_json::to_vec(&ModuleControlResponseToModule::CatalogUpdate {}).expect("body");
    assert_unanswered(
        describe_against(Answer::Frame(FrameType::Response, other_op), false).await,
        "reply to a different operation",
    );
}

/// A daemon that does not know `scope.describe` refuses the frame, and one
/// that does refuses a module it has not registered. Either refusal leaves
/// the scope unconfirmed.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_describe_is_unverifiable() {
    for code in [
        "unsupported_control_frame",
        "not_registered",
        "invalid_control_body",
    ] {
        let body = serde_json::to_vec(&ErrorBody::new(code, "refused")).expect("body");
        assert_unanswered(
            describe_against(Answer::Frame(FrameType::Error, body), false).await,
            code,
        );
    }
}

/// The daemon answers an unknown ref with a `not_live` reply, not a
/// refusal. An owner's first sync after the daemon starts lists every scope
/// it holds, so once it has synced, a ref it left out is gone. Only modules
/// in the daemon's roster may sync at all, so under an owner outside the
/// roster the ref can never be confirmed.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_scope_is_ended_under_a_synced_owner_and_unverifiable_under_an_unconfigured_one()
{
    use plexus_core::scope::{recheck_call_scope, SCOPE_ENDED, SCOPE_UNVERIFIABLE};
    let (stamp, _) = bound_stamp();
    let synced_owner = describe_against(
        Answer::Frame(
            FrameType::Response,
            describe_body(subc_protocol::scope::ScopeStatus::NotLive, true, true),
        ),
        false,
    )
    .await
    .expect("a not_live reply is an answer");
    assert_eq!(synced_owner.status, ScopeStatus::NotLive);
    assert_eq!(
        recheck_call_scope(&stamp, Ok(&synced_owner)),
        Err(SCOPE_ENDED)
    );
    let unconfigured_owner = describe_against(
        Answer::Frame(
            FrameType::Response,
            describe_body(subc_protocol::scope::ScopeStatus::NotLive, false, false),
        ),
        false,
    )
    .await
    .expect("a not_live reply is an answer");
    assert_eq!(
        recheck_call_scope(&stamp, Ok(&unconfigured_owner)),
        Err(SCOPE_UNVERIFIABLE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_that_has_not_synced_yields_the_retryable_not_synced() {
    use plexus_core::scope::{
        approval_scope_verdict, recheck_call_scope, ApprovalScopeVerdict, SCOPE_NOT_SYNCED,
    };
    let described = describe_against(
        Answer::Frame(
            FrameType::Response,
            describe_body(subc_protocol::scope::ScopeStatus::NotLive, false, true),
        ),
        false,
    )
    .await
    .expect("a not_live reply is an answer");
    assert_eq!(described.status, ScopeStatus::NotLive);
    assert!(!described.owner_synced);
    assert!(described.owner_configured);
    assert_eq!(described.live, None);
    let (stamp, approval) = bound_stamp();
    assert_eq!(
        recheck_call_scope(&stamp, Ok(&described)),
        Err(SCOPE_NOT_SYNCED)
    );
    assert_eq!(
        approval_scope_verdict(&approval, Ok(&described)),
        ApprovalScopeVerdict::Hold(SCOPE_NOT_SYNCED)
    );
}
