//! `scope.describe` over this module's own subc connection.
//!
//! A module-originated control request is a REQUEST frame on channel 0 of the
//! module's registered connection; subc answers with a RESPONSE (or ERROR)
//! frame on channel 0 carrying the same correlation id. The dispatch loop hands
//! every such reply to [`PendingControlReplies::complete`], which wakes the
//! caller waiting on that correlation id.
//!
//! The reader is synchronous because governance is: it is asked from inside a
//! blocking section, just before a stored approval would be claimed for
//! sending, and that decision needs the answer first.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Mutex};
use std::time::Duration;

use plexus_core::scope::{
    parse_scope_owner, CallScope, ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus,
};
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::mpsc;

/// How long one `scope.describe` may take before it counts as unanswered.
/// An unanswered read holds the approval unsent; it is never read as "live".
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The first correlation id used for module-originated control requests. HELLO
/// uses 1; starting far above it keeps the two from ever meeting.
const FIRST_CONTROL_CORRELATION: u64 = 1 << 32;

/// Callers waiting on a reply to a control request this module sent, by
/// correlation id.
pub struct PendingControlReplies {
    next: AtomicU64,
    waiting: Mutex<HashMap<u64, std_mpsc::Sender<Frame>>>,
}

impl Default for PendingControlReplies {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(FIRST_CONTROL_CORRELATION),
            waiting: Mutex::new(HashMap::new()),
        }
    }
}

impl PendingControlReplies {
    pub(crate) fn clear(&self) {
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.clear();
        }
    }

    pub(crate) fn register(&self) -> Result<(u64, std_mpsc::Receiver<Frame>), ScopeReadError> {
        let correlation = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = std_mpsc::channel();
        self.waiting
            .lock()
            .map_err(|_| ScopeReadError("control reply table was poisoned".to_string()))?
            .insert(correlation, sender);
        Ok((correlation, receiver))
    }

    pub(crate) fn forget(&self, correlation: u64) {
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.remove(&correlation);
        }
    }

    /// Deliver a channel-0 RESPONSE or ERROR frame to the caller waiting on its
    /// correlation id. Returns false when nobody is waiting (a late reply after
    /// a timeout, or a reply to something this table did not send).
    pub fn complete(&self, frame: Frame) -> bool {
        let sender = match self.waiting.lock() {
            Ok(mut waiting) => waiting.remove(&frame.header.corr),
            Err(_) => None,
        };
        match sender {
            Some(sender) => sender.send(frame).is_ok(),
            None => false,
        }
    }
}

/// Reads scopes from the subc daemon over this module's own connection.
pub struct DaemonScopeReader {
    writer: mpsc::Sender<Frame>,
    version: u8,
    pending: std::sync::Arc<PendingControlReplies>,
    timeout: Duration,
}

impl DaemonScopeReader {
    pub fn new(
        writer: mpsc::Sender<Frame>,
        version: u8,
        pending: std::sync::Arc<PendingControlReplies>,
    ) -> Self {
        Self {
            writer,
            version,
            pending,
            timeout: DESCRIBE_TIMEOUT,
        }
    }

    /// A shorter wait than [`DESCRIBE_TIMEOUT`], so a test of the unanswered
    /// case does not sit out the production deadline.
    #[cfg(test)]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn describe_blocking(
        &self,
        owner: &str,
        scope_ref: &str,
    ) -> Result<ScopeDescription, ScopeReadError> {
        let owner_principal = parse_scope_owner(owner).ok_or_else(|| {
            ScopeReadError(format!(
                "'{owner}' is not a module principal that can own a scope"
            ))
        })?;
        let body = serde_json::to_vec(&ModuleControlRequestFromModule::ScopeDescribe {
            owner: owner_principal,
            scope_ref: scope_ref.to_string(),
        })
        .map_err(|error| ScopeReadError(format!("encode scope.describe: {error}")))?;
        // One deadline covers both queuing the request and waiting for the
        // reply: a full egress queue must not hold this caller past the
        // timeout any more than a silent daemon may.
        let deadline = std::time::Instant::now() + self.timeout;
        let (correlation, replies) = self.pending.register()?;
        let frame = Frame::build_with_version(
            self.version,
            FrameType::Request,
            crate::wire::control_flags(),
            0,
            0,
            correlation,
            body,
        )
        .map_err(|error| {
            self.pending.forget(correlation);
            ScopeReadError(format!("build scope.describe frame: {error}"))
        })?;
        let mut frame = frame;
        loop {
            match self.writer.try_send(frame) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending.forget(correlation);
                    return Err(ScopeReadError(
                        "the daemon connection is closed".to_string(),
                    ));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    if std::time::Instant::now() >= deadline {
                        self.pending.forget(correlation);
                        return Err(ScopeReadError(
                            "the daemon connection's send queue stayed full past the scope.describe deadline"
                                .to_string(),
                        ));
                    }
                    frame = returned;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let reply = match replies.recv_timeout(remaining) {
            Ok(reply) => reply,
            Err(_) => {
                self.pending.forget(correlation);
                return Err(ScopeReadError(
                    "the daemon did not answer scope.describe in time".to_string(),
                ));
            }
        };
        describe_reply(&reply)
    }
}

impl ScopeReader for DaemonScopeReader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        // Waiting on the reply blocks this thread. Callers already run inside
        // the module's blocking sections; entering one here as well keeps a
        // call from an async worker from stalling the runtime.
        crate::blocking_section(|| self.describe_blocking(owner, scope_ref))
    }
}

/// Decode subc's reply to a `scope.describe`.
fn describe_reply(reply: &Frame) -> Result<ScopeDescription, ScopeReadError> {
    if reply.header.ty == FrameType::Error {
        let detail = serde_json::from_slice::<ErrorBody>(&reply.body)
            .map(|body| format!("{}: {}", body.code, body.message))
            .unwrap_or_else(|_| "an unreadable error body".to_string());
        return Err(ScopeReadError(format!("scope.describe refused: {detail}")));
    }
    match serde_json::from_slice::<ModuleControlResponseToModule>(&reply.body) {
        Ok(ModuleControlResponseToModule::ScopeDescribe {
            status,
            owner_synced,
            owner_configured,
            scope,
            ..
        }) => Ok(ScopeDescription {
            status: match status {
                subc_protocol::scope::ScopeStatus::Live => ScopeStatus::Live,
                subc_protocol::scope::ScopeStatus::Ended => ScopeStatus::Ended,
                subc_protocol::scope::ScopeStatus::NotLive => ScopeStatus::NotLive,
            },
            owner_synced,
            owner_configured,
            live: scope.as_ref().map(CallScope::from_stamp),
        }),
        Ok(_) => Err(ScopeReadError(
            "subc answered scope.describe with a different operation".to_string(),
        )),
        Err(error) => Err(ScopeReadError(format!(
            "unreadable scope.describe reply: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
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
    async fn an_unknown_scope_is_ended_under_a_synced_owner_and_unverifiable_under_an_unconfigured_one(
    ) {
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
}
