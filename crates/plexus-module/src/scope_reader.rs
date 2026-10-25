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
            parent: scope.as_ref().and_then(|stamp| stamp.parent.clone()),
            expires_at_ms: scope.as_ref().and_then(|stamp| stamp.expires_at_ms),
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
#[path = "scope_reader_tests.rs"]
mod tests;
