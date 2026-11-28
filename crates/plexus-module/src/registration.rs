//! Self-claim minting on the registration connection owned by Plexus's reader.

use crate::{scope_reader::PendingControlReplies, wire, ModuleError};
use std::sync::Arc;
use std::time::Duration;
use subc_client_rs::registration::{ClaimError, ClaimMinter};
use subc_protocol::claim::{ClaimMintReply, ClaimMintRequest, ClaimRateLimitedDetail};
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::{mpsc, watch};

const MINT_BUDGET: Duration = Duration::from_secs(5);

pub(super) struct Minter {
    writer: mpsc::WeakSender<Frame>,
    pending: Arc<PendingControlReplies>,
    stopping: watch::Sender<bool>,
    version: u8,
}

/// Marks the installed minter unavailable when its registration loop shuts down.
/// The installed minter holds no strong writer, so it cannot keep shutdown open.
pub(super) struct Lifetime {
    stopping: watch::Sender<bool>,
    pending: Arc<PendingControlReplies>,
}

impl Lifetime {
    pub(super) fn begin_shutdown(&self) {
        self.stopping.send_replace(true);
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.begin_shutdown();
        self.pending.clear();
    }
}

pub(super) fn install(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    pending: Arc<PendingControlReplies>,
) -> Result<Lifetime, ModuleError> {
    let (minter, lifetime) = Minter::new(writer, version, pending);
    subc_client_rs::registration::install_claim_minter(Arc::new(minter)).map_err(|error| {
        ModuleError::Message(format!("install registration claim minter: {error}"))
    })?;
    Ok(lifetime)
}

struct PendingMint<'a> {
    pending: &'a PendingControlReplies,
    correlation: u64,
}

impl Drop for PendingMint<'_> {
    fn drop(&mut self) {
        // Cancellation also wakes a blocking receiver whose request was queued.
        self.pending.forget(self.correlation);
    }
}

impl Minter {
    pub(super) fn new(
        writer: &mpsc::Sender<Frame>,
        version: u8,
        pending: Arc<PendingControlReplies>,
    ) -> (Self, Lifetime) {
        let (stopping, _) = watch::channel(false);
        let minter = Self {
            writer: writer.downgrade(),
            pending: Arc::clone(&pending),
            stopping: stopping.clone(),
            version,
        };
        (minter, Lifetime { stopping, pending })
    }

    async fn call(
        &self,
        request: &ClaimMintRequest,
        stopping: &mut watch::Receiver<bool>,
    ) -> Result<Frame, ClaimError> {
        if *stopping.borrow() {
            return Err(ClaimError::Unavailable);
        }
        let writer = self.writer.upgrade().ok_or(ClaimError::Unavailable)?;
        let (correlation, replies) = self
            .pending
            .register()
            .map_err(|_| ClaimError::Unavailable)?;
        let _pending = PendingMint {
            pending: &self.pending,
            correlation,
        };
        let frame = Frame::build_with_version(
            self.version,
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            correlation,
            serde_json::to_vec(request).map_err(|_| ClaimError::Protocol)?,
        )
        .map_err(|_| ClaimError::Protocol)?;
        let permit = tokio::select! {
            biased;
            _ = stopping.wait_for(|&stopping| stopping) => return Err(ClaimError::Unavailable),
            permit = writer.reserve() => permit.map_err(|_| ClaimError::Unavailable)?,
        };
        {
            // Hold the read guard only while enqueuing, so shutdown cannot
            // start between the final check and the send.
            let stopping = stopping.borrow();
            if *stopping {
                return Err(ClaimError::Unavailable);
            }
            permit.send(frame);
        }
        tokio::task::spawn_blocking(move || replies.recv())
            .await
            .map_err(|_| ClaimError::Unavailable)?
            .map_err(|_| ClaimError::Unavailable)
    }

    async fn mint_with_budget(
        &self,
        request: ClaimMintRequest,
    ) -> Result<ClaimMintReply, ClaimError> {
        let mut stopping = self.stopping.subscribe();
        loop {
            let reply = self.call(&request, &mut stopping).await?;
            if reply.header.ty == FrameType::Error {
                let error: ErrorBody =
                    serde_json::from_slice(&reply.body).map_err(|_| ClaimError::Protocol)?;
                if error.code == subc_protocol::error_codes::CLAIM_RATE_LIMITED {
                    let detail: ClaimRateLimitedDetail =
                        serde_json::from_value(error.detail.ok_or(ClaimError::Protocol)?)
                            .map_err(|_| ClaimError::Protocol)?;
                    tokio::select! {
                        biased;
                        _ = stopping.wait_for(|&stopping| stopping) => {}
                        _ = tokio::time::sleep(Duration::from_millis(detail.retry_after_ms)) => continue,
                    }
                }
                return Err(ClaimError::Refused { code: error.code });
            }
            if reply.header.ty != FrameType::Response {
                return Err(ClaimError::Protocol);
            }
            return serde_json::from_slice(&reply.body).map_err(|_| ClaimError::Protocol);
        }
    }
}

#[subc_client_rs::async_trait]
impl ClaimMinter for Minter {
    async fn mint(&self, request: ClaimMintRequest) -> Result<ClaimMintReply, ClaimError> {
        let result = tokio::time::timeout(MINT_BUDGET, self.mint_with_budget(request))
            .await
            .unwrap_or(Err(ClaimError::Timeout));
        // Use one shutdown-state check for both warnings so a refusal racing
        // with shutdown is classified at just one log level.
        let stopping = self.stopping.borrow();
        if *stopping {
            if let Err(ClaimError::Refused { code }) = &result {
                plexus_core::diag!(debug wire: "registration claim.mint refused during shutdown: {code}");
            }
            // subc-client-rs stops the current reconnect loop on Unavailable.
            // Neither a fresh claim nor a retryable refusal should escape shutdown.
            return Err(ClaimError::Unavailable);
        }
        if let Err(error) = &result {
            // Report the code, never the daemon-authored error body or claim.
            if let ClaimError::Refused { code } = error {
                plexus_core::diag!(warn wire: "registration claim.mint refused: {code}");
            }
            plexus_core::diag!(warn wire: "registration claim.mint failed; outbound connection refused");
        }
        result
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
