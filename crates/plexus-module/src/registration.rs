//! Self-claim minting on the registration connection owned by Plexus's reader.

use crate::{scope_reader::PendingControlReplies, wire, ModuleError};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use subc_client_rs::registration::{ClaimError, ClaimMinter};
use subc_protocol::claim::{ClaimMintReply, ClaimMintRequest, ClaimRateLimitedDetail};
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::mpsc;

const MINT_BUDGET: Duration = Duration::from_secs(5);

struct Minter {
    writer: mpsc::WeakSender<Frame>,
    pending: Arc<PendingControlReplies>,
    active: Arc<AtomicBool>,
    version: u8,
}

/// Marks the installed minter unavailable when its registration loop ends.
/// The installed minter holds no strong writer, so it cannot keep shutdown open.
pub(super) struct Lifetime {
    active: Arc<AtomicBool>,
    pending: Arc<PendingControlReplies>,
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.pending.clear();
    }
}

pub(super) fn install(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    pending: Arc<PendingControlReplies>,
) -> Result<Lifetime, ModuleError> {
    let active = Arc::new(AtomicBool::new(true));
    subc_client_rs::registration::install_claim_minter(Arc::new(Minter {
        writer: writer.downgrade(),
        pending: Arc::clone(&pending),
        active: Arc::clone(&active),
        version,
    }))
    .map_err(|error| ModuleError::Message(format!("install registration claim minter: {error}")))?;
    Ok(Lifetime { active, pending })
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
    async fn call(&self, request: &ClaimMintRequest) -> Result<Frame, ClaimError> {
        if !self.active.load(Ordering::Acquire) {
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
        // Close may race registration in the reply table. Never send after the
        // lifetime guard has invalidated the owner, even if a writer still lives.
        if !self.active.load(Ordering::Acquire) {
            return Err(ClaimError::Unavailable);
        }
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
        writer
            .send(frame)
            .await
            .map_err(|_| ClaimError::Unavailable)?;
        tokio::task::spawn_blocking(move || replies.recv())
            .await
            .map_err(|_| ClaimError::Unavailable)?
            .map_err(|_| ClaimError::Unavailable)
    }

    async fn mint_with_budget(
        &self,
        request: ClaimMintRequest,
    ) -> Result<ClaimMintReply, ClaimError> {
        loop {
            let reply = self.call(&request).await?;
            if reply.header.ty == FrameType::Error {
                let error: ErrorBody =
                    serde_json::from_slice(&reply.body).map_err(|_| ClaimError::Protocol)?;
                if error.code == subc_protocol::error_codes::CLAIM_RATE_LIMITED {
                    let detail: ClaimRateLimitedDetail =
                        serde_json::from_value(error.detail.ok_or(ClaimError::Protocol)?)
                            .map_err(|_| ClaimError::Protocol)?;
                    tokio::time::sleep(Duration::from_millis(detail.retry_after_ms)).await;
                    continue;
                }
                // The error names the failed step, without logging claims or
                // daemon-authored bodies. Never authenticate an outbound
                // connection with the launch nonce after claim minting fails.
                plexus_core::diag!(warn wire: "registration claim.mint refused: {}", error.code);
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
        if result.is_err() {
            plexus_core::diag!(warn wire: "registration claim.mint failed; outbound connection refused");
        }
        result
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
