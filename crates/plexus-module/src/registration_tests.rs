use super::*;
use crate::bounded::recv_within;
use serde_json::json;
use subc_protocol::claim::{Claim, ClaimPurpose};

fn seam() -> (Arc<Minter>, mpsc::Receiver<Frame>, Lifetime) {
    let (writer, frames) = mpsc::channel(4);
    let (minter, lifetime) = Minter::new(
        &writer,
        subc_protocol::PROTOCOL_VERSION,
        Arc::new(PendingControlReplies::default()),
    );
    // The test's registration connection owns the sender, not the minter.
    // Keep it alive until the receiver closes, as drain_writer does in run().
    tokio::spawn(async move { writer.closed().await });
    (Arc::new(minter), frames, lifetime)
}

async fn next_frame(frames: &mut mpsc::Receiver<Frame>) -> Frame {
    recv_within(frames.recv(), MINT_BUDGET, "claim.mint request").await
}

fn request() -> ClaimMintRequest {
    ClaimMintRequest::new(ClaimPurpose::SelfConnection)
}

fn answer(minter: &Minter, request: &Frame, ty: FrameType, body: serde_json::Value) {
    assert!(minter.pending.complete(
        Frame::build_with_version(
            request.header.ver,
            ty,
            wire::control_flags(),
            0,
            0,
            request.header.corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    ));
}

#[tokio::test]
async fn mints_self_claim_on_correlated_registration_control_lane() {
    let (minter, mut frames, _lifetime) = seam();
    let caller = Arc::clone(&minter);
    let mint = tokio::spawn(async move { caller.mint(request()).await });
    let frame = next_frame(&mut frames).await;
    assert_eq!(frame.header.ty, FrameType::Request);
    assert_eq!((frame.header.channel, frame.header.epoch), (0, 0));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&frame.body).unwrap(),
        json!({"op":"claim.mint","purpose":"self"})
    );
    answer(
        &minter,
        &frame,
        FrameType::Response,
        serde_json::to_value(ClaimMintReply::new(Claim::new("self-claim"), 0)).unwrap(),
    );
    // Wall-clock expiry is informational; the daemon validates presentation.
    assert_eq!(
        mint.await.unwrap().unwrap().claim.expose_secret(),
        "self-claim"
    );
}

#[tokio::test]
async fn mint_refusal_is_preserved_and_never_retried_as_nonce() {
    let (minter, mut frames, _lifetime) = seam();
    let caller = Arc::clone(&minter);
    let mint = tokio::spawn(async move { caller.mint(request()).await });
    let frame = next_frame(&mut frames).await;
    answer(
        &minter,
        &frame,
        FrameType::Error,
        json!({"code":"claim_not_permitted","message":"refused"}),
    );
    assert!(
        matches!(mint.await.unwrap(), Err(ClaimError::Refused { code }) if code == "claim_not_permitted")
    );
    assert!(frames.try_recv().is_err());
}

#[tokio::test]
async fn rejects_wrong_operation_and_malformed_claim_replies() {
    for body in [
        json!({"op":"catalog.update"}),
        json!({"op":"claim.present","claim":"wrong","expires_at_ms":1}),
    ] {
        let (minter, mut frames, _lifetime) = seam();
        let caller = Arc::clone(&minter);
        let mint = tokio::spawn(async move { caller.mint(request()).await });
        let frame = next_frame(&mut frames).await;
        answer(&minter, &frame, FrameType::Response, body);
        assert!(matches!(mint.await.unwrap(), Err(ClaimError::Protocol)));
    }
}

#[tokio::test]
async fn closing_registration_fails_pending_and_future_mints() {
    let (minter, mut frames, lifetime) = seam();
    let caller = Arc::clone(&minter);
    let mint = tokio::spawn(async move { caller.mint(request()).await });
    next_frame(&mut frames).await;
    drop(lifetime);
    assert!(matches!(mint.await.unwrap(), Err(ClaimError::Unavailable)));
    assert!(matches!(
        minter.mint(request()).await,
        Err(ClaimError::Unavailable)
    ));
    assert!(frames.try_recv().is_err());
}

#[tokio::test]
async fn rate_limit_delay_is_honored_within_one_bounded_budget() {
    let (minter, mut frames, _lifetime) = seam();
    let caller = Arc::clone(&minter);
    let mint = tokio::spawn(async move { caller.mint(request()).await });
    let first = next_frame(&mut frames).await;
    let limited_at = tokio::time::Instant::now();
    answer(
        &minter,
        &first,
        FrameType::Error,
        json!({"code":"claim_rate_limited","message":"wait","detail":{"retry_after_ms":100}}),
    );
    let second = next_frame(&mut frames).await;
    assert!(limited_at.elapsed() >= Duration::from_millis(100));
    assert_ne!(first.header.corr, second.header.corr);
    answer(
        &minter,
        &second,
        FrameType::Error,
        json!({"code":"claim_rate_limited","message":"wait","detail":{"retry_after_ms":10000}}),
    );
    assert!(matches!(mint.await.unwrap(), Err(ClaimError::Timeout)));
    assert!(frames.try_recv().is_err());
}
