//! GitHub bot request ingress; only calls with an owned receipt may reach the GitHub API.
pub mod effects;
pub mod gates;
pub mod request_map;
pub mod taxonomy;
pub(crate) mod validation;
pub mod vendor_band;

use crate::credentials::CredentialSource;
use crate::github::receipt::Claim;
use crate::github::receipt::DEFAULT_CLAIM_LEASE_SECONDS;
use crate::governance::GovernanceEngine;
use crate::storage::PlexusStore;
use crate::transport::Transport;
use serde_json::{json, Value};

/// Send a GitHub App bot request on an agent's behalf.
///
/// The caller's route must have been opened under a session scope held by the
/// subc daemon (see [`crate::scope`]), and that scope must let the call act as
/// its agent; otherwise [`gates::run_scoped`] refuses before GitHub is
/// contacted. Before each write is sent, the scope is checked again with the
/// daemon, and the scope is recorded on the request's audit rows.
#[allow(clippy::too_many_arguments)]
pub fn bot_request_scoped<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    store: &PlexusStore,
    engine: &GovernanceEngine<C, T>,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    request_id: &str,
    claim_owner: &str,
    now: i64,
) -> Value {
    let generation = match store.github_repo_binding_generation() {
        Ok(generation) => generation,
        Err(error) => {
            eprintln!(warn storage: "GitHub binding generation preflight failed for request {request_id}, nonce {nonce}: {error}");
            let mut reply = gates::replay_scoped(
                store,
                caller_principal,
                scope,
                request,
                nonce,
                request_id,
                claim_owner,
                now,
                DEFAULT_CLAIM_LEASE_SECONDS,
            );
            let outcome = if matches!(
                reply.claim,
                Some(Claim::Replay(_) | Claim::Unknown(_) | Claim::InFlight)
            ) {
                replay_or_refusal(&reply)
            } else {
                reply.refusal_code = Some("store_failure".into());
                json!({"status":"refused","refusal_code":"store_failure"})
            };
            if let Err(error) = store.audit_github_facade(&reply) {
                eprintln!(error storage: "GitHub facade audit failed for nonce {nonce}, request {}: {error}", reply.request_id);
            }
            return json!({"result":outcome});
        }
    };
    let mut reply = gates::run_scoped(
        store,
        caller_principal,
        scope,
        request,
        nonce,
        request_id,
        claim_owner,
        now,
        DEFAULT_CLAIM_LEASE_SECONDS,
    );
    let outcome = match reply.claim.as_ref() {
        Some(Claim::PendingApproval(row)) => {
            json!({"status":"pending_approval", "action_request_id":row.action_request_id})
        }
        Some(Claim::Owned(_)) => {
            vendor_band::run(engine, store, &mut reply, nonce, claim_owner, now)
        }
        _ => replay_or_refusal(&reply),
    };
    if let Err(error) = store.audit_github_facade(&reply) {
        eprintln!(error storage: "GitHub facade audit failed for nonce {nonce}, request {}: {error}", reply.request_id);
    }
    json!({"result":outcome, "repo_binding_generation":generation})
}

fn replay_or_refusal(reply: &gates::GateReply) -> Value {
    if let Some(Claim::Replay(row) | Claim::Unknown(row)) = &reply.claim {
        return row
            .outcome
            .clone()
            .unwrap_or_else(|| json!({"status":row.state,"refusal_code":row.refusal_code}));
    }
    let code = reply.refusal_code.clone();
    if code.as_deref() == Some("consent_unavailable") {
        return json!({"status":"refused","refusal_code":code,"code":code,
            "action":reply.action,"transmission":"not_sent",
            "message":format!("consent_unavailable for action '{}': flows cannot request consent", reply.action)});
    }
    let mut value = json!({"status":"refused","refusal_code":code});
    if let Some(refusal) = &reply.grant_refusal {
        value["code"] = json!(refusal.code());
        value["detail"] = json!(refusal.detail());
    }
    value
}
