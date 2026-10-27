//! GitHub bot request ingress; only calls with an owned receipt may reach the GitHub API.
pub mod effects;
mod expectation;
pub mod gates;
pub mod request_map;
pub mod run_scope;
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
    bot_request_scoped_with_expect(
        store,
        engine,
        caller_principal,
        scope,
        request,
        nonce,
        None,
        request_id,
        claim_owner,
        now,
    )
}

/// Like [`bot_request_scoped`], with an optional caller-pinned bot handle and
/// repository-binding generation. `expect` is not sent to GitHub.
#[allow(clippy::too_many_arguments)]
pub fn bot_request_scoped_with_expect<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    store: &PlexusStore,
    engine: &GovernanceEngine<C, T>,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    expect: Option<&Value>,
    request_id: &str,
    claim_owner: &str,
    now: i64,
) -> Value {
    bot_request_scoped_with_preconditions(
        store,
        engine,
        caller_principal,
        scope,
        request,
        nonce,
        expect,
        None,
        request_id,
        claim_owner,
        now,
    )
}

/// Like [`bot_request_scoped_with_expect`], with an optional run scope that
/// must remain a live child of the authoritative route scope before each write.
#[allow(clippy::too_many_arguments)]
pub fn bot_request_scoped_with_preconditions<
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
>(
    store: &PlexusStore,
    engine: &GovernanceEngine<C, T>,
    caller_principal: &str,
    scope: Option<&crate::scope::CallScope>,
    request: &Value,
    nonce: &str,
    expect: Option<&Value>,
    run_scope: Option<&Value>,
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
                expect,
                run_scope,
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
                // No receipt was claimed on this attempt, so resending the
                // identical request with the same nonce is safe.
                json!({"status":"refused","refusal_code":"store_failure","retry_same_nonce":true})
            };
            if let Err(error) = store.audit_github_facade(&reply) {
                eprintln!(error storage: "GitHub facade audit failed for nonce {nonce}, request {}: {error}", reply.request_id);
            }
            return json!({"result":outcome});
        }
    };
    let mut reply = gates::run_scoped_with_preconditions(
        store,
        caller_principal,
        scope,
        request,
        nonce,
        expect,
        run_scope,
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
        let mut outcome = row
            .outcome
            .clone()
            .unwrap_or_else(|| json!({"status":row.state,"refusal_code":row.refusal_code}));
        // Stored terminal refusals were finished as refused, so the same nonce
        // replays the refusal and a new attempt needs a new nonce. Older stored
        // outcomes written before the flag existed gain it here from that
        // terminal receipt state.
        if outcome.get("status").and_then(Value::as_str) == Some("refused")
            && outcome.get("retry_same_nonce").is_none()
        {
            outcome["retry_same_nonce"] = json!(false);
        }
        return outcome;
    }
    let code = reply.refusal_code.clone();
    // Every admission refusal here happens before the receipt is claimed,
    // including `nonce_in_flight`, which waits for the current owner, so
    // resending the identical request with the same nonce is safe. For
    // `nonce_in_flight` that means waiting for the current owner to resolve
    // the request, then retrying the same nonce.
    if code.as_deref() == Some("consent_unavailable") {
        return json!({"status":"refused","refusal_code":code,"code":code,
            "action":reply.action,"transmission":"not_sent","retry_same_nonce":true,
            "message":format!("consent_unavailable for action '{}': flows cannot request consent", reply.action)});
    }
    let mut value = json!({"status":"refused","refusal_code":code, "retry_same_nonce":true});
    if let Some(field) = &reply.invalid_request_field {
        value["code"] = json!("invalid_request");
        value["field"] = json!(field);
        value["transmission"] = json!("not_sent");
    }
    if let Some(dimension) = match code.as_deref() {
        Some("stale_authority{dimension: expected_handle}") => Some("expected_handle"),
        Some("stale_authority{dimension: expected_binding}") => Some("expected_binding"),
        _ => None,
    } {
        value["code"] = json!("stale_authority");
        value["dimension"] = json!(dimension);
        value["transmission"] = json!("not_sent");
    }
    if let Some(refusal) = &reply.grant_refusal {
        value["code"] = json!(refusal.code());
        value["detail"] = json!(refusal.detail());
    }
    if code.as_deref() == Some("delegating_scope_required") {
        value["scope_role"] = json!("route");
    }
    value
}
