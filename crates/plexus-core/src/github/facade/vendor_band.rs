//! Revalidate receipt authority, authorize ownership reads, and dispatch each
//! repository-bound mutation only after those reads complete.
use super::{effects, gates, taxonomy};
use crate::credentials::CredentialSource;
use crate::github::pagination::{self, WalkError};
use crate::github::receipt::{Claim, Receipt};
use crate::github::resolver::{self, DeclaredArgsError};
use crate::governance::{
    facade_origin, AuthorizationRequest, CatalogDenial, Denial, GovernanceEngine, ReceiptApproval,
    ReceiptClaim,
};
use crate::storage::PlexusStore;
use crate::transport::Transport;
use serde_json::{json, Value};

fn receipt_update(
    result: Result<bool, cortexkit_store::StoreError>,
    operation: &str,
    agent: &str,
    nonce: &str,
) {
    if let Err(error) = result {
        eprintln!(warn storage: "GitHub receipt {agent}/{nonce} {operation} failed: {error}");
    }
}

fn stale(store: &PlexusStore, reply: &gates::GateReply, row: &Receipt) -> Result<(), String> {
    let handle = reply.handle.as_ref().ok_or("store_failure")?;
    let mapped = reply.mapped.as_ref().ok_or("store_failure")?;
    let repository = mapped.canonical["repository"]
        .as_str()
        .ok_or("repository_unbound")?;
    let current = gates::GateStore::authority(
        store,
        handle,
        &reply.caller_principal,
        &row.agent_id,
        mapped,
        repository,
    )
    .map_err(|code| {
        if code == "module_grant_absent" {
            crate::grant_refusal::GrantRefusal::new(
                crate::grant_refusal::GrantTarget::new(
                    crate::grant_refusal::Layer::Module,
                    &reply.caller_principal,
                    "github",
                    Some(&handle.connection_id),
                    mapped.action,
                ),
                crate::grant_refusal::Cause::Missing,
            )
            .wire()
            .to_string()
        } else {
            code
        }
    })?;
    let original = &row.authority_baseline;
    for (field, dimension) in [
        ("handle_enabled", "handle_disabled"),
        ("repo_binding_generation", "repository_rebound"),
        ("agent_grant_generation", "agent_grant_revoked"),
        ("module_grant_generation", "module_grant_revoked"),
        ("policy_effect_hash", "policy_changed"),
        ("credential_generation", "credential_rotated"),
        ("app_handle_generation", "handle_row_changed"),
    ] {
        if original[field] != current.baseline[field] {
            return Err(format!("stale_authority{{dimension: {dimension}}}"));
        }
    }
    Ok(())
}

fn approval(row: &Receipt) -> Option<ReceiptApproval> {
    row.action_request_id.as_ref().map(|id| ReceiptApproval {
        action_request_id: id.clone(),
        agent_id: row.agent_id.clone(),
    })
}

/// Narrow one leg's arguments to what its catalog action declares. The request
/// arguments carry every field of the bot request (a close's comment, an
/// edit's labels), and only the leg that owns a field may send it.
fn leg_args<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    handle: &gates::Handle,
    action: &str,
    args: &Value,
    gate: &str,
) -> Result<Value, String> {
    resolver::declared_args(
        engine.store(),
        &handle.connection_principal,
        &handle.connection_id,
        action,
        args,
    )
    .map_err(|error| match error {
        DeclaredArgsError::Store => "store_failure".into(),
        DeclaredArgsError::NotDeclared => {
            taxonomy::denial(&Denial::Catalog(CatalogDenial::NotFound), gate)
        }
    })
}

fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    reply: &gates::GateReply,
    row: &Receipt,
    action: &str,
    args: Value,
) -> Result<Value, String> {
    let handle = reply.handle.as_ref().ok_or("store_failure")?;
    let args = leg_args(engine, handle, action, &args, "G8")?;
    let request =
        AuthorizationRequest::new(&reply.caller_principal, &handle.connection_id, action, args)
            .with_bound_agent(&row.agent_id, &handle.app_handle_id);
    let request = with_reply_scope(request, reply);
    let request = facade_origin::request(request, approval(row));
    let reservation = engine
        .authorize(request)
        .map_err(|denial| taxonomy::denial(&denial, "G8"))?;
    taxonomy::dispatch(engine.revalidate_and_dispatch(&reservation).outcome)
}

/// Carry the caller's daemon scope onto a governed leg for its audit rows. The
/// facade's agent layer comes from the delegating scope's resolved bot
/// binding, passed as the bound agent, so the scope is attribution only here.
fn with_reply_scope(
    request: AuthorizationRequest,
    reply: &gates::GateReply,
) -> AuthorizationRequest {
    match reply.scope.as_ref() {
        Some(scope) => request.with_scope_attribution_only(scope.clone()),
        None => request,
    }
}

/// Copy only the named fields out of a GitHub response body, each under its
/// reply name and only when GitHub sent it with the expected JSON type. The
/// reply never carries the rest of the body (author, text, node ids), and a
/// field GitHub left out is left out of the reply rather than invented.
fn pick(body: &Value, fields: &[(&str, &str)]) -> Value {
    let mut picked = serde_json::Map::new();
    for &(source, target) in fields {
        let Some(value) = body.get(source) else {
            continue;
        };
        let typed = match source {
            "id" | "number" => value.is_u64(),
            "draft" | "isDraft" => value.is_boolean(),
            // GitHub sends null for an issue closed or reopened without a reason.
            "state_reason" => value.is_string() || value.is_null(),
            _ => value.is_string(),
        };
        if typed {
            picked.insert(target.into(), value.clone());
        }
    }
    Value::Object(picked)
}

const URL_AND_ID: &[(&str, &str)] = &[("html_url", "url"), ("id", "id")];

/// Write legs whose GitHub response is the issue itself. The label legs answer
/// with the issue's label list instead, so they cannot name the issue.
const ISSUE_RETURNING_LEGS: &[&str] = &[
    "edit_issue",
    "add_issue_assignees",
    "remove_issue_assignees",
];

/// The caller-facing result of a completed request, taken from the response of
/// the leg that defines the request's outcome. `legs` pairs each planned write
/// with its GitHub response, in dispatch order; `issue_read` is the issue as
/// read before an issue edit, used when no leg returned the issue.
fn projection(kind: &str, legs: &[(&str, Value)], issue_read: Option<&Value>) -> Value {
    let last = legs.last().map(|(_, body)| body).unwrap_or(&Value::Null);
    match kind {
        "reaction" => pick(last, &[("id", "id"), ("content", "content")]),
        "close" | "reopen" => {
            // The state change is always the final leg; a comment, when the
            // request carried one, was posted before it.
            let mut result = pick(
                last,
                &[("state", "state"), ("state_reason", "state_reason")],
            );
            if let Some((_, comment)) = legs
                .iter()
                .rev()
                .skip(1)
                .find(|(action, _)| *action == "add_issue_comment")
            {
                result["comment"] = pick(comment, URL_AND_ID);
            }
            result
        }
        "issue_edit" => {
            let issue = legs
                .iter()
                .rev()
                .find(|(action, _)| ISSUE_RETURNING_LEGS.contains(action))
                .map(|(_, body)| body)
                .or(issue_read)
                .unwrap_or(&Value::Null);
            pick(issue, URL_AND_ID)
        }
        "pr_create" => pick(
            last,
            &[
                ("number", "number"),
                ("html_url", "url"),
                ("state", "state"),
                ("draft", "draft"),
            ],
        ),
        "pr_ready" | "pr_draft" => match legs.last() {
            Some((_, body)) => pick(
                body,
                &[("url", "url"), ("number", "number"), ("isDraft", "draft")],
            ),
            None => pick(
                issue_read.unwrap_or(&Value::Null),
                &[
                    ("html_url", "url"),
                    ("number", "number"),
                    ("draft", "draft"),
                ],
            ),
        },
        _ => pick(last, URL_AND_ID),
    }
}

/// Stop a scoped request before a write because its scope no longer holds.
/// The reply names the writes already sent (in order), since those stay sent.
///
/// A definitive answer (`scope_ended`, `delegation_withdrawn`) is recorded on
/// the receipt, so a same-nonce retry replays the refusal and sends nothing.
/// `scope_not_synced` is retryable: carriers hold with backoff until the owner
/// syncs. It releases this worker's claim without recording a refusal, so a
/// same-nonce retry skips writes already sent and resumes at the first unsent
/// one. `scope_unverifiable` is final to carriers, but retains the same uncached
/// receipt behavior in case the caller explicitly retries.
#[allow(clippy::too_many_arguments)]
fn stop_for_scope(
    store: &PlexusStore,
    reply: &mut gates::GateReply,
    agent: &str,
    nonce: &str,
    owner: &str,
    now: i64,
    code: &str,
    sent: &[(&str, Value)],
) -> Value {
    eprintln!(warn governance:
        "bot_request {} stopped before a write ({code}); writes already sent: {}",
        reply.request_id,
        sent.len()
    );
    reply.gate = "G10";
    reply.refusal_code = Some(code.to_string());
    let legs_sent: Vec<&str> = sent.iter().map(|(action, _)| *action).collect();
    let value = json!({"status":"refused", "refusal_code":code, "legs_sent":legs_sent});
    if matches!(
        code,
        crate::scope::SCOPE_UNVERIFIABLE | crate::scope::SCOPE_NOT_SYNCED
    ) {
        receipt_update(
            store.release_github_claim_between_legs(agent, nonce, owner, now),
            "release",
            agent,
            nonce,
        );
    } else {
        receipt_update(
            store.finish_github_facade(agent, nonce, owner, "refused", &value, Some(code), now),
            "finish refusal",
            agent,
            nonce,
        );
    }
    value
}

fn owned(value: &Value, login: &str) -> bool {
    value.pointer("/user/login").and_then(Value::as_str) == Some(login)
        && value.pointer("/user/type").and_then(Value::as_str) == Some("Bot")
}

fn pr_state_kind(kind: &str) -> bool {
    matches!(kind, "pr_ready" | "pr_draft")
}

/// GraphQL reports application failures in successful HTTP responses. Reuse the
/// REST validation refusal vocabulary, discarding messages and all unknown fields.
fn pr_state_response(kind: &str, value: Value) -> Result<Value, String> {
    let mutation = if kind == "pr_ready" {
        "markPullRequestReadyForReview"
    } else {
        "convertPullRequestToDraft"
    };
    if value.get("errors").is_some() {
        let errors = super::validation::errors(&value.to_string());
        return Err(if errors.is_empty() {
            "vendor_rejected{status: 422}".into()
        } else {
            format!(
                "vendor_rejected{{status: 422, errors: {}}}",
                serde_json::to_string(&errors).expect("validation errors are JSON")
            )
        });
    }
    let pr = &value["data"][mutation]["pullRequest"];
    if !pr["isDraft"].is_boolean() || !pr["number"].is_u64() || !pr["url"].is_string() {
        return Err("vendor_rejected{status: 422}".into());
    }
    Ok(pr.clone())
}

/// A claimed receipt is required to enter this code. Pre-dispatch reads lack
/// that claim, so they cannot record that a GitHub mutation was attempted.
pub fn run<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    store: &PlexusStore,
    reply: &mut gates::GateReply,
    nonce: &str,
    owner: &str,
    now: i64,
) -> Value {
    let Some(Claim::Owned(row)) = reply.claim.as_ref() else {
        return json!({"status":"pending"});
    };
    let row = row.clone();
    let agent = row.agent_id.clone();
    let fail = |reply: &mut gates::GateReply, gate, code: String| {
        reply.gate = gate;
        let typed = serde_json::from_str::<Value>(&code)
            .ok()
            .filter(|value| value.get("detail").is_some());
        let code = typed
            .as_ref()
            .and_then(|value| value["code"].as_str())
            .unwrap_or(&code)
            .to_owned();
        reply.refusal_code = Some(code.clone());
        let mut value = json!({"status":"refused", "refusal_code":code});
        if let Some(typed) = typed {
            value["code"] = typed["code"].clone();
            value["detail"] = typed["detail"].clone();
        }
        if code == "nonce_in_flight" {
            // Another worker may still complete the write for this nonce.
            // Keep the receipt pending for a later owner to resume unfinished effects.
        } else if code.contains("StoreFailure")
            || code == "store_failure"
            || matches!(
                code.as_str(),
                "pre_dispatch_read_incomplete{reason: lease_expired}"
                    | "pre_dispatch_read_incomplete{reason: invalid_response}"
                    // Nothing was sent and the vault may answer on a retry,
                    // so the same nonce must be able to run again.
                    | crate::github::credential::UNRESOLVABLE_TRANSIENT
            )
        {
            // These refusals happen before a write is sent or after its
            // outcome is recorded, so no write is in doubt and the claim is
            // released for a same-nonce retry. Writes an earlier leg already
            // completed keep their recorded outcome and are not sent again;
            // the retry resumes at the first unsent leg. If a write may have
            // been sent without a recorded outcome, the release is refused and
            // the claim stays until lease expiry settles it as outcome_unknown.
            receipt_update(
                store.release_github_claim_between_legs(&agent, nonce, owner, now),
                "release",
                &agent,
                nonce,
            );
        } else {
            receipt_update(
                store.finish_github_facade(
                    &agent,
                    nonce,
                    owner,
                    "refused",
                    &value,
                    Some(&code),
                    now,
                ),
                "finish refusal",
                &agent,
                nonce,
            );
        }
        value
    };
    if let Err(code) = stale(store, reply, &row) {
        return fail(reply, "G8", code);
    }
    let Some(mapped) = reply.mapped.as_ref() else {
        return fail(reply, "G8", "store_failure".into());
    };
    let mapped = mapped.clone();
    let Some(handle) = reply.handle.as_ref() else {
        return fail(reply, "G8", "store_failure".into());
    };
    let handle = handle.clone();
    let slug = handle
        .credential_reference
        .strip_prefix("github_app:")
        .unwrap_or("");
    let login = format!("{slug}[bot]");
    let mut args = mapped.args.clone();
    let mut completed = Vec::new();
    if mapped.request_kind == "comment_edit_last" {
        let start = now;
        let mut read_error = None;
        let walk = pagination::walk(
            effects::list_read(),
            start,
            crate::storage::now_ms,
            |page| {
                let mut page_args = args.clone();
                page_args["page"] = json!(page.page);
                page_args["per_page"] = json!(page.per_page);
                match read(engine, reply, &row, "github.issue_comments.list", page_args) {
                    Ok(value) => Ok(value),
                    Err(code) => {
                        read_error = Some(code);
                        Err(WalkError::ReadFailed)
                    }
                }
            },
        );
        let walk = match walk {
            Ok(walk) => walk,
            Err(error) => {
                return fail(
                    reply,
                    "G8",
                    read_error.unwrap_or_else(|| match error {
                        WalkError::Incomplete => {
                            "pre_dispatch_read_incomplete{reason: page_bound}".into()
                        }
                        WalkError::LeaseExpired => {
                            "pre_dispatch_read_incomplete{reason: lease_expired}".into()
                        }
                        WalkError::InvalidResponse | WalkError::ReadFailed => {
                            "pre_dispatch_read_incomplete{reason: invalid_response}".into()
                        }
                    }),
                )
            }
        };
        if !pagination::may_dispatch(
            &[pagination::ListRead::IssueComments],
            std::slice::from_ref(&walk),
        ) {
            return fail(
                reply,
                "G8",
                "pre_dispatch_read_incomplete{reason: page_bound}".into(),
            );
        }
        let Some(comment) = effects::comment_from_walk(&walk, slug) else {
            return fail(reply, "G8", "not_present".into());
        };
        let Some(id) = comment["id"].as_u64() else {
            return fail(reply, "G8", "not_present".into());
        };
        args["comment_id"] = json!(id);
        completed.push("github.issue_comments.list");
    }
    let mut issue_read = None;
    for &action in mapped.reads {
        if action == "github.issue_comments.list" {
            continue;
        }
        let value = match read(engine, reply, &row, action, args.clone()) {
            Ok(value) => value,
            Err(code)
                if mapped.request_kind == "issue_edit"
                    && code == "vendor_rejected{status: 404}" =>
            {
                return fail(reply, "G8", "not_present".into());
            }
            Err(code) => return fail(reply, "G8", code),
        };
        completed.push(action);
        if action == "github.issue.get" || action == "github.pull_request.get" {
            issue_read = Some(value.clone());
        }
        if mapped.request_kind == "comment_edit_last" && value["id"] != args["comment_id"] {
            return fail(reply, "G8", "not_present".into());
        }
        if pr_state_kind(&mapped.request_kind) && !owned(&value, &login) {
            return fail(reply, "G8", "pr_edit_not_own".into());
        }
        if matches!(
            mapped.request_kind.as_str(),
            "comment_edit_last" | "comment_edit" | "issue_edit"
        ) && !owned(&value, &login)
        {
            let code = if mapped.request_kind == "issue_edit" {
                "issue_edit_not_own".into()
            } else {
                format!(
                    "comment_author_mismatch{{expected_login: {login}, actual_login: {}}}",
                    value
                        .pointer("/user/login")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                )
            };
            return fail(reply, "G8", code);
        }
    }
    if let Err(code) = stale(store, reply, &row) {
        return fail(reply, "G9", code);
    }
    let proof = effects::OwnershipProof::new(&mapped.request_kind, completed, true);
    let mut legs = effects::plan(&mapped);
    if pr_state_kind(&mapped.request_kind) {
        let pr = issue_read.as_ref().unwrap_or(&Value::Null);
        let (Some(draft), Some(node_id)) = (
            pr["draft"].as_bool(),
            pr["node_id"].as_str().filter(|id| !id.is_empty()),
        ) else {
            return fail(
                reply,
                "G9",
                "pre_dispatch_read_incomplete{reason: invalid_response}".into(),
            );
        };
        if !pr["number"].is_u64() || !pr["html_url"].is_string() {
            return fail(
                reply,
                "G9",
                "pre_dispatch_read_incomplete{reason: invalid_response}".into(),
            );
        }
        if draft == (mapped.request_kind == "pr_draft")
            && row
                .effects
                .iter()
                .all(|effect| effect.dispatch_attempted_at.is_none())
        {
            legs.clear();
        } else {
            // Repository keys stay on the governed call for resource filtering;
            // the REST transport sends only the GraphQL variables and fixed query.
            legs = vec![(
                mapped.action,
                json!({"owner":args["owner"], "repo":args["repo"], "variables":{"pullRequestId":node_id}}),
            )];
        }
    }
    if mapped.request_kind == "comment_edit_last" {
        for (_, leg) in &mut legs {
            leg["comment_id"] = args["comment_id"].clone();
        }
    }
    // Each write's GitHub response, kept to build the caller's result. A leg an
    // earlier owner of this receipt already finished contributes the response
    // recorded on its effect.
    let mut responses: Vec<(&str, Value)> = Vec::new();
    for (index, (action, args)) in legs.into_iter().enumerate() {
        if let Some(outcome) = row
            .effects
            .get(index)
            .and_then(|effect| effect.outcome.as_ref())
        {
            responses.push((action, outcome.clone()));
            continue;
        }
        let args = match leg_args(engine, &handle, action, &args, "G10") {
            Ok(args) => args,
            Err(code) => return fail(reply, "G10", code),
        };
        // A request sent under a scope re-reads that scope, uncached, before
        // every write it has not sent yet, so a session revoked mid-request
        // sends nothing more. Pre-dispatch reads are not re-checked.
        if let Some(scope) = reply.scope.clone() {
            let answer = engine.describe_scope(&scope.owner, &scope.scope_ref);
            if let Err(code) = crate::scope::recheck_call_scope(&scope, answer.as_ref()) {
                if let Err(error) = &answer {
                    eprintln!(warn governance:
                        "scope read for bot_request {} failed: {}",
                        reply.request_id, error.0
                    );
                }
                return stop_for_scope(store, reply, &agent, nonce, owner, now, code, &responses);
            }
        }
        let request =
            AuthorizationRequest::new(&reply.caller_principal, &handle.connection_id, action, args)
                .with_bound_agent(&row.agent_id, &handle.app_handle_id);
        let request = with_reply_scope(request, reply);
        let request = facade_origin::receipt_request(
            request,
            approval(&row),
            ReceiptClaim {
                agent_id: row.agent_id.clone(),
                request_nonce: nonce.into(),
                claim_owner: owner.into(),
                effect_index: index,
            },
            proof.clone(),
        );
        let reservation = match engine.authorize(request) {
            Ok(reservation) => reservation,
            Err(denial) => return fail(reply, "G10", taxonomy::denial(&denial, "G10")),
        };
        match taxonomy::dispatch(engine.revalidate_and_dispatch(&reservation).outcome) {
            Ok(value) => {
                let value = if pr_state_kind(&mapped.request_kind) {
                    match pr_state_response(&mapped.request_kind, value) {
                        Ok(value) => value,
                        Err(code) => return fail(reply, "G10", code),
                    }
                } else {
                    value
                };
                if store
                    .finish_github_effect(&agent, nonce, owner, index, &value, now)
                    .ok()
                    != Some(true)
                {
                    eprintln!(error storage: "GitHub effect persistence failed for receipt {agent}/{nonce}, effect {index}");
                    if let Err(error) = store.mark_github_outcome_unknown(&agent, nonce, owner, now)
                    {
                        eprintln!(error storage: "mark GitHub receipt {agent}/{nonce} outcome_unknown failed: {error}");
                    }
                    reply.gate = "G10";
                    return json!({"status":"outcome_unknown"});
                }
                responses.push((action, value));
            }
            Err(code) if code == "outcome_unknown" => {
                receipt_update(
                    store.mark_github_outcome_unknown(&agent, nonce, owner, now),
                    "mark outcome_unknown",
                    &agent,
                    nonce,
                );
                return json!({"status":"outcome_unknown"});
            }
            Err(code) => return fail(reply, "G10", code),
        }
    }
    // The projection is stored as the receipt's outcome, so a same-nonce replay
    // returns exactly this reply without contacting GitHub again.
    let result = json!({
        "status":"completed",
        "result": projection(&mapped.request_kind, &responses, issue_read.as_ref()),
    });
    if store
        .finish_github_facade(&agent, nonce, owner, "completed", &result, None, now)
        .ok()
        != Some(true)
    {
        // GitHub responses for every write leg are stored on the receipt's effects.
        // Replay rebuilds the completed result from those responses, skipping dispatch.
        eprintln!(error storage: "GitHub completion persistence failed for receipt {agent}/{nonce}; all effects are durable");
    }
    reply.gate = "G10";
    result
}
