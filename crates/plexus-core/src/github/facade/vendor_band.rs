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
    for (field, dimension) in crate::governance::AUTHORITY_DIMENSIONS {
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
    clock: &dyn Fn() -> i64,
) -> Result<Value, taxonomy::Failure> {
    let expires_at = row.claim_lease_expires_at.ok_or("store_failure")?;
    let check_lease = || {
        pagination::check_lease(expires_at, clock()).map_err(|_| {
            taxonomy::Failure::from("pre_dispatch_read_incomplete{reason: lease_expired}")
        })
    };
    check_lease()?;
    let handle = reply
        .handle
        .as_ref()
        .ok_or_else(|| taxonomy::Failure::from("store_failure".to_string()))?;
    let args = leg_args(engine, handle, action, &args, "G8")?;
    if action == "github.issue_comments.list"
        && (args.get("per_page").and_then(Value::as_u64) != Some(pagination::PER_PAGE as u64)
            || args.get("page").and_then(Value::as_u64).is_none())
    {
        return Err("pre_dispatch_read_incomplete{reason: invalid_response}".into());
    }
    let request =
        AuthorizationRequest::new(&reply.caller_principal, &handle.connection_id, action, args)
            .with_bound_agent(&row.agent_id, &handle.app_handle_id);
    let request = with_reply_scope(request, reply);
    let request = facade_origin::request(request, approval(row));
    let reservation = engine
        .authorize(request)
        .map_err(|denial| taxonomy::denied(&denial, "G8"))?;
    check_lease()?;
    let result = engine.revalidate_and_dispatch(&reservation);
    check_lease()?;
    taxonomy::dispatched(result)
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
            "draft" | "isDraft" | "isInMergeQueue" => value.is_boolean(),
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

/// Recover a completed result using only durable write responses. Admission and
/// ownership reads must not override a result whose writes already completed.
pub(crate) fn recover_completed(row: &Receipt, kind: &str) -> Option<Value> {
    if row.state != "pending"
        || row.effects.is_empty()
        || row.effects.iter().any(|effect| effect.outcome.is_none())
    {
        return None;
    }
    let mut issue_read = None;
    let responses: Vec<_> = row
        .effects
        .iter()
        .map(|effect| {
            let outcome = effect.outcome.as_ref().expect("settled effect");
            if let Some(read) = outcome.get("__plexus_issue_read") {
                issue_read = Some(read);
            }
            (
                effect.effect.as_str(),
                outcome.get("__plexus_response").unwrap_or(outcome).clone(),
            )
        })
        .collect();
    Some(json!({"status":"completed","result":projection(kind, &responses, issue_read)}))
}

/// The caller-facing result of a completed request, taken from the response of
/// the leg that defines the request's outcome. `legs` pairs each planned write
/// with its GitHub response, in dispatch order; `issue_read` is the issue as
/// read before an issue edit, used when no leg returned the issue.
pub(crate) fn projection(kind: &str, legs: &[(&str, Value)], issue_read: Option<&Value>) -> Value {
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
        "pr_edit" => pick(last, &[("html_url", "url"), ("number", "number")]),
        "pr_enqueue" | "pr_dequeue" => pick(
            legs.last()
                .map(|(_, body)| body)
                .or(issue_read)
                .unwrap_or(&Value::Null),
            &[
                ("url", "url"),
                ("number", "number"),
                ("isInMergeQueue", "queued"),
                ("headRefOid", "head_sha"),
            ],
        ),
        "resolve_thread" | "unresolve_thread" => {
            json!({"id":last["id"], "resolved":last["isResolved"]})
        }
        "stack_create" | "stack_add" => pick(last, &[("url", "url"), ("number", "number")]),
        "stack_unstack" => {
            let mut result = pick(last, &[("url", "url"), ("number", "number")]);
            result["dissolved"] = json!(last.is_null());
            result
        }
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
    claim_owner: &str,
    _now: i64,
    code: &str,
    scope_role: &str,
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
    let mut value = json!({"status":"refused", "refusal_code":code, "legs_sent":legs_sent,
        "scope_role":scope_role});
    if scope_role == "run" && sent.is_empty() {
        value["transmission"] = json!("not_sent");
    }
    // The flag mirrors the receipt action below: released claims stay safe to
    // retry with the same nonce, finished refusals replay and need a new nonce.
    let retry_same_nonce = matches!(
        code,
        crate::scope::SCOPE_UNVERIFIABLE | crate::scope::SCOPE_NOT_SYNCED
    );
    value["retry_same_nonce"] = json!(retry_same_nonce);
    if retry_same_nonce {
        receipt_update(
            store.release_github_claim_between_legs(
                agent,
                nonce,
                claim_owner,
                crate::storage::now_ms(),
            ),
            "release",
            agent,
            nonce,
        );
    } else {
        receipt_update(
            store.finish_github_facade(
                agent,
                nonce,
                claim_owner,
                "refused",
                &value,
                Some(code),
                crate::storage::now_ms(),
            ),
            "finish refusal",
            agent,
            nonce,
        );
    }
    value
}

fn owned(value: &Value, login: &str) -> bool {
    value
        .pointer("/user/login")
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(login))
        && value.pointer("/user/type").and_then(Value::as_str) == Some("Bot")
}

const PR_EDIT_NOT_OWN_MESSAGE: &str = "'pr edit' changes only pull requests this repository's bot opened ({bot}); #{number} was opened by {author}. Ask the author, or run it as the operator with GH_SHIM_BYPASS=operator.";

fn stack_not_own(pr: &Value, number: &Value, login: &str) -> taxonomy::Failure {
    let author = pr["user"]["login"].as_str().unwrap_or("unknown");
    json!({"code":"stack_pr_not_own", "detail":{
        "number":number, "author_login":author,
        "message":format!("Stack operations change only pull requests this repository's bot opened ({login}); #{number} was opened by {author}.")
    }}).to_string().into()
}

/// How many GraphQL `errors` entries one operator line carries. Five is enough
/// to tell a permission problem from a missing node when several mutations
/// fail together, and small enough that one chatty reply cannot flood the log.
const GRAPHQL_LOGGED_ERRORS: usize = 5;

/// Longest vendor message one operator line carries, in characters. Long
/// messages may carry echoed request material rather than a reason, so the
/// line keeps only a sentence-sized prefix.
const GRAPHQL_MESSAGE_CHARS: usize = 300;

/// The operator-log projection of a GraphQL `errors` reply, or `None` when the
/// reply carries no `errors` value to project.
///
/// The agent-facing refusal keeps the closed REST validation vocabulary (free
/// vendor text never crosses that boundary), so this line is the only place
/// the vendor's reason survives: the request kind and action, the bot handle
/// and repository that sent it, and each error's type, path and message.
///
/// Only this projection is logged, never the reply itself. Like the REST and
/// MCP vendor-error lines, it is emitted for refusals only: success bodies
/// are vendor payload and may legitimately carry secret material.
fn graphql_errors_log_line(
    kind: &str,
    action: &str,
    login: &str,
    repository: &str,
    value: &Value,
) -> Option<String> {
    let errors = value.get("errors")?;
    let entries: &[Value] = errors.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut rendered = Vec::new();
    for error in entries.iter().take(GRAPHQL_LOGGED_ERRORS) {
        rendered.push(logged_graphql_error(error));
    }
    Some(format!(
        "github GraphQL errors refused kind={kind} action={action} bot={login} repository={repository} errors={}",
        rendered.join("; ")
    ))
}

/// One GraphQL error entry for the operator log: its vendor type, its path
/// and its message. The type and path are vendor structure; the message is
/// free vendor text, so it is scrubbed and cut before it is rendered. The
/// path renders dot-joined rather than as JSON so the line never ends in a
/// bracketed span: the fleet renderer reads a trailing `[...]` span as a
/// context bound (which precedes the message) and rejects a line shaped like
/// a message followed by one.
fn logged_graphql_error(error: &Value) -> String {
    let error_type = error
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    let path = logged_graphql_path(error);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .map(sanitize_graphql_message)
        .unwrap_or_else(|| "<none>".into());
    format!("type={error_type} path={path} message={message:?}")
}

/// A GraphQL error path (`["mutation"]`, `["data", "node", 0]`) rendered
/// dot-joined for the operator log. Segments are field names or indices;
/// anything else renders as `?` rather than reaching the log raw.
fn logged_graphql_path(error: &Value) -> String {
    error
        .get("path")
        .and_then(Value::as_array)
        .map(|segments| {
            segments
                .iter()
                .map(|segment| {
                    segment
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| segment.as_u64().map(|index| index.to_string()))
                        .or_else(|| segment.as_i64().map(|index| index.to_string()))
                        .unwrap_or_else(|| "?".into())
                })
                .collect::<Vec<_>>()
                .join(".")
        })
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "<none>".into())
}

/// A vendor message for the operator log only: credential-shaped words become
/// `[redacted]`, any signed-URL query or userinfo becomes `[redacted]`, and
/// the remainder is cut to `GRAPHQL_MESSAGE_CHARS` characters. The request's
/// credential is not passed to this projection as a separate input, and the
/// vendor's message is still scrubbed in case it quotes request material.
fn sanitize_graphql_message(message: &str) -> String {
    let (redacted, _) = crate::secret_input::redact_secret_shaped_words(message);
    let scrubbed = scrub_signed_urls(&redacted);
    crate::text::prefix_within_chars(&scrubbed, GRAPHQL_MESSAGE_CHARS)
        .0
        .to_string()
}

/// Any whitespace-separated word carrying a URL scheme with its userinfo and
/// query redacted, reusing the endpoint redactor the transports log with. The
/// host and path stay so the operator can tell which vendor surface answered;
/// the userinfo and query are what may carry a secret, so those become
/// `[redacted]`.
fn scrub_signed_urls(text: &str) -> String {
    let mut scrubbed = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let word_start = rest
            .find(|ch: char| !ch.is_whitespace())
            .unwrap_or(rest.len());
        scrubbed.push_str(&rest[..word_start]);
        rest = &rest[word_start..];
        let word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let word = &rest[..word_end];
        if word.contains("://") {
            scrubbed.push_str(&crate::http_support::redacted_endpoint(word));
        } else {
            scrubbed.push_str(word);
        }
        rest = &rest[word_end..];
    }
    scrubbed
}

fn graphql_errors(
    kind: &str,
    action: &str,
    login: &str,
    repository: &str,
    value: &Value,
) -> Result<(), String> {
    if value.get("errors").is_some() {
        // The refusal below drops the vendor's reason by design; this line is
        // the only place it survives, for the operator only.
        if let Some(line) = graphql_errors_log_line(kind, action, login, repository, value) {
            eprintln!(warn governance: "{line}");
        }
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
    Ok(())
}

fn thread_kind(kind: &str) -> bool {
    matches!(kind, "resolve_thread" | "unresolve_thread")
}

fn stack_shape(value: &Value, args: &Value) -> Result<(), String> {
    let expected = format!(
        "https://api.github.com/repos/{}/{}/stacks/",
        args["owner"].as_str().unwrap_or(""),
        args["repo"].as_str().unwrap_or("")
    );
    let number = value["number"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("pre_dispatch_read_incomplete{reason: invalid_response}")?;
    if !value["url"]
        .as_str()
        .is_some_and(|url| url.eq_ignore_ascii_case(&format!("{expected}{number}")))
    {
        return Err("agent_repository_conflict".into());
    }
    if args
        .get("stack_number")
        .is_some_and(|n| *n != value["number"])
    {
        return Err("pre_dispatch_read_incomplete{reason: invalid_response}".into());
    }
    let members = value["pull_requests"]
        .as_array()
        .ok_or("pre_dispatch_read_incomplete{reason: invalid_response}")?;
    let mut seen = std::collections::BTreeSet::new();
    for pr in members {
        if !pr["number"]
            .as_u64()
            .is_some_and(|n| n > 0 && seen.insert(n))
            || !pr["user"]["login"].is_string()
            || !pr["user"]["type"].is_string()
        {
            return Err("pre_dispatch_read_incomplete{reason: invalid_response}".into());
        }
        let repo = format!(
            "https://api.github.com/repos/{}/{}",
            args["owner"].as_str().unwrap_or(""),
            args["repo"].as_str().unwrap_or("")
        );
        if !pr
            .pointer("/base/repo/url")
            .and_then(Value::as_str)
            .is_some_and(|url| url.eq_ignore_ascii_case(&repo))
        {
            return Err("agent_repository_conflict".into());
        }
    }
    Ok(())
}

fn write_response(
    kind: &str,
    action: &str,
    login: &str,
    repository: &str,
    value: Value,
    args: &Value,
) -> Result<Value, String> {
    if queue_kind(kind) {
        graphql_errors(kind, action, login, repository, &value)?;
        let mutation = if kind == "pr_enqueue" {
            "enqueuePullRequest"
        } else {
            "dequeuePullRequest"
        };
        let pr = &value["data"][mutation]["mergeQueueEntry"]["pullRequest"];
        if !queue_pr_shape(pr)
            || pr["id"] != args["variables"]["pullRequestId"]
            || pr["isInMergeQueue"].as_bool() != Some(kind == "pr_enqueue")
            || (kind == "pr_enqueue"
                && !pr["headRefOid"]
                    .as_str()
                    .zip(args["variables"]["expectedHeadOid"].as_str())
                    .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(expected)))
        {
            return Err("outcome_unknown".into());
        }
        return Ok(pr.clone());
    }
    if pr_state_kind(kind) {
        return pr_state_response(kind, action, login, repository, value);
    }
    if thread_kind(kind) {
        graphql_errors(kind, action, login, repository, &value)?;
        let mutation = if kind == "resolve_thread" {
            "resolveReviewThread"
        } else {
            "unresolveReviewThread"
        };
        let thread = &value["data"][mutation]["thread"];
        if thread["id"] != args["variables"]["threadId"]
            || thread["isResolved"].as_bool() != Some(kind == "resolve_thread")
        {
            return Err("outcome_unknown".into());
        }
        return Ok(thread.clone());
    }
    if matches!(kind, "stack_create" | "stack_add" | "stack_unstack") {
        if kind == "stack_unstack" && value.is_null() {
            return Ok(value);
        }
        stack_shape(&value, args).map_err(|_| "outcome_unknown".to_owned())?;
    }
    Ok(value)
}

fn pr_state_kind(kind: &str) -> bool {
    matches!(kind, "pr_ready" | "pr_draft")
}

fn queue_kind(kind: &str) -> bool {
    matches!(kind, "pr_enqueue" | "pr_dequeue")
}

fn queue_pr_shape(pr: &Value) -> bool {
    pr["id"].as_str().is_some_and(|id| !id.is_empty())
        && pr["url"].is_string()
        && pr["number"].as_u64().is_some_and(|n| n > 0)
        && pr["isInMergeQueue"].is_boolean()
        && pr["headRefOid"]
            .as_str()
            .is_some_and(|sha| sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// GraphQL reports application failures in successful HTTP responses. Reuse the
/// REST validation refusal vocabulary, discarding messages and all unknown fields.
/// The vendor's reason is kept in the operator log instead; the reply never
/// carries it.
fn pr_state_response(
    kind: &str,
    action: &str,
    login: &str,
    repository: &str,
    value: Value,
) -> Result<Value, String> {
    let mutation = if kind == "pr_ready" {
        "markPullRequestReadyForReview"
    } else {
        "convertPullRequestToDraft"
    };
    if value.get("errors").is_some() && value.get("data").is_none_or(Value::is_null) {
        // The refusal below drops the vendor's reason by design; this line is
        // the only place it survives, for the operator only.
        if let Some(line) = graphql_errors_log_line(kind, action, login, repository, &value) {
            eprintln!(warn governance: "{line}");
        }
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
    if value.get("errors").is_some()
        || !pr["isDraft"].is_boolean()
        || !pr["number"].is_u64()
        || !pr["url"].is_string()
    {
        return Err("outcome_unknown".into());
    }
    Ok(pr.clone())
}

/// Persist only definitive refusals. Temporary failures release the claim while
/// retaining durable progress, so retries cannot repeat successful write legs.
#[allow(clippy::too_many_arguments)]
fn refuse(
    store: &PlexusStore,
    row: &Receipt,
    reply: &mut gates::GateReply,
    nonce: &str,
    claim_owner: &str,
    gate: &'static str,
    failure: taxonomy::Failure,
) -> Value {
    let agent = row.agent_id.clone();
    let code = failure.code;
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
    let durable = store
        .github_receipt(&agent, nonce)
        .ok()
        .flatten()
        .unwrap_or_else(|| row.clone());
    let legs_sent: Vec<_> = durable
        .effects
        .iter()
        .filter(|effect| effect.outcome.is_some())
        .map(|effect| &effect.effect)
        .collect();
    let mut value = json!({"status":"refused", "refusal_code":code});
    if !legs_sent.is_empty() {
        value["legs_sent"] = json!(legs_sent);
    }
    if let Some(typed) = typed {
        value["code"] = typed["code"].clone();
        value["detail"] = typed["detail"].clone();
    }
    if code == "review_thread_not_own" {
        value["transmission"] = json!("not_sent");
    }
    // The flag mirrors the receipt action taken below, not a table of code
    // names: released claims (including the wait-and-retry `nonce_in_flight`)
    // stay safe to retry with the same nonce, while finished refusals replay
    // that refusal and need a new nonce for a new attempt.
    let retry_same_nonce = code == "nonce_in_flight" || failure.retryable;
    value["retry_same_nonce"] = json!(retry_same_nonce);
    if code == "nonce_in_flight" {
        // Another worker may still complete the write for this nonce.
        // Keep the receipt pending for a later owner to resume unfinished effects.
    } else if failure.retryable {
        // These refusals happen before a write is sent or after its
        // outcome is recorded, so no write is in doubt and the claim is
        // released for a same-nonce retry. Writes an earlier leg already
        // completed keep their recorded outcome and are not sent again;
        // the retry resumes at the first unsent leg. If a write may have
        // been sent without a recorded outcome, the release is refused and
        // the claim stays until lease expiry settles it as outcome_unknown.
        receipt_update(
            store.release_github_claim_between_legs(
                &agent,
                nonce,
                claim_owner,
                crate::storage::now_ms(),
            ),
            "release",
            &agent,
            nonce,
        );
    } else {
        receipt_update(
            store.finish_github_facade(
                &agent,
                nonce,
                claim_owner,
                "refused",
                &value,
                Some(&code),
                crate::storage::now_ms(),
            ),
            "finish refusal",
            &agent,
            nonce,
        );
    }
    value
}

/// A claimed receipt is required to enter this code. Pre-dispatch reads lack
/// that claim, so they cannot record that a GitHub mutation was attempted.
pub fn run<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    store: &PlexusStore,
    reply: &mut gates::GateReply,
    nonce: &str,
    claim_owner: &str,
    now: i64,
) -> Value {
    run_with_clock(
        engine,
        store,
        reply,
        nonce,
        claim_owner,
        now,
        &crate::storage::now_ms,
    )
}

/// Exercise pre-read lease boundaries without waiting for wall-clock expiry.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub fn run_with_test_clock<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    store: &PlexusStore,
    reply: &mut gates::GateReply,
    nonce: &str,
    claim_owner: &str,
    now: i64,
    clock: &dyn Fn() -> i64,
) -> Value {
    run_with_clock(engine, store, reply, nonce, claim_owner, now, clock)
}

#[allow(clippy::too_many_arguments)]
fn run_with_clock<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    store: &PlexusStore,
    reply: &mut gates::GateReply,
    nonce: &str,
    claim_owner: &str,
    now: i64,
    clock: &dyn Fn() -> i64,
) -> Value {
    let Some(Claim::Owned(row)) = reply.claim.as_ref() else {
        return json!({"status":"pending"});
    };
    let row = row.clone();
    let agent = row.agent_id.clone();
    let fail = |reply: &mut gates::GateReply, gate, failure| {
        refuse(store, &row, reply, nonce, claim_owner, gate, failure)
    };
    let fail_read = |reply: &mut gates::GateReply, gate, mut failure: taxonomy::Failure| {
        // Reads run again when a partial receipt resumes. Only an unattempted
        // receipt can promise that no write was sent; retain partial progress
        // and the original failure classification on resumed requests.
        let not_sent = row
            .effects
            .iter()
            .all(|effect| effect.dispatch_attempted_at.is_none() && effect.outcome.is_none());
        if not_sent {
            if failure.code == "outcome_unknown" {
                failure.code = "pre_dispatch_read_incomplete{reason: transport_unknown}".into();
            }
            failure.retryable = true;
        }
        let mut value = fail(reply, gate, failure);
        if not_sent {
            value["transmission"] = json!("not_sent");
        }
        value
    };
    if let Err(code) = stale(store, reply, &row) {
        return fail(reply, "G8", code.into());
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
    let login =
        crate::github::credential::bot_login(&handle.credential_reference).unwrap_or_default();
    let mut args = mapped.args.clone();
    let mut completed = Vec::new();
    if mapped.request_kind == "comment_edit_last" {
        let start = now;
        let mut read_error = None;
        let walk = pagination::walk_newest_bot_comment(slug, start, clock, |page| {
            let mut page_args = args.clone();
            page_args["page"] = json!(page.page);
            page_args["per_page"] = json!(page.per_page);
            match read(
                engine,
                reply,
                &row,
                "github.issue_comments.list",
                page_args,
                clock,
            ) {
                Ok(value) => Ok(value),
                Err(code) => {
                    read_error = Some(code);
                    Err(WalkError::ReadFailed)
                }
            }
        });
        let walk = match walk {
            Ok(walk) => walk,
            Err(error) => {
                return fail_read(
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
        let Some(comment) = walk.newest_bot_comment(slug) else {
            return fail(reply, "G8", "not_present".to_string().into());
        };
        let Some(id) = comment["id"].as_u64() else {
            return fail(reply, "G8", "not_present".to_string().into());
        };
        args["comment_id"] = json!(id);
        completed.push("github.issue_comments.list");
    }
    let mut issue_read = None;
    if matches!(mapped.request_kind.as_str(), "stack_create" | "stack_add") {
        for number in args["pull_requests"].as_array().expect("validated PR list") {
            let value = match read(
                engine,
                reply,
                &row,
                "github.pull_request.get",
                json!({"owner":args["owner"], "repo":args["repo"], "pull_number":number}),
                clock,
            ) {
                Ok(value) => value,
                Err(code) => return fail_read(reply, "G8", code),
            };
            if !owned(&value, &login) {
                return fail(reply, "G8", stack_not_own(&value, number, &login));
            }
        }
        completed.push("github.pull_request.get");
    }
    for &action in mapped.reads {
        if action == "github.issue_comments.list"
            || matches!(mapped.request_kind.as_str(), "stack_create" | "stack_add")
        {
            continue;
        }
        let read_args = if action == "github.pull_request.queue_state.get" {
            json!({"owner":args["owner"], "repo":args["repo"], "variables":{"owner":args["owner"], "repo":args["repo"], "number":args["pull_number"]}})
        } else if action == "github.review_thread.get" {
            json!({"owner":args["owner"], "repo":args["repo"], "variables":{"threadId":args["thread_id"]}})
        } else if mapped.request_kind == "resolve_thread" {
            // The reviewed thread query has the PR number but not its author.
            // Use the same PR read and ownership check as PR edits and stacks.
            json!({"owner":args["owner"], "repo":args["repo"], "pull_number":args["pull_number"]})
        } else {
            args.clone()
        };
        let value = match read(engine, reply, &row, action, read_args, clock) {
            Ok(value) => value,
            Err(code)
                if mapped.request_kind == "issue_edit"
                    && code.code == "vendor_rejected{status: 404}" =>
            {
                return fail_read(reply, "G8", "not_present".into());
            }
            Err(code) => return fail_read(reply, "G8", code),
        };
        completed.push(action);
        let value = if queue_kind(&mapped.request_kind) {
            let repository = format!(
                "{}/{}",
                args["owner"].as_str().unwrap_or(""),
                args["repo"].as_str().unwrap_or("")
            );
            if let Err(code) =
                graphql_errors(&mapped.request_kind, action, &login, &repository, &value)
            {
                return fail_read(reply, "G8", code.into());
            }
            let mut pr = value["data"]["repository"]["pullRequest"].clone();
            if !queue_pr_shape(&pr)
                || pr["number"] != args["pull_number"]
                || !matches!(pr["state"].as_str(), Some("OPEN" | "CLOSED" | "MERGED"))
            {
                return fail_read(
                    reply,
                    "G8",
                    "pre_dispatch_read_incomplete{reason: invalid_response}".into(),
                );
            }
            // Normalize GraphQL's Actor to the shared REST ownership predicate.
            pr["user"] = json!({"login":pr["author"]["login"], "type":pr["author"]["__typename"]});
            pr
        } else {
            value
        };
        if action == "github.review_thread.get" {
            let repository = format!(
                "{}/{}",
                args["owner"].as_str().unwrap_or(""),
                args["repo"].as_str().unwrap_or("")
            );
            if let Err(code) = graphql_errors(
                &mapped.request_kind,
                mapped.action,
                &login,
                &repository,
                &value,
            ) {
                return fail_read(reply, "G8", code.into());
            }
            let node = &value["data"]["node"];
            let Some(repository) = node
                .pointer("/pullRequest/repository/nameWithOwner")
                .and_then(Value::as_str)
            else {
                return fail(reply, "G8", "not_present".into());
            };
            if node["id"] != args["thread_id"] {
                return fail(reply, "G8", "not_present".into());
            }
            let expected = format!(
                "{}/{}",
                args["owner"].as_str().unwrap_or(""),
                args["repo"].as_str().unwrap_or("")
            );
            if !repository.eq_ignore_ascii_case(&expected) {
                return fail(reply, "G8", "agent_repository_conflict".into());
            }
            if mapped.request_kind == "resolve_thread" {
                let Some(number) = node["pullRequest"]["number"].as_u64().filter(|n| *n > 0) else {
                    return fail_read(
                        reply,
                        "G8",
                        "pre_dispatch_read_incomplete{reason: invalid_response}".into(),
                    );
                };
                args["pull_number"] = json!(number);
            }
        }
        if mapped.request_kind == "resolve_thread"
            && action == "github.pull_request.get"
            && !owned(&value, &login)
        {
            let number = &args["pull_number"];
            let author = value["user"]["login"].as_str().unwrap_or("unknown");
            return fail(
                reply,
                "G8",
                json!({"code":"review_thread_not_own", "detail":{
                    "number":number, "author_login":author,
                    "message":format!("'resolveReviewThread' works only on pull requests this repository's bot opened ({login}); #{number} was opened by {author}. Reply to the finding as the bot, then resolve the thread as the operator.")
                }}).to_string().into(),
            );
        }
        if mapped.request_kind == "stack_unstack" {
            if let Err(code) = stack_shape(&value, &args) {
                if code == "pre_dispatch_read_incomplete{reason: invalid_response}" {
                    return fail_read(reply, "G8", code.into());
                }
                return fail(reply, "G8", code.into());
            }
            if let Some(pr) = value["pull_requests"]
                .as_array()
                .expect("validated stack")
                .iter()
                .find(|pr| !owned(pr, &login))
            {
                return fail(reply, "G8", stack_not_own(pr, &pr["number"], &login));
            }
        }
        if (mapped.request_kind == "pr_edit" || queue_kind(&mapped.request_kind))
            && !owned(&value, &login)
        {
            let message = PR_EDIT_NOT_OWN_MESSAGE
                .replace("{bot}", &login)
                .replace("{number}", &args["pull_number"].to_string())
                .replace(
                    "{author}",
                    value["user"]["login"].as_str().unwrap_or("unknown"),
                );
            return fail(
                reply,
                "G8",
                json!({"code":"pr_edit_not_own", "detail":{"message":message}})
                    .to_string()
                    .into(),
            );
        }
        if queue_kind(&mapped.request_kind) {
            if value["state"] != "OPEN" {
                return fail(reply, "G8", "pull_request_not_open".into());
            }
            if mapped.request_kind == "pr_enqueue" {
                let expected = args["expected_head_sha"]
                    .as_str()
                    .expect("validated head SHA");
                let actual = value["headRefOid"].as_str().expect("validated PR head");
                if !actual.eq_ignore_ascii_case(expected) {
                    return fail(reply, "G8", json!({"code":"pull_request_head_moved", "detail":{"expected_head_sha":expected, "actual_head_sha":actual}}).to_string().into());
                }
            }
            issue_read = Some(value.clone());
        }
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
            return fail(reply, "G8", code.into());
        }
    }
    if let Err(code) = stale(store, reply, &row) {
        return fail(reply, "G9", code.into());
    }
    let proof = effects::OwnershipProof::new(&mapped.request_kind, completed);
    let mut legs = effects::plan(&mapped);
    if queue_kind(&mapped.request_kind) {
        let pr = issue_read.as_ref().expect("queue read completed");
        if pr["isInMergeQueue"].as_bool() == Some(mapped.request_kind == "pr_enqueue")
            && row
                .effects
                .iter()
                .all(|effect| effect.dispatch_attempted_at.is_none())
        {
            legs.clear();
        } else {
            let mut variables = json!({"pullRequestId":pr["id"]});
            if mapped.request_kind == "pr_enqueue" {
                variables["expectedHeadOid"] = args["expected_head_sha"].clone();
            }
            legs = vec![(
                mapped.action,
                json!({"owner":args["owner"], "repo":args["repo"], "variables":variables}),
            )];
        }
    }
    if thread_kind(&mapped.request_kind) {
        legs = vec![(
            mapped.action,
            json!({"owner":args["owner"], "repo":args["repo"], "variables":{"threadId":args["thread_id"]}}),
        )];
    }
    if pr_state_kind(&mapped.request_kind) {
        let pr = issue_read.as_ref().unwrap_or(&Value::Null);
        let (Some(draft), Some(node_id)) = (
            pr["draft"].as_bool(),
            pr["node_id"].as_str().filter(|id| !id.is_empty()),
        ) else {
            return fail_read(
                reply,
                "G9",
                "pre_dispatch_read_incomplete{reason: invalid_response}".into(),
            );
        };
        if !pr["number"].is_u64() || !pr["html_url"].is_string() {
            return fail_read(
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
            responses.push((
                action,
                outcome.get("__plexus_response").unwrap_or(outcome).clone(),
            ));
            continue;
        }
        let args = match leg_args(engine, &handle, action, &args, "G10") {
            Ok(args) => args,
            Err(code) => return fail(reply, "G10", code.into()),
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
                return stop_for_scope(
                    store,
                    reply,
                    &agent,
                    nonce,
                    claim_owner,
                    now,
                    code,
                    "route",
                    &responses,
                );
            }
            if let Some(run_scope) = reply.run_scope.as_ref() {
                let answer = engine.describe_scope(&run_scope.owner, &run_scope.scope_ref);
                if let Err(code) =
                    run_scope.recheck(&scope, answer.as_ref(), crate::storage::now_ms())
                {
                    return stop_for_scope(
                        store,
                        reply,
                        &agent,
                        nonce,
                        claim_owner,
                        now,
                        code,
                        "run",
                        &responses,
                    );
                }
            }
        }
        let response_args = args.clone();
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
                claim_owner: claim_owner.into(),
                effect_index: index,
            },
            proof.clone(),
        );
        let reservation = match engine.authorize(request) {
            Ok(reservation) => reservation,
            Err(denial) => return fail(reply, "G10", taxonomy::denied(&denial, "G10")),
        };
        let dispatch = engine.revalidate_and_dispatch(&reservation);
        if matches!(
            dispatch.outcome,
            crate::governance::TransportOutcome::NotSent { .. }
                | crate::governance::TransportOutcome::VendorFailed { .. }
        ) {
            receipt_update(
                store.clear_github_dispatch(
                    &agent,
                    nonce,
                    claim_owner,
                    index,
                    &reservation.request_id,
                    crate::storage::now_ms(),
                ),
                "clear unsent dispatch",
                &agent,
                nonce,
            );
        }
        match taxonomy::dispatched(dispatch) {
            Ok(value) => {
                let value = {
                    let repository = format!(
                        "{}/{}",
                        response_args["owner"].as_str().unwrap_or(""),
                        response_args["repo"].as_str().unwrap_or("")
                    );
                    match write_response(
                        &mapped.request_kind,
                        action,
                        &login,
                        &repository,
                        value,
                        &response_args,
                    ) {
                        Ok(value) => value,
                        Err(code) if code == "outcome_unknown" => {
                            receipt_update(
                                store.mark_github_outcome_unknown(
                                    &agent,
                                    nonce,
                                    claim_owner,
                                    crate::storage::now_ms(),
                                ),
                                "mark outcome_unknown",
                                &agent,
                                nonce,
                            );
                            return json!({"status":"outcome_unknown"});
                        }
                        Err(code) => return fail(reply, "G10", code.into()),
                    }
                };
                let durable_value = if mapped.request_kind == "issue_edit" {
                    json!({"__plexus_response":value,"__plexus_issue_read":issue_read})
                } else {
                    value.clone()
                };
                if store
                    .finish_github_effect(
                        &agent,
                        nonce,
                        claim_owner,
                        index,
                        &durable_value,
                        crate::storage::now_ms(),
                    )
                    .ok()
                    != Some(true)
                {
                    eprintln!(error storage: "GitHub effect persistence failed for receipt {agent}/{nonce}, effect {index}");
                    if let Err(error) = store.mark_github_outcome_unknown(
                        &agent,
                        nonce,
                        claim_owner,
                        crate::storage::now_ms(),
                    ) {
                        eprintln!(error storage: "mark GitHub receipt {agent}/{nonce} outcome_unknown failed: {error}");
                    }
                    reply.gate = "G10";
                    return json!({"status":"outcome_unknown"});
                }
                responses.push((action, value));
            }
            Err(code) if code.code == "outcome_unknown" => {
                receipt_update(
                    store.mark_github_outcome_unknown(
                        &agent,
                        nonce,
                        claim_owner,
                        crate::storage::now_ms(),
                    ),
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
        .finish_github_facade(
            &agent,
            nonce,
            claim_owner,
            "completed",
            &result,
            None,
            crate::storage::now_ms(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A GraphQL `errors` reply exercising every operator-log scrubber: a
    /// plain vendor sentence, a credential-shaped word, a signed URL, an
    /// overlong message, and one entry more than a single line carries.
    fn erroneous() -> Value {
        json!({"errors": [
            {"type": "FORBIDDEN", "path": ["mutation"],
             "message": "actor cannot resolve this thread"},
            {"type": "NOT_FOUND", "path": ["data", "node"],
             "message": "node vanished"},
            {"type": "CUSTOM", "path": ["viewer"],
             "message": "leaked ghp_abcdefghijklmnopqrstuvwxyz0123456789 in transit"},
            {"type": "RATE_LIMITED", "path": ["cost"],
             "message": "see https://files.example/blob?sig=SIGNED-URL-SECRET&se=2026 for detail"},
            {"type": "LONG", "path": ["up"], "message": "m".repeat(500)},
            {"type": "EXTRA", "path": ["sixth"],
             "message": "beyond the per-line cap"},
        ]})
    }

    /// A GraphQL error refusal keeps its closed-vocabulary reply while the
    /// vendor's reason reaches the operator log scrubbed of secrets.
    #[test]
    fn graphql_errors_log_type_path_and_message_and_keep_the_refusal() {
        const TEST: &str = "github::facade::vendor_band::tests::graphql_errors_log_type_path_and_message_and_keep_the_refusal";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
            crate::test_logging::init_child();
            // GraphQL-shaped entries match no REST validation code, so the
            // reply is the bare refusal while the reason goes to the log.
            assert_eq!(
                graphql_errors(
                    "resolve_thread",
                    "graphql resolvereviewthread",
                    "app-fixture[bot]",
                    "org/repo",
                    &erroneous()
                )
                .unwrap_err(),
                "vendor_rejected{status: 422}"
            );
            return;
        }
        let output = crate::test_http::bounded::child_test_output(
            TEST,
            &[("PLEXUS_LOG_STDERR_CHILD", "1")],
            std::time::Duration::from_secs(30),
            "graphql diagnostic child",
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        let lines: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains("github GraphQL errors refused"))
            .collect();
        assert_eq!(lines.len(), 1, "{stderr}");
        let line = lines[0];
        for expected in [
            "kind=resolve_thread",
            "action=graphql resolvereviewthread",
            "bot=app-fixture[bot]",
            "repository=org/repo",
            "type=FORBIDDEN",
            "path=mutation",
            "actor cannot resolve this thread",
            "type=NOT_FOUND",
            "path=data.node",
            "type=CUSTOM",
            "[redacted]",
            "type=RATE_LIMITED",
            "https://files.example/blob?[redacted]",
        ] {
            assert!(line.contains(expected), "{expected} missing: {line}");
        }
        for absent in [
            "ghp_",
            "SIGNED-URL-SECRET",
            "sig=",
            "beyond the per-line cap",
            &"m".repeat(301),
        ] {
            assert!(!line.contains(absent), "{absent} leaked: {line}");
        }
        assert!(
            line.contains(&"m".repeat(300)),
            "the overlong message is cut, not dropped: {line}"
        );
        let expected = graphql_errors_log_line(
            "resolve_thread",
            "graphql resolvereviewthread",
            "app-fixture[bot]",
            "org/repo",
            &erroneous(),
        )
        .expect("the fixture carries an errors value");
        crate::test_logging::assert_diagnostic(
            line,
            cortexkit_log::ParsedLevel::Warn,
            "plexus.governance",
            &expected,
        );
    }
}
