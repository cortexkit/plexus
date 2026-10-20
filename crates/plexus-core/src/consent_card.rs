//! Approval cards served by the Cingulate consent module for held tool calls.
//! Requester and subject identity come only from the session scope stamped by
//! the subc daemon on the route, never from card content.
//! The requester wire is pinned under the module's cingulate-consent-requester
//! fixtures. Plexus never answers a card on the user's behalf.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::scope::CallScope;
use crate::secret_input::{contains_secret_input, withhold_from_preview};
use crate::storage::{ActionRequestRecord, PlexusStore};

pub const CONTROL_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub const CONSENT_REQUEST: &str = "consent.request";
pub const CONSENT_GET: &str = "consent.get";
pub const CONSENT_AWAIT: &str = "consent.await";
pub const CONSENT_DETACH: &str = "consent.detach";
pub const CONSENT_WITHDRAW: &str = "consent.withdraw";
pub const CONSENT_REPORT_EXECUTION: &str = "consent.report_execution";
/// Broca cuts calls at 120 seconds. Detach must commit before the caller gives
/// up, or a later answer reaches neither the held call nor the agent.
pub const HELD_CALL_BUDGET: Duration = Duration::from_secs(110);
pub const AWAIT_MAX_MS: u64 = 120_000;
const AWAIT_ROUTE_DEADLINE: Duration = Duration::from_secs(30);
const AWAIT_REPLY_RESERVE: Duration = Duration::from_secs(1);

/// The option ids on every card Plexus files. Get and await identify the
/// chosen option by `answered_choice_id`, never by label.
pub const OPTION_APPROVE: &str = "approve";
pub const OPTION_DENY: &str = "deny";

/// The execution outcomes `consent.report_execution` accepts.
pub const EXECUTED: &str = "executed";
pub const APPROVED_NOT_EXECUTED: &str = "approved_not_executed";
pub const OUTCOME_UNKNOWN: &str = "outcome_unknown";

/// Written as the `decider` of a request decided on its card, followed by the
/// card's id. It tells a request the user approved on their phone apart from
/// one the operator approved through the `requests` tool.
pub const CONSENT_CARD_DECIDER_PREFIX: &str = "consent_card:";

/// The longest preview text a card carries, in characters. The preview is a
/// reminder of what will be sent, not a copy of it.
pub const PREVIEW_TEXT_MAX_CHARS: usize = 600;
/// The longest rendering of any one argument value in the preview.
const PREVIEW_VALUE_MAX_CHARS: usize = 160;
/// Shown in place of an argument whose name marks it as secret.
const PREVIEW_WITHHELD: &str = "[withheld]";
/// The longest card lifetime Cingulate accepts (24 hours).
const MAX_EXPIRES_IN_MS: i64 = 86_400_000;

/// Why an elicitation operation produced no reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElicitationCallError {
    /// Cingulate answered with a coded refusal, such as
    /// `consent_unavailable` or `elicitation_not_owner`.
    Refused { code: String, message: String },
    /// The request never left Plexus.
    NotSent,
    /// The request was sent but no answer arrived.
    OutcomeUnknown,
    /// The reply could not be read.
    Transport,
}

impl ElicitationCallError {
    /// The code a log line names: Cingulate's own code for a refusal.
    pub fn code(&self) -> &str {
        match self {
            Self::Refused { code, .. } => code,
            Self::NotSent => "consent_route_not_sent",
            Self::OutcomeUnknown => "consent_route_outcome_unknown",
            Self::Transport => "consent_route_unreadable",
        }
    }
}

/// Calls Cingulate under the held call's daemon scope selector. The timeout
/// covers route admission and the reply; implementations must not fall back to
/// an unscoped route when admission fails.
pub trait ElicitationRoute: Send + Sync {
    fn call_scoped(
        &self,
        scope: &CallScope,
        operation: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ElicitationCallError>;
}

/// What the user is asked to judge about one call held for approval.
#[derive(Debug, Clone)]
pub struct ParkedApproval<'a> {
    /// The approval row id, echoed as the card's `requester_ref`.
    pub request_id: &'a str,
    pub dedup_key: &'a str,
    /// The action's catalog title, or its name when it has none.
    pub action_label: &'a str,
    /// The service's catalog name (the app manifest's `name`).
    pub service_label: &'a str,
    /// The action's catalog risk: `read`, `write` or `destructive`.
    pub risk: &'a str,
    /// The arguments the action will be sent with.
    pub args: &'a Value,
    /// Recipient-declaring sends require the entire text and every recipient,
    /// not a bounded reminder. Their wire size is checked before parking.
    pub complete_preview: bool,
    /// Plexus's exact-JSON hash of those arguments, as stored on the request.
    pub args_digest: &'a str,
    /// How long the request has left before it expires.
    pub expires_in_ms: i64,
}

/// The `consent.request` body for one call held for approval.
///
/// Every field is built from what the user must judge: what will be done, on
/// which service, with which arguments. No argument whose name marks it as
/// secret is rendered, and the body as a whole never names a secret-looking
/// key (`contains_secret_input` holds false for it).
pub fn consent_request_body(parked: &ParkedApproval<'_>) -> Value {
    let material_damage = parked.risk != "read";
    let consequence = match parked.risk {
        "read" => format!(
            "It reads data from {} and changes nothing.",
            parked.service_label
        ),
        "destructive" => format!(
            "It can delete or overwrite data in {} and may not be undoable.",
            parked.service_label
        ),
        _ => format!("It changes data in {}.", parked.service_label),
    };
    let body = json!({
        "kind": "consent",
        "title": format!("{} on {}", parked.action_label, parked.service_label),
        "prompt": format!(
            "Allow {} to run once on {} with the arguments shown? {consequence}",
            parked.action_label, parked.service_label
        ),
        "options": [
            {"id": OPTION_APPROVE, "label": "Approve", "effect": "grant"},
            {"id": OPTION_DENY, "label": "Deny", "effect": "decline"},
        ],
        "default": OPTION_DENY,
        "urgency": "normal",
        "on_expiry": "deny",
        "material_damage": material_damage,
        "late_execution": "notify_only",
        "target": {"kind": "service", "label": parked.service_label},
        "expires_in_ms": parked.expires_in_ms.clamp(1, MAX_EXPIRES_IN_MS),
        "requester_ref": parked.request_id,
        "dedup_key": parked.dedup_key,
        "args_digest": parked.args_digest,
        "preview": {"label": "Will send", "text": if parked.complete_preview { complete_preview_text(parked.args) } else { preview_text(parked.args) }},
        "facts": [
            {"label": "Action", "value": parked.action_label},
            {"label": "Risk", "value": parked.risk},
        ],
    });
    body
}

/// A bounded, readable rendering of an action's arguments, one `name: value`
/// line per top-level argument. An argument whose name marks it as secret,
/// whose value holds such an argument, or whose value contains something
/// shaped like a credential (a `ghp_` token, a JWT, ...), is shown as
/// withheld; its value is never rendered. Long values are cut, and the whole text is capped at
/// [`PREVIEW_TEXT_MAX_CHARS`].
pub fn preview_text(args: &Value) -> String {
    let text = match args {
        Value::Object(object) if object.is_empty() => "(no arguments)".to_string(),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| {
                let rendered = if withhold_from_preview(key, value) {
                    PREVIEW_WITHHELD.to_string()
                } else {
                    render_value(value)
                };
                format!("{key}: {rendered}")
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other if withhold_from_preview("", other) => PREVIEW_WITHHELD.to_string(),
        other => render_value(other),
    };
    truncate_chars(&text, PREVIEW_TEXT_MAX_CHARS)
}

/// The same secret filter as the ordinary preview, without truncating values.
pub fn complete_preview_text(args: &Value) -> String {
    match args {
        Value::Object(object) if object.is_empty() => "(no arguments)".into(),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| {
                let rendered = if withhold_from_preview(key, value) {
                    PREVIEW_WITHHELD.to_owned()
                } else if let Value::String(text) = value {
                    text.clone()
                } else {
                    value.to_string()
                };
                format!("{key}: {rendered}")
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other if withhold_from_preview("", other) => PREVIEW_WITHHELD.into(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The card request has no string limit of its own. Its serialized size is
/// bounded by the daemon's maximum frame body, including the method and params,
/// JSON escaping, and card metadata, so the full request must be measured.
pub fn consent_request_wire_len(parked: &ParkedApproval<'_>) -> usize {
    serde_json::to_vec(&json!({"method": CONSENT_REQUEST, "params": consent_request_body(parked)}))
        .expect("consent body is serializable JSON")
        .len()
}

fn render_value(value: &Value) -> String {
    let rendered = match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    truncate_chars(&rendered, PREVIEW_VALUE_MAX_CHARS)
}

/// Cut `text` to at most `max` characters, marking a cut with an ellipsis.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// The requester for approval cards. All id operations use the original
/// approval's scope, including withdrawal after a held call has returned.
pub struct ConsentCards {
    route: Arc<dyn ElicitationRoute>,
}

impl ConsentCards {
    pub fn new(route: Arc<dyn ElicitationRoute>) -> Self {
        Self { route }
    }

    pub fn available_scope(scope: Option<&CallScope>) -> bool {
        scope.is_some_and(|scope| {
            scope.flow_id.is_none()
                && ((scope.acting_agent().is_some()
                    && matches!(scope.kind.as_deref(), Some("head" | "ephemeral")))
                    || (scope.owner == "reserved:prefrontal-core"
                        && scope.kind.as_deref() == Some("worker")
                        && scope.parent.is_some()))
        })
    }

    pub fn file(
        &self,
        store: &PlexusStore,
        principal: &str,
        scope: &CallScope,
        parked: &ParkedApproval<'_>,
    ) -> Result<String, ElicitationCallError> {
        let body = consent_request_body(parked);
        if contains_secret_input(&body) {
            return Err(ElicitationCallError::Refused {
                code: "consent_card_secret_field".into(),
                message: "the card body names a secret-looking field".into(),
            });
        }
        let reply = self
            .route
            .call_scoped(scope, CONSENT_REQUEST, body, CONTROL_RPC_TIMEOUT)?;
        let id = reply
            .get("elicitation_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(ElicitationCallError::Transport)?
            .to_string();
        store
            .set_action_request_elicitation_id(principal, parked.request_id, &id)
            .map_err(|_| ElicitationCallError::Transport)?;
        Ok(id)
    }

    pub fn get(&self, scope: &CallScope, id: &str) -> Result<Value, ElicitationCallError> {
        self.route.call_scoped(
            scope,
            CONSENT_GET,
            json!({"elicitation_id": id}),
            CONTROL_RPC_TIMEOUT,
        )
    }

    /// Reserve time to tell Cingulate the tool call is no longer waiting, so
    /// later settlements notify the agent. A timed-out await returning pending
    /// is never an approval.
    pub fn wait_until(
        &self,
        scope: &CallScope,
        id: &str,
        deadline: Instant,
    ) -> Result<Value, ElicitationCallError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait = remaining
                .saturating_sub(CONTROL_RPC_TIMEOUT)
                .min(Duration::from_millis(AWAIT_MAX_MS))
                .min(AWAIT_ROUTE_DEADLINE - AWAIT_REPLY_RESERVE);
            if wait.as_millis() == 0 {
                return self.route.call_scoped(
                    scope,
                    CONSENT_DETACH,
                    json!({"elicitation_id": id}),
                    CONTROL_RPC_TIMEOUT.min(remaining),
                );
            }
            let started = Instant::now();
            let record = match self.route.call_scoped(
                scope,
                CONSENT_AWAIT,
                json!({"elicitation_id": id, "timeout_ms": wait.as_millis() as u64}),
                wait + AWAIT_REPLY_RESERVE,
            ) {
                Ok(record) => record,
                // A broken await ends the held wait too. Mark the card detached
                // before returning so Cingulate sends later answers as notices.
                Err(_) => {
                    return self.route.call_scoped(
                        scope,
                        CONSENT_DETACH,
                        json!({"elicitation_id": id}),
                        CONTROL_RPC_TIMEOUT.min(deadline.saturating_duration_since(Instant::now())),
                    )
                }
            };
            if record.get("state").and_then(Value::as_str) != Some("pending") {
                return Ok(record);
            }
            // A peer may answer pending without honoring its long-poll timeout.
            // Pace those replies without spending the time reserved for detach.
            let pause = Duration::from_millis(250)
                .saturating_sub(started.elapsed())
                .min(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .saturating_sub(CONTROL_RPC_TIMEOUT),
                );
            std::thread::sleep(pause);
        }
    }

    pub fn withdraw(&self, request: &ActionRequestRecord) {
        let (Some(id), Some(scope)) = (request.elicitation_id.as_deref(), request.scope.as_ref())
        else {
            return;
        };
        if let Err(error) = self.route.call_scoped(
            &scope.to_call_scope(),
            CONSENT_WITHDRAW,
            json!({"elicitation_id": id}),
            CONTROL_RPC_TIMEOUT,
        ) {
            eprintln!(warn consent: "could not withdraw consent card {id} ({})", error.code());
        }
    }

    pub(crate) fn report_execution(
        &self,
        scope: &CallScope,
        id: &str,
        execution: &str,
    ) -> Result<(), ElicitationCallError> {
        self.route
            .call_scoped(
                scope,
                CONSENT_REPORT_EXECUTION,
                json!({"elicitation_id": id, "execution": execution}),
                CONTROL_RPC_TIMEOUT,
            )
            .map(|_| ())
    }
}

/// Completed outcomes take precedence because TransportResponse::success sets
/// transmission to Sent. Other outcomes use the transport classification;
/// VendorFailed with any state except Failed is treated as uncertain.
pub(crate) fn execution_from_dispatch(
    dispatch: &crate::governance::DispatchOutcome,
) -> &'static str {
    use crate::governance::TransportOutcome;
    use crate::transport::TransmissionState;
    if matches!(dispatch.outcome, TransportOutcome::Completed { .. }) {
        return EXECUTED;
    }
    if matches!(dispatch.outcome, TransportOutcome::VendorFailed { .. })
        && dispatch.transmission != TransmissionState::Sent
    {
        return OUTCOME_UNKNOWN;
    }
    match dispatch.transmission {
        TransmissionState::Sent | TransmissionState::NotSent => APPROVED_NOT_EXECUTED,
        TransmissionState::OutcomeUnknown => OUTCOME_UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(
        transmission: crate::transport::TransmissionState,
        outcome: crate::governance::TransportOutcome,
    ) -> &'static str {
        execution_from_dispatch(&crate::governance::DispatchOutcome {
            reservation_id: "reservation".into(),
            reconciliation: None,
            transmission,
            retryability: crate::transport::Retryability::Terminal,
            retry_after_ms: None,
            error_signal: None,
            outcome,
        })
    }

    #[test]
    fn pre_send_refusal_is_reported_not_executed() {
        assert_eq!(
            report(
                crate::transport::TransmissionState::NotSent,
                crate::governance::TransportOutcome::NotSent {
                    code: "scope_ended".into(),
                    message: "scope ended".into()
                }
            ),
            "approved_not_executed"
        );
    }
    #[test]
    fn definite_vendor_failure_is_reported_not_executed() {
        assert_eq!(
            report(
                crate::transport::TransmissionState::Sent,
                crate::governance::TransportOutcome::VendorFailed {
                    code: "422".into(),
                    message: "definite refusal".into()
                }
            ),
            "approved_not_executed"
        );
    }
    #[test]
    fn uncertain_transmission_is_reported_unknown() {
        assert_eq!(
            report(
                crate::transport::TransmissionState::OutcomeUnknown,
                crate::governance::TransportOutcome::OutcomeUnknown
            ),
            "outcome_unknown"
        );
    }
    #[test]
    fn completed_outcome_is_reported_executed_with_definitively_sent_transmission() {
        assert_eq!(
            report(
                crate::transport::TransmissionState::Sent,
                crate::governance::TransportOutcome::Completed {
                    response: Some(json!({}))
                }
            ),
            "executed"
        );
    }
    #[test]
    fn inconsistent_vendor_failure_is_reported_unknown() {
        for state in [
            crate::transport::TransmissionState::NotSent,
            crate::transport::TransmissionState::OutcomeUnknown,
        ] {
            assert_eq!(
                report(
                    state,
                    crate::governance::TransportOutcome::VendorFailed {
                        code: "failure".into(),
                        message: "inconsistent transmission".into()
                    }
                ),
                "outcome_unknown"
            );
        }
    }

    fn scope() -> CallScope {
        CallScope {
            owner: "reserved:prefrontal-core".into(),
            scope_ref: "head".into(),
            scope_epoch: 7,
            kind: Some("head".into()),
            parent: None,
            parent_state: None,
            agent_id: Some("agent".into()),
            flow_id: None,
            delegates: true,
            owner_authorized: true,
        }
    }

    #[test]
    fn immediate_pending_replies_are_paced() {
        struct Immediate(std::sync::Mutex<Vec<Instant>>);
        impl ElicitationRoute for Immediate {
            fn call_scoped(
                &self,
                _: &CallScope,
                operation: &str,
                _: Value,
                _: Duration,
            ) -> Result<Value, ElicitationCallError> {
                assert_eq!(operation, CONSENT_AWAIT);
                let mut calls = self.0.lock().unwrap();
                calls.push(Instant::now());
                Ok(json!({"state": if calls.len()==1 { "pending" } else { "answered" }}))
            }
        }
        let route = Arc::new(Immediate(std::sync::Mutex::new(Vec::new())));
        let reply = ConsentCards::new(route.clone())
            .wait_until(&scope(), "card", Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(reply["state"], "answered");
        let calls = route.0.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[1].duration_since(calls[0]) >= Duration::from_millis(240));
    }

    #[test]
    fn pending_waits_detach_before_the_held_budget_ends() {
        struct Pending(std::sync::Mutex<Vec<String>>);
        impl ElicitationRoute for Pending {
            fn call_scoped(
                &self,
                _: &CallScope,
                op: &str,
                params: Value,
                timeout: Duration,
            ) -> Result<Value, ElicitationCallError> {
                self.0.lock().unwrap().push(op.into());
                if op == CONSENT_AWAIT {
                    let wait = params["timeout_ms"].as_u64().unwrap();
                    assert!(wait <= AWAIT_MAX_MS);
                    assert!(Duration::from_millis(wait) < timeout);
                    std::thread::sleep(Duration::from_millis(wait));
                }
                if op == CONSENT_DETACH {
                    // A detach needs time to commit and return its response;
                    // an instantaneous fake would not exercise the reserve.
                    assert!(
                        timeout >= Duration::from_millis(30),
                        "detach has insufficient reply budget"
                    );
                    std::thread::sleep(Duration::from_millis(30));
                }
                Ok(json!({"state":"pending", "detached": op == CONSENT_DETACH}))
            }
        }
        let route = Arc::new(Pending(std::sync::Mutex::new(Vec::new())));
        let cards = ConsentCards::new(route.clone());
        let start = Instant::now();
        let deadline = start + CONTROL_RPC_TIMEOUT + Duration::from_millis(30);
        let reply = cards.wait_until(&scope(), "card", deadline).unwrap();
        assert_eq!(reply["detached"], true);
        assert!(
            Instant::now() < deadline,
            "detach missed the caller's deadline"
        );
        let calls = route.0.lock().unwrap();
        assert!(calls.iter().any(|op| op == CONSENT_AWAIT));
        assert_eq!(calls.last().unwrap(), CONSENT_DETACH);
        assert_eq!(HELD_CALL_BUDGET, Duration::from_secs(110));
    }

    #[test]
    fn a_settled_detach_reply_is_returned_instead_of_pending() {
        struct Settled;
        impl ElicitationRoute for Settled {
            fn call_scoped(
                &self,
                _: &CallScope,
                op: &str,
                _: Value,
                _: Duration,
            ) -> Result<Value, ElicitationCallError> {
                assert_eq!(op, CONSENT_DETACH);
                Ok(json!({"state":"answered", "answered_choice_id":"approve"}))
            }
        }
        let reply = ConsentCards::new(Arc::new(Settled))
            .wait_until(&scope(), "card", Instant::now() + CONTROL_RPC_TIMEOUT)
            .unwrap();
        assert_eq!(reply["state"], "answered");
    }

    fn parked<'a>(args: &'a Value, risk: &'a str) -> ParkedApproval<'a> {
        ParkedApproval {
            complete_preview: false,
            request_id: "req-1",
            dedup_key: "reserved:broca:call-1",
            action_label: "Send message",
            service_label: "Slack",
            risk,
            args,
            args_digest: "sha256:00",
            expires_in_ms: 300_000,
        }
    }

    #[test]
    fn a_secret_named_argument_never_reaches_the_card() {
        let args = json!({
            "channel": "#general",
            "api_token": "tok-value-1",
            "auth": {"password": "pw-value-2"},
            "items": [{"client_secret": "sec-value-3"}],
            "text": "hello",
        });
        let body = consent_request_body(&parked(&args, "write"));
        let rendered = body.to_string();
        for secret in ["tok-value-1", "pw-value-2", "sec-value-3"] {
            assert!(!rendered.contains(secret), "{secret} leaked: {rendered}");
        }
        assert!(!contains_secret_input(&body), "{body}");
        let text = body["preview"]["text"].as_str().unwrap();
        assert!(text.contains("channel: #general"), "{text}");
        assert!(text.contains("api_token: [withheld]"), "{text}");
        assert!(text.contains("auth: [withheld]"), "{text}");
        assert!(text.contains("items: [withheld]"), "{text}");
    }

    /// A value shaped like a credential is withheld from the card even under
    /// an innocent argument name, in both the bounded and the complete
    /// preview. Hiding it costs nothing; the call itself is not refused for it.
    #[test]
    fn a_token_shaped_value_under_an_innocent_name_never_reaches_the_card() {
        let token = format!("ghp_{}", "Z".repeat(36));
        let args = json!({
            "channel": "#general",
            "text": format!("use {token} for the deploy"),
        });
        for complete_preview in [false, true] {
            let mut card = parked(&args, "write");
            card.complete_preview = complete_preview;
            let body = consent_request_body(&card);
            let rendered = body.to_string();
            assert!(!rendered.contains(&token), "the token leaked: {rendered}");
            let text = body["preview"]["text"].as_str().unwrap();
            assert!(text.contains("text: [withheld]"), "{text}");
            assert!(text.contains("channel: #general"), "{text}");
        }
        assert!(
            !contains_secret_input(&args),
            "the call carrying it is not refused"
        );
    }

    #[test]
    fn the_preview_is_bounded() {
        let args = json!({"body": "x".repeat(10_000), "more": "y".repeat(10_000),
                          "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6});
        let text = preview_text(&args);
        assert!(text.chars().count() <= PREVIEW_TEXT_MAX_CHARS, "{text}");
        assert!(text.contains('…'));
    }

    #[test]
    fn material_damage_follows_risk() {
        let args = json!({});
        for (risk, damage) in [("read", false), ("write", true), ("destructive", true)] {
            let body = consent_request_body(&parked(&args, risk));
            assert_eq!(body["material_damage"], damage, "{risk}");
        }
    }

    #[test]
    fn identity_is_absent_from_the_body() {
        let args = json!({"text": "hello"});
        let body = consent_request_body(&parked(&args, "write"));
        for field in [
            "principal",
            "subject",
            "agent_id",
            "owner",
            "requester",
            "session_ref",
            "parent_session_ref",
        ] {
            assert!(
                body.get(field).is_none(),
                "identity field {field} in {body}"
            );
        }
        assert_eq!(body["requester_ref"], "req-1");
        assert_eq!(body["dedup_key"], "reserved:broca:call-1");
    }
}
#[test]
fn credential_handle_values_are_redacted_under_ordinary_argument_names() {
    let value = "ckh_0123456789abcdef";
    for key in ["handle", "body", "actor", "note"] {
        let args = json!({key: value});
        assert!(
            !crate::secret_input::contains_secret_input(&args),
            "ordinary key refused"
        );
        for preview in [preview_text(&args), complete_preview_text(&args)] {
            assert!(
                !preview.contains(value),
                "preview exposed a vault handle: {preview}"
            );
            assert!(preview.contains(PREVIEW_WITHHELD));
        }
    }
    assert!(crate::secret_input::contains_secret_input(
        &json!({"credential_handle": "x"})
    ));
}
