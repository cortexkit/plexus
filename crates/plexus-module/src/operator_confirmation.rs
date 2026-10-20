//! Operation-bound step-up for authority minted through the management surface.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use subc_protocol::session::{OperatorConfirmReply, OperatorConfirmRequest};
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::mpsc;

use crate::{manifest, scope_reader::PendingControlReplies, RouteFrameContext};

const CONFIRM_TIMEOUT: Duration = Duration::from_secs(290);

#[derive(Debug)]
pub(crate) struct Refusal {
    pub code: &'static str,
    pub reason: String,
}

impl Refusal {
    fn unavailable(reason: impl ToString) -> Self {
        Self {
            code: "operator_confirmation_unavailable",
            reason: reason.to_string(),
        }
    }
}

/// Whether this request can need confirmation, without consulting mutable state.
/// The admin client uses this to leave enough time for a person's response.
pub fn may_need_confirmation(method: &str, params: &Value) -> bool {
    match method {
        manifest::ADMIN_ISSUE_TICKET_OP
        | manifest::ADMIN_GRANT_OP
        | manifest::ADMIN_REPIN_ACTION_OP => true,
        manifest::ADMIN_SET_POLICY_OP => params["effect"] == "allow",
        manifest::ADMIN_REBIND_CREDENTIAL_OP => params["apply"] == true,
        manifest::ADMIN_WIDEN_CEILING_OP
        | manifest::ADMIN_RECIPIENTS_ADD_OP
        | manifest::GITHUB_BIND_OP
        | manifest::GITHUB_GRANT_OP
        | manifest::GITHUB_IMPORT_OP => params["dry_run"] == false,
        _ => false,
    }
}

pub(crate) fn summary(method: &str, params: &Value) -> Option<String> {
    if !may_need_confirmation(method, params) {
        return None;
    }
    // Only authority identifiers are included, never credential IDs, inventory
    // contents, or arbitrary argument dumps. Restrict caller-supplied labels to
    // identifier characters so they cannot add sentences or prompt formatting.
    let label = |field: &str, fallback: &str| {
        params[field]
            .as_str()
            .unwrap_or(fallback)
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "-_:./*".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .take(60)
            .collect::<String>()
    };
    let connection = label("connection_id", "the connection");
    Some(match method {
        manifest::ADMIN_ISSUE_TICKET_OP => format!(
            "issue a binding ticket for {} on {connection}",
            label("app_key", "the app")
        ),
        manifest::ADMIN_GRANT_OP => format!(
            "grant {} {} on {connection}",
            label("grantee_principal", "direct"),
            label("authority_kind", "invoke")
        ),
        manifest::ADMIN_WIDEN_CEILING_OP => format!("widen the action ceiling on {connection}"),
        manifest::ADMIN_SET_POLICY_OP => format!(
            "allow {} on {connection}",
            label("action_selector", "the selected actions")
        ),
        manifest::ADMIN_REPIN_ACTION_OP => format!(
            "repin and unquarantine {} on {connection}",
            label("action", "the action")
        ),
        manifest::ADMIN_REBIND_CREDENTIAL_OP => {
            format!("replace credential authority on {connection}")
        }
        manifest::ADMIN_RECIPIENTS_ADD_OP => format!(
            "authorize a messaging recipient on {}",
            label("connection", "the connection")
        ),
        manifest::GITHUB_IMPORT_OP => "import GitHub App handle authority".to_string(),
        manifest::GITHUB_BIND_OP => format!(
            "bind repository authority to GitHub handle {}",
            label("app_handle_id", "the handle")
        ),
        manifest::GITHUB_GRANT_OP => format!(
            "grant {} authority on GitHub handle {}",
            label("kind", "invoke"),
            if params["all_handles"] == true {
                "all enabled handles".to_owned()
            } else {
                label("app_handle_id", "the handle")
            }
        ),
        _ => unreachable!("only authority-widening ceremonies need confirmation"),
    })
}

pub(crate) fn audit_refusal(state: &crate::ModuleState, method: &str, refusal: &Refusal) -> Value {
    let mut response = crate::tool_error(refusal.code, &refusal.reason);
    let mut audit =
        plexus_core::storage::AuditRecord::ceremony("direct", None, None, method, "", None);
    audit.risk = None;
    audit.decision = "deny".to_string();
    audit.reason_code = refusal.code.to_string();
    audit.gate = Some("operator_confirmation".to_string());
    audit.outcome = Some("refused".to_string());
    audit.request_id = Some(crate::fresh_request_id());
    if let Err(error) = state.store().append_audit(&audit) {
        crate::warn_audit_failed(&mut response, "operator confirmation refusal", &error);
    }
    response
}

struct Withdrawal<'a> {
    pending: &'a PendingControlReplies,
    writer: &'a mpsc::Sender<Frame>,
    route: RouteFrameContext,
    correlation: u64,
    accepted: bool,
    answered: bool,
}

impl Drop for Withdrawal<'_> {
    fn drop(&mut self) {
        self.pending.forget(self.correlation);
        if self.accepted && !self.answered {
            if let Ok(cancel) = Frame::build_with_version(
                self.route.version,
                FrameType::Cancel,
                crate::wire::control_flags(),
                0,
                0,
                self.correlation,
                Vec::new(),
            ) {
                match self.writer.try_send(cancel) {
                    Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                    Err(mpsc::error::TrySendError::Full(cancel)) => {
                        let writer = self.writer.clone();
                        tokio::spawn(async move {
                            let _ = writer.send(cancel).await;
                        });
                    }
                }
            }
        }
    }
}

pub(crate) async fn confirm(
    summary: &str,
    route: RouteFrameContext,
    writer: &mpsc::Sender<Frame>,
    pending: &Arc<PendingControlReplies>,
) -> Result<(), Refusal> {
    confirm_with_timeout(summary, route, writer, pending, CONFIRM_TIMEOUT).await
}

pub(crate) async fn confirm_with_timeout(
    summary: &str,
    route: RouteFrameContext,
    writer: &mpsc::Sender<Frame>,
    pending: &Arc<PendingControlReplies>,
    timeout: Duration,
) -> Result<(), Refusal> {
    let deadline = tokio::time::Instant::now() + timeout;
    let body = serde_json::to_vec(&OperatorConfirmRequest::new(
        summary,
        route.channel,
        route.epoch,
    ))
    .map_err(Refusal::unavailable)?;
    let (correlation, replies) = pending
        .register()
        .map_err(|error| Refusal::unavailable(error.0))?;
    let mut withdrawal = Withdrawal {
        pending,
        writer,
        route,
        correlation,
        accepted: false,
        answered: false,
    };
    let frame = Frame::build_with_version(
        route.version,
        FrameType::Request,
        crate::wire::control_flags(),
        0,
        0,
        correlation,
        body,
    )
    .map_err(Refusal::unavailable)?;
    tokio::time::timeout_at(deadline, writer.send(frame))
        .await
        .map_err(|_| Refusal::unavailable("operator confirmation send deadline elapsed"))?
        .map_err(|_| Refusal::unavailable("the daemon connection is closed"))?;
    withdrawal.accepted = true;
    // PendingControlReplies returns synchronous receivers for its scope.describe
    // callers. Receive on the blocking pool so the async dispatch loop remains
    // free to deliver the daemon's answer.
    let wait = tokio::task::spawn_blocking(move || {
        replies.recv_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()))
    });
    let reply = tokio::time::timeout_at(deadline, wait)
        .await
        .map_err(|_| Refusal::unavailable("operator confirmation deadline elapsed"))?
        .map_err(Refusal::unavailable)?
        .map_err(|_| {
            Refusal::unavailable("the daemon did not answer operator confirmation in time")
        })?;
    withdrawal.answered = true;
    if reply.header.ty == FrameType::Response {
        return match serde_json::from_slice::<OperatorConfirmReply>(&reply.body) {
            Ok(reply) if reply.outcome == "confirmed" => Ok(()),
            _ => Err(Refusal::unavailable(
                "unrecognized operator confirmation reply",
            )),
        };
    }
    match serde_json::from_slice::<ErrorBody>(&reply.body) {
        Ok(error) if reply.header.ty == FrameType::Error => Err(Refusal {
            code: if error.code == subc_protocol::error_codes::OPERATOR_DECLINED {
                "operator_confirmation_declined"
            } else {
                "operator_confirmation_unavailable"
            },
            reason: format!("{}: {}", error.code, error.message),
        }),
        _ => Err(Refusal::unavailable(
            "unreadable operator confirmation refusal",
        )),
    }
}

/// A wire-level fake for handler tests; it never connects to a presence service.
#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn approving_test_peer(
    mut requests: mpsc::Receiver<Frame>,
    writer: &mpsc::Sender<Frame>,
    pending: &PendingControlReplies,
) {
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("test peer request deadline")
    {
        if frame.header.channel == 0 && frame.header.ty == FrameType::Request {
            let _: OperatorConfirmRequest =
                serde_json::from_slice(&frame.body).expect("confirmation request");
            assert!(pending.complete(
                Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Response,
                    crate::wire::control_flags(),
                    0,
                    0,
                    frame.header.corr,
                    serde_json::to_vec(&OperatorConfirmReply::confirmed()).unwrap(),
                )
                .unwrap()
            ));
        } else {
            writer.send(frame).await.expect("test response receiver");
            return;
        }
    }
}
