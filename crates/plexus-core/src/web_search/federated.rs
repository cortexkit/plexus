//! Search authority is bound to the public tool, not its vendor adapter.

use super::{facade::SearchTool, CallerKey};
use crate::federated::{
    card::{CallBinding, CallerIdentity},
    FederatedCaller,
};
use crate::governance::{AuthorizationRequest, Denial};
use serde_json::{json, Map, Value};

#[derive(Clone)]
pub(crate) struct SearchAuthorization {
    pub caller: FederatedCaller,
    pub binding: CallBinding,
}

impl SearchAuthorization {
    pub fn new(
        caller: &FederatedCaller,
        tool: SearchTool,
        arguments: &Map<String, Value>,
    ) -> Result<Self, Denial> {
        Ok(Self {
            caller: caller.clone(),
            binding: CallBinding {
                caller: CallerIdentity::from(caller),
                owner_principal: String::new(),
                subject: tool.name().into(),
                action: tool.name().into(),
                args_digest: crate::jcs::jcs_sha256(&json!(arguments))
                    .map_err(|_| Denial::StoreFailure)?,
            },
        })
    }

    pub fn bind(&self, request: AuthorizationRequest) -> AuthorizationRequest {
        request
            .with_federated_caller(self.caller.clone())
            .with_federated_search(self.binding.clone())
    }

    pub fn caller_key(&self) -> Result<CallerKey, Denial> {
        Ok(CallerKey {
            principal: String::from_utf8(
                crate::jcs::canonicalize(&json!(self.binding.caller))
                    .map_err(|_| Denial::StoreFailure)?,
            )
            .map_err(|_| Denial::StoreFailure)?,
            agent_id: None,
        })
    }
}

/// The invoke denial members are retained inside the search error envelope.
pub(crate) fn denial_wire(denial: &Denial) -> Value {
    let mut error = json!({"code": denial.reason_code(), "terminal": denial.terminal(),
        "message": "governance denied the connector operation", "transmission": "not_sent"});
    match denial {
        Denial::FederatedPairingEnded | Denial::FederatedLivenessUnavailable => {
            error = json!({"code":denial.reason_code(), "message":denial.reason_code(),
                "retryable":matches!(denial, Denial::FederatedLivenessUnavailable), "transmission":"not_sent"});
        }
        Denial::ConsentUnavailable { action } => {
            let action = crate::text::refusal_echo(action);
            error["action"] = json!(action);
            error["message"] = json!(format!("consent_unavailable for action '{action}': no admissible session or consent route is available"));
        }
        Denial::NeedsDecisionPlane(_) => {
            error["message"] =
                json!("S3/S4 execution is not active: no production decision plane is configured.")
        }
        Denial::ArgumentUndeclared { field } => {
            error["field"] = json!(crate::text::refusal_echo(field))
        }
        Denial::RecipientArgumentInvalid { pointer } => error["pointer"] = json!(pointer),
        Denial::ConnectorHomeNotHeld { state } => {
            if state.pointer("/error/code").and_then(Value::as_str)
                == Some("request_deadline_exceeded")
            {
                return state.clone();
            }
            error = json!({"code":"connector_home_not_held", "message":format!("connector home not held: {state}"),"connectorHome":state,"transmission":"not_sent"});
        }
        _ => {}
    }
    json!({"error":error})
}

#[cfg(test)]
mod tests;
