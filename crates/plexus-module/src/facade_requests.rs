//! Facade approval-request inspection, listing and decisions.

use super::*;

pub(super) fn facade_requests_inspect(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(id) = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Ok(tool_error(
                "invalid_request",
                "requests inspect requires request_id",
            ));
        };
        match state.store().list_action_requests(principal_key) {
            Ok(requests) => {
                json!({"result":{"requests":requests.into_iter().filter(|request| request.request_id == id).collect::<Vec<_>>(),"reconciliations":[]}})
            }
            Err(error) => {
                wire::store_failure("request inspected", "request could not be read", &error)
            }
        }
    })
}

pub(super) fn facade_requests_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let principal_key = call.principal_key;
    Ok({
        match state
            .store()
            .list_action_requests(principal_key)
            .and_then(|requests| {
                state
                    .store()
                    .list_write_reconciliations(principal_key)
                    .map(|reconciliations| (requests, reconciliations))
            }) {
            Ok((requests, (reconciliations, reconciliations_truncated))) => {
                json!({"result": {"requests": requests, "reconciliations": reconciliations, "reconciliations_truncated": reconciliations_truncated}})
            }
            Err(error) => {
                crate::wire::store_failure("requests read", "requests could not be read", &error)
            }
        }
    })
}

pub(super) fn facade_requests_approve(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(request_id) = arguments.get("request_id").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "approve requires request_id"}}),
            );
        };
        // Approving dispatches the call, which may reach a blocking vendor
        // transport and, for a request raised under a daemon scope, waits
        // on the daemon's scope.describe reply.
        blocking_section(|| {
            match state
                .runtime
                .engine
                .approve_request(principal_key, request_id, principal_key)
            {
                Ok(outcome) => dispatch_response(outcome),
                Err(denial) => denial_response(&denial),
            }
        })
    })
}

pub(super) fn facade_requests_deny(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(request_id) = arguments.get("request_id").and_then(Value::as_str) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "deny requires request_id"}}),
            );
        };
        match state
            .runtime
            .engine
            .deny_request(principal_key, request_id, principal_key)
        {
            Ok(true) => json!({"result": {"denied": true}}),
            Ok(false) => {
                json!({"error": {"code": "request_not_pending", "message": "request is no longer pending"}})
            }
            Err(denial) => denial_response(&denial),
        }
    })
}
