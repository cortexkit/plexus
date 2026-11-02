use super::*;

pub(super) fn reply(
    state: &ModuleState,
    principal: &str,
    arguments: &serde_json::Map<String, Value>,
    scope: Option<&CallScope>,
    audience: Option<&flow_audience::Audience>,
) -> Value {
    let agent = plexus_core::scope::basal_flow_read_agent(principal, scope);
    let result = (|| {
        if let Some(field) = arguments.keys().find(|field| field.as_str() != "action") {
            return json!({"error":{"code":"invalid_request","field":field}});
        }
        let mut result = match state.store().read_github_bindings_for_module(principal) {
            Ok(result) => result,
            Err(_) => return denial_response(&plexus_core::Denial::StoreFailure),
        };
        let generation = result["repo_binding_generation"].clone();
        let rows = std::mem::take(result["bindings"].as_array_mut().expect("binding rows"));
        let mut bindings = Vec::with_capacity(rows.len());
        for binding in rows {
            if agent.is_some_and(|agent| binding["agent_id"] != agent) {
                continue;
            }
            if let Some(audience) = audience {
                // A failed project lookup must refuse the whole read: dropping
                // the row would hand the caller a complete-looking list with a
                // repository missing, which a flow would then cache by generation.
                let repository = binding["repository"].as_str().expect("stored repository");
                match flow_audience::try_repository_allowed(state.store(), audience, repository) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(_) => return denial_response(&plexus_core::Denial::StoreFailure),
                }
            }
            bindings.push(binding);
        }
        json!({"result":{"generation":generation,"bindings":bindings}})
    })();
    let mut response = result;
    if let Err(error) = state.store().audit_github_control(
        principal,
        agent,
        None,
        "github.bindings.list",
        &fresh_request_id(),
        response.pointer("/error/code").and_then(Value::as_str),
    ) {
        warn_audit_failed(&mut response, "github.bindings.list", &error);
    }
    response
}

#[cfg(test)]
#[path = "github_bindings_list_tests.rs"]
mod tests;
