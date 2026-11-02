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
        let bindings = result["bindings"].as_array_mut().expect("binding rows");
        bindings.retain(|binding| {
            agent.is_none_or(|agent| binding["agent_id"] == agent)
                && audience.is_none_or(|audience| {
                    flow_audience::repository_allowed(
                        state.store(),
                        audience,
                        binding["repository"].as_str().expect("stored repository"),
                    )
                })
        });
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
