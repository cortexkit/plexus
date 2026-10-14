//! Job-log and artifact reads restrict agent-stamped Basal flows to repositories
//! bound to that agent's enabled bot, and authorize every API request independently.
use super::*;

pub(super) fn repository(value: &Value, invalid: &'static str) -> Result<String, ReadError> {
    let name = value.as_str().ok_or(ReadError::Refused(invalid))?;
    let name = crate::github::canonical_repository(name);
    name.split_once('/')
        .filter(|(owner, repo)| {
            !owner.is_empty()
                && !repo.is_empty()
                && !repo.contains('/')
                && [*owner, *repo].iter().all(|part| {
                    part.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                })
                && !matches!(*repo, "." | "..")
        })
        .ok_or(ReadError::Refused(invalid))?;
    Ok(name)
}

pub(super) fn invoke<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &str,
    action: &str,
    args: Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
) -> Result<Value, ReadError> {
    let visible = || -> Result<(), ReadError> {
        if let Some(agent) = crate::scope::basal_flow_read_agent(principal, scope) {
            let handle = engine
                .store()
                .github_handle_for_repo(repository)
                .map_err(|_| ReadError::Denied(Denial::StoreFailure))?;
            if !handle.is_some_and(|handle| handle.agent_id == agent && handle.status == "enabled")
            {
                return Err(ReadError::Refused("repository_not_visible"));
            }
        }
        Ok(())
    };
    visible()?;
    let mut request = AuthorizationRequest::new(
        principal,
        crate::poller::GITHUB_ACTIONS_CONNECTION,
        action,
        args,
    )
    .with_diagnostic_tool("github");
    if let Some(scope) = scope {
        request = request.with_scope_attribution_only(scope.clone());
    }
    if let Some(agent) = attributed_agent {
        request = request.with_attributed_agent(agent);
    }
    let reservation = engine.authorize(request).map_err(ReadError::Denied)?;
    // Bindings can change during authorization; recheck before sending each leg.
    visible()?;
    match engine.revalidate_and_dispatch(&reservation).outcome {
        TransportOutcome::Completed {
            response: Some(value),
        } => Ok(value),
        other => Err(ReadError::Dispatch(other)),
    }
}
