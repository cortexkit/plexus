use super::*;

fn summary(value: &Value) -> Result<(Value, i64, u64, u64), ReadError> {
    let id = value
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(ReadError::InvalidResponse)?;
    let number = value
        .get("run_number")
        .and_then(Value::as_u64)
        .ok_or(ReadError::InvalidResponse)?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or(ReadError::InvalidResponse)?;
    let conclusion = value
        .get("conclusion")
        .filter(|v| v.is_null() || v.is_string())
        .ok_or(ReadError::InvalidResponse)?;
    let created = value
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or(ReadError::InvalidResponse)?;
    let timestamp =
        crate::poller::iso8601::parse_to_millis(created).ok_or(ReadError::InvalidResponse)?;
    Ok((
        json!({"id":id,"run_number":number,"status":status,"conclusion":conclusion,"created_at":created}),
        timestamp,
        number,
        id,
    ))
}

pub(super) fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
) -> Result<Value, ReadError> {
    let repository = ci::repository(repository, "run_arguments_invalid")?;
    let (owner, repo) = repository.split_once('/').unwrap();
    let fields = args
        .as_object()
        .ok_or(ReadError::Refused("run_arguments_invalid"))?;
    if fields.keys().any(|key| key != "run_id") {
        return Err(ReadError::Refused("run_arguments_invalid"));
    }
    let run_id = args
        .get("run_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(ReadError::Refused("run_arguments_invalid"))?;
    let mut quota = ci::ReadQuota::new(2);
    let mut invoke = |action, args| {
        ci::invoke(
            engine,
            principal,
            &repository,
            action,
            args,
            scope,
            attributed_agent,
            &mut quota,
        )
    };
    let run = invoke(
        "get_workflow_run_metadata",
        json!({"owner":owner,"repo":repo,"run_id":run_id}),
    )
    .map_err(|error| match error {
        ReadError::Dispatch(TransportOutcome::VendorFailed { code, .. }) if code == "http_404" => {
            ReadError::Refused("run_not_found")
        }
        other => other,
    })?;
    let branch = match run.get("head_branch") {
        Some(Value::Null) => return Err(ReadError::Refused("run_branch_unknown")),
        Some(Value::String(branch)) if !branch.is_empty() => branch,
        _ => return Err(ReadError::InvalidResponse),
    };
    let workflow = run
        .get("workflow_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(ReadError::InvalidResponse)?;
    let (run, created, number, id) = summary(&run)?;
    if id != run_id {
        return Err(ReadError::InvalidResponse);
    }
    let latest = invoke(
        "list_workflow_runs_for_workflow",
        json!({"owner":owner,"repo":repo,"workflow_id":workflow,"branch":branch}),
    )?;
    let runs = latest
        .get("workflow_runs")
        .and_then(Value::as_array)
        .ok_or(ReadError::InvalidResponse)?;
    let mut newer = Value::Null;
    if let Some(candidate) = runs.first() {
        let (mut candidate_summary, candidate_created, candidate_number, candidate_id) =
            summary(candidate)?;
        if candidate_id != run_id
            && (candidate_created > created
                || (candidate_created == created && candidate_number > number))
        {
            let url = candidate
                .get("html_url")
                .and_then(Value::as_str)
                .ok_or(ReadError::InvalidResponse)?;
            candidate_summary["url"] = json!(url);
            newer = candidate_summary;
        }
    }
    Ok(json!({"repository":repository,"superseded":!newer.is_null(),"run":run,"newer":newer}))
}
