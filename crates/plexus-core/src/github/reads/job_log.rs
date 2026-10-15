use super::*;

pub(super) fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
) -> Result<Value, ReadError> {
    let repository = ci::repository(repository, "job_log_arguments_invalid")?;
    let (owner, repo) = repository.split_once('/').unwrap();
    let fields = args
        .as_object()
        .ok_or(ReadError::Refused("job_log_arguments_invalid"))?;
    if fields
        .keys()
        .any(|key| !matches!(key.as_str(), "job_id" | "max_bytes"))
    {
        return Err(ReadError::Refused("job_log_arguments_invalid"));
    }
    let job_id = args
        .get("job_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(ReadError::Refused("job_log_arguments_invalid"))?;
    let max_bytes = match args.get("max_bytes") {
        None => 65_536,
        Some(value) => value
            .as_u64()
            .filter(|bytes| (1..=262_144).contains(bytes))
            .ok_or(ReadError::Refused("job_log_arguments_invalid"))?,
    };
    let mut quota = ci::ReadQuota::new(2);
    let mut invoke = |action: &str, args: Value| -> Result<Value, ReadError> {
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
        .map_err(|error| match error {
            ReadError::Dispatch(TransportOutcome::VendorFailed { code, .. }) => {
                ReadError::Refused(match code.as_str() {
                    "http_404" | "http_410" | "job_log_unavailable" => "job_log_unavailable",
                    "job_log_redirect_refused" => "job_log_redirect_refused",
                    "job_log_read_limit" => "job_log_read_limit",
                    "job_log_download_failed" => "job_log_download_failed",
                    _ => "job_log_read_failed",
                })
            }
            other => other,
        })
    };
    let job = invoke(
        "get_job",
        json!({"owner":owner,"repo":repo,"job_id":job_id}),
    )?;
    if job.get("status").and_then(Value::as_str) != Some("completed") {
        return Err(ReadError::Refused("job_not_finished"));
    }
    let tail = invoke(
        "github.actions.job_log",
        json!({"owner":owner,"repo":repo,"job_id":job_id,"max_bytes":max_bytes}),
    )?;
    let total = tail
        .get("total_bytes")
        .and_then(Value::as_u64)
        .ok_or(ReadError::InvalidResponse)?;
    let truncated = tail
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or(ReadError::InvalidResponse)?;
    let text = tail
        .get("text")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(ReadError::Refused("job_log_unavailable"))?;
    Ok(
        json!({"repository":repository,"job_id":job_id,"total_bytes":total,"truncated":truncated,"text":text}),
    )
}
