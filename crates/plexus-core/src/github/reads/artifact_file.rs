use super::*;

use crate::rest_api::artifact_file::MAX_ARTIFACT_BYTES;

pub(super) fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
) -> Result<Value, ReadError> {
    let invalid = ReadError::Refused("artifact_arguments_invalid");
    let repository = ci::repository(repository, "artifact_arguments_invalid")?;
    let (owner, repo) = repository.split_once('/').unwrap();
    let fields = args.as_object().ok_or_else(|| invalid.clone())?;
    if fields
        .keys()
        .any(|key| !matches!(key.as_str(), "run_id" | "artifact" | "path" | "max_bytes"))
    {
        return Err(invalid);
    }
    let run_id = args
        .get("run_id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| invalid.clone())?;
    let artifact = args
        .get("artifact")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid.clone())?;
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| {
            !path.is_empty() && crate::rest_api::artifact_file::safe_path(path.as_bytes())
        })
        .ok_or_else(|| invalid.clone())?;
    let max_bytes = match args.get("max_bytes") {
        None => 65_536,
        Some(value) => value
            .as_u64()
            .filter(|bytes| (1..=262_144).contains(bytes))
            .ok_or(invalid)?,
    };
    // Up to 100 listing pages and one authenticated ZIP redirect request.
    let mut quota = ci::ReadQuota::new(101);
    let mut invoke = |action: &str, args: Value| {
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
                    "artifact_too_large" => "artifact_too_large",
                    "artifact_invalid_zip" => "artifact_invalid_zip",
                    "artifact_file_not_found" => "artifact_file_not_found",
                    "http_404" | "http_410" | "job_log_unavailable" => "artifact_not_found",
                    "job_log_redirect_refused" => "job_log_redirect_refused",
                    "job_log_read_limit" => "job_log_read_limit",
                    "job_log_download_failed" => "job_log_download_failed",
                    _ => "artifact_read_failed",
                })
            }
            other => other,
        })
    };
    let mut newest: Option<(i64, Value)> = None;
    let mut seen = 0u64;
    // Walk filtered pages before selecting; API ordering is not the selection rule.
    for page in 1..=100 {
        let listed = invoke(
            "list_workflow_run_artifacts",
            json!({"owner":owner,"repo":repo,"run_id":run_id,"name":artifact,"page":page}),
        )?;
        let entries = listed
            .get("artifacts")
            .and_then(Value::as_array)
            .ok_or(ReadError::InvalidResponse)?;
        let total = listed
            .get("total_count")
            .and_then(Value::as_u64)
            .ok_or(ReadError::InvalidResponse)?;
        for entry in entries {
            if entry.get("name").and_then(Value::as_str) != Some(artifact) {
                continue;
            }
            let created = entry
                .get("created_at")
                .and_then(Value::as_str)
                .and_then(crate::poller::iso8601::parse_to_millis)
                .ok_or(ReadError::InvalidResponse)?;
            if newest
                .as_ref()
                .is_none_or(|(previous, _)| created > *previous)
            {
                newest = Some((created, entry.clone()));
            }
        }
        seen += entries.len() as u64;
        if seen >= total {
            break;
        }
        if entries.is_empty() || page == 100 {
            return Err(ReadError::Refused("job_log_read_limit"));
        }
    }
    let (_, selected) = newest.ok_or(ReadError::Refused("artifact_not_found"))?;
    match selected.get("expired").and_then(Value::as_bool) {
        Some(true) => return Err(ReadError::Refused("artifact_expired")),
        Some(false) => {}
        None => return Err(ReadError::InvalidResponse),
    }
    let size = selected
        .get("size_in_bytes")
        .and_then(Value::as_u64)
        .ok_or(ReadError::InvalidResponse)?;
    if size > MAX_ARTIFACT_BYTES {
        return Err(ReadError::Refused("artifact_too_large"));
    }
    let id = selected
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(ReadError::InvalidResponse)?;
    let tail = invoke(
        "github.actions.artifact_file",
        json!({"owner":owner,"repo":repo,"artifact_id":id,"path":path,"max_bytes":max_bytes}),
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
        .ok_or(ReadError::InvalidResponse)?;
    Ok(
        json!({"repository":repository,"run_id":run_id,"artifact":artifact,"path":path,"total_bytes":total,"truncated":truncated,"text":text}),
    )
}
