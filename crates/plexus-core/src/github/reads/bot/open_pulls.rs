use super::*;

pub(super) fn project(
    repository: &str,
    prefix: Option<&str>,
    response: &Value,
) -> Result<Value, BotReadError> {
    // A successful HTTP status may still carry GraphQL errors and partial data.
    // Returning that data would disguise a permission failure as an empty queue.
    if response
        .get("errors")
        .is_some_and(|errors| !errors.is_null())
    {
        return Err(BotReadError::InvalidResponse);
    }
    let connection = &response["data"]["repository"]["pullRequests"];
    let nodes = connection["nodes"]
        .as_array()
        .filter(|nodes| nodes.len() <= 100)
        .ok_or(BotReadError::InvalidResponse)?;
    let truncated = connection["pageInfo"]["hasNextPage"]
        .as_bool()
        .ok_or(BotReadError::InvalidResponse)?;
    let mut prs = Vec::new();
    for node in nodes {
        let head = node["headRefName"]
            .as_str()
            .ok_or(BotReadError::InvalidResponse)?;
        if prefix.is_some_and(|prefix| !head.starts_with(prefix)) {
            continue;
        }
        let threads = node["reviewThreads"]["nodes"]
            .as_array()
            .filter(|nodes| nodes.len() <= 100)
            .ok_or(BotReadError::InvalidResponse)?;
        let unresolved = threads
            .iter()
            .map(|thread| {
                thread["isResolved"]
                    .as_bool()
                    .ok_or(BotReadError::InvalidResponse)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|resolved| !resolved)
            .count();
        if !node["number"].is_u64()
            || !node["headRefOid"].is_string()
            || !node["updatedAt"].is_string()
            || !matches!(
                node["mergeable"].as_str(),
                Some("MERGEABLE" | "CONFLICTING" | "UNKNOWN")
            )
            || !node["isInMergeQueue"].is_boolean()
        {
            return Err(BotReadError::InvalidResponse);
        }
        let threads_truncated = node["reviewThreads"]["pageInfo"]["hasNextPage"]
            .as_bool()
            .ok_or(BotReadError::InvalidResponse)?;
        prs.push(json!({"number":node["number"], "headRefName":head, "headRefOid":node["headRefOid"],
            "updatedAt":node["updatedAt"], "mergeable":node["mergeable"], "isInMergeQueue":node["isInMergeQueue"],
            "unresolved_threads":unresolved, "threads_truncated":threads_truncated}));
    }
    Ok(json!({"repository":repository,"prs":prs,"truncated":truncated}))
}
