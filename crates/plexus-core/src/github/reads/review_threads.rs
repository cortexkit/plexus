use super::*;
use std::collections::BTreeSet;

const MAX_PAGES: usize = 3;

pub(super) fn validate_args(args: &Value) -> Result<(), ReadError> {
    let fields = args
        .as_object()
        .ok_or(ReadError::Refused("review_threads_arguments_invalid"))?;
    // Only the PR number is caller-controlled. Query text, variables, cursors
    // and pagination limits belong to the reviewed action and its bounded walk.
    if fields.keys().any(|key| key != "pr") {
        return Err(ReadError::Refused("review_threads_arguments_invalid"));
    }
    args["pr"]
        .as_u64()
        .filter(|pr| *pr > 0 && *pr <= i32::MAX as u64)
        .ok_or(ReadError::Refused("review_threads_arguments_invalid"))?;
    Ok(())
}

pub(super) fn read(
    repository: &str,
    pr: &Value,
    mut invoke: impl FnMut(Option<&str>) -> Result<Value, ReadError>,
) -> Result<Value, ReadError> {
    let mut threads = Vec::new();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        let response = invoke(cursor.as_deref())?;
        // HTTP 200 can carry GraphQL errors and partial data. Do not present a
        // partial or permission-filtered result as a complete thread listing.
        if response
            .get("errors")
            .is_some_and(|errors| !errors.is_null())
        {
            return Err(ReadError::InvalidResponse);
        }
        let connection = response
            .pointer("/data/repository/pullRequest/reviewThreads")
            .ok_or(ReadError::InvalidResponse)?;
        let nodes = connection["nodes"]
            .as_array()
            .filter(|nodes| nodes.len() <= 100)
            .ok_or(ReadError::InvalidResponse)?;
        for node in nodes {
            threads.push(thread(node)?);
        }
        let more = connection
            .pointer("/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            .ok_or(ReadError::InvalidResponse)?;
        if !more || page == MAX_PAGES {
            return Ok(
                json!({"repository":repository,"pr":pr,"threads":threads,"incomplete":more}),
            );
        }
        let next = connection
            .pointer("/pageInfo/endCursor")
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty())
            .ok_or(ReadError::InvalidResponse)?;
        if !seen.insert(next.to_owned()) {
            return Err(ReadError::InvalidResponse);
        }
        cursor = Some(next.to_owned());
    }
    unreachable!("the last allowed page returns an incomplete listing")
}

fn thread(node: &Value) -> Result<Value, ReadError> {
    let id = node["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or(ReadError::InvalidResponse)?;
    let resolved = node["isResolved"]
        .as_bool()
        .ok_or(ReadError::InvalidResponse)?;
    let outdated = node["isOutdated"]
        .as_bool()
        .ok_or(ReadError::InvalidResponse)?;
    let comments = node
        .pointer("/comments/nodes")
        .and_then(Value::as_array)
        .filter(|comments| comments.len() <= 1)
        .ok_or(ReadError::InvalidResponse)?;
    let first = comments.first();
    let text = |pointer| {
        first
            .and_then(|comment| comment.pointer(pointer))
            .and_then(Value::as_str)
    };
    let (excerpt, _) = crate::review_body::excerpt(text("/body"));
    Ok(json!({
        "thread_id":id,"is_resolved":resolved,"is_outdated":outdated,
        "path":node["path"].as_str(),"line":node["line"].as_u64(),
        "author_login":text("/author/login"),
        "author_is_bot":text("/author/__typename").map(|kind| kind == "Bot"),
        "body_excerpt":excerpt,"url":text("/url"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_projects_first_comment_and_nulls_without_guessing_bot_login() {
        let mut node = json!({"id":"PRRT_1","isResolved":false,"isOutdated":true,"path":"a.rs","line":null,
            "comments":{"nodes":[{"author":{"login":"human[bot]","__typename":"User"},"body":"hello","url":"https://github.com/o/r/pull/1#discussion_r1"}]}});
        let result = thread(&node).unwrap();
        assert_eq!(result["author_login"], "human[bot]");
        assert_eq!(result["author_is_bot"], false);
        assert_eq!(result["is_outdated"], true);
        node["comments"]["nodes"] = json!([]);
        let result = thread(&node).unwrap();
        for field in [
            "line",
            "author_login",
            "author_is_bot",
            "body_excerpt",
            "url",
        ] {
            assert!(result.get(field).unwrap().is_null());
        }
    }

    #[test]
    fn repeated_or_missing_page_cursors_refuse_instead_of_looping() {
        for cursor in [Value::Null, json!(""), json!("repeated")] {
            let response = json!({"data":{"repository":{"pullRequest":{"reviewThreads":{
                "nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":cursor}
            }}}}});
            assert_eq!(
                read("o/r", &json!(1), |_| Ok(response.clone())),
                Err(ReadError::InvalidResponse)
            );
        }
    }
}
