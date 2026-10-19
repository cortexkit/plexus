//! Bot read actions whose reply keeps what a `gh`-style caller needs from the
//! HTTP response, not just its body: the status, the next page from `Link`,
//! and GitHub's rate-limit headers, which the bot read budget records.
//!
//! The policy is the bot read layer's (`github/reads/bot.rs`); it is checked
//! again here, where the URL is built, so a refused path or media type cannot
//! reach the wire even from a crate-internal caller that skipped it. Redirects
//! are never followed: each request the read budget charged is exactly one
//! HTTP request.
use super::*;
use crate::github::reads::bot::{self, EnvelopeShape};

fn refused_locally(reason: &str) -> TransportResponse {
    eprintln!(warn transport: "REST bot read refused locally: {reason}");
    local_not_sent()
}

/// GitHub's rate-limit headers, as the bot read budget stores them.
fn rate_limit(headers: &reqwest::header::HeaderMap) -> Value {
    let number = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<i64>().ok())
    };
    match (number("x-ratelimit-remaining"), number("x-ratelimit-reset")) {
        (Some(remaining), Some(reset)) => serde_json::json!({
            "remaining": remaining,
            "reset_at_ms": reset.saturating_mul(1_000),
        }),
        _ => Value::Null,
    }
}

/// The internal projection a failed bot read carries in its error message:
/// the status and rate-limit headers, never the body.
fn projection(status: u16, rate_limit: &Value) -> String {
    serde_json::json!({"status": status, "rate_limit": rate_limit}).to_string()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn send(
    client: &Client,
    throttle_until: &mut Option<Instant>,
    config: &RestConfig,
    operation: &HttpOperation,
    shape: EnvelopeShape,
    request: &TransportRequest,
    credential: &ResolvedCredential,
) -> TransportResponse {
    if operation.method != HttpMethod::Get {
        return refused_locally("bot reads are GET only");
    }
    let Some(mut args) = request.args.as_object().cloned() else {
        return refused_locally("arguments are not an object");
    };
    let Some(media_type) = bot::accepted_media_type(args.remove("accept").as_ref()) else {
        return refused_locally("media type not allowed");
    };
    let query = match args.remove("query") {
        None => Map::new(),
        Some(Value::Object(query)) if query.values().all(Value::is_string) => query,
        Some(_) => return refused_locally("query is not a flat string map"),
    };
    let suffix = if shape.relative_path {
        match args
            .remove("path")
            .as_ref()
            .and_then(Value::as_str)
            .and_then(bot::relative_path)
        {
            Some(suffix) => suffix,
            None => return refused_locally("path not allowed"),
        }
    } else {
        String::new()
    };
    let prepared = match prepare_request(&config.base_url, operation, &Value::Object(args)) {
        Ok(prepared) => prepared,
        Err(error) => return preparation_failure(error),
    };
    // A search path names no repository: its owner and repo arguments are
    // governance context, fenced into `q`, and must not reach the query string.
    let mut url = prepared.url;
    if !operation.path.contains("{owner}") {
        url = strip_query_keys(&url, &["owner", "repo"]);
    }
    let (path_part, query_part) = match url.split_once('?') {
        Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
        None => (url.clone(), None),
    };
    let mut url = format!("{path_part}{suffix}");
    let path = format!("{}{suffix}", prepared.path.split('?').next().unwrap_or(""));
    if has_dot_segment(&path) {
        return refused_locally("dot segment");
    }
    if let Some(query) = query_part {
        url.push('?');
        url.push_str(&query);
    }
    append_query(&mut url, &query);
    let mut headers = match build_headers(&config.credential_bindings, credential) {
        Ok(headers) => headers,
        Err(_) => {
            eprintln!(warn transport: "REST credential header binding is invalid");
            return local_not_sent();
        }
    };
    headers.insert(ACCEPT, HeaderValue::from_static(media_type));
    let deadline = Instant::now()
        .checked_add(config.request_timeout)
        .unwrap_or_else(Instant::now);
    let method = reqwest::Method::GET;
    let response = match with_request_deadline(client.get(&url).headers(headers), deadline).send() {
        Ok(response) => response,
        Err(error) => return request_failure_response(error, &method, &path),
    };
    classify(response, throttle_until, &method, &path, media_type)
}

fn strip_query_keys(url: &str, keys: &[&str]) -> String {
    let Some((path, query)) = url.split_once('?') else {
        return url.to_owned();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            !keys.contains(&key)
        })
        .collect();
    if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

fn classify(
    response: Response,
    throttle_until: &mut Option<Instant>,
    method: &reqwest::Method,
    path: &str,
    media_type: &str,
) -> TransportResponse {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let limit = rate_limit(&headers);
    if let Some(delay) = response_throttle(status, &headers) {
        *throttle_until = throttle_deadline(Instant::now(), delay);
        eprintln!(warn transport: "REST vendor throttle: status={status} retry_after_ms={}", duration_ms(delay));
        let mut throttled = crate::http_support::throttled_response("REST", delay);
        throttled.error_message = Some(projection(status, &limit));
        return throttled;
    }
    let success = (200..300).contains(&status);
    let body_limit = if success {
        bot::MAX_BOT_READ_BODY_BYTES
    } else {
        REST_ERROR_BODY_CAP
    };
    let body = match read_body_bounded(response, body_limit) {
        Ok(body) => body,
        Err(BodyReadFailure { failure, cause }) => {
            eprintln!(warn transport: "REST response body failed on {method} {path}: {failure:?}: {cause}");
            return match failure {
                HttpAttemptFailure::Timeout => timeout_response(),
                failure => failure
                    .outcome_unknown_response()
                    .unwrap_or_else(TransportResponse::unknown),
            };
        }
    };
    if !success {
        log_rest_error(
            method,
            path,
            status,
            &body.text,
            accepted_github_permissions(&headers).as_deref(),
        );
        // A read changes nothing, so a gateway error is reported with its
        // status like any other refusal rather than as an unknown outcome.
        // A 401 keeps the `http_401` code the vault's credential check reads;
        // a 403 is a permission refusal and never reported as a bad credential.
        let mut failed = TransportResponse::vendor_error(&format!("http_{status}"), "");
        failed.error_message = Some(projection(status, &limit));
        return failed;
    }
    if body.truncated {
        eprintln!(warn transport: "REST bot read on {method} {path} exceeded {} bytes", bot::MAX_BOT_READ_BODY_BYTES);
        let mut refused = TransportResponse::vendor_error("response_too_large", "");
        refused.error_message = Some(projection(status, &limit));
        return refused;
    }
    let text = body.text;
    let parsed = if !bot::media_type_is_json(media_type) {
        Value::String(text)
    } else if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    let link = headers
        .get(reqwest::header::LINK)
        .and_then(|value| value.to_str().ok());
    TransportResponse::success(serde_json::json!({
        "status": status,
        "body": parsed,
        "next_page": bot::next_page(link),
        "rate_limit": limit,
    }))
}

#[cfg(test)]
#[path = "read_envelope_tests.rs"]
mod tests;
