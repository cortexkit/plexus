//! Credentialed API lookup followed by one credentialless HTTPS storage hop.
//! No storage response or signed URL is included in failure diagnostics.
use super::*;
use std::collections::VecDeque;
use std::io::Read;

pub(super) const MAX_LOG_READ_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const LOG_DEADLINE: Duration = Duration::from_secs(30);

pub(super) fn refused(code: &str) -> TransportResponse {
    eprintln!(warn transport: "REST log download refused: {code}");
    TransportResponse::vendor_error(code, "GitHub Actions download could not be read")
}

pub(super) fn storage_failure(status: u16, _url: &reqwest::Url) -> TransportResponse {
    // Unlike a reviewed API endpoint, even the path of a signed storage URL can
    // be a credential. Keep the entire destination out of operator diagnostics.
    let destination = "[signed URL redacted]";
    eprintln!(warn transport: "REST log storage failed: status={status} destination={destination}");
    refused("job_log_download_failed")
}

pub(super) fn missing_log(status: u16) -> bool {
    matches!(status, 404 | 410)
}

fn destination_allowed(url: &reqwest::Url, hosts: &[String]) -> bool {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    hosts.iter().any(|allowed| {
        if let Some(suffix) = allowed.strip_prefix("*.") {
            host.strip_suffix(suffix)
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
        } else {
            host == allowed
        }
    })
}

pub(super) fn api_redirect(
    client: &Client,
    config: &RestConfig,
    operation: &HttpOperation,
    tail: &crate::manifest::CredentiallessTail,
    args: &Value,
    credential: &ResolvedCredential,
    deadline: Duration,
) -> Result<reqwest::Url, Box<TransportResponse>> {
    let prepared = match prepare_request(&config.base_url, operation, args) {
        Ok(prepared) if prepared.method == reqwest::Method::GET => prepared,
        _ => return Err(Box::new(local_not_sent())),
    };
    let headers = build_headers(&config.credential_bindings, credential)
        .map_err(|_| Box::new(local_not_sent()))?;
    let response = client
        .get(&prepared.url)
        .headers(headers)
        .timeout(deadline)
        .send()
        .map_err(|_| Box::new(refused("job_log_download_failed")))?;
    if missing_log(response.status().as_u16()) {
        return Err(Box::new(refused("job_log_unavailable")));
    }
    if response.status().as_u16() != 302 {
        return Err(Box::new(refused("job_log_redirect_refused")));
    }
    let url = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| reqwest::Url::parse(value).ok());
    let Some(url) = url.filter(|url| destination_allowed(url, &tail.allowed_hosts)) else {
        return Err(Box::new(refused("job_log_redirect_refused")));
    };
    Ok(url)
}

pub(super) fn redact(bytes: &[u8], url: &reqwest::Url, credential: &ResolvedCredential) -> String {
    let mut text = strip_ansi(bytes);
    // GitHub masks secrets in normal logs; also redact credentials known to this read.
    text = text.replace(url.as_str(), "[signed URL redacted]");
    if let Ok(secret) = std::str::from_utf8(credential.payload()) {
        if !secret.is_empty() {
            text = text.replace(secret, "[credential redacted]");
        }
    }
    text
}

pub(super) fn download(
    client: &Client,
    config: &RestConfig,
    operation: &HttpOperation,
    tail: &crate::manifest::CredentiallessTail,
    request: &TransportRequest,
    credential: &ResolvedCredential,
) -> TransportResponse {
    let started = Instant::now();
    let deadline = config.request_timeout.min(LOG_DEADLINE);
    let max_bytes = match request.args.get("max_bytes") {
        None => 65_536,
        Some(value) => match value.as_u64().filter(|value| (1..=262_144).contains(value)) {
            Some(value) => value as usize,
            None => return local_not_sent(),
        },
    };
    let mut args = request.args.clone();
    if let Some(args) = args.as_object_mut() {
        args.remove("max_bytes");
    }
    let url = match api_redirect(client, config, operation, tail, &args, credential, deadline) {
        Ok(url) => url,
        Err(response) => return *response,
    };

    // Build new requests, not copies of the API request: even custom credential
    // headers must remain on the API origin. HEAD supplies a documented Azure
    // start-offset range; suffix ranges are not documented by Azure Blob.
    let remaining = || {
        deadline
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
    };
    let Some(time) = remaining() else {
        return refused("job_log_read_limit");
    };
    let properties = match client.head(url.clone()).timeout(time).send() {
        Ok(response) => response,
        Err(_) => return refused("job_log_download_failed"),
    };
    if properties.status().is_redirection() {
        return refused("job_log_redirect_refused");
    }
    let known_length = properties
        .status()
        .is_success()
        .then(|| content_length(&properties))
        .flatten();
    drop(properties);
    let Some(time) = remaining() else {
        return refused("job_log_read_limit");
    };
    let mut storage = client.get(url.clone()).timeout(time);
    if let Some(length) = known_length.filter(|length| *length > 0) {
        storage = storage.header(
            reqwest::header::RANGE,
            format!("bytes={}-", length.saturating_sub(max_bytes as u64)),
        );
    }
    let response = match storage.send() {
        Ok(response) => response,
        Err(_) => return refused("job_log_download_failed"),
    };
    if response.status().is_redirection() {
        return refused("job_log_redirect_refused");
    }
    if missing_log(response.status().as_u16()) {
        return refused("job_log_unavailable");
    }
    if !matches!(response.status().as_u16(), 200 | 206) {
        return storage_failure(response.status().as_u16(), &url);
    }
    let (total, expected_length) = if response.status().as_u16() == 206 {
        let range = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("bytes "))
            .and_then(|value| value.split_once('/'))
            .and_then(|(range, total)| {
                let (start, end) = range.split_once('-')?;
                Some((
                    start.parse::<u64>().ok()?,
                    end.parse::<u64>().ok()?,
                    total.parse::<u64>().ok()?,
                ))
            });
        let Some((start, end, total)) = range.filter(|(start, end, total)| {
            start <= end && end.checked_add(1) == Some(*total) && total - start <= max_bytes as u64
        }) else {
            return refused("job_log_download_failed");
        };
        if content_length(&response).is_some_and(|length| length != end - start + 1) {
            return refused("job_log_download_failed");
        }
        (Some(total), Some(end - start + 1))
    } else {
        (content_length(&response), None)
    };
    if content_length(&response).is_some_and(|length| length > MAX_LOG_READ_BYTES) {
        return refused("job_log_read_limit");
    }
    let (bytes, read) = match read_tail(response, max_bytes, started, MAX_LOG_READ_BYTES) {
        Ok(result) => result,
        Err(code) => return refused(code),
    };
    if expected_length.is_some_and(|length| read != length) {
        return refused("job_log_download_failed");
    }
    let total = total.unwrap_or(read);
    let text = redact(&bytes, &url, credential);
    if text.is_empty() {
        return refused("job_log_unavailable");
    }
    TransportResponse::success(
        serde_json::json!({"total_bytes": total, "truncated": total > max_bytes as u64, "text": text}),
    )
}

pub(super) fn content_length(response: &Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())?
        .parse()
        .ok()
}

fn read_tail(
    response: Response,
    max_bytes: usize,
    started: Instant,
    read_limit: u64,
) -> Result<(Vec<u8>, u64), &'static str> {
    tail_bytes(
        response,
        max_bytes,
        started,
        LOG_DEADLINE,
        read_limit,
        "job_log_download_failed",
        "job_log_read_limit",
    )
}

pub(super) fn tail_bytes<R: Read>(
    mut response: R,
    max_bytes: usize,
    started: Instant,
    deadline: Duration,
    read_limit: u64,
    io_code: &'static str,
    limit_code: &'static str,
) -> Result<(Vec<u8>, u64), &'static str> {
    let mut tail = VecDeque::with_capacity(max_bytes);
    let mut read = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        if started.elapsed() >= deadline {
            return Err("job_log_read_limit");
        }
        let count = response.read(&mut buffer).map_err(|_| io_code)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > read_limit {
            return Err(limit_code);
        }
        for byte in &buffer[..count] {
            if tail.len() == max_bytes {
                tail.pop_front();
            }
            tail.push_back(*byte);
        }
    }
    Ok((tail.into_iter().collect(), read))
}

pub(super) fn strip_ansi(bytes: &[u8]) -> String {
    let mut clean = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().copied().peekable();
    while let Some(byte) = iter.next() {
        if byte != 0x1b {
            clean.push(byte);
            continue;
        }
        match iter.next() {
            Some(b'[') => {
                for byte in iter.by_ref() {
                    if (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
            }
            Some(b']' | b'P' | b'X' | b'^' | b'_') => {
                while let Some(byte) = iter.next() {
                    if byte == 7 || (byte == 0x1b && iter.peek() == Some(&b'\\')) {
                        if byte == 0x1b {
                            iter.next();
                        }
                        break;
                    }
                }
            }
            Some(0x20..=0x2f) => {
                for byte in iter.by_ref() {
                    if (0x30..=0x7e).contains(&byte) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    String::from_utf8_lossy(&clean).into_owned()
}

#[cfg(test)]
pub(super) mod tests;
