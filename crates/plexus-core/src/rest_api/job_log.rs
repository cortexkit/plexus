//! Credentialed API lookup followed by one credentialless HTTPS storage hop.
//! No storage response or signed URL is included in failure diagnostics.
use super::*;
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
        || url.port_or_known_default() != Some(443)
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

// Keep the credentialed API inputs explicit: its throttle belongs to the
// connection, while the returned URL is used only by credentialless requests.
#[allow(clippy::too_many_arguments)]
pub(super) fn api_redirect(
    client: &Client,
    throttle_until: &mut Option<Instant>,
    config: &RestConfig,
    operation: &HttpOperation,
    tail: &crate::manifest::CredentiallessTail,
    args: &Value,
    credential: &ResolvedCredential,
    deadline: Duration,
) -> Result<reqwest::Url, Box<TransportResponse>> {
    let prepared = match prepare_request(&config.base_url, operation, args) {
        Ok(prepared) if prepared.method == reqwest::Method::GET => prepared,
        Err(error) => return Err(Box::new(preparation_failure(error))),
        Ok(_) => return Err(Box::new(local_not_sent())),
    };
    let headers = build_headers(&config.credential_bindings, credential)
        .map_err(|_| Box::new(local_not_sent()))?;
    let response = client
        .get(&prepared.url)
        .headers(headers)
        .timeout(deadline)
        .send()
        .map_err(|error| {
            Box::new(request_failure_response(
                error,
                &prepared.method,
                &prepared.path,
            ))
        })?;
    if missing_log(response.status().as_u16()) {
        return Err(Box::new(refused("job_log_unavailable")));
    }
    if response.status().as_u16() != 302 {
        if response.status().as_u16() < 400 {
            return Err(Box::new(refused("job_log_redirect_refused")));
        }
        return Err(Box::new(classify_response(
            response,
            throttle_until,
            &prepared.method,
            &prepared.path,
            false,
        )));
    }
    let url = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| reqwest::Url::parse(value).ok());
    let Some(url) = url.filter(|url| {
        // A fixture's explicit trust root permits its ephemeral TLS port. The
        // deployed client has no such setting and accepts only HTTPS port 443.
        #[cfg(test)]
        if config.test_root_certificate.is_some() {
            let mut standard = url.clone();
            let _ = standard.set_port(None);
            return destination_allowed(&standard, &tail.allowed_hosts);
        }
        destination_allowed(url, &tail.allowed_hosts)
    }) else {
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
            // A byte tail may start inside a credential. Do not return a long
            // leading suffix merely because its prefix fell outside the tail.
            for (offset, _) in secret.char_indices().skip(1) {
                let suffix = &secret[offset..];
                if suffix.len() >= 8 && text.starts_with(suffix) {
                    text.replace_range(..suffix.len(), "[credential redacted]");
                    break;
                }
            }
        }
    }
    text
}

pub(super) fn download(
    client: &Client,
    throttle_until: &mut Option<Instant>,
    config: &RestConfig,
    operation: &HttpOperation,
    tail: &crate::manifest::CredentiallessTail,
    request: &TransportRequest,
    credential: &ResolvedCredential,
) -> TransportResponse {
    let started = Instant::now();
    let deadline = config.request_timeout.min(LOG_DEADLINE);
    // Only the bot catalog's job log action declares `offset` and `length`,
    // and only its callers get the byte-range form; every other caller keeps
    // the bounded tail below.
    if request.args.get("length").is_some() {
        return download_range(
            client,
            throttle_until,
            config,
            operation,
            tail,
            request,
            credential,
            started,
            deadline,
        );
    }
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
    let url = match api_redirect(
        client,
        throttle_until,
        config,
        operation,
        tail,
        &args,
        credential,
        deadline,
    ) {
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
    let (bytes, read) = match read_tail(response, max_bytes, started, deadline, MAX_LOG_READ_BYTES)
    {
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

/// A byte range of a job log: `length` bytes from `offset`, through the same
/// single credential-free redirect to log storage the tail read uses. The
/// reply's `length` counts the raw bytes read, so `offset + length` is where
/// the next range starts; `total_bytes` comes from storage's `Content-Range`.
#[allow(clippy::too_many_arguments)]
fn download_range(
    client: &Client,
    throttle_until: &mut Option<Instant>,
    config: &RestConfig,
    operation: &HttpOperation,
    tail: &crate::manifest::CredentiallessTail,
    request: &TransportRequest,
    credential: &ResolvedCredential,
    started: Instant,
    deadline: Duration,
) -> TransportResponse {
    let offset = request
        .args
        .get("offset")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let Some(length) = request
        .args
        .get("length")
        .and_then(Value::as_u64)
        .filter(|length| (1..=crate::github::reads::bot::MAX_JOB_LOG_RANGE_BYTES).contains(length))
    else {
        return local_not_sent();
    };
    let Some(last) = offset.checked_add(length - 1) else {
        return local_not_sent();
    };
    let mut args = request.args.clone();
    if let Some(args) = args.as_object_mut() {
        args.remove("offset");
        args.remove("length");
    }
    let url = match api_redirect(
        client,
        throttle_until,
        config,
        operation,
        tail,
        &args,
        credential,
        deadline,
    ) {
        Ok(url) => url,
        Err(response) => return *response,
    };
    let Some(time) = deadline
        .checked_sub(started.elapsed())
        .filter(|time| !time.is_zero())
    else {
        return refused("job_log_read_limit");
    };
    // A new request, not a copy of the API request: no credential header
    // leaves the API origin.
    let response = match client
        .get(url.clone())
        .timeout(time)
        .header(reqwest::header::RANGE, format!("bytes={offset}-{last}"))
        .send()
    {
        Ok(response) => response,
        Err(_) => return refused("job_log_download_failed"),
    };
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return refused("job_log_redirect_refused");
    }
    if missing_log(status) {
        return refused("job_log_unavailable");
    }
    let content_range = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("bytes "))
        .map(str::to_owned);
    if status == 416 {
        // The range starts at or past the end: an empty read that still says
        // how long the log is.
        let Some(total) = content_range
            .as_deref()
            .and_then(|range| range.strip_prefix("*/"))
            .and_then(|total| total.parse::<u64>().ok())
        else {
            return refused("job_log_download_failed");
        };
        return TransportResponse::success(serde_json::json!({
            "body": "", "offset": offset, "length": 0, "total_bytes": total,
        }));
    }
    let (bytes, total) = match status {
        206 => {
            let Some((start, end, total)) = content_range.as_deref().and_then(|range| {
                let (range, total) = range.split_once('/')?;
                let (start, end) = range.split_once('-')?;
                Some((
                    start.parse::<u64>().ok()?,
                    end.parse::<u64>().ok()?,
                    total.parse::<u64>().ok()?,
                ))
            }) else {
                return refused("job_log_download_failed");
            };
            if start != offset || end < start || end > last || end >= total {
                return refused("job_log_download_failed");
            }
            let expected = end - start + 1;
            match tail_bytes(
                response,
                expected as usize,
                started,
                deadline,
                expected,
                "job_log_download_failed",
                "job_log_download_failed",
            ) {
                Ok((bytes, read)) if read == expected => (bytes, total),
                Ok(_) => return refused("job_log_download_failed"),
                Err(code) => return refused(code),
            }
        }
        // Storage ignored the range and sent the whole log: keep only the
        // asked-for window while reading it.
        200 => match window_bytes(response, offset, length, started, deadline) {
            Ok(window) => window,
            Err(code) => return refused(code),
        },
        _ => return storage_failure(status, &url),
    };
    let read = bytes.len() as u64;
    TransportResponse::success(serde_json::json!({
        "body": redact(&bytes, &url, credential),
        "offset": offset,
        "length": read,
        "total_bytes": total,
    }))
}

/// Read a whole log body, keeping bytes `offset..offset + length` and counting
/// the rest. Refuses a body longer than the log read limit.
fn window_bytes<R: Read>(
    mut response: R,
    offset: u64,
    length: u64,
    started: Instant,
    deadline: Duration,
) -> Result<(Vec<u8>, u64), &'static str> {
    let mut window = Vec::new();
    let mut position = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        if deadline <= started.elapsed() {
            return Err("job_log_read_limit");
        }
        let count = response
            .read(&mut buffer)
            .map_err(|_| "job_log_download_failed")?;
        if count == 0 {
            break;
        }
        let chunk_start = position;
        position += count as u64;
        if position > MAX_LOG_READ_BYTES {
            return Err("job_log_read_limit");
        }
        let from = offset.max(chunk_start);
        let to = (offset + length).min(position);
        if from < to {
            window.extend_from_slice(
                &buffer[(from - chunk_start) as usize..(to - chunk_start) as usize],
            );
        }
    }
    Ok((window, position))
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
    deadline: Duration,
    read_limit: u64,
) -> Result<(Vec<u8>, u64), &'static str> {
    tail_bytes(
        response,
        max_bytes,
        started,
        deadline,
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
    let mut tail = Vec::with_capacity(max_bytes);
    let mut read = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        if started.elapsed() >= deadline {
            return Err(limit_code);
        }
        let count = response.read(&mut buffer).map_err(|_| io_code)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > read_limit {
            return Err(limit_code);
        }
        let chunk = &buffer[count.saturating_sub(max_bytes)..count];
        let discard = tail
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(max_bytes);
        tail.drain(..discard);
        tail.extend_from_slice(chunk);
    }
    Ok((tail, read))
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
