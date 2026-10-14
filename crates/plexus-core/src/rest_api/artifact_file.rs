//! Bounded in-memory ZIP reads; only the selected entry is ever decompressed.
use super::*;
use std::io::{Cursor, Read};

pub(crate) const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_RATIO: u64 = 200;

pub(crate) fn safe_path(path: &[u8]) -> bool {
    !path.starts_with(b"/")
        && !path.contains(&b'\\')
        && !path.contains(&0)
        && !path.split(|byte| *byte == b'/').any(|part| part == b"..")
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
    let deadline = config.request_timeout.min(job_log::LOG_DEADLINE);
    let max_bytes = match request.args.get("max_bytes") {
        None => 65_536,
        Some(value) => match value.as_u64().filter(|bytes| (1..=262_144).contains(bytes)) {
            Some(bytes) => bytes as usize,
            None => return local_not_sent(),
        },
    };
    let Some(path) = request
        .args
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty() && safe_path(path.as_bytes()))
    else {
        return local_not_sent();
    };
    let mut args = request.args.clone();
    if let Some(args) = args.as_object_mut() {
        args.remove("path");
        args.remove("max_bytes");
    }
    let url =
        match job_log::api_redirect(client, config, operation, tail, &args, credential, deadline) {
            Ok(url) => url,
            Err(response) => return *response,
        };
    let Some(time) = deadline
        .checked_sub(started.elapsed())
        .filter(|time| !time.is_zero())
    else {
        return job_log::refused("job_log_read_limit");
    };
    // Fresh request: the API's Authorization and custom credential headers stay behind.
    let storage = client.get(url.clone()).timeout(time);
    let response = match storage.send() {
        Ok(response) => response,
        Err(_) => return job_log::refused("job_log_download_failed"),
    };
    if response.status().is_redirection() {
        return job_log::refused("job_log_redirect_refused");
    }
    if job_log::missing_log(response.status().as_u16()) {
        return job_log::refused("job_log_unavailable");
    }
    if response.status().as_u16() != 200 {
        return job_log::storage_failure(response.status().as_u16(), &url);
    }
    if job_log::content_length(&response).is_some_and(|bytes| bytes > MAX_ARTIFACT_BYTES) {
        return job_log::refused("artifact_too_large");
    }
    let archive = match read_archive(response, started, deadline, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(code) => return job_log::refused(code),
    };
    let (bytes, total) = match extract_tail(archive, path, max_bytes, started, deadline) {
        Ok(result) => result,
        Err(code) => return job_log::refused(code),
    };
    let text = job_log::redact(&bytes, &url, credential);
    TransportResponse::success(
        serde_json::json!({"total_bytes":total,"truncated":total > max_bytes as u64,"text":text}),
    )
}

fn read_archive(
    mut response: Response,
    started: Instant,
    deadline: Duration,
    limit: u64,
) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        if started.elapsed() >= deadline {
            return Err("job_log_read_limit");
        }
        let count = response
            .read(&mut buffer)
            .map_err(|_| "job_log_download_failed")?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() as u64 + count as u64 > limit {
            return Err("artifact_too_large");
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

// ZIP metadata is allocated by the library before len() is available, and duplicate
// names collapse in its map. Check the raw directory first to bound allocations and
// validate every record, including duplicates that the library would otherwise hide.
fn preflight(bytes: &[u8]) -> Result<(), &'static str> {
    let invalid = "artifact_invalid_zip";
    let u16_at = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(
            bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
        ))
    };
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let u64_at = |offset: usize| -> Option<u64> {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
        ))
    };
    let end = (bytes.len().saturating_sub(65_557)..bytes.len().saturating_sub(21))
        .rev()
        .find(|offset| {
            bytes.get(*offset..*offset + 4) == Some(b"PK\x05\x06")
                && u16_at(*offset + 20)
                    .is_some_and(|length| *offset + 22 + length as usize == bytes.len())
        })
        .ok_or(invalid)?;
    if u16_at(end + 4) != Some(0) || u16_at(end + 6) != Some(0) {
        return Err(invalid);
    }
    let count = u16_at(end + 10).ok_or(invalid)?;
    if u16_at(end + 8) != Some(count) {
        return Err(invalid);
    }
    let size = u32_at(end + 12).ok_or(invalid)?;
    let offset = u32_at(end + 16).ok_or(invalid)?;
    let (count, size, offset, directory_end) =
        if count == u16::MAX || size == u32::MAX || offset == u32::MAX {
            let locator = end.checked_sub(20).ok_or(invalid)?;
            if bytes.get(locator..locator + 4) != Some(b"PK\x06\x07")
                || u32_at(locator + 4) != Some(0)
                || u32_at(locator + 16) != Some(1)
            {
                return Err(invalid);
            }
            let zip64 =
                usize::try_from(u64_at(locator + 8).ok_or(invalid)?).map_err(|_| invalid)?;
            if bytes.get(zip64..zip64.checked_add(4).ok_or(invalid)?) != Some(b"PK\x06\x06")
                || zip64.checked_add(56).is_none_or(|end| end > locator)
                || u32_at(zip64 + 16) != Some(0)
                || u32_at(zip64 + 20) != Some(0)
            {
                return Err(invalid);
            }
            let count = u64_at(zip64 + 32).ok_or(invalid)?;
            if u64_at(zip64 + 24) != Some(count) {
                return Err(invalid);
            }
            (
                count,
                u64_at(zip64 + 40).ok_or(invalid)?,
                u64_at(zip64 + 48).ok_or(invalid)?,
                zip64,
            )
        } else {
            (count as u64, size as u64, offset as u64, end)
        };
    if count > MAX_ENTRIES as u64 {
        return Err("artifact_too_large");
    }
    let mut position = usize::try_from(offset).map_err(|_| invalid)?;
    let stop = position
        .checked_add(usize::try_from(size).map_err(|_| invalid)?)
        .ok_or(invalid)?;
    if stop > directory_end {
        return Err(invalid);
    }
    for _ in 0..count {
        if bytes.get(position..position.checked_add(4).ok_or(invalid)?) != Some(b"PK\x01\x02") {
            return Err(invalid);
        }
        let flags = u16_at(position + 8).ok_or(invalid)?;
        let method = u16_at(position + 10).ok_or(invalid)?;
        if flags & 1 != 0 || !matches!(method, 0 | 8) {
            return Err(invalid);
        }
        let name_start = position.checked_add(46).ok_or(invalid)?;
        let name_end = name_start
            .checked_add(u16_at(position + 28).ok_or(invalid)? as usize)
            .ok_or(invalid)?;
        let name = bytes.get(name_start..name_end).ok_or(invalid)?;
        if !safe_path(name) {
            return Err(invalid);
        }
        position = name_end
            .checked_add(u16_at(position + 30).ok_or(invalid)? as usize)
            .and_then(|offset| offset.checked_add(u16_at(position + 32)? as usize))
            .ok_or(invalid)?;
        if position > stop {
            return Err(invalid);
        }
    }
    if position != stop {
        return Err(invalid);
    }
    Ok(())
}

fn extract_tail(
    bytes: Vec<u8>,
    path: &str,
    max_bytes: usize,
    started: Instant,
    deadline: Duration,
) -> Result<(Vec<u8>, u64), &'static str> {
    preflight(&bytes)?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| "artifact_invalid_zip")?;
    let mut selected = None;
    for index in 0..archive.len() {
        let entry = archive
            .by_index_data(index)
            .map_err(|_| "artifact_invalid_zip")?;
        if entry.name_raw() == path.as_bytes() {
            selected = Some(index);
        }
    }
    let index = selected.ok_or("artifact_file_not_found")?;
    let file = archive
        .by_index(index)
        .map_err(|_| "artifact_invalid_zip")?;
    let ratio_limit = file.compressed_size().saturating_mul(MAX_RATIO);
    let limit = MAX_ARTIFACT_BYTES.min(ratio_limit);
    if file.size() > limit {
        return Err("artifact_too_large");
    }
    let expected = file.size();
    let (tail, total) = job_log::tail_bytes(
        file,
        max_bytes,
        started,
        deadline,
        limit,
        "artifact_invalid_zip",
        "artifact_too_large",
    )?;
    if total != expected {
        return Err("artifact_invalid_zip");
    }
    Ok((tail, total))
}

#[cfg(test)]
mod tests;
