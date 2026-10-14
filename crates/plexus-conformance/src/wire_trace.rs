//! Wire-trace capture for vault credential route verification.
//!
//! The claustrum vault must be able to verify a live `route.open` /
//! `credential.get` from the wire, but credential custody forbids secret bytes ever leaving
//! the process. This module reconciles the two
//! with a decorator that implements [`CkcredRoutePeer`] around the real peer and
//! records each call to a trace sink, REDACTING secret bytes at write time.
//!
//! Each call becomes one JSON line: `{timestamp_ms, operation, request,
//! response, latency_ms}`. Redaction rules:
//! - the bearer `handle` in request params is replaced by its fingerprint;
//! - every non-null `payload` in the response, at any depth, is replaced by
//!   `{"__redacted": true, "json_type": "u8_array", "len": N,
//!   "fingerprint": "sha256:…"}` — enough to verify the byte-array contract
//!   shape without the bytes. A payload of any OTHER shape (a base64 string,
//!   an object) is redacted the same way with its own `json_type`: the live
//!   wire has drifted to a string payload before, and a redactor that only
//!   recognises the expected shape writes the drifted secret in clear;
//! - everything else (error objects, `record_version`, `expires_at_ms`,
//!   metadata) is recorded verbatim.
//!
//! Because redaction happens BEFORE any byte is written, the trace file is a
//! separate artifact from the evidence JSON and the evidence leak-scan does NOT
//! cover it: once redaction has run there is no raw secret left to scan for.
//! The file is created owner-only (0600) as a second, structural guard.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use plexus_core::{fingerprint, CkcredRouteError, CkcredRoutePeer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::evidence::now_ms;

/// Append-only JSON-lines sink for redacted wire-trace events.
///
/// Events are serialized and flushed one line at a time so a partial run still
/// leaves a readable trace. Write failures are swallowed: the trace is
/// diagnostic material and must never abort the credential operation it shadows.
pub struct WireTraceSink {
    writer: Mutex<std::fs::File>,
}

impl WireTraceSink {
    /// Create (or truncate) the trace file at `path` with owner-only (0600)
    /// permissions.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = open_owner_only(path)?;
        Ok(Self {
            writer: Mutex::new(file),
        })
    }

    /// Serialize one event as a single JSON line. Never fails the caller.
    pub fn write_event(&self, event: Value) {
        let Ok(mut file) = self.writer.lock() else {
            return;
        };
        let Ok(mut line) = serde_json::to_string(&event) else {
            return;
        };
        line.push('\n');
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

/// Open `path` for writing (create or truncate) restricted to the owning user
/// (0600). `OpenOptions::mode` only applies when the file is CREATED — a
/// pre-existing file keeps its old mode — so permissions are also enforced
/// explicitly after open. Evidence and trace artifacts carry credential
/// fingerprints and audit topology, which are sensitive even when redacted;
/// callers must not depend on the host umask.
pub fn open_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Decorator implementing [`CkcredRoutePeer`] that records each call to a
/// [`WireTraceSink`] with secret bytes redacted, then forwards to the inner peer
/// unchanged. The inner peer's result is returned verbatim to the caller; only
/// the recorded copy is redacted.
pub struct TracingRoutePeer<P> {
    inner: Arc<P>,
    sink: Arc<WireTraceSink>,
}

impl<P> TracingRoutePeer<P> {
    pub fn new(inner: Arc<P>, sink: Arc<WireTraceSink>) -> Self {
        Self { inner, sink }
    }
}

impl<P: CkcredRoutePeer> CkcredRoutePeer for TracingRoutePeer<P> {
    fn call(&self, operation: &str, params: Value) -> Result<Value, CkcredRouteError> {
        let started = Instant::now();
        let timestamp_ms = now_ms();
        let result = self.inner.call(operation, params.clone());
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.sink.write_event(json!({
            "timestamp_ms": timestamp_ms,
            "operation": operation,
            "request": redact_request(&params),
            "response": redact_response(&result),
            "latency_ms": latency_ms,
        }));
        result
    }
}

/// Record a route-level connect attempt around `SubcCkcredRoutePeer::connect`.
/// The `route.open` frames themselves live in `subc_client_rs` (out of reach);
/// The vault can cross-check those from its daemon side. Connect parameters
/// (connection file path, module id) are not secret and are recorded verbatim.
pub fn record_route_connect(sink: &WireTraceSink, params: Value, status: &str, latency_ms: u64) {
    sink.write_event(json!({
        "timestamp_ms": now_ms(),
        "operation": "route.connect",
        "request": params,
        "response": { "status": status },
        "latency_ms": latency_ms,
    }));
}

/// Redact bearer handles and payloads at every depth before a request is recorded.
fn redact_request(params: &Value) -> Value {
    let mut redacted = params.clone();
    redact_request_children(&mut redacted);
    redacted
}

fn redact_request_children(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map {
                if matches!(key.as_str(), "handle" | "payload") && !entry.is_null() {
                    *entry = if key == "handle" {
                        match entry {
                            Value::String(text) => {
                                json!({"fingerprint": fingerprint(text.as_bytes())})
                            }
                            Value::Array(items) => {
                                json!({"fingerprint": fingerprint(&u8_array_bytes(items))})
                            }
                            _ => payload_marker(entry),
                        }
                    } else {
                        payload_marker(entry)
                    };
                } else {
                    redact_request_children(entry);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_request_children),
        _ => {}
    }
}

/// Redact a response's secret bytes. The `credential.get` result carries the
/// live payload under `result.payload`; every `payload` key anywhere in the
/// response is replaced with a shape-preserving redaction marker (type, length
/// and fingerprint, no bytes), whatever JSON type it holds. Matching on the key
/// rather than on the expected array shape is deliberate: a payload that has
/// drifted to a base64 string or moved to another level is exactly the case
/// where the bytes would otherwise be written in clear. Error objects and all
/// other fields are verbatim. A route-level error (no response body) is
/// recorded by its variant name, which is never secret.
fn redact_response(result: &Result<Value, CkcredRouteError>) -> Value {
    let Ok(value) = result else {
        let error = result.as_ref().unwrap_err();
        return json!({ "route_error": format!("{error:?}") });
    };
    let mut redacted = value.clone();
    redact_payloads(&mut redacted);
    redacted
}

/// Replace every non-null `payload` value under `value` with its redaction
/// marker. A null payload carries no secret and stays as it is, so a reader
/// can still tell "no payload" from "payload redacted".
fn redact_payloads(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if key == "payload" {
                    if !entry.is_null() {
                        *entry = payload_marker(entry);
                    }
                } else {
                    redact_payloads(entry);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_payloads),
        _ => {}
    }
}

/// The redaction marker for one payload: its JSON type, its length in bytes
/// and a SHA-256 fingerprint of those bytes. A byte array is fingerprinted as
/// the bytes it encodes and a string as its UTF-8 bytes, so the same secret
/// fingerprints the same in either shape; anything else is fingerprinted as
/// its serialized JSON.
fn payload_marker(payload: &Value) -> Value {
    let (json_type, bytes) = match payload {
        Value::Array(items) if items.iter().all(is_u8) => ("u8_array", u8_array_bytes(items)),
        Value::String(text) => ("string", text.as_bytes().to_vec()),
        other => (
            match other {
                Value::Array(_) => "array",
                Value::Object(_) => "object",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                _ => "other",
            },
            serde_json::to_vec(other).unwrap_or_default(),
        ),
    };
    json!({
        "__redacted": true,
        "json_type": json_type,
        "len": bytes.len(),
        "fingerprint": format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
    })
}

fn is_u8(value: &Value) -> bool {
    value
        .as_u64()
        .is_some_and(|number| number <= u64::from(u8::MAX))
}

/// Decode a JSON u8 array (numbers 0..=255) back to bytes for fingerprinting.
/// Out-of-range entries are ignored; the goal is a stable fingerprint of the
/// secret bytes, not a validated decode.
fn u8_array_bytes(array: &[Value]) -> Vec<u8> {
    array
        .iter()
        .filter_map(Value::as_u64)
        .filter(|value| *value <= u8::MAX as u64)
        .map(|value| value as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_request_secrets_are_redacted() {
        let value = json!({"nested":[{"handle":"nested-secret", "payload":"write-secret"}], "safe":"visible"});
        let redacted = redact_request(&value);
        let text = redacted.to_string();
        assert!(
            !text.contains("nested-secret") && !text.contains("write-secret"),
            "nested request secrets must be redacted"
        );
        assert_eq!(redacted["safe"], "visible");
    }
    use plexus_core::test_scratch::Scratch;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    #[cfg(unix)]
    #[test]
    fn artifact_files_are_owner_only_even_when_preexisting() {
        use std::os::unix::fs::PermissionsExt;
        let path = Scratch::file("wire-trace-mode", "trace.jsonl");
        // Simulate the defect found in the first live proof: the file already
        // exists with permissive umask-derived mode before the sink opens it.
        std::fs::write(&path, b"stale").expect("precreate");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let _file = open_owner_only(&path).expect("open");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        std::fs::remove_file(&path).ok();
        assert_eq!(
            mode, 0o600,
            "owner-only must be enforced, not umask-derived"
        );
    }

    /// Minimal route peer that returns queued responses and logs the raw calls.
    #[derive(Default)]
    struct MockRoutePeer {
        responses: StdMutex<VecDeque<Result<Value, CkcredRouteError>>>,
        calls: StdMutex<Vec<(String, Value)>>,
    }

    impl MockRoutePeer {
        fn push(&self, response: Value) {
            self.responses
                .lock()
                .expect("response queue lock")
                .push_back(Ok(response));
        }
    }

    impl CkcredRoutePeer for MockRoutePeer {
        fn call(&self, operation: &str, params: Value) -> Result<Value, CkcredRouteError> {
            self.calls
                .lock()
                .expect("call log lock")
                .push((operation.to_string(), params.clone()));
            self.responses
                .lock()
                .expect("response queue lock")
                .pop_front()
                .unwrap_or(Err(CkcredRouteError::Transport))
        }
    }

    fn temp_trace_path(label: &str) -> Scratch {
        Scratch::file(&format!("wire-trace-{label}"), "trace.jsonl")
    }

    fn read_lines(path: &Path) -> Vec<Value> {
        let text = std::fs::read_to_string(path).expect("read trace file");
        text.lines()
            .map(|line| serde_json::from_str(line).expect("trace line is valid JSON"))
            .collect()
    }

    #[test]
    fn credential_get_payload_and_handle_are_redacted_to_fingerprints() {
        let path = temp_trace_path("redact");
        let sink = Arc::new(WireTraceSink::open(&path).expect("open sink"));
        let peer = Arc::new(MockRoutePeer::default());
        // CANARY as a u8 array; the handle is a distinct secret byte string.
        peer.push(json!({
            "result": {"payload": [67, 65, 78, 65, 82, 89], "record_version": 7, "expires_at_ms": 123}
        }));
        let tracing = TracingRoutePeer::new(Arc::clone(&peer), Arc::clone(&sink));

        let handle = b"ckh_secret-bearer-handle";
        let params = json!({
            "handle": handle.iter().copied().map(Value::from).collect::<Vec<_>>()
        });
        let response = tracing
            .call("credential.get", params)
            .expect("call succeeds");

        // The caller still sees the verbatim, unredacted response.
        assert_eq!(response["result"]["payload"][0], 67);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line["operation"], "credential.get");

        let serialized = serde_json::to_string(line).expect("serialize line");
        // Raw secret bytes appear nowhere in the written record.
        let raw_handle = String::from_utf8_lossy(handle);
        assert!(
            !serialized.contains(raw_handle.as_ref()),
            "raw handle leaked"
        );
        assert!(!serialized.contains("CANARY"), "raw payload leaked");
        assert!(!serialized.contains("67,65,78"), "payload array leaked");

        // Handle is recorded as a fingerprint.
        let handle_field = &line["request"]["handle"];
        assert!(handle_field["fingerprint"]
            .as_str()
            .expect("fp")
            .starts_with("ckfp_"));

        // Payload is recorded as a redaction marker with shape + fingerprint.
        let payload = &line["response"]["result"]["payload"];
        assert_eq!(payload["__redacted"], true);
        assert_eq!(payload["json_type"], "u8_array");
        assert_eq!(payload["len"], 6);
        assert!(payload["fingerprint"]
            .as_str()
            .expect("fp")
            .starts_with("sha256:"));

        // Non-secret fields are verbatim.
        assert_eq!(line["response"]["result"]["record_version"], 7);
        assert_eq!(line["response"]["result"]["expires_at_ms"], 123);
        assert!(line["timestamp_ms"].as_i64().expect("timestamp") > 0);
        assert!(line["latency_ms"].as_u64().is_some());

        let _ = std::fs::remove_file(&path);
    }

    /// A payload that arrives as a base64 STRING rather than the contracted
    /// byte array must still be redacted. The vault has sent this shape before
    /// (plexus-core rejects it as drift at decode time), and the trace is
    /// written before any decode, so a redactor keyed on the array shape would
    /// write the drifted secret into the trace file in clear.
    #[test]
    fn a_string_or_relocated_payload_is_redacted_too() {
        let path = temp_trace_path("string-payload");
        let sink = Arc::new(WireTraceSink::open(&path).expect("open sink"));
        let peer = Arc::new(MockRoutePeer::default());
        // "CANARY-SECRET" in base64.
        peer.push(json!({"result": {"payload": "Q0FOQVJZLVNFQ1JFVA==", "record_version": 2}}));
        peer.push(json!({"payload": {"token": "CANARY-NESTED"}}));
        let tracing = TracingRoutePeer::new(Arc::clone(&peer), Arc::clone(&sink));
        tracing
            .call("credential.get", json!({"handle": "ckh_x"}))
            .expect("first call");
        tracing
            .call("credential.get", json!({"handle": "ckh_y"}))
            .expect("second call");

        let lines = read_lines(&path);
        let serialized = std::fs::read_to_string(&*path).expect("read trace");
        assert!(
            !serialized.contains("Q0FOQVJZLVNFQ1JFVA=="),
            "a base64 string payload was written in clear: {serialized}"
        );
        assert!(
            !serialized.contains("CANARY-NESTED"),
            "a relocated payload was written in clear: {serialized}"
        );
        let string_marker = &lines[0]["response"]["result"]["payload"];
        assert_eq!(string_marker["__redacted"], true);
        assert_eq!(string_marker["json_type"], "string");
        assert_eq!(string_marker["len"], 20);
        assert_eq!(lines[0]["response"]["result"]["record_version"], 2);
        let object_marker = &lines[1]["response"]["payload"];
        assert_eq!(object_marker["__redacted"], true);
        assert_eq!(object_marker["json_type"], "object");
    }

    #[test]
    fn ckcred_error_object_is_passed_through_verbatim() {
        let path = temp_trace_path("error");
        let sink = Arc::new(WireTraceSink::open(&path).expect("open sink"));
        let peer = Arc::new(MockRoutePeer::default());
        peer.push(json!({
            "result": {"error": {"code": "revoked", "class": "permanent"}}
        }));
        let tracing = TracingRoutePeer::new(Arc::clone(&peer), Arc::clone(&sink));

        let response = tracing
            .call("credential.get", json!({"handle": [1, 2, 3]}))
            .expect("route call succeeds even when CKCRED reports an error");
        assert_eq!(response["result"]["error"]["code"], "revoked");

        let lines = read_lines(&path);
        let line = &lines[0];
        // The vault's error object is diagnostic material and stays verbatim.
        assert_eq!(line["response"]["result"]["error"]["code"], "revoked");
        assert_eq!(line["response"]["result"]["error"]["class"], "permanent");
        // No payload was present, so no redaction marker is invented.
        assert!(line["response"]["result"].get("payload").is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn route_level_error_is_recorded_without_a_body() {
        let path = temp_trace_path("route-error");
        let sink = Arc::new(WireTraceSink::open(&path).expect("open sink"));
        let peer = Arc::new(MockRoutePeer::default());
        // Empty queue => MockRoutePeer returns Err(Transport).
        let tracing = TracingRoutePeer::new(Arc::clone(&peer), Arc::clone(&sink));

        let error = tracing
            .call("credential.get", json!({"handle": [9]}))
            .expect_err("route error propagates to the caller");
        assert_eq!(error, CkcredRouteError::Transport);

        let lines = read_lines(&path);
        assert_eq!(lines[0]["response"]["route_error"], "Transport");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trace_file_is_created_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = temp_trace_path("perms");
            let _sink = WireTraceSink::open(&path).expect("open sink");
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "trace file must be 0600");
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn connect_event_is_recorded_around_the_route_open() {
        let path = temp_trace_path("connect");
        let sink = WireTraceSink::open(&path).expect("open sink");
        record_route_connect(
            &sink,
            json!({"connection_file": "/tmp/subc.sock", "module_id": "ckcred"}),
            "ok",
            3,
        );
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["operation"], "route.connect");
        assert_eq!(lines[0]["request"]["module_id"], "ckcred");
        assert_eq!(lines[0]["response"]["status"], "ok");
        let _ = std::fs::remove_file(&path);
    }
}
