//! Wire-trace capture for vault credential route verification.
//!
//! The claustrum vault must be able to verify a live `route.open` /
//! `credential.get` from the wire, but credential custody forbids secret bytes ever leaving
//! the process. This module reconciles the two
//! with a decorator that implements [`CkcredRoutePeer`] around the real peer and
//! records each call to a trace sink, REDACTING secret bytes at write time.
//!
//! Each call becomes one JSON line with timing and a redacted request/response.
//! Only known metadata fields are retained verbatim. Unknown fields are replaced
//! by shape and fingerprint markers so a renamed secret cannot escape redaction.
//! Trace snapshots are published atomically with owner-only permissions.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use plexus_core::{fingerprint, CkcredRouteError, CkcredRoutePeer};
use serde_json::{json, Value};

use crate::evidence::now_ms;

/// Append-only JSON-lines sink for redacted wire-trace events.
///
/// Events are serialized and flushed one line at a time so a partial run still
/// leaves a readable trace. Write failures are swallowed: the trace is
/// diagnostic material and must never abort the credential operation it shadows.
pub struct WireTraceSink {
    writer: Mutex<Vec<u8>>,
    path: PathBuf,
}

impl WireTraceSink {
    /// Create (or truncate) the trace file at `path` with owner-only (0600)
    /// permissions.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        crate::write_owner_only(path, b"")?;
        Ok(Self {
            writer: Mutex::new(Vec::new()),
            path: path.to_path_buf(),
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
        file.extend_from_slice(line.as_bytes());
        let _ = crate::write_owner_only(&self.path, &file);
    }
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
        let request = redact_request(&params);
        let result = self.inner.call(operation, params);
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.sink.write_event(json!({
            "timestamp_ms": timestamp_ms,
            "operation": operation,
            "request": request,
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

/// Project only known metadata; never clone a secret subtree before redacting it.
fn redact_request(params: &Value) -> Value {
    redact_fields(params)
}

fn redact_fields(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, entry)| {
                    let safe = match key.as_str() {
                        "result" | "error" => redact_fields(entry),
                        "record_version" | "expires_at_ms" | "provider_status"
                            if entry.is_number() || entry.is_null() =>
                        {
                            entry.clone()
                        }
                        "credential_id" | "code" | "class"
                            if entry.is_string() || entry.is_null() =>
                        {
                            entry.clone()
                        }
                        "handle" => {
                            let bytes = match entry {
                                Value::String(text) => {
                                    zeroize::Zeroizing::new(text.as_bytes().to_vec())
                                }
                                Value::Array(items) => {
                                    zeroize::Zeroizing::new(u8_array_bytes(items))
                                }
                                _ => zeroize::Zeroizing::new(Vec::new()),
                            };
                            json!({"fingerprint": fingerprint(&bytes)})
                        }
                        _ if entry.is_null() => Value::Null,
                        _ => payload_marker(entry),
                    };
                    (key.clone(), safe)
                })
                .collect(),
        ),
        _ => payload_marker(value),
    }
}

fn redact_response(result: &Result<Value, CkcredRouteError>) -> Value {
    match result {
        Ok(value) => redact_fields(value),
        Err(error) => json!({"route_error": format!("{error:?}")}),
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
    let bytes = zeroize::Zeroizing::new(bytes);
    json!({
        "__redacted": true,
        "json_type": json_type,
        "len": bytes.len(),
        "fingerprint": plexus_core::jcs::sha256_tagged(&bytes),
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
    fn unknown_secret_fields_are_redacted_without_changing_the_peer_response() {
        let original = json!({"result":{"token":"secret-token","value":[255,0,128],"access_token":{"nested":"secret-token"},"record_version":7}});
        let safe = redact_response(&Ok(original.clone()));
        assert!(
            !safe.to_string().contains("secret-token"),
            "renamed secrets must not enter a trace"
        );
        assert_eq!(safe["result"]["value"]["__redacted"], true);
        assert_eq!(safe["result"]["record_version"], 7);
        assert_eq!(original["result"]["token"], "secret-token");
    }

    #[test]
    fn nested_request_secrets_are_redacted() {
        let value = json!({"nested":[{"handle":"nested-secret", "payload":"write-secret"}], "safe":"visible"});
        let redacted = redact_request(&value);
        let text = redacted.to_string();
        assert!(
            !text.contains("nested-secret") && !text.contains("write-secret"),
            "nested request secrets must be redacted"
        );
        assert_eq!(redacted["safe"]["__redacted"], true);
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
        crate::write_owner_only(&path, b"new").expect("write");
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
