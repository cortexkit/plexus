//! Send one vault management call to the RUNNING claustrum module and print a
//! REDACTED reply.
//!
//! Run a credential management method using the daemon's normal authenticated
//! route protocol. Timestamps around the request make operator diagnostics
//! comparable with service logs without dumping credential reply bodies.
//!
//! SECRETS: `credential.get` replies carry live token bytes. Reply bodies are
//! not dumped: only recognized status values, numeric record metadata and
//! booleans are printable; arbitrary strings, unknown fields and malformed
//! reply bodies are omitted. Measurement transcripts get pasted
//! into peer messages and runbooks, and a token in a transcript outlives the
//! token's rotation.
//!
//! Usage:
//!   cargo run -p plexus-module --example vault_call -- <connection-file> <method> '<params json>'
//!
//! e.g.
//!   vault_call conn.json credential.get '{"handle":"ckh_..."}'
//!   vault_call conn.json credential.report_auth_failure \
//!       '{"handle":"ckh_...","provider_status":401,"record_version":7}'

use std::time::Duration;

use subc_control::{ClientControlRequest, ClientControlResponse};
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The vault registers `ManagementSurface` only; a `ToolProvider` target is
/// refused at route open. Other first-party modules (prefrontal-core) expose
/// management operations the same way, so the target is overridable: pass
/// `--module <id>` as the first pair of arguments to address one of them.
const DEFAULT_MODULE_ID: &str = "claustrum";
const DEADLINE: Duration = Duration::from_secs(30);

#[cfg(test)]
#[path = "../../plexus-core/tests/support/bounded.rs"]
mod bounded;

fn print_vault_reply(sent_at_ms: u128, received_at_ms: u128, body: &[u8]) {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut value) => {
            redact_payload(&mut value);
            println!(
                "{{\"sent_at_ms\":{sent_at_ms},\"received_at_ms\":{received_at_ms},\"reply\":{}}}",
                serde_json::to_string(&value).unwrap()
            );
        }
        Err(_) => println!("non-JSON vault reply omitted ({} bytes)", body.len()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // An inherited module identity makes the daemon refuse the connection as a
    // bad consumer, pointing at authentication rather than the environment.
    //
    // SAFETY: single-threaded, before any task is spawned.
    unsafe {
        std::env::remove_var("SUBC_MODULE_ID");
        std::env::remove_var("SUBC_LAUNCH_NONCE");
        // Names the pipe a module reads its nonce from; inherited here without
        // the pipe itself.
        std::env::remove_var("SUBC_LAUNCH_NONCE_FD");
    }

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut module_id = DEFAULT_MODULE_ID.to_string();
    if args.first().map(String::as_str) == Some("--module") {
        if args.len() < 2 {
            eprintln!("--module requires a module id");
            std::process::exit(2);
        }
        module_id = args[1].clone();
        args.drain(..2);
    }
    let mut args = args.into_iter();
    let (Some(connection_path), Some(method), Some(params)) =
        (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: vault_call [--module <id>] <connection-file> <method> '<params json>'");
        std::process::exit(2);
    };
    let params: serde_json::Value = match serde_json::from_str(&params) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("params argument is not valid JSON: {error}");
            std::process::exit(2);
        }
    };
    let body = serde_json::json!({ "method": method, "params": params });

    let connection =
        connection_file::read(&connection_path).expect("read the daemon connection file");
    let endpoint = connection
        .endpoints
        .first()
        .expect("the daemon publishes at least one endpoint");
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .expect("connect to the daemon");
    authenticate_client(&mut stream, &connection, DEADLINE)
        .await
        .expect("authenticate to the daemon");

    let (channel, epoch) = open_route(&mut stream, &module_id).await;

    // Millisecond timestamps let an operator compare request latency with
    // the corresponding service log without printing credential bodies.
    let sent_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis();

    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        1,
        serde_json::to_vec(&body).expect("serialize the vault call"),
    )
    .expect("build the vault call");
    write_frame(&mut stream, &frame)
        .await
        .expect("write the vault frame");

    let reply = timeout(DEADLINE, read_frame(&mut stream))
        .await
        .expect("vault reply deadline")
        .expect("read the vault reply")
        .expect("daemon connection remains open");

    let received_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis();

    print_vault_reply(sent_at_ms, received_at_ms, &reply.body);
}

/// Keep only recognized, non-secret metadata. Unknown field names are not
/// echoed either: a malformed reply could put credential bytes in a key.
fn redact_payload(value: &mut serde_json::Value) {
    let serde_json::Value::Object(map) = value else {
        *value = serde_json::json!("<redacted>");
        return;
    };
    let mut safe = serde_json::Map::new();
    let mut omitted = 0;
    for (key, entry) in map.iter() {
        match key.as_str() {
            "result" | "error" => {
                let mut nested = entry.clone();
                redact_payload(&mut nested);
                safe.insert(key.clone(), nested);
            }
            "record_version" | "expires_at" | "expires_at_ms" | "exp" if entry.is_number() => {
                safe.insert(key.clone(), entry.clone());
            }
            "ok" | "success" | "refreshable" if entry.is_boolean() => {
                safe.insert(key.clone(), entry.clone());
            }
            "code" | "status"
                if entry.as_str().is_some_and(|value| {
                    matches!(
                        value,
                        "ok" | "success"
                            | "active"
                            | "expired"
                            | "revoked"
                            | "auth_required"
                            | "credential_missing"
                            | "credential_not_found"
                            | "vault_locked"
                            | "not_found"
                    )
                }) =>
            {
                safe.insert(key.clone(), entry.clone());
            }
            _ => {
                omitted += 1;
            }
        }
    }
    if omitted > 0 {
        safe.insert("redacted_fields".into(), serde_json::json!(omitted));
    }
    *value = serde_json::Value::Object(safe);
}

async fn open_route(stream: &mut TcpStream, module_id: &str) -> (u16, u32) {
    let request = ClientControlRequest::RouteOpen {
        scope: None,
        role_versions: None,
        target: RouteTarget::ManagementSurface {
            module_id: module_id.to_string(),
        },
        identity: BindIdentity::new("/tmp", "vault-call".to_string(), "operator".to_string()),
        consumer_identity: None,
        consumer_capabilities: None,
        admission_facts: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        1,
        serde_json::to_vec(&request).expect("serialize route open"),
    )
    .expect("build route open");
    write_frame(stream, &frame).await.expect("write route open");
    let reply = timeout(DEADLINE, read_frame(stream))
        .await
        .expect("route open deadline")
        .expect("read route open reply")
        .expect("daemon connection remains open");
    match serde_json::from_slice::<ClientControlResponse>(&reply.body) {
        Ok(ClientControlResponse::RouteOpen {
            route_channel,
            route_epoch,
        }) => (route_channel, route_epoch),
        other => {
            eprintln!(
                "route open refused: {}",
                String::from_utf8_lossy(&reply.body)
            );
            eprintln!("parsed: {other:?}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::redact_payload;
    use serde_json::json;

    /// Run with `cargo test -p plexus-module --example vault_call`: example
    /// tests are not part of `cargo test --workspace`.
    #[test]
    fn every_payload_shape_is_redacted_before_printing() {
        let mut reply = json!({
            "result": {
                "payload": "Q0FOQVJZLVNFQ1JFVA==",
                "record_version": 3,
                "nested": [{"payload": [67, 65, 78]}, {"payload": {"token": "CANARY"}}],
                "absent": {"payload": null}
            }
        });
        redact_payload(&mut reply);
        let printed = reply.to_string();
        assert!(
            !printed.contains("Q0FOQVJZLVNFQ1JFVA=="),
            "string payload printed: {printed}"
        );
        assert!(
            !printed.contains("CANARY"),
            "object payload printed: {printed}"
        );
        assert!(
            !printed.contains("67,65,78"),
            "array payload printed: {printed}"
        );
        assert!(reply["result"].get("payload").is_none());
        assert!(reply["result"].get("nested").is_none());
        assert_eq!(reply["result"]["record_version"], 3);
        assert!(reply["result"].get("absent").is_none());
    }

    #[test]
    fn live_tokens_never_reach_stdout() {
        const TEST: &str = "tests::live_tokens_never_reach_stdout";
        let token = format!("ghp_{}", "EXAMPLE".repeat(6));
        if let Some(body) = std::env::var_os("PLEXUS_VAULT_REPLY_CHILD") {
            super::print_vault_reply(1, 2, body.to_str().unwrap().as_bytes());
            return;
        }
        let mut bodies = Vec::new();
        for field in [
            "payload",
            "token",
            "access_token",
            "secret",
            "future_secret",
            "detail",
            "code",
            token.as_str(),
        ] {
            bodies.push(json!({"result":{field:token,"record_version":3}}).to_string());
        }
        bodies.push(format!("truncated non-JSON reply: {token}"));
        for body in bodies {
            let output = super::bounded::child_output(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env("PLEXUS_VAULT_REPLY_CHILD", body),
                std::time::Duration::from_secs(10),
                "vault stdout redaction child",
            )
            .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !stdout.contains(&token),
                "live credential bytes reached stdout: {stdout}"
            );
        }
    }
}
