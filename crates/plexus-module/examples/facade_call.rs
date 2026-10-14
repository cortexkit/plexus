//! Send one facade tool call to the RUNNING plexus module and print the reply.
//!
//! WHY THIS EXISTS: facade operations are reachable from an agent session
//! through the MCP gateway and from tests through the in-process harness, but
//! there is otherwise no way to exercise one against the LIVE daemon from a
//! shell. That gap means a deployed facade op can sit unexercised: shipped,
//! migrated, and never once called.
//!
//! A deploy that has never executed its own new code path is not verified, it
//! is merely installed. This closes that.
//!
//! Usage:
//!   cargo run -p plexus-module --example facade_call -- <connection-file> '<json>'
//!
//! where <json> is the tool-call body, e.g.
//!   '{"name":"events","arguments":{"op":"list"}}'
//!
//! Deliberately DUMB: it does not interpret the reply, retry, or validate the
//! request. It is a wire pipe, so that what you read is what the module said.

use std::time::Duration;

use subc_control::{ClientControlRequest, ClientControlResponse};
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MODULE_ID: &str = "plexus";
const DEADLINE: Duration = Duration::from_secs(30);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // The harness scrubs these for the same reason: an inherited module identity
    // makes the daemon refuse the connection as a bad consumer, and the error
    // points at authentication rather than at the environment.
    //
    // SAFETY: single-threaded, before any task is spawned.
    unsafe {
        std::env::remove_var("SUBC_MODULE_ID");
        std::env::remove_var("SUBC_LAUNCH_NONCE");
        // Names the pipe a module reads its nonce from; inherited here without
        // the pipe itself.
        std::env::remove_var("SUBC_LAUNCH_NONCE_FD");
    }

    let mut args = std::env::args().skip(1);
    let (Some(connection_path), Some(body)) = (args.next(), args.next()) else {
        eprintln!("usage: facade_call <connection-file> '<tool-call json>'");
        std::process::exit(2);
    };
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("argument is not valid JSON: {error}");
            std::process::exit(2);
        }
    };

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

    let (channel, epoch) = open_route(&mut stream).await;

    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        1,
        serde_json::to_vec(&parsed).expect("serialize the tool call"),
    )
    .expect("build the tool call");
    write_frame(&mut stream, &frame)
        .await
        .expect("write the tool frame");

    let reply = timeout(DEADLINE, read_frame(&mut stream))
        .await
        .expect("tool reply deadline")
        .expect("read the tool reply")
        .expect("daemon connection remains open");

    // Pretty-print when the reply is JSON, raw otherwise — a module error that is
    // not JSON is exactly when you least want the output swallowed.
    match serde_json::from_slice::<serde_json::Value>(&reply.body) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(_) => println!("{}", String::from_utf8_lossy(&reply.body)),
    }
}

async fn open_route(stream: &mut TcpStream) -> (u16, u32) {
    let request = ClientControlRequest::RouteOpen {
        scope: None,
        role_versions: None,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.to_string(),
        },
        identity: BindIdentity::new("/tmp", "facade-call".to_string(), "operator".to_string()),
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
