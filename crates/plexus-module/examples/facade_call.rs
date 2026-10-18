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

use subc_protocol::{BindIdentity, RouteTarget};
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

    let consumer = timeout(
        DEADLINE,
        subc_client_rs::SubcConsumer::connect(
            std::path::Path::new(&connection_path),
            subc_client_rs::ConsumerOptions::default(),
        ),
    )
    .await
    .expect("daemon connection deadline")
    .expect("connect to the daemon");
    // The consumer routes by channel, epoch and correlation, so notifications
    // or unrelated frames cannot be mistaken for this operation's answer.
    let reply = timeout(
        DEADLINE,
        consumer.call(
            RouteTarget::ToolProvider {
                module_id: MODULE_ID.to_owned(),
            },
            BindIdentity::new("/tmp", "facade-call", "operator"),
            serde_json::to_vec(&parsed).expect("serialize the tool call"),
            subc_client_rs::CallOptions::default(),
        ),
    )
    .await
    .expect("tool reply deadline")
    .expect("tool call failed");

    // Pretty-print when the reply is JSON, raw otherwise — a module error that is
    // not JSON is exactly when you least want the output swallowed.
    match serde_json::from_slice::<serde_json::Value>(&reply) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(_) => println!("{}", String::from_utf8_lossy(&reply)),
    }
}
