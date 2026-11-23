use super::{role_reply, ConnectorHome, ROLE};
use crate::blocking_section;
use futures_util::future::BoxFuture;
use plexus_core::PlexusStore;
use serde_json::{json, Value};
use std::{future, path::Path, sync::Arc, time::Duration};
use subc_client_rs::{
    CallError, CallOptions, SubcConsumer, SubscribeOptions, Subscription, SubscriptionEnd,
};
use subc_protocol::{BindIdentity, ErrorBody, RouteTarget};
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

const CALL_BOUND: Duration = Duration::from_secs(3);
const RETRY: Duration = Duration::from_secs(3);
const CHECK_DEADLINE: Duration = Duration::from_millis(200);
type Reply<'a> = BoxFuture<'a, Result<Value, ErrorBody>>;

fn request_bytes(method: &str, params: Value) -> Vec<u8> {
    json!({"method": method, "params": params})
        .to_string()
        .into_bytes()
}

fn failure(code: &str, message: &str) -> ErrorBody {
    ErrorBody {
        code: code.into(),
        message: message.into(),
        detail: None,
    }
}

fn malformed() -> ErrorBody {
    failure(
        "peer_protocol_error",
        "entorhinal sent an invalid connector-home lease reply",
    )
}

fn unavailable() -> ErrorBody {
    failure(
        "unavailable",
        "entorhinal connector-home lease route unavailable",
    )
}

enum Exit {
    Stopped,
    Ended(ErrorBody),
    Unsupported(ErrorBody),
}

// If the daemon stops the task before it can run its close path, dropping the
// consumer releases the route and this guard still invalidates local admission.
struct Disconnect<'a>(&'a ConnectorHome);
impl Drop for Disconnect<'_> {
    fn drop(&mut self) {
        self.0.gate.disconnect();
    }
}

pub(crate) async fn run(
    home: Arc<ConnectorHome>,
    store: Arc<PlexusStore>,
    connection_file: &Path,
    mut stop: mpsc::Receiver<()>,
) {
    let _disconnect = Disconnect(&home);
    let mut last_error = None;
    loop {
        let exit = open(&home, &store, connection_file, &mut stop).await;
        home.gate.disconnect();
        match exit {
            Exit::Stopped => return,
            Exit::Unsupported(error) => {
                plexus_core::diag!(warn wire: "entorhinal does not support connector-home leases ({}); using role.read", error.code);
                home.enable_legacy();
                let _ = blocking_section(|| home.refresh());
                return;
            }
            Exit::Ended(error) if last_error.as_deref() != Some(error.code.as_str()) => {
                plexus_core::diag!(warn wire: "connector-home lease unavailable ({})", error.code);
                last_error = Some(error.code);
            }
            Exit::Ended(_) => {}
        }
        tokio::select! {
            _ = stop.recv() => return,
            _ = tokio::time::sleep(RETRY) => {}
        }
    }
}

async fn open(
    home: &ConnectorHome,
    store: &PlexusStore,
    connection_file: &Path,
    stop: &mut mpsc::Receiver<()>,
) -> Exit {
    let connected = tokio::select! {
        _ = stop.recv() => return Exit::Stopped,
        connected = tokio::time::timeout(CALL_BOUND, SubcConsumer::connect(connection_file, Default::default())) => connected,
    };
    let Ok(Ok(consumer)) = connected else {
        return Exit::Ended(unavailable());
    };
    let options = CallOptions {
        timeout: CALL_BOUND,
        route_retry_deadline: CALL_BOUND,
        ..Default::default()
    };
    let route = tokio::select! {
        _ = stop.recv() => return Exit::Stopped,
        route = consumer.open_route(RouteTarget::ManagementSurface { module_id: "entorhinal".into() }, BindIdentity::new("plexus", "module"), options.clone()) => route,
    };
    let Ok(route) = route else {
        return Exit::Ended(unavailable());
    };
    let result = match consumer
        .subscribe_route(
            &route,
            request_bytes("role.lease", json!({"role": ROLE})),
            SubscribeOptions {
                route_open_timeout: CALL_BOUND,
                ..Default::default()
            },
        )
        .await
    {
        Ok(mut stream) => {
            watch(home, store, &mut stream, stop, |method, params| {
                let options = options.clone();
                let consumer = &consumer;
                let route = &route;
                Box::pin(async move {
                    let bytes = consumer
                        .request(route, request_bytes(method, params), options)
                        .await
                        .map_err(|error| match error {
                            CallError::Module(body) => body,
                            _ => unavailable(),
                        })?;
                    role_reply(serde_json::from_slice(&bytes).map_err(|_| malformed())?)
                })
            })
            .await
        }
        Err(_) => Exit::Ended(unavailable()),
    };
    home.gate.disconnect();
    let _ = tokio::time::timeout(
        CALL_BOUND,
        consumer.close_handle(&route, Default::default()),
    )
    .await;
    result
}

async fn watch<'a>(
    home: &ConnectorHome,
    store: &PlexusStore,
    stream: &mut Subscription,
    stop: &mut mpsc::Receiver<()>,
    call: impl Fn(&'static str, Value) -> Reply<'a>,
) -> Exit {
    let mut tick = tokio::time::interval(CHECK_DEADLINE);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut highest = None;
    let mut last_seq = None;
    let mut yielding = None;
    loop {
        if yielding.is_none() {
            yielding = home
                .gate
                .wait_for_yield()
                .map(|gen| call("role.lease.yield", json!({"role": ROLE, "gen": gen})));
        }
        tokio::select! {
            biased;
            _ = stop.recv() => return Exit::Stopped,
            payload = stream.events().recv() => {
                let Some(payload) = payload else { return ended(stream.ended().await, last_seq.is_some()); };
                let notice = match serde_json::from_slice::<super::gate::Notice>(&payload) {
                    Ok(notice) => notice,
                    Err(_) => {
                        // A malformed notice still gets an ack if its sequence is readable.
                        if let Some(seq) = serde_json::from_slice::<Value>(&payload).ok()
                            .and_then(|value| value.get("seq").and_then(Value::as_u64)) {
                            home.gate.disconnect();
                            let _ = call("role.lease.ack", json!({"role": ROLE, "seq": seq})).await;
                        }
                        return Exit::Ended(malformed());
                    }
                };
                home.gate.receive(notice);
                let mut ack = call("role.lease.ack", json!({"role": ROLE, "seq": notice.seq}));
                let reply = loop {
                    tokio::select! {
                        _ = stop.recv() => return Exit::Stopped,
                        reply = &mut ack => break reply,
                        yielded = yield_reply(&mut yielding) => {
                            yielding = None;
                            home.gate.finish_yield(yielded);
                        }
                    }
                };
                match reply {
                    Ok(ack) if ack.get("acknowledged").and_then(Value::as_bool) == Some(true) => {},
                    Ok(_) => return Exit::Ended(malformed()),
                    Err(error) => return Exit::Ended(error),
                }
                if last_seq.is_some_and(|seq| notice.seq <= seq) {
                    continue;
                }
                last_seq = Some(notice.seq);
                if highest != Some(notice.gen) {
                    match blocking_section(|| store.observe_connector_home_generation(notice.gen)) {
                        Ok(true) => highest = Some(notice.gen),
                        Ok(false) => continue,
                        Err(_) => return Exit::Ended(failure("store_failure", "cannot journal connector-home lease generation")),
                    }
                }
                home.gate.confirm(notice);
            }
            yielded = yield_reply(&mut yielding) => {
                yielding = None;
                home.gate.finish_yield(yielded);
            }
            _ = home.gate.drained.notified() => {}
            _ = tick.tick() => {}
        }
    }
}

async fn yield_reply(pending: &mut Option<Reply<'_>>) -> Option<bool> {
    match pending {
        Some(reply) => reply
            .await
            .ok()
            .and_then(|reply| reply.get("yielded").and_then(Value::as_bool)),
        None => future::pending().await,
    }
}

fn ended(end: SubscriptionEnd, got_notice: bool) -> Exit {
    match end {
        SubscriptionEnd::Error(error)
            if !got_notice && matches!(error.code.as_str(), "unknown_method" | "unsupported") =>
        {
            Exit::Unsupported(error)
        }
        SubscriptionEnd::Error(error) => Exit::Ended(error),
        // Some management handlers encode the refusal in a unary reply instead
        // of sending an Error frame. Never accept a unary success as a watch.
        SubscriptionEnd::Response(bytes) if !got_notice => {
            match serde_json::from_slice(&bytes).map(role_reply) {
                Ok(Err(error))
                    if matches!(error.code.as_str(), "unknown_method" | "unsupported") =>
                {
                    Exit::Unsupported(error)
                }
                Ok(Err(error)) => Exit::Ended(error),
                _ => Exit::Ended(malformed()),
            }
        }
        _ => Exit::Ended(unavailable()),
    }
}
