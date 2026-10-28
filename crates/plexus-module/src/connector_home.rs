//! Fence outside effects to the user's connector-home machine. Entorhinal, the
//! CortexKit module that records which machine holds each single-holder role,
//! answers `role.read` for `connector_home`; plexus serves only while it
//! confirms this machine holds it.
use plexus_core::SubcPrefrontalRoutePeer;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use subc_protocol::ErrorBody;

pub const ROLE: &str = "connector_home";
pub const STATUS_OP: &str = "plexus.admin.connector_home.status";

pub trait RolePeer: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody>;
}

pub(crate) fn role_reply(value: Value) -> Result<Value, ErrorBody> {
    if let Some(error) = value.get("error") {
        return Err(
            serde_json::from_value(error.clone()).unwrap_or_else(|_| ErrorBody {
                code: "peer_protocol_error".into(),
                message: "entorhinal returned a malformed error".into(),
                detail: None,
            }),
        );
    }
    value.get("result").cloned().ok_or_else(|| ErrorBody {
        code: "peer_protocol_error".into(),
        message: "entorhinal reply omitted result".into(),
        detail: None,
    })
}
impl RolePeer for SubcPrefrontalRoutePeer {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        self.call_service(method, params).and_then(role_reply)
    }
}
struct EntorhinalPeer {
    path: std::path::PathBuf,
    connection: Mutex<Option<SubcPrefrontalRoutePeer>>,
}
impl RolePeer for EntorhinalPeer {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        cached_role_call(
            &self.connection,
            || {
                SubcPrefrontalRoutePeer::connect(
                    &self.path,
                    "entorhinal",
                    subc_protocol::BindIdentity::new("connector-home", "plexus", "module"),
                )
                .map_err(|_| ErrorBody {
                    code: "unavailable".into(),
                    message: "entorhinal route unavailable".into(),
                    detail: None,
                })
                .map(|peer| peer.with_call_timeout(std::time::Duration::from_secs(3)))
            },
            method,
            params,
        )
    }
}

fn cached_role_call<P: RolePeer>(
    connection: &Mutex<Option<P>>,
    connect: impl FnOnce() -> Result<P, ErrorBody>,
    method: &str,
    params: Value,
) -> Result<Value, ErrorBody> {
    let mut connection = connection.lock().unwrap();
    if connection.is_none() {
        *connection = Some(connect()?);
    }
    let reply = RolePeer::call(
        connection.as_ref().expect("connected role peer"),
        method,
        params,
    );
    // A broken daemon route must be replaceable after a restart. Semantic
    // refusals keep the connection; only transport failures require a dial.
    if reply.as_ref().is_err_and(|error| {
        matches!(
            error.code.as_str(),
            "unavailable" | "outcome_unknown" | "timeout" | "transport_error"
        )
    }) {
        *connection = None;
    }
    reply
}
#[cfg(any(test, feature = "test-support"))]
struct Unavailable;
#[cfg(any(test, feature = "test-support"))]
impl RolePeer for Unavailable {
    fn call(&self, _: &str, _: Value) -> Result<Value, ErrorBody> {
        Err(ErrorBody {
            code: "unavailable".into(),
            message: "entorhinal route unavailable".into(),
            detail: None,
        })
    }
}

struct RoleAnswer {
    epoch: u64,
    known: bool,
    held_here: bool,
    stale: bool,
    holder_name: Option<String>,
    source: Option<String>,
}

impl RoleAnswer {
    fn parse(value: &Value) -> Result<Self, ErrorBody> {
        let malformed = || ErrorBody {
            code: "peer_protocol_error".into(),
            message: "entorhinal returned a malformed role.read reply".into(),
            detail: None,
        };
        let text = |key: &str| -> Result<Option<String>, ErrorBody> {
            match value.get(key) {
                Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                _ => Err(malformed()),
            }
        };
        if value.get("role").and_then(Value::as_str) != Some(ROLE) {
            return Err(malformed());
        }
        // Even nullable fields must be present: a partial answer cannot establish ownership.
        text("holder")?;
        Ok(Self {
            epoch: value
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or_else(malformed)?,
            known: value
                .get("known")
                .and_then(Value::as_bool)
                .ok_or_else(malformed)?,
            held_here: value
                .get("held_here")
                .and_then(Value::as_bool)
                .ok_or_else(malformed)?,
            stale: value
                .get("stale")
                .and_then(Value::as_bool)
                .ok_or_else(malformed)?,
            holder_name: text("holder_name")?,
            source: text("source")?,
        })
    }

    fn confirmed_in_process(&self) -> bool {
        // Entorhinal marks its cached answers stale whenever it restarts, and clears
        // the mark only after re-reading the role from its synced store. A stale
        // answer may predate another machine taking the role, so it never counts
        // as confirmation.
        !self.stale
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    state: &'static str,
    epoch: Option<u64>,
    holder_name: Option<String>,
    code: Option<String>,
    source: Option<String>,
    checked_at: Option<i64>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            state: "unknown",
            epoch: None,
            holder_name: None,
            code: None,
            source: None,
            checked_at: None,
        }
    }
}
pub struct ConnectorHome {
    snapshot: Mutex<Snapshot>,
    read_lane: Mutex<()>,
    peer: Arc<dyn RolePeer>,
    decision: tokio::sync::watch::Sender<bool>,
}

impl ConnectorHome {
    pub fn new(peer: Arc<dyn RolePeer>) -> Self {
        Self {
            snapshot: Mutex::new(Snapshot::default()),
            read_lane: Mutex::new(()),
            peer,
            decision: tokio::sync::watch::channel(false).0,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn unavailable() -> Self {
        Self::new(Arc::new(Unavailable))
    }
    pub fn production(path: &std::path::Path) -> Self {
        Self::new(Arc::new(EntorhinalPeer {
            path: path.to_owned(),
            connection: Mutex::new(None),
        }))
    }
    /// Only fresh, well-formed answers replace the last decision. Route failures and
    /// stale answers preserve it; integrity failures revoke admission immediately.
    /// Plexus never persists admission, so a restart needs a new confirmed read.
    pub fn refresh(&self) -> Result<Value, ErrorBody> {
        // Serialize requests and updates so concurrent readers cannot apply answers out of order.
        let _read = self.read_lane.lock().unwrap();
        let reply = self
            .peer
            .call("role.read", json!({"role":ROLE}))
            .and_then(|value| {
                RoleAnswer::parse(&value)?;
                Ok(value)
            });
        let mut next = self.snapshot.lock().unwrap();
        let before = next.clone();
        match &reply {
            Ok(value) => {
                let answer = RoleAnswer::parse(value).expect("validated role answer");
                if answer.confirmed_in_process() {
                    next.state = if !answer.known {
                        "unknown"
                    } else if answer.held_here {
                        "held"
                    } else {
                        "not_held"
                    };
                    next.epoch = Some(answer.epoch);
                    next.holder_name = answer.holder_name;
                    next.source = answer.source;
                    next.code = None;
                    next.checked_at = Some(plexus_core::storage::now_ms());
                }
            }
            Err(error) if error.code == "claim_integrity_failed" => {
                next.state = "integrity_failed";
                next.code = Some(error.code.clone());
                next.checked_at = Some(plexus_core::storage::now_ms());
            }
            Err(_) => {}
        }
        if (
            before.state,
            before.epoch,
            &before.holder_name,
            &before.source,
            &before.code,
        ) != (
            next.state,
            next.epoch,
            &next.holder_name,
            &next.source,
            &next.code,
        ) {
            eprintln!(info wire: "connector home: {} -> {} epoch={:?} holder_name={:?}", before.state, next.state, next.epoch, next.holder_name);
        }
        self.decision.send_if_modified(|held| {
            let admitted = next.state == "held";
            let changed = *held != admitted;
            *held = admitted;
            changed
        });
        reply
    }
    pub(crate) fn decisions(&self) -> tokio::sync::watch::Receiver<bool> {
        self.decision.subscribe()
    }
    pub fn held(&self) -> bool {
        self.snapshot.lock().unwrap().state == "held"
    }
    pub fn status(&self) -> Value {
        let s = self.snapshot.lock().unwrap();
        json!({"state":s.state, "epoch":s.epoch, "holder_name":s.holder_name, "code":s.code, "source":s.source, "checkedAt":s.checked_at})
    }
    pub fn refusal(&self) -> Option<Value> {
        if self.held() {
            return None;
        }
        let state = json!({"state":self.snapshot.lock().unwrap().state});
        Some(
            json!({"error":{"code":"connector_home_not_held", "message":format!("connector home not held: {state}"), "connectorHome":state, "transmission":"not_sent"}}),
        )
    }
    pub fn live_status(&self) -> Value {
        let live = self.refresh();
        match live {
            Ok(role) => json!({"result":{"role":role, "connectorHome":self.status()}}),
            Err(error) => json!({"error":error,"connectorHome":self.status()}),
        }
    }
    /// Development and test helper that admits connector effects; production never calls it.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_admitted() -> Self {
        let home = Self::unavailable();
        *home.snapshot.lock().unwrap() = Snapshot {
            state: "held",
            epoch: Some(1),
            ..Snapshot::default()
        };
        home.decision.send_replace(true);
        home
    }
}
/// Whether calls to one tool have an effect outside this store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolEffect {
    /// Every call reaches outside the store.
    Always,
    /// Only the listed ops reach outside the store.
    Ops(&'static [&'static str]),
    /// No call reaches outside the store.
    Never,
}

/// The decision for every tool served on the tool route. An effect is a
/// vendor call (including public search backends), a phone consent card filed
/// or withdrawn through prefrontal, or an approved request executed; those
/// run only while this machine holds the connector home.
///
/// A tool missing from this table requires the gate as a safe fallback. A test
/// also requires every advertised tool to have an entry so adding a tool forces
/// an explicit effect decision.
pub const TOOL_EFFECTS: &[(&str, ToolEffect)] = &[
    ("invoke", ToolEffect::Always),
    ("web_search", ToolEffect::Always),
    // Calls grep.app, a public backend outside this machine.
    ("code_search", ToolEffect::Always),
    // Both bindings.read and bindings.read_for_agent only inspect the store.
    ("github", ToolEffect::Ops(&["bot_request"])),
    ("github_read", ToolEffect::Always),
    // Every call posts a reaction on GitHub as the agent's bot.
    ("github_react", ToolEffect::Always),
    ("connections", ToolEffect::Ops(&["connect"])),
    ("requests", ToolEffect::Ops(&["approve", "deny"])),
    ("tool.withdraw", ToolEffect::Always),
    ("catalog", ToolEffect::Never),
    ("events", ToolEffect::Never),
    ("events_get", ToolEffect::Never),
];

/// Whether this tool call has an effect outside this store; see [`TOOL_EFFECTS`].
pub fn tool_effect(name: &str, op: Option<&str>) -> bool {
    match TOOL_EFFECTS
        .iter()
        .find(|(tool, _)| *tool == name)
        .map(|(_, effect)| *effect)
    {
        Some(ToolEffect::Always) => true,
        Some(ToolEffect::Ops(ops)) => op.is_some_and(|op| ops.contains(&op)),
        Some(ToolEffect::Never) => false,
        None => true,
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Peer(Arc<AtomicUsize>);
    impl RolePeer for Peer {
        fn call(&self, _: &str, _: Value) -> Result<Value, ErrorBody> {
            match self.0.load(Ordering::SeqCst) {
                0 => Ok(json!({})),
                1 => Err(ErrorBody {
                    code: "claim_integrity_failed".into(),
                    message: "refused".into(),
                    detail: None,
                }),
                _ => Err(ErrorBody {
                    code: "unavailable".into(),
                    message: "disconnected".into(),
                    detail: None,
                }),
            }
        }
    }

    #[test]
    fn role_route_is_reused_until_a_transport_failure() {
        let connections = AtomicUsize::new(0);
        let state = Arc::new(AtomicUsize::new(0));
        let connection = Mutex::new(None);
        let call = || {
            cached_role_call(
                &connection,
                || {
                    connections.fetch_add(1, Ordering::SeqCst);
                    Ok(Peer(state.clone()))
                },
                "role.read",
                json!({}),
            )
        };
        call().unwrap();
        call().unwrap();
        state.store(1, Ordering::SeqCst);
        assert!(call().is_err());
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        state.store(2, Ordering::SeqCst);
        assert!(call().is_err());
        state.store(0, Ordering::SeqCst);
        call().unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }
}
