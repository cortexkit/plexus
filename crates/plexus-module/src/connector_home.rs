//! Admit connector effects only when engram's claim names this machine as the connector home.
use plexus_core::SubcPrefrontalRoutePeer;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use subc_protocol::ErrorBody;

pub const SUBJECT: &str = "role:connector_home";
pub const STATUS_OP: &str = "plexus.admin.connector_home.status";
pub const CLAIM_OP: &str = "plexus.admin.connector_home.claim";

pub trait ClaimPeer: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody>;
}

pub(crate) fn claim_reply(value: Value) -> Result<Value, ErrorBody> {
    if let Some(error) = value.get("error") {
        return Err(
            serde_json::from_value(error.clone()).unwrap_or_else(|_| ErrorBody {
                code: "peer_protocol_error".into(),
                message: "engram returned a malformed error".into(),
                detail: None,
            }),
        );
    }
    Ok(value.get("result").cloned().unwrap_or(value))
}
impl ClaimPeer for SubcPrefrontalRoutePeer {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        self.call_service(method, params).and_then(claim_reply)
    }
}
struct EngramPeer {
    path: std::path::PathBuf,
}
impl ClaimPeer for EngramPeer {
    fn call(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        // Reconnect on each read so a daemon unavailable at startup can later confirm ownership.
        let target = serde_json::from_value(
            json!({"kind":"internal_service", "module_id":"engram", "service_id":"agent-sync"}),
        )
        .expect("internal service target");
        let peer = SubcPrefrontalRoutePeer::connect_target(
            &self.path,
            target,
            subc_protocol::BindIdentity::new("connector-home", "plexus", "module"),
        )
        .map_err(|_| ErrorBody {
            code: "unavailable".into(),
            message: "engram route unavailable".into(),
            detail: None,
        })?
        .with_call_timeout(std::time::Duration::from_secs(3));
        ClaimPeer::call(&peer, method, params)
    }
}
struct Unavailable;
impl ClaimPeer for Unavailable {
    fn call(&self, _: &str, _: Value) -> Result<Value, ErrorBody> {
        Err(ErrorBody {
            code: "unavailable".into(),
            message: "engram route unavailable".into(),
            detail: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    state: &'static str,
    epoch: Option<u64>,
    holder: Option<String>,
    source: Option<String>,
    checked_at: Option<i64>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            state: "unknown",
            epoch: None,
            holder: None,
            source: None,
            checked_at: None,
        }
    }
}
pub struct ConnectorHome {
    snapshot: Mutex<Snapshot>,
    read_lane: Mutex<()>,
    peer: Arc<dyn ClaimPeer>,
    /// The first `claim.force` request built for each apply `request_id`.
    /// A retry with the same id resends exactly that request, so engram (the
    /// service that owns the claim) can recognise it as the same apply rather
    /// than a new one. Bounded: the oldest ids are forgotten past
    /// [`MAX_REMEMBERED_APPLIES`], since a retry belongs right after its apply.
    applies: Mutex<std::collections::VecDeque<(String, Value)>>,
}

/// How many apply request ids the module remembers for retries.
pub const MAX_REMEMBERED_APPLIES: usize = 64;
impl ConnectorHome {
    pub fn new(peer: Arc<dyn ClaimPeer>) -> Self {
        Self {
            snapshot: Mutex::new(Snapshot::default()),
            read_lane: Mutex::new(()),
            peer,
            applies: Mutex::new(Default::default()),
        }
    }
    pub fn unavailable() -> Self {
        Self::new(Arc::new(Unavailable))
    }
    pub fn production(path: &std::path::Path) -> Self {
        Self::new(Arc::new(EngramPeer {
            path: path.to_owned(),
        }))
    }
    /// Starts unknown on each boot: only a successful claim.read with held_here=true
    /// admits connector effects. Engram computes held_here; plexus never compares device ids.
    /// A failed read preserves unknown, held or not_held, including on route errors,
    /// timeouts, key_unavailable and unavailable: ownership does not expire, and engram
    /// can answer from its local confirmed record while its cloud is unreachable.
    /// The exception is verify_failed, which sets not_held because ownership evidence
    /// failed integrity checks rather than merely being temporarily unavailable.
    /// Plexus never persists this decision, so a restart requires a new successful read.
    pub fn refresh(&self) -> Result<Value, ErrorBody> {
        // Hold this lock across the request and update so concurrent refreshes cannot apply answers out of order.
        let _read = self.read_lane.lock().unwrap();
        let reply = self.peer.call("claim.read", json!({"subject":SUBJECT}));
        let mut next = self.snapshot.lock().unwrap();
        let before = next.clone();
        match &reply {
            Ok(value) => {
                let epoch = value["epoch"].as_u64();
                let held = epoch.is_some_and(|epoch| epoch > 0) && value["held_here"] == true;
                next.state = if held { "held" } else { "not_held" };
                next.epoch = epoch;
                next.holder = value["holder"].as_str().map(str::to_owned);
                next.source = value["source"].as_str().map(str::to_owned);
                next.checked_at = Some(plexus_core::storage::now_ms());
            }
            Err(error) if error.code == "verify_failed" => {
                next.state = "not_held";
                next.checked_at = Some(plexus_core::storage::now_ms());
            }
            Err(_) => {}
        }
        if (before.state, before.epoch, &before.holder) != (next.state, next.epoch, &next.holder) {
            eprintln!(info wire: "connector home: {} -> {} epoch={:?} holder={:?}", before.state, next.state, next.epoch, next.holder);
        }
        reply
    }
    pub fn held(&self) -> bool {
        self.snapshot.lock().unwrap().state == "held"
    }
    pub fn status(&self) -> Value {
        let s = self.snapshot.lock().unwrap();
        json!({"state":s.state, "epoch":s.epoch, "holder":s.holder, "source":s.source, "checkedAt":s.checked_at})
    }
    pub fn refusal(&self) -> Option<Value> {
        if self.held() {
            return None;
        }
        let state = self.status();
        Some(
            json!({"error":{"code":"connector_home_not_held", "message":format!("connector home not held: {state}"), "connectorHome":state, "transmission":"not_sent"}}),
        )
    }
    pub fn live_status(&self) -> Value {
        let live = self.refresh();
        match live {
            Ok(claim) => json!({"result":{"claim":claim, "connectorHome":self.status()}}),
            Err(error) => json!({"error":error,"connectorHome":self.status()}),
        }
    }
    pub fn claim(&self, params: &Value) -> Value {
        let Some(reason) = params["reason"].as_str().filter(|r| !r.trim().is_empty()) else {
            return json!({"error":{"code":"invalid_request","message":"a non-empty reason is required"}});
        };
        let latest = match self.refresh() {
            Ok(v) => v,
            Err(e) => return json!({"error":e}),
        };
        let Some(epoch) = latest["epoch"].as_u64() else {
            return json!({"error":{"code":"peer_protocol_error","message":"claim.read omitted epoch"}});
        };
        if params["apply"] != true {
            return json!({"result":{"preview":true,"subject":SUBJECT,"expected_epoch":epoch,"to_device":"self","reason":reason,"connectorHome":self.status()}});
        }
        let Some(id) = params["request_id"]
            .as_str()
            .filter(|id| valid_request_id(id))
        else {
            return json!({"error":{"code":"invalid_request","message":"apply requires a stable 32 lowercase hex request_id"}});
        };
        let request = {
            let mut applies = self.applies.lock().unwrap();
            let request = match applies.iter().find(|(known, _)| known == id) {
                Some((_, request)) => request.clone(),
                None => {
                    let request = force_request("self", epoch, id, reason);
                    if applies.len() >= MAX_REMEMBERED_APPLIES {
                        applies.pop_front();
                    }
                    applies.push_back((id.to_owned(), request.clone()));
                    request
                }
            };
            if request["reason"] != reason {
                return json!({"error":{"code":"id_reused","message":"request_id reused with a different reason"}});
            }
            request
        };
        match self.peer.call("claim.force", request) {
            Ok(outcome) => {
                let refreshed = self.refresh();
                json!({"result":{"outcome":outcome,"connectorHome":self.status(),"readError":refreshed.err()}})
            }
            Err(mut error) => {
                if matches!(error.code.as_str(), "epoch_moved" | "not_holder") {
                    let detail = error.detail.as_ref().cloned().unwrap_or(Value::Null);
                    error.message = format!(
                        "{}: holder={} epoch={}",
                        error.code, detail["holder"], detail["epoch"]
                    );
                }
                json!({"error":error})
            }
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
        home
    }
}
pub fn valid_request_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn force_request(target: &str, epoch: u64, id: &str, reason: &str) -> Value {
    json!({"subject":SUBJECT,"request_id":id,"to_device":target,"expected_epoch":epoch,"cut":"","reason":reason})
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
/// A tool missing from this table is treated as having no effect, so a test
/// checks that every advertised tool has an entry: adding a tool forces a
/// decision here instead of silently skipping the gate.
pub const TOOL_EFFECTS: &[(&str, ToolEffect)] = &[
    ("invoke", ToolEffect::Always),
    ("web_search", ToolEffect::Always),
    // Calls grep.app, a public backend outside this machine.
    ("code_search", ToolEffect::Always),
    ("github", ToolEffect::Ops(&["bot_request", "read"])),
    ("github_read", ToolEffect::Always),
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
