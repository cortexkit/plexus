//! Identity and residence reads against Entorhinal's shared agent registry.
//!
//! Delivery routing needs an existence check when an operator changes a
//! subscription, but polling must not pay for that check. This module keeps the
//! set-time route seam independent from the consumer's delivery interpretation.

#[cfg(any(test, feature = "test-support"))]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Mutex;

use cortexkit_agent_identity::{AgentResolveReply, AgentStatus, GoneReason};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::github_identity::PrefrontalRoutePeer;

/// The Entorhinal management operation that resolves an agent registry id.
pub const AGENT_RESOLVE_OPERATION: &str = "agent.resolve";

const AGENT_WHERE_OPERATION: &str = "agent.where";

/// A confirmed, non-local residence. The box id survives re-keying, while
/// the residence epoch changes on a move, including a move back to this box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentResidence {
    pub holder_box: String,
    pub epoch: u64,
}

/// The registry's set-time verdict for a requested delivery agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentLookup {
    /// The registry has a live agent with this id.
    Known,
    /// The shared identity log has not seen this id; it may not have caught up.
    Unknown,
    /// The id was a registry entry that has since been retired.
    Retired,
    /// The registry could not be consulted or returned an unrecognized reply.
    Unavailable,
}

/// Resolves delivery targets at subscription changes and identifies retired
/// agents during periodic scheduler maintenance, not during event dispatch.
pub trait AgentRegistry: Send + Sync {
    fn lookup(&self, agent_id: &str) -> AgentLookup;

    /// Read confirmed remote residence uncached. Missing, stale, local, or
    /// unavailable residence cannot authorize remote work.
    fn remote_residence(&self, _agent_id: &str) -> Option<AgentResidence> {
        None
    }
}

/// In-memory registry stub for tests that need explicit registry verdicts.
#[cfg(any(test, feature = "test-support"))]
pub struct StubAgentRegistry {
    default_response: Mutex<AgentLookup>,
    responses: Mutex<HashMap<String, AgentLookup>>,
    requests: Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for StubAgentRegistry {
    fn default() -> Self {
        Self {
            default_response: Mutex::new(AgentLookup::Unavailable),
            responses: Mutex::new(HashMap::new()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl StubAgentRegistry {
    pub fn with_default_response(response: AgentLookup) -> Self {
        Self {
            default_response: Mutex::new(response),
            ..Self::default()
        }
    }

    pub fn set_default_response(&self, response: AgentLookup) {
        *self
            .default_response
            .lock()
            .expect("agent registry default response lock") = response;
    }

    pub fn set_response(&self, agent_id: impl Into<String>, response: AgentLookup) {
        self.responses
            .lock()
            .expect("agent registry responses lock")
            .insert(agent_id.into(), response);
    }

    /// Agent ids requested from this stub, in call order.
    pub fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("agent registry requests lock")
            .clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl AgentRegistry for StubAgentRegistry {
    fn lookup(&self, agent_id: &str) -> AgentLookup {
        self.requests
            .lock()
            .expect("agent registry requests lock")
            .push(agent_id.to_string());
        self.responses
            .lock()
            .expect("agent registry responses lock")
            .get(agent_id)
            .copied()
            .unwrap_or_else(|| {
                *self
                    .default_response
                    .lock()
                    .expect("agent registry default response lock")
            })
    }
}

/// Production fail-closed registry used when the Entorhinal route is unavailable.
pub struct FailClosedAgentRegistry;

impl AgentRegistry for FailClosedAgentRegistry {
    fn lookup(&self, _agent_id: &str) -> AgentLookup {
        AgentLookup::Unavailable
    }
}

/// [`AgentRegistry`] adapter for Entorhinal's management surface.
pub struct EntorhinalAgentRegistry<P> {
    peer: Arc<P>,
}

impl<P> Clone for EntorhinalAgentRegistry<P> {
    fn clone(&self) -> Self {
        Self {
            peer: Arc::clone(&self.peer),
        }
    }
}

impl<P> EntorhinalAgentRegistry<P> {
    pub fn new(peer: Arc<P>) -> Self {
        Self { peer }
    }
}

impl<P: PrefrontalRoutePeer + 'static> AgentRegistry for EntorhinalAgentRegistry<P> {
    fn lookup(&self, agent_id: &str) -> AgentLookup {
        let Ok(reply) = self.peer.call(
            AGENT_RESOLVE_OPERATION,
            serde_json::json!({ "agent_id": agent_id }),
        ) else {
            return AgentLookup::Unavailable;
        };
        resolve_agent_lookup_reply(agent_id, &reply)
    }

    fn remote_residence(&self, agent_id: &str) -> Option<AgentResidence> {
        let reply = self
            .peer
            .call(
                AGENT_WHERE_OPERATION,
                serde_json::json!({"agent_id": agent_id}),
            )
            .ok()?;
        confirmed_remote_residence(&reply)
    }
}

fn confirmed_remote_residence(reply: &Value) -> Option<AgentResidence> {
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Status {
        HeldElsewhere,
    }

    #[derive(Deserialize)]
    struct Row {
        status: Status,
        known: bool,
        stale: bool,
        epoch: u64,
        holder_box: String,
    }

    if reply.get("error").is_some() || reply.get("code").is_some() {
        return None;
    }
    let Row {
        status: Status::HeldElsewhere,
        known,
        stale,
        epoch,
        holder_box,
    } = serde_json::from_value(reply.get("result")?.clone()).ok()?;
    // `holder` can contain the identity of the writer of the residence record
    // rather than a daemon box id. Check only `holder_box`, and trust `stale`
    // instead of guessing freshness from the wall clock.
    (known
        && !stale
        && epoch > 0
        && holder_box.len() == 32
        && holder_box.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(AgentResidence { holder_box, epoch })
}

/// Decode Entorhinal's registry reply without performing I/O.
///
/// An unfamiliar success shape fails closed: accepting it as a known target
/// would silently route work to an id whose existence was never established.
pub fn resolve_agent_lookup_reply(agent_id: &str, reply: &Value) -> AgentLookup {
    if reply.get("error").is_some() || reply.get("code").is_some() {
        return AgentLookup::Unavailable;
    }
    let Some(body) = reply.get("result") else {
        return AgentLookup::Unavailable;
    };
    if [
        "agent_id",
        "generation",
        "gone",
        "incarnation",
        "merged_into",
        "status",
    ]
    .iter()
    .any(|key| body.get(key).is_none())
    {
        return AgentLookup::Unavailable;
    }
    let Ok(reply) = serde_json::from_value::<AgentResolveReply>(body.clone()) else {
        return AgentLookup::Unavailable;
    };
    if reply.agent.agent_id != agent_id {
        return AgentLookup::Unavailable;
    }
    // The shared types preserve unfamiliar strings and do not validate writer
    // invariants. Plexus must require a complete tombstone before destroying
    // authority, and must never transfer grants to a merge destination.
    match reply.agent.status {
        AgentStatus::Live => AgentLookup::Known,
        AgentStatus::Unknown => AgentLookup::Unknown,
        AgentStatus::Retired | AgentStatus::Merged
            if reply.agent.gone.as_ref().is_some_and(|gone| {
                gone.at >= 0 && matches!(gone.reason, GoneReason::Deleted | GoneReason::Merged)
            }) =>
        {
            AgentLookup::Retired
        }
        _ => AgentLookup::Unavailable,
    }
}

#[cfg(test)]
pub(crate) fn entorhinal_reply(agent_id: &str, status: &str) -> Value {
    let gone = match status {
        "retired" => serde_json::json!({"at":1,"reason":"deleted"}),
        "merged" => serde_json::json!({"at":1,"reason":"merged","into_agent_id":"survivor"}),
        _ => Value::Null,
    };
    serde_json::json!({"result":{
        "agent_id":agent_id,"status":status,"gone":gone,
        "merged_into":if status == "merged" {Some("survivor")} else {None},
        "generation":7,"incarnation":"0123456789abcdef"
    }})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_identity::PrefrontalRouteError;

    struct MockRoutePeer {
        calls: Mutex<Vec<(String, Value)>>,
        reply: Mutex<Result<Value, PrefrontalRouteError>>,
    }

    impl PrefrontalRoutePeer for MockRoutePeer {
        fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError> {
            self.calls
                .lock()
                .expect("route calls lock")
                .push((operation.to_string(), params));
            self.reply.lock().expect("route reply lock").clone()
        }
    }

    impl Default for MockRoutePeer {
        fn default() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                reply: Mutex::new(Ok(entorhinal_reply("agent-1", "live"))),
            }
        }
    }

    #[test]
    fn route_registry_uses_entorhinal_agent_resolve() {
        let peer = Arc::new(MockRoutePeer::default());
        let registry = EntorhinalAgentRegistry::new(Arc::clone(&peer));

        assert_eq!(registry.lookup("agent-1"), AgentLookup::Known);
        assert_eq!(
            peer.calls.lock().expect("route calls lock").as_slice(),
            &[(
                AGENT_RESOLVE_OPERATION.to_string(),
                serde_json::json!({"agent_id": "agent-1"}),
            )]
        );
    }

    #[test]
    fn malformed_residence_rows_cannot_authorize_a_remote_caller() {
        let valid = serde_json::json!({"result": {
            "status":"held_elsewhere", "known":true, "stale":false, "epoch":1,
            "holder_box":"0123456789abcdef0123456789abcdef", "ignored":{}
        }});
        assert!(confirmed_remote_residence(&valid).is_some());
        for (field, concrete) in [
            ("status", serde_json::json!("future_state")),
            ("known", serde_json::json!(false)),
            ("stale", serde_json::json!("false")),
            ("epoch", serde_json::json!(1.5)),
            ("epoch", serde_json::json!(-1)),
            ("holder_box", serde_json::json!(["a"])),
            ("holder_box", serde_json::json!("not-a-box-id")),
        ] {
            let mut reply = valid.clone();
            reply["result"][field] = concrete;
            assert_eq!(confirmed_remote_residence(&reply), None, "{reply}");
        }
        let mut ambiguous = valid;
        ambiguous["error"] = serde_json::json!({"code":"unavailable"});
        assert_eq!(confirmed_remote_residence(&ambiguous), None);
    }

    #[test]
    fn registry_rejects_reply_echoing_a_different_agent() {
        let peer = Arc::new(MockRoutePeer::default());
        *peer.reply.lock().unwrap() = Ok(entorhinal_reply("someone-else", "retired"));
        assert_eq!(
            EntorhinalAgentRegistry::new(peer).lookup("requested-agent"),
            AgentLookup::Unavailable
        );
    }

    #[test]
    fn entorhinal_samples_replay_through_real_adapter() {
        let mut count = 0;
        for source in [
            include_str!("../tests/fixtures/agent-identity-reads-v1/agent-resolve.json"),
            include_str!("../tests/fixtures/agent-identity-reads-v1/agent-resolve-merged.json"),
        ] {
            let records: Vec<Value> = serde_json::from_str(source).unwrap();
            for record in records {
                assert_eq!(record["op"], "agent.resolve");
                let id = record["request"]["agent_id"].as_str().unwrap_or("");
                let expected = match record["reply"]["result"]["status"].as_str() {
                    Some("live") => AgentLookup::Known,
                    Some("retired" | "merged") => AgentLookup::Retired,
                    Some("unknown") => AgentLookup::Unknown,
                    _ => AgentLookup::Unavailable,
                };
                let peer = Arc::new(MockRoutePeer::default());
                *peer.reply.lock().unwrap() = Ok(record["reply"].clone());
                assert_eq!(
                    EntorhinalAgentRegistry::new(peer).lookup(id),
                    expected,
                    "{record}"
                );
                count += 1;
            }
        }
        assert_eq!(count, 9);
    }

    #[test]
    fn entorhinal_fixture_bytes_match_verified_manifest() {
        use sha2::{Digest, Sha256};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/agent-identity-reads-v1");
        let sums = include_bytes!("../tests/fixtures/agent-identity-reads-v1/SHA256SUMS");
        assert_eq!(
            format!("{:x}", Sha256::digest(sums)),
            "18c544afce7d40c8fc7e44dcbcee8ece5dac9a157c356a7c6002e34fa202fa62"
        );
        for line in std::str::from_utf8(sums).unwrap().lines() {
            let (digest, name) = line.split_once("  ").unwrap();
            assert_eq!(
                format!(
                    "{:x}",
                    Sha256::digest(std::fs::read(root.join(name)).unwrap())
                ),
                digest,
                "{name}"
            );
        }
    }

    #[test]
    fn malformed_entorhinal_replies_and_transport_fail_closed() {
        let valid = entorhinal_reply("agent-1", "retired");
        let mut bad = vec![
            serde_json::json!({}),
            serde_json::json!({"error":{"code":"unknown_agent"}}),
        ];
        for (key, value) in [
            ("status", serde_json::json!("future")),
            ("agent_id", serde_json::json!("other")),
            ("gone", Value::Null),
            ("gone", serde_json::json!({"at":1})),
            ("gone", serde_json::json!({"reason":"deleted"})),
            ("gone", serde_json::json!({"reason":"future","at":1})),
            ("gone", serde_json::json!({"reason":"deleted","at":-1})),
            ("gone", serde_json::json!({"reason":"deleted","at":1.5})),
        ] {
            let mut reply = valid.clone();
            reply["result"][key] = value;
            bad.push(reply);
        }
        for reply in bad {
            assert_eq!(
                resolve_agent_lookup_reply("agent-1", &reply),
                AgentLookup::Unavailable,
                "{reply}"
            );
        }
        let peer = Arc::new(MockRoutePeer::default());
        *peer.reply.lock().unwrap() = Err(PrefrontalRouteError::Transport);
        assert_eq!(
            EntorhinalAgentRegistry::new(peer).lookup("agent-1"),
            AgentLookup::Unavailable
        );
    }
}
