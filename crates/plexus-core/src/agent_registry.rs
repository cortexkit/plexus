//! Resolution of agent ids against prefrontal's registry.
//!
//! Delivery routing needs an existence check when an operator changes a
//! subscription, but polling must not pay for that check. This module keeps the
//! set-time route seam independent from the consumer's delivery interpretation.

#[cfg(any(test, feature = "test-support"))]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Mutex;

use serde_json::Value;

use crate::github_identity::PrefrontalRoutePeer;

/// The prefrontal management operation that resolves an agent registry id.
pub const AGENT_RESOLVE_OPERATION: &str = "agent.resolve";

/// The registry's set-time verdict for a requested delivery agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentLookup {
    /// The registry has a live agent with this id.
    Known,
    /// No agent has this id.
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

/// Production fail-closed registry used when no prefrontal route is configured.
pub struct FailClosedAgentRegistry;

impl AgentRegistry for FailClosedAgentRegistry {
    fn lookup(&self, _agent_id: &str) -> AgentLookup {
        AgentLookup::Unavailable
    }
}

/// [`AgentRegistry`] adapter for prefrontal's management surface.
pub struct PrefrontalAgentRegistry<P> {
    peer: Arc<P>,
}

impl<P> Clone for PrefrontalAgentRegistry<P> {
    fn clone(&self) -> Self {
        Self {
            peer: Arc::clone(&self.peer),
        }
    }
}

impl<P> PrefrontalAgentRegistry<P> {
    pub fn new(peer: Arc<P>) -> Self {
        Self { peer }
    }
}

impl<P: PrefrontalRoutePeer + 'static> AgentRegistry for PrefrontalAgentRegistry<P> {
    fn lookup(&self, agent_id: &str) -> AgentLookup {
        let Ok(reply) = self.peer.call(
            AGENT_RESOLVE_OPERATION,
            serde_json::json!({ "agent_id": agent_id }),
        ) else {
            return AgentLookup::Unavailable;
        };
        resolve_agent_lookup_reply_for(agent_id, &reply)
    }
}

fn resolve_agent_lookup_reply_for(agent_id: &str, reply: &Value) -> AgentLookup {
    let body = reply.get("result").unwrap_or(reply);
    if body
        .pointer("/agent/agent_id")
        .or_else(|| body.pointer("/gone/agent_id"))
        .is_some_and(|echo| echo.as_str() != Some(agent_id))
    {
        return AgentLookup::Unavailable;
    }
    resolve_agent_lookup_reply(reply)
}

/// Decode prefrontal's registry reply without performing I/O.
///
/// An unfamiliar success shape fails closed: accepting it as a known target
/// would silently route work to an id whose existence was never established.
pub fn resolve_agent_lookup_reply(reply: &Value) -> AgentLookup {
    let reply = reply.get("result").unwrap_or(reply);
    if reply.get("agent").is_some() && reply.get("gone").is_some() {
        return AgentLookup::Unavailable;
    }
    // A live agent is reported as an object. `{"agent": null}` (or any other
    // non-object) names no agent, so it must not read as proof one exists.
    if reply.get("agent").is_some_and(Value::is_object) {
        AgentLookup::Known
    } else if reply.get("gone").is_some_and(|gone| {
        gone.is_object()
            && gone.get("at").and_then(Value::as_u64).is_some()
            && match gone.get("reason").and_then(Value::as_str) {
                Some("deleted") => true,
                Some("merged") => gone.get("into_agent_id").and_then(Value::as_str).is_some(),
                _ => false,
            }
    }) {
        AgentLookup::Retired
    } else if reply
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| reply.get("code"))
        .and_then(Value::as_str)
        == Some("unknown_agent")
    {
        AgentLookup::Unknown
    } else {
        AgentLookup::Unavailable
    }
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
                reply: Mutex::new(Ok(serde_json::json!({"agent": {"id": "agent-1"}}))),
            }
        }
    }

    #[test]
    fn route_registry_uses_the_confirmed_prefrontal_management_operation() {
        let peer = Arc::new(MockRoutePeer::default());
        let registry = PrefrontalAgentRegistry::new(Arc::clone(&peer));

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
    fn registry_rejects_reply_echoing_a_different_agent() {
        let peer = Arc::new(MockRoutePeer::default());
        *peer.reply.lock().unwrap() =
            Ok(serde_json::json!({"result":{"agent":{"agent_id":"someone-else"}}}));
        assert_eq!(
            PrefrontalAgentRegistry::new(peer).lookup("requested-agent"),
            AgentLookup::Unavailable
        );
    }

    #[test]
    fn registry_reply_classes_stay_distinct_and_unknown_shapes_fail_closed() {
        assert_eq!(
            resolve_agent_lookup_reply(&serde_json::json!({"error": {"code": "unknown_agent"}})),
            AgentLookup::Unknown
        );
        assert_eq!(
            resolve_agent_lookup_reply(
                &serde_json::json!({"gone": {"reason": "deleted", "at": 1}})
            ),
            AgentLookup::Retired
        );
        // A null or non-object agent field establishes nothing about the id,
        // so it fails closed like any other unfamiliar shape.
        for unproven in [
            serde_json::json!({"agent": null}),
            serde_json::json!({"agent": "agent-1"}),
            serde_json::json!({"result": {"agent": null}}),
        ] {
            assert_eq!(
                resolve_agent_lookup_reply(&unproven),
                AgentLookup::Unavailable,
                "{unproven} must not resolve as a known agent"
            );
        }
        assert_eq!(
            resolve_agent_lookup_reply(&serde_json::json!({"result": {"agent": {"id": "a"}}})),
            AgentLookup::Known
        );
        assert_eq!(
            resolve_agent_lookup_reply(&serde_json::json!({"unexpected": true})),
            AgentLookup::Unavailable
        );
    }
}
