//! An in-process routing provider for tests. It answers `role.describe` as a
//! router that serves search, chooses the first route of its own ranking that
//! the select offers, and records every call it receives so a test can read
//! the exact params plexus sent.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use super::{RouteRef, RoutingCallError, RoutingPeer};

/// How the fake answers.
#[derive(Debug, Clone, PartialEq)]
pub enum FakeMode {
    /// Answer every op normally.
    Serve,
    /// Every call fails as if the route could not be opened.
    Unreachable,
    /// `route.select` is refused with this code; other ops answer normally.
    RefuseSelect(String),
}

pub struct FakeRouter {
    ranking: Vec<RouteRef>,
    mode: Mutex<FakeMode>,
    describe: Mutex<Value>,
    calls: Mutex<Vec<(String, Value)>>,
    decisions: AtomicUsize,
}

impl FakeRouter {
    /// A router preferring routes in `ranking` order. A route offered but not
    /// ranked is chosen only after every ranked one, in the order offered.
    pub fn ranked(ranking: Vec<RouteRef>) -> Self {
        Self {
            ranking,
            mode: Mutex::new(FakeMode::Serve),
            describe: Mutex::new(Self::serving_search_describe()),
            calls: Mutex::new(Vec::new()),
            decisions: AtomicUsize::new(0),
        }
    }

    /// The `role.describe` answer of a router that serves search selection
    /// and reads attempt outcomes.
    pub fn serving_search_describe() -> Value {
        json!({
            "role": "routing",
            "version": 1,
            "ops": ["role.describe", "route.select", "route.report", "route.account_for", "route.account_observe"],
            "consumers": [{"id": super::CONSUMER, "priced_only": false}],
            "requirement_fields": ["iq"],
            "detail_supported": false,
            "kinds": ["search"],
            "capabilities": [
                "select_kind", "select_media", "select_search",
                "select_eligible_routes", "report_attempt_outcomes"
            ],
        })
    }

    pub fn set_mode(&self, mode: FakeMode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub fn set_describe(&self, describe: Value) {
        *self.describe.lock().unwrap() = describe;
    }

    /// The params of every call of `method`, oldest first.
    pub fn params(&self, method: &str) -> Vec<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(called, _)| called == method)
            .map(|(_, params)| params.clone())
            .collect()
    }

    /// Every op called, oldest first.
    pub fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(method, _)| method.clone())
            .collect()
    }

    fn select(&self, params: &Value) -> Result<Value, RoutingCallError> {
        let offered: Vec<RouteRef> = params["eligible_routes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|route| {
                Some(RouteRef::new(
                    route.get("provider")?.as_str()?,
                    route.get("model")?.as_str()?,
                ))
            })
            .collect();
        let chosen = self
            .ranking
            .iter()
            .find(|route| offered.contains(route))
            .or_else(|| offered.first());
        let Some(route) = chosen else {
            return Err(RoutingCallError::Refused {
                code: "no_route".into(),
                message: "no route meets the request: no_available_model".into(),
                detail: json!({"reason": "no_available_model"}),
            });
        };
        let decision = self.decisions.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"result": {
            "decision_id": format!("dec_{decision:012}"),
            "engine": {
                "caller_local": false,
                "local": false,
                "model": route.model,
                "module": "plexus",
                "provider": route.provider,
            },
            "expires_at_ms": 1_750_000_600_000_i64,
        }}))
    }
}

impl RoutingPeer for FakeRouter {
    fn call(
        &self,
        method: &str,
        params: Value,
        _scope: Option<&crate::scope::CallScope>,
        _timeout: Duration,
    ) -> Result<Value, RoutingCallError> {
        self.calls
            .lock()
            .unwrap()
            .push((method.to_owned(), params.clone()));
        let mode = self.mode.lock().unwrap().clone();
        if mode == FakeMode::Unreachable {
            return Err(RoutingCallError::Unreachable("fake router unreachable".into()));
        }
        match method {
            "role.describe" => Ok(json!({"result": self.describe.lock().unwrap().clone()})),
            "route.select" => match mode {
                FakeMode::RefuseSelect(code) => Err(RoutingCallError::Refused {
                    code,
                    message: "refused by the fake router".into(),
                    detail: json!({}),
                }),
                _ => self.select(&params),
            },
            "route.report" => Ok(json!({"result": {
                "decision_id": params["decision_id"],
                "report_id": "rep_fake",
                "outcome": params["outcome"],
            }})),
            other => Err(RoutingCallError::Refused {
                code: "invalid_request".into(),
                message: format!("the fake router does not serve {other}"),
                detail: json!({"field": "method"}),
            }),
        }
    }
}
