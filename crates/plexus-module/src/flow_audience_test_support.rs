//! Access to the internal handlers and cache for the supervised audience tests.

use super::{Answer, Duration, FlowAudiences, Instant};
use crate::{
    blocking_section, facade_tool_reply_with_budget, grants_would_ask,
    request_execution::RequestBudget, test_fixtures::imported_runtime, wire, CallMode, ModuleState,
    RouteBindings,
};
use plexus_core::{scope::CallScope, test_scratch::Scratch, MockTransport, PlexusStore};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::Arc};
use subc_protocol::{Frame, FrameType, Principal};

pub struct FlowRuntime(Arc<ModuleState>);

impl FlowRuntime {
    pub fn new(audiences: FlowAudiences) -> (Self, Arc<PlexusStore>, Arc<MockTransport>, Scratch) {
        let (mut state, store, transport, scratch) = imported_runtime();
        Arc::get_mut(&mut state).unwrap().runtime.flow_audiences = audiences;
        (Self(state), store, transport, scratch)
    }

    pub fn call(&self, name: &str, args: Value, stamp: Option<CallScope>) -> Value {
        let bindings = Arc::new(RouteBindings::new());
        bindings
            .insert_mode(
                1,
                1,
                Principal::Reserved {
                    module_id: "basal".into(),
                },
                stamp,
                CallMode::Flow,
            )
            .unwrap();
        let frame =
            Frame::build(FrameType::Request, wire::control_flags(), 1, 1, 7, vec![]).unwrap();
        blocking_section(|| {
            facade_tool_reply_with_budget(
                &frame,
                json!({"name":name,"arguments":args}).as_object().unwrap(),
                &self.0,
                &bindings,
                RequestBudget::new(),
            )
        })
        .unwrap()
    }

    pub fn would_ask(&self, scope: &CallScope, request: &Value) -> Value {
        blocking_section(|| {
            grants_would_ask::run(
                &self.0,
                "reserved:basal",
                Some(scope),
                request.as_object().unwrap(),
            )
        })
    }

    pub fn audiences(&self) -> &FlowAudiences {
        &self.0.runtime.flow_audiences
    }
}

pub fn expire_cache_entry(audiences: &FlowAudiences, flow_id: &str) {
    audiences.cache.lock().unwrap().get_mut(flow_id).unwrap().0 =
        Instant::now() - Duration::from_secs(31);
}

pub fn clear_cache(audiences: &FlowAudiences) {
    audiences.cache.lock().unwrap().clear();
}

pub fn seed_cache_entry(
    audiences: &FlowAudiences,
    flow_id: String,
    answer: Answer,
    inserted: Instant,
    used: Instant,
) {
    audiences
        .cache
        .lock()
        .unwrap()
        .insert(flow_id, (inserted, answer, used));
}

pub fn cache_keys(audiences: &FlowAudiences) -> HashSet<String> {
    audiences.cache.lock().unwrap().keys().cloned().collect()
}
