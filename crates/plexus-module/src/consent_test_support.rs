//! A nonblocking consent service double for withdrawal and attribution tests.
//! Request and detach return a pending card; await simulates a broken route so
//! these tests can park immediately without waiting out the 110-second tool
//! request deadline.
//! The live-daemon requester tests cover actual waits, answers and wire bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use plexus_core::consent_card::{
    ConsentCards, ElicitationCallError, ElicitationRoute, CONSENT_AWAIT, CONSENT_DETACH,
    CONSENT_GET, CONSENT_REPORT_EXECUTION, CONSENT_REQUEST, CONSENT_WITHDRAW,
};
use plexus_core::scope::CallScope;
use serde_json::{json, Value};

#[derive(Default)]
struct PendingCards(Mutex<HashMap<String, Value>>);
impl ElicitationRoute for PendingCards {
    fn call_scoped(
        &self,
        _: &CallScope,
        operation: &str,
        params: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        if operation == CONSENT_AWAIT {
            return Err(ElicitationCallError::NotSent);
        }
        let mut cards = self.0.lock().unwrap();
        if operation == CONSENT_REQUEST {
            let id = format!("el_{}", params["requester_ref"].as_str().unwrap());
            let mut record = params;
            record["elicitation_id"] = json!(id);
            record["state"] = json!("pending");
            cards.insert(id.clone(), record);
            return Ok(json!({"elicitation_id": id}));
        }
        let id = params["elicitation_id"].as_str().unwrap();
        let record = cards
            .get_mut(id)
            .ok_or_else(|| ElicitationCallError::Refused {
                code: "elicitation_not_found".into(),
                message: "unknown test card".into(),
            })?;
        match operation {
            CONSENT_WITHDRAW => {
                if record["state"] == "pending" {
                    record["state"] = json!("withdrawn");
                }
            }
            CONSENT_REPORT_EXECUTION => record["execution"] = params["execution"].clone(),
            CONSENT_GET | CONSENT_DETACH => {}
            _ => return Err(ElicitationCallError::Transport),
        }
        let mut reply = record.clone();
        if operation == CONSENT_DETACH && reply["state"] == "pending" {
            reply["detached"] = json!(true);
        }
        Ok(reply)
    }
}

pub(super) fn pending_cards() -> Arc<ConsentCards> {
    Arc::new(ConsentCards::new(Arc::new(PendingCards::default())))
}

pub(super) fn live_reader(scope: CallScope) -> Arc<dyn plexus_core::scope::ScopeReader> {
    struct Live(CallScope);
    impl plexus_core::scope::ScopeReader for Live {
        fn describe(
            &self,
            _: &str,
            _: &str,
        ) -> Result<plexus_core::scope::ScopeDescription, plexus_core::scope::ScopeReadError>
        {
            Ok(plexus_core::scope::ScopeDescription {
                status: plexus_core::scope::ScopeStatus::Live,
                owner_synced: true,
                owner_configured: true,
                live: Some(self.0.clone()),
            })
        }
    }
    Arc::new(Live(scope))
}

pub(super) fn worker_stamp(scope_ref: &str, epoch: u64) -> subc_protocol::scope::ScopeStamp {
    let owner = subc_protocol::Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let mut stamp = subc_protocol::scope::ScopeStamp::new(
        owner.clone(),
        scope_ref,
        epoch,
        subc_protocol::scope::ScopeKind::Worker,
    )
    .with_owner_authorized(true);
    stamp.parent = Some(
        serde_json::from_value(json!({"owner":owner,"ref":"head-parent","scope_epoch":1})).unwrap(),
    );
    stamp.parent_state = Some(subc_protocol::scope::ParentState::Linked);
    stamp
}

#[derive(Default)]
pub(super) struct SearchCardSpy(pub std::sync::atomic::AtomicUsize);
impl ElicitationRoute for SearchCardSpy {
    fn call_scoped(
        &self,
        _: &CallScope,
        operation: &str,
        _: Value,
        _: Duration,
    ) -> Result<Value, ElicitationCallError> {
        assert_eq!(operation, CONSENT_REQUEST);
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"elicitation_id":"el_forbidden_search_card"}))
    }
}
impl SearchCardSpy {
    pub(super) fn cards(self: &Arc<Self>) -> Arc<ConsentCards> {
        Arc::new(ConsentCards::new(self.clone()))
    }
    pub(super) fn calls(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
