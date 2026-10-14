//! Daemon-stamp fixtures shared by bot-write integration tests.
use plexus_core::scope::{CallScope, ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};

pub fn delegating_scope(agent: &str) -> CallScope {
    CallScope {
        owner: "reserved:prefrontal-core".into(),
        scope_ref: "fixture-session".into(),
        scope_epoch: 1,
        kind: Some("head".into()),
        parent: None,
        parent_state: None,
        agent_id: Some(agent.into()),
        flow_id: None,
        delegates: true,
        owner_authorized: true,
    }
}

/// A daemon answer for a fixed live fixture session. Tests of revocation and
/// outages install their own reader instead.
pub struct LiveScopeReader(pub CallScope);
impl ScopeReader for LiveScopeReader {
    fn describe(&self, owner: &str, scope_ref: &str) -> Result<ScopeDescription, ScopeReadError> {
        assert_eq!(owner, self.0.owner);
        assert_eq!(scope_ref, self.0.scope_ref);
        Ok(ScopeDescription {
            status: ScopeStatus::Live,
            owner_synced: true,
            owner_configured: true,
            live: Some(self.0.clone()),
        })
    }
}
