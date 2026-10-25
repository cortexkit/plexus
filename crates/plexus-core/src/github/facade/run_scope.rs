//! A caller-supplied liveness constraint, never a source of bot authority.
use crate::scope::{
    principal_label, CallScope, ScopeDescription, ScopeReadError, ScopeStatus, SCOPE_ENDED,
    SCOPE_NOT_SYNCED, SCOPE_UNVERIFIABLE,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct RunScope {
    pub owner: String,
    #[serde(rename = "ref")]
    pub scope_ref: String,
    pub epoch: u64,
}

impl RunScope {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("run_scope")?;
        for field in object.keys() {
            if !matches!(field.as_str(), "owner" | "ref" | "epoch") {
                return Err(format!("run_scope.{field}"));
            }
        }
        Ok(Self {
            owner: object
                .get("owner")
                .and_then(Value::as_str)
                .ok_or("run_scope.owner")?
                .to_owned(),
            scope_ref: object
                .get("ref")
                .and_then(Value::as_str)
                .ok_or("run_scope.ref")?
                .to_owned(),
            epoch: object
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or("run_scope.epoch")?,
        })
    }

    pub fn recheck(
        &self,
        route: &CallScope,
        answer: Result<&ScopeDescription, &ScopeReadError>,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        let described = answer.map_err(|_| SCOPE_UNVERIFIABLE)?;
        match described.status {
            ScopeStatus::Ended => return Err(SCOPE_ENDED),
            ScopeStatus::NotLive if described.owner_synced => return Err(SCOPE_ENDED),
            ScopeStatus::NotLive if described.owner_configured => return Err(SCOPE_NOT_SYNCED),
            ScopeStatus::NotLive => return Err(SCOPE_UNVERIFIABLE),
            ScopeStatus::Live => {}
        }
        let live = described.live.as_ref().ok_or(SCOPE_UNVERIFIABLE)?;
        if live.owner != self.owner || live.scope_ref != self.scope_ref {
            return Err(SCOPE_UNVERIFIABLE);
        }
        if live.scope_epoch != self.epoch {
            return Err(SCOPE_ENDED);
        }
        if described
            .expires_at_ms
            .is_some_and(|expiry| u64::try_from(now_ms).map_or(true, |now| now >= expiry))
        {
            return Err(SCOPE_ENDED);
        }
        let parent = described.parent.as_ref().ok_or(SCOPE_UNVERIFIABLE)?;
        if principal_label(&parent.owner) != route.owner
            || parent.scope_ref != route.scope_ref
            || parent.scope_epoch != route.scope_epoch
        {
            return Err("run_scope_not_child");
        }
        Ok(())
    }
}
