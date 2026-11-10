//! Reconcile scoped vault metadata, never credential payloads, into search connections.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use plexus_core::credentials::CkcredRoutePeer;
use plexus_core::diag;
use plexus_core::storage::web_search_auto::SearchKey;
use plexus_core::web_search::providers::provider_for_vault_service;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{blocking_section, web_search_provider_admin, ModuleState};

const OWNER: &str = "direct";
const MIN_RETRY_MS: i64 = 60_000;
const MAX_RETRY_MS: i64 = 3_600_000;

fn unknown_method(reply: &Value) -> bool {
    ["/code", "/error/code", "/result/error/code"]
        .iter()
        .any(|path| reply.pointer(path).and_then(Value::as_str) == Some("unknown_method"))
}

fn active_keys(reply: &Value) -> Result<BTreeSet<SearchKey>, ()> {
    let rows = reply
        .pointer("/result/credentials")
        .and_then(Value::as_array)
        .ok_or(())?;
    let mut keys = BTreeSet::new();
    for row in rows {
        // Presence distinguishes an older vault from an unmapped service.
        // A current vault can legitimately return a null provider.
        if row.get("provider").is_none() {
            return Err(());
        }
        let incarnation = row["incarnation"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(())?;
        let Some(provider) = row["provider"]
            .as_str()
            .and_then(provider_for_vault_service)
        else {
            continue;
        };
        if row["state"] != "active"
            || !row["categories"].as_array().is_some_and(|categories| {
                categories.iter().any(|category| category == "web-search")
            })
        {
            continue;
        }
        let id = row["id"]
            .as_str()
            .filter(|id| plexus_core::credentials::valid_credential_id(id))
            .ok_or(())?;
        let version = row["record_version"]
            .as_u64()
            .filter(|version| *version > 0 && *version <= i64::MAX as u64)
            .ok_or(())?;
        keys.insert(SearchKey {
            provider: provider.name.into(),
            credential_id: id.into(),
            incarnation: incarnation.into(),
            record_version: version,
        });
    }
    Ok(keys)
}

#[derive(Default)]
struct Reconciler {
    retries: BTreeMap<SearchKey, (i64, i64)>,
    warned_unsupported: bool,
}

impl Reconciler {
    fn unsupported(&mut self) {
        if !self.warned_unsupported {
            diag!(warn web_search: "vault scoped search metadata is unsupported or incomplete; automatic connection is disabled until a complete snapshot is available");
            self.warned_unsupported = true;
        }
    }

    fn due(&self, now: i64) -> bool {
        self.retries.values().any(|(next, _)| *next <= now)
    }

    fn list_and_reconcile(
        &mut self,
        state: &Arc<ModuleState>,
        peer: &dyn CkcredRoutePeer,
        now: i64,
        notice: bool,
    ) {
        if !state.runtime.connector_home.held() {
            return;
        }
        match peer.call("credential.list_scoped", json!({})) {
            Ok(reply) => {
                if self.reconcile(state, &reply, now, notice).is_err() {
                    diag!(warn web_search: "search key reconciliation could not read or write its store; it will retry");
                }
            }
            Err(_) => {
                diag!(warn web_search: "scoped search key list is unavailable; no connections changed")
            }
        }
    }

    fn reconcile(
        &mut self,
        state: &Arc<ModuleState>,
        reply: &Value,
        now: i64,
        notice: bool,
    ) -> Result<(), cortexkit_store::StoreError> {
        if !state.runtime.connector_home.held() {
            return Ok(());
        }
        let active = match active_keys(reply) {
            Ok(active) => active,
            Err(()) => {
                self.unsupported();
                return Ok(());
            }
        };
        self.retries.retain(|key, _| active.contains(key));
        let store = state.store();
        let recorded = store.auto_search_connections(OWNER)?;
        for row in &recorded {
            if row.revoked_at_ms.is_some() {
                continue;
            }
            let connection = store.connection(OWNER, &row.connection_id)?;
            let person_revoked = connection
                .as_ref()
                .is_some_and(|connection| connection.status == "revoked")
                || (connection.is_none() && row.appended_at_ms.is_some());
            let removed = !active.contains(&row.key);
            if (removed || person_revoked) && state.runtime.connector_home.held() {
                if let Some(id) = store.revoke_auto_search_connection(
                    OWNER,
                    &row.key,
                    removed && !person_revoked,
                )? {
                    state.runtime.mcp_transport.unregister_connection(&id);
                    state.runtime.rest_transport.unregister_connection(&id);
                }
            }
        }
        let recorded = store.auto_search_connections(OWNER)?;
        for key in &active {
            let prior = recorded.iter().find(|row| row.key == *key);
            if prior.is_some_and(|row| row.revoked_at_ms.is_some() || row.appended_at_ms.is_some())
            {
                continue;
            }
            if !notice && self.retries.get(key).is_some_and(|(next, _)| *next > now) {
                continue;
            }
            if !state.runtime.connector_home.held() {
                break;
            }
            let provider = plexus_core::web_search::providers::provider_named(&key.provider)
                .expect("mapped provider");
            let applied = web_search_provider_admin::auto_plan_and_apply(
                state,
                OWNER,
                provider,
                &key.credential_id,
                |id| {
                    // The association cannot move to a different connection on a
                    // retry: doing so would erase a person's final revoke.
                    if prior.is_some_and(|row| row.connection_id != id) {
                        return Err(json!({"error":{"code":"auto_connection_changed"}}));
                    }
                    store
                        .remember_auto_search_connection(OWNER, key, id)
                        .map_err(|_| json!({"error":{"code":"auto_connection_store"}}))
                },
            );
            let complete = applied.as_ref().is_ok_and(|(_, reply)| {
                reply.pointer("/result/applied") == Some(&Value::Bool(true))
            });
            if complete && state.runtime.connector_home.held() {
                if store.complete_auto_search_connection(OWNER, key)? {
                    let empty = applied
                        .as_ref()
                        .ok()
                        .and_then(|(_, reply)| reply.pointer("/result/grants"))
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty);
                    if empty {
                        diag!(info web_search: "connected search provider {}; no caller holds search yet", key.provider);
                    }
                }
                self.retries.remove(key);
            } else {
                let delay = self
                    .retries
                    .get(key)
                    .map_or(MIN_RETRY_MS, |(_, delay)| (*delay * 2).min(MAX_RETRY_MS));
                self.retries
                    .insert(key.clone(), (now.saturating_add(delay), delay));
                diag!(warn web_search: "search provider {} did not complete discovery/enrollment; retry in {} seconds or on the next vault notice", key.provider, delay / 1000);
            }
        }
        Ok(())
    }
}

pub(crate) fn spawn(
    state: Arc<ModuleState>,
    stop: mpsc::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    spawn_with_reconnect_delay(state, stop, Duration::from_secs(60))
}

fn spawn_with_reconnect_delay(
    state: Arc<ModuleState>,
    mut stop: mpsc::Receiver<()>,
    reconnect_delay: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(peer) = state.runtime.vault_peer.clone() else {
            return;
        };
        let mut reconcile = Reconciler::default();
        loop {
            let watch = blocking_section(|| peer.watch_scoped());
            if let Ok(mut watch) = watch {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut was_home = state.runtime.connector_home.held();
                loop {
                    tokio::select! {
                        _ = stop.recv() => return,
                        event = watch.events.recv() => {
                            let Some(event) = event else { break };
                            if unknown_method(&event) { reconcile.unsupported(); break; }
                            if event["kind"] != "changed" { break; }
                            blocking_section(|| reconcile.list_and_reconcile(&state, peer.as_ref(), plexus_core::storage::now_ms(), true));
                        }
                        _ = tick.tick() => {
                            let now = plexus_core::storage::now_ms();
                            let home = state.runtime.connector_home.held();
                            if home && (!was_home || reconcile.due(now)) {
                                blocking_section(|| reconcile.list_and_reconcile(&state, peer.as_ref(), now, false));
                            }
                            was_home = home;
                        }
                    }
                }
            }
            tokio::select! {
                _ = stop.recv() => return,
                _ = tokio::time::sleep(reconnect_delay) => {}
            }
        }
    })
}

#[cfg(test)]
#[path = "web_search_auto_tests.rs"]
mod tests;
