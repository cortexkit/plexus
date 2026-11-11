//! Connector-home-only discovery and manifest activation follow-up. Losing
//! connector-home drops the watch and fences GitHub reads, proposals, cards
//! and repository binds until this computer holds the role again.

use crate::{blocking_section, ModuleState};
use plexus_core::github::manifest_binding::{ApprovalPass, Progress, DISCOVERY_INTERVAL};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

pub(crate) fn spawn(
    state: Arc<ModuleState>,
    stop: mpsc::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    spawn_every(state, stop, Duration::from_secs(5))
}

fn spawn_every(
    state: Arc<ModuleState>,
    mut stop: mpsc::Receiver<()>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(peer) = state.runtime.vault_peer.as_ref() else {
            return;
        };
        let Some(credentials) = state.runtime.github_handle_credentials.as_ref() else {
            return;
        };
        let Some(cards) = state.runtime.engine.consent_card_client() else {
            return;
        };
        let mut progress = Progress::default();
        let mut watch: Option<plexus_core::credentials::CkcredWatch> = None;
        let mut last_discovery = None;
        let mut last_watch_attempt = None;
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let event = tokio::select! {
                biased;
                _ = stop.recv() => break,
                _ = tick.tick() => None,
                value = async {
                    match watch.as_mut() {
                        Some(watch) => watch.events.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match value {
                        Some(value) => Some(value),
                        None => { watch = None; continue; }
                    }
                }
            };
            if !state.runtime.connector_home.held() {
                watch = None;
                last_discovery = None;
                last_watch_attempt = None;
                continue;
            }
            blocking_section(|| {
                let reader = crate::github_control_reader(&state);
                let held = || state.runtime.connector_home.held();
                let now = plexus_core::storage::now_ms();
                let mut pass = ApprovalPass {
                    store: state.store(),
                    vault: peer.as_ref(),
                    cards,
                    credentials: credentials.as_ref(),
                    reader: reader.as_ref(),
                    held: &held,
                    progress: &mut progress,
                };
                let result = if let Some(event) = event {
                    pass.notice(event, now)
                } else if due(last_discovery, now, DISCOVERY_INTERVAL) {
                    last_discovery = Some(now);
                    pass.discover(now)
                } else {
                    pass.follow_ready(now)
                };
                if let Err(code) = result {
                    plexus_core::diag!(warn governance: "manifest binding pass failed: {code}");
                }
                if progress.stopped() {
                    watch = None;
                }
                if !progress.stopped()
                    && watch.is_none()
                    && held()
                    && due(last_watch_attempt, now, Duration::from_secs(30))
                {
                    last_watch_attempt = Some(now);
                    watch = peer.watch_manifest().ok();
                }
            });
        }
    })
}

fn due(last: Option<i64>, now: i64, interval: Duration) -> bool {
    last.is_none_or(|last| now.saturating_sub(last) >= interval.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plexus_core::credentials::{CkcredRouteError, CkcredRoutePeer, CkcredWatch};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };
    #[test]
    fn discovery_is_due_on_start_and_every_fifteen_minutes() {
        assert!(due(None, 0, DISCOVERY_INTERVAL));
        assert!(!due(Some(1), 900_000, DISCOVERY_INTERVAL));
        assert!(due(Some(1), 900_001, DISCOVERY_INTERVAL));
    }

    struct Vault {
        watches: Mutex<Vec<mpsc::Sender<Value>>>,
    }
    impl CkcredRoutePeer for Vault {
        fn call(&self, method: &str, _: Value) -> Result<Value, CkcredRouteError> {
            assert_eq!(method, "manifest.propose_binding");
            Ok(json!({"result":{"error":{"code":"one_tap_disabled","class":"transient"}}}))
        }
        fn watch_manifest(&self) -> Result<CkcredWatch, CkcredRouteError> {
            let (sender, receiver) = mpsc::channel(16);
            self.watches.lock().unwrap().push(sender);
            Ok(CkcredWatch::from_events(receiver))
        }
    }
    struct Reader(AtomicUsize);
    impl plexus_core::github::control::InstallationReader for Reader {
        fn repositories_page(
            &self,
            _: &plexus_core::ResolvedCredential,
            _: usize,
            _: usize,
        ) -> Result<Value, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(
                json!({"repository_selection":"selected","total_count":1,"repositories":[{"full_name":"org/repo"}]}),
            )
        }
    }
    struct Claim(AtomicBool);
    impl crate::connector_home::RolePeer for Claim {
        fn call(&self, _: &str, _: Value) -> Result<Value, subc_protocol::ErrorBody> {
            Ok(
                json!({"role":crate::connector_home::ROLE,"epoch":1,"known":true,"held_here":self.0.load(Ordering::SeqCst),"stale":false,"holder":null,"holder_name":null,"source":null}),
            )
        }
    }
    async fn until(predicate: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !predicate() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_gates_watch_and_discovery_with_the_vault_disabled() {
        let store = Arc::new(crate::test_support::open_memory_store("manifest-worker"));
        store
            .put_github_handle(&plexus_core::storage::github_store::GithubHandle {
                app_handle_id: "test-app".into(),
                agent_id: "test-agent".into(),
                app_id: 7,
                installation_id: None,
                credential_reference: "github_app:test-app".into(),
                credential_generation: 1,
                status: "enabled".into(),
                proven_at: None,
                connection_principal: "direct".into(),
                connection_id: "test-connection".into(),
            })
            .unwrap();
        let mut runtime = crate::runtime_for_test(store);
        let peer = Arc::new(Vault {
            watches: Mutex::new(vec![]),
        });
        let reader = Arc::new(Reader(AtomicUsize::new(0)));
        let claim = Arc::new(Claim(AtomicBool::new(false)));
        runtime.vault_peer = Some(peer.clone());
        runtime.github_control_reader = Some(reader.clone());
        runtime.github_handle_credentials =
            Some(crate::consent_test_support::anonymous_handle_credentials());
        runtime.engine = runtime
            .engine
            .with_consent_cards(crate::consent_test_support::pending_cards());
        runtime.connector_home = Arc::new(crate::connector_home::ConnectorHome::new(claim.clone()));
        let state = Arc::new(ModuleState {
            health: Arc::new(crate::health::HealthState::new()),
            runtime,
        });
        let (stop, receiver) = mpsc::channel(1);
        let task = spawn_every(state.clone(), receiver, Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(reader.0.load(Ordering::SeqCst), 0);
        assert!(peer.watches.lock().unwrap().is_empty());
        claim.0.store(true, Ordering::SeqCst);
        state.runtime.connector_home.refresh().unwrap();
        until(|| reader.0.load(Ordering::SeqCst) == 1 && !peer.watches.lock().unwrap().is_empty())
            .await;
        let sender = peer.watches.lock().unwrap()[0].clone();
        sender.send(json!({"kind":"changed","epoch":"abc","seq":1,"version":null,"manifest_sha256":null})).await.unwrap();
        claim.0.store(false, Ordering::SeqCst);
        state.runtime.connector_home.refresh().unwrap();
        until(|| sender.is_closed()).await;
        assert_eq!(reader.0.load(Ordering::SeqCst), 1);
        assert!(state.store().github_manifest_bindings().unwrap().is_empty());
        stop.send(()).await.unwrap();
        task.await.unwrap();
    }
}
