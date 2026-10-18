use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use plexus_core::credentials::{CkcredCredentialSource, CkcredRouteError, CkcredRoutePeer};
use plexus_core::github::credential::HandleCredentialPreparer;
use serde_json::{json, Value};

/// A reply in the vault's real `credential.get_scoped` shape: the same body as
/// `credential.get`, with the token as a JSON array of byte integers, plus the
/// `credential_id` the vault actually resolved (claustrum read_surface.rs and
/// wire-contract-v1 §3). The token is deliberately neither `ghs_`-prefixed nor
/// 40 characters: a vault can serve a much longer, multi-segment token, and
/// plexus must treat the bytes as opaque.
fn vault_reply(credential_id: &str, token: &str) -> Value {
    json!({"result": {
        "payload": token.as_bytes(),
        "expires_at_ms": 3_600_000,
        "record_version": 767,
        "credential_id": credential_id,
    }})
}

fn first_token() -> String {
    ["eyJhbGciOiJSUzI1NiJ9", "first-installation", "c2lnbmF0dXJl"].join(".")
}

#[derive(Default)]
struct Peer {
    calls: Mutex<Vec<(String, Value)>>,
    response: Mutex<Option<Value>>,
    changed: Condvar,
}

impl Peer {
    fn wait_for_401_report(&self) {
        let calls = self.calls.lock().unwrap();
        let has_401 = |calls: &Vec<(String, Value)>| {
            calls.iter().any(|(operation, params)| {
                operation == "credential.report_auth_failure" && params["provider_status"] == 401
            })
        };
        let (calls, _) = self
            .changed
            .wait_timeout_while(calls, std::time::Duration::from_secs(5), |calls| {
                !has_401(calls)
            })
            .unwrap();
        assert!(
            has_401(&calls),
            "known 401 report must reach the vault peer"
        );
    }
}

impl CkcredRoutePeer for Peer {
    fn call(&self, operation: &str, params: Value) -> Result<Value, CkcredRouteError> {
        self.calls.lock().unwrap().push((operation.into(), params));
        self.changed.notify_all();
        Ok(self
            .response
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| vault_reply("github_app:one", &first_token())))
    }
}

fn setup() -> (Arc<Peer>, HandleCredentialPreparer<Peer>, Arc<AtomicI64>) {
    let peer = Arc::new(Peer::default());
    let now = Arc::new(AtomicI64::new(0));
    let clock = Arc::clone(&now);
    let preparer = HandleCredentialPreparer::new(
        CkcredCredentialSource::new(Arc::clone(&peer)),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (peer, preparer, now)
}

#[test]
fn cold_cache_scoped_read_once_and_expiry_margin() {
    let (peer, preparer, now) = setup();
    assert_eq!(
        preparer
            .prepare("handle", 1, "github_app:one")
            .unwrap()
            .payload(),
        first_token().as_bytes()
    );
    assert_eq!(
        preparer
            .prepare("handle", 1, "github_app:one")
            .unwrap()
            .payload(),
        first_token().as_bytes()
    );
    assert_eq!(
        peer.calls.lock().unwrap().as_slice(),
        &[(
            "credential.get_scoped".into(),
            json!({"credential_id":"github_app:one"})
        )]
    );
    now.store(3_540_000, Ordering::SeqCst);
    // A refresh can serve a new token on the next read, so the nonce stays usable.
    assert_eq!(
        preparer.prepare("handle", 1, "github_app:one"),
        Err("handle_credential_unresolvable{class: transient}")
    );
    assert_eq!(peer.calls.lock().unwrap().len(), 2);
    assert_eq!(
        preparer.prepare("handle", 1, "not-a-github-app-reference"),
        Err("handle_credential_unresolvable{class: permanent}")
    );
    assert_eq!(peer.calls.lock().unwrap().len(), 2);
}

#[test]
fn old_generation_reads_do_not_evict_current_cached_token() {
    let (peer, preparer, _) = setup();
    preparer.prepare("handle", 3, "github_app:one").unwrap();
    preparer.prepare("handle", 0, "github_app:one").unwrap();
    preparer.prepare("handle", 3, "github_app:one").unwrap();
    assert_eq!(peer.calls.lock().unwrap().len(), 2);
}

#[test]
fn resolved_id_mismatch_refuses_without_caching() {
    let (peer, preparer, _) = setup();
    *peer.response.lock().unwrap() =
        Some(vault_reply("github_app:other", "other.installation.token"));
    assert_eq!(
        preparer.prepare("handle", 1, "github_app:one"),
        Err("handle_credential_unresolvable{class: permanent}")
    );
    assert_eq!(
        preparer.prepare("handle", 1, "github_app:one"),
        Err("handle_credential_unresolvable{class: permanent}")
    );
    assert_eq!(peer.calls.lock().unwrap().len(), 2);
}

#[test]
fn rotation_changes_bearer_without_connection_remint() {
    let (peer, preparer, _) = setup();
    let first = preparer.prepare("handle", 1, "github_app:one").unwrap();
    *peer.response.lock().unwrap() =
        Some(vault_reply("github_app:one", "rotated.installation.token"));
    let second = preparer.prepare("handle", 2, "github_app:one").unwrap();
    assert_ne!(first.payload(), second.payload());
    assert_eq!(peer.calls.lock().unwrap().len(), 2);
}

#[test]
fn vendor_401_invalidates_and_reports_once_but_403_does_not() {
    let (peer, preparer, _) = setup();
    preparer.prepare("handle", 1, "github_app:one").unwrap();
    preparer.vendor_status("handle", 1, "github_app:one", 403);
    preparer.prepare("handle", 1, "github_app:one").unwrap();
    assert_eq!(
        peer.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == "credential.get_scoped")
            .count(),
        1
    );
    preparer.vendor_status("handle", 1, "github_app:one", 401);
    preparer.prepare("handle", 1, "github_app:one").unwrap();
    // The queue is ordered: once the known 401 is observed, any erroneous 403
    // report queued before it must also be visible to the report-count check.
    peer.wait_for_401_report();
    let calls = peer.calls.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|(name, _)| name == "credential.report_auth_failure")
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|(name, _)| name == "credential.get_scoped")
            .count(),
        2
    );
}

#[test]
fn store_backed_seam_reads_scoped_token_from_handle_row_not_caller() {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    use plexus_core::governance::GovernanceSeams;
    use plexus_core::storage::github_store::{GithubGovernanceSeams, GithubHandle};
    use plexus_core::PlexusStore;

    let scratch = plexus_core::test_scratch::Scratch::database("github-credential-seam");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: scratch.path().to_string_lossy().into_owned(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).unwrap();
    store
        .insert_connection(
            "direct",
            "handle-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store
        .put_github_handle(&GithubHandle {
            app_handle_id: "app-handle".into(),
            agent_id: "agent".into(),
            app_id: 1,
            installation_id: None,
            credential_reference: "github_app:one".into(),
            credential_generation: 1,
            status: "enabled".into(),
            proven_at: None,
            connection_principal: "direct".into(),
            connection_id: "handle-connection".into(),
        })
        .unwrap();
    let connection = store
        .connection("direct", "handle-connection")
        .unwrap()
        .unwrap();
    let (peer, preparer, _) = setup();
    let seams = GithubGovernanceSeams {
        store: &store,
        credential_provider: Some(Arc::new(preparer)),
    };
    let handle = seams.handle_row(&connection).unwrap().unwrap();
    let token = seams
        .prepare_handle_credential(&connection, &handle)
        .unwrap();
    assert_eq!(token.payload(), first_token().as_bytes());
    assert_eq!(
        peer.calls.lock().unwrap().as_slice(),
        &[(
            "credential.get_scoped".into(),
            json!({"credential_id":"github_app:one"})
        )]
    );
    let missing = GithubGovernanceSeams {
        store: &store,
        credential_provider: None,
    };
    assert!(missing
        .prepare_handle_credential(&connection, &handle)
        .is_err());
    seams.handle_auth_failure(&connection, &handle);
    peer.wait_for_401_report();
    assert_eq!(
        peer.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == "credential.report_auth_failure")
            .count(),
        1
    );
}

/// The shape the credential slice first guessed (a string `access_token`) is
/// not what the vault sends, and must not decode: accepting it would mean the
/// decoder reads a field the real wire never carries.
#[test]
fn scoped_read_decodes_the_vault_byte_array_and_refuses_an_access_token_string() {
    let (peer, preparer, _) = setup();
    assert_eq!(
        preparer
            .prepare("handle", 1, "github_app:one")
            .unwrap()
            .payload(),
        first_token().as_bytes()
    );
    *peer.response.lock().unwrap() = Some(json!({"result": {
        "credential_id": "github_app:one",
        "access_token": "ghs_invented",
        "expires_at_ms": 3_600_000
    }}));
    assert_eq!(
        preparer.prepare("handle", 2, "github_app:one"),
        Err("handle_credential_unresolvable{class: permanent}")
    );
}

#[test]
fn slow_vault_handle_does_not_block_another_handle() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    struct SlowPeer {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl CkcredRoutePeer for SlowPeer {
        fn call(&self, _: &str, params: Value) -> Result<Value, CkcredRouteError> {
            let id = params["credential_id"].as_str().unwrap();
            if id == "github_app:slow" {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            Ok(vault_reply(id, &first_token()))
        }
    }
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let preparer = Arc::new(HandleCredentialPreparer::new(
        CkcredCredentialSource::new(Arc::new(SlowPeer {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        })),
        Arc::new(|| 0),
    ));
    let slow = preparer.clone();
    let slow = std::thread::spawn(move || slow.prepare("slow", 1, "github_app:slow"));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let fast = preparer.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let start = Instant::now();
    let fast = std::thread::spawn(move || {
        done_tx
            .send(fast.prepare("fast", 1, "github_app:fast"))
            .unwrap();
    });
    let result = done_rx.recv_timeout(Duration::from_millis(500));
    let elapsed = start.elapsed();
    release_tx.send(()).unwrap();
    slow.join().unwrap().unwrap();
    fast.join().unwrap();
    println!("other-handle preparation while vault blocked: {elapsed:?}");
    assert!(
        result.is_ok(),
        "a slow vault handle must not block another handle"
    );
    result.unwrap().unwrap();
}
