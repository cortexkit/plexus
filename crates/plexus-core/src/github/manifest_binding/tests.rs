use super::*;
use crate::credentials::{CkcredRouteError, ResolvedCredential};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use std::{
    cell::Cell,
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

const AGENT: &str = "agent_4444444444444444";
const REPO: &str = "octo-owner/new-repo";
const SLUG: &str = "plex-alfonso";
const NOW: i64 = 1_794_355_300_123;
const VECTORS: &str = include_str!("../../../tests/fixtures/manifest-binding-v1.json");

fn sample(name: &str) -> Value {
    serde_json::from_str::<Value>(VECTORS).unwrap()["samples"][name].clone()
}

#[test]
fn producer_samples_pin_every_decoder_and_refusal_remedy() {
    use sha2::{Digest, Sha256};
    assert_eq!(
        hex::encode(Sha256::digest(VECTORS)),
        "8c070db5272be78e6682714a53628453e5bf7fda5a43431d4e73b4d663218433"
    );
    let samples = serde_json::from_str::<Value>(VECTORS).unwrap()["samples"]
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(samples.len(), 45);
    let expected: BTreeMap<_, _> = [
        ("already_bound", Remedy::Retry),
        ("approval_invalid", Remedy::Stop),
        ("bound_to_other_agent", Remedy::TerminalRepository),
        ("expired", Remedy::TerminalRepository),
        ("github_unavailable", Remedy::Retry),
        ("home_unavailable", Remedy::Retry),
        ("identity_mismatch", Remedy::Stop),
        ("identity_unavailable", Remedy::Retry),
        ("installation_all", Remedy::TerminalRepository),
        ("installation_too_large", Remedy::Stop),
        ("installation_unusable", Remedy::Stop),
        ("invalid_params", Remedy::Stop),
        ("manifest_setup_incomplete", Remedy::Stop),
        ("not_found", Remedy::Stop),
        ("not_installed", Remedy::TerminalRepository),
        ("not_reproducible", Remedy::Stop),
        ("one_tap_disabled", Remedy::Retry),
        ("pairing_unavailable", Remedy::Retry),
        ("phone_not_registered", Remedy::Stop),
        ("remote_setup_incomplete", Remedy::Stop),
        ("secret_home_elsewhere", Remedy::Stop),
        ("secret_setup_incomplete", Remedy::Stop),
        ("stale_base", Remedy::Retry),
        ("store_error", Remedy::Retry),
        ("superseded", Remedy::Retry),
        ("unknown_version", Remedy::Retry),
    ]
    .into_iter()
    .collect();
    let mut seen = BTreeSet::new();
    for (name, value) in samples {
        match name.as_str() {
            name if name.starts_with("refusal.") => {
                let error = wire::response::<Proposal>(value).unwrap_err();
                assert_eq!(error.remedy(), expected[error.code()], "{name}");
                seen.insert(error.code().to_string());
                if error.code() == "already_bound" {
                    let Failure::Domain(refusal) = error else {
                        panic!()
                    };
                    assert_eq!(refusal.version, Some(30));
                    assert!(wire::valid_hash(
                        refusal.manifest_sha256.as_deref().unwrap()
                    ));
                }
            }
            "propose.reply" => {
                let reply: Proposal = wire::response(value).unwrap();
                let statement = reply.statement(AGENT, SLUG, REPO).unwrap();
                assert_eq!(
                    serde_json::from_value::<wire::Statement>(
                        sample("statement")["statement"].clone()
                    )
                    .unwrap(),
                    statement
                );
                assert_eq!(statement.repo, "Octo-Owner/New-Repo");
            }
            "statement" => {
                let proposal: Proposal = wire::response(sample("propose.reply")).unwrap();
                assert_eq!(proposal.statement_b64url, value["statement_b64url"]);
                assert_eq!(
                    proposal
                        .statement(AGENT, SLUG, REPO)
                        .unwrap()
                        .installation_permissions
                        .len(),
                    4
                );
            }
            "watch.empty" | "watch.stored" => {
                wire::Notice::decode(value).unwrap();
            }
            "active_status.ready" | "active_status.not_ready" => {
                let reply: ActiveStatus = wire::response(value).unwrap();
                let hash = sample("propose.reply")["result"]["manifest_sha256"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                assert_eq!(reply.ready_for(29, &hash), name == "active_status.ready");
            }
            "cross.manifest_to_secret" | "cross.secret_to_manifest" => {
                assert_eq!(
                    wire::response::<Value>(value["reply"].clone())
                        .unwrap_err()
                        .remedy(),
                    Remedy::Stop
                );
                assert!(value["request"]["params"]["envelope_b64url"].is_string());
            }
            "envelope" => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(value["envelope_b64url"].as_str().unwrap())
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap(),
                    value["envelope"]
                );
                assert_eq!(String::from_utf8(bytes).unwrap(), value["envelope_utf8"]);
            }
            "propose.request" => {
                assert_eq!(
                    value,
                    json!({"method":"manifest.propose_binding","params":{"agent_id":AGENT,"app_id":4617236,"app_slug":SLUG,"repo":REPO}})
                );
            }
            // These operations belong to the agent runtime or the phone, not Plexus. Decode
            // their producer shapes only in tests; never add a sender here.
            "approve.reply" | "approve.resend" => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Approved {
                    status: String,
                    proposal_id: String,
                    version: i64,
                    manifest_sha256: String,
                }
                let reply: Approved = wire::response(value).unwrap();
                assert_eq!(reply.status, "approved");
                assert_eq!(reply.version, 29);
                assert_eq!(
                    reply.proposal_id,
                    sample("propose.reply")["result"]["proposal_id"]
                );
                assert!(wire::valid_hash(&reply.manifest_sha256));
            }
            "latest.reply" => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Envelope {
                    key_id: String,
                    manifest_bytes: String,
                    signature: String,
                }
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Latest {
                    version: i64,
                    envelope: Envelope,
                }
                let reply: Latest = wire::response(value).unwrap();
                assert_eq!(reply.version, 29);
                assert_eq!(reply.envelope.key_id.len(), 16);
                assert!(
                    serde_json::from_str::<Value>(&reply.envelope.manifest_bytes).unwrap()
                        ["bindings"]["Octo-Owner/New-Repo"]
                        == AGENT
                );
                assert!(!reply.envelope.signature.is_empty());
            }
            "report.reply" => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Reported {
                    status: String,
                    member_id: String,
                    version: i64,
                }
                let reply: Reported = wire::response(value).unwrap();
                assert_eq!(reply.status, "recorded");
                assert_eq!(reply.version, 29);
                assert!(reply.member_id.starts_with("fed-computer:"));
            }
            "approve.request" => {
                assert_eq!(value["method"], "manifest.approve");
                assert_eq!(
                    value["params"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec!["envelope_b64url", "signature_b64url"]
                );
            }
            "report.request" => {
                assert_eq!(value["method"], "manifest.report_active");
                assert_eq!(value["params"]["version"], 29);
                assert_eq!(value["params"]["verdict"], "valid");
                assert!(value["params"]["reason"].is_null());
            }
            _ => panic!("uncovered producer sample {name}"),
        }
    }
    assert_eq!(seen, expected.keys().map(|s| s.to_string()).collect());
}

#[test]
fn unknown_or_malformed_commitments_fail_closed() {
    let proposal: Proposal = wire::response(sample("propose.reply")).unwrap();
    assert!(proposal.statement("other", SLUG, REPO).is_err());
    assert!(proposal.statement(AGENT, "other", REPO).is_err());
    assert!(proposal.statement(AGENT, SLUG, "org/other").is_err());
    let mut invalid = proposal.clone();
    invalid.manifest_sha256 = "0".repeat(64);
    assert!(invalid.statement(AGENT, SLUG, REPO).is_err());
    invalid = proposal.clone();
    invalid.statement_b64url.push('=');
    assert!(invalid.statement(AGENT, SLUG, REPO).is_err());
    invalid = proposal;
    invalid.expires_at_ms += 1;
    assert!(invalid.statement(AGENT, SLUG, REPO).is_err());
    let mut ready: ActiveStatus = wire::response(sample("active_status.ready")).unwrap();
    let hash = ready.manifest_sha256.clone();
    ready.computers[0].payload_sha256 = Some("0".repeat(64));
    assert!(!ready.ready_for(29, &hash));
    ready.computers.clear();
    assert!(!ready.ready_for(29, &hash));
    assert!(!ready.ready_for(30, &hash));
    let error = wire::response::<Value>(
        json!({"result":{"error":{"class":"transient","code":"new_code"}}}),
    )
    .unwrap_err();
    assert_eq!(error.remedy(), Remedy::Stop);
    for code in [
        "unknown_method",
        "invalid_params",
        "invalid_request",
        "flow_scopes_unsupported",
        "invalid_control_body",
        "unknown_module",
    ] {
        assert_eq!(wire::transport_remedy(code), Remedy::Stop);
    }
    assert_eq!(wire::transport_remedy("route_closed"), Remedy::Retry);
    assert!(wire::Notice::decode(
        json!({"kind":"changed","epoch":"x","seq":1,"version":29,"manifest_sha256":null})
    )
    .is_err());
}

struct Vault {
    calls: Mutex<Vec<(String, Value)>>,
    reply: Mutex<Value>,
    status: Mutex<Value>,
}
impl Vault {
    fn new() -> Self {
        Self {
            calls: Mutex::new(vec![]),
            reply: Mutex::new(sample("propose.reply")),
            status: Mutex::new(sample("active_status.not_ready")),
        }
    }
    fn proposals(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "manifest.propose_binding")
            .count()
    }
}
impl CkcredRoutePeer for Vault {
    fn call(&self, method: &str, params: Value) -> Result<Value, CkcredRouteError> {
        self.calls.lock().unwrap().push((method.into(), params));
        Ok(if method == "manifest.propose_binding" {
            self.reply.lock().unwrap().clone()
        } else {
            assert_eq!(method, "manifest.active_status");
            self.status.lock().unwrap().clone()
        })
    }
}

struct Cards {
    available: Cell<bool>,
    state: Cell<CardState>,
    filed: Cell<usize>,
    attempts: Cell<usize>,
    lose_reply: Cell<bool>,
    conflict: Cell<bool>,
}
impl Cards {
    fn new() -> Self {
        Self {
            available: Cell::new(true),
            state: Cell::new(CardState::Pending),
            filed: Cell::new(0),
            attempts: Cell::new(0),
            lose_reply: Cell::new(false),
            conflict: Cell::new(false),
        }
    }
}
impl BindingCards for Cards {
    fn manifest_binding_card(&self, request: CardRequest<'_>) -> Result<CardReply, String> {
        if !self.available.get() {
            return Ok(CardReply::KindNotAvailable);
        }
        Ok(match request {
            CardRequest::Available => CardReply::Available,
            CardRequest::File { handle, proposal } => {
                assert_eq!(handle.app_id, 4617236);
                assert_eq!(
                    proposal.statement_b64url,
                    sample("propose.reply")["result"]["statement_b64url"]
                );
                self.attempts.set(self.attempts.get() + 1);
                if self.conflict.get() {
                    return Ok(CardReply::Conflict);
                }
                self.filed.set(1);
                if self.lose_reply.replace(false) {
                    return Err("lost_reply".into());
                }
                CardReply::Filed("card-1".into())
            }
            CardRequest::Get { card_id, .. } | CardRequest::Await { card_id, .. } => {
                assert_eq!(card_id, "card-1");
                CardReply::State(self.state.get())
            }
        })
    }
}

struct Credentials {
    calls: AtomicUsize,
}
impl HandleCredentialProvider for Credentials {
    fn prepare(
        &self,
        id: &str,
        generation: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        assert_eq!(reference, format!("github_app:{id}"));
        assert_eq!(generation, 1);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ResolvedCredential::new(
            b"installation-token".to_vec(),
            None,
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}
struct Reader {
    calls: Cell<usize>,
    pages: std::cell::RefCell<Vec<Value>>,
    drop_home: std::cell::RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}
impl Reader {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
            pages: std::cell::RefCell::new(vec![listing(&[REPO])]),
            drop_home: Default::default(),
        }
    }
}
impl InstallationReader for Reader {
    fn repositories_page(
        &self,
        token: &ResolvedCredential,
        page: usize,
        per_page: usize,
    ) -> Result<Value, String> {
        assert_eq!(token.payload(), b"installation-token");
        assert_eq!(per_page, 100);
        self.calls.set(self.calls.get() + 1);
        if let Some(home) = self.drop_home.borrow().as_ref() {
            home.store(false, Ordering::SeqCst);
        }
        self.pages
            .borrow()
            .get(page - 1)
            .cloned()
            .ok_or("unexpected_page".into())
    }
}
fn listing(repos: &[&str]) -> Value {
    json!({"repository_selection":"selected","total_count":repos.len(),"repositories":repos.iter().map(|name|json!({"full_name":name})).collect::<Vec<_>>()})
}
fn handle() -> GithubHandle {
    GithubHandle {
        app_handle_id: SLUG.into(),
        agent_id: AGENT.into(),
        app_id: 4617236,
        installation_id: Some(1),
        credential_reference: format!("github_app:{SLUG}"),
        credential_generation: 1,
        status: "enabled".into(),
        proven_at: None,
        connection_principal: "direct".into(),
        connection_id: "handle-connection".into(),
    }
}
fn store() -> PlexusStore {
    let store = PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: crate::storage::new_id("manifest-binding"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    })
    .unwrap();
    store
        .insert_connection(
            "direct",
            "handle-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    store.put_github_handle(&handle()).unwrap();
    store
}
struct Fixture {
    store: PlexusStore,
    vault: Vault,
    cards: Cards,
    credentials: Credentials,
    reader: Reader,
    held: std::sync::Arc<std::sync::atomic::AtomicBool>,
    gate: Box<dyn Fn() -> bool>,
    progress: Progress,
}
impl Fixture {
    fn new() -> Self {
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let gate = held.clone();
        Self {
            store: store(),
            vault: Vault::new(),
            cards: Cards::new(),
            credentials: Credentials {
                calls: AtomicUsize::new(0),
            },
            reader: Reader::new(),
            held,
            gate: Box::new(move || gate.load(Ordering::SeqCst)),
            progress: Progress::default(),
        }
    }
    fn pass(&mut self) -> ApprovalPass<'_> {
        ApprovalPass {
            store: &self.store,
            vault: &self.vault,
            cards: &self.cards,
            credentials: &self.credentials,
            reader: &self.reader,
            held: self.gate.as_ref(),
            progress: &mut self.progress,
        }
    }
    fn discover(&mut self) {
        self.pass().discover(NOW).unwrap();
    }
    fn record(&self) -> BindingRecord {
        self.store
            .github_manifest_bindings()
            .unwrap()
            .pop()
            .unwrap()
    }
    fn bound(&self) -> bool {
        self.store
            .github_manifest_repository_handle(REPO)
            .unwrap()
            .is_some()
    }
    fn notice(&mut self) {
        self.pass().notice(sample("watch.stored"), NOW).unwrap();
    }
}

#[test]
fn unavailable_card_kind_sends_no_propose_request() {
    let mut f = Fixture::new();
    f.cards.available.set(false);
    f.discover();
    f.discover();
    assert_eq!(f.reader.calls.get(), 2);
    assert_eq!(f.vault.proposals(), 0);
    assert_eq!(f.cards.filed.get(), 0);
    assert!(!f.bound());
    assert!(f.store.list_audit("reserved:plexus").unwrap().is_empty());
    assert!(f.store.github_manifest_bindings().unwrap().is_empty());
}

#[test]
fn connector_home_fences_every_effect_and_disabled_is_dormant() {
    let mut f = Fixture::new();
    f.held.store(false, Ordering::SeqCst);
    f.discover();
    f.notice();
    f.pass().follow_ready(NOW).unwrap();
    assert_eq!(f.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.reader.calls.get(), 0);
    assert!(f.vault.calls.lock().unwrap().is_empty());
    assert!(f.store.github_manifest_bindings().unwrap().is_empty());
    f.held.store(true, Ordering::SeqCst);
    *f.vault.reply.lock().unwrap() = sample("refusal.one_tap_disabled");
    f.discover();
    f.discover();
    assert_eq!(f.vault.proposals(), 2);
    assert_eq!(f.cards.filed.get(), 0);
    assert!(!f.bound());
    assert_eq!(f.progress.disabled_logged_at, Some(NOW));
    assert!(f.store.github_manifest_bindings().unwrap().is_empty());
    assert!(!f.progress.stopped);
    assert!(f.store.list_audit("reserved:plexus").unwrap().is_empty());
    f.pass().discover(NOW + 3_600_000).unwrap();
    assert_eq!(f.progress.disabled_logged_at, Some(NOW + 3_600_000));
}

#[test]
fn card_survives_restart_and_a_lost_file_reply_is_deduplicated() {
    let mut f = Fixture::new();
    f.cards.lose_reply.set(true);
    assert!(f.pass().discover(NOW).is_err());
    assert_eq!(f.record().state, "pending");
    assert!(f.record().card_id.is_none());
    f.progress = Progress::default();
    f.discover();
    assert_eq!(f.cards.filed.get(), 1);
    assert_eq!(f.cards.attempts.get(), 2);
    assert_eq!(f.record().card_id.as_deref(), Some("card-1"));
    f.progress = Progress::default();
    f.discover();
    assert_eq!(f.cards.attempts.get(), 2);
    let audit = f.store.list_audit("reserved:plexus").unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|a| a.reason_code == "github_manifest_proposed")
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|a| a.reason_code == "github_manifest_card_filed")
            .count(),
        1
    );
    assert!(audit
        .iter()
        .all(|a| a.agent_id.as_deref() == Some(AGENT) && a.app_handle_id.as_deref() == Some(SLUG)));
}

#[test]
fn matching_notice_waits_for_every_computer_and_binds_without_grants() {
    let mut f = Fixture::new();
    f.discover();
    assert_eq!(
        f.vault.calls.lock().unwrap()[0],
        (
            "manifest.propose_binding".into(),
            sample("propose.request")["params"].clone()
        )
    );
    let mut wrong = sample("watch.stored");
    wrong["manifest_sha256"] = json!("0".repeat(64));
    f.pass().notice(wrong, NOW).unwrap();
    assert_eq!(f.record().state, "pending");
    f.notice();
    assert_eq!(f.record().state, "awaiting_active");
    assert!(!f.bound());
    *f.vault.status.lock().unwrap() = sample("refusal.unknown_version");
    f.pass().follow_ready(NOW).unwrap();
    assert!(!f.bound());
    assert!(!f.progress.stopped);
    *f.vault.status.lock().unwrap() = sample("active_status.ready");
    f.pass().follow_ready(NOW).unwrap();
    assert!(f.bound());
    assert_eq!(f.record().state, "bound");
    let audit = f.store.list_audit("reserved:plexus").unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|a| a.reason_code == "github_manifest_bound")
            .count(),
        1
    );
    assert_eq!(
        f.store.read_github_bindings().unwrap()["repo_binding_generation"],
        1
    );
    assert!(f
        .store
        .list_grants("direct", "handle-connection")
        .unwrap()
        .is_empty());
    f.discover();
    f.notice();
    assert_eq!(f.vault.proposals(), 1);
}

#[test]
fn missed_notice_converges_via_already_bound_without_a_second_card() {
    let mut f = Fixture::new();
    f.discover();
    let mut already = sample("refusal.already_bound");
    already["result"]["error"]["version"] = json!(29);
    already["result"]["error"]["manifest_sha256"] =
        sample("propose.reply")["result"]["manifest_sha256"].clone();
    *f.vault.reply.lock().unwrap() = already;
    *f.vault.status.lock().unwrap() = sample("active_status.ready");
    f.progress = Progress::default();
    f.discover();
    assert!(f.bound());
    assert_eq!(f.cards.attempts.get(), 1);
}

#[test]
fn decline_and_expiry_require_observed_removal_then_readdition() {
    for (answer, state, event) in [
        (CardState::Declined, "declined", "github_manifest_declined"),
        (CardState::Expired, "expired", "github_manifest_expired"),
    ] {
        let mut f = Fixture::new();
        f.discover();
        f.cards.state.set(answer);
        f.discover();
        assert_eq!(f.record().state, state);
        f.discover();
        f.notice();
        assert_eq!(f.vault.proposals(), 1);
        assert!(!f.bound());
        assert_eq!(
            f.store
                .list_audit("reserved:plexus")
                .unwrap()
                .iter()
                .filter(|a| a.reason_code == event)
                .count(),
            1
        );
        // An incomplete listing is not evidence that the repository left.
        *f.reader.pages.borrow_mut() =
            vec![json!({"repository_selection":"selected","total_count":1,"repositories":[]})];
        f.discover();
        assert!(f.record().present);
        *f.reader.pages.borrow_mut() = vec![listing(&[])];
        f.discover();
        assert!(!f.record().present);
        *f.reader.pages.borrow_mut() = vec![listing(&[REPO])];
        f.cards.state.set(CardState::Pending);
        f.discover();
        assert_eq!(f.vault.proposals(), 2);
        assert_eq!(f.record().state, "pending");
    }
}

#[test]
fn skips_all_selection_existing_bindings_and_disabled_handles() {
    let mut f = Fixture::new();
    f.reader.pages.borrow_mut()[0]["repository_selection"] = json!("all");
    f.discover();
    assert_eq!(f.vault.proposals(), 0);
    assert!(f.store.github_manifest_bindings().unwrap().is_empty());
    assert_eq!(f.reader.calls.get(), 1);
    *f.reader.pages.borrow_mut() = vec![listing(&[REPO])];
    f.store.bind_github_repo(REPO, SLUG).unwrap();
    f.discover();
    assert_eq!(f.vault.proposals(), 0);
    let mut disabled = handle();
    disabled.status = "disabled".into();
    f.store.put_github_handle(&disabled).unwrap();
    let before = f.reader.calls.get();
    f.discover();
    assert_eq!(f.reader.calls.get(), before);
    let mut other = Fixture::new();
    let mut h = handle();
    h.app_handle_id = "other".into();
    h.agent_id = "other-agent".into();
    h.credential_reference = "github_app:other".into();
    h.connection_id = "other-connection".into();
    h.status = "disabled".into();
    other.store.put_github_handle(&h).unwrap();
    other
        .store
        .insert_connection(
            "direct",
            "other-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    other.store.bind_github_repo(REPO, "other").unwrap();
    other.discover();
    other.discover();
    assert_eq!(other.vault.proposals(), 0);
    assert!(other.store.github_manifest_bindings().unwrap().is_empty());
}

#[test]
fn every_page_spends_read_budget_and_budget_exhaustion_prevents_a_read() {
    let mut f = Fixture::new();
    f.cards.available.set(false);
    let mut first = listing(&["octo-owner/one"]);
    first["total_count"] = json!(2);
    let mut second = listing(&[REPO]);
    second["total_count"] = json!(2);
    *f.reader.pages.borrow_mut() = vec![first, second];
    f.discover();
    assert_eq!(f.reader.calls.get(), 2);
    // Reserve the rest of the 3,500-request hourly allowance. The discovery
    // pages already spent two units; one more must now be refused.
    for _ in 0..218 {
        f.store.reserve_github_bot_read(SLUG, 16, NOW).unwrap();
    }
    f.store.reserve_github_bot_read(SLUG, 10, NOW).unwrap();
    f.discover();
    assert_eq!(f.reader.calls.get(), 2);
    assert_eq!(f.vault.proposals(), 0);
}

#[test]
fn bind_rechecks_installation_and_transaction_rolls_back_on_stale_progress() {
    let mut f = Fixture::new();
    f.discover();
    f.notice();
    *f.vault.status.lock().unwrap() = sample("active_status.ready");
    *f.reader.pages.borrow_mut() = vec![listing(&[])];
    assert!(f.pass().follow_ready(NOW).is_err());
    assert!(!f.bound());
    let stale = f.record();
    f.store
        .observe_github_manifest_installation(&handle(), &[])
        .unwrap();
    f.store
        .observe_github_manifest_installation(&handle(), &[REPO.into()])
        .unwrap();
    assert!(f
        .store
        .bind_github_manifest_repository(&stale, vec![REPO.into()])
        .is_err());
    assert!(!f.bound());
    assert!(!f
        .store
        .list_audit("reserved:plexus")
        .unwrap()
        .iter()
        .any(|a| a.reason_code == "github_manifest_bound"));
}

#[test]
fn process_restart_reopens_the_saved_proposal_without_refiling_its_card() {
    let scratch = crate::test_scratch::Scratch::database("manifest-restart");
    let descriptor = StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: crate::storage::new_id("manifest-restart"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: scratch.path().to_string_lossy().into_owned(),
        },
    };
    let mut f = Fixture::new();
    f.store = PlexusStore::open(&descriptor).unwrap();
    f.store
        .insert_connection(
            "direct",
            "handle-connection",
            "github_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    f.store.put_github_handle(&handle()).unwrap();
    f.discover();
    let before = f.record();
    drop(std::mem::replace(&mut f.store, store()));
    f.store = PlexusStore::open(&descriptor).unwrap();
    f.progress = Progress::default();
    assert_eq!(f.record(), before);
    f.discover();
    assert_eq!(f.cards.attempts.get(), 1);
    assert_eq!(f.record().proposal_id, before.proposal_id);
}

#[test]
fn claim_loss_during_listing_prevents_proposal_and_local_progress() {
    let mut f = Fixture::new();
    *f.reader.drop_home.borrow_mut() = Some(f.held.clone());
    f.discover();
    assert_eq!(f.reader.calls.get(), 1);
    assert_eq!(f.vault.proposals(), 0);
    assert!(f.store.github_manifest_bindings().unwrap().is_empty());
}

#[test]
fn supersession_reproposes_on_next_pass_but_bad_identity_stops() {
    let mut f = Fixture::new();
    *f.vault.reply.lock().unwrap() = sample("refusal.superseded");
    f.discover();
    assert_eq!(f.cards.filed.get(), 0);
    assert!(!f.progress.stopped());
    *f.vault.reply.lock().unwrap() = sample("propose.reply");
    f.discover();
    assert_eq!(f.cards.filed.get(), 1);
    *f.vault.reply.lock().unwrap() = sample("refusal.identity_mismatch");
    f.discover();
    assert!(f.progress.stopped());
    let before = f.reader.calls.get();
    f.discover();
    assert_eq!(f.reader.calls.get(), before);
}

#[test]
fn a_cross_session_card_conflict_is_durable_and_only_the_watch_advances_it() {
    let mut f = Fixture::new();
    f.cards.conflict.set(true);
    f.discover();
    assert_eq!(f.record().state, "card_conflict");
    assert_eq!(f.cards.attempts.get(), 1);
    f.progress = Progress::default();
    f.discover();
    assert_eq!(f.cards.attempts.get(), 1);
    assert_eq!(f.vault.proposals(), 1);
    *f.vault.status.lock().unwrap() = sample("active_status.ready");
    f.notice();
    assert!(f.bound());
    assert_eq!(f.cards.filed.get(), 0);
}

#[test]
fn real_card_adapter_samples_feed_the_discovery_and_activation_sequence() {
    use crate::consent_card::{ConsentCards, ElicitationCallError, ElicitationRoute};
    struct Route {
        outcome: &'static str,
    }
    impl ElicitationRoute for Route {
        fn call_scoped(
            &self,
            _: &crate::scope::CallScope,
            _: &str,
            _: Value,
            _: std::time::Duration,
        ) -> Result<Value, ElicitationCallError> {
            panic!("unexpected scoped card")
        }
        fn call_unscoped(
            &self,
            method: &str,
            _: Value,
            _: std::time::Duration,
        ) -> Result<Value, ElicitationCallError> {
            if method == "consent.request" {
                return Ok(json!({"elicitation_id":"el_1"}));
            }
            let op = if method == "consent.get" {
                "get"
            } else {
                assert_eq!(method, "consent.await");
                "await"
            };
            let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../plexus-module/tests/fixtures/cingulate-consent-requester/vectors/manifest-binding-v1/filer-{op}-{}.json",self.outcome));
            Ok(
                serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()["reply"]
                    ["result"]
                    .clone(),
            )
        }
    }
    for outcome in ["allowed", "declined", "expired"] {
        let mut f = Fixture::new();
        let cards = ConsentCards::new(std::sync::Arc::new(Route { outcome }));
        {
            let mut pass = f.pass();
            pass.cards = &cards;
            pass.discover(NOW).unwrap();
        }
        assert_eq!(f.record().card_id.as_deref(), Some("el_1"));
        assert!(!f.bound());
        {
            let mut pass = f.pass();
            pass.cards = &cards;
            pass.notice(sample("watch.stored"), NOW).unwrap();
        }
        assert!(!f.bound());
        *f.vault.status.lock().unwrap() = sample("active_status.ready");
        {
            let mut pass = f.pass();
            pass.cards = &cards;
            pass.follow_ready(NOW).unwrap();
        }
        assert_eq!(f.bound(), outcome == "allowed");
        if outcome != "allowed" {
            assert_eq!(
                f.record().state,
                if outcome == "declined" {
                    "declined"
                } else {
                    "expired"
                }
            );
        }
    }
}
