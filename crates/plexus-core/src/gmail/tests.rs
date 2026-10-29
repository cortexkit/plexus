use super::*;
use crate::{
    credentials::{
        CkcredRouteError, CkcredRoutePeer, ResolvedCredential, ScopedCredential,
        TransientCredentialError,
    },
    rest_api::{RestConfig, RestTransport},
    test_scratch::Scratch,
};
use hpke::{Deserializable, Kem, Serializable};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use vault::{Sealed, VaultError};

const SUBJECT: &str = "hello";
fn args() -> Value {
    json!({"to":["alice@example.com"],"cc":[],"bcc":[],"subject":SUBJECT,"body":"hello\nworld"})
}
fn request(id: &str, args: Value) -> TransportRequest {
    TransportRequest {
        request_id: id.into(),
        connection_id: "mail".into(),
        action: "gmail.send".into(),
        args,
        credential_fingerprint: String::new(),
    }
}
fn document() -> crate::manifest::IngestedManifest {
    crate::manifest::ingest_value(
        serde_json::from_str(
            &subc_jsonc::jsonc_to_json(include_str!("../../../../catalog/gmail.jsonc")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}
fn manifest() -> crate::AppManifest {
    document().manifest
}
fn fake_gmail(status: u16) -> (RestTransport, crate::test_http::FixedRequestServer) {
    let (url, server) = crate::test_http::FixedRequestServer::start(
        1,
        "gmail-error",
        move |_, _| {
            format!("HTTP/1.1 {status} Refused\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}")
        },
    );
    let mut config = RestConfig::from_manifest(&manifest());
    config.base_url = url;
    (RestTransport::new(config), server)
}

struct FakeVault {
    read_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    account: Mutex<Option<String>>,
    error: Mutex<Option<CredentialError>>,
    reads: AtomicUsize,
    reports: Mutex<Vec<u64>>,
    sk: <hpke::kem::X25519HkdfSha256 as Kem>::PrivateKey,
    pk: [u8; 32],
}
impl FakeVault {
    fn new() -> Self {
        let (sk, pk) = hpke::kem::X25519HkdfSha256::derive_keypair(&[42; 32]);
        Self {
            read_hook: Mutex::new(None),
            account: Mutex::new(Some("owner@example.com".into())),
            error: Mutex::new(None),
            reads: AtomicUsize::new(0),
            reports: Mutex::new(Vec::new()),
            sk,
            pk: pk.to_bytes().as_slice().try_into().unwrap(),
        }
    }
}
impl GmailCredentials for FakeVault {
    fn read(&self) -> Result<ScopedCredential, CredentialError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let hook = self.read_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        if let Some(error) = self.error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(ScopedCredential {
            credential_id: "oauth:gmail".into(),
            credential: ResolvedCredential::new(b"fake-token".to_vec(), None, 17),
            account_id: self.account.lock().unwrap().clone(),
        })
    }
    fn report_401(&self, version: u64) -> Result<(), VaultError> {
        self.reports.lock().unwrap().push(version);
        Ok(())
    }
}
impl SentTextSealer for FakeVault {
    fn seal(&self, text: &[u8], aad: &[u8]) -> Result<Sealed, VaultError> {
        vault::seal_to_key(&self.pk, "fake-key", text, aad)
    }
}
impl SentTextOpener for FakeVault {
    fn open(&self, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let enc =
            <hpke::kem::X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed.enc).unwrap();
        hpke::setup_receiver::<
            hpke::aead::ChaCha20Poly1305,
            hpke::kdf::HkdfSha256,
            hpke::kem::X25519HkdfSha256,
        >(&hpke::OpModeR::Base, &self.sk, &enc, vault::INFO)
        .and_then(|mut c| c.open(&sealed.ciphertext, aad))
        .map(Zeroizing::new)
        .map_err(|_| VaultError::permanent("open_failed"))
    }
}
struct Fixture {
    _scratch: Scratch,
    store: Arc<PlexusStore>,
    vault: Arc<FakeVault>,
    backend: GmailBackend,
}
impl Fixture {
    fn new() -> Self {
        let scratch = Scratch::database("gmail");
        let store = Arc::new(
            PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "gmail".into(),
                isolation: cortexkit_store_types::Isolation::Module,
                backend: cortexkit_store_types::StorageBackend::Sqlite {
                    path: scratch.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let vault = Arc::new(FakeVault::new());
        let backend = GmailBackend::new(vault.clone(), vault.clone(), vault.clone());
        store
            .pin_gmail_mailbox("direct", "mail", "owner@example.com")
            .unwrap();
        Self {
            _scratch: scratch,
            store,
            vault,
            backend,
        }
    }
    fn send(
        &self,
        id: &str,
        args: Value,
        transport: &dyn Transport,
        now: i64,
    ) -> TransportResponse {
        self.backend
            .send(&self.store, "direct", request(id, args), transport, || now)
    }
}

#[test]
fn gmail_mime_ascii_and_non_ascii_bytes() {
    let ascii = mime::Message::parse(&args())
        .unwrap()
        .compose("owner@example.com", 1000)
        .unwrap();
    assert_eq!(ascii,b"From: owner@example.com\r\nDate: Thu, 01 Jan 1970 00:00:01 GMT\r\nTo: alice@example.com\r\nSubject: hello\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8NCndvcmxk\r\n");
    let mut a = args();
    a["subject"] = json!("Héllo ☃");
    let utf8 = mime::Message::parse(&a)
        .unwrap()
        .compose("owner@example.com", 1000)
        .unwrap();
    assert!(String::from_utf8(utf8)
        .unwrap()
        .contains("Subject: =?UTF-8?B?SMOpbGxvIOKYgw==?=\r\n"));
    a["subject"] = json!("☃".repeat(200));
    a["body"] = json!("long body ".repeat(2000));
    let bytes = mime::Message::parse(&a)
        .unwrap()
        .compose("owner@example.com", 1000)
        .unwrap();
    assert!(String::from_utf8(bytes)
        .unwrap()
        .split("\r\n")
        .all(|line| line.len() <= 998));
}

#[test]
fn gmail_header_injection_sends_nothing() {
    let f = Fixture::new();
    let t = crate::MockTransport::default();
    for field in ["subject", "to", "cc", "bcc"] {
        for line in ["\r", "\n", "\r\n"] {
            let mut a = args();
            let value = format!("alice@example.com{line}Bcc: victim@example.com");
            if field == "subject" {
                a[field] = json!(value);
            } else {
                a[field] = json!([value]);
            }
            assert_eq!(
                f.send("injection", a, &t, 1000).error_code.as_deref(),
                Some("gmail_header_injection")
            );
        }
    }
    assert!(t.requests().is_empty());
}
#[test]
fn gmail_invalid_address_sends_nothing() {
    let f = Fixture::new();
    let t = crate::MockTransport::default();
    for value in [
        "not-an-address",
        "a@@example.com",
        "Alice <a@example.com>",
        "a@example.com,b@example.com",
        "a..b@example.com",
        "a@-example.com",
        "a@example..com",
        "a@localhost",
        " a@example.com",
        "é@example.com",
    ] {
        for field in ["to", "cc", "bcc"] {
            let mut a = args();
            a[field] = json!([value]);
            assert_eq!(
                f.send("address", a, &t, 1000).error_code.as_deref(),
                Some("gmail_invalid_address"),
                "{field}: {value}"
            );
        }
    }
    assert!(t.requests().is_empty());
}
#[test]
fn gmail_account_mismatch_and_missing_id_send_nothing() {
    let f = Fixture::new();
    let t = crate::MockTransport::default();
    for account in [
        Some("other@example.com".into()),
        Some("Owner@example.com".into()),
        None,
    ] {
        *f.vault.account.lock().unwrap() = account;
        assert_eq!(
            f.send("account", args(), &t, 1000).error_code.as_deref(),
            Some("gmail_account_mismatch")
        );
    }
    assert!(t.requests().is_empty());
}
#[test]
fn gmail_401_reports_served_version_and_rereads_once() {
    let f = Fixture::new();
    let (t, server) = fake_gmail(401);
    assert_eq!(
        f.send("unauthorized", args(), &t, 1000)
            .error_code
            .as_deref(),
        Some("http_401")
    );
    assert_eq!(*f.vault.reports.lock().unwrap(), vec![17]);
    assert_eq!(f.vault.reads.load(Ordering::SeqCst), 2);
    server.join().unwrap();
}
#[test]
fn gmail_403_never_reports_or_rereads() {
    let f = Fixture::new();
    let (t, server) = fake_gmail(403);
    assert_eq!(
        f.send("forbidden", args(), &t, 1000).error_code.as_deref(),
        Some("http_403")
    );
    server.join().unwrap();
    assert!(f.vault.reports.lock().unwrap().is_empty());
    assert_eq!(f.vault.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn gmail_5xx_and_429_are_not_credential_failures() {
    let f = Fixture::new();
    for (index, status) in [500, 429].into_iter().enumerate() {
        let (t, server) = fake_gmail(status);
        let response = f.send(
            &format!("temporary-{status}"),
            args(),
            &t,
            (index as i64 + 1) * 1000,
        );
        server.join().unwrap();
        if status == 500 {
            assert_eq!(response.error_code.as_deref(), Some("http_500"));
            assert_eq!(response.retryability, Retryability::AutoRetryable);
            assert_eq!(
                response.transmission,
                crate::transport::TransmissionState::OutcomeUnknown
            );
        } else {
            assert_eq!(response.retryability, Retryability::Throttle);
        }
    }
    assert!(f.vault.reports.lock().unwrap().is_empty());
    assert_eq!(f.vault.reads.load(Ordering::SeqCst), 2);
}
#[test]
fn gmail_not_found_is_not_reauth_and_vault_failures_send_nothing() {
    let f = Fixture::new();
    let t = crate::MockTransport::default();
    for (error, code, retry) in [
        (
            CredentialError::Permanent(PermanentCredentialError::NotFound),
            "not_found",
            Retryability::Terminal,
        ),
        (
            CredentialError::AuthRequired,
            "auth_required",
            Retryability::Terminal,
        ),
        (
            CredentialError::Transient(TransientCredentialError::RefreshFailed),
            "credential_transient",
            Retryability::AutoRetryable,
        ),
    ] {
        *f.vault.error.lock().unwrap() = Some(error);
        let response = f.send("vault-error", args(), &t, 1000);
        assert_eq!(response.error_code.as_deref(), Some(code));
        assert_eq!(response.retryability, retry);
    }
    assert!(t.requests().is_empty());
    assert!(f.vault.reports.lock().unwrap().is_empty());
}

#[test]
fn gmail_accepted_wire_and_sealed_row_open_through_fake_vault() {
    let f = Fixture::new();
    let captured = Arc::new(Mutex::new(String::new()));
    let capture = captured.clone();
    let (url, server) = crate::test_http::FixedRequestServer::start(
        1,
        "gmail",
        move |_, request| {
            *capture.lock().unwrap() = request.to_owned();
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"id\":\"gmail-123\"}".into()
        },
    );
    let mut config = RestConfig::from_manifest(&manifest());
    config.base_url = url;
    let t = RestTransport::new(config);
    let response = f.send("sent-1", args(), &t, 1000);
    server.join().unwrap();
    assert_eq!(
        response.response,
        Some(json!({"status":"accepted","message_id":"gmail-123","sent_text_row_id":"sent-1"}))
    );
    let wire = captured.lock().unwrap();
    assert!(wire.starts_with("POST /gmail/v1/users/me/messages/send HTTP/1.1\r\n"));
    assert!(wire
        .to_ascii_lowercase()
        .contains("authorization: bearer fake-token\r\n"));
    let body: Value = serde_json::from_str(wire.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 1);
    let raw = body["raw"].as_str().unwrap();
    assert!(!raw.contains(['+', '/', '=']));
    let expected = mime::Message::parse(&args())
        .unwrap()
        .compose("owner@example.com", 1000)
        .unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(raw).unwrap(), expected);
    let opened = f
        .backend
        .read_sent_text(&f.store, "direct", "sent-1", 1001)
        .unwrap();
    assert_eq!(&*opened, &expected);
    let audits = f.store.list_audit("direct").unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|r| r.action.as_deref() == Some("sent_text_read"))
            .count(),
        1
    );
    assert!(audits.iter().all(|r| !r
        .args_redaction_summary
        .as_deref()
        .unwrap_or("")
        .contains("hello")));
}

#[test]
fn gmail_sealed_row_rejects_changed_row_connection_or_recipient_aad() {
    let f = Fixture::new();
    let t = crate::MockTransport::default();
    t.set_response(crate::MockResponse::Success(json!({"id":"123"})));
    f.send("bound-row", args(), &t, 1000);
    let row = f
        .store
        .sent_text("direct", "bound-row", 1001)
        .unwrap()
        .unwrap();
    let good = aad("bound-row", "mail", &row.recipient_hash);
    assert!(f.vault.open(&row.sealed, &good).is_ok());
    for changed in [
        aad("moved-row", "mail", &row.recipient_hash),
        aad("bound-row", "other", &row.recipient_hash),
        aad("bound-row", "mail", "different-recipients"),
    ] {
        assert_eq!(
            f.vault.open(&row.sealed, &changed).unwrap_err().code,
            "open_failed"
        );
    }
}

#[test]
fn gmail_rate_limit_is_one_per_second_per_owner_connection_and_survives_restart() {
    let f = Fixture::new();
    let t = crate::MockTransport::default();
    t.set_response(crate::MockResponse::Success(json!({"id":"id"})));
    assert!(f.send("first", args(), &t, 1000).error_code.is_none());
    let restarted = GmailBackend::new(f.vault.clone(), f.vault.clone(), f.vault.clone());
    assert_eq!(
        restarted
            .send(&f.store, "direct", request("too-fast", args()), &t, || 1999)
            .error_code
            .as_deref(),
        Some("gmail_rate_limited")
    );
    assert!(f.send("second", args(), &t, 2000).error_code.is_none());
    assert_eq!(t.requests().len(), 2);
}

#[test]
fn gmail_recipient_gate_checks_to_cc_and_bcc() {
    use crate::governance::{AuthorizationRequest, GovernanceEngine};
    let f = Fixture::new();
    f.store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &document())
        .unwrap();
    f.store
        .insert_connection("direct", "mail", "gmail", "pending", &json!({}))
        .unwrap();
    let ticket = f
        .store
        .create_binding_ticket("direct", "mail", b"oauth:gmail")
        .unwrap();
    f.store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    f.store
        .seed_catalog_from_manifest("direct", "mail", "gmail")
        .unwrap();
    f.store
        .insert_grant(&crate::storage::GrantInput {
            grant_id: "invoke".into(),
            principal: "direct".into(),
            connection_id: "mail".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["gmail.send".into()],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    f.store
        .set_policy("direct", "mail", "gmail.send", "allow", None)
        .unwrap();
    f.store
        .change_recipient("direct", "mail", None, "alice@example.com", true, true)
        .unwrap();
    let t = Arc::new(crate::MockTransport::default());
    let e = GovernanceEngine::new(
        f.store.clone(),
        Arc::new(crate::StubCredentialSource::with_default_success(
            b"unused".to_vec(),
        )),
        t.clone(),
    )
    .with_gmail_backend(Arc::new(f.backend))
    .with_decision_plane(Arc::new(crate::decision_plane::StubDecisionPlane::new()));
    let mut listed = args();
    listed["cc"] = json!(["alice@example.com"]);
    listed["bcc"] = json!(["alice@example.com"]);
    assert!(matches!(
        e.authorize(AuthorizationRequest::new(
            "direct",
            "mail",
            "gmail.send",
            listed.clone()
        )),
        Err(crate::governance::Denial::ResourceFilter(
            crate::governance::ResourceDenial::WriteFiltersAbsent
        ))
    ));
    f.store
        .insert_grant(&crate::storage::GrantInput {
            grant_id: "configure".into(),
            principal: "direct".into(),
            connection_id: "mail".into(),
            grantee_principal: "direct".into(),
            risk_ceiling: "write".into(),
            action_selectors: vec!["gmail.send".into()],
            authority_kind: "connection_admin".into(),
            expires_at: None,
        })
        .unwrap();
    assert!(matches!(
        f.store
            .configure_connection_filters_if_admin(
                "direct",
                "mail",
                "direct",
                &json!({"write_enabling":["to","cc","bcc"]})
            )
            .unwrap(),
        crate::storage::ConfigureOutcome::Configured(_)
    ));
    let filters = f
        .store
        .connection("direct", "mail")
        .unwrap()
        .unwrap()
        .resource_filters;
    assert_eq!(filters["write_enabling"], json!(["to", "cc", "bcc"]));
    assert!(filters.get("values").is_none());
    let reservation = e
        .authorize(AuthorizationRequest::new(
            "direct",
            "mail",
            "gmail.send",
            listed.clone(),
        ))
        .unwrap();
    for field in ["to", "cc", "bcc"] {
        let mut a = listed.clone();
        a[field] = json!(["unlisted@example.com"]);
        assert!(
            matches!(
                e.authorize(AuthorizationRequest::new("direct", "mail", "gmail.send", a)),
                Err(crate::governance::Denial::ActionRequestCreated { .. })
            ),
            "unlisted {field} must enter approval"
        );
    }
    assert!(t.requests().is_empty());
    for field in ["cc", "bcc"] {
        let mut a = args();
        a["to"] = json!([]);
        a[field] = json!(["alice@example.com"]);
        assert!(e
            .authorize(AuthorizationRequest::new("direct", "mail", "gmail.send", a))
            .is_ok());
    }
    t.set_response(crate::MockResponse::Success(json!({"id":"governed-id"})));
    let result = e.revalidate_and_dispatch(&reservation);
    assert!(
        matches!(
            result.outcome,
            crate::governance::TransportOutcome::Completed { .. }
        ),
        "{result:?}"
    );
    assert_eq!(t.requests().len(), 1);
    assert!(f.store.list_audit("direct").unwrap().iter().any(|r| r
        .args_redaction_summary
        .as_deref()
        .is_some_and(|s| s.contains("args_hash:") && !s.contains("hello"))));
    let stale = e
        .authorize(AuthorizationRequest::new(
            "direct",
            "mail",
            "gmail.send",
            listed,
        ))
        .unwrap();
    let store = f.store.clone();
    *f.vault.read_hook.lock().unwrap() = Some(Box::new(move || {
        store
            .change_recipient("direct", "mail", None, "alice@example.com", false, true)
            .unwrap();
    }));
    let refused = e.revalidate_and_dispatch(&stale);
    assert!(
        matches!(refused.outcome,crate::governance::TransportOutcome::NotSent {ref code,..} if code=="aborted_stale_authorization"),
        "{refused:?}"
    );
    assert_eq!(
        t.requests().len(),
        1,
        "a recipient revoked during vault preparation must not be sent to"
    );
}

#[test]
fn gmail_rfc9180_a2_1_chacha20_vector() {
    // RFC 9180 Appendix A.2.1, sequence 0: an independent known ciphertext,
    // not an encrypt/decrypt round trip using the same implementation.
    let bytes = |s: &str| hex::decode(s).unwrap();
    let sk = <hpke::kem::X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&bytes(
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    ))
    .unwrap();
    let enc = <hpke::kem::X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&bytes(
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    ))
    .unwrap();
    let mut context = hpke::setup_receiver::<
        hpke::aead::ChaCha20Poly1305,
        hpke::kdf::HkdfSha256,
        hpke::kem::X25519HkdfSha256,
    >(
        &hpke::OpModeR::Base,
        &sk,
        &enc,
        &bytes("4f6465206f6e2061204772656369616e2055726e"),
    )
    .unwrap();
    let plaintext=context.open(&bytes("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),&bytes("436f756e742d30")).unwrap();
    assert_eq!(
        hex::encode(plaintext),
        "4265617574792069732074727574682c20747275746820626561757479"
    );
}

struct WirePeer {
    calls: Mutex<Vec<(String, Value)>>,
    replies: Mutex<std::collections::VecDeque<Value>>,
}
impl CkcredRoutePeer for WirePeer {
    fn call(&self, op: &str, params: Value) -> Result<Value, CkcredRouteError> {
        self.calls.lock().unwrap().push((op.into(), params));
        Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("fake vault reply"))
    }
}
fn wire_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/vault-wire/enrollment_wire_contract.json"
    ))
    .unwrap()
}

#[test]
fn gmail_ckcred_wire_fixture_decoders_and_reserved_encoders() {
    let fixture = wire_fixture();
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../tests/fixtures/vault-wire/enrollment_wire_contract.json"
        ))),
        "eb0ef07ed7eb97e7bf9e7aefdd6bfa1322d2253e46b2e4fe91d05b1113523802"
    );
    let op = |name: &str| {
        fixture["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["op"] == name)
            .unwrap()
    };
    let public: Value =
        serde_json::from_str(op("credential.public_key")["success"][1].as_str().unwrap()).unwrap();
    assert!(vault::decode_public_key(&public, "a0289810032eb417").is_ok());
    assert_eq!(
        vault::decode_public_key(&public, vault::KEY_ID)
            .unwrap_err()
            .code,
        "sent_text_key_mismatch"
    );
    let mut tampered = public.clone();
    tampered["result"]["key_id"] = json!("0000000000000000");
    assert!(vault::decode_public_key(&tampered, "a0289810032eb417").is_err());
    let get: Value =
        serde_json::from_str(op("credential.get_scoped")["success"][0].as_str().unwrap()).unwrap();
    let report: Value = serde_json::from_str(
        op("credential.report_auth_failure")["success"][0]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let peer = Arc::new(WirePeer {
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new([get, report, public].into()),
    });
    let v = vault::Vault::new(peer.clone());
    let got = v.read().unwrap();
    assert_eq!(got.credential.record_version, 1);
    assert_eq!(got.credential.payload(), b"fixture-not-a-secret");
    assert!(got.account_id.is_none());
    v.report_401(12).unwrap();
    assert_eq!(
        v.seal(b"text", b"aad").unwrap_err().code,
        "sent_text_key_mismatch"
    );
    assert_eq!(
        *peer.calls.lock().unwrap(),
        vec![
            (
                "credential.get_scoped".into(),
                json!({"credential_id":"oauth:gmail"})
            ),
            (
                "credential.report_auth_failure".into(),
                json!({"credential_id":"oauth:gmail","record_version":12,"provider_status":401})
            ),
            (
                "credential.public_key".into(),
                json!({"credential_id":"kem:plexus-sent-text:1"})
            )
        ]
    );
}

#[test]
fn gmail_open_wire_is_strict_standard_padded_base64() {
    use base64::engine::general_purpose::STANDARD;
    let sealed = Sealed {
        key_id: vault::KEY_ID.into(),
        enc: vec![251; 32],
        ciphertext: vec![255, 254],
    };
    let params = vault::open_params(vault::KEY, &sealed, b"aad");
    assert_eq!(
        params,
        json!({"credential_id":"kem:plexus-sent-text:1","enc_b64":"+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=","ciphertext_b64":"//4=","info_b64":"cGxleHVzLXNlbnQtdGV4dC92MQ==","aad_b64":"YWFk"})
    );
    let peer=Arc::new(WirePeer { calls:Mutex::new(Vec::new()),replies:Mutex::new([json!({"result":{"plaintext_b64":STANDARD.encode(b"opened text"),"key_id":vault::KEY_ID}})].into()) });
    let v = vault::Vault::new(peer.clone());
    assert_eq!(&*v.open(&sealed, b"aad").unwrap(), b"opened text");
    assert_eq!(
        peer.calls.lock().unwrap()[0],
        ("credential.open".into(), params)
    );
}

#[test]
fn gmail_real_catalog_ingest_adds_only_gmail_action() {
    let f = Fixture::new();
    let mut before = Vec::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
    for file in std::fs::read_dir(root).unwrap() {
        let path = file.unwrap().path();
        if path.file_name().unwrap() == "gmail.jsonc" {
            continue;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let doc = crate::manifest::ingest_value(
            serde_json::from_str(&subc_jsonc::jsonc_to_json(&source).unwrap()).unwrap(),
        )
        .unwrap();
        f.store
            .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &doc)
            .unwrap();
        f.store
            .insert_connection(
                "direct",
                &doc.manifest.key,
                &doc.manifest.key,
                "active",
                &json!({}),
            )
            .unwrap();
        f.store
            .seed_catalog_from_manifest("direct", &doc.manifest.key, &doc.manifest.key)
            .unwrap();
        before.push((
            doc.manifest.key.clone(),
            f.store
                .list_catalog_actions_all("direct", &doc.manifest.key)
                .unwrap(),
        ));
    }
    assert!(!before.is_empty());
    f.store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &document())
        .unwrap();
    f.store
        .insert_connection("direct", "gmail", "gmail", "active", &json!({}))
        .unwrap();
    f.store
        .seed_catalog_from_manifest("direct", "gmail", "gmail")
        .unwrap();
    let added = f.store.list_catalog_actions_all("direct", "gmail").unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].name, "gmail.send");
    assert!(added[0].ask_first);
    assert_eq!(added[0].risk, "write");
    assert_eq!(added[0].severity, "S3");
    for (key, expected) in before {
        assert_eq!(
            expected,
            f.store.list_catalog_actions_all("direct", &key).unwrap(),
            "existing catalog action changed in {key}"
        );
    }
}

fn open_fixture() -> Value {
    wire_fixture()["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["op"] == "credential.open")
        .unwrap()
        .clone()
}

#[test]
fn gmail_sealer_reproduces_vault_encapsulation_and_ciphertext() {
    use base64::engine::general_purpose::STANDARD;
    let fixture = open_fixture();
    let spec = &fixture["hpke"];
    assert_eq!(
        (
            spec["mode"].as_str(),
            spec["kem_id"].as_u64(),
            spec["kdf_id"].as_u64(),
            spec["aead_id"].as_u64()
        ),
        (Some("base"), Some(32), Some(1), Some(3))
    );
    assert_eq!(spec["info"], "plexus-sent-text/v1");
    let key = hex::decode(spec["recipient_public_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let ikm = hex::decode(spec["ephemeral_ikm_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let associated = hex::decode(spec["aad_hex"].as_str().unwrap()).unwrap();
    let sealed = vault::seal_with_ikm(
        &key,
        "a0289810032eb417",
        spec["plaintext"].as_str().unwrap().as_bytes(),
        &associated,
        ikm,
    )
    .unwrap();
    let request: Value = serde_json::from_str(fixture["request"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(&sealed.enc), spec["enc_hex"]);
    assert_eq!(STANDARD.encode(&sealed.enc), request["enc_b64"]);
    assert_eq!(
        STANDARD.encode(&sealed.ciphertext),
        request["ciphertext_b64"]
    );
    assert_eq!(
        vault::open_params("kem:wire-fixture", &sealed, &associated),
        request
    );
}

#[test]
fn gmail_public_half_is_fetched_once_and_encapsulation_is_never_reused() {
    let fixture = wire_fixture();
    let public = fixture["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["op"] == "credential.public_key")
        .unwrap()["success"][1]
        .as_str()
        .unwrap();
    let peer = Arc::new(WirePeer {
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new([serde_json::from_str(public).unwrap()].into()),
    });
    let vault = vault::Vault::for_test_key(peer.clone(), "kem:wire-fixture", "a0289810032eb417");
    let first = vault.seal(b"text", b"aad").unwrap();
    let second = vault.seal(b"text", b"aad").unwrap();
    assert_ne!(first.enc, second.enc);
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_eq!(
        *peer.calls.lock().unwrap(),
        vec![(
            "credential.public_key".into(),
            json!({"credential_id":"kem:wire-fixture"})
        )]
    );
}

#[test]
fn gmail_admin_read_back_decodes_every_vault_open_case_and_audits_each() {
    use base64::engine::general_purpose::STANDARD;
    let f = Fixture::new();
    let fixture = open_fixture();
    let request: Value = serde_json::from_str(fixture["request"].as_str().unwrap()).unwrap();
    let replies =
        std::iter::once(&fixture["success"][0]).chain(fixture["refusals"].as_array().unwrap());
    let peer = Arc::new(WirePeer {
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new(
            replies
                .map(|v| serde_json::from_str(v.as_str().unwrap()).unwrap())
                .collect(),
        ),
    });
    let opener = Arc::new(vault::Vault::for_test_key(
        peer.clone(),
        "kem:wire-fixture",
        "a0289810032eb417",
    ));
    let backend = Arc::new(GmailBackend::new(f.vault.clone(), f.vault.clone(), opener));
    let engine = crate::governance::GovernanceEngine::new(
        f.store.clone(),
        Arc::new(crate::StubCredentialSource::default()),
        Arc::new(crate::MockTransport::default()),
    )
    .with_gmail_backend(backend);
    for (index, expected) in [
        None,
        Some("open_failed"),
        Some("open_failed"),
        Some("kind_not_openable"),
        Some("not_found"),
        Some("malformed_encoding"),
    ]
    .into_iter()
    .enumerate()
    {
        let row_id = format!("fixture-open-{index}");
        let row = SentTextRow {
            row_id: row_id.clone(),
            connection_id: "mail".into(),
            recipient_hash: "recipient-hash".into(),
            sealed: Sealed {
                key_id: "a0289810032eb417".into(),
                enc: STANDARD
                    .decode(request["enc_b64"].as_str().unwrap())
                    .unwrap(),
                ciphertext: STANDARD
                    .decode(request["ciphertext_b64"].as_str().unwrap())
                    .unwrap(),
            },
        };
        f.store
            .save_sent_text("direct", &row, crate::storage::now_ms())
            .unwrap();
        let result = engine.read_sent_text("direct", &row_id);
        match expected {
            Some(code) => assert_eq!(result.unwrap_err(), code),
            None => assert_eq!(
                &*result.unwrap(),
                fixture["hpke"]["plaintext"].as_str().unwrap().as_bytes()
            ),
        }
        let calls = peer.calls.lock().unwrap();
        let (op, params) = &calls[index];
        assert_eq!(op, "credential.open");
        assert_eq!(
            *params,
            vault::open_params(
                "kem:wire-fixture",
                &row.sealed,
                &aad(&row_id, "mail", "recipient-hash")
            )
        );
    }
    assert_eq!(
        f.store
            .list_audit("direct")
            .unwrap()
            .iter()
            .filter(|r| r.action.as_deref() == Some("sent_text_read"))
            .count(),
        6
    );
}

#[test]
fn gmail_ticket_pins_verified_mailbox_atomically_without_filter_defaults() {
    let f = Fixture::new();
    f.store
        .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &document())
        .unwrap();
    let ceiling = f
        .store
        .ceiling_within_manifest("gmail", "write", &["gmail.send".into()])
        .unwrap()
        .unwrap();
    let audit = |_: &crate::storage::BindingTicket| {
        crate::storage::AuditRecord::ceremony(
            "direct",
            Some("gmail"),
            Some("enrolled"),
            "issue_ticket",
            "write",
            None,
        )
    };
    let mailbox = f.backend.mailbox().unwrap();
    f.store
        .issue_gmail_ticket("direct", "enrolled", &mailbox, &ceiling, &audit)
        .unwrap()
        .unwrap();
    assert_eq!(
        f.store
            .gmail_mailbox("direct", "enrolled")
            .unwrap()
            .as_deref(),
        Some("owner@example.com")
    );
    assert_eq!(
        f.store
            .connection("direct", "enrolled")
            .unwrap()
            .unwrap()
            .resource_filters,
        json!({})
    );
    assert_eq!(
        f.store
            .connection_credential_reference("direct", "enrolled")
            .unwrap()
            .as_deref(),
        Some("oauth:gmail")
    );
    assert!(f
        .store
        .issue_gmail_ticket("direct", "enrolled", "other@example.com", &ceiling, &audit)
        .is_err());
    assert_eq!(
        f.store
            .gmail_mailbox("direct", "enrolled")
            .unwrap()
            .as_deref(),
        Some("owner@example.com")
    );
    assert!(f
        .store
        .issue_binding_ticket(
            "direct",
            "unconfirmed",
            "gmail",
            "credential_reference",
            b"oauth:gmail",
            &ceiling
        )
        .is_err());
    assert!(f
        .store
        .connection("direct", "unconfirmed")
        .unwrap()
        .is_none());
}
