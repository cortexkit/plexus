//! Vault-only custody for Gmail tokens and archived text. No private key is
//! stored by Plexus; Plexus pins the public key before sealing a message.

use crate::credentials::{
    CkcredCredentialSource, CkcredRoutePeer, CredentialError, ScopedCredential,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem,
    Serializable,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub const KEY: &str = "kem:plexus-sent-text:1";
pub const KEY_ID: &str = "f0d59c165a515480";
pub const INFO: &[u8] = b"plexus-sent-text/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: String,
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultError {
    pub code: &'static str,
    pub transient: bool,
}
impl VaultError {
    pub fn permanent(code: &'static str) -> Self {
        Self {
            code,
            transient: false,
        }
    }
    pub fn transient() -> Self {
        Self {
            code: "vault_transient",
            transient: true,
        }
    }
}

pub trait GmailCredentials: Send + Sync {
    fn read(&self) -> Result<ScopedCredential, CredentialError>;
    fn report_401(&self, record_version: u64) -> Result<(), VaultError>;
}
pub trait SentTextSealer: Send + Sync {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, VaultError>;
}
pub trait SentTextOpener: Send + Sync {
    fn open(&self, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError>;
}

pub struct Vault<P: CkcredRoutePeer + ?Sized> {
    peer: Arc<P>,
    public_key: Mutex<Option<[u8; 32]>>,
    credential_id: &'static str,
    key_id: &'static str,
}
impl<P: CkcredRoutePeer> Vault<P> {
    pub fn new(peer: Arc<P>) -> Self {
        Self {
            peer,
            public_key: Mutex::new(None),
            credential_id: KEY,
            key_id: KEY_ID,
        }
    }
    #[cfg(test)]
    pub(crate) fn for_test_key(
        peer: Arc<P>,
        credential_id: &'static str,
        key_id: &'static str,
    ) -> Self {
        Self {
            peer,
            public_key: Mutex::new(None),
            credential_id,
            key_id,
        }
    }
}

fn result(response: &Value) -> Result<&Value, VaultError> {
    let result = response
        .get("result")
        .ok_or(VaultError::permanent("vault_invalid_reply"))?;
    if let Some(error) = result.get("error") {
        return Err(
            match error.get("code").and_then(Value::as_str).unwrap_or("") {
                "open_failed" => VaultError::permanent("open_failed"),
                "kind_not_openable" => VaultError::permanent("kind_not_openable"),
                "not_found" => VaultError::permanent("not_found"),
                "malformed_encoding" => VaultError::permanent("malformed_encoding"),
                "sign_payload_too_large" => VaultError::permanent("sign_payload_too_large"),
                "open_rate_limited" => VaultError {
                    code: "open_rate_limited",
                    transient: true,
                },
                _ if error.get("class").and_then(Value::as_str) == Some("transient") => {
                    VaultError::transient()
                }
                _ => VaultError::permanent("vault_refused"),
            },
        );
    }
    Ok(result)
}

pub(crate) fn decode_public_key(
    response: &Value,
    expected_id: &str,
) -> Result<[u8; 32], VaultError> {
    let value = result(response)?;
    let invalid = || VaultError::permanent("sent_text_key_mismatch");
    if value.get("algorithm").and_then(Value::as_str) != Some("x25519") {
        return Err(invalid());
    }
    let bytes = hex::decode(
        value
            .get("public_key_hex")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| invalid())?;
    let id = hex::encode(&Sha256::digest(key)[..8]);
    if id != expected_id || value.get("key_id").and_then(Value::as_str) != Some(id.as_str()) {
        return Err(invalid());
    }
    Ok(key)
}

impl<P: CkcredRoutePeer> GmailCredentials for Vault<P> {
    fn read(&self) -> Result<ScopedCredential, CredentialError> {
        CkcredCredentialSource::new(self.peer.clone()).get_scoped("oauth:gmail")
    }
    fn report_401(&self, record_version: u64) -> Result<(), VaultError> {
        let reply = self.peer.call("credential.report_auth_failure", json!({"credential_id":"oauth:gmail", "record_version":record_version,"provider_status":401})).map_err(|_| VaultError::transient())?;
        result(&reply)?
            .get("accepted")
            .and_then(Value::as_bool)
            .ok_or(VaultError::permanent("vault_invalid_reply"))?;
        Ok(())
    }
}

impl<P: CkcredRoutePeer> SentTextSealer for Vault<P> {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, VaultError> {
        let mut cached = self
            .public_key
            .lock()
            .map_err(|_| VaultError::transient())?;
        let public_key = match *cached {
            Some(key) => key,
            None => {
                let response = self
                    .peer
                    .call(
                        "credential.public_key",
                        json!({"credential_id":self.credential_id}),
                    )
                    .map_err(|_| VaultError::transient())?;
                let key = decode_public_key(&response, self.key_id)?;
                *cached = Some(key);
                key
            }
        };
        drop(cached);
        if plaintext.len() + aad.len() + INFO.len() + 32 + 16 > 1_048_576 {
            return Err(VaultError::permanent("sign_payload_too_large"));
        }
        seal_to_key(&public_key, self.key_id, plaintext, aad)
    }
}

pub(crate) fn seal_to_key(
    public_key: &[u8; 32],
    key_id: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Sealed, VaultError> {
    let mut rng = hpke::rand_core::UnwrapErr(OsRng);
    seal_with_rng(public_key, key_id, plaintext, aad, &mut rng)
}

fn seal_with_rng<R: hpke::rand_core::RngCore + hpke::rand_core::CryptoRng>(
    public_key: &[u8; 32],
    key_id: &str,
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<Sealed, VaultError> {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(public_key)
        .map_err(|_| VaultError::permanent("sent_text_key_mismatch"))?;
    let (enc, mut context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            &pk,
            INFO,
            rng,
        )
        .map_err(|_| VaultError::permanent("sent_text_seal_failed"))?;
    let ciphertext = context
        .seal(plaintext, aad)
        .map_err(|_| VaultError::permanent("sent_text_seal_failed"))?;
    Ok(Sealed {
        key_id: key_id.into(),
        enc: enc.to_bytes().to_vec(),
        ciphertext,
    })
}

/// Reproduce the vault's fixed encapsulation vector without making seeded
/// randomness available to any production caller.
#[cfg(test)]
pub(crate) fn seal_with_ikm(
    public_key: &[u8; 32],
    key_id: &str,
    plaintext: &[u8],
    aad: &[u8],
    ikm: [u8; 32],
) -> Result<Sealed, VaultError> {
    struct Ikm {
        bytes: [u8; 32],
        offset: usize,
    }
    impl hpke::rand_core::RngCore for Ikm {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.offset + dest.len();
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }
    }
    impl hpke::rand_core::CryptoRng for Ikm {}
    let mut rng = Ikm {
        bytes: ikm,
        offset: 0,
    };
    let sealed = seal_with_rng(public_key, key_id, plaintext, aad, &mut rng)?;
    assert_eq!(rng.offset, 32, "one ephemeral key per encapsulation");
    Ok(sealed)
}

// getrandom is already the workspace's OS entropy source. HPKE uses rand_core
// 0.9's fallible interface; an unavailable OS RNG aborts sealing, never falls
// back to deterministic randomness, and no message has been sent at that point.
struct OsRng;
impl hpke::rand_core::TryRngCore for OsRng {
    type Error = getrandom::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_ne_bytes(self.bytes()?))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_ne_bytes(self.bytes()?))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dest)
    }
}
impl hpke::rand_core::TryCryptoRng for OsRng {}
impl OsRng {
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], getrandom::Error> {
        let mut b = [0; N];
        getrandom::fill(&mut b)?;
        Ok(b)
    }
}

pub(crate) fn open_params(credential_id: &str, sealed: &Sealed, aad: &[u8]) -> Value {
    json!({"credential_id":credential_id,"enc_b64":STANDARD.encode(&sealed.enc),"ciphertext_b64":STANDARD.encode(&sealed.ciphertext),"info_b64":STANDARD.encode(INFO),"aad_b64":STANDARD.encode(aad)})
}
impl<P: CkcredRoutePeer> SentTextOpener for Vault<P> {
    fn open(&self, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if sealed.key_id != self.key_id {
            return Err(VaultError::permanent("sent_text_key_mismatch"));
        }
        let mut response = self
            .peer
            .call(
                "credential.open",
                open_params(self.credential_id, sealed, aad),
            )
            .map_err(|_| VaultError::transient())?;
        let decoded = (|| {
            let value = result(&response)?;
            if value.get("key_id").and_then(Value::as_str) != Some(sealed.key_id.as_str()) {
                return Err(VaultError::permanent("sent_text_key_mismatch"));
            }
            let encoded = value
                .get("plaintext_b64")
                .and_then(Value::as_str)
                .ok_or(VaultError::permanent("vault_invalid_reply"))?;
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .map_err(|_| VaultError::permanent("vault_invalid_reply"))?,
            );
            if STANDARD.encode(&*bytes) != encoded {
                return Err(VaultError::permanent("vault_invalid_reply"));
            }
            Ok(bytes)
        })();
        if let Some(Value::String(encoded)) = response.pointer_mut("/result/plaintext_b64") {
            use zeroize::Zeroize;
            encoded.zeroize();
        }
        decoded
    }
}
