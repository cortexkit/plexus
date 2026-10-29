//! Governed Gmail send: structured MIME, pinned mailbox, vault-sealed archive,
//! and a durable one-second send slot. Only the REST request uses raw bytes.

pub mod mime;
pub mod vault;
use crate::{
    credentials::{CredentialError, PermanentCredentialError},
    storage::{sent_text_store::SentTextRow, PlexusStore},
    transport::{Retryability, Transport, TransportRequest, TransportResponse},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use vault::{GmailCredentials, SentTextOpener, SentTextSealer};
use zeroize::Zeroizing;

pub(crate) struct PreparedGmail {
    credential: crate::credentials::ScopedCredential,
    plaintext: Zeroizing<Vec<u8>>,
    row: SentTextRow,
}

pub struct GmailBackend {
    credentials: Arc<dyn GmailCredentials>,
    sealer: Arc<dyn SentTextSealer>,
    opener: Arc<dyn SentTextOpener>,
    send_lock: Mutex<()>,
}

pub fn aad(row_id: &str, connection: &str, recipient_hash: &str) -> Vec<u8> {
    // A JSON tuple has unambiguous boundaries even when identifiers contain
    // separators; its version label leaves room for future archive formats.
    serde_json::to_vec(&json!([
        "plexus-sent-text/v1",
        row_id,
        connection,
        recipient_hash
    ]))
    .expect("string tuple")
}
pub fn refusal(code: &str, transient: bool) -> TransportResponse {
    let mut response = TransportResponse::vendor_error(code).not_sent();
    if transient {
        response.retryability = Retryability::AutoRetryable;
    }
    response
}
fn credential_code(error: &CredentialError) -> (&'static str, bool) {
    match error {
        CredentialError::AuthRequired => ("auth_required", false),
        CredentialError::Permanent(PermanentCredentialError::NotFound) => ("not_found", false),
        CredentialError::Permanent(_) => ("credential_invalid", false),
        CredentialError::Transient(_) => ("credential_transient", true),
    }
}
fn credential_refusal(error: CredentialError) -> TransportResponse {
    let (code, transient) = credential_code(&error);
    refusal(code, transient)
}

impl GmailBackend {
    pub fn new(
        credentials: Arc<dyn GmailCredentials>,
        sealer: Arc<dyn SentTextSealer>,
        opener: Arc<dyn SentTextOpener>,
    ) -> Self {
        Self {
            credentials,
            sealer,
            opener,
            send_lock: Mutex::new(()),
        }
    }
    pub fn mailbox(&self) -> Result<String, &'static str> {
        let scoped = self
            .credentials
            .read()
            .map_err(|error| credential_code(&error).0)?;
        if scoped.credential_id != "oauth:gmail" {
            return Err("gmail_credential_mismatch");
        }
        scoped
            .account_id
            .filter(|mailbox| mime::address(mailbox).is_ok())
            .ok_or("gmail_account_unconfirmed")
    }
    pub fn send<T: Transport + ?Sized>(
        &self,
        store: &PlexusStore,
        owner: &str,
        request: TransportRequest,
        transport: &T,
        now_ms: impl Fn() -> i64,
    ) -> TransportResponse {
        let prepared = match self.prepare(store, owner, &request, now_ms()) {
            Ok(p) => p,
            Err(response) => return *response,
        };
        self.send_prepared(store, owner, request, transport, now_ms, prepared)
    }

    /// Resolve the mailbox-bearing credential and seal the message before the
    /// governance claim. A slow vault read must not reopen the authorization
    /// window after a grant or recipient entry has been revoked.
    pub(crate) fn prepare(
        &self,
        store: &PlexusStore,
        owner: &str,
        request: &TransportRequest,
        at_ms: i64,
    ) -> Result<PreparedGmail, Box<TransportResponse>> {
        let message =
            mime::Message::parse(&request.args).map_err(|code| Box::new(refusal(code, false)))?;
        let mailbox = store
            .gmail_mailbox(owner, &request.connection_id)
            .map_err(|_| Box::new(refusal("store_failure", true)))?
            .ok_or_else(|| Box::new(refusal("gmail_account_unconfirmed", false)))?;
        let plaintext = Zeroizing::new(
            message
                .compose(&mailbox, at_ms)
                .map_err(|code| Box::new(refusal(code, false)))?,
        );
        let credential = self
            .credentials
            .read()
            .map_err(|error| Box::new(credential_refusal(error)))?;
        if credential.credential_id != "oauth:gmail" {
            return Err(Box::new(refusal("gmail_credential_mismatch", false)));
        }
        if credential.account_id.as_deref() != Some(mailbox.as_str()) {
            return Err(Box::new(refusal("gmail_account_mismatch", false)));
        }
        let mut recipients: Vec<_> = message
            .to
            .iter()
            .chain(&message.cc)
            .chain(&message.bcc)
            .map(|r| crate::recipients::normalize_recipient(r))
            .collect();
        recipients.sort();
        recipients.dedup();
        let recipient_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&recipients).expect("recipients"),
        ));
        let associated = aad(&request.request_id, &request.connection_id, &recipient_hash);
        let sealed = self
            .sealer
            .seal(&plaintext, &associated)
            .map_err(|error| Box::new(refusal(error.code, error.transient)))?;
        let row = SentTextRow {
            row_id: request.request_id.clone(),
            connection_id: request.connection_id.clone(),
            recipient_hash,
            sealed,
        };
        Ok(PreparedGmail {
            credential,
            plaintext,
            row,
        })
    }

    pub(crate) fn send_prepared<T: Transport + ?Sized>(
        &self,
        store: &PlexusStore,
        owner: &str,
        mut request: TransportRequest,
        transport: &T,
        now_ms: impl Fn() -> i64,
        prepared: PreparedGmail,
    ) -> TransportResponse {
        let PreparedGmail {
            credential,
            plaintext,
            row,
        } = prepared;
        // Hold the local lock across the network call. The durable cooldown is
        // extended after it returns, so a slow seal, store write or suspended
        // sending thread cannot bunch two sends into the same second.
        let _send_guard = match self.send_lock.lock() {
            Ok(g) => g,
            Err(_) => return refusal("gmail_send_lock_failed", true),
        };
        let now = now_ms();
        match store.claim_gmail_send(owner, &request.connection_id, now) {
            Ok(true) => {}
            Ok(false) => {
                let mut r = refusal("gmail_rate_limited", false);
                r.retryability = Retryability::Throttle;
                r.retry_after_ms = Some(1000);
                return r;
            }
            Err(_) => return refusal("store_failure", true),
        }
        if store.save_sent_text(owner, &row, now).is_err() {
            return refusal("store_failure", true);
        }
        request.args = json!({"raw":URL_SAFE_NO_PAD.encode(&*plaintext)});
        let connection_id = request.connection_id.clone();
        let mut response = transport.dispatch(request, &credential.credential);
        if store
            .finish_gmail_send(owner, &connection_id, now_ms())
            .is_err()
        {
            return TransportResponse::unknown_with_error("store_failure");
        }
        if response.error_code.as_deref().is_some_and(|code| {
            code.strip_prefix("http_")
                .and_then(|s| s.parse::<u16>().ok())
                .is_some_and(|s| s >= 500)
        }) {
            response.retryability = Retryability::AutoRetryable;
        }
        if response.provider_auth_status() == Some(401) {
            // A rejected write is not automatically resent. Report the exact
            // served version, then read once to let the vault refresh or latch
            // needs_reauth; the caller must authorize a new send attempt.
            let _ = self
                .credentials
                .report_401(credential.credential.record_version);
            if let Err(error) = self.credentials.read() {
                if error == CredentialError::AuthRequired {
                    response.error_code = Some("auth_required".into());
                }
            }
        }
        if response.error_code.is_none() {
            if let Some(id) = response
                .response
                .as_ref()
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            {
                response.response = Some(
                    json!({"status":"accepted","message_id":id,"sent_text_row_id":row.row_id}),
                );
            } else {
                return TransportResponse::unknown_with_error("gmail_invalid_reply");
            }
        }
        response
    }
    pub fn read_sent_text(
        &self,
        store: &PlexusStore,
        owner: &str,
        row_id: &str,
        now: i64,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        // Audit before asking the vault, including failed or expired reads.
        store
            .audit_sent_text_read(owner, row_id, "attempted")
            .map_err(|_| "store_failure")?;
        let row = store
            .sent_text(owner, row_id, now)
            .map_err(|_| "store_failure")?
            .ok_or("not_found")?;
        self.opener
            .open(
                &row.sealed,
                &aad(&row.row_id, &row.connection_id, &row.recipient_hash),
            )
            .map_err(|e| e.code)
    }
}

#[cfg(test)]
mod tests;
