//! Handle credential preparation: the vault mints an installation token; Plexus
//! never receives an App signing key or exchanges an App JWT with GitHub.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::credentials::{
    CkcredCredentialSource, CkcredRoutePeer, CredentialError, ResolvedCredential,
};

const EXPIRY_MARGIN_MS: i64 = 60_000;

/// Refusal codes for a handle token plexus could not obtain. Callers match on
/// the `handle_credential_unresolvable` prefix; the brace detail says whether
/// retrying can help. `transient` may clear on retry. `auth_required` needs a
/// person to repair the GitHub App (uninstalled, or installed on two
/// accounts). `permanent` is a plexus setup fault such as a missing vault
/// grant, a malformed reference, or a token the vault served that plexus must
/// refuse. The codes are fixed strings so the provider trait can keep its
/// `&'static str` error type.
pub const UNRESOLVABLE_TRANSIENT: &str = "handle_credential_unresolvable{class: transient}";
pub const UNRESOLVABLE_AUTH_REQUIRED: &str = "handle_credential_unresolvable{class: auth_required}";
pub const UNRESOLVABLE_PERMANENT: &str = "handle_credential_unresolvable{class: permanent}";
pub(crate) const APP_PREFIX: &str = "github_app:";

pub(crate) fn app_reference(app_handle_id: &str) -> String {
    format!("{APP_PREFIX}{app_handle_id}")
}

pub(crate) fn bot_login(reference: &str) -> Option<String> {
    reference
        .strip_prefix(APP_PREFIX)
        .filter(|slug| !slug.is_empty())
        .map(|slug| format!("{slug}[bot]"))
}

/// The refusal code for a vault read failure, keyed on the class the vault's
/// own error reports rather than a class chosen here.
fn unresolvable_for_vault_error(error: &CredentialError) -> &'static str {
    match error.class() {
        "auth_required" => UNRESOLVABLE_AUTH_REQUIRED,
        "permanent" => UNRESOLVABLE_PERMANENT,
        _ => UNRESOLVABLE_TRANSIENT,
    }
}

/// Secret-bearing operations supplied to the store-backed governance seam.
/// The seam owns the handle identity; callers cannot supply a vault reference.
pub trait HandleCredentialProvider: Send + Sync {
    fn prepare(
        &self,
        app_handle_id: &str,
        generation: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str>;
    fn vendor_status(&self, app_handle_id: &str, generation: i64, reference: &str, status: u16);
}

/// An injectable clock keeps cache expiry independent of wall-clock tests.
pub struct HandleCredentialPreparer<P> {
    source: CkcredCredentialSource<P>,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    invalidation: std::sync::atomic::AtomicU64,
    cache: Mutex<HashMap<(String, i64), ResolvedCredential>>,
}

impl<P: CkcredRoutePeer + 'static> HandleCredentialPreparer<P> {
    pub fn new(
        source: CkcredCredentialSource<P>,
        now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            source,
            now_ms,
            invalidation: std::sync::atomic::AtomicU64::new(0),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The reference and generation come from the handle row, never the caller.
    /// Refuse a mismatched resolved id before a token can reach the transport.
    pub fn prepare(
        &self,
        app_handle_id: &str,
        credential_generation: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        if !reference.starts_with(APP_PREFIX) || reference.len() <= APP_PREFIX.len() {
            return Err(UNRESOLVABLE_PERMANENT);
        }
        let key = (app_handle_id.to_owned(), credential_generation);
        let mut cache = self.cache.lock().map_err(|_| UNRESOLVABLE_TRANSIENT)?;
        if let Some(token) = cache.get(&key) {
            if token
                .expires_at_ms
                .is_some_and(|expiry| expiry.saturating_sub(EXPIRY_MARGIN_MS) > (self.now_ms)())
            {
                return Ok(token.clone());
            }
        }
        cache.remove(&key);
        let invalidation = self.invalidation.load(std::sync::atomic::Ordering::SeqCst);
        drop(cache);
        // Vault I/O must not hold the cache lock: unrelated handles can prepare
        // their credentials while this handle waits for its token.
        // The caller sees only the failure class, so the reason goes to the
        // operator log. Without it an unregistered vault record, a caller the
        // vault does not recognise and an expired token are indistinguishable.
        // CredentialError carries no secret material.
        let scoped = self.source.get_scoped(reference).map_err(|error| {
            eprintln!(
                warn transport:
                "scoped credential read failed for handle {app_handle_id} ({reference}): {error}"
            );
            unresolvable_for_vault_error(&error)
        })?;
        if scoped.credential_id != reference {
            eprintln!(
                warn transport:
                "scoped credential read for handle {app_handle_id} asked for {reference} but the vault resolved {}",
                scoped.credential_id
            );
            return Err(UNRESOLVABLE_PERMANENT);
        }
        if !scoped
            .credential
            .expires_at_ms
            .is_some_and(|expiry| expiry.saturating_sub(EXPIRY_MARGIN_MS) > (self.now_ms)())
        {
            eprintln!(
                warn transport:
                "scoped credential for handle {app_handle_id} ({reference}) has no expiry or expires within the refresh margin"
            );
            return Err(if scoped.credential.expires_at_ms.is_some() {
                UNRESOLVABLE_TRANSIENT
            } else {
                UNRESOLVABLE_PERMANENT
            });
        }
        let mut cache = self.cache.lock().map_err(|_| UNRESOLVABLE_TRANSIENT)?;
        cache.retain(|(id, generation), _| {
            id != app_handle_id || *generation >= credential_generation
        });
        // Do not repopulate the cache from a vault read that overlapped a 401.
        // The caller still receives the vault's answer; the next call fetches
        // again rather than reusing a possibly rejected token.
        if invalidation == self.invalidation.load(std::sync::atomic::Ordering::SeqCst) {
            cache.insert(key, scoped.credential.clone());
        }
        Ok(scoped.credential)
    }

    /// A GitHub 401 invalidates only the rejected generation. 403 means the
    /// token was accepted but lacks permission for the requested resource.
    pub fn vendor_status(
        &self,
        app_handle_id: &str,
        generation: i64,
        reference: &str,
        status: u16,
    ) {
        if status == 401 {
            if let Ok(mut cache) = self.cache.lock() {
                self.invalidation
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                cache.remove(&(app_handle_id.to_owned(), generation));
            }
            self.source.report_scoped_auth_failure(reference, status);
        }
    }
}

impl<P: CkcredRoutePeer + 'static> HandleCredentialProvider for HandleCredentialPreparer<P> {
    fn prepare(
        &self,
        app_handle_id: &str,
        generation: i64,
        reference: &str,
    ) -> Result<ResolvedCredential, &'static str> {
        HandleCredentialPreparer::prepare(self, app_handle_id, generation, reference)
    }

    fn vendor_status(&self, app_handle_id: &str, generation: i64, reference: &str, status: u16) {
        HandleCredentialPreparer::vendor_status(self, app_handle_id, generation, reference, status)
    }
}
