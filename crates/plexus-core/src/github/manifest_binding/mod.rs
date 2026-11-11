//! Repository discovery and the durable propose → card → activation → bind
//! sequence. Phone answers never authorize a bind here: only the vault's stored
//! version and its fleet activation verdict do.

pub mod wire;

use crate::{
    credentials::CkcredRoutePeer,
    github::{control::InstallationReader, credential::HandleCredentialProvider},
    storage::{
        github_bot_reads_store::BotReadAdmission, github_manifest_binding::BindingRecord,
        github_store::GithubHandle, PlexusStore,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use wire::{ActiveStatus, Failure, Notice, Proposal, Remedy};

pub const DISCOVERY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

pub enum CardRequest<'a> {
    Available,
    File {
        handle: &'a GithubHandle,
        proposal: &'a Proposal,
    },
    Get {
        card_id: &'a str,
        statement_b64url: &'a str,
    },
    Await {
        card_id: &'a str,
        statement_b64url: &'a str,
        timeout_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardState {
    Pending,
    Approved,
    Declined,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardReply {
    KindNotAvailable,
    Available,
    Filed(String),
    Conflict,
    State(CardState),
}

pub trait BindingCards {
    /// Filing must deduplicate by statement bytes, including across a lost reply
    /// or a crash before the returned card id is saved locally.
    fn manifest_binding_card(&self, request: CardRequest<'_>) -> Result<CardReply, String>;
}

#[derive(Default)]
pub struct Progress {
    disabled_logged_at: Option<i64>,
    logged: BTreeSet<String>,
    stopped: bool,
}

impl Progress {
    pub fn stopped(&self) -> bool {
        self.stopped
    }
}

pub struct ApprovalPass<'a> {
    pub store: &'a PlexusStore,
    pub vault: &'a dyn CkcredRoutePeer,
    pub cards: &'a dyn BindingCards,
    pub credentials: &'a dyn HandleCredentialProvider,
    pub reader: &'a dyn InstallationReader,
    pub held: &'a dyn Fn() -> bool,
    pub progress: &'a mut Progress,
}

impl ApprovalPass<'_> {
    fn admitted(&self) -> bool {
        !self.progress.stopped && (self.held)()
    }

    fn log_once(&mut self, key: String, message: &str) {
        if self.progress.logged.insert(key) {
            crate::diag!(warn governance: "manifest binding: {message}");
        }
    }

    fn failure(
        &mut self,
        failure: Failure,
        record: Option<&mut BindingRecord>,
        now: i64,
    ) -> Result<(), String> {
        if failure.code() == "one_tap_disabled" {
            if self
                .progress
                .disabled_logged_at
                .is_none_or(|last| now.saturating_sub(last) >= 3_600_000)
            {
                crate::diag!(info governance: "manifest binding: one_tap_disabled");
                self.progress.disabled_logged_at = Some(now);
            }
            return Ok(());
        }
        match failure.remedy() {
            Remedy::Retry => {}
            Remedy::TerminalRepository => {
                if let Some(record) = record {
                    record.state = "terminal".into();
                    self.save(record, None)?;
                    self.log_once(
                        format!(
                            "{}:{}:{}",
                            record.app_handle_id,
                            record.repository,
                            failure.code()
                        ),
                        failure.code(),
                    );
                }
            }
            Remedy::Stop => {
                self.progress.stopped = true;
                crate::diag!(error governance: "manifest binding stopped: {}", failure.code());
            }
        }
        Ok(())
    }

    fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, Failure> {
        if !self.admitted() {
            return Err(Failure::Transport("connector_home_not_held".into()));
        }
        let reply = self
            .vault
            .manifest_call(method, params)
            .map_err(|_| Failure::Transport("vault_unavailable".into()))?;
        wire::response(reply)
    }

    fn save(&self, record: &mut BindingRecord, event: Option<&str>) -> Result<(), String> {
        if !self.admitted() {
            return Err("connector_home_not_held".into());
        }
        if !self
            .store
            .save_github_manifest_binding(record, event)
            .map_err(|_| "store_error")?
        {
            return Err("proposal_changed".into());
        }
        record.revision += 1;
        Ok(())
    }

    /// A complete installation snapshot, charged one request at a time. `None`
    /// means all-repository access and must never be treated as an empty list.
    fn installation(
        &mut self,
        handle: &GithubHandle,
        now: i64,
    ) -> Result<Option<Vec<String>>, String> {
        if !self.admitted() {
            return Err("connector_home_not_held".into());
        }
        let token = self.credentials.prepare(
            &handle.app_handle_id,
            handle.credential_generation,
            &handle.credential_reference,
        )?;
        let mut repositories = BTreeSet::new();
        let mut total = None;
        for page in 1..=10 {
            if !self.admitted() {
                return Err("connector_home_not_held".into());
            }
            if !matches!(
                self.store
                    .reserve_github_bot_read(&handle.app_handle_id, 1, now)
                    .map_err(|_| "store_error")?,
                BotReadAdmission::Reserved
            ) {
                return Err("bot_read_budget_exhausted".into());
            }
            let value = self.reader.repositories_page(&token, page, 100)?;
            if page == 1 {
                match value["repository_selection"].as_str() {
                    Some("all") => {
                        self.log_once(format!("all:{}", handle.app_handle_id), "installation_all");
                        return Ok(None);
                    }
                    Some("selected") => {}
                    _ => return Err("installation_selection_missing".into()),
                }
            }
            let count = value["total_count"]
                .as_u64()
                .filter(|n| *n <= 1000)
                .ok_or("installation_count_invalid")?;
            if total.is_some_and(|n| n != count) {
                return Err("installation_count_changed".into());
            }
            total = Some(count);
            let items = value["repositories"]
                .as_array()
                .ok_or("installation_repositories_invalid")?;
            if items.is_empty() && repositories.len() < count as usize {
                return Err("installation_incomplete".into());
            }
            for item in items {
                let name = item["full_name"]
                    .as_str()
                    .ok_or("installation_repository_invalid")?;
                crate::github::resolver::split_repository(name)
                    .map_err(|_| "installation_repository_invalid")?;
                if !repositories.insert(crate::github::canonical_repository(name)) {
                    return Err("installation_duplicate".into());
                }
            }
            if repositories.len() > count as usize {
                return Err("installation_count_invalid".into());
            }
            if repositories.len() == count as usize {
                return Ok(Some(repositories.into_iter().collect()));
            }
        }
        Err("installation_incomplete".into())
    }

    pub fn discover(&mut self, now: i64) -> Result<(), String> {
        if !self.admitted() {
            return Ok(());
        }
        let available = matches!(
            self.cards.manifest_binding_card(CardRequest::Available),
            Ok(CardReply::Available)
        );
        let handles = self
            .store
            .github_manifest_handles()
            .map_err(|_| "store_error")?;
        for handle in handles {
            if !self.admitted() {
                break;
            }
            let installation = match self.installation(&handle, now) {
                Ok(Some(repositories)) => repositories,
                Ok(None) => continue,
                Err(code) => {
                    self.log_once(format!("{}:{code}", handle.app_handle_id), &code);
                    continue;
                }
            };
            if !self.admitted() {
                break;
            }
            self.store
                .observe_github_manifest_installation(&handle, &installation)
                .map_err(|_| "store_error")?;
            let records = self
                .store
                .github_manifest_bindings()
                .map_err(|_| "store_error")?;
            for repository in &installation {
                let mut record = records
                    .iter()
                    .find(|r| {
                        r.app_handle_id == handle.app_handle_id && r.repository == *repository
                    })
                    .cloned()
                    .unwrap_or_else(|| BindingRecord::observed(&handle, repository));
                let owner = self
                    .store
                    .github_manifest_repository_handle(&record.repository)
                    .map_err(|_| "store_error")?;
                if let Some(owner) = owner {
                    if owner != handle.app_handle_id && record.state != "terminal" {
                        self.log_once(
                            format!("other:{}:{}", handle.app_handle_id, record.repository),
                            "repository_bound_elsewhere",
                        );
                    }
                    continue;
                }
                if record.agent_id != handle.agent_id
                    || matches!(
                        record.state.as_str(),
                        "declined" | "expired" | "terminal" | "bound"
                    )
                {
                    continue;
                }
                if matches!(record.state.as_str(), "awaiting_active" | "card_conflict") {
                    continue;
                }
                if self.card_settlement(&mut record)? {
                    continue;
                }
                // Do not create a vault proposal unless its statement can be
                // put in front of the owner. No generic card can substitute.
                if !available || !self.admitted() {
                    continue;
                }
                let slug = handle
                    .credential_reference
                    .strip_prefix("github_app:")
                    .filter(|s| !s.is_empty())
                    .ok_or("app_slug_missing")?;
                let params = json!({
                    "agent_id": handle.agent_id,
                    "app_id": handle.app_id,
                    "app_slug": slug,
                    "repo": record.repository,
                });
                match self.call::<Proposal>("manifest.propose_binding", params) {
                    Ok(proposal) => {
                        let statement_matches = proposal
                            .statement(&handle.agent_id, slug, &record.repository)
                            .is_ok();
                        if !statement_matches || proposal.expires_at_ms <= now {
                            self.failure(Failure::InvalidReply, None, now)?;
                            break;
                        }
                        if record.proposal_id.as_deref() != Some(&proposal.proposal_id) {
                            record.proposal_id = Some(proposal.proposal_id.clone());
                            record.manifest_version = Some(proposal.manifest_version);
                            record.manifest_sha256 = Some(proposal.manifest_sha256.clone());
                            record.statement_b64url = Some(proposal.statement_b64url.clone());
                            record.expires_at_ms = Some(proposal.expires_at_ms);
                            record.state = "pending".into();
                            record.card_id = None;
                            self.save(&mut record, Some("github_manifest_proposed"))?;
                        }
                        if record.card_id.is_none()
                            && record.state != "card_conflict"
                            && self.admitted()
                        {
                            let filed = self.cards.manifest_binding_card(CardRequest::File {
                                handle: &handle,
                                proposal: &proposal,
                            });
                            match filed {
                                Ok(CardReply::Filed(id)) if !id.is_empty() => {
                                    record.card_id = Some(id);
                                    self.save(&mut record, Some("github_manifest_card_filed"))?;
                                }
                                Ok(CardReply::Conflict) => {
                                    // Another session already holds the card for
                                    // this statement. Filing again cannot help;
                                    // the vault's manifest watch reports the outcome.
                                    record.state = "card_conflict".into();
                                    self.save(&mut record, None)?;
                                    self.log_once(
                                        format!(
                                            "card-conflict:{}:{}",
                                            handle.app_handle_id, record.repository
                                        ),
                                        "elicitation_request_conflict",
                                    );
                                }
                                _ => return Err("manifest_binding_card_unavailable".into()),
                            }
                        }
                    }
                    // The vault already maps this repository to this agent in a
                    // stored version, so no card is needed: bind once that
                    // version is active everywhere.
                    Err(Failure::Domain(ref refusal))
                        if refusal.code == "already_bound" && refusal.remedy() == Remedy::Retry =>
                    {
                        record.manifest_version = refusal.version;
                        record.manifest_sha256 = refusal.manifest_sha256.clone();
                        record.state = "awaiting_active".into();
                        self.save(&mut record, None)?;
                    }
                    Err(failure) => self.failure(failure, Some(&mut record), now)?,
                }
            }
        }
        self.follow_ready(now)
    }

    fn card_settlement(&self, record: &mut BindingRecord) -> Result<bool, String> {
        let Some(id) = record.card_id.as_deref() else {
            return Ok(false);
        };
        if !self.admitted() {
            return Ok(true);
        }
        let statement_b64url = record
            .statement_b64url
            .as_deref()
            .ok_or("proposal_statement_missing")?;
        let request = if record.state == "awaiting_active" {
            CardRequest::Await {
                card_id: id,
                statement_b64url,
                timeout_ms: 0,
            }
        } else {
            CardRequest::Get {
                card_id: id,
                statement_b64url,
            }
        };
        match self.cards.manifest_binding_card(request) {
            Ok(CardReply::State(CardState::Declined)) => {
                record.state = "declined".into();
                self.save(record, Some("github_manifest_declined"))?;
                Ok(true)
            }
            Ok(CardReply::State(CardState::Expired)) => {
                record.state = "expired".into();
                self.save(record, Some("github_manifest_expired"))?;
                Ok(true)
            }
            Ok(CardReply::State(_)) => Ok(false),
            _ => Ok(true),
        }
    }

    pub fn notice(&mut self, value: Value, now: i64) -> Result<(), String> {
        if !self.admitted() {
            return Ok(());
        }
        let notice = match Notice::decode(value.clone()) {
            Ok(notice) => notice,
            Err(_) => {
                let failure = wire::response::<Value>(value)
                    .err()
                    .unwrap_or(Failure::InvalidReply);
                return self.failure(failure, None, now);
            }
        };
        for mut record in self
            .store
            .github_manifest_bindings()
            .map_err(|_| "store_error")?
        {
            if record.present
                && matches!(record.state.as_str(), "pending" | "card_conflict")
                && record.manifest_version == notice.version
                && record.manifest_sha256 == notice.manifest_sha256
            {
                if self.card_settlement(&mut record)? {
                    continue;
                }
                record.state = "awaiting_active".into();
                self.save(&mut record, None)?;
            }
        }
        self.follow_ready(now)
    }

    pub fn follow_ready(&mut self, now: i64) -> Result<(), String> {
        if !self.admitted() {
            return Ok(());
        }
        let handles = self
            .store
            .github_manifest_handles()
            .map_err(|_| "store_error")?;
        for mut record in self
            .store
            .github_manifest_bindings()
            .map_err(|_| "store_error")?
        {
            if !record.present || record.state != "awaiting_active" {
                continue;
            }
            if self.card_settlement(&mut record)? {
                continue;
            }
            let Some(handle) = handles
                .iter()
                .find(|h| h.app_handle_id == record.app_handle_id && h.agent_id == record.agent_id)
            else {
                continue;
            };
            let (Some(version), Some(hash)) =
                (record.manifest_version, record.manifest_sha256.as_deref())
            else {
                return Err("proposal_commitment_missing".into());
            };
            match self.call::<ActiveStatus>("manifest.active_status", json!({"version":version})) {
                Ok(status) if status.ready_for(version, hash) => {
                    let Some(installation) = self.installation(handle, now)? else {
                        continue;
                    };
                    if !self.admitted() {
                        break;
                    }
                    self.store
                        .bind_github_manifest_repository(&record, installation)
                        .map_err(|_| "store_error")??;
                }
                Ok(_) => {}
                Err(failure) => self.failure(failure, None, now)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
