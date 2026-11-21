use super::{
    aft_import_selectors, import_handle, invoke_selectors, resolve_repositories,
    InstallationReader, InventoryHandle, WRITES,
};
use crate::github::credential::{app_reference, HandleCredentialProvider};
use crate::storage::{github_store::GithubImportRow, PlexusStore};

const REPROBE_INTERVAL_MS: i64 = 15 * 60 * 1000;

pub(crate) struct Carrier {
    pub suffix: &'static str,
    pub principal: &'static str,
    pub kind: &'static str,
    pub risk: &'static str,
    pub selectors: &'static [&'static str],
}

/// These supplement the shared import defaults: Prefrontal's existing grant,
/// and AFT's GitHub reads, bot writes, and the reads and additional writes they
/// can dispatch. Together they match the carrier grants of onboarded bots.
/// None grants authority to an agent or binds a repository; the bot still needs
/// a repository binding to read and both a binding and an agent grant to write.
pub(crate) const VAULT_APP_IMPORT_ADDITIONAL_CARRIERS: &[Carrier] = &[
    Carrier {
        suffix: "reserved-basal",
        principal: "reserved:basal",
        kind: "invoke",
        risk: "write",
        selectors: &[
            "add_issue_assignees",
            "add_issue_comment",
            "add_issue_labels",
            "add_pr_review",
            "add_reaction",
            "close_issue",
            "create_issue",
            "create_pull_request",
            "edit_issue",
            "github.issue.get",
            "github.issue_comment.get",
            "github.issue_comments.list",
            "remove_issue_assignees",
            "remove_issue_label",
            "reopen_issue",
            "update_issue_comment",
        ],
    },
    Carrier {
        suffix: "poll",
        principal: "direct",
        kind: "poll",
        risk: "read",
        selectors: &["github.issue_timeline.list"],
    },
];

/// An App identity from the vault's scoped listing, after the watcher validates
/// the metadata and checks that the named agent is live.
pub struct AttestedApp<'a> {
    pub slug: &'a str,
    pub agent: &'a str,
    pub app_id: i64,
}

pub enum AttestedImport {
    Imported { proven: bool },
    AlreadyImported,
}

pub enum ExistingAttestedApp {
    Enabled,
    Disabled { next_probe_at_ms: Option<i64> },
    Conflict,
}

impl AttestedApp<'_> {
    /// Find a previous import by vault record, not by connection or agent.
    pub fn existing(
        &self,
        store: &PlexusStore,
    ) -> Result<Option<ExistingAttestedApp>, cortexkit_store::StoreError> {
        Ok(store
            .github_handle_identity_for_record(&app_reference(self.slug))?
            .map(|existing| {
                if existing.app_id != self.app_id || existing.agent != self.agent {
                    ExistingAttestedApp::Conflict
                } else if existing.enabled {
                    ExistingAttestedApp::Enabled
                } else {
                    ExistingAttestedApp::Disabled {
                        next_probe_at_ms: existing.next_probe_at_ms,
                    }
                }
            }))
    }

    /// Import only the handle and carrier grants. Listing the installation's
    /// repositories with the new handle's GitHub token proves the token works.
    /// There are no bound repositories to check yet. Commit that proof with
    /// the handle so policy apply cannot use a handle whose probe failed.
    pub fn import(
        &self,
        store: &PlexusStore,
        provider: Option<&dyn HandleCredentialProvider>,
        reader: &dyn InstallationReader,
        now: i64,
        held: &dyn Fn() -> bool,
    ) -> Result<AttestedImport, String> {
        let item = self.inventory_handle();
        let mut handle = import_handle(&item);
        let proven = provider.is_some_and(|provider| {
            resolve_repositories(
                provider,
                reader,
                &item,
                handle.credential_generation,
                now,
                held,
            )
            .is_ok()
        });
        if proven {
            handle.status = "enabled".into();
            handle.proven_at = Some(now);
        }
        let created = store
            .import_attested_github_handle(
                &GithubImportRow {
                    handle,
                    repositories: Vec::new(),
                    grants: Vec::new(),
                    module_actions: aft_import_selectors(invoke_selectors(WRITES.iter().copied()))
                        .into_iter()
                        .collect(),
                    policies: Vec::new(),
                },
                (!proven).then(|| now.saturating_add(REPROBE_INTERVAL_MS)),
                held,
            )
            .map_err(|_| "import_store_failed")??;
        if created {
            Ok(AttestedImport::Imported { proven })
        } else {
            Ok(AttestedImport::AlreadyImported)
        }
    }

    /// Retry an incomplete installation proof whose durable cooldown has elapsed.
    pub fn reprobe(
        &self,
        store: &PlexusStore,
        provider: &dyn HandleCredentialProvider,
        reader: &dyn InstallationReader,
        now: i64,
        held: &dyn Fn() -> bool,
    ) -> Result<bool, cortexkit_store::StoreError> {
        let item = self.inventory_handle();
        let handle = import_handle(&item);
        let next = now.saturating_add(REPROBE_INTERVAL_MS);
        let Some(claim) = store.claim_attested_probe(&handle, now, next, held)? else {
            return Ok(false);
        };
        if resolve_repositories(
            provider,
            reader,
            &item,
            claim.credential_generation,
            now,
            held,
        )
        .is_err()
        {
            return Ok(false);
        }
        store.complete_attested_probe(&handle, claim, now, held)
    }

    fn inventory_handle(&self) -> InventoryHandle {
        InventoryHandle {
            app_handle_id: self.slug.into(),
            agent_id: self.agent.into(),
            app_id: self.app_id,
            installation_id: None,
            credential_id: app_reference(self.slug),
            status: "disabled".into(),
            grants: Vec::new(),
        }
    }
}
