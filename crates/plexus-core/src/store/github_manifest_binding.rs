//! Durable proposal progress and installation-presence observations. A declined
//! repository is eligible again only after a complete listing omits it and a
//! later complete listing contains it. Failed or partial lists change nothing.

use super::{append_audit_on_conn, AuditRecord, PlexusStore, StoreError};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    pub app_handle_id: String,
    pub repository: String,
    pub agent_id: String,
    pub proposal_id: Option<String>,
    pub manifest_version: Option<i64>,
    pub manifest_sha256: Option<String>,
    pub statement_b64url: Option<String>,
    pub expires_at_ms: Option<i64>,
    pub state: String,
    pub card_id: Option<String>,
    pub present: bool,
    pub revision: i64,
}

impl BindingRecord {
    pub(crate) fn observed(handle: &super::github_store::GithubHandle, repository: &str) -> Self {
        Self {
            app_handle_id: handle.app_handle_id.clone(),
            repository: repository.into(),
            agent_id: handle.agent_id.clone(),
            proposal_id: None,
            manifest_version: None,
            manifest_sha256: None,
            statement_b64url: None,
            expires_at_ms: None,
            state: "observed".into(),
            card_id: None,
            present: true,
            revision: -1,
        }
    }
}

fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BindingRecord> {
    Ok(BindingRecord {
        app_handle_id: row.get(0)?,
        repository: row.get(1)?,
        agent_id: row.get(2)?,
        proposal_id: row.get(3)?,
        manifest_version: row.get(4)?,
        manifest_sha256: row.get(5)?,
        statement_b64url: row.get(6)?,
        expires_at_ms: row.get(7)?,
        state: row.get(8)?,
        card_id: row.get(9)?,
        present: row.get(10)?,
        revision: row.get(11)?,
    })
}

pub(super) fn audit(
    conn: &Connection,
    record: &BindingRecord,
    event: &str,
) -> rusqlite::Result<()> {
    let mut audit = AuditRecord::ceremony(
        "reserved:plexus",
        Some("github"),
        None,
        event,
        "write",
        None,
    );
    audit.actor = "module".into();
    audit.agent_id = Some(record.agent_id.clone());
    audit.app_handle_id = Some(record.app_handle_id.clone());
    audit.gate = Some("manifest_binding".into());
    audit.reason_code = event.into();
    audit.request_id = record.proposal_id.clone();
    audit.args_redaction_summary = Some(format!("repository={}", record.repository));
    append_audit_on_conn(conn, &audit, None, None, None, None)
}

impl PlexusStore {
    pub fn github_manifest_handles(
        &self,
    ) -> Result<Vec<super::github_store::GithubHandle>, StoreError> {
        self.inner.with_read(|conn| {
            conn.prepare("SELECT app_handle_id,agent_id,app_id,installation_id,credential_reference,credential_generation,status,proven_at,connection_principal,connection_id FROM github_app_handle WHERE status='enabled' ORDER BY app_handle_id")?
                .query_map([], |r| Ok(super::github_store::GithubHandle {
                    app_handle_id:r.get(0)?, agent_id:r.get(1)?, app_id:r.get(2)?, installation_id:r.get(3)?,
                    credential_reference:r.get(4)?, credential_generation:r.get(5)?, status:r.get(6)?, proven_at:r.get(7)?,
                    connection_principal:r.get(8)?, connection_id:r.get(9)?,
                }))?.collect()
        })
    }

    pub fn github_manifest_repository_handle(
        &self,
        repository: &str,
    ) -> Result<Option<String>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT app_handle_id FROM github_repo_binding WHERE repository=?1",
                [repository],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn github_manifest_bindings(&self) -> Result<Vec<BindingRecord>, StoreError> {
        self.inner.with_read(|conn| {
            conn.prepare("SELECT app_handle_id,repository,agent_id,proposal_id,manifest_version,manifest_sha256,statement_b64url,expires_at_ms,state,card_id,present,revision FROM github_manifest_binding ORDER BY app_handle_id,repository")?
                .query_map([], row)?.collect()
        })
    }

    pub fn observe_github_manifest_installation(
        &self,
        handle: &super::github_store::GithubHandle,
        repositories: &[String],
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            // Mark only actual removals. A full but unchanged list must not
            // reset a declined proposal or invalidate in-flight progress.
            let mut statement = conn.prepare("SELECT repository FROM github_manifest_binding WHERE app_handle_id=?1 AND present=1")?;
            let old: Vec<String> = statement.query_map([&handle.app_handle_id], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            for repository in old {
                if !repositories.contains(&repository) {
                    conn.execute("UPDATE github_manifest_binding SET present=0,revision=revision+1 WHERE app_handle_id=?1 AND repository=?2", params![handle.app_handle_id, repository])?;
                }
            }
            for repository in repositories {
                conn.execute("UPDATE github_manifest_binding SET agent_id=?3,proposal_id=NULL,manifest_version=NULL,manifest_sha256=NULL,statement_b64url=NULL,expires_at_ms=NULL,state='observed',card_id=NULL,present=1,revision=revision+1
                    WHERE app_handle_id=?1 AND repository=?2 AND present=0", params![handle.app_handle_id, repository, handle.agent_id])?;
            }
            Ok(())
        })
    }

    /// Compare-and-set progress and its audit event in one transaction. The
    /// revision also fences answers or readiness read before a remove/re-add.
    pub fn save_github_manifest_binding(
        &self,
        record: &BindingRecord,
        event: Option<&str>,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let changed = if record.revision == -1 {
                conn.execute("INSERT INTO github_manifest_binding(app_handle_id,repository,agent_id,proposal_id,manifest_version,manifest_sha256,statement_b64url,expires_at_ms,state,card_id,present,revision)
                    SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,0
                    WHERE EXISTS(SELECT 1 FROM github_app_handle WHERE app_handle_id=?1 AND agent_id=?3 AND status='enabled')
                    ON CONFLICT(app_handle_id,repository) DO NOTHING",
                    params![record.app_handle_id,record.repository,record.agent_id,record.proposal_id,record.manifest_version,record.manifest_sha256,record.statement_b64url,record.expires_at_ms,record.state,record.card_id])? == 1
            } else { conn.execute("UPDATE github_manifest_binding SET proposal_id=?4,manifest_version=?5,manifest_sha256=?6,statement_b64url=?7,expires_at_ms=?8,state=?9,card_id=?10,revision=revision+1
                WHERE app_handle_id=?1 AND repository=?2 AND revision=?3 AND present=1 AND agent_id=?11",
                params![record.app_handle_id, record.repository, record.revision, record.proposal_id, record.manifest_version, record.manifest_sha256, record.statement_b64url, record.expires_at_ms, record.state, record.card_id, record.agent_id])? == 1 };
            if changed {
                if let Some(event) = event { audit(conn, record, event)?; }
            }
            Ok(changed)
        })
    }
}

pub(super) fn finish_bind(conn: &Connection, record: &BindingRecord) -> rusqlite::Result<()> {
    let changed = conn.execute("UPDATE github_manifest_binding SET state='bound',revision=revision+1
        WHERE app_handle_id=?1 AND repository=?2 AND revision=?3 AND present=1 AND state='awaiting_active'
        AND manifest_version=?4 AND manifest_sha256=?5 AND agent_id=?6
        AND EXISTS(SELECT 1 FROM github_app_handle h WHERE h.app_handle_id=?1 AND h.agent_id=?6 AND h.status='enabled')",
        params![record.app_handle_id, record.repository, record.revision, record.manifest_version, record.manifest_sha256, record.agent_id])?;
    if changed != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    audit(conn, record, "github_manifest_bound")
}

#[cfg(test)]
#[path = "github_manifest_binding_tests.rs"]
mod tests;
