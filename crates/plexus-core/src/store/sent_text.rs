use super::*;
use crate::gmail::vault::Sealed;

pub struct SentTextRow {
    pub row_id: String,
    pub connection_id: String,
    pub recipient_hash: String,
    pub sealed: Sealed,
}

impl PlexusStore {
    /// First creation pins the verified mailbox. Rebinding never silently
    /// changes it: a new Google login must still represent exactly this mailbox.
    #[cfg(any(test, feature = "test-support"))]
    pub fn pin_gmail_mailbox(
        &self,
        owner: &str,
        connection: &str,
        mailbox: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("INSERT INTO gmail_accounts(principal,connection_id,mailbox) VALUES (?1,?2,?3) ON CONFLICT(principal,connection_id) DO NOTHING", [owner,connection,mailbox])?;
            Ok(())
        })
    }
    pub fn gmail_mailbox(
        &self,
        owner: &str,
        connection: &str,
    ) -> Result<Option<String>, StoreError> {
        self.inner.with_read(|conn| {
            conn.query_row(
                "SELECT mailbox FROM gmail_accounts WHERE principal=?1 AND connection_id=?2",
                [owner, connection],
                |r| r.get(0),
            )
            .optional()
        })
    }
    /// A durable, owner-scoped slot also enforces spacing across worker threads
    /// and daemon restarts. A failed send still spends its slot.
    pub fn claim_gmail_send(
        &self,
        owner: &str,
        connection: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.inner.with_conn_fenced(|conn| Ok(conn.execute("UPDATE gmail_accounts SET next_send_ms=?3+1000 WHERE principal=?1 AND connection_id=?2 AND next_send_ms<=?3", rusqlite::params![owner,connection,now])? == 1))
    }
    pub fn finish_gmail_send(
        &self,
        owner: &str,
        connection: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| { conn.execute("UPDATE gmail_accounts SET next_send_ms=MAX(next_send_ms,?3+1000) WHERE principal=?1 AND connection_id=?2",rusqlite::params![owner,connection,now])?;Ok(()) })
    }
    pub fn save_sent_text(
        &self,
        owner: &str,
        row: &SentTextRow,
        now: i64,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            let written=conn.execute("INSERT INTO sent_text(row_id,principal,connection_id,recipient_hash,key_id,enc,ciphertext,expires_at_ms,created_at_ms) SELECT ?1,?2,?3,?4,?5,?6,?7,?8+retention_days*86400000,?8 FROM sent_text_settings WHERE singleton=1", rusqlite::params![row.row_id,owner,row.connection_id,row.recipient_hash,row.sealed.key_id,row.sealed.enc,row.sealed.ciphertext,now])?;
            if written != 1 { return Err(rusqlite::Error::QueryReturnedNoRows); }
            Ok(())
        })
    }
    pub fn sent_text(
        &self,
        owner: &str,
        row_id: &str,
        now: i64,
    ) -> Result<Option<SentTextRow>, StoreError> {
        self.inner.with_read(|conn| conn.query_row("SELECT row_id,connection_id,recipient_hash,key_id,enc,ciphertext FROM sent_text WHERE principal=?1 AND row_id=?2 AND expires_at_ms>?3", rusqlite::params![owner,row_id,now], |r| Ok(SentTextRow { row_id:r.get(0)?,connection_id:r.get(1)?,recipient_hash:r.get(2)?,sealed:Sealed { key_id:r.get(3)?,enc:r.get(4)?,ciphertext:r.get(5)? } })).optional())
    }
    pub fn audit_sent_text_read(
        &self,
        owner: &str,
        row_id: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("INSERT INTO audit_journal(principal,actor,acting_principal,action,risk,severity,decision,reason_code,gate,args_redaction_summary,ts) VALUES (?1,'direct','direct','sent_text_read','read','S3','allow',?2,'ceremony',?3,?4)", rusqlite::params![owner,reason,serde_json::json!({"row_id":row_id}).to_string(),now_ms()])?;
            Ok(())
        })
    }
    pub fn set_sent_text_retention(&self, days: i64) -> Result<(), StoreError> {
        self.inner.with_conn_fenced(|conn| {
            conn.execute("UPDATE sent_text_settings SET retention_days=?1 WHERE singleton=1", [days])?;
            conn.execute("UPDATE sent_text SET expires_at_ms=MIN(expires_at_ms,created_at_ms+?1*86400000)", [days])?;
            conn.execute("INSERT INTO audit_journal(principal,actor,acting_principal,action,risk,severity,decision,reason_code,gate,args_redaction_summary,ts) VALUES ('direct','direct','direct','sent_text_retention','write','S3','allow','applied','ceremony',?1,?2)",rusqlite::params![serde_json::json!({"days":days}).to_string(),now_ms()])?;
            Ok(())
        })
    }
    pub fn prune_sent_text(&self, now: i64) -> Result<usize, StoreError> {
        self.inner.with_conn_fenced(|conn| conn.execute("DELETE FROM sent_text WHERE row_id IN (SELECT row_id FROM sent_text WHERE expires_at_ms<=?1 ORDER BY expires_at_ms LIMIT 500)", [now]))
    }
}

#[cfg(test)]
#[path = "sent_text_tests.rs"]
mod tests;
