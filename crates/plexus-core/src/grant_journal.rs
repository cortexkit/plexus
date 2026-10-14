//! Restore-survival revocations beside, never inside, the replaceable database.
//! Total machine loss is not covered: restoring both files from an older generation
//! loses revocations newer than that generation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub(crate) const NAME: &str = "grant-revocations.jsonl";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revocation {
    pub principal: String,
    pub grant_id: String,
    pub revoked_at_ms: i64,
}

fn parse_record(line: &[u8]) -> Result<Revocation, String> {
    let entry: Revocation = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    if entry.principal.is_empty() || entry.grant_id.is_empty() {
        return Err("principal and grant_id must not be empty".into());
    }
    Ok(entry)
}

/// Replay grant revocations, rejecting any malformed newline-terminated record.
/// Restoring a database must not make a revoked grant usable again. Skipping
/// an unreadable revocation could do exactly that, so reject the file and
/// prevent startup rather than silently omitting the revocation.
///
/// This strict reader relies on `append` writing complete records. It builds
/// each record and its newline in one buffer and passes it to `write_all` on
/// a file opened for append. The revoking transaction holds the database write
/// lock while appending. Writers must preserve these record boundaries or the
/// reader could reject an otherwise valid journal at startup.
///
/// A crash or full disk can interrupt an append and leave a final line without
/// a newline. The revoking transaction deletes the grant only after the append
/// succeeds, so an incomplete record need not represent a completed revocation.
/// Skip an unparseable final line with a warning. Apply a parseable final line
/// because revoking an additional grant cannot restore revoked authority.
/// Require every newline-terminated record to parse.
pub(crate) fn read(path: &Path) -> Result<Vec<Revocation>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let (complete, torn_tail) = split_torn_tail(&bytes);
    let mut entries = complete
        .into_iter()
        .flat_map(|complete| complete.split(|byte| *byte == b'\n'))
        .enumerate()
        .map(|(index, line)| {
            parse_record(line).map_err(|e| format!("{} line {}: {e}", path.display(), index + 1))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(tail) = torn_tail {
        match parse_record(tail) {
            Ok(entry) => entries.push(entry),
            Err(error) => eprintln!(warn governance:
                "{}: skipping an unterminated final line left by an interrupted append ({error}); it was never acknowledged",
                path.display()
            ),
        }
    }
    Ok(entries)
}

/// Split the journal into its newline-terminated lines (without the final
/// newline; `None` when there are none) and an unterminated final line, if
/// there is one.
fn split_torn_tail(bytes: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    match bytes.iter().rposition(|byte| *byte == b'\n') {
        _ if bytes.is_empty() => (None, None),
        Some(last) if last + 1 == bytes.len() => (Some(&bytes[..last]), None),
        Some(last) => (Some(&bytes[..last]), Some(&bytes[last + 1..])),
        None => (None, Some(bytes)),
    }
}

pub(crate) fn ensure(path: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.sync_all()?;
    // Persist the directory entry as well as the empty file before advertising it.
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()
}

pub(crate) fn append(path: &Path, entry: &Revocation) -> rusqlite::Result<()> {
    let persist = || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut bytes = serde_json::to_vec(entry)?;
        bytes.push(b'\n');
        drop_torn_tail(path)?;
        let mut file = OpenOptions::new().append(true).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    };
    persist().map_err(rusqlite::Error::ToSqlConversionFailure)
}

/// Repair an interrupted append before writing the next record. A parseable
/// tail may already have revoked a grant during replay, so preserve it by
/// terminating its line. Only an unparseable tail can be discarded. The caller
/// holds the database write lock to serialize journal writers.
fn drop_torn_tail(path: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    // Normal appends read one byte, regardless of the number of old records.
    // Only an interrupted final record requires scanning backwards to its start.
    let mut position = length;
    let mut chunks = Vec::new();
    let keep = loop {
        let count = position.min(4096) as usize;
        position -= count as u64;
        file.seek(SeekFrom::Start(position))?;
        let mut chunk = vec![0; count];
        file.read_exact(&mut chunk)?;
        if let Some(newline) = chunk.iter().rposition(|byte| *byte == b'\n') {
            chunks.push(chunk[newline + 1..].to_vec());
            break position + newline as u64 + 1;
        }
        chunks.push(chunk);
        if position == 0 {
            break 0;
        }
    };
    let tail: Vec<u8> = chunks.into_iter().rev().flatten().collect();
    if parse_record(&tail).is_ok() {
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"\n")?;
        return file.sync_all();
    }
    eprintln!(warn governance:
        "{}: removing an unterminated final line left by an interrupted append",
        path.display()
    );
    file.set_len(keep)?;
    file.sync_all()
}

/// Called inside the caller's transaction, retaining the queryable snapshot too.
/// Grant minting chooses a fresh id, so replay cannot revoke a later re-grant.
pub(crate) fn apply(conn: &Connection, entry: &Revocation) -> rusqlite::Result<usize> {
    apply_as(conn, entry, &entry.principal)
}

/// Retain the caller's actor in the SQL snapshot without changing journal bytes.
/// Restore replay uses the owner when the original actor is unavailable.
pub(crate) fn apply_as(
    conn: &Connection,
    entry: &Revocation,
    actor: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO grant_revocations
            (revocation_id, grant_id, principal, connection_id, grantee_principal,
             authority_kind, risk_ceiling, action_selectors, expires_at, generation,
             created_at_ms, revoked_at_ms, revoked_by)
         SELECT ?3, grant_id, principal, connection_id, grantee_principal,
                authority_kind, risk_ceiling, action_selectors, expires_at, generation,
                created_at_ms, ?4, ?5
         FROM grants WHERE principal = ?1 AND grant_id = ?2",
        (
            &entry.principal,
            &entry.grant_id,
            crate::storage::new_id("revocation"),
            entry.revoked_at_ms,
            actor,
        ),
    )?;
    conn.execute(
        "DELETE FROM grants WHERE principal = ?1 AND grant_id = ?2",
        (&entry.principal, &entry.grant_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{GrantInput, PlexusStore};
    use crate::test_scratch::Scratch;
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    fn record(grant_id: &str) -> String {
        format!(r#"{{"principal":"direct","grant_id":"{grant_id}","revoked_at_ms":1}}"#)
    }

    fn journal(label: &str, contents: &str) -> Scratch {
        let scratch = Scratch::file(label, NAME);
        std::fs::write(scratch.path(), contents).expect("write journal");
        scratch
    }

    fn grant_ids(entries: &[Revocation]) -> Vec<&str> {
        entries
            .iter()
            .map(|entry| entry.grant_id.as_str())
            .collect()
    }

    #[test]
    fn a_torn_unparseable_final_line_is_skipped() {
        let scratch = journal(
            "journal-torn-tail",
            &format!(
                "{}\n{{\"principal\":\"direct\",\"grant_id\":\"g-2\",\"rev",
                record("g-1")
            ),
        );
        let entries = read(scratch.path()).expect("a torn tail does not refuse the journal");
        assert_eq!(grant_ids(&entries), ["g-1"]);
        // A journal holding nothing but a torn first record is empty, not broken.
        let only_torn = journal("journal-only-torn", "{\"principal\":\"di");
        assert!(read(only_torn.path()).expect("readable").is_empty());
    }

    #[test]
    fn a_malformed_line_that_ends_in_a_newline_refuses_the_journal() {
        for contents in [
            format!("{}\nnot json\n{}\n", record("g-1"), record("g-2")),
            format!("{}\nnot json\n", record("g-1")),
            format!("not json\n{}", record("g-2")),
            format!("{}\n\n", record("g-1")),
        ] {
            let scratch = journal("journal-malformed", &contents);
            assert!(
                read(scratch.path()).is_err(),
                "a whole malformed line must refuse the journal: {contents:?}"
            );
        }
    }

    #[test]
    fn an_unterminated_final_line_that_parses_is_honoured() {
        let scratch = journal(
            "journal-whole-tail",
            &format!("{}\n{}", record("g-1"), record("g-2")),
        );
        let entries = read(scratch.path()).expect("readable");
        assert_eq!(grant_ids(&entries), ["g-1", "g-2"]);
    }

    #[test]
    fn append_preserves_a_parseable_unterminated_revocation() {
        for contents in [
            record("g-2"),
            format!("{}\n{}", record("g-1"), record("g-2")),
        ] {
            let scratch = journal("journal-append-after-whole-tail", &contents);
            let before = read(scratch.path()).expect("replay before append");
            append(
                scratch.path(),
                &Revocation {
                    principal: "direct".into(),
                    grant_id: "g-3".into(),
                    revoked_at_ms: 3,
                },
            )
            .expect("append");
            let after = read(scratch.path()).expect("replay after append");
            let mut expected = grant_ids(&before);
            expected.push("g-3");
            assert_eq!(
                grant_ids(&after),
                expected,
                "append lost an applied revocation"
            );
        }
    }

    #[test]
    fn append_after_a_torn_tail_writes_the_record_on_its_own_line() {
        let scratch = journal(
            "journal-append-after-torn",
            &format!("{}\n{{\"principal\":\"dir", record("g-1")),
        );
        append(
            scratch.path(),
            &Revocation {
                principal: "direct".into(),
                grant_id: "g-3".into(),
                revoked_at_ms: 3,
            },
        )
        .expect("append");
        let contents = std::fs::read_to_string(scratch.path()).expect("read journal");
        assert_eq!(contents.lines().count(), 2, "{contents:?}");
        assert!(contents.ends_with('\n'));
        let entries =
            read(scratch.path()).expect("the journal stays readable after the next revoke");
        assert_eq!(grant_ids(&entries), ["g-1", "g-3"]);
    }

    /// The store replays the journal when it opens. A torn tail left by a
    /// crash during a revoke must not stop it from opening, and the grant that
    /// revoke named stays live, as its caller was told.
    #[test]
    fn a_store_whose_journal_has_a_torn_tail_still_opens_and_keeps_the_grant() {
        let scratch = Scratch::database("journal-torn-boot");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "journal-torn-boot".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: scratch.path().to_string_lossy().into_owned(),
            },
        };
        let journal_path = scratch.path().with_file_name(NAME);
        {
            let store = PlexusStore::open(&descriptor).expect("open store");
            store
                .insert_connection(
                    "direct",
                    "conn-1",
                    "mock",
                    "active",
                    &serde_json::json!({"required": [], "write_enabling": []}),
                )
                .expect("connection");
            for grant_id in ["g-revoked", "g-live"] {
                store
                    .insert_grant(&GrantInput {
                        grant_id: grant_id.into(),
                        principal: "direct".into(),
                        connection_id: "conn-1".into(),
                        grantee_principal: "direct".into(),
                        risk_ceiling: "read".into(),
                        action_selectors: vec!["*".into()],
                        authority_kind: "invoke".into(),
                        expires_at: None,
                    })
                    .expect("grant");
            }
            assert!(store.revoke_grant("direct", "g-revoked").expect("revoke"));
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&journal_path)
            .expect("open journal");
        file.write_all(br#"{"principal":"direct","grant_id":"g-live","rev"#)
            .expect("tear the tail");
        drop(file);

        let _store =
            PlexusStore::open(&descriptor).expect("a torn tail must not stop the store opening");
        let live = |grant_id: &str| -> bool {
            rusqlite::Connection::open(scratch.path())
                .expect("open database")
                .query_row(
                    "SELECT COUNT(*) FROM grants WHERE grant_id = ?1",
                    [grant_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count")
                == 1
        };
        assert!(
            live("g-live"),
            "the unacknowledged revoke must not take effect"
        );
        assert!(!live("g-revoked"));
    }
}
