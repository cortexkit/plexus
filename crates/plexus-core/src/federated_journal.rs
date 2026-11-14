//! Federated deletions survive replacement of the database, not loss of both files.
//! Follow `grant_journal.rs`: fsync complete newline-delimited records before
//! committing a delete, and refuse replay of malformed newline-terminated lines.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub(crate) const NAME: &str = "federated-deletions.jsonl";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Deletion {
    pub row_id: Option<String>,
    pub card_refs: Vec<String>,
    pub deleted_at_ms: i64,
}

fn parse_record(line: &[u8]) -> Result<Deletion, String> {
    let entry: Deletion = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    if entry.row_id.as_ref().is_some_and(String::is_empty)
        || (entry.row_id.is_none() && entry.card_refs.is_empty())
        || entry.card_refs.iter().any(String::is_empty)
    {
        return Err("a deletion must name a row or card refs, with no empty ids or refs".into());
    }
    Ok(entry)
}

/// Reject malformed complete lines before any database writes. An unparseable,
/// unterminated tail was never acknowledged and is skipped; a parseable tail is
/// applied conservatively, just as in the local revocation journal.
pub(crate) fn scan(
    path: &Path,
    mut visit: impl FnMut(Deletion) -> Result<(), String>,
) -> Result<usize, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut count = 0;
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?
            == 0
        {
            break;
        }
        let complete = line.last() == Some(&b'\n');
        if complete {
            line.pop();
        }
        match parse_record(&line) {
            Ok(entry) => {
                visit(entry)?;
                count += 1;
            }
            Err(error) if complete => {
                return Err(format!("{} line {}: {error}", path.display(), count + 1))
            }
            Err(error) => {
                crate::diag!(warn governance: "{}: skipping an unterminated final line left by an interrupted append ({error}); it was never acknowledged", path.display())
            }
        }
    }
    Ok(count)
}

pub(crate) fn append(path: &Path, entry: &Deletion) -> rusqlite::Result<()> {
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

/// The caller holds the database writer fence. Preserve a parseable tail that
/// replay may already have applied; discard only an unparseable torn append.
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
    crate::diag!(warn governance:
        "{}: removing an unterminated final line left by an interrupted append",
        path.display()
    );
    file.set_len(keep)?;
    file.sync_all()
}

/// Replay targets only the old stored id, never its key. Fresh re-grants survive.
/// Processed refs are inserted even when the row is already absent.
pub(crate) fn apply(conn: &Connection, entry: &Deletion) -> rusqlite::Result<usize> {
    for card_ref in &entry.card_refs {
        conn.execute(
            "INSERT OR IGNORE INTO federated_processed_cards (card_ref) VALUES (?1)",
            [card_ref],
        )?;
    }
    match &entry.row_id {
        Some(id) => conn.execute("DELETE FROM federated_rows WHERE id=?1", [id]),
        None => Ok(0),
    }
}

#[cfg(test)]
#[path = "federated_journal/tests.rs"]
mod tests;
