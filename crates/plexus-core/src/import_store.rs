//! Offline cutover: preserve durable authority and undelivered work, not spent authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cortexkit_store::{open_sqlite, StorageDescriptor};
use cortexkit_store_types::{Isolation, StorageBackend};
use rusqlite::{params, types::Value, Connection, OptionalExtension};

use crate::storage::{CATALOG_PRINCIPAL, MIGRATIONS};

type Result<T> = std::result::Result<T, String>;
type Record = BTreeMap<String, Value>;

/// `recomputed` counts carried rows with rewritten hashes, not hash columns.
/// Thus read = carried + scrubbed, and recomputed <= carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableSummary {
    pub table: String,
    pub read: u64,
    pub carried: u64,
    pub scrubbed: u64,
    pub recomputed: u64,
}

const TABLES: &[&str] = &[
    "app_manifests",
    "connections",
    "recipient_allowlist",
    "grants",
    "policies",
    "catalog_actions",
    "probe_subscriptions",
    "trigger_subscriptions",
    "trigger_events",
    // Publishing markers for the events carried above, so an unacked event
    // that was not yet published is still published from the new store.
    "event_outbox",
    "event_outbox_failures",
    // Where the webhook relay stream was committed, so delivery resumes
    // instead of replaying or skipping.
    "relay_cursor",
    // GitHub App handles, their repository bindings and their bot-request
    // receipts. The handle carries authority; a receipt is what stops a
    // replayed request nonce from acting twice.
    "github_app_handle",
    "github_repo_binding",
    "github_bot_receipt",
    "action_requests",
    "consent_call_keys",
    // Writes whose outcome is still being reconciled (with the arguments the
    // read-back needs), and the settled results callers can still read, which
    // keep only the status and never the arguments.
    "pending_write_reconciliations",
    "write_reconciliation_results",
    // Operator-set per-minute limits for each web search backend.
    "web_search_limits",
    // The answer cursor from when plexus read card answers from prefrontal.
    // Nothing reads or advances it now (Cingulate answers each held call
    // directly), but the table stays because migrations are additive, so an
    // import copies it like every other table.
    "elicitation_answers_cursor",
    // Repository ids already resolved for the carried watches. A watch
    // detects a deleted-and-recreated repository by comparing against the
    // recorded id, which an empty cache would forget.
    "github_repo_id_cache",
    // The trailing hour's GitHub Actions request reservations. The token's
    // hourly budget is spent at GitHub whatever store records it, so the new
    // store must count the same hour; rows older than an hour are dropped by
    // the next admission anyway.
    "github_actions_quota",
    // Preserve the cumulative counts reported by the health interface: events
    // dropped on deletion and relay drops by reason. Switching stores must not
    // reset the reported history to zero.
    "event_outbox_counters",
    "reservations",
    "binding_tickets",
    "audit_journal",
];

/// Tables of the current schema that `import_store` deliberately does not
/// copy, each with the reason. Every table a migration creates must be in
/// [`TABLES`] or here; a test fails on a table that is in neither. Read only
/// by that test: the import has nothing to do for these tables.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const EXCLUDED_TABLES: &[(&str, &str)] = &[
    (
        "cortexkit_schema_version",
        "the migration ledger belongs to the destination, which records its own migrations",
    ),
    (
        "cortexkit_fence",
        "the writer fence belongs to the destination file and its own lease",
    ),
    ("sqlite_sequence", "SQLite's own AUTOINCREMENT bookkeeping"),
    (
        "github_repo_binding_generation",
        "a fence counter compared only against snapshots held in a running module; a cutover \
         starts from a stopped module, the destination's migration creates the counter, and \
         every carried binding insert advances it",
    ),
    (
        "grant_revocations",
        "revocation snapshots are audit evidence and, like audit_journal, are not carried; the \
         revocation journal beside the store stays the durable record and is replayed on import",
    ),
];

fn descriptor(path: &Path) -> Result<StorageDescriptor> {
    Ok(StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "plexus".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_str().ok_or("store path is not UTF-8")?.to_owned(),
        },
    })
}

struct TemporaryDirectory(PathBuf);
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Import into a distinct, previously absent path. No key is loaded or moved.
/// The source is opened by cortexkit-store, whose path-derived lease refuses a
/// running module before SQLite reads the database. No source migrations run.
pub fn import_store(from: &Path, to: &Path) -> Result<Vec<TableSummary>> {
    let from = from
        .canonicalize()
        .map_err(|e| format!("source {}: {e}", from.display()))?;
    if !from.is_file() {
        return Err(format!("source {} is not a file", from.display()));
    }
    let parent = to
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|e| format!("destination directory: {e}"))?;
    let to = parent.join(to.file_name().ok_or("destination needs a filename")?);
    if to.symlink_metadata().is_ok() {
        return Err(format!(
            "destination {} already exists; choose a new path",
            to.display()
        ));
    }
    let revocations = crate::grant_journal::read(&parent.join(crate::grant_journal::NAME))?;
    let source = open_sqlite(&descriptor(&from)?).map_err(|e| {
        format!("cannot acquire source store: {e}; stop the plexus module before import-store")
    })?;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let scratch = parent.join(format!(
        ".plexus-import-{}-{}-{}",
        std::process::id(),
        crate::storage::now_ms(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&scratch)
        .map_err(|e| format!("create import staging directory: {e}"))?;
    let temporary = TemporaryDirectory(scratch);
    let staged = temporary.0.join("store.db");
    let destination = open_sqlite(&descriptor(&staged)?).map_err(|e| e.to_string())?;
    destination
        .migrate("plexus", MIGRATIONS)
        .map_err(|e| e.to_string())?;
    // Nested results retain row-specific errors without changing the store's SQL error API.
    let summary = source
        .with_conn(|old| {
            old.execute_batch("PRAGMA query_only = ON; BEGIN")?;
            let result = destination.with_conn(|new| Ok(copy_store(old, new, &revocations)));
            old.execute_batch("ROLLBACK")?;
            Ok(result)
        })
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())??;
    // A published SQLite file must not depend on sidecars in the staging directory.
    destination
        .with_conn(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
        })
        .map_err(|e| e.to_string())?;
    drop(destination);
    std::fs::File::open(&staged)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    // Reserve the final name with a hard link to the COMPLETE database. Unlike
    // an exists-then-rename check this cannot overwrite a concurrent creator.
    // Both names contain the same complete file even if the final rename fails.
    std::fs::hard_link(&staged, &to)
        .map_err(|e| format!("publish {} without overwriting: {e}", to.display()))?;
    std::fs::remove_file(&staged)
        .map_err(|e| format!("remove staging link {}: {e}", staged.display()))?;
    std::fs::File::open(&parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("sync destination directory: {e}"))?;
    Ok(summary)
}

fn copy_store(
    old: &Connection,
    new: &Connection,
    revocations: &[crate::grant_journal::Revocation],
) -> Result<Vec<TableSummary>> {
    let tx = new.unchecked_transaction().map_err(|e| e.to_string())?;
    let mut summaries = Vec::new();
    for &table in TABLES {
        // An older store may lack this table. Skip it without creating missing
        // rows. In particular, do not infer permitted targets from grants or
        // past approvals when the table of explicitly permitted targets is absent.
        if old
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .is_none()
        {
            summaries.push(TableSummary {
                table: table.into(),
                ..Default::default()
            });
            continue;
        }
        let mut summary = TableSummary {
            table: table.into(),
            ..Default::default()
        };
        summary.read = old
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .map_err(|e| format!("{table}: {e}"))?;
        let predicate = match table {
            "reservations" | "binding_tickets" | "audit_journal" => {
                summary.scrubbed = summary.read;
                summaries.push(summary);
                continue;
            }
            // Every event row is copied, acknowledged or not. A stored event's
            // payload and hash are how a later poll recognizes the same item
            // version as a duplicate, so dropping acknowledged rows would let
            // the new store record those items again.
            "trigger_events" => "",
            "event_outbox" => " WHERE event_id IN (SELECT event_id FROM trigger_events)",
            "event_outbox_failures" => " WHERE event_key IN (SELECT event_key FROM event_outbox WHERE event_id IN (SELECT event_id FROM trigger_events))",
            "action_requests" => {
                let receipts: bool = old.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='github_bot_receipt')", [], |row| row.get(0)).map_err(|e| e.to_string())?;
                if receipts { " WHERE reconciliation_status IS NOT NULL OR request_id IN (SELECT action_request_id FROM github_bot_receipt WHERE action_request_id IS NOT NULL)" }
                else { " WHERE reconciliation_status IS NOT NULL" }
            },
            "consent_call_keys" => " WHERE request_id IN (SELECT request_id FROM action_requests WHERE reconciliation_status IS NOT NULL)",
            _ => "",
        };
        let mut statement = old
            .prepare(&format!("SELECT * FROM {table}{predicate}"))
            .map_err(|e| format!("{table}: {e}"))?;
        let columns = statement
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut rows = statement.query([]).map_err(|e| format!("{table}: {e}"))?;
        while let Some(row) = rows.next().map_err(|e| format!("{table}: {e}"))? {
            let mut record = Record::new();
            for (i, column) in columns.iter().enumerate() {
                // SQLite values preserve BLOB, NULL, and empty BLOB distinctly.
                record.insert(
                    column.clone(),
                    row.get(i).map_err(|e| format!("{table}.{column}: {e}"))?,
                );
            }
            let id = identity(table, &record);
            let recomputed =
                transform(old, &tx, table, &mut record).map_err(|e| format!("{id}: {e}"))?;
            // Legacy imports have project labels but no provenance column.
            // Mark those labels as operator-written to preserve their meaning.
            let mut insert_columns = columns.clone();
            if table == "trigger_subscriptions" && !record.contains_key("project_source") {
                let source = match record.get("project_id") {
                    Some(Value::Text(_)) => Value::Text("hand".into()),
                    _ => Value::Null,
                };
                record.insert("project_source".into(), source);
                insert_columns.push("project_source".into());
            }
            let names = insert_columns
                .iter()
                .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(",");
            let placeholders = vec!["?"; insert_columns.len()].join(",");
            tx.execute(
                &format!("INSERT INTO {table} ({names}) VALUES ({placeholders})"),
                rusqlite::params_from_iter(insert_columns.iter().map(|c| &record[c])),
            )
            .map_err(|e| format!("{id}: {e}"))?;
            summary.carried += 1;
            summary.recomputed += u64::from(recomputed);
        }
        summary.scrubbed = summary.read - summary.carried;
        summaries.push(summary);
    }
    // Probe subscriptions are copied before their corresponding trigger rows,
    // whose pins are computed from the probe return schemas. Validate that each
    // probe has a matching trigger row after both tables have been copied.
    let orphan: Option<String> = tx.query_row("SELECT p.subscription_id FROM probe_subscriptions p LEFT JOIN trigger_subscriptions s ON s.subscription_id=p.subscription_id AND s.cursor_kind='probe' WHERE s.subscription_id IS NULL LIMIT 1", [], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
    if let Some(id) = orphan {
        return Err(format!(
            "probe_subscriptions {id}: missing probe trigger subscription"
        ));
    }
    for entry in revocations {
        let removed = crate::grant_journal::apply(&tx, entry).map_err(|e| e.to_string())?;
        if let Some(summary) = summaries.iter_mut().find(|s| s.table == "grants") {
            summary.carried -= removed as u64;
            summary.scrubbed += removed as u64;
        }
    }
    // A source from before recipient lists had an owner carries rows with no
    // principal; give each owner of the connection id its own copy, exactly as
    // the schema migration does for a store upgraded in place.
    tx.execute_batch(crate::storage::RECIPIENT_ALLOWLIST_PRINCIPAL_BACKFILL)
        .map_err(|e| format!("recipient_allowlist owner backfill: {e}"))?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(summaries)
}

fn text<'a>(row: &'a Record, key: &str) -> Result<&'a str> {
    match row.get(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(format!("{key} must be text")),
    }
}

fn identity(table: &str, row: &Record) -> String {
    let keys = match table {
        "app_manifests" => vec!["principal", "key"],
        "catalog_actions" => vec!["principal", "connection_id", "name"],
        "connections" => vec!["principal", "connection_id"],
        "recipient_allowlist" => vec!["connection_id", "recipient"],
        "grants" => vec!["principal", "grant_id"],
        "policies" => vec!["principal", "policy_id"],
        "action_requests" => vec!["principal", "request_id"],
        "consent_call_keys" => vec!["requester", "call_key"],
        "trigger_events" => vec!["event_id"],
        "event_outbox" => vec!["event_key"],
        "event_outbox_failures" => vec!["event_key", "version"],
        "relay_cursor" => vec!["source"],
        "github_app_handle" => vec!["app_handle_id"],
        "github_repo_binding" => vec!["repository"],
        "github_bot_receipt" => vec!["agent_id", "request_nonce"],
        "pending_write_reconciliations" | "write_reconciliation_results" => {
            vec!["principal", "request_id"]
        }
        "web_search_limits" => vec!["backend"],
        "github_repo_id_cache" => vec!["repo"],
        "github_actions_quota" => vec!["reservation_id"],
        "event_outbox_counters" => vec!["name"],
        "elicitation_answers_cursor" => vec![],
        _ => vec!["subscription_id"],
    };
    format!(
        "{table} [{}]",
        keys.iter()
            .map(|k| match row.get(*k) {
                Some(Value::Integer(version))
                    if table == "event_outbox_failures" && *k == "version" =>
                    version.to_string(),
                _ => text(row, k).unwrap_or("<invalid id>").to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn hash(json: &str) -> Result<String> {
    let value = serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    crate::jcs::jcs_sha256(&value).map_err(|e| e.to_string())
}

fn action_hash(new: &Connection, row: &Record) -> Result<String> {
    new.query_row("SELECT schema_hash FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3", params![text(row, "principal")?, text(row, "connection_id")?, text(row, "action")?], |r| r.get(0)).optional().map_err(|e| e.to_string())?.ok_or_else(|| format!("missing catalog action {}", text(row, "action").unwrap_or("<invalid>")))
}

fn transform(old: &Connection, new: &Connection, table: &str, row: &mut Record) -> Result<bool> {
    for column in [
        "manifest_json",
        "transport_config",
        "resource_filters",
        "health_state",
        "ceiling_selectors",
        "action_selectors",
        "rate_limit_json",
        "trust_rule_json",
        "schema_json",
        "reviewed_schema_json",
        "reconciliation_json",
        "cursor_state",
        "fixed_args",
        "actor_source_json",
        "payload",
        "actor_logins",
        "args_snapshot",
        "actions",
        "return_schema",
    ] {
        if let Some(value) = row.get(column) {
            if !matches!(value, Value::Null) {
                let body = text(row, column)?;
                serde_json::from_str::<serde_json::Value>(body)
                    .map_err(|e| format!("{column}: invalid JSON: {e}"))?;
            }
        }
    }
    if table == "connections" {
        // Manifests are ingested once per host and shared by every principal's
        // connections, so resolve the app key in the system-scoped catalog.
        let exists: bool = new
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM app_manifests WHERE principal=?1 AND key=?2)",
                params![CATALOG_PRINCIPAL, text(row, "app_key")?],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err("missing app manifest".into());
        }
        if !matches!(
            row.get("credential_binding"),
            Some(Value::Blob(_) | Value::Null)
        ) {
            return Err("credential_binding must be BLOB or NULL".into());
        }
        if let Some(Value::Blob(binding)) = row.get("credential_binding") {
            if !crate::storage::is_reference_binding(binding) {
                if text(row, "status")? != "revoked" {
                    return Err(crate::storage::removed_binding_error(text(
                        row,
                        "connection_id",
                    )?));
                }
                row.insert("credential_binding".into(), Value::Null);
            }
        }
    } else if table == "recipient_allowlist" {
        let exists: bool = new
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM connections WHERE connection_id=?1)",
                [text(row, "connection_id")?],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err("missing connection".into());
        }
    } else if table == "github_app_handle" {
        let exists: bool = new
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM connections WHERE principal=?1 AND connection_id=?2)",
                params![
                    text(row, "connection_principal")?,
                    text(row, "connection_id")?
                ],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err("missing connection".into());
        }
    } else if table == "write_reconciliation_results"
        && text(row, "connection_id")?.is_empty()
        && text(row, "status")? == "unreconcilable"
    {
        // A deleted handle can leave an unreconcilable result with no connection
        // ID. It records the uncertain write, but cannot authorize another call.
    } else if row.contains_key("connection_id") {
        let exists: bool = new
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM connections WHERE principal=?1 AND connection_id=?2)",
                params![text(row, "principal")?, text(row, "connection_id")?],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err("missing connection".into());
        }
    }
    match table {
        "catalog_actions" => {
            row.insert(
                "schema_hash".into(),
                Value::Text(hash(text(row, "schema_json")?)?),
            );
        }
        "trigger_subscriptions" => {
            let schema_hash = if text(row, "cursor_kind")? == "probe" {
                let schema: String = new
                    .query_row(
                        "SELECT return_schema FROM probe_subscriptions WHERE subscription_id=?1",
                        [text(row, "subscription_id")?],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?
                    .ok_or("missing probe return_schema")?;
                hash(&schema)?
            } else {
                action_hash(new, row)?
            };
            row.insert("schema_hash".into(), Value::Text(schema_hash));
        }
        "trigger_events" => {
            let exists: bool = new.query_row("SELECT EXISTS(SELECT 1 FROM trigger_subscriptions WHERE subscription_id=?1 AND principal=?2 AND connection_id=?3)", params![text(row,"subscription_id")?,text(row,"principal")?,text(row,"connection_id")?], |r| r.get(0)).map_err(|e| e.to_string())?;
            if !exists {
                return Err("missing trigger subscription".into());
            }
            row.insert(
                "payload_hash".into(),
                Value::Text(hash(text(row, "payload")?)?),
            );
        }
        "action_requests" => {
            // Requests store arguments but no schema snapshot. Only the catalog
            // body with the original pin can justify rewriting that pin; using
            // a newer schema would invent provenance for an unknown outcome.
            let original: Option<String> = old.query_row(
                "SELECT schema_hash FROM catalog_actions WHERE principal=?1 AND connection_id=?2 AND name=?3",
                params![text(row, "principal")?, text(row, "connection_id")?, text(row, "action")?],
                |r| r.get(0),
            ).optional().map_err(|e| e.to_string())?;
            if original.as_deref() != Some(text(row, "schema_hash")?) {
                return Err(
                    "missing catalog schema matching the reconciliation request's original pin"
                        .into(),
                );
            }
            row.insert("schema_hash".into(), Value::Text(action_hash(new, row)?));
            row.insert(
                "args_hash".into(),
                Value::Text(hash(text(row, "args_snapshot")?)?),
            );
        }
        "probe_subscriptions" => {
            hash(text(row, "return_schema")?)?;
            return Ok(false);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
