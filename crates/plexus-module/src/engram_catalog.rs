use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cortexkit_store_types::{StorageBackend, StorageDescriptor};

pub(crate) const FILE_NAME: &str = "engram-catalog.json";

const CATALOG_BYTES: &[u8] = br#"{
  "schema_version": 1,
  "module_id": "plexus",
  "entries": [
    {
      "entry_id": "plexus/store",
      "class": "portable",
      "mechanism": "page-db",
      "path": "store.db",
      "writer_interaction": "read-transaction-live"
    },
    {
      "entry_id": "plexus/catalog",
      "class": "rebuild",
      "mechanism": "filetree",
      "path": "catalog"
    },
    {
      "entry_id": "plexus/grant-revocations",
      "class": "portable",
      "mechanism": "filetree",
      "path": "grant-revocations.jsonl",
      "writer_interaction": "none"
    },
    {
      "entry_id": "plexus/logs",
      "class": "excluded",
      "reason": "Diagnostics can name repositories and queries.",
      "mechanism": "log-stream",
      "path": "logs"
    },
    {
      "entry_id": "plexus/store-leases",
      "class": "device-local",
      "reason": "cortexkit-store single-writer leases must never be restored on another machine.",
      "mechanism": "filetree",
      "path": "*.lease"
    }
  ]
}
"#;

#[derive(Debug, PartialEq, Eq)]
enum WriteOutcome {
    Written,
    Unchanged,
}

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn data_directory(descriptor: &StorageDescriptor) -> Option<PathBuf> {
    let StorageBackend::Sqlite { path } = &descriptor.backend else {
        return None;
    };
    if path == ":memory:" {
        return None;
    }

    let database_path = Path::new(path);
    Some(
        database_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    )
}

pub(crate) fn write_best_effort(data_directory: &Path) {
    if let Err(error) = write_catalog(data_directory) {
        plexus_core::diag!(warn storage: "could not write Engram backup catalog: {error}");
    }
}

fn write_catalog(data_directory: &Path) -> io::Result<WriteOutcome> {
    let destination = data_directory.join(FILE_NAME);
    match fs::read(&destination) {
        Ok(existing) if existing == CATALOG_BYTES => return Ok(WriteOutcome::Unchanged),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (temporary_path, mut temporary_file) = create_temporary_file(data_directory)?;
    let result = (|| {
        temporary_file.write_all(CATALOG_BYTES)?;
        temporary_file.sync_all()?;
        drop(temporary_file);
        fs::rename(&temporary_path, &destination)?;
        Ok(WriteOutcome::Written)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn create_temporary_file(data_directory: &Path) -> io::Result<(PathBuf, fs::File)> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    for _ in 0..100 {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temporary_path = data_directory.join(format!(
            ".{FILE_NAME}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&temporary_path) {
            Ok(file) => {
                if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                    drop(file);
                    let _ = fs::remove_file(&temporary_path);
                    return Err(error);
                }
                return Ok((temporary_path, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique Engram catalog temporary file",
    ))
}

#[cfg(test)]
mod tests {
    use super::{data_directory, write_best_effort, write_catalog, WriteOutcome, CATALOG_BYTES};
    use plexus_core::test_scratch::Scratch;
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    #[test]
    fn engram_catalog_bytes_are_stable_and_unchanged_writes_are_skipped() {
        let scratch = Scratch::directory("engram-catalog-stability");
        let directory = scratch.path();
        let destination = directory.join(super::FILE_NAME);

        assert_eq!(write_catalog(directory).unwrap(), WriteOutcome::Written);
        assert_eq!(fs::read(&destination).unwrap(), CATALOG_BYTES);
        let first_metadata = fs::metadata(&destination).unwrap();
        assert_eq!(first_metadata.permissions().mode() & 0o777, 0o600);

        assert_eq!(write_catalog(directory).unwrap(), WriteOutcome::Unchanged);
        let second_metadata = fs::metadata(&destination).unwrap();
        assert_eq!(first_metadata.ino(), second_metadata.ino());
        assert_eq!(fs::read(&destination).unwrap(), CATALOG_BYTES);
    }

    #[test]
    fn engram_catalog_declares_exact_entry_ids_and_device_local_lease_pattern() {
        let catalog: serde_json::Value = serde_json::from_slice(CATALOG_BYTES).unwrap();
        assert_eq!(catalog["schema_version"], 1);
        assert_eq!(catalog["module_id"], "plexus");
        let entries = catalog["entries"].as_array().unwrap();
        let entry_ids: Vec<_> = entries
            .iter()
            .map(|entry| entry["entry_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            entry_ids,
            [
                "plexus/store",
                "plexus/catalog",
                "plexus/grant-revocations",
                "plexus/logs",
                "plexus/store-leases",
            ]
        );
        let store = entries
            .iter()
            .find(|entry| entry["entry_id"] == "plexus/store")
            .unwrap();
        assert_eq!(store["class"], "portable");
        assert_eq!(store["mechanism"], "page-db");
        assert_eq!(store["path"], "store.db");
        assert_eq!(store["writer_interaction"], "read-transaction-live");

        let catalog_entry = entries
            .iter()
            .find(|entry| entry["entry_id"] == "plexus/catalog")
            .unwrap();
        assert_eq!(catalog_entry["class"], "rebuild");
        assert_eq!(catalog_entry["mechanism"], "filetree");
        assert_eq!(catalog_entry["path"], "catalog");

        let revocations = entries
            .iter()
            .find(|entry| entry["entry_id"] == "plexus/grant-revocations")
            .unwrap();
        assert_eq!(revocations["class"], "portable");
        assert_eq!(revocations["mechanism"], "filetree");
        assert_eq!(revocations["path"], "grant-revocations.jsonl");
        assert_eq!(revocations["writer_interaction"], "none");

        let leases = entries
            .iter()
            .find(|entry| entry["entry_id"] == "plexus/store-leases")
            .unwrap();
        assert_eq!(leases["class"], "device-local");
        assert_eq!(
            leases["path"], "*.lease",
            "cortexkit-store lease files must remain out of backups"
        );
        assert!(leases["reason"]
            .as_str()
            .is_some_and(|reason| !reason.trim().is_empty()));

        let logs = entries
            .iter()
            .find(|entry| entry["entry_id"] == "plexus/logs")
            .unwrap();
        assert_eq!(logs["class"], "excluded");
        assert_eq!(logs["mechanism"], "log-stream");
        assert_eq!(logs["path"], "logs");
        assert!(logs["reason"]
            .as_str()
            .is_some_and(|reason| !reason.trim().is_empty()));
    }

    #[test]
    fn engram_catalog_replaces_the_old_file_atomically() {
        let scratch = Scratch::directory("engram-catalog-atomic");
        let destination = scratch.path().join(super::FILE_NAME);
        fs::write(&destination, b"previous catalog").unwrap();
        let previous = File::open(&destination).unwrap();
        let previous_inode = previous.metadata().unwrap().ino();

        assert_eq!(
            write_catalog(scratch.path()).unwrap(),
            WriteOutcome::Written
        );
        assert_ne!(
            fs::metadata(&destination).unwrap().ino(),
            previous_inode,
            "catalog publication must replace the old inode rather than rewrite it in place"
        );
        assert_eq!(fs::read(&destination).unwrap(), CATALOG_BYTES);
    }

    #[test]
    fn engram_catalog_write_failure_does_not_block_startup() {
        let scratch = Scratch::directory("engram-catalog-failure");
        let not_a_directory = scratch.path().join("not-a-directory");
        fs::write(&not_a_directory, b"file").unwrap();

        write_best_effort(&not_a_directory);

        assert!(Path::new(&not_a_directory).is_file());
    }

    #[test]
    fn engram_catalog_uses_the_database_parent_as_its_data_directory() {
        use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

        let scratch = Scratch::directory("engram-catalog-data-dir");
        let database = scratch.path().join("store.db");
        let descriptor = StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: "plexus-test".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: database.to_string_lossy().into_owned(),
            },
        };

        assert_eq!(data_directory(&descriptor).as_deref(), Some(scratch.path()));
    }
}
