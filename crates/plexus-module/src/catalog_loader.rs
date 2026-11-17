//! Startup store initialization and catalog file validation and ingestion.

use super::*;

pub(super) fn initialize_store(
    hello_ack: &ModuleHelloAckBody,
) -> Result<(PlexusStore, Option<PathBuf>), ModuleError> {
    let value = hello_ack.storage.as_ref().ok_or_else(|| {
        ModuleError::Message("subc HELLO_ACK omitted the storage descriptor".to_string())
    })?;
    let descriptor: StorageDescriptor = serde_json::from_value(value.clone())
        .map_err(|error| ModuleError::Message(format!("invalid storage descriptor: {error}")))?;
    let data_directory = engram_catalog::data_directory(&descriptor);
    let store = PlexusStore::open(&descriptor)
        .map_err(|error| ModuleError::Message(format!("open plexus store: {error}")))?;
    Ok((store, data_directory))
}

pub(super) fn ingest_catalog(store: &PlexusStore) -> Result<(), ModuleError> {
    let directory = catalog_directory(
        std::env::var_os("PLEXUS_CATALOG_DIR"),
        cfg!(debug_assertions),
    )?;
    ingest_catalog_from(store, &directory)
}

/// Resolve the catalog directory from the deployment environment.
///
/// A release build refuses to run without `PLEXUS_CATALOG_DIR` rather than
/// falling back to the compile-time repository path. The fallback exists for
/// `cargo run` during development - but on the machine where the repository
/// tree actually exists, a production daemon that lost its env line would not
/// fail: it would silently ingest the WORKING TREE's catalog, serving
/// uncommitted manifest edits as though they were reviewed and staged. A
/// missing variable must be a named boot refusal, not a plausible guess.
///
/// Both arms take their inputs as parameters (the env value and the build
/// kind) so each is testable from any build without mutating process-global
/// environment state.
pub(super) fn catalog_directory(
    configured: Option<std::ffi::OsString>,
    dev_fallback_allowed: bool,
) -> Result<PathBuf, ModuleError> {
    if let Some(directory) = configured {
        return Ok(PathBuf::from(directory));
    }
    if dev_fallback_allowed {
        return Ok(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog"));
    }
    Err(ModuleError::Message(
        "PLEXUS_CATALOG_DIR is not set: a release build does not guess a catalog \
         location, because the compile-time fallback points at the development \
         tree. Set it in the module's env block in subc.jsonc."
            .to_string(),
    ))
}

pub(super) fn catalog_paths(directory: &Path) -> Result<Vec<PathBuf>, ModuleError> {
    let mut paths = std::fs::read_dir(directory)
        .map_err(|error| ModuleError::Message(format!("read catalog directory: {error}")))?
        .map(|entry| entry.map(|item| item.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ModuleError::Message(format!("read catalog entry: {error}")))?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "jsonc")
    });
    paths.sort();
    Ok(paths)
}

// Both boot and the offline check use this pipeline so a rollback is tested
// against the schema and semantic validation the candidate will actually run.
pub(super) fn parse_catalog_manifest(
    source: &str,
) -> Result<plexus_core::IngestedManifest, ModuleError> {
    let normalized = subc_jsonc::jsonc_to_json(source)
        .map_err(|error| ModuleError::Message(format!("normalize catalog manifest: {error}")))?;
    let value: Value = serde_json::from_str(&normalized)
        .map_err(|error| ModuleError::Message(format!("parse catalog manifest: {error}")))?;
    plexus_core::ingest_value(value)
        .map_err(|error| ModuleError::Message(format!("validate catalog manifest: {error}")))
}

pub(super) fn check_catalog(directory: &Path) -> i32 {
    let paths = match catalog_paths(directory) {
        Ok(paths) => paths,
        Err(error) => {
            std::eprintln!("cannot check catalog {}: {error}", directory.display());
            println!("catalog: 0 ok, 0 refused, 1 I/O errors");
            return 2;
        }
    };
    let (ok, refused, io_errors) = tally_catalog(&paths);
    println!("catalog: {ok} ok, {refused} refused, {io_errors} I/O errors");
    if io_errors > 0 {
        2
    } else if refused > 0 {
        1
    } else {
        0
    }
}

/// Check each manifest and print one line per file; returns the counts of
/// files that parsed, were refused, and could not be read. A file that cannot
/// be read counts as an I/O error only, not also as a refusal, so the summary
/// adds up to the number of files.
pub(super) fn tally_catalog(paths: &[PathBuf]) -> (usize, usize, usize) {
    let (mut ok, mut refused, mut io_errors) = (0, 0, 0);
    for path in paths {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                io_errors += 1;
                println!(
                    "unreadable {}: read catalog manifest: {error}",
                    path.display()
                );
                continue;
            }
        };
        match parse_catalog_manifest(&source) {
            Ok(_) => {
                ok += 1;
                println!("ok {}", path.display());
            }
            Err(error) => {
                refused += 1;
                println!("refused {}: {error}", path.display());
            }
        }
    }
    (ok, refused, io_errors)
}

/// The catalog ingest itself, with the directory supplied rather than read from
/// the environment.
///
/// Split out so a test can drive the real boot path against a temporary catalog:
/// resolving the directory from a process-wide environment variable would make
/// any such test mutate global state shared with every other test in the binary.
/// The point of testing here rather than against the store directly is that the
/// retirement sweep's CALL SITE is what makes it effective, and a sweep nobody
/// invokes is indistinguishable from an absent one.
pub(super) fn ingest_catalog_from(
    store: &PlexusStore,
    directory: &Path,
) -> Result<(), ModuleError> {
    let paths = catalog_paths(directory)?;
    // The retirement pass below withdraws every stored manifest the directory
    // does not contain. A directory holding no manifests at all is a wrong or
    // half-synced PLEXUS_CATALOG_DIR far more often than a deliberate
    // withdrawal of every vendor, and following it would retire the whole
    // catalog on this boot. Refuse to boot instead.
    if paths.is_empty() {
        return Err(ModuleError::Message(format!(
            "catalog directory {} holds no .jsonc manifests; refusing to boot rather \
             than retire every stored manifest (check PLEXUS_CATALOG_DIR)",
            directory.display()
        )));
    }
    let mut reviewed = Vec::new();
    for path in &paths {
        let source = std::fs::read_to_string(path).map_err(|error| {
            ModuleError::Message(format!("read catalog manifest {}: {error}", path.display()))
        })?;
        let ingested = parse_catalog_manifest(&source).map_err(|error| {
            ModuleError::Message(format!(
                "refused catalog manifest {}: {error}",
                path.display()
            ))
        })?;
        let key = ingested.manifest.key.clone();
        // The store records a content change in the upsert's own transaction.
        store
            .upsert_manifest("system", &ingested)
            .map_err(|error| {
                ModuleError::Message(format!(
                    "store catalog manifest {}: {error}",
                    path.display()
                ))
            })?;
        reviewed.push(key);
    }

    // Withdrawals need their own pass, because the loop above can only express
    // what the directory CONTAINS. Upserting the files present leaves a manifest
    // deleted from the catalog untouched in the store, still listed as
    // connectable and still ticketable -- so retiring a vendor for being
    // ungovernable had no effect on a running module.
    //
    // Failing the boot on a retirement error is deliberate: reaching here means
    // the directory parsed cleanly, so a store error is a real fault, and
    // serving a catalog whose withdrawals were silently skipped is the state
    // this pass exists to prevent.
    // Each retirement's audit row is written in the retirement's transaction.
    store
        .retire_absent_manifests("system", &reviewed)
        .map_err(|error| ModuleError::Message(format!("retire absent manifests: {error}")))?;

    // GitHub handle rows seeded before the seeder pinned reviewed argument
    // schemas still hold the open placeholder, which leaves the
    // undeclared-argument check with nothing to refuse on any bot write, and
    // nothing else ever rewrites them. This runs after the loop that stores
    // each catalog file and after absent manifests are retired, so the schemas
    // come from the manifests this boot just stored and never from a retired
    // one. A store error fails the boot, as a retirement error does.
    let pins = store
        .pin_handle_placeholder_schemas()
        .map_err(|error| ModuleError::Message(format!("pin handle schemas: {error}")))?;
    eprintln!(info catalog:
        "pinned reviewed argument schemas on {} GitHub handle catalog rows that held the open placeholder",
        pins.pinned.len()
    );
    let mut per_connection: std::collections::BTreeMap<(&str, &str), usize> =
        std::collections::BTreeMap::new();
    for pin in &pins.pinned {
        *per_connection
            .entry((pin.principal.as_str(), pin.connection_id.as_str()))
            .or_default() += 1;
    }
    for ((principal, connection_id), count) in per_connection {
        eprintln!(debug catalog:
            "pinned reviewed argument schemas on {count} catalog rows of {principal}/{connection_id}"
        );
    }
    // Every handle on the same manifest has the same gap, because the missing
    // schema is in the shared manifest, so one line per action says it all.
    let mut gaps: std::collections::BTreeMap<(&str, &str), usize> =
        std::collections::BTreeMap::new();
    for gap in &pins.gaps {
        *gaps.entry((gap.action.as_str(), gap.reason)).or_default() += 1;
    }
    for ((action, reason), count) in gaps {
        eprintln!(warn catalog:
            "GitHub handle action {action} keeps the open placeholder schema on {count} connections: {reason}"
        );
    }
    Ok(())
}
