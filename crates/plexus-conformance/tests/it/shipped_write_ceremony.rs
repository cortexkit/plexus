//! The write ceremony for `github_rest`, rehearsed against the SHIPPED manifest.
//!
//! WHY THIS EXISTS: `catalog/github_rest.jsonc` parses (proved by
//! `shipped_catalog_ingests`) and has never been through a ceremony. Parsing
//! proves the file is well-formed; it says nothing about whether a ticket can be
//! minted against it. Those are different failures and only one of them is
//! currently fenced.
//!
//! The gap matters because of WHEN the first attempt happens: this connector
//! exists for the seen-marker write, its ceremony runs once with an operator
//! present, and the authority ceiling it sets is PERMANENT. A refusal discovered
//! at that moment is discovered in front of someone, and a ceiling minted wrong
//! is not editable afterwards — it needs a new ticket and a new connection.
//!
//! It also mints production's FIRST write authority. Every existing connection
//! is read-ceilinged, so no shipped manifest has ever been ticketed at write
//! risk, and the `write` path through `ceiling_within_manifest` has only ever
//! run against hand-built test fixtures that declare exactly what the test
//! wants. A fixture agreeing with the test proves the two agree; it does not
//! prove the shipped file does.
//!
//! This rehearses the exact call the live ceremony makes, with the exact
//! arguments, against the real bytes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use plexus_core::test_scratch::Scratch;
use plexus_core::{ingest_value, PlexusStore};

/// The parameters the live ceremony will use, named once so the test cannot
/// drift from the thing it is rehearsing.
const APP_KEY: &str = "github_rest";
const RISK: &str = "write";
/// EVERY action the live ticket will name, in one place, because the ceiling it
/// sets is permanent. A rehearsal that exercises a SUBSET proves the ceremony
/// works for the subset and says nothing about the set actually being minted --
/// and the difference is not recoverable afterwards, since widening a ceiling
/// means a new ticket and a new connection.
const ACTIONS: [&str; 3] = ["add_reaction", "add_issue_comment", "update_issue_comment"];

static SEQ: AtomicU64 = AtomicU64::new(0);

fn catalog_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../catalog/{APP_KEY}.jsonc"))
}

fn store() -> (Scratch, PlexusStore) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = Scratch::database("write-ceremony");
    let descriptor = StorageDescriptor {
        module_id: "plexus".to_string(),
        storage_namespace: format!("write-ceremony-{unique}"),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    };
    let store = PlexusStore::open(&descriptor).expect("open store");
    (path, store)
}

/// Ingest the shipped manifest through the production parser and path.
fn ingest_shipped(store: &PlexusStore) {
    let source = std::fs::read_to_string(catalog_path()).expect("the shipped manifest must exist");
    let normalized = subc_jsonc::jsonc_to_json(&source).expect("shipped manifest must be JSONC");
    let value: serde_json::Value =
        serde_json::from_str(&normalized).expect("shipped manifest must be JSON");
    let manifest = ingest_value(value).expect("shipped manifest must ingest");
    store
        .upsert_manifest("system", &manifest)
        .expect("manifest must store");
}

/// The ticket the live ceremony mints must be resolvable against the shipped
/// manifest, at write risk, naming exactly the action we will name.
///
/// This is link 1 of the authority chain and the gate that refuses first. If it
/// refuses, the ceremony stops before a connection exists, which is the good
/// case — but it stops in front of the operator, which is the case this test
/// exists to prevent.
#[test]
fn the_shipped_manifest_admits_a_write_ceiling_for_every_action_the_ticket_names() {
    let (path, store) = store();
    ingest_shipped(&store);

    let selectors: Vec<String> = ACTIONS.iter().map(|a| a.to_string()).collect();
    let ceiling = store
        .ceiling_within_manifest(APP_KEY, RISK, &selectors)
        .expect("the ceiling lookup must not fail at the store layer")
        .unwrap_or_else(|refusal| {
            panic!(
                "the shipped {APP_KEY} manifest refused a {RISK}-risk ceiling for \
                 {ACTIONS:?}: {refusal:?}. This is the refusal the live ceremony \
                 would hit with the operator watching."
            )
        });

    assert_eq!(
        ceiling.risk.to_string(),
        RISK,
        "the resolved ceiling must be the risk that was asked for"
    );
    let mut resolved = ceiling.action_selectors.clone();
    resolved.sort();
    let mut expected: Vec<String> = ACTIONS.iter().map(|a| a.to_string()).collect();
    expected.sort();
    assert_eq!(
        resolved, expected,
        "the ceiling must name the action EXPANDED rather than a wildcard: a \
         permanent ceiling stored as '*' would silently inherit whatever a \
         future manifest review adds to this vendor"
    );

    let _ = std::fs::remove_file(&path);
}

/// The same manifest must REFUSE authority it does not declare.
///
/// Without this the test above is satisfiable by a ceiling resolver that admits
/// anything — the constant-accept shape. The two arms together prove the gate
/// discriminates rather than nods.
#[test]
fn the_shipped_manifest_refuses_authority_it_does_not_declare() {
    let (path, store) = store();
    ingest_shipped(&store);

    // An action the manifest does not declare. Deliberately a plausible one:
    // the failure mode worth fencing is a ceiling minted for a verb someone
    // ASSUMED was in scope, not for an obvious typo.
    let undeclared = vec!["merge_pull_request".to_string()];
    let refusal = store
        .ceiling_within_manifest(APP_KEY, RISK, &undeclared)
        .expect("the ceiling lookup must not fail at the store layer");
    assert!(
        refusal.is_err(),
        "a ceiling naming an undeclared action must be refused, not clamped to \
         the declared set: clamping would mint a ceiling the operator did not ask \
         for and would not read back"
    );

    // Risk above what the declared action carries. `add_reaction` is declared
    // `write`, so a destructive ceiling over it is overreach.
    let over_risk = store
        .ceiling_within_manifest(APP_KEY, "destructive", &[ACTIONS[0].to_string()])
        .expect("the ceiling lookup must not fail at the store layer");
    assert!(
        over_risk.is_err(),
        "a ceiling above the declared risk of every named action must be refused"
    );

    let _ = std::fs::remove_file(&path);
}
