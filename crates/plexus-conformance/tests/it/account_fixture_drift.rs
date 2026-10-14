//! The vendored account key-rotation fixture must not drift from its source.
//!
//! WHY THE FIXTURE IS VENDORED AT ALL: it is authored and owned by the account
//! service, in a sibling repository. CI materialises only `commons` and
//! `plexus` (see .github/workflows/ci.yml), so a test reading it
//! across repositories would pass on a developer machine and be unrunnable in
//! CI — the shape where a conformance suite quietly stops being a gate.
//!
//! WHY DRIFT IS CHECKED RATHER THAN TRUSTED: a vendored copy of someone else's
//! contract is a snapshot of a decision they can revise. If they add a vector —
//! and this fixture exists precisely because rotation semantics keep gaining
//! cases — a stale copy means this repo keeps passing a conformance gate that
//! the owning service has already moved past. Silent, and in the direction that
//! reads as compliance.
//!
//! So: CI runs the conformance against the vendored bytes, and anyone with the
//! sibling repository checked out ALSO gets told when those bytes have gone
//! stale. The check degrades to a skip only when the source is genuinely absent,
//! and says so rather than passing quietly.

use std::path::{Path, PathBuf};

/// Where the fixture came from, recorded so the provenance survives the copy.
const SOURCE_RELATIVE: &str = "workers/account/test/fixtures/two-key-overlap-samples.json";

fn vendored_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/account/two-key-overlap-samples.json")
}

fn source_path() -> PathBuf {
    // The account repo sits beside this one in the standard checkout layout.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../cortexkit-account")
        .join(SOURCE_RELATIVE)
}

/// The vendored fixture is present and parses.
///
/// Asserted separately from the drift check because these fail for different
/// reasons and want different fixes: a missing or malformed vendored file is a
/// broken checkout, while drift is a stale copy of a live contract.
#[test]
fn the_vendored_fixture_is_present_and_well_formed() {
    let path = vendored_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("vendored fixture unreadable at {}: {error}", path.display())
    });
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("vendored fixture must be valid JSON");

    // Spot-check the structure the conformance gate depends on, so a truncated
    // or replaced file fails HERE rather than as a confusing assertion inside
    // the verifier tests.
    for key in [
        "jwks",
        "post_retirement_jwks",
        "duplicate_kid_jwks",
        "samples",
    ] {
        assert!(
            value.get(key).is_some(),
            "vendored fixture is missing '{key}': it cannot drive the rotation gate"
        );
    }
    let samples = value["samples"]
        .as_object()
        .expect("samples must be an object of name -> token");
    assert!(
        samples.len() >= 8,
        "expected the full vector set, found {} — a short fixture passes vacuously",
        samples.len()
    );
}

/// The vendored copy matches the source, when the source is reachable.
///
/// Skips ONLY when the sibling repository is absent, and reports the skip rather
/// than passing silently — an unrunnable check that looks green is the thing
/// this file exists to avoid.
#[test]
fn the_vendored_fixture_matches_its_source_when_available() {
    let source = source_path();
    if !source.exists() {
        // Not a failure: CI legitimately has no account checkout. Printed so a
        // reader of the output can tell "verified" from "could not verify".
        println!(
            "SKIP drift check: no account checkout at {} (expected in CI; \
             the vendored bytes still drive the conformance gate)",
            source.display()
        );
        return;
    }

    let vendored = std::fs::read_to_string(vendored_path()).expect("vendored fixture");
    let upstream = std::fs::read_to_string(&source).expect("source fixture");

    assert_eq!(
        vendored,
        upstream,
        "the vendored account fixture has DRIFTED from {}.\n\
         The account service owns these vectors and has changed them; re-vendor \
         and re-run the rotation gate rather than editing the copy, because the \
         copy is evidence about their contract and not about ours.",
        source.display()
    );
}
