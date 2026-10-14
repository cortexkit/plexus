#!/usr/bin/env bash
# Runs a mutation-catalogue control that edits the probe guest's source
# (crates/plexus-probe/guest). The host crate, plexus-probe, embeds the compiled
# guest from assets/plexus-probe-guest.wasm, so a guest edit has no effect until
# that file is rebuilt. This rebuilds it, runs the named host test (or the broad
# suite with --broad), and restores the original Wasm file on exit.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
saved="$(mktemp)"
asset=crates/plexus-probe/assets/plexus-probe-guest.wasm
cp "$asset" "$saved"
trap 'cp "$saved" "$asset"; rm -f "$saved"' EXIT
CARGO_HOME="$root/target/guest-cargo" scripts/build-probe-guest.sh
if [ "$1" = --broad ]; then
    python3 scripts/tests/cargo-junit.py
else
    cargo test --locked -p plexus-probe --lib "$1" -- --exact --nocapture
fi
