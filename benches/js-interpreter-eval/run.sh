#!/usr/bin/env bash
# Rebuild the isolated evaluators and replace their raw result snapshots.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

all_results="${1:-results/measurement.json}"
bellard_results="${2:-results/bellard-measurement.json}"

cargo build --release -p bellard-eval
cargo build --release -p quickjs-wasm-guest --target wasm32-wasip1
./target/release/bellard-eval "$bellard_results"
BELLARD_RESULT_PATH="$bellard_results" \
  cargo run --release -p js-interpreter-eval -- "$all_results"
bash ./collect-upstream-metadata.sh
