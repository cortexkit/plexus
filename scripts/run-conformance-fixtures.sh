#!/usr/bin/env bash
# Shared by CI and the Linux pre-push gate. Report every failed fixture.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
build_result="$(cargo build --locked -p plexus-conformance --bin plexus-conformance --message-format=json)"
harness="$(printf '%s\n' "$build_result" | python3 -c 'import json,sys; rows=[json.loads(line) for line in sys.stdin]; paths=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="plexus-conformance" and r.get("executable")]; assert len(paths)==1, paths; print(paths[0])')"
fixture_list="$("$harness" list)"
mapfile -t fixtures <<< "$fixture_list"
if [ -z "$fixture_list" ]; then fixtures=(); fi
if [ "${#fixtures[@]}" -eq 0 ]; then
  echo "::error::plexus-conformance list returned no fixtures"
  exit 1
fi
echo "Fixtures: ${fixtures[*]}"
failed=()
for fixture in "${fixtures[@]}"; do
  echo "==> plexus-conformance run --fixture ${fixture}"
  if ! "$harness" run --fixture "$fixture"; then
    echo "::error::conformance fixture ${fixture} failed"
    failed+=("$fixture")
  fi
done
echo "Conformance: $(( ${#fixtures[@]} - ${#failed[@]} )) of ${#fixtures[@]} fixtures passed"
if [ "${#failed[@]}" -gt 0 ]; then
  echo "::error::failed fixtures: ${failed[*]}"
  exit 1
fi
