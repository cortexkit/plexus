#!/usr/bin/env bash
# Save publicly available upstream metadata used to reproduce the evaluation results.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$root/sources"
errors="$out/collection-errors.txt"
mkdir -p "$out"
: > "$errors"

# Preserve the last successful snapshot when GitHub/NVD rate-limits an anonymous run.
fetch() {
  local destination="$1"
  local url="$2"
  local temporary="${destination}.tmp"
  if curl -fsSL -A 'plexus-js-interpreter-eval/1' "$url" -o "$temporary"; then
    mv "$temporary" "$destination"
  else
    rm -f "$temporary"
    printf 'failed: %s\n' "$url" >> "$errors"
  fi
}

fetch "$out/quickjs-ng-releases.json" \
  'https://api.github.com/repos/quickjs-ng/quickjs/releases?per_page=100'
fetch "$out/quickjs-ng-tags.json" \
  'https://api.github.com/repos/quickjs-ng/quickjs/tags?per_page=100'
fetch "$out/quickjs-ng-security-advisories.json" \
  'https://api.github.com/repos/quickjs-ng/quickjs/security-advisories?per_page=100'
fetch "$out/wasmtime-releases.json" \
  'https://api.github.com/repos/bytecodealliance/wasmtime/releases?per_page=100'
fetch "$out/wasmtime-security-advisories.json" \
  'https://api.github.com/repos/bytecodealliance/wasmtime/security-advisories?per_page=100'
fetch "$out/bellard-quickjs-releases.json" \
  'https://api.github.com/repos/bellard/quickjs/releases?per_page=100'
fetch "$out/bellard-quickjs-security-advisories.json" \
  'https://api.github.com/repos/bellard/quickjs/security-advisories?per_page=100'
fetch "$out/bellard-quickjs-tags.json" \
  'https://api.github.com/repos/bellard/quickjs/tags?per_page=100'
fetch "$out/rquickjs-releases.json" \
  'https://api.github.com/repos/DelSkayn/rquickjs/releases?per_page=100'
fetch "$out/rquickjs-security-advisories.json" \
  'https://api.github.com/repos/DelSkayn/rquickjs/security-advisories?per_page=100'
fetch "$out/rquickjs-tags.json" \
  'https://api.github.com/repos/DelSkayn/rquickjs/tags?per_page=100'
fetch "$out/rquickjs-crates-io.json" 'https://crates.io/api/v1/crates/rquickjs'

nvd_body="$out/nvd-quickjs-cves.json.tmp"
nvd_headers="$out/nvd-quickjs-cves.headers.txt.tmp"
if curl -fsSL -A 'plexus-js-interpreter-eval/1' \
  -D "$nvd_headers" \
  'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=QuickJS' \
  -o "$nvd_body"; then
  mv "$nvd_body" "$out/nvd-quickjs-cves.json"
  mv "$nvd_headers" "$out/nvd-quickjs-cves.headers.txt"
else
  rm -f "$nvd_body" "$nvd_headers"
  printf 'failed: NVD QuickJS CVE keyword query\n' >> "$errors"
fi

if [[ ! -s "$errors" ]]; then
  printf 'collected_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/collected-at.txt"
else
  printf 'attempted_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/refresh-attempt.txt"
fi
