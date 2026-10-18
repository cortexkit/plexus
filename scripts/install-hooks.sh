#!/usr/bin/env bash
# Explicitly opt this clone into the repository's push guard.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
desired="$root/.githooks"
current="$(git -C "$root" config --get core.hooksPath || true)"
if [ -n "$current" ] && [ "$current" != "$desired" ] && [ "$current" != '.githooks' ]; then
  echo "refusing: core.hooksPath already names $current; not replacing existing hooks" >&2
  exit 1
fi
git -C "$root" config --local core.hooksPath "$desired"
echo "installed repository hooks: $desired (direct pushes still permit deliberate --no-verify)"
