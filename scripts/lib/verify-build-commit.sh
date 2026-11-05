#!/usr/bin/env bash
# Read the binary's declared identity, not an incidental substring in its data.
set -euo pipefail
# Bash 3.2 can lose an unset-variable error status in EXIT; success must be explicit.
finished=0
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$root/scripts/lib/private-copy.sh"
directory="$(private_executable_copy "$1")"
cleanup_verification() {
  local status=$?
  local cleanup_status=0
  rm -rf "$directory" || cleanup_status=$?
  if [ "$status" -eq 0 ]; then status=$cleanup_status; fi
  if [ "$status" -eq 0 ] && [ "$finished" -ne 1 ]; then status=1; fi
  exit "$status"
}
trap cleanup_verification EXIT
version="$("$directory/ckdev-plexus" --version)"
python3 - "$version" "$2" <<'PY'
import re, sys
match = re.fullmatch(r'ck-plexus(?:-admin)? \S+ \(commit ([0-9a-f]{40}(?:-dirty)?), lock [0-9a-f]+\)', sys.argv[1])
if not match or match[1] != sys.argv[2]:
    print('refusing: binary must report the exact clean HEAD commit ' + sys.argv[2], file=sys.stderr)
    sys.exit(1)
PY
finished=1
