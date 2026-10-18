#!/usr/bin/env bash
# Read the binary's declared identity, not an incidental substring in its data.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$root/scripts/lib/private-copy.sh"
directory="$(private_executable_copy "$1")"
trap 'rm -rf "$directory"' EXIT
version="$("$directory/ckdev-plexus" --version)"
python3 - "$version" "$2" <<'PY'
import re, sys
match = re.fullmatch(r'ck-plexus \S+ \(commit ([0-9a-f]{40}(?:-dirty)?), lock [0-9a-f]+\)', sys.argv[1])
if not match or match[1] != sys.argv[2]:
    print('refusing: binary must report the exact clean HEAD commit ' + sys.argv[2], file=sys.stderr)
    sys.exit(1)
PY
