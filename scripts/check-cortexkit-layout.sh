#!/usr/bin/env bash
# Nothing under .cortexkit/ may be tracked except the allowed folders and files.
#
# The fleet layout keeps internal material (design notes, investigations, tool state)
# under .cortexkit/, ignored by git. Only release-notes/, skills/, rules/, WORKER.md and
# top-level project settings files (.cortexkit/<module>.jsonc, which the daemon reads)
# may be tracked there.
#
# The check lists every tracked path under .cortexkit/ and refuses any path outside that
# list. Listing only tracked files that are also ignored (`git ls-files -ci`) is not
# enough: a stray `!` rule in .gitignore can un-ignore a private file, which is then
# tracked without being ignored.
#
# It also confirms the ignore block works (an internal path is ignored, the allowed ones
# are not), so internal files stay out of `git status`. If a control fails, the checker
# reports itself BLIND and exits 2.
#
# Exit 0 clean, 1 a disallowed file is tracked, 2 the ignore rules don't work or git
# could not list the tracked files.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

if ! git check-ignore -q --no-index .cortexkit/internal-docs/designs/control.md; then
  echo "BLIND: .cortexkit/internal-docs/ is not ignored; the .cortexkit block is missing from .gitignore" >&2
  exit 2
fi
if git check-ignore -q --no-index .cortexkit/release-notes/control.md; then
  echo "BLIND: .cortexkit/release-notes/ is ignored; the block's allow lines are missing" >&2
  exit 2
fi
if git check-ignore -q --no-index .cortexkit/WORKER.md; then
  echo "BLIND: .cortexkit/WORKER.md is ignored; the shared worker guide must be trackable" >&2
  exit 2
fi

if ! tracked="$(git ls-files -- .cortexkit)"; then
  echo "BLIND: git ls-files failed, so the tracked files under .cortexkit/ are unknown" >&2
  exit 2
fi

allowed='^\.cortexkit/(release-notes/|skills/|rules/|WORKER\.md$|[a-z0-9-]+\.jsonc$)'
disallowed="$(printf '%s\n' "$tracked" | grep -vE "$allowed" | grep -v '^$' || true)"

if [ -n "$disallowed" ]; then
  echo "tracked files under .cortexkit/ that the layout keeps out of git:" >&2
  printf '%s\n' "$disallowed" | sed 's/^/  /' >&2
  echo "move them to .cortexkit/internal-docs/ (or remove them) and 'git rm --cached' them" >&2
  exit 1
fi
echo "controls hold; no disallowed file is tracked under .cortexkit/"
