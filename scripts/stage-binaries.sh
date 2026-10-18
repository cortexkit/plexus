#!/usr/bin/env bash
# Maintainer deployment tool; outside contributors do not need to stage binaries.
# Stage the built release binaries for placement: sign, write sidecars, publish a
# currency pointer, and retire the superseded pair.
#
# Run scripts/release-binaries.sh first — it refuses a binary whose embedded
# commit is not HEAD, which is the check that catches a stale build-script stamp.
#
# WHY THIS IS A SCRIPT. Otherwise every step here is hand-typed identically on
# each placement. Hand-typed steps drift, and the drift is invisible: a stale
# build-script stamp, which release-binaries.sh now refuses, can reach a
# signed, sidecar-verified artifact precisely because each individual step
# looks right.
#
# WHY THE .current FILE. The placer's currency check otherwise infers which
# artifact is newest from mtime. mtime is a property of the filesystem, not a
# statement by the producer, and it survives a copy that changes nothing else.
# This file is the producer saying which bytes are meant, in a form the placer
# can verify against the artifact rather than trust.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="${PLEXUS_STAGING_DIR:-$HOME/.local/share/cortexkit/staging}"
cd "$REPO_ROOT"

if [ -n "$(git status --porcelain)" ]; then
  echo "refusing to stage from a dirty tree: commit or stash first" >&2
  exit 1
fi

# Marker verification is part of staging rather than a separate hand-run step,
# because doing it by hand is what left the control OPTIONAL: three of the last
# four cards from here carried markers with no control, and the peer placing them
# supplied their own. A marker reading "staged 1 / live 0" is consistent with the
# live image genuinely lacking the string AND with the instrument having failed
# on that file -- `strings` on a missing or non-Mach-O path also counts 0. The
# control is a needle known to be present in BOTH images, so a zero from it means
# the instrument is broken rather than the string is absent.
MARKERS=()
CONTROL=""
MARKER_NONE=0
MARKER_BINARY=daemon
CATALOG_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --catalog-dir) CATALOG_DIR="${2:?--catalog-dir needs a path}"; shift 2 ;;
    --help|-h)
      echo "usage: scripts/stage-binaries.sh [--catalog-dir <path>] --marker <string|none> [--control <string>] [--marker-binary daemon|admin]"
      echo "  --catalog-dir overrides PLEXUS_CATALOG_DIR in ~/.config/cortexkit/subc.jsonc"
      exit 0 ;;
    --marker)
      if [ "${2:-}" = "none" ]; then MARKER_NONE=1; else MARKERS+=("${2:?--marker needs a string}"); fi
      shift 2 ;;
    --control) CONTROL="${2:?--control needs a string}"; shift 2 ;;
    --marker-binary) MARKER_BINARY="${2:?--marker-binary needs daemon or admin}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ ${#MARKERS[@]} -gt 0 ] && [ -z "$CONTROL" ]; then
  echo "refusing: --marker requires --control (a needle present in BOTH images)" >&2
  echo "  without it, a marker reading 0 on the live image cannot be told apart" >&2
  echo "  from the instrument failing on that file" >&2
  exit 1
fi
if [ ${#MARKERS[@]} -eq 0 ] && [ "$MARKER_NONE" -eq 0 ]; then
  echo "refusing: pass --marker <string> --control <string>, or --marker none" >&2
  echo "  --marker none is for a change that adds no literal, where identity" >&2
  echo "  rests on the sidecar chain and LC_UUID instead" >&2
  exit 1
fi

SHA_FULL="$(git rev-parse HEAD)"
SHA="$(git rev-parse --short=7 HEAD)"
if [ "$(uname -s)" != Darwin ]; then
  echo "stage-binaries: this deployment lane requires macOS (codesign and LC_UUID)" >&2
  exit 2
fi

# The binaries must exist and must carry this commit. release-binaries.sh already
# refuses a mismatch, but staging is a separate act and a stale target/ directory
# from an earlier build is exactly what it would not catch.
for BIN in ck-plexus ck-plexus-admin; do
  if [ ! -x "target/release/$BIN" ]; then
    echo "missing target/release/$BIN: run scripts/release-binaries.sh first" >&2
    exit 1
  fi
done
# Read the declared build identity, not a substring which also matches -dirty.
if ! bash "$REPO_ROOT/scripts/lib/verify-build-commit.sh" target/release/ck-plexus "$SHA_FULL"; then
  echo "target/release/ck-plexus does not carry HEAD $SHA_FULL" >&2
  echo "rebuild with scripts/release-binaries.sh (it refuses this case by name)" >&2
  exit 1
fi

# Check the candidate, not the running daemon: their manifest schemas can differ.
if [ -z "$CATALOG_DIR" ]; then
  if ! CATALOG_DIR="$(python3 - "$HOME/.config/cortexkit/subc.jsonc" <<'PY'
import json, re, sys
try:
    with open(sys.argv[1]) as stream:
        source = stream.read()
    # Preserve quoted strings while removing JSONC comments and trailing commas.
    token = r'"(?:\\.|[^"\\])*"'
    source = re.sub(token + r'|//[^\n]*|/\*[\s\S]*?\*/',
                    lambda m: m[0] if m[0].startswith('"') else ' ', source)
    source = re.sub(token + r'|,\s*(?=[}\]])',
                    lambda m: m[0] if m[0].startswith('"') else '', source)
    directory = json.loads(source)['modules']['plexus']['env']['PLEXUS_CATALOG_DIR']
    if not isinstance(directory, str) or not directory:
        raise ValueError('PLEXUS_CATALOG_DIR is not a nonempty path')
    print(directory)
except (OSError, ValueError, KeyError, TypeError) as error:
    print(error, file=sys.stderr)
    sys.exit(1)
PY
)"; then
    echo "refusing: cannot check the deployed catalog; configure PLEXUS_CATALOG_DIR or pass --catalog-dir <path>" >&2
    exit 1
  fi
fi
if [ ! -d "$CATALOG_DIR" ] || [ ! -r "$CATALOG_DIR" ] || [ ! -x "$CATALOG_DIR" ]; then
  echo "refusing: cannot check the deployed catalog: $CATALOG_DIR is not a readable directory" >&2
  exit 1
fi
# The catalog check executes the candidate, so it runs from a copy on the
# internal disk, never from target/: target/ may live on an external volume,
# and a new binary executed from there can raise a macOS removable-volume
# prompt that stalls that volume for every process until someone answers it.
# The copy keeps the linker's ad-hoc signature, and nothing is signed before
# the catalog check passes. It lives in a new owner-only temp directory and
# takes the ckdev- name, because process listings show
# the file name: a temporary check must not look like the running ck-plexus
# daemon to process-identity checks. EXIT removes the copy
# on success and on every ordinary refusal path.
source "$REPO_ROOT/scripts/lib/private-copy.sh"
CHECK_DIR="$(private_executable_copy target/release/ck-plexus)" || {
  echo "refusing: cannot prepare a private catalog-check copy" >&2
  exit 1
}
CHECK_BINARY="$CHECK_DIR/ckdev-plexus"
trap 'rm -rf "$CHECK_DIR"' EXIT
if ! CATALOG_CHECK="$("$CHECK_BINARY" --check-catalog "$CATALOG_DIR" 2>&1)"; then
  echo "refusing: ck-plexus cannot check the deployed catalog: $CATALOG_DIR" >&2
  printf '%s\n' "$CATALOG_CHECK" >&2
  exit 1
fi
printf '%s\n' "$CATALOG_CHECK"

mkdir -p "$STAGING"
echo "==> staging $SHA into $STAGING"
STAGING_ROOT="$STAGING"
STAGING="$(mktemp -d "$STAGING_ROOT/.candidate.XXXXXX")"
PUBLISH_LOCK=""
trap 'rm -rf "$CHECK_DIR" "$STAGING"; if [ -n "$PUBLISH_LOCK" ]; then rmdir "$PUBLISH_LOCK"; fi' EXIT

for BIN in ck-plexus ck-plexus-admin; do
  DEST="$STAGING/SIGNED.$BIN.$SHA"
  cp "target/release/$BIN" "$DEST"
  # The identifier is pinned to the deployed name rather than derived from the
  # path: an ad-hoc signature otherwise embeds the staging filename, which makes
  # the code identifier change every time the sha in the name changes.
  #
  # `-o runtime` is macOS hardened runtime, and no entitlements are granted.
  # Without it any process running as the same user can attach a debugger to
  # the module and read its launch nonce out of memory. Hardening is also what
  # forbids running freshly generated native code, which is why the probe
  # sandbox interprets its guests instead; the checks below prove both.
  codesign --force --sign - -o runtime --identifier "$BIN" "$DEST"
  ( cd "$STAGING" && shasum -a 256 "SIGNED.$BIN.$SHA" > "SIGNED.$BIN.$SHA.sha256" )
  ( cd "$STAGING" && shasum -c "SIGNED.$BIN.$SHA.sha256" >/dev/null )
  UUID="$(dwarfdump --uuid "$DEST" | awk '{print $2}')"
  DIGEST="$(cut -d' ' -f1 "$STAGING/SIGNED.$BIN.$SHA.sha256")"
  printf '    %-18s LC_UUID=%s\n' "$BIN" "$UUID"
  printf '    %-18s sha256=%s\n' "" "$DIGEST"
done

# Read the signature BACK rather than trusting the command above. A signing
# step that dropped `-o runtime` produces a perfectly valid signature, the
# binary runs, and nothing anywhere else notices: the only symptom is that a
# debugger can now attach. Another module's placement step once re-signed its
# binary without `-o runtime` in exactly this way, unnoticed.
#
# An unreadable signature is refused as such, rather than read as "no
# get-task-allow": the entitlement check below is an absence check, and an
# absence reported by a command that failed means nothing.
require_hardened() {
  local path="$1" described flags entitlements
  if ! described="$(codesign -dv "$path" 2>&1)"; then
    echo "refusing: cannot read the signature of $path" >&2
    printf '%s\n' "$described" >&2
    exit 1
  fi
  flags="$(printf '%s\n' "$described" | sed -n 's/.*flags=0x[0-9a-fA-F]*(\([^)]*\)).*/\1/p')"
  if [ -z "$flags" ]; then
    echo "refusing: no signature flags found for $path; the check could not run" >&2
    printf '%s\n' "$described" >&2
    exit 1
  fi
  case ",$flags," in
    *,runtime,*) ;;
    *) echo "refusing: $path is not signed with hardened runtime (flags: $flags)" >&2
       echo "  a debugger could attach to it and read the module's launch nonce" >&2
       exit 1 ;;
  esac
  if ! entitlements="$(codesign -d --entitlements - "$path" 2>/dev/null)"; then
    echo "refusing: cannot read the entitlements of $path" >&2
    exit 1
  fi
  case "$entitlements" in
    *get-task-allow*)
      echo "refusing: $path carries get-task-allow, which lets a debugger attach" >&2
      exit 1 ;;
  esac
  printf '==> hardened    %-18s flags=%s\n' "$(basename "$path")" "$flags"
}
for BIN in ck-plexus ck-plexus-admin; do
  require_hardened "$STAGING/SIGNED.$BIN.$SHA"
done

# The flags say what the signature permits, not whether the binary works under
# it. A hardened binary that executes native generated code passes every check
# above and is killed by the kernel the first time a probe runs. So run a real
# guest through the signed file itself, with no supervisor environment. The
# admin binary has no sandbox and so no smoke run; it is still checked above.
if ! SMOKE="$(env -i "$STAGING/SIGNED.ck-plexus.$SHA" --smoke-probe 2>&1)"; then
  echo "refusing: the signed ck-plexus cannot run a probe guest" >&2
  echo "  (no output usually means the kernel killed it)" >&2
  printf '%s\n' "$SMOKE" >&2
  exit 1
fi
printf '==> %s\n' "$SMOKE"

# Marker verification runs BEFORE the currency pointer is published and before
# any predecessor is retired. It used to run last, which meant a REFUSED marker
# had already declared the new artifact current and already deleted the pair a
# rollback would use -- the refusal was correct and arrived after the damage.
# A check that gates nothing is a report.
# Candidate markers for THIS pair, derived rather than remembered.
#
# The live binary carries its own build commit, so the diff between it and HEAD
# is exactly the set of literals that can discriminate. Reading the commit needs
# care: the image holds several 40-hex strings and the FIRST is a sibling's
# provenance stamp, not ours -- taking `head -1` yields a sha that is not in this
# repo at all. The discriminator is which candidate git resolves HERE.
suggest_markers() {
  local live_sha=""
  # Literals are PACKED, so a sha has no word boundary and a fixed 40-char
  # window lands off by however many characters the neighbour contributed:
  # extracting 40 chars here yielded `0` plus the first 39 of the real sha, a
  # string that resolves nowhere. So take each maximal hex run and slide a
  # window across it, testing every offset against this repo.
  live_sha="$(python3 "$REPO_ROOT/scripts/lib/embedded-commit.py" "$LIVE_DAEMON" "$REPO_ROOT" 40)"
  if [ -z "$live_sha" ]; then
    echo "  (cannot name candidates: no sha in the running image resolves here)" >&2
    return 0
  fi
  echo "  candidate markers, from git diff $(echo "$live_sha" | cut -c1-12)..HEAD:" >&2
  git diff "$live_sha..HEAD" -- 'crates/*/src/*.rs' \
    | grep -E '^\+' | grep -oE '"[a-z][a-z0-9 _:=-]{18,60}"' \
    | tr -d '"' | sort -u | head -5 | sed 's/^/    /' >&2
}

# Which pair the marker is measured against. A change can be admin-only -- the
# credential-free ceremony fix touched ck-plexus-admin.rs and nothing else -- and
# then there is no daemon marker to find, because the daemon's source did not
# move. Gating such a build against the daemon pair refuses every honest marker
# and invites staging with --marker none, which is how a gate teaches you to
# bypass it. Default stays the daemon so existing use is unchanged.
case "$MARKER_BINARY" in
  daemon)
    LIVE_DAEMON="${PLEXUS_LIVE_BIN:-$HOME/.local/share/cortexkit/bin/ck-plexus}"
    STAGED_DAEMON="$STAGING/SIGNED.ck-plexus.$SHA"
    ;;
  admin)
    LIVE_DAEMON="${PLEXUS_LIVE_ADMIN_BIN:-$HOME/.local/share/cortexkit/bin/ck-plexus-admin}"
    STAGED_DAEMON="$STAGING/SIGNED.ck-plexus-admin.$SHA"
    ;;
  *)
    echo "refusing: --marker-binary must be daemon or admin, got '$MARKER_BINARY'" >&2
    exit 1
    ;;
esac
if [ "$MARKER_NONE" -eq 1 ]; then
  echo "==> marker: none declared; identity rests on the sidecar chain and LC_UUID"
elif [ ! -f "$LIVE_DAEMON" ]; then
  echo "refusing: no live image at $LIVE_DAEMON to compare against" >&2
  exit 1
else
  # A present control proves the instrument read SOMETHING, not that it read a
  # binary: a text file containing the control word satisfies it and every
  # marker below then reports a confident, meaningless verdict. Found by testing
  # this check against a plain text file, which passed. So check the file KIND
  # first -- that is the precondition the control was standing in for.
  for f in "$STAGED_DAEMON" "$LIVE_DAEMON"; do
    kind="$(file -b "$f" 2>/dev/null || true)"
    case "$kind" in
      *Mach-O*) ;;
      *) echo "refusing: $f is not a Mach-O image (file says: ${kind:-unreadable})" >&2
         echo "  strings on a non-binary still produces counts, so a marker read" >&2
         echo "  against it would be confident and meaningless" >&2
         exit 1 ;;
    esac
  done

  # The control runs on BOTH files: if it reads 0 anywhere, every marker count
  # below is meaningless and the run must stop rather than report.
  # `--` ends grep's options: a marker such as `--carrier <principal>` was read
  # as a flag, grep failed, `|| true` swallowed it, and the empty count printed
  # as "equal on both". Any count that is not a number is refused by name below.
  count_in() { strings "$1" | grep -cF -- "$2" || true; }
  require_count() {
    case "$1" in
      ''|*[!0-9]*) echo "refusing: counting '$2' produced no number ('$1'); the instrument failed, so no verdict" >&2; exit 1 ;;
    esac
  }
  c_staged="$(count_in "$STAGED_DAEMON" "$CONTROL")"
  c_live="$(count_in "$LIVE_DAEMON" "$CONTROL")"
  require_count "$c_staged" "$CONTROL"; require_count "$c_live" "$CONTROL"
  printf '==> control %-38s staged=%s live=%s\n' "$CONTROL" "$c_staged" "$c_live"
  if [ "$c_staged" -eq 0 ] || [ "$c_live" -eq 0 ]; then
    echo "refusing: the control is absent from at least one image, so the" >&2
    echo "  instrument cannot see that file and no marker count can be trusted" >&2
    exit 1
  fi
  fail=0
  for m in "${MARKERS[@]}"; do
    m_staged="$(count_in "$STAGED_DAEMON" "$m")"
    m_live="$(count_in "$LIVE_DAEMON" "$m")"
    require_count "$m_staged" "$m"; require_count "$m_live" "$m"
    if [ "$m_staged" != "$m_live" ]; then verdict="DISCRIMINATES"; else verdict="NO -- equal on both"; fi
    printf '==> marker  %-38s staged=%s live=%s  %s\n' "$m" "$m_staged" "$m_live" "$verdict"
    [ "$verdict" = "DISCRIMINATES" ] || fail=1
  done
  if [ "$fail" -ne 0 ]; then
    # A refused marker leaves the operator guessing, and guessing is how a
    # marker string gets INVENTED rather than read -- which happened here: a
    # plausible message that existed in no binary, refused 0/0. So name the
    # candidates instead, drawn from THIS build's diff against the running
    # image, because a feature list is a list of things true of the running
    # image too.
    suggest_markers
    echo "refusing: a marker that reads the same on both images is not a marker" >&2
    exit 1
  fi
fi

# EVERY PUBLISHING SIDE EFFECT LIVES HERE AND NOWHERE ELSE, and this function is
# called exactly once, below, after the last thing that can refuse.
#
# The ordering used to be implicit and I got it wrong: the marker check ran after
# the pointer was written and after predecessors were deleted, so a correct
# refusal arrived having already published and already destroyed the rollback
# pair. Fixing that by hand left the next guard to land wherever it was typed.
#
# With one publish point, "is this check in the right place" becomes "is it above
# the call", which a reader can answer instead of remembering. Producing and
# signing the artifacts must precede verification -- you cannot inspect a binary
# you have not built -- so this is the publishing half only: what declares the
# pair CURRENT and what destroys its predecessor.
publish_staging() {
  local stamp bin digest old retired=0
  PUBLISH_LOCK="$STAGING_ROOT/.publish.lock"
  if ! mkdir "$PUBLISH_LOCK"; then
    PUBLISH_LOCK=""
    echo "refusing: another staging publisher holds the publication lock" >&2
    exit 1
  fi
  for bin in ck-plexus ck-plexus-admin; do
    if [ -e "$STAGING_ROOT/SIGNED.$bin.$SHA" ] || [ -L "$STAGING_ROOT/SIGNED.$bin.$SHA" ]; then
      echo "refusing: immutable staging artifact already exists for $bin at $SHA" >&2
      exit 1
    fi
  done
  for bin in ck-plexus ck-plexus-admin; do
    mv "$STAGING/SIGNED.$bin.$SHA" "$STAGING_ROOT/"
    mv "$STAGING/SIGNED.$bin.$SHA.sha256" "$STAGING_ROOT/"
  done
  rmdir "$STAGING"
  STAGING="$STAGING_ROOT"
  # The candidate directory is gone; cleanup must never delete the staging root.
  trap 'rm -rf "$CHECK_DIR"; rmdir "$PUBLISH_LOCK"' EXIT
  stamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  # The currency declaration, in the form the subconscious placer settled on: a
  # keyed file at the STAGING ROOT naming which stage is current, rather than a
  # file inside a stage attesting to itself. The difference matters because two
  # self-attesting files in one directory cannot say which of them is live.
  #
  # NOTE ON `stage=`: the settled form names a per-stage DIRECTORY. This module
  # stages flat sha-suffixed FILES in one root, so `stage` names the absolute
  # artifact path instead. The parent of that path is still the staging root,
  # which is what the reading gate derives, so the lookup lands correctly either
  # way -- but a consumer that stats `stage` expecting a directory will find a
  # regular file, and that is a difference to know rather than discover.
  #
  # Renamed through a temp file: a reader arrives at an arbitrary moment
  # relative to this write, and a half-written declaration naming half a path
  # sends it to a directory that does not exist, so its refusal names the wrong
  # cause.
  for bin in ck-plexus ck-plexus-admin; do
    {
      printf 'stage=%s\n' "$STAGING/SIGNED.$bin.$SHA"
      printf 'revision=%s\n' "$SHA_FULL"
      printf 'declared_at=%s\n' "$stamp"
    } > "$STAGING/.$bin.current.tmp.$$"
    mv -f "$STAGING/.$bin.current.tmp.$$" "$STAGING/$bin.current"
  done
  echo "==> currency declared at $stamp (root form, revision ${SHA_FULL})"

  # Only artifacts this script would have produced, and never the running
  # binaries or a rollback copy, which live outside the staging directory.
  #
  # The .current declarations are outside this glob by construction, not by an
  # exclusion rule -- so a future rename that brought them inside would have
  # this loop delete the declaration silently, on the run that publishes it.
  # Refuse that explicitly rather than relying on the name.
  for old in "$STAGING"/SIGNED.ck-plexus.* "$STAGING"/SIGNED.ck-plexus-admin.*; do
    [ -e "$old" ] || continue
    case "$old" in
      *".$SHA"|*".$SHA.sha256") continue ;;
      *.current|*.current.tmp.*)
        echo "refusing: the retirement glob now reaches a currency declaration" >&2
        echo "  ($old) -- it would be deleted by the run that publishes it" >&2
        exit 1 ;;
    esac
    rm -f "$old"
    retired=$((retired + 1))
  done
  echo "==> retired $retired superseded staging artifact(s)"

  # The declaration must still exist after retirement ran. The refusal above
  # catches the glob reaching a file NAMED *.current; this catches the class --
  # any path by which the declaration fails to survive a publishing run,
  # including a rename of either side that the name-based check cannot see.
  #
  # Worth the line because the failure is near-perfect: the declaration
  # vanishes, the placing gate finds no root manifest, falls through to mtime,
  # prints INFERRED, and PLACES. No refusal, no error, and a line that is not an
  # error. A guard silently downgraded to a guess.
  for bin in ck-plexus ck-plexus-admin; do
    if [ ! -s "$STAGING/$bin.current" ]; then
      echo "refusing: $bin.current is missing or empty after publication" >&2
      echo "  the placer falls back to mtime when it finds no declaration, and" >&2
      echo "  says INFERRED rather than failing -- so this must stop here" >&2
      exit 1
    fi
  done
}

publish_staging

echo "==> staged pair and pointers:"
ls -1 "$STAGING" | grep -E "^(SIGNED\.ck-plexus(-admin)?\.$SHA(\.sha256)?|ck-plexus(-admin)?\.current)$" | sed 's/^/    /'
