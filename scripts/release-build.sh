#!/usr/bin/env bash
# Build both release binaries with the committed lockfile and verify their provenance.
set -euo pipefail

cd "$(dirname "$0")/.."

REV="$(git rev-parse HEAD)"

# A dirty checkout cannot be identified by its commit, even if the binaries
# would otherwise report that commit.
dirty=$(git status --porcelain)
if [ -n "$dirty" ]; then
  echo "refusing to build a release from a dirty tree: the built bytes would not match $REV" >&2
  echo "commit or stash first, or use a plain cargo build for a dev binary" >&2
  exit 1
fi

echo "building at $REV"
# The ordinary Cargo build embeds the checked-in probe guest without rebuilding it.
cargo build --locked --release -p plexus-module --bin ck-plexus --bin ck-plexus-admin

after_rev=$(git rev-parse HEAD)
dirty=$(git status --porcelain)
if [[ "$after_rev" != "$REV" || -n "$dirty" ]]; then
  echo "refusing to report provenance: the checkout changed during the build (expected clean $REV; HEAD is $after_rev)" >&2
  exit 1
fi

echo
# A ckdev- probe leaves any live production process unambiguous. The hard
# link (or copy if linking fails) runs the exact bytes just built.
probe_dir="$(mktemp -d)"
# Bash 3.2 can lose an unset-variable error status in EXIT; success must be explicit.
finished=0
on_exit() {
  local status=$?
  local cleanup_status=0
  rm -rf "$probe_dir" || cleanup_status=$?
  if [ "$status" -eq 0 ]; then status=$cleanup_status; fi
  if [ "$status" -eq 0 ] && [ "$finished" -ne 1 ]; then
    echo "release-build.sh: stopped before its last step; treating this run as failed" >&2
    status=1
  fi
  exit "$status"
}
trap on_exit EXIT
revision_pattern='\(commit ([0-9a-f]{40}), lock [0-9a-f]{64}\)$'
suffix=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) suffix=.exe ;;
esac
paths=()
for bin in ck-plexus ck-plexus-admin; do
  built="target/release/$bin$suffix"
  paths+=("$built")
  link="$probe_dir/ckdev-${bin#ck-}$suffix"
  ln "$built" "$link" 2>/dev/null || cp "$built" "$link"
  if ! version=$("$link" --version); then
    echo "release-build.sh: $bin version probe failed" >&2
    exit 1
  fi
  if [[ ! "$version" =~ $revision_pattern || "${BASH_REMATCH[1]}" != "$REV" ]]; then
    echo "release-build.sh: $bin does not report revision $REV: ${version:-<no version output>}" >&2
    exit 1
  fi
  printf '%-15s %s\n' "$bin" "$version"
done

echo
echo "sha256:"
# Report build hashes on runners with either checksum tool. The release
# workflow hashes the final archives separately, after signing on macOS.
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${paths[@]}" | sed 's|target/release/||'
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${paths[@]}" | sed 's|target/release/||'
else
  echo "no sha256 tool found (looked for shasum, sha256sum)" >&2
  exit 1
fi
finished=1
