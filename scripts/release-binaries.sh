#!/bin/sh
# Maintainer deployment build tool; outside contributors do not need this release lane.
# Build the ck-plexus release binaries against the committed Cargo.lock.
#
# WHY THIS SCRIPT EXISTS AT ALL
#
# A release built from a hand-typed `cargo build --release`, copied forward
# from one restage to the next, is the worst place for the lock to go
# unenforced: CI at least gets re-run and its result is
# examined, while a release binary is built once and then serves traffic for
# weeks. A flag that is missing from a script can be added; a flag that is
# missing from a habit has nowhere to live.
#
# Every release build must therefore go through this script rather than a
# remembered command line, because `--locked` here is the only thing that makes
# "this binary came from commit X" also mean "this binary linked the
# dependencies commit X names". Without it, two builds at the same commit can
# link different versions and no deploy check we have can tell them apart:
# inode identity, LC_UUID and buildCommit all establish SOURCE identity only.
#
# A fresh resolve can move many packages at once, including rustls and http,
# which are on the path that carries vendor credentials to remote MCP servers.
# Those moves produce no git diff.
set -eu

cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Darwin ]; then
  echo "release-binaries: this deployment lane requires macOS (codesign and LC_UUID)" >&2
  exit 2
fi

echo "==> lock: $(shasum -a 256 Cargo.lock | cut -c1-16)  (committed set)"

# --locked makes a stale or absent lock a hard failure. If this line ever fails
# with "cannot update the lock file", the fix is to update the lock in its own
# reviewed commit and re-run -- never to drop the flag, which would silently
# ship whatever cargo resolved at that moment.
cargo build --release --locked -p plexus-module --bin ck-plexus --bin ck-plexus-admin

# THE PROVENANCE STAMP IS AN ASSERTION, SO VERIFY IT RATHER THAN TRUSTING IT.
#
# build.rs embeds `git rev-parse HEAD` and declares .git/HEAD plus the resolved
# ref as rerun inputs. That is not sufficient. `git push` can pack refs, which
# DELETES the loose ref file the build script declared, and a later commit
# recreates it; cargo can then reuse a stale build-script result. A release
# build can then reuse an earlier result and stamp the PREVIOUS commit while
# every other check passes, so the resulting binary is signed and staged under
# the name of a commit it was not built from.
#
# The whole deploy ladder rests on this value. Step 0 checks fix ancestry
# against it and acceptance reads it back from the running module, so a stale
# stamp is worse than an absent one: absent fails loudly, stale passes every
# check while naming the wrong source.
#
# Both binaries embed the same build-script commit, so verify each before signing
# or staging either one.
head_sha=$(git rev-parse HEAD)
# A private executable copy reports the same build identity as health. Matching
# that field exactly rejects dirty builds and incidental hashes in binary data.
for binary in ck-plexus ck-plexus-admin; do
  if ! bash scripts/lib/verify-build-commit.sh "target/release/$binary" "$head_sha"; then
    echo "REFUSED: $binary does not carry HEAD $head_sha" >&2
    echo "  The build script did not re-run, so its embedded commit is stale." >&2
    echo "  Remedy: touch .git/HEAD and the ref under .git/refs/heads/, then" >&2
    echo "  re-run this script. Do not sign or stage this binary." >&2
    exit 1
  fi
  echo "==> provenance: $binary carries HEAD $(echo "$head_sha" | cut -c1-12)"
done

for binary in ck-plexus ck-plexus-admin; do
  path="target/release/$binary"
  # LC_UUID rather than a content hash: the linker sets it and it survives code
  # signing, whereas signing rewrites the file and moves every hash. Publishing
  # a hash means a legitimate re-sign invalidates the value owners verified,
  # and the only signal is silence.
  uuid=$(dwarfdump --uuid "$path" 2>/dev/null | awk '{print $2}')
  echo "==> $binary  LC_UUID=${uuid:-unavailable}"
  echo "    sha256=$(shasum -a 256 "$path" | cut -c1-16)  (note only; signing moves this)"
done
