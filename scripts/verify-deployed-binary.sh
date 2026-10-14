#!/bin/sh
# Maintainer deployment diagnostic; outside contributors do not need a live fleet binary.
# Prove that the process serving a CortexKit module is executing the binary at
# the deploy path, by comparing inodes.
#
# This exists because the naive one-liner has four independent failure modes,
# three of which are FALSE ALARMS whose natural remedy is an unnecessary
# redeploy — so a sloppy version pushes an operator toward overwriting and
# restarting a module that was already correct, during the window they are
# being most careful. The fourth is worse: a false ALL-CLEAR.
#
#   1. stat without -L reads the SYMLINK's inode rather than the target's.
#   2. `lsof -d txt` returns SEVERAL rows — the binary, /usr/lib/dyld, a sqlite
#      -shm file, a system plist cache — so picking by position (head/tail)
#      selects whichever row the kernel happened to order first. It may be
#      right by luck; a sibling module compared a plist cache inode against
#      its binary's and got a guaranteed mismatch on a correct deploy.
#   3. A filter matching nothing yields an EMPTY value, and empty-vs-number
#      compares unequal. That reads as "the deploy is wrong" when it means "my
#      filter found nothing" — a null result presented as a negative one.
#   4. THE DANGEROUS ONE. `lsof -p ""` does not fail: the empty argument is
#      ignored and lsof lists EVERY process on the machine. Combined with
#      anchoring on the path, that silently changes the question from "is THIS
#      process running this file" to "is ANY process running this file", so a
#      dead module with a stale pid verifies clean as long as anything at all
#      holds the binary open. The pid must therefore be proven live BEFORE
#      lsof runs; a non-empty check on the result cannot close it, because the
#      result is legitimately non-empty in exactly that failure.
#
# Process selection is exact rather than a substring: `pgrep -f ck-plexus`
# also matches `ck-plexus-admin`, so a running admin CLI could be measured
# instead of the module.
#
# Written for /bin/sh because macOS ships bash 3.2, where bash-4 conveniences
# such as `mapfile` do not exist.
set -eu

# $1 is the deployed binary.
BINARY="${1:-$HOME/.local/share/cortexkit/bin/ck-plexus}"
PROCESS_NAME=$(basename "$BINARY")

if [ ! -e "$BINARY" ]; then
    echo "CHECK FAILED: no binary at $BINARY" >&2
    exit 2
fi

# Resolve by exact accounting name from `ps`, NOT with pgrep.
#
# pgrep on BSD/macOS silently EXCLUDES ITS OWN ANCESTORS, and CortexKit tooling
# frequently runs inside a supervised module: a shell spawned under ck-aft,
# itself under the ck-subc daemon, cannot see either of them via pgrep by any
# flag: with both live, every pgrep form returns empty. The failure is silent and it lands on the
# modules MOST likely to be running the checker, so the tool is blindest
# exactly where it is most used.
#
# `ps -eo pid=,ucomm=` has no such exclusion. Matching ucomm exactly keeps the
# original property that ck-plexus-admin is not mistaken for the module.
PIDS=$(ps -eo pid=,ucomm= | awk -v name="$PROCESS_NAME" '$2 == name { print $1 }' || true)
PID_COUNT=$(printf '%s\n' "$PIDS" | grep -c . || true)

if [ -z "$PIDS" ] || [ "$PID_COUNT" -eq 0 ]; then
    echo "CHECK FAILED: no running process named $PROCESS_NAME" >&2
    exit 2
fi
if [ "$PID_COUNT" -gt 1 ]; then
    echo "CHECK FAILED: $PID_COUNT processes named $PROCESS_NAME ($PIDS); refusing to guess" >&2
    exit 2
fi
PID="$PIDS"

# Prove the pid is live before lsof sees it. This ordering is load-bearing:
# an empty or dead pid reaching lsof turns the question into a machine-wide
# one that answers clean.
if ! ps -p "$PID" >/dev/null 2>&1; then
    echo "CHECK FAILED: pid $PID is not running" >&2
    exit 2
fi

# Resolve through any symlink so the path comparison matches what lsof
# reports, which is always the real path.
RESOLVED=$(readlink -f "$BINARY" 2>/dev/null || echo "$BINARY")

# Anchor on the path (last field) and read the inode (second to last), rather
# than trusting row order. Linux lsof appends " (deleted)" to the name once the
# file the process runs has been replaced at its path, which is exactly the
# staged-but-not-restarted case this script exists to catch; without
# allowing for it that case read as "the check failed" instead of MISMATCH.
RUNNING_INODE=$(lsof -p "$PID" -a -d txt | awk -v path="$RESOLVED" '
    { name = $NF; node = $(NF-1) }
    $NF == "(deleted)" { name = $(NF-1); node = $(NF-2) }
    name == path { print node }' | head -1)
if [ -z "$RUNNING_INODE" ]; then
    echo "CHECK FAILED: no txt row for $RESOLVED in pid $PID — the CHECK failed, which is not the same as a bad deploy" >&2
    exit 2
fi

# `ls -iLd` rather than stat: these flags are POSIX, so this reads the same field
# on macOS and on GNU systems. `stat -Lf '%i'` is BSD-only, and GNU stat accepts
# it with a different meaning (-f is filesystem status, %i its id), so on Linux
# it printed a filesystem id and every correct deploy read as a MISMATCH.
DISK_INODE=$(ls -iLd "$BINARY" | awk '{ print $1 }')
if [ -z "$DISK_INODE" ]; then
    echo "CHECK FAILED: could not read the inode of $BINARY" >&2
    exit 2
fi

if [ "$RUNNING_INODE" != "$DISK_INODE" ]; then
    echo "MISMATCH: pid $PID runs inode $RUNNING_INODE, deploy path holds $DISK_INODE" >&2
    echo "The process is serving an older binary; restart the module." >&2
    exit 1
fi

# Freshness of shared crates needs no check here. Every dependency comes from
# crates.io at an exact version, so a shared fix reaches this binary only
# through a Cargo.lock change in this repo's own history, which the build
# commit already covers.
echo "OK: pid $PID is executing $RESOLVED (inode $DISK_INODE)"
exit 0
