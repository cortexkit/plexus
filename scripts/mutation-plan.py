#!/usr/bin/env python3
"""Plan nonempty mutation shards before GitHub allocates their runners.

Selection mirrors the pinned ckdev-mutate runner: changed edit/test paths,
changed controls or prebuilds, followed by sorted-ID modulo sharding.

Which rows run depends on the event:

- A train push replays the rows its diff against origin/main touches; with no
  origin/main to compare against, every row counts as touched. A commit
  reaches main only after its train's run went green on that exact commit (the
  pre-push hook and scripts/train.sh both enforce this), so every touched row
  has already been replayed by the time main moves.
- A push to main therefore replays nothing. Replaying the whole catalogue there
  would repeat the train's work on the same commit and costs many runner-hours
  per landing.
- The nightly schedule and manual dispatch replay every row with --broad. That
  run catches interactions between changes that no single train's diff selects.
- Pull requests replay nothing; the mutation job also excludes them.

The shard count grows with the selection, up to MAX_SHARDS, so each shard stays
well inside the mutation job's 180-minute limit.
"""
import argparse
import json
import math
import subprocess
import tomllib

# Rows one shard aims to replay. A diff or --all replay runs only each row's
# named tests. A --broad replay runs every test target of the row's package, so
# a row takes longer and a shard gets fewer of them. Measured on GitHub's hosted
# runners, one shard of 292 broad rows took 166 minutes, and shards of about 246
# plain rows did not all finish inside the 180-minute limit. These sizes leave a
# shard roughly half its time to spare.
ROWS_PER_SHARD = 120
BROAD_ROWS_PER_SHARD = 80
# Upper bound on runners one CI run allocates for mutation proofs. Past
# 16 x 80 broad rows or 16 x 120 plain rows, shards grow beyond the sizes above;
# the full broad catalogue of 1,369 rows gives about 86 rows per shard, still
# far below the measured limit.
MAX_SHARDS = 16


def selected_rows(current, baseline, changed):
    previous = baseline.get("control", [])
    prebuild_changed = current.get("prebuild", []) != baseline.get("prebuild", [])
    return [row for row in current.get("control", []) if
            prebuild_changed or row not in previous or row.get("test_file") in changed or
            any(edit.get("file") in changed for edit in
                (row.get("edits") or [{"file": row.get("file")}]))]


def shard_total(count, broad):
    """Shards for `count` selected rows; 0 when nothing is selected."""
    if not count:
        return 0
    per_shard = BROAD_ROWS_PER_SHARD if broad else ROWS_PER_SHARD
    return min(MAX_SHARDS, max(1, math.ceil(count / per_shard)))


def selection_for(event, ref):
    """The ckdev-mutate selection flags for a CI event; empty selects nothing."""
    if event == "push" and ref.startswith("refs/heads/train/"):
        return "--diff origin/main"
    if event in ("schedule", "workflow_dispatch"):
        return "--all --broad"
    # A main push lands a commit whose train already replayed every touched
    # row; pull requests never allocate mutation runners.
    return ""


def plan(rows, event, ref):
    return plan_selection(rows, selection_for(event, ref))


def plan_selection(rows, selection):
    count = len(rows) if selection else 0
    total = shard_total(count, "--broad" in selection.split())
    # The mutation job reads `total` from the matrix for its name and its
    # --shard i/n argument. With no rows the job is skipped, so the empty
    # matrix carries no total.
    matrix = {"shard": list(range(1, total + 1)), "total": [total]} if total else {"shard": []}
    return {"matrix": matrix,
            "selection": selection, "has_mutations": bool(count), "count": count}


def main_tip():
    """Return origin/main's commit, or None when the remote has no main branch."""
    found = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "origin/main^{commit}"],
                           capture_output=True)
    return found.stdout.decode().strip() if found.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True)
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    with open("mutations.toml", "rb") as stream:
        current = tomllib.load(stream)
    rows = current.get("control", [])
    base_ref = None
    if args.event == "push" and args.ref.startswith("refs/heads/train/"):
        base_ref = main_tip()
    if base_ref is None and args.event == "push" and args.ref.startswith("refs/heads/train/"):
        # With no main branch yet, as in a fresh repository or a fork, there is
        # nothing to compare against, so every control counts as touched.
        result = plan_selection(rows, "--all")
    elif base_ref:
        changed = set(subprocess.check_output(
            ["git", "diff", "--name-only", "-z", base_ref, "HEAD", "--"]
        ).decode().split("\0"))
        base = subprocess.run(["git", "show", base_ref + ":mutations.toml"], capture_output=True)
        if base.returncode and "mutations.toml" not in changed:
            raise RuntimeError("cannot read the comparison mutation catalogue")
        baseline = tomllib.loads(base.stdout.decode()) if base.returncode == 0 else {}
        rows = selected_rows(current, baseline, changed)
        result = plan(rows, args.event, args.ref)
        result["selection"] = "--diff " + base_ref
    else:
        result = plan(rows, args.event, args.ref)
    print("matrix=" + json.dumps(result["matrix"], separators=(",", ":")))
    print("selection=" + result["selection"])
    print("has-mutations=" + str(result["has_mutations"]).lower())
    print("count=" + str(result["count"]))


if __name__ == "__main__":
    main()
