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
- A main push skips mutation proofs only when the CI workflow has a successful
  run for the same sha on a train ref. Without that API proof, it replays every
  control so a missing or failed lookup cannot suppress the gate.
- The nightly schedule and manual dispatch replay every row with --broad. That
  run catches interactions between changes that no single train's diff selects.
- Pull requests select nothing, so the mutation job allocates no shards.

The shard count grows with the selection, up to MAX_SHARDS, so each shard stays
well inside the mutation job's 180-minute limit.
"""
import argparse
import json
import math
import subprocess
import tomllib

# Train reports 39784016510, 39741325245 and 39717873268 replayed 31, 45 and
# 83 plain rows at 38.7-41.6 seconds per row, with 5-9 minutes of setup and
# baseline per shard. At the slowest observed rate and longest baseline, 23 rows
# take about 25 minutes; typical 45- and 83-row selections split into 22-23 and
# 20-21 rows per runner respectively.
ROWS_PER_SHARD = 23
# Broad replays run every test target of each row's package, so their per-row
# cost is higher. Keep the nightly shard target at 80 rows for its 180-minute
# job limit; landing shards use the 23-row wait-time target.
BROAD_ROWS_PER_SHARD = 80
# Upper bound on runners one CI run allocates for mutation proofs. Above 1,280
# broad rows, shards exceed 80; the 1,369-row catalogue averages about 86 rows
# per shard at the 16-shard cap.
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


def selection_for(event, ref, main_train_verified=False):
    """Select controls for CI; unverified main pushes fail safe to all rows."""
    if event == "push" and ref.startswith("refs/heads/train/"):
        return "--diff origin/main"
    if event in ("schedule", "workflow_dispatch"):
        return "--all --broad"
    if event == "push" and ref == "refs/heads/main":
        # A successful train run on this exact sha already replayed every
        # touched row. Without that proof, run all controls rather than assuming.
        return "" if main_train_verified else "--all"
    # Pull requests never allocate mutation runners.
    return ""


def plan(rows, event, ref, main_train_verified=False):
    return plan_selection(rows, selection_for(event, ref, main_train_verified))


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
    parser.add_argument(
        "--main-train-verified", action="store_true",
        help="main push has a successful CI run on this exact sha on a train ref",
    )
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
        result = plan(rows, args.event, args.ref, args.main_train_verified)
        result["selection"] = "--diff " + base_ref
    else:
        result = plan(rows, args.event, args.ref, args.main_train_verified)
    print("matrix=" + json.dumps(result["matrix"], separators=(",", ":")))
    print("selection=" + result["selection"])
    print("has-mutations=" + str(result["has_mutations"]).lower())
    print("count=" + str(result["count"]))


if __name__ == "__main__":
    main()
