#!/usr/bin/env python3
"""Plan nonempty mutation shards before GitHub allocates their runners.

Selection mirrors the pinned ckdev-mutate runner: changed edit/test paths,
changed controls or prebuilds, followed by sorted-ID modulo sharding.
"""
import argparse
import json
import subprocess
import tomllib


def selected_rows(current, baseline, changed):
    previous = baseline.get("control", [])
    prebuild_changed = current.get("prebuild", []) != baseline.get("prebuild", [])
    return [row for row in current.get("control", []) if
            prebuild_changed or row not in previous or row.get("test_file") in changed or
            any(edit.get("file") in changed for edit in
                (row.get("edits") or [{"file": row.get("file")}]))]


def plan(rows, event, ref):
    selection = ("--diff origin/main" if event == "push" and ref.startswith("refs/heads/train/")
                 else "--all" if event == "push" and ref == "refs/heads/main"
                 else "--all --broad" if event in ("schedule", "workflow_dispatch") else "")
    count = len(rows) if selection else 0
    return {"matrix": {"shard": list(range(1, min(4, count) + 1))},
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
        result = plan(rows, "push", "refs/heads/main")
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
