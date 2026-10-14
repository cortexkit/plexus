#!/usr/bin/env python3
"""Resolve packed build stamps with one Git batch, preserving candidate order."""
import re
import subprocess
import sys


def resolve(binary, repo, width=12):
    strings = subprocess.run(["strings", binary], capture_output=True, text=True, check=True).stdout
    candidates = []
    for run in sorted(set(re.findall(r"[0-9a-f]{%d,}(?:-dirty)?" % width, strings))):
        if run.endswith("-dirty"):
            candidates.append(run)
        else:
            candidates.extend(run[i:i + width] for i in range(len(run) - width + 1))
    ordinary = [value for value in candidates if not value.endswith("-dirty")]
    if ordinary:
        replies = subprocess.run(
            ["git", "-C", repo, "cat-file", "--batch-check=%(objecttype)"],
            input="".join(value + "^{commit}\n" for value in ordinary),
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        if len(replies) != len(ordinary):
            raise RuntimeError("Git did not answer every build-stamp candidate")
        found = {value for value, reply in zip(ordinary, replies) if reply == "commit"}
    else:
        found = set()
    return next((value for value in candidates if value.endswith("-dirty") or value in found), "")


if __name__ == "__main__":
    print(resolve(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 12))
