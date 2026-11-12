#!/usr/bin/env python3
"""Reject in-memory paths: cortexkit-store puts their writer lease in the cwd."""

from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
LITERAL = '":memory:"'
# These production comparisons interpret descriptors rather than opening stores.
COMPARISONS = {
    "crates/plexus-core/src/storage.rs": re.compile(
        r'^\s*StorageBackend::Sqlite \{ path \} if path != ":memory:" => \{\s*$'
    ),
    "crates/plexus-module/src/engram_catalog.rs": re.compile(
        r'^\s*if path == ":memory:" \{\s*$'
    ),
}


def violations(root, allowed):
    hits = []
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if LITERAL in line and not (
                relative in allowed and allowed[relative].fullmatch(line)
            ):
                hits.append(f"{relative}:{number}: {line.strip()}")
    return hits


def main():
    scratch = ROOT / "target" / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="memory-gate-", dir=scratch) as control:
        Path(control, "control.rs").write_text('let path = ":memory:";\n')
        if len(violations(Path(control), {})) != 1:
            sys.exit("refusing: in-memory store search missed its planted control")
    hits = violations(ROOT / "crates", COMPARISONS)
    if hits:
        print('refusing: raw ":memory:" store path under crates/', file=sys.stderr)
        print("The store's lease lands in the current directory; use test_scratch::store_path().", file=sys.stderr)
        print("\n".join(hits), file=sys.stderr)
        return 1
    print("in-memory store path check passed (planted control detected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
