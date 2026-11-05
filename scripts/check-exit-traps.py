#!/usr/bin/env python3
"""Refuse tracked shell scripts with errexit and EXIT but no explicit success."""

import re
import subprocess
import sys
from pathlib import Path


def unsafe(text: str) -> bool:
    # This is a layout check, not a shell interpreter. Ignore comment lines and
    # join continued commands so the usual set/trap spellings share one check.
    text = re.sub(r"(?m)^\s*#.*$", "", text).replace("\\\n", "")
    settings = re.findall(r"(?:^|[;\n])\s*set[ \t]+([^\n;#]+)", text)
    errexit = any(
        re.search(r"(?:^|\s)-[a-zA-Z]*e[a-zA-Z]*(?=\s|$)|(?:^|\s)-o\s+errexit\b", flags)
        for flags in settings
    )
    exit_trap = re.search(r"(?:^|[;\n])\s*trap[ \t]+[^\n]+[ \t]+(?:EXIT|0)(?=[ \t]*(?:[;#\n]|$))", text)
    finished = re.search(r"(?:^|[;\n])\s*finished=1(?=[ \t]*(?:[;#\n]|$))", text)
    return bool(errexit and exit_trap and not finished)


def self_test() -> bool:
    unsafe_fixture = '#!/bin/bash\nset FLAGS\ntrap \'rm -rf "$scratch"\' EXIT\n'
    guarded_fixture = '''#!/bin/bash
set FLAGS
finished=0
cleanup() {
  status=$?
  if [ "$status" -eq 0 ] && [ "$finished" -ne 1 ]; then status=1; fi
  exit "$status"
}
trap cleanup EXIT
finished=1
'''
    for flags in ("-e", "-euo pipefail", "-Eeuo pipefail", "-u -e", "-o errexit"):
        if not unsafe(unsafe_fixture.replace("FLAGS", flags)) or unsafe(guarded_fixture.replace("FLAGS", flags)):
            print("BLIND: EXIT-trap check misjudged its unsafe or guarded fixture: " + flags, file=sys.stderr)
            return False
    print("EXIT-trap controls passed (unsafe and guarded fixtures; 5 errexit spellings)")
    return True


def main() -> int:
    if not self_test():
        return 2
    root = Path(__file__).resolve().parent.parent
    try:
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
        checked = 0
        violations = []
        for name in filter(None, tracked):
            path = root / name
            with path.open("rb") as source:
                header = source.readline(256)
            if path.suffix != ".sh" and not re.match(rb"#![^\n]*\b(?:bash|sh|dash|ksh|zsh)(?:\s|$)", header):
                continue
            checked += 1
            if unsafe(path.read_text()):
                violations.append(name)
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        print(f"EXIT-trap check cannot inspect tracked scripts: {error}", file=sys.stderr)
        return 2
    if not checked:
        print("BLIND: EXIT-trap check found no tracked shell scripts", file=sys.stderr)
        return 2
    for name in violations:
        print(f"refusing: {name}: errexit with an EXIT trap requires a finished=1 success marker", file=sys.stderr)
    if violations:
        return 1
    print(f"checked {checked} tracked shell scripts; EXIT-trap success markers present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
