#!/usr/bin/env bash
# ck-plexus Rust test gate.
#
# Run from the repo root after any code change. Static source/dependency and
# operator-script checks precede formatting, clippy and the Rust test suites.
# An unformatted commit fails before compilation.
# Serialize cargo invocations (never parallel cargo): concurrent workspace
# builds on a shared machine saturate it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_phase() {
  local label="$1"
  shift
  local started=$SECONDS
  echo "==> $label"
  "$@"
  echo "    ok ($((SECONDS - started))s)"
}

# Refuse a raw `std::env::temp_dir()` anywhere under crates/.
#
# Test scratch written straight into the shared temp directory is what filled it
# with 63,131 plexus entries — three files per SQLite store, none of them ever
# removed — until a bare listing of that directory took roughly fifteen minutes
# and stalled unrelated programs on this host. `plexus_core::test_scratch` puts
# every scratch path under one root, removes it on drop, and sweeps aged
# leftovers at the start of each run. A convention decays; this does not.
#
# The pattern matches `env::temp_dir`, which catches both the fully qualified
# call and a bare `temp_dir()` reached through `use std::env`.
#
# A file may be listed here as a NAMED exception when it genuinely needs the raw
# directory. Prefer having none: the helper's own definition is the only entry
# that should normally be present.
TEMP_DIR_ALLOWED=(
  # Defines the scratch root itself, so it is the one place that must resolve
  # the shared temp directory.
  "crates/plexus-core/src/test_scratch.rs"
  "crates/plexus-conformance/src/artifact.rs" # Fallible CLI scratch roots and private artifact staging directories.
)

refuse_raw_temp_dir() {
  local hits allowed
  hits="$(grep -R -n --exclude-dir=target --include='*.rs' 'env::temp_dir' crates || true)"
  # Positive control, run every time: the scratch helper itself resolves the
  # shared temp directory, so the search must find it before its result means
  # anything. If it does not, the pattern or the search path has drifted and an
  # empty result would be a clean bill from a check that looked at nothing.
  # A here-string, not a pipe: `grep -q` closes a pipe early, and under
  # pipefail the writer's SIGPIPE would read as a miss.
  if ! grep -q "^${TEMP_DIR_ALLOWED[0]}:" <<<"$hits"; then
    echo "refusing: the temp_dir search did not find its own control site" >&2
    echo "  expected a match in ${TEMP_DIR_ALLOWED[0]}; the pattern or path has drifted" >&2
    exit 1
  fi
  for allowed in "${TEMP_DIR_ALLOWED[@]}"; do
    hits="$(printf '%s\n' "$hits" | grep -v "^${allowed}:" || true)"
  done
  hits="$(printf '%s\n' "$hits" | sed '/^$/d')"
  if [ -n "$hits" ]; then
    echo "refusing: raw std::env::temp_dir() under crates/" >&2
    printf '%s\n' "$hits" >&2
    echo >&2
    echo "Use plexus_core::test_scratch::Scratch instead:" >&2
    echo "  Scratch::database(label)      a SQLite store path" >&2
    echo "  Scratch::directory(label)     a directory to write several files into" >&2
    echo "  Scratch::file(label, name)    one named file" >&2
    echo >&2
    echo "Each lands under \$TMPDIR/plexus-tests, is removed when the returned" >&2
    echo "value drops, and is swept by age if a run is killed before that." >&2
    echo "If a site genuinely needs the raw call, add it to TEMP_DIR_ALLOWED in" >&2
    echo "$0 with a comment saying why." >&2
    exit 1
  fi
}

run_phase "no raw std::env::temp_dir() under crates/" refuse_raw_temp_dir

# Test waits that depend on a reply or child exit must carry a deadline. Keep the
# match on the actual method statement so a helper-wrapped call remains allowed.
refuse_unbounded_test_waits() {
  python3 - "$repo_root" <<'PY'
import os
import sys

root = sys.argv[1]
def rust_tokens(source):
    """Tokenize enough Rust to ignore comments and literal contents safely."""
    tokens = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        following = source[index:index + 2]
        if char.isspace():
            index += 1
            continue
        if following == "//":
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if following == "/*":
            index += 2
            depth = 1
            while index < length and depth:
                pair = source[index:index + 2]
                if pair == "/*":
                    depth += 1
                    index += 2
                elif pair == "*/":
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue

        # Raw strings (including byte and C-string prefixes) can contain braces,
        # comment markers, and apparent wait calls without being Rust code.
        prefix = 2 if source.startswith(("br", "cr"), index) else 1 if char == "r" else 0
        if prefix:
            quote = index + prefix
            while quote < length and source[quote] == "#":
                quote += 1
            if quote < length and source[quote] == '"':
                marker = '"' + "#" * (quote - index - prefix)
                close = source.find(marker, quote + 1)
                end = length if close < 0 else close + len(marker)
                tokens.append(("literal", source[index:end], index, end))
                index = end
                continue

        if char == '"':
            start = index
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            tokens.append(("literal", source[start:index], start, index))
            continue

        if char == "'":
            # A character literal closes immediately after one scalar or escape;
            # a lifetime such as 'static does not, and stays ordinary tokens.
            end = index + 1
            if end < length and source[end] == "\\":
                end += 1
                if end < length and source[end] == "u" and end + 1 < length and source[end + 1] == "{":
                    close = source.find("}", end + 2)
                    end = length if close < 0 else close + 1
                elif end < length and source[end] == "x":
                    end = min(length, end + 3)
                else:
                    end = min(length, end + 1)
            elif end < length:
                end += 1
            if end < length and source[end] == "'":
                end += 1
                tokens.append(("literal", source[index:end], index, end))
                index = end
                continue
            tokens.append(("punct", char, index, index + 1))
            index += 1
            continue

        if char == "_" or char.isalpha():
            end = index + 1
            while end < length and (source[end] == "_" or source[end].isalnum()):
                end += 1
            tokens.append(("ident", source[index:end], index, end))
            index = end
            continue

        tokens.append(("punct", char, index, index + 1))
        index += 1
    return tokens


def direct_waits(source):
    tokens = rust_tokens(source)
    waits = []
    for index in range(len(tokens) - 3):
        text = [token[1] for token in tokens[index:index + 4]]
        if text == [".", "output", "(", ")"]:
            waits.append(("output()", tokens[index][2]))
        if (text == [".", "recv", "(", ")"] and index + 5 < len(tokens)
                and tokens[index + 4][1] == "." and tokens[index + 5][1] == "await"):
            waits.append(("recv().await", tokens[index][2]))
    return waits


CFG_TEST = ["#", "[", "cfg", "(", "test", ")", "]"]


def skip_attribute(tokens, index):
    if index + 1 >= len(tokens) or tokens[index][1] != "#" or tokens[index + 1][1] != "[":
        return index
    depth = 1
    cursor = index + 2
    while cursor < len(tokens) and depth:
        if tokens[cursor][1] == "[":
            depth += 1
        elif tokens[cursor][1] == "]":
            depth -= 1
        cursor += 1
    return cursor


def cfg_test_modules(source):
    """Return cfg(test) inline spans and external module declarations."""
    tokens = rust_tokens(source)
    modules = []
    for index in range(len(tokens) - len(CFG_TEST) + 1):
        if [token[1] for token in tokens[index:index + len(CFG_TEST)]] != CFG_TEST:
            continue
        cursor = index + len(CFG_TEST)
        path_value = None
        while cursor + 1 < len(tokens) and tokens[cursor][1] == "#" and tokens[cursor + 1][1] == "[":
            end = skip_attribute(tokens, cursor)
            attribute = tokens[cursor:end]
            if (len(attribute) >= 6 and attribute[2][1] == "path" and attribute[3][1] == "="
                    and attribute[4][0] == "literal"):
                literal = attribute[4][1]
                if literal.startswith('"') and literal.endswith('"'):
                    path_value = literal[1:-1]
            cursor = end
        if cursor < len(tokens) and tokens[cursor][1] == "pub":
            cursor += 1
            if cursor < len(tokens) and tokens[cursor][1] == "(":
                depth = 1
                cursor += 1
                while cursor < len(tokens) and depth:
                    if tokens[cursor][1] == "(":
                        depth += 1
                    elif tokens[cursor][1] == ")":
                        depth -= 1
                    cursor += 1
        if cursor + 2 >= len(tokens) or tokens[cursor][1] != "mod":
            continue
        module_name = tokens[cursor + 1][1]
        terminator = tokens[cursor + 2][1]
        if terminator == ";":
            modules.append(("external", module_name, path_value, None))
        elif terminator == "{":
            depth = 1
            end = cursor + 3
            while end < len(tokens) and depth:
                if tokens[end][1] == "{":
                    depth += 1
                elif tokens[end][1] == "}":
                    depth -= 1
                end += 1
            if depth == 0:
                modules.append(("inline", module_name, path_value,
                                 (tokens[index][2], tokens[end - 1][3])))
    return modules


def resolve_module_file(source_path, module_name, path_value):
    base = os.path.dirname(source_path)
    candidates = [os.path.join(base, path_value)] if path_value else [
        os.path.join(base, module_name + ".rs"),
        os.path.join(base, module_name, "mod.rs"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.realpath(candidate)
    return None


def test_regions(relative, absolute, source, listed_files):
    parts = relative.replace("\\", "/").split("/")
    name = parts[-1]
    canonical = os.path.realpath(absolute)
    if "tests" in parts or canonical in listed_files:
        return [(0, len(source))]
    if "examples" in parts:
        return [span for kind, _, _, span in cfg_test_modules(source) if kind == "inline"]
    if name.startswith("test_") or name.endswith("_tests.rs"):
        return [(0, len(source))]
    if "src" in parts:
        return [span for kind, _, _, span in cfg_test_modules(source) if kind == "inline"]
    return []


def test_waits(relative, absolute, source, listed_files):
    regions = test_regions(relative, absolute, source, listed_files)
    return [(kind, source.count("\n", 0, position) + 1) for kind, position in direct_waits(source)
            if any(start <= position < end for start, end in regions)]


# Controls distinguish production from tests and make a broken cfg(test) span
# extractor fail before the repository scan can report a false clean result.
production_control = "fn writer() { let _reply = rx.recv().await; }"
if test_waits("crates/plexus-module/src/fixture.rs", "/fixture.rs", production_control, set()):
    print("refusing: the wait guard treats a planted production receive as test code", file=sys.stderr)
    sys.exit(1)
inline_control = '''#[cfg(test)] mod t {
    const TEXT: &str = "} rx.recv().await {"; // } comment brace
    const BRACE: char = '}';
    const HEX: char = '\\x7d';
    /* } nested /* { */ comment */
    fn waits() { let _reply = rx.recv().await; }
}'''
if test_waits("crates/plexus-module/src/fixture.rs", "/fixture.rs", inline_control, set()) != [
    ("recv().await", 6)
]:
    print("refusing: cfg(test) module detection missed its planted direct-use control", file=sys.stderr)
    sys.exit(1)
tests_control = "async fn waits() { let _reply = rx.recv().await; let _out = cmd.output(); }"
if test_waits("crates/plexus-core/tests/planted.rs", "/planted.rs", tests_control, set()) != [
    ("recv().await", 1), ("output()", 1)
]:
    print("refusing: the tests/ path guard missed its planted direct-use control", file=sys.stderr)
    sys.exit(1)
example_control = '''fn main() {
    let _reply = rx.recv().await;
    let _out = cmd.output();
}
#[cfg(test)] mod tests { fn waits() { let _reply = rx.recv().await; } }'''
if test_waits("crates/plexus-core/examples/fixture.rs", "/fixture.rs", example_control, set()) != [
    ("recv().await", 5)
]:
    print("refusing: examples main or cfg(test) scope control drifted", file=sys.stderr)
    sys.exit(1)
if test_waits("crates/plexus-module/src/fixture.rs", "/fixture.rs",
               'fn waits() { recv_within(rx.recv(), Duration::from_secs(5), "reply").await; }', set()):
    print("refusing: the receive guard rejected its wrapped positive control", file=sys.stderr)
    sys.exit(1)
if test_waits("crates/plexus-core/tests/planted.rs", "/planted.rs",
               'fn child() { child_output(&mut command, timeout, "test child"); }', set()):
    print("refusing: the child-output guard rejected its wrapped positive control", file=sys.stderr)
    sys.exit(1)

files = {}
for directory, directories, names in os.walk(os.path.join(root, "crates")):
    directories[:] = [name for name in directories if name != "target"]
    for name in names:
        if name.endswith(".rs"):
            path = os.path.realpath(os.path.join(directory, name))
            with open(path, encoding="utf-8") as source_file:
                files[path] = source_file.read()

listed_files = set()
for path, source in files.items():
    for kind, module_name, path_value, _ in cfg_test_modules(source):
        if kind == "external":
            resolved = resolve_module_file(path, module_name, path_value)
            if resolved:
                listed_files.add(resolved)

violations = []
checked = 0
for path, source in files.items():
    relative = os.path.relpath(path, root)
    regions = test_regions(relative, path, source, listed_files)
    if not regions:
        continue
    checked += 1
    for kind, line in test_waits(relative, path, source, listed_files):
        violations.append((relative, line, kind))

if violations:
    print("refusing: test receive and child waits must use bounded helpers", file=sys.stderr)
    for path, line, kind in violations:
        print(f"  {path}:{line}: bare {kind}", file=sys.stderr)
    sys.exit(1)
print(f"    checked receive/child waits in {checked} test-code Rust source file(s); planted controls passed")
PY
}

run_phase "bounded test receive and child waits" refuse_unbounded_test_waits

# A fleet-named executable must not be launched by a test or rig. The helper
# publishes a content-addressed `ckdev-` copy before an executable path is used,
# making process listings distinguish test runs from deployed cards.
# Check that every Cargo binary reference is lexically inside that helper call;
# semicolon-delimited statements keep an adjacent direct spawn from borrowing a
# wrapped reference on the previous line.
# Keep this all-reference scan alongside the shared spawn guard: conformance
# launchers resolve Cargo paths with var_os and pass them into supervisor config,
# rather than using the env! and Command::new shapes the shared guard recognises.
refuse_ckdev_binary_names() {
  python3 - "$repo_root" <<'PY'
import os
import sys

root = sys.argv[1]
needle = "CARGO_BIN_EXE_ck-"

def unchecked_references(source):
    """Return each fleet binary literal not nested in ckdev_binary(...)."""
    misses = []
    pending = []
    stack = []
    statement = 1
    line = 1
    index = 0
    last_identifier = ""
    state = "code"
    block_depth = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1:index + 2]
        if char == "\n":
            line += 1
        if state == "line-comment":
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block-comment":
            if char == "/" and following == "*":
                block_depth += 1
                index += 2
                continue
            if char == "*" and following == "/":
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            index += 1
            continue
        if state in ("string", "char"):
            if state == "string" and source.startswith(needle, index):
                helper_frames = [depth for depth, wrapped in enumerate(stack) if wrapped]
                if helper_frames:
                    # A reference stays provisional until its helper call closes.
                    # A semicolon inside the still-open call means this belongs to
                    # a nested block statement, not just the helper's path input.
                    pending.append((line, statement, helper_frames[-1]))
                else:
                    misses.append((line, statement))
                index += len(needle)
                continue
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
            index += 1
            continue
        if char == "/" and following == "/":
            state = "line-comment"
            index += 2
            continue
        if char == "/" and following == "*":
            state = "block-comment"
            block_depth = 1
            index += 2
            continue
        if char == '"':
            state = "string"
            index += 1
            continue
        if char == "'":
            # Lifetimes have no closing quote. Skip only actual one-character
            # literals so punctuation inside them cannot alter call nesting.
            if following == "\\":
                close = source.find("'", index + 2)
                if close != -1:
                    state = "char"
                    index += 1
                    continue
            elif index + 2 < len(source) and source[index + 2] == "'":
                state = "char"
                index += 1
                continue
        if char.isalnum() or char == "_":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] == "_"):
                end += 1
            last_identifier = source[index:end]
            index = end
            continue
        if char == "(":
            stack.append(last_identifier == "ckdev_binary")
            last_identifier = ""
        elif char == ")":
            if stack:
                frame = len(stack) - 1
                wrapped = stack.pop()
                if wrapped:
                    pending = [reference for reference in pending if reference[2] != frame]
            last_identifier = ""
        elif char == ";":
            # A helper call must close without an inner statement boundary for
            # its reference to count as wrapped. Reset active frames, and reject
            # pending references whose helper call is still open.
            stack = [False] * len(stack)
            remaining = []
            for reference in pending:
                frame = reference[2]
                if frame < len(stack) and not stack[frame]:
                    misses.append(reference[:2])
                else:
                    remaining.append(reference)
            pending = remaining
            statement += 1
            last_identifier = ""
        elif not char.isspace():
            last_identifier = ""
        index += 1
    return misses

# Controls run on every gate invocation. The first proves helper-wrapped input
# is accepted. The next three prove adjacent spawns, unrelated helper calls, and
# direct spawns in helper argument blocks are all refused.
wrapped = 'Command::new(ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus")));'
if unchecked_references(wrapped):
    print("refusing: the ckdev guard rejects its wrapped positive control", file=sys.stderr)
    sys.exit(1)
wrapped_then_direct = (
    'let wrapped = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));\n'
    'Command::new(env!("CARGO_BIN_EXE_ck-plexus"));'
)
if len(unchecked_references(wrapped_then_direct)) != 1:
    print("refusing: the ckdev guard missed its adjacent direct-spawn control", file=sys.stderr)
    sys.exit(1)
unrelated_helper = (
    'let pair = (ckdev_binary(path), env!("CARGO_BIN_EXE_ck-plexus"));'
)
if len(unchecked_references(unrelated_helper)) != 1:
    print("refusing: the ckdev guard accepted an unrelated helper call", file=sys.stderr)
    sys.exit(1)
block_spawn = (
    'ckdev_binary({ Command::new(env!("CARGO_BIN_EXE_ck-plexus")).status().ok(); path });'
)
if len(unchecked_references(block_spawn)) != 1:
    print("refusing: the ckdev guard accepted a direct spawn in a helper argument block", file=sys.stderr)
    sys.exit(1)

site_count = 0
violations = []
for directory, directories, names in os.walk(os.path.join(root, "crates")):
    directories[:] = [name for name in directories if name != "target"]
    for name in names:
        if not name.endswith(".rs"):
            continue
        path = os.path.join(directory, name)
        with open(path, encoding="utf-8") as source_file:
            source = source_file.read()
        if needle in source:
            site_count += source.count(needle)
            for line, statement in unchecked_references(source):
                violations.append((os.path.relpath(path, root), line, statement))
if site_count == 0:
    print("refusing: no CARGO_BIN_EXE_ck- sites were checked", file=sys.stderr)
    sys.exit(1)
if violations:
    print("refusing: CARGO_BIN_EXE_ck- must be passed through ckdev_binary(...) in the same statement", file=sys.stderr)
    for path, line, statement in violations:
        print(f"  {path}:{line} (statement {statement})", file=sys.stderr)
    sys.exit(1)
print(f"    checked {site_count} CARGO_BIN_EXE_ck- site(s); all use ckdev_binary")
PY
}

run_phase "no fleet-named test executable launches" refuse_ckdev_binary_names

# Refuse any path dependency, [patch] entries included, that resolves outside
# this repository. Shared dependencies must come from the registry at the
# versions selected by this workspace's committed lock.
#
# It reads the resolved graph: every package cargo resolved from a path has no
# `source`, and its manifest must sit under the repository root.
refuse_outside_path_deps() {
  python3 scripts/check-path-deps.py --self-test
  python3 scripts/check-path-deps.py
}

run_phase "no path dependency outside the repository" refuse_outside_path_deps

# Internal notes, investigations and audit ledgers live in the gitignored
# .cortexkit/ folder, never in the published tree. The check exits 1 when
# a file under .cortexkit/ that the ignore rules exclude is tracked anyway (it
# can only get there by force-adding), and 2 when the .gitignore block is
# missing, because then nothing is ignored and the first check would pass by
# looking at nothing.
run_phase "no internal CortexKit file is tracked" \
  bash scripts/check-cortexkit-layout.sh

# Test scripts/train*.sh, scripts/watch-ci.sh and staging verification against
# stubbed external tools. The Python runner first verifies it counts and reports
# a deliberately failing test and a passing test, then discovers test_*.py.
# It refuses failures and runs that discover no tests.
run_phase "operator script regression tests" \
  python3 -B scripts/tests/run.py

# Formatting check, scoped to this workspace's own members.
#
# Registry dependencies are not this repository's formatting responsibility.
# `--no-deps` names only
# the members declared in this Cargo.toml, which is the set this gate is
# actually responsible for.
#
# The list is derived rather than hardcoded: a new crate added to the workspace
# is covered without anyone remembering to add it, and an empty list refuses
# rather than silently checking nothing.
FMT_MEMBERS=()
while IFS= read -r member; do
  FMT_MEMBERS+=(-p "$member")
done < <(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; [print(p["name"]) for p in json.load(sys.stdin)["packages"]]')
if [ ${#FMT_MEMBERS[@]} -eq 0 ]; then
  echo "refusing: cargo metadata named no workspace members to format-check" >&2
  exit 1
fi

# `cargo fmt --all` must be run before committing; this check fails the gate on
# an unformatted commit.
run_phase "cargo fmt (workspace members) -- --check" \
  cargo fmt "${FMT_MEMBERS[@]}" -- --check

# Clippy with warnings as errors, across all targets.
# `--locked` makes a stale or absent Cargo.lock a FAILURE rather than a silent
# re-resolve. Without it the committed lock is advisory: cargo quietly updates
# it and the run proceeds against a dependency set nobody chose, which is the
# state the lock exists to prevent. A fresh resolve can move many packages,
# including rustls and http, with no git diff to show for it.
run_phase "cargo clippy --workspace --all-targets --locked --quiet -- -D warnings" \
  cargo clippy --workspace --all-targets --locked --quiet -- -D warnings

# The shipped feature set, compiled on its own.
#
# plexus-conformance depends on plexus-core with `test-support` as a NORMAL
# dependency, because the harness legitimately drives the stub credential
# source, transport and decision plane. Cargo's resolver unifies that feature
# into every build that selects the conformance crate, which every
# `--workspace` command in this gate does. Without the phases below, no gate
# command compiles plexus-core or ck-plexus the way a release does: a
# production call to a test-support-gated item, or code that is dead only in
# the shipped configuration, would surface first at release time.
#
# Selecting only the shipped packages, with no test, example or bench target,
# leaves dev-dependency features out, so `test-support` stays off. The feature
# tree is checked first: a selection change that lets the feature back in then
# fails here, instead of quietly turning the compile below into one more
# test-support build.
refuse_test_support_in_shipped_features() {
  local control shipped
  control="$(cargo tree --locked -e normal,build,features -p plexus-conformance -i plexus-core)"
  # Positive control, run every time: the conformance harness does enable the
  # feature, so the search must find it there. Otherwise the pattern or the
  # cargo tree output format has drifted, and an empty result below would be a
  # clean bill from a check that recognises nothing.
  if ! grep -q 'plexus-core feature "test-support"' <<<"$control"; then
    echo "refusing: the feature-tree search did not find test-support in its control" >&2
    echo "  expected plexus-conformance to enable plexus-core feature \"test-support\"" >&2
    exit 1
  fi
  shipped="$(cargo tree --locked -e normal,build,features -p plexus-core -p plexus-module)"
  if grep -q 'feature "test-support"' <<<"$shipped"; then
    echo "refusing: the shipped package set enables a test-support feature" >&2
    grep 'feature "test-support"' <<<"$shipped" >&2
    exit 1
  fi
}

run_phase "shipped packages build without test-support" \
  refuse_test_support_in_shipped_features
run_phase "cargo check --locked -p plexus-core --lib (shipped features)" \
  cargo check --locked --quiet -p plexus-core --lib
run_phase "cargo clippy --locked -p plexus-module --bins (shipped features) -- -D warnings" \
  cargo clippy --locked --quiet -p plexus-module --bins -- -D warnings

# Compile and run library, binary and integration tests.
run_phase "cargo test --workspace --locked --quiet" \
  cargo test --workspace --locked --quiet

# Example diagnostics carry their own credential-redaction contract; Cargo's
# default test selection compiles examples but does not run their unit tests.
run_phase "cargo test --workspace --examples --locked --quiet" \
  cargo test --workspace --examples --locked --quiet
