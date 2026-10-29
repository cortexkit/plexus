#!/usr/bin/env bash
# CI parity: fast locally, full on Linux, or a combined run dispatching full via Motor.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

require_pass() {
  python3 - "$1" <<'PY'
import json, pathlib, subprocess, sys, time

def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()

try:
    sha = git("rev-parse", "--verify", sys.argv[1] + "^{commit}")
    receipt = pathlib.Path(git("rev-parse", "--git-path", "plexus-prepush")) / (sha + ".json")
    data = json.loads(receipt.read_text())
    age = time.time() - data["passed_at"]
    if data["sha"] != sha or data["tree"] != git("rev-parse", sha + "^{tree}") or not 0 <= age <= 86400:
        raise ValueError("receipt does not match the commit or freshness window")
except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
    sys.exit("prepush: no PASS in the last 24 hours for this commit; run scripts/prepush.sh on the commit to push")
print("prepush: recent PASS verified for " + sha)
PY
}

mode="${1:-}"
case "$mode" in
  --require-pass)
    [ "$#" -eq 2 ] || { echo "usage: scripts/prepush.sh [--require-pass COMMIT]" >&2; exit 2; }
    require_pass "$2"
    exit ;;
  --fast|--full) [ "$#" -eq 1 ] || exit 2 ;;
  '') [ "$#" -eq 0 ] || exit 2 ;;
  *) echo "usage: scripts/prepush.sh [--fast|--full|--require-pass COMMIT]" >&2; exit 2 ;;
esac

sha="$(git rev-parse HEAD)"
step="clean committed source"
trap 'echo "FAIL prepush${mode/--/-}: $sha ($step)" >&2' ERR
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "Commit all intended changes before running the full gate; a PASS must name the tested commit." >&2
  false
fi

case "$mode" in
  --fast)
    step="fast local preflight (no compilation)"
    echo "==> $step"
    bash scripts/rust-test-gate.sh --fast ;;
  --full)
    step="full Linux CI parity gate (failing substep is printed above)"
    bash scripts/rust-test-gate.sh --ci ;;
  '')
    receipt_dir="$(git rev-parse --git-path plexus-prepush)"
    mkdir -p "$receipt_dir"
    # A failed retry must not leave an older green receipt authorizing a push.
    rm -f "$receipt_dir/$sha.json"
    step="fast local preflight"
    bash scripts/prepush.sh --fast
    step="Linux CI parity gate (16 vCPUs; failing substep is printed above)"
    ck motor run --platform linux --vcpus 16 --net --timeout 7200 \
      --env CARGO_PROFILE_DEV_DEBUG=0 --env CARGO_PROFILE_TEST_DEBUG=0 \
      --env CARGO_INCREMENTAL=0 -- bash scripts/prepush.sh --full ;;
esac

step="source unchanged during gate"
[ "$(git rev-parse HEAD)" = "$sha" ]
[ -z "$(git status --porcelain --untracked-files=normal)" ]
case "$mode" in
  --fast) echo "PASS prepush-fast: $sha (local; no compilation)"; exit 0 ;;
  --full) echo "PASS prepush-full: $sha (Linux CI parity)"; exit 0 ;;
esac
python3 - "$receipt_dir/$sha.json" "$sha" <<'PY'
import json, pathlib, subprocess, sys, time
path = pathlib.Path(sys.argv[1])
data = {"sha": sys.argv[2], "tree": subprocess.check_output(
    ["git", "rev-parse", sys.argv[2] + "^{tree}"], text=True).strip(), "passed_at": time.time()}
temporary = path.with_suffix(".partial")
temporary.write_text(json.dumps(data) + "\n")
temporary.replace(path)
PY
echo "PASS prepush: $sha (fast local + full Linux CI parity; valid 24h)"
