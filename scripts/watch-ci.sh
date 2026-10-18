#!/usr/bin/env bash
# Maintainer landing watcher; outside contributors do not need this train lane.
# Operator tooling runs through the real GitHub CLI (gh); the shim is only for AI agent commands.
# Watch a CI run and FAIL FAST: exit the moment any job concludes 'failure',
# without waiting for the rest of the run. Exit 0 only when the whole run
# succeeds. Prints the first failing job's failed-test lines on the way out.
#
# WATCH_CI_SETTLE=1: on failure, keep waiting until the RUN completes before
# exiting nonzero. Chains that intend to `"$OPERATOR_GH" run rerun --failed`
# need this - a rerun request against a still-running run is refused ("cannot
# be rerun; This workflow is already running"), which has burned rerun-then-watch
# chains twice. Fail-fast reporting still prints immediately; only the exit
# is deferred to rerun-safety.
#
# Usage:
#   scripts/watch-ci.sh            # run for the local HEAD sha
#   scripts/watch-ci.sh <run-id>
#   scripts/watch-ci.sh <sha>      # run for any branch head, e.g. a train branch
#   WATCH_CI_SETTLE=1 scripts/watch-ci.sh <run-id>
#
# The watch is bounded. WATCH_CI_TIMEOUT (seconds, default 14400 = 4 h, past the
# longest job timeout in ci.yml plus queueing) caps the whole watch, and
# WATCH_CI_MAX_POLL_ERRORS (default 20 consecutive failed status polls, about
# 15 minutes at the default cadence) ends a watch whose gh calls keep failing.
# Either ends with exit 3 (CI_UNDETERMINED), which train-push.sh reports as a
# pushed-but-unwatched train rather than a verdict: nothing lands, and a re-run
# attaches to the same run.
set -uo pipefail

# The repository the runs live in: from the checkout's origin unless REPO is
# given. A fixed default was the first thing a lift of this script kept by
# accident, so a lifted copy watched THIS repository's runs for another repo's
# trains. Both github.com URL forms are accepted; anything else refuses so the
# watch never quietly targets the wrong repository.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/repository-identity.sh"
repo_from_origin() {
  local url
  url="$(git config --get remote.origin.url 2>/dev/null)" || return 1
  github_repository_slug "$url"
}
if [ -z "${REPO:-}" ]; then
  REPO="$(repo_from_origin)" || {
    echo "watch-ci: cannot derive the repository from origin; set REPO=owner/name" >&2
    exit 2
  }
fi
# Which workflow gates a landing. A sha can carry runs from several workflows
# (cost-gate, testbox), so resolving a run BY SHA has to name the gating one or
# it can latch a run that says nothing about the tests.
WORKFLOW="${WATCH_CI_WORKFLOW:-ci.yml}"
# Which trigger produced the run. A sha is not unique across triggers either: a
# commit that a schedule (or workflow_dispatch) later re-ran carries several
# runs of the same workflow with possibly different conclusions, and the
# newest-first list then answers for whichever fired last. A landing asks
# whether THIS PUSH is green, so the default is the push run; set the event to
# watch a different trigger's run for the same sha.
EVENT="${WATCH_CI_EVENT:-push}"
BRANCH="${WATCH_CI_BRANCH:-}"
# How long to wait for a run to appear for a sha: 40 tries, 15s apart, is ten
# minutes of patience for a queue that normally produces a run in seconds. Both
# knobs exist so tests can drive the resolver without waiting out that budget.
RESOLVE_ATTEMPTS="${WATCH_CI_RESOLVE_ATTEMPTS:-40}"
RESOLVE_SLEEP="${WATCH_CI_RESOLVE_SLEEP:-15}"
POLL_SLEEP="${WATCH_CI_POLL_SLEEP:-45}"
HEARTBEAT="${WATCH_CI_HEARTBEAT:-}"
# Without these the status loop below had no exit but a verdict: a gh that kept
# failing (expired auth, a revoked token, a network that never came back) read
# as `poll-error` forever, and a train waiting on this watch hung with it.
WATCH_TIMEOUT="${WATCH_CI_TIMEOUT:-14400}"
MAX_POLL_ERRORS="${WATCH_CI_MAX_POLL_ERRORS:-20}"
for bound in WATCH_TIMEOUT MAX_POLL_ERRORS RESOLVE_ATTEMPTS; do
  if ! [[ "${!bound}" =~ ^[1-9][0-9]*$ ]]; then
    echo "watch-ci: ${bound} must be a positive integer (got '${!bound}')" >&2
    exit 2
  fi
done
for bound in RESOLVE_SLEEP POLL_SLEEP; do
  if ! [[ "${!bound}" =~ ^[0-9]+$ ]]; then
    echo "watch-ci: ${bound} must be a non-negative integer (got '${!bound}')" >&2
    exit 2
  fi
done
WATCH_STARTED=$SECONDS
POLL_ERRORS=0
WATCH_ATTEMPT="${WATCH_CI_ATTEMPT:-}"
if [ -n "$WATCH_ATTEMPT" ]; then
  if ! [[ "$WATCH_ATTEMPT" =~ ^[1-9][0-9]*$ ]]; then
    echo "watch-ci: WATCH_CI_ATTEMPT must be a positive integer" >&2
    exit 2
  fi
fi
HEARTBEAT_TMP=""
SLEEP_PID=""
STATUS_FILE="$(mktemp "${TMPDIR:-/tmp}/watch-ci-status.XXXXXX")" || exit 2

watcher_start_time() {
  ps -p "$$" -o lstart= 2>/dev/null | awk '{$1=$1; print}'
}
WATCHER_START="$(watcher_start_time)"

cleanup_watch() {
  if [ -n "$SLEEP_PID" ]; then
    kill "$SLEEP_PID" 2>/dev/null || true
    wait "$SLEEP_PID" 2>/dev/null || true
  fi
  [ -z "$HEARTBEAT_TMP" ] || rm -f "$HEARTBEAT_TMP"
  [ -z "$HEARTBEAT" ] || rm -f "$HEARTBEAT"
  rm -f "$STATUS_FILE"
}
trap cleanup_watch EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

write_heartbeat() {
  [ -n "$HEARTBEAT" ] || return 0
  HEARTBEAT_TMP="$HEARTBEAT.tmp.$$"
  {
    printf 'pid=%s\n' "$$"
    printf 'start=%s\n' "$WATCHER_START"
    printf 'updated=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } > "$HEARTBEAT_TMP"
  mv "$HEARTBEAT_TMP" "$HEARTBEAT"
  HEARTBEAT_TMP=""
}

watch_sleep() {
  sleep "$1" &
  SLEEP_PID=$!
  wait "$SLEEP_PID"
  sleep_rc=$?
  SLEEP_PID=""
  return "$sleep_rc"
}

watch_run_view() {
  if [ -n "$WATCH_ATTEMPT" ]; then
    "$OPERATOR_GH" run view "$@" --attempt "$WATCH_ATTEMPT"
  else
    "$OPERATOR_GH" run view "$@"
  fi
}

# A completed run's verdict is read with queries that must succeed. A gh
# failure (network, rate limit, auth) answers with empty output, and an empty
# conclusion or job list would otherwise read as "nothing failed" and land an
# unverified sha. Retry briefly, then fail closed with exit 3.
verdict_query() {
  local run="$1" out attempt
  shift
  for attempt in 1 2 3; do
    if out=$(watch_run_view "$run" --repo "$REPO" "$@" 2>/dev/null) && [ -n "$out" ]; then
      printf '%s' "$out"
      return 0
    fi
    [ "$attempt" -lt 3 ] && watch_sleep "${WATCH_CI_VERDICT_RETRY_SLEEP:-5}"
  done
  return 1
}

undetermined() {
  echo "CI_UNDETERMINED run=$RID reason='$1'${WATCH_ATTEMPT:+ attempt=$WATCH_ATTEMPT}" >&2
  exit 3
}

# Read the run's status, counting consecutive failures. Ends the watch when the
# overall deadline has passed or gh has failed too many times in a row.
poll_status() {
  local status
  if [ $((SECONDS - WATCH_STARTED)) -ge "$WATCH_TIMEOUT" ]; then
    undetermined "the run did not finish within ${WATCH_TIMEOUT}s"
  fi
  if status=$(watch_run_view "$RID" --repo "$REPO" --json status --jq '.status' 2>/dev/null) &&
    [ -n "$status" ]; then
    POLL_ERRORS=0
    printf '%s' "$status"
    return 0
  fi
  POLL_ERRORS=$((POLL_ERRORS + 1))
  if [ "$POLL_ERRORS" -ge "$MAX_POLL_ERRORS" ]; then
    undetermined "the run status could not be read ${POLL_ERRORS} times in a row"
  fi
  printf 'poll-error'
}

ARG="${1:-}"
RID=""
WATCH_SHA=""
# The only positional is a numeric run id or a commit sha. A flag-shaped or
# otherwise unrecognized arg (e.g. a misremembered --sha invocation) would
# otherwise become the "run id", drive `"$OPERATOR_GH" run view` into
# poll-error, and spin this watch forever - hanging any chain that expects it
# to exit and notify.
#
# Run ids are decimal and around 11 digits; a sha is 7-40 hex characters. The
# two only overlap for an all-decimal sha, so length decides that case: a
# 32-or-longer all-decimal string is a sha, never a run id.
#
# Anything that is not a run id is resolved through git rather than pattern
# matched: the run lookup below compares against the FULL head sha, so a short
# sha stored verbatim never matches and the watch reports "no run appeared"
# after the whole poll budget. Resolving also admits tags, branch names and
# HEAD~n, and dereferences an annotated tag to the commit that carries runs.
if [ -n "$ARG" ]; then
  if [[ "$ARG" =~ ^[0-9]+$ ]] && [ "${#ARG}" -lt 32 ]; then
    RID="$ARG"
  elif WATCH_SHA=$(git rev-parse --verify --quiet "${ARG}^{commit}"); then
    :
  else
    echo "watch-ci: argument must be a numeric run id or a commit ref this checkout can resolve (got '$ARG'); pass nothing to watch HEAD's run" >&2
    exit 2
  fi
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/operator-gh.sh" || exit 1

if [ -z "$RID" ]; then
  # Grabbing the newest run right after a push races run creation and latches
  # a stale (often already-failed) run. Resolve the run FOR A SPECIFIC SHA,
  # polling until it appears.
  #
  # The sha, not the branch, is what identifies the run: watching by branch
  # would follow whatever lands there next, and a train is watched on its own
  # branch head rather than on main.
  if [ -z "$WATCH_SHA" ]; then
    WATCH_SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
  fi
  for _ in $(seq 1 "$RESOLVE_ATTEMPTS"); do
    if [ -n "$BRANCH" ]; then
      RID=$("$OPERATOR_GH" run list --repo "$REPO" --workflow "$WORKFLOW" --event "$EVENT" --limit 40 \
        --branch "$BRANCH" \
        --json databaseId,headSha,headBranch \
        --jq ".[] | select(.headSha==\"$WATCH_SHA\") | .databaseId" | head -1)
    else
      RID=$("$OPERATOR_GH" run list --repo "$REPO" --workflow "$WORKFLOW" --event "$EVENT" --limit 40 \
        --json databaseId,headSha \
        --jq ".[] | select(.headSha==\"$WATCH_SHA\") | .databaseId" | head -1)
    fi
    [ -n "$RID" ] && break
    watch_sleep "$RESOLVE_SLEEP"
  done
  if [ -z "$RID" ]; then
    echo "no $WORKFLOW run (event=$EVENT) appeared for $WATCH_SHA" >&2
    exit 2
  fi
fi
echo "watching run $RID (fail-fast)"

# Print the URL on a machine-greppable line: callers that wrap this watch
# (train-push.sh) report the run to the operator without a second gh query.
RUN_URL=$(watch_run_view "$RID" --repo "$REPO" --json url --jq '.url' 2>/dev/null || echo "")
if [ -n "$RUN_URL" ] && [ "$RUN_URL" != "null" ]; then
  echo "CI_RUN_URL $RUN_URL"
fi

while true; do
  write_heartbeat
  # Not a command substitution: poll_status counts failures in this shell and
  # may end the watch, neither of which survives a subshell.
  poll_status > "$STATUS_FILE"
  STATUS="$(cat "$STATUS_FILE")"
  # Every failing job fails the train, including 'Bash permission e2e
  # (Windows)'. That job is continue-on-error in PR mode (_unit-suite.yml
  # strict=false), but it is a required check on main, so a red there makes
  # the landing refuse; treating it as advisory only hid the failure until
  # the end of the run.
  FAILED_JOB=$(watch_run_view "$RID" --repo "$REPO" --json jobs \
    --jq '[.jobs[] | select(.conclusion=="failure")][0] | if . == null then "" else .name + "|" + (.databaseId|tostring) end' 2>/dev/null || echo "")

  if [ -n "$FAILED_JOB" ] && [ "$FAILED_JOB" != "null" ]; then
    NAME="${FAILED_JOB%%|*}"; JID="${FAILED_JOB##*|}"
    echo "CI_EARLY_FAIL job='$NAME' run=$RID"
    watch_run_view --repo "$REPO" --job "$JID" --log-failed 2>/dev/null \
      | grep -aE "FAIL \[|panicked at|error\[|bash startup failure" | head -8
    if [ "${WATCH_CI_SETTLE:-0}" = "1" ]; then
      echo "settling: waiting for run completion so a rerun is accepted"
      while poll_status > "$STATUS_FILE" && [ "$(cat "$STATUS_FILE")" != "completed" ]; do
        write_heartbeat
        watch_sleep "$POLL_SLEEP"
      done
    fi
    exit 1
  fi

  if [ "$STATUS" = "completed" ]; then
    if ! CONC=$(verdict_query "$RID" --json conclusion --jq '.conclusion'); then
      undetermined "could not read the run conclusion"
    fi
    if [ "$CONC" = "success" ]; then
      echo "CI_DONE run=$RID conclusion=$CONC${WATCH_ATTEMPT:+ attempt=$WATCH_ATTEMPT}"
      exit 0
    fi
    # The run's summary conclusion can read non-success while every job
    # passed or was skipped; judge the jobs, which are what main requires.
    # Only a successful query that lists jobs may conclude "all passed": an
    # empty answer from a failed or truncated query must not read as green.
    if ! JOB_COUNT=$(verdict_query "$RID" --json jobs --jq '.jobs | length') \
      || ! [[ "$JOB_COUNT" =~ ^[0-9]+$ ]] || [ "$JOB_COUNT" -eq 0 ]; then
      undetermined "could not list the run's jobs (conclusion=$CONC)"
    fi
    # The "bad=" prefix keeps a legitimately empty list distinguishable from
    # a query that printed nothing.
    if ! GATING_BAD=$(verdict_query "$RID" --json jobs \
      --jq '"bad=" + ([.jobs[] | select(.conclusion!="success" and .conclusion!="skipped") | .name] | join("; "))'); then
      undetermined "could not read job conclusions (conclusion=$CONC)"
    fi
    GATING_BAD="${GATING_BAD#bad=}"
    if ! SUCCESS_COUNT=$(verdict_query "$RID" --json jobs \
      --jq '[.jobs[] | select(.conclusion=="success")] | length') \
      || ! [[ "$SUCCESS_COUNT" =~ ^[0-9]+$ ]]; then
      undetermined "could not count successful jobs (conclusion=$CONC)"
    fi
    if [ -z "$GATING_BAD" ] && [ "$SUCCESS_COUNT" -gt 0 ]; then
      echo "CI_DONE run=$RID conclusion=$CONC jobs_all_passed=1${WATCH_ATTEMPT:+ attempt=$WATCH_ATTEMPT}"
      exit 0
    fi
    echo "CI_DONE run=$RID conclusion=$CONC gating_failed='$GATING_BAD'${WATCH_ATTEMPT:+ attempt=$WATCH_ATTEMPT}"
    exit 1
  fi

  watch_sleep "$POLL_SLEEP"
done
