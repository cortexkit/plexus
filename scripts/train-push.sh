#!/usr/bin/env bash
# Maintainer landing tool; outside contributors do not need this push lane.
# Push a train to its own branch, let CI be the gate, and advance main only on
# green. Operator tooling runs through the real GitHub CLI (gh) via watch-ci.sh;
# the shim is only for AI agent commands.
#
# Lifting this into another repository: carry scripts/train-push.sh,
# scripts/watch-ci.sh, scripts/lib/{operator-gh.sh,repository-identity.sh,
# workflow-gates.py} and a .github/repository-id resolved from its GitHub API —
# plus `python3`, `git`, and the real `gh` on PATH. The default branch
# is read from origin/HEAD, and repo-local preflights run only when their
# scripts exist (see "Repo-local preflights" below), with the header line
# naming which ones ran.
#
# CI must pass on the exact commit that lands. A targeted local smoke test can
# find an obvious break early, but does not replace the repository's CI gate.
#
# The contract we keep is "main is never red". That is a property of what lands
# on main, not of where the tests ran: nothing lands here except a sha whose CI
# run concluded success, and it lands by fast-forward only - never a merge,
# never a force.
#
# EDIT THIS FILE BY WRITE-TEMP-THEN-RENAME, NEVER IN PLACE. A running bash holds
# an open fd and reads on by byte offset, so an in-place write (same inode) makes
# a live train resume at the wrong offset and die on a syntax error in code it
# never reached - "line 789: syntax error near unexpected token `('" in a file
# that passes `bash -n` before and after. A rename into place (new inode) leaves
# the live run on the old bytes. Nothing lands from such a failure: it happens before
# the landing push, and the ref left behind is the recoverable repush state.
#
# A MERGE IS ITSELF A TRAIN PUSH. Under required status checks, a merge commit
# made locally has no check of its own - main's protection sees an unchecked
# sha and refuses the push, however green both sides were separately. So do the
# merge on the train branch, let CI run on the merge sha, and fast-forward main
# to that same sha. A merge commit whose first parent is origin/main is already
# a descendant of it, so it fast-forwards like any other train.
#
# Usage:
#   scripts/train-push.sh <train-name>
#   scripts/train-push.sh <train-name> --land
#   scripts/train-push.sh <train-name> -- <local smoke command...>
#
# The optional smoke is the targeted slice the diff touches (the one or two
# suites you would rerun by hand), NOT the full gate. It exists to catch an
# obvious break before spending a CI run.
#
# A red train leaves origin/train/<train-name> in place: fix, commit, and run
# this script again with the same name to update the branch and re-run CI.
#
# If main moves while CI runs, the train is re-queued automatically: rebase onto
# the new origin/main, re-push the branch, watch a fresh run - up to 3 rounds.
# Automatic re-queueing is only for a moved default branch. Re-running this
# script on the same sha may explicitly rerun failed or cancelled CI jobs.
#
# THE INVARIANT THE RE-QUEUE KEEPS: only the sha a check actually ran against
# may fast-forward main. A green run for the pre-rebase sha proves something
# about a base that no longer exists, so it never authorizes the landing of the
# rebased commit; the rebased sha gets pushed and waits for its own run. That is
# also why a moved main cannot be resolved by pushing the old sha harder.
#
# RELEASES ARE TRAINS TOO. Under required checks a release tag must point at a
# sha that is already on the default branch by fast-forward and carries the
# green check, so the sequence is: train, fast-forward, tag the green sha. The
# local full gate drops out of the release scripts along with everything else -
# tagging a locally-gated sha that never went through a train produces a tag
# whose commit no check ever saw.
#
# WHERE BRANCH PROTECTION IS UNAVAILABLE (a private repo on a Free plan has no
# required status checks), this script's fast-forward-only-on-green IS the gate.
# Nothing on the server will stop a direct push then, so the discipline of
# pushing through here is the whole of the contract.
#
# Exit codes:
#   0  landed on the default branch
#   1  CI red
#   2  precondition refusal, bad usage, failed smoke, or no CI run resolved
#   3  the default branch kept moving through 3 re-queue rounds, or the rebase
#      conflicted
#   4  CI is green, but landing or its outcome verification failed; re-run
#      with --land to finish without paying for another CI run
set -euo pipefail

# Run from a private copy of this file. bash reads a script incrementally, so an
# edit to scripts/train-push.sh while a train is watching CI (a pick of a
# peer's fix, a rebase that moves the file) shifts the running instance's read
# offset and it can die at its next statement with a syntax error, after CI
# goes green and before the fast-forward. The copy is immune.
if [ -z "${TRAIN_PUSH_EXEC_COPY:-}" ]; then
  train_push_copy="$(mktemp "${TMPDIR:-/tmp}/train-push.XXXXXX")"
  cp "${BASH_SOURCE[0]}" "$train_push_copy"
  TRAIN_PUSH_EXEC_COPY="$train_push_copy" exec bash "$train_push_copy" "$@"
fi
trap 'rm -f "$TRAIN_PUSH_EXEC_COPY"' EXIT

repo_slug_override="${REPO:-}"
REPO="$(git rev-parse --show-toplevel)" || {
  printf 'train-push: refusing — cannot resolve the repository while the current working directory is valid\n' >&2
  exit 2
}
script_dir="$REPO/scripts"

remote="origin"
# Resolved from the remote below, never assumed: this repo's default branch is
# main today, but a script that hardcodes it silently lands trains on a branch
# that is not the one protection and CI are configured for.
default_branch=""
# The workflow whose run gates a landing, shared with watch-ci.sh so the probe
# and the watch cannot disagree about which run counts. WATCH_CI_WORKFLOW is
# the one override for both scripts (a lift with `ci.yml` sets it once); the
# step-0 scan below reads the same variable, so the file it checks and the run
# it waits for cannot name two different workflows.
tests_workflow_name="${WATCH_CI_WORKFLOW:-ci.yml}"
# CI and every push must resolve to the tracked repository identity, even when
# REPO overrides the slug used to look up checks.
repo_slug="$repo_slug_override"
# How long the first-run probe waits for a run to start. Overridable for the
# same reason watch-ci.sh's resolver knobs are: tests cannot wait out the
# real budget.
probe_attempts="${TRAIN_PUSH_PROBE_ATTEMPTS:-12}"
probe_sleep="${TRAIN_PUSH_PROBE_SLEEP:-10}"
say() { printf 'train-push: %s\n' "$1"; }
refuse() {
  printf 'train-push: refusing — %s\n' "$1" >&2
  exit 2
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
if [ "$#" -eq 0 ]; then
  refuse "no train name given (usage: scripts/train-push.sh <train-name> [--land | -- <smoke command>])"
fi

train_name="$1"
shift
case "$train_name" in
  -*) refuse "train name must not look like a flag (got '$train_name')" ;;
esac

land_only=0
smoke_given=0
smoke_cmd=()
if [ "$#" -gt 0 ]; then
  if [ "$1" = "--land" ]; then
    land_only=1
    shift
    [ "$#" -eq 0 ] || refuse "--land does not accept a smoke command"
  elif [ "$1" = "--" ]; then
    shift
    if [ "$#" -eq 0 ]; then
      refuse "-- given without a smoke command"
    fi
    smoke_given=1
    smoke_cmd=("$@")
  else
    refuse "unexpected argument '$1' (use --land, or put the smoke command after a bare --)"
  fi
fi

train_ref="train/$train_name"
# Validate before the name reaches a refspec: a name with a space, a leading
# dot, or '..' in it produces a confusing git error deep in the push instead of
# a named refusal here.
if ! git -C "$REPO" check-ref-format "refs/heads/$train_ref"; then
  refuse "'$train_name' is not a usable branch name component"
fi

# Resolve identity before any remote reads or local preflights. Recheck at each
# push because origin can change while a long CI watch is in progress.
# shellcheck source=lib/operator-gh.sh
source "$REPO/scripts/lib/operator-gh.sh" || exit 2
# shellcheck source=lib/repository-identity.sh
source "$REPO/scripts/lib/repository-identity.sh"
origin_slug="$(require_github_repository "$REPO" "$OPERATOR_GH" "" "$repo_slug_override")" || exit 2
repo_slug="${repo_slug_override:-$origin_slug}"
push_to_origin() {
  require_github_repository "$REPO" "$OPERATOR_GH" "" "$repo_slug" >/dev/null || return 1
  git -C "$REPO" push "$@"
}

# REFUSE A CONCURRENT TRAIN. Two trains overlap the moment one is backgrounded and
# another started - which is exactly what an operator wants to do, because a train
# takes minutes and waiting is dull. They are not concurrent-safe: each resolves
# HEAD and moves refs on one remote, so the second can land the first's commits,
# or find main already where it meant to put it and report a failure over a
# landing that succeeded. That false failure is the mild outcome; the dangerous
# one is a train landing a sha its CI never tested.
#
# A remote train/* ref is NOT the signal: a ref outlives its process (a red CI
# leaves the ref as the repush target, and the same train name is re-run round
# after round), and a ref arrives late (a train between resolve-HEAD and push
# holds no ref yet, so a second train in that window would be permitted - the
# exact concurrency to refuse). A pid is the direct observable. The lock below
# is a record, not a mutex: it means nothing unless its process is alive, so a
# SIGKILLed train (no trap runs) leaves a file the next scan clears. No EXIT
# trap on purpose - bash traps are global and a function further down sets one.
#
# Limit: the lock is local, refs are remote, so this sees trains on this box
# only. One operator, one box here; a second machine driving the same remote is
# invisible to it, which is why leftover refs are still listed below.
# Absolute so locks and heartbeats remain addressable after the launch cwd is
# removed; later diagnostics can also name a path usable from anywhere.
#
# Two directories, because a linked worktree has both. `git_dir` is THIS
# worktree's (.git/worktrees/<name>): in-progress operations (MERGE_HEAD,
# rebase-merge/) live there and are per-worktree. `git_common_dir` is the
# repository's own .git, shared by every worktree: anything that is one fact
# per repository (the train lock, the watch heartbeat, the trigger proof,
# hooks) must live there, or each fresh worktree re-proves the trigger, two
# worktrees can push the same train at once, and the repo's pre-push hook is
# looked for in a directory that never has one.
git_dir="$(git -C "$REPO" rev-parse --absolute-git-dir 2>/dev/null)"
git_common_dir="$(cd "$REPO" && cd "$(git rev-parse --git-common-dir 2>/dev/null)" 2>/dev/null && pwd -P)"
[ -n "$git_common_dir" ] || git_common_dir="$git_dir"
train_lock_dir="$git_common_dir/train-push-locks"
watch_name="${train_name//\//-}"
watch_heartbeat="$git_common_dir/train-push-$watch_name.watch"
mkdir -p "$train_lock_dir" 2>/dev/null || true
train_lock_held="$train_lock_dir/held"

# ACQUIRE BEFORE ANY NETWORK WORK, AND ACQUIRE ATOMICALLY. A scan-then-write
# guard with a `git ls-remote` between the scan and the write admitted two
# trains started together: the window is a network round trip, and "background
# one train, start another" lands inside it by construction.
# `mkdir` is the POSIX atomic primitive: EEXIST if it exists, so of N racers
# exactly one wins and there is no check-then-act to lose.
#
# The owner file is written after the directory exists, leaving a two-syscall
# window where the lock is held by someone who has not said who they are. An
# unreadable owner is treated as live and refused, never recovered: dispossessing
# a process mid-acquisition gives two live trains, the thing this guard exists
# to prevent; refusing costs one `rm -rf` the message names. Fail closed.
train_lock_attempts=0
# A pid alone cannot prove the owner is still the train: macOS recycles pids,
# and an unrelated process reusing the recorded pid made a finished train's
# leftover lock look live. The owner records its process start time too, and a
# pid whose start time differs is a different process.
process_start_time() {
  ps -p "$1" -o lstart= 2>/dev/null | awk '{$1=$1; print}' || true
}
# Computed before taking the lock so the owner write right after mkdir stays a
# single write, keeping the window where the lock has no readable owner short.
train_lock_my_start="$(process_start_time "$$")"
while true; do
  if mkdir "$train_lock_held" 2>/dev/null; then
    printf '%s %s\n%s\n' "$$" "$train_name" "$train_lock_my_start" > "$train_lock_held/owner"
    break
  fi

  owner_pid="$(awk 'NR==1{print $1}' "$train_lock_held/owner" 2>/dev/null || true)"
  owner_name="$(awk 'NR==1{print $2}' "$train_lock_held/owner" 2>/dev/null || true)"
  owner_start="$(awk 'NR==2' "$train_lock_held/owner" 2>/dev/null || true)"

  if [ -z "$owner_pid" ]; then
    printf 'train-push: the train lock is held with no readable owner.\n' >&2
    printf '  a train was killed between taking the lock and recording its pid.\n' >&2
    printf '  if you are sure no train is running:  rm -rf %s\n' "$train_lock_held" >&2
    refuse "train lock held by an unidentified owner; refusing rather than dispossessing it"
  fi

  owner_live=0
  if kill -0 "$owner_pid" 2>/dev/null; then
    if [ -n "$owner_start" ]; then
      [ "$(process_start_time "$owner_pid")" = "$owner_start" ] && owner_live=1
    else
      # A lock written before start times were recorded: live only if the pid
      # is still running this script.
      ps -p "$owner_pid" -o command= 2>/dev/null | grep -q 'train-push' && owner_live=1
    fi
  fi

  if [ "$owner_live" = 1 ]; then
    printf 'train-push: train %s is RUNNING as pid %s\n' "${owner_name:-?}" "$owner_pid" >&2
    printf '  wait for it, or kill it if you know it is wedged.\n' >&2
    refuse "a train is already running on this machine; wait for it"
  fi

  # Stale owner. Recovery is serialized by a second mkdir lock, `reap`. A
  # rename alone was not enough: two trains reading the same stale owner both
  # renamed `held`, and the second rename took the first one's FRESH lock
  # (created by its mkdir after its own rename), so both trains proceeded.
  # Inside `reap`, `held` cannot change hands: a fresh mkdir fails while it
  # exists and every other remover is waiting on `reap`. So re-reading the
  # owner there and finding the same stale record proves the removal is safe.
  train_lock_reap="$train_lock_dir/reap"
  if [ -n "${TRAIN_PUSH_TEST_LOCK_RACE_HOOK:-}" ]; then
    "$TRAIN_PUSH_TEST_LOCK_RACE_HOOK"
  fi
  if mkdir "$train_lock_reap" 2>/dev/null; then
    printf '%s\n%s\n' "$$" "$train_lock_my_start" > "$train_lock_reap/owner"
    if [ "$(awk 'NR==1{print $1}' "$train_lock_held/owner" 2>/dev/null || true)" = "$owner_pid" ] &&
      [ "$(awk 'NR==2' "$train_lock_held/owner" 2>/dev/null || true)" = "$owner_start" ]; then
      rm -rf "$train_lock_held" 2>/dev/null || true
    fi
    rm -rf "$train_lock_reap" 2>/dev/null || true
  else
    reaper_pid="$(awk 'NR==1' "$train_lock_reap/owner" 2>/dev/null || true)"
    reaper_start="$(awk 'NR==2' "$train_lock_reap/owner" 2>/dev/null || true)"
    if [ -z "$reaper_pid" ] || ! kill -0 "$reaper_pid" 2>/dev/null ||
      [ "$(process_start_time "$reaper_pid")" != "$reaper_start" ]; then
      # A reaper holds `reap` for a few milliseconds. One that is gone left
      # it behind; removing it here would reopen the race, so fail closed.
      printf 'train-push: a stale-lock recovery was interrupted.\n' >&2
      printf '  if you are sure no train is running:  rm -rf %s %s\n' "$train_lock_reap" "$train_lock_held" >&2
      refuse "train lock recovery left behind; refusing rather than racing it"
    fi
  fi

  train_lock_attempts=$((train_lock_attempts + 1))
  if [ "$train_lock_attempts" -ge 3 ]; then
    refuse "could not acquire the train lock after clearing a stale owner; try again"
  fi
done

# Leftover refs do not refuse - no process drives them, so they cannot race this
# train. They are listed with the delete composed, because the operator reaching
# this line is usually mid-CI-failure and composing `--delete train/<name>` by
# hand next to several refs is where the wrong one gets deleted.
stale_refs=$(git -C "$REPO" ls-remote --heads "$remote" 'train/*' 2>/dev/null | wc -l | tr -d ' ')
if [ "${stale_refs:-0}" -gt 0 ]; then
  printf 'train-push: %s train ref(s) on %s with no live train here:\n' \
    "$stale_refs" "$remote" >&2
  git -C "$REPO" ls-remote --heads "$remote" 'train/*' 2>/dev/null |
    sed "s|.*refs/heads/|    git push $remote --delete |" >&2
  printf '  (proceeding: a ref without a process cannot race this train)\n' >&2
fi

# watch-ci.sh receives the GitHub slug for its own REPO interface at each call;
# this process keeps REPO as the stable checkout path used by every git command.

# Read the default branch off the remote. Every later message, the moved-branch
# check and the fast-forward target all come from this one answer.
resolve_default_branch() {
  local ref
  local name

  ref="$(git -C "$REPO" symbolic-ref -q "refs/remotes/$remote/HEAD" 2>/dev/null || true)"
  name="${ref#refs/remotes/"$remote"/}"
  if [ -n "$ref" ] && [ -n "$name" ] && [ "$name" != "$ref" ]; then
    printf '%s\n' "$name"
    return 0
  fi

  name="$("$OPERATOR_GH" repo view "$repo_slug" --json defaultBranchRef --jq '.defaultBranchRef.name' 2>/dev/null || true)"
  [ -n "$name" ] || return 1
  printf '%s\n' "$name"
}

resolve_ci_run() {
  local sha="$1"
  "$OPERATOR_GH" run list --repo "$repo_slug" --workflow "$tests_workflow_name" \
    --event "${WATCH_CI_EVENT:-push}" --branch "$train_ref" --limit 40 --json databaseId,headSha,headBranch \
    --jq ".[] | select(.headSha==\"$sha\") | .databaseId" 2>/dev/null | head -1
}

ci_run_attempt() {
  "$OPERATOR_GH" run view "$1" --repo "$repo_slug" --json attempt --jq '.attempt' 2>/dev/null
}

wait_for_new_run_attempt() {
  local run_id="$1"
  local previous_attempt="$2"
  local attempts="${TRAIN_PUSH_RERUN_ATTEMPTS:-30}"
  local wait_seconds="${TRAIN_PUSH_RERUN_SLEEP:-2}"
  local current_attempt
  for _ in $(seq 1 "$attempts"); do
    current_attempt="$(ci_run_attempt "$run_id" || true)"
    if [[ "$current_attempt" =~ ^[0-9]+$ ]] && [ "$current_attempt" -gt "$previous_attempt" ]; then
      printf '%s\n' "$current_attempt"
      return 0
    fi
    sleep "$wait_seconds"
  done
  printf 'train-push: rerun request for %s did not advance its attempt beyond %s\n' \
    "$run_id" "$previous_attempt" >&2
  return 1
}

wait_for_run_attempt_completion() {
  local run_id="$1"
  local attempt="$2"
  local attempts="${TRAIN_PUSH_RERUN_WAIT_ATTEMPTS:-360}"
  local wait_seconds="${TRAIN_PUSH_RERUN_WAIT_SLEEP:-10}"
  local status
  for _ in $(seq 1 "$attempts"); do
    status="$("$OPERATOR_GH" run view "$run_id" --repo "$repo_slug" --attempt "$attempt" \
      --json status --jq '.status' 2>/dev/null || true)"
    [ "$status" = "completed" ] && return 0
    sleep "$wait_seconds"
  done
  printf 'train-push: rerun attempt %s for run %s did not complete before the wait limit\n' \
    "$attempt" "$run_id" >&2
  return 1
}

rerun_existing_run() {
  local run_id="$1"
  local old_attempt="$2"
  local bad_jobs line conclusion job_id
  local current_attempt="$old_attempt"
  local remaining_actions
  local -a failed_job_ids=() cancelled_job_ids=()

  bad_jobs="$("$OPERATOR_GH" run view "$run_id" --repo "$repo_slug" --json jobs \
    --jq '[.jobs[] | select(.conclusion=="failure" or .conclusion=="cancelled") | .conclusion + "|" + (.databaseId|tostring)] | .[]' 2>/dev/null || true)"
  while IFS='|' read -r conclusion job_id; do
    [ -n "$job_id" ] || continue
    case "$job_id" in *[!0-9]*) continue ;; esac
    case "$conclusion" in
      failure) failed_job_ids+=("$job_id") ;;
      cancelled) cancelled_job_ids+=("$job_id") ;;
    esac
  done <<< "$bad_jobs"

  if [ "${#failed_job_ids[@]}" -eq 0 ] && [ "${#cancelled_job_ids[@]}" -eq 0 ]; then
    printf 'train-push: completed run %s has no failed or cancelled jobs to rerun; refusing to treat its old conclusion as this push result\n' \
      "$run_id" >&2
    return 1
  fi
  remaining_actions=$(( ${#failed_job_ids[@]} > 0 ? 1 : 0 ))
  remaining_actions=$((remaining_actions + ${#cancelled_job_ids[@]}))

  if [ "${#failed_job_ids[@]}" -gt 0 ]; then
    GH_SHIM_BYPASS=operator "$OPERATOR_GH" run rerun "$run_id" --failed >&2 || {
      printf 'train-push: could not rerun failed jobs for run %s\n' "$run_id" >&2
      return 1
    }
    current_attempt="$(wait_for_new_run_attempt "$run_id" "$current_attempt")" || return 1
    remaining_actions=$((remaining_actions - 1))
    if [ "$remaining_actions" -gt 0 ]; then
      wait_for_run_attempt_completion "$run_id" "$current_attempt" || return 1
    fi
  fi
  if [ "${#cancelled_job_ids[@]}" -gt 0 ]; then
    for job_id in "${cancelled_job_ids[@]}"; do
      # `--failed` does not include cancelled jobs, so each is rerun explicitly.
      GH_SHIM_BYPASS=operator "$OPERATOR_GH" run rerun "$run_id" --job "$job_id" >&2 || {
        printf 'train-push: could not rerun cancelled job %s for run %s\n' "$job_id" "$run_id" >&2
        return 1
      }
      current_attempt="$(wait_for_new_run_attempt "$run_id" "$current_attempt")" || return 1
      remaining_actions=$((remaining_actions - 1))
      if [ "$remaining_actions" -gt 0 ]; then
        wait_for_run_attempt_completion "$run_id" "$current_attempt" || return 1
      fi
    done
  fi
  printf '%s\n' "$current_attempt"
}

ci_run_url() {
  "$OPERATOR_GH" run view "$1" --repo "$repo_slug" --json url --jq '.url' 2>/dev/null || true
}

report_existing_red() {
  local sha="$1"
  local run_url="$2"
  printf 'train-push: CI red for previously pushed %s\n' "$sha" >&2
  [ -z "$run_url" ] || printf 'train-push: run %s\n' "$run_url" >&2
  printf 'train-push: %s/%s still holds %s — fix, commit, and re-run: scripts/train-push.sh %s\n' \
    "$remote" "$train_ref" "$sha" "$train_name" >&2
}

landing_failed() {
  local reason="$1"
  local sha="$2"
  local run_url="$3"
  {
    printf 'train-push: CI green, but landing failed — %s\n' "$reason"
    printf '  green run: %s\n' "$run_url"
    printf '  train sha: %s\n' "$sha"
    printf '  finish without re-running CI:\n'
    printf '    scripts/train-push.sh %s --land\n' "$train_name"
  } >&2
  exit 4
}

require_repo_after_green() {
  local sha="$1"
  local run_url="$2"
  if [ ! -d "$REPO" ]; then
    landing_failed "repository path $REPO no longer exists" "$sha" "$run_url"
  fi
}


read_watcher_heartbeat() {
  heartbeat_pid=""
  heartbeat_start=""
  heartbeat_updated=""
  heartbeat_dead_note=""
  [ -f "$watch_heartbeat" ] || return 0

  heartbeat_pid="$(sed -n 's/^pid=//p' "$watch_heartbeat" | head -1)"
  heartbeat_start="$(sed -n 's/^start=//p' "$watch_heartbeat" | head -1)"
  heartbeat_updated="$(sed -n 's/^updated=//p' "$watch_heartbeat" | head -1)"
  case "$heartbeat_pid" in
    '' | *[!0-9]*) heartbeat_now="" ;;
    *) heartbeat_now="$(process_start_time "$heartbeat_pid")" ;;
  esac

  if [ -n "$heartbeat_now" ] && [ "$heartbeat_now" = "$heartbeat_start" ] && kill -0 "$heartbeat_pid" 2>/dev/null; then
    refuse "watcher $heartbeat_pid is still running for $remote/$train_ref; wait for it"
  fi

  heartbeat_dead_note="watcher ${heartbeat_pid:-unknown} died at ${heartbeat_updated:-an unknown time}"
}

refuse_non_fast_forward() {
  local sha="$1"
  refuse "$sha is not a fast-forward of $remote/$default_branch; rebase and re-run: scripts/train-push.sh $train_name"
}

land_verified_sha() {
  local sha="$1"
  local run_url="$2"

  require_repo_after_green "$sha" "$run_url"
  git -C "$REPO" fetch -q "$remote" "$default_branch" ||
    landing_failed "git fetch $remote $default_branch failed" "$sha" "$run_url"
  if ! git -C "$REPO" merge-base --is-ancestor "$remote_default" "$sha"; then
    refuse_non_fast_forward "$sha"
  fi

  say "landing CI-verified $sha on $remote/$default_branch"
  set +e
  push_to_origin "$remote" "$sha:refs/heads/$default_branch" 2>&1 | tee "$push_log"
  land_rc="${PIPESTATUS[0]}"
  set -e
  if [ "$land_rc" -ne 0 ]; then
    land_reason="push of $sha to $remote/$default_branch failed; $remote/$train_ref still holds the tested sha"
    if grep -qE 'GH006|equired status check|rotected branch update failed' "$push_log"; then
      land_reason="refused: $sha has no status check on origin. Merge onto the train branch and push there; CI runs on the merge sha, then main fast-forwards."
    fi
    landing_failed "$land_reason" "$sha" "$run_url"
  fi

  git -C "$REPO" fetch -q "$remote" "$default_branch" ||
    landing_failed "could not verify $remote/$default_branch after push" "$sha" "$run_url"
  if ! git -C "$REPO" merge-base --is-ancestor "$sha" "$remote_default"; then
    landing_failed "push reported success but $sha is not on $remote/$default_branch" "$sha" "$run_url"
  fi

  say "landed previously-verified sha $sha from $run_url on $remote/$default_branch"
  if ! push_to_origin -q "$remote" --delete "$train_ref"; then
    printf 'train-push: warning — could not delete %s/%s (delete it by hand)\n' "$remote" "$train_ref" >&2
  fi
  rm -f "$watch_heartbeat"
  say "done"
}

watch_log="$(mktemp "${TMPDIR:-/tmp}/train-push-watch.XXXXXX")"
push_log="$(mktemp "${TMPDIR:-/tmp}/train-push-push.XXXXXX")"
trap 'rm -f "$watch_log" "$push_log" "$TRAIN_PUSH_EXEC_COPY"' EXIT

git -C "$REPO" fetch -q --prune "$remote" || refuse "git fetch $remote failed"
default_branch="$(resolve_default_branch || true)"
if [ -z "$default_branch" ]; then
  refuse "could not determine $remote's default branch (run: git remote set-head $remote -a)"
fi
remote_default="refs/remotes/$remote/$default_branch"
if ! git -C "$REPO" rev-parse --verify -q "$remote_default" >/dev/null; then
  refuse "no $remote/$default_branch to land on"
fi

head_sha="$(git -C "$REPO" rev-parse HEAD)"
train_remote_sha=""
if git -C "$REPO" rev-parse --verify -q "refs/remotes/$remote/$train_ref" >/dev/null; then
  train_remote_sha="$(git -C "$REPO" rev-parse "refs/remotes/$remote/$train_ref")"
fi

recover_existing=0
if [ "$land_only" -eq 1 ]; then
  [ -n "$train_remote_sha" ] || refuse "--land needs an existing $remote/$train_ref"
  recover_existing=1
elif [ -n "$train_remote_sha" ] && [ "$train_remote_sha" = "$head_sha" ]; then
  recover_existing=1
fi

if [ "$recover_existing" -eq 1 ]; then
  verified_sha="$train_remote_sha"
  read_watcher_heartbeat
  run_id="$(resolve_ci_run "$verified_sha")"
  run_url=""
  run_status=""
  run_conclusion=""
  rerun_attempt=""

  if [ -n "$run_id" ]; then
    verdict="$("$OPERATOR_GH" run view "$run_id" --repo "$repo_slug" \
      --json status,conclusion --jq '[.status, (.conclusion // "")] | @tsv' 2>/dev/null || true)"
    IFS=$'\t' read -r run_status run_conclusion <<< "$verdict"
    run_url="$(ci_run_url "$run_id")"
  fi

  if [ "$run_status" = "completed" ] && [ "$run_conclusion" != "success" ]; then
    old_attempt="$(ci_run_attempt "$run_id" || true)"
    if ! [[ "$old_attempt" =~ ^[0-9]+$ ]]; then
      refuse "could not read the current attempt for completed run $run_id"
    fi
    rerun_attempt="$(rerun_existing_run "$run_id" "$old_attempt")" || exit 2
    say "sha already ran in ${run_url:-run $run_id} ($run_conclusion); rerunning its failed and cancelled jobs (attempt $rerun_attempt)"
  fi

  if [ "$run_status" != "completed" ] || [ -n "$rerun_attempt" ]; then
    watch_target="${run_id:-$verified_sha}"
    if [ -z "$rerun_attempt" ]; then
      say "attaching to CI for existing $remote/$train_ref at $verified_sha"
    fi
    set +e
    (cd "$REPO" && REPO="$repo_slug" WATCH_CI_BRANCH="$train_ref" WATCH_CI_HEARTBEAT="$watch_heartbeat" \
      WATCH_CI_ATTEMPT="$rerun_attempt" \
      WATCH_CI_WORKFLOW="$tests_workflow_name" "$script_dir/watch-ci.sh" "$watch_target") 2>&1 | tee "$watch_log"
    watch_rc="${PIPESTATUS[0]}"
    set -e
    run_url="$(grep -m1 '^CI_RUN_URL ' "$watch_log" 2>/dev/null | sed 's/^CI_RUN_URL //' || true)"
    if [ "$watch_rc" -ne 0 ]; then
      if [ "$watch_rc" -eq 1 ]; then
        report_existing_red "$verified_sha" "$run_url"
        exit 1
      fi
      refuse "could not watch CI for existing $remote/$train_ref at $verified_sha (watch-ci exit $watch_rc)"
    fi
  fi

  [ -n "$run_url" ] || run_url="(run url not reported)"
  if [ -n "$heartbeat_dead_note" ]; then
    say "$heartbeat_dead_note; landing its verified sha $verified_sha"
  fi
  land_verified_sha "$verified_sha" "$run_url"
  exit 0
fi

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
# Step 0 reads the workflow files, because everything after it assumes a train
# push produces a run whose checks mean something.
#
# It is checked first because getting the order wrong is unrecoverable from the
# operator's side: turn on required status checks while the workflow still
# triggers on the default branch only, and every train pushes a branch that
# produces no run, so no check ever arrives and the branch becomes unpushable.
#
# The reading is done by scripts/lib/workflow-gates.py rather than by matching
# lines here: `if:` conditions are routinely written as folded scalars, and a
# line-oriented search misses them on exactly the workflows whose behaviour
# depends on the ref. The path derives from the same variable the probe and
# the watch use: two spellings of the workflow name in one script disagreed on
# every lift whose gate is not called tests.yml.
tests_workflow="$REPO/.github/workflows/$tests_workflow_name"
gate_scanner="$REPO/scripts/lib/workflow-gates.py"

command -v python3 >/dev/null 2>&1 ||
  refuse "python3 is required to read the workflow files"
if [ ! -f "$tests_workflow" ]; then
  # `ls` on an unmatched glob exits nonzero, which under `set -e` would end the
  # script inside this substitution before the refusal is printed.
  present="$({ find "$REPO/.github/workflows" -maxdepth 1 \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null || true; } | sort | tr '\n' ' ')"
  refuse "no $tests_workflow — set WATCH_CI_WORKFLOW=<file> to the workflow that gates a landing (present: ${present:-none}), and add \`train/**\` to on.push.branches in that file"
fi

set +e
gate_report="$(python3 "$gate_scanner" --train-ref "$train_ref" \
  --tests-workflow "$tests_workflow" \
  "$REPO"/.github/workflows/*.yml "$REPO"/.github/workflows/*.yaml 2>&1)"
scanner_rc=$?
set -e
if [ "$scanner_rc" -ne 0 ]; then
  printf '%s\n' "$gate_report" >&2
  refuse "could not read the workflow files (workflow-gates.py exit $scanner_rc)"
fi

# A here-string rather than `printf | grep -q`: under pipefail, grep -q closes
# the pipe on its first match and a producer still writing takes SIGPIPE, so
# the pipeline returns 141 and the guard reads FALSE exactly when the row is
# present. The report is small enough today that the writer usually finishes
# first, which is the kind of reasoning that hides the defect until it does not.
if ! grep -qx 'trigger|ok' <<<"$gate_report"; then
  refuse "$tests_workflow_name does not run on $train_ref — add \`train/**\` to on.push.branches in .github/workflows/$tests_workflow_name"
fi

# Conditions that decide on something the landing path never satisfies. A gate
# that never evaluates true is not a check that passed, it is a check that never
# ran - and in a run summary the two are indistinguishable.
#
#   ref conditions   - a job gated on the default branch's ref is skipped on the
#                      train push (the ref is refs/heads/train/...), and the
#                      train run is the one whose checks protection consults
#                      when the fast-forward asks to land that sha. The gate
#                      therefore never guards anything. This refuses.
#   event conditions - whether `github.event_name == 'pull_request'` ever fires
#                      depends on how this repo lands changes, which cannot be
#                      read off the YAML. This warns.
#   tag-only refs    - a condition that only names refs/tags/ belongs to the
#                      release event rather than the landing path, and widening
#                      it to trains would be wrong. Warned, never refused.
#   concurrency      - a group that is not per-ref means pushing a train cancels
#                      an in-flight run on another ref. Warned.
#
# The judgement is "this condition against this trigger list", so findings are
# printed under a header naming the file, the events that start it and its
# concurrency group.
event_gated="$(printf '%s\n' "$gate_report" | sed -n 's/^warn|//p')"
ref_gated="$(printf '%s\n' "$gate_report" | sed -n 's/^ref|//p')"

if [ -n "$event_gated" ]; then
  {
    printf 'train-push: WARNING — conditions that may never fire on the landing path:\n'
    printf '%s\n' "$event_gated" | sed 's/^/  /'
    printf '  judge this against how the repo lands; the scanner cannot know the landing path\n'
  } >&2
fi

if [ -n "$ref_gated" ]; then
  {
    printf 'train-push: refusing — ref-gated conditions that no train can satisfy:\n'
    printf '%s\n' "$ref_gated" | sed 's/^/  /'
    printf '  fix: gate on github.event_name or paths, or widen the ref condition to include refs/heads/train/\n'
  } >&2
  exit 2
fi

# Last part of step 0: a repo-local pre-push hook that runs the full gate turns
# the red-train loop into something you cannot use - every fix-and-repush pays
# the gate again, and even deleting the branch after a land runs the suite. We
# only report it: the hook may be doing something else entirely, and running it
# here to find out would be the very cost being warned about.
warn_repo_local_pre_push() {
  local configured
  local repo_local="$git_common_dir/hooks/pre-push"
  local hook
  local -a candidates

  candidates=("$repo_local")
  configured="$(git -C "$REPO" config --get core.hooksPath 2>/dev/null || true)"
  if [ -n "$configured" ]; then
    case "$configured" in
      /*) : ;;
      *) configured="$REPO/$configured" ;;
    esac
  fi
  if [ -n "$configured" ]; then
    case "$configured" in
      # AFT's managed dispatcher is not a gate: it chains to the repo-local
      # hook, which is already a candidate above. Its presence alone says
      # nothing about whether a gate runs. Matched by path shape rather than an
      # absolute location because the data and cache directories move with XDG
      # settings. The first pair is the older per-storage-root location; newer
      # releases share one content-addressed set under the AFT cache directory.
      */cortexkit/aft/git-hooks | */cortexkit/aft/git-hooks/*) : ;;
      */aft/git-hooks/*) : ;;
      *)
        if [ "$configured/pre-push" != "$repo_local" ]; then
          candidates+=("$configured/pre-push")
        fi
        ;;
    esac
  fi

  for hook in "${candidates[@]}"; do
    [ -f "$hook" ] && [ -x "$hook" ] || continue
    {
      printf 'train-push: WARNING — repo-local pre-push hook: %s\n' "$hook"
      printf '  verify it does not refuse pushes to train/** or ref deletions\n'
    } >&2
  done
}

warn_repo_local_pre_push

# Refuse a tree that is mid-merge/cherry-pick/rebase: a conflicted tree can
# carry stale HEAD state, and here it would also push a sha that is not the
# change under test.
#
# A rebase in progress is the DIRECTORY (rebase-merge/ or rebase-apply/), which
# git creates on start and removes on finish or abort. REBASE_HEAD is a
# convenience ref that git does not always remove when a rebase completes, so
# on its own it is a fossil, not an operation: a checkout that finished a
# rebase weeks ago would otherwise refuse every train until someone deleted
# the file by hand. MERGE_HEAD and CHERRY_PICK_HEAD are cleaned up by git and
# stay authoritative.
for marker in CHERRY_PICK_HEAD MERGE_HEAD; do
  if [ -e "$git_dir/$marker" ]; then
    refuse "$marker present (unresolved git operation)"
  fi
done
for rebase_dir in rebase-merge rebase-apply; do
  if [ -d "$git_dir/$rebase_dir" ]; then
    refuse "$rebase_dir/ present (rebase in progress)"
  fi
done
if [ -e "$git_dir/REBASE_HEAD" ]; then
  say "note: REBASE_HEAD present with no rebase in progress (a finished rebase's leftover ref; ignored)"
fi

# CI tests the pushed commit, not the working tree. Uncommitted work would be
# invisible to the gate and then silently absent from what lands on main.
if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  # Name the paths: a tree that is dirty only for a moment (a tool writing
  # into the checkout) is otherwise invisible by the time anyone looks.
  git -C "$REPO" status --porcelain | head -20 >&2
  refuse "working tree is not clean (commit or stash before pushing a train)"
fi

# A train must not add local dependency paths that escape the repository. CI
# runs the same check, and this catches the problem before spending a push run.
if ! python3 "$REPO/scripts/check-path-deps.py"; then
  refuse "dependency path resolves outside the repository"
fi

# A local main behind origin/main means the train was built on a stale base:
# CI would test it green and the land would still be refused in step 5.
if git -C "$REPO" rev-parse --verify -q refs/heads/"$default_branch" >/dev/null; then
  if ! git -C "$REPO" merge-base --is-ancestor "$remote_default" "refs/heads/$default_branch"; then
    refuse "local $default_branch is behind $remote/$default_branch (git merge --ff-only $remote/$default_branch first)"
  fi
fi

# HEAD is what lands, so HEAD is what has to fast-forward main. Checked here so
# a doomed train is refused before it costs a CI run, and again after CI.
if ! git -C "$REPO" merge-base --is-ancestor "$remote_default" "$head_sha"; then
  refuse "HEAD is not a descendant of $remote/$default_branch (rebase onto $remote/$default_branch first)"
fi

# ---------------------------------------------------------------------------
# First-run self-check: prove the trigger instead of believing the YAML
# ---------------------------------------------------------------------------
# The scan above reads intent; this reads the platform. A widened trigger that
# has never been exercised is a claim, so once per repository push a throwaway
# commit to a probe branch and wait for a run to START on it. If the two
# disagree, it is always the platform that is right.
probe_marker="$git_common_dir/train-push-proven"

run_trigger_probe() {
  local probe_ref="train/trigger-probe"
  local probe_sha
  local rid=""
  local _attempt

  say "first train in this repo — proving $tests_workflow_name starts on a train branch"
  # commit-tree writes the probe commit as a loose object: HEAD, the index and
  # the working tree are untouched by the probe.
  probe_sha="$(git -C "$REPO" commit-tree "$head_sha^{tree}" -p "$head_sha" -m "train-push trigger probe")" ||
    refuse "could not build the trigger probe commit"
  push_to_origin -q --force "$remote" "$probe_sha:refs/heads/$probe_ref" ||
    refuse "could not push the trigger probe to $remote/$probe_ref"

  # ~2 minutes. A run that is going to exist is queued within seconds; waiting
  # longer would only delay the first train in every clone.
  #
  # Resolved by SHA across every workflow rather than filtered by workflow
  # file: the forge lists workflow files from the default branch, so a file the
  # train itself adds or renames is not queryable under its new name until it
  # lands, and a file-filtered query found nothing for a probe whose run had
  # started (the first lift that renamed ci.yml hit exactly this). The run is
  # matched to the gating workflow by its display name, which the file carries
  # in `name:` and which survives a rename; a file without `name:` is shown
  # under its path, so that is the fallback expectation.
  local want_name
  want_name="$(sed -n 's/^name:[[:space:]]*//p' "$tests_workflow" | head -1 | sed 's/^["'"'"']//; s/["'"'"']$//')"
  [ -n "$want_name" ] || want_name="$tests_workflow"
  for _attempt in $(seq 1 "$probe_attempts"); do
    rid="$("$OPERATOR_GH" run list --repo "$repo_slug" \
      --branch "$probe_ref" --limit 20 --json databaseId,headSha,workflowName \
      --jq ".[] | select(.headSha==\"$probe_sha\" and .workflowName==$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$want_name")) | .databaseId" 2>/dev/null | head -1)"
    [ -n "$rid" ] && break
    sleep "$probe_sleep"
  done

  local delete_error
  if ! delete_error="$(push_to_origin -q "$remote" --delete "$probe_ref" 2>&1)"; then
    printf 'train-push: warning — could not delete %s/%s: %s\n' "$remote" "$probe_ref" "$delete_error" >&2
  fi

  if [ -z "$rid" ]; then
    refuse "no $tests_workflow_name run started for the probe on $probe_ref — the platform does not run it on train branches, whatever the workflow file says"
  fi

  printf 'run %s started for probe %s on %s at %s\n' \
    "$rid" "$probe_sha" "$probe_ref" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$probe_marker"
  say "trigger proven by run $rid"
}

if [ ! -f "$probe_marker" ]; then
  run_trigger_probe
fi

# Repo-local preflights. Each runs only when its script exists, and the header
# line names which ones ran, so a repository with none is distinguishable from
# one whose hook was deleted.
preflights_ran=()
# A repository may add its own preflights beside this script without editing
# it; the hook is sourced so it can call `refuse` and `say`.
if [ -f "$REPO/scripts/train-push.local.sh" ]; then
  # shellcheck disable=SC1091
  . "$REPO/scripts/train-push.local.sh"
  preflights_ran+=(train-push.local.sh)
fi
if [ "${#preflights_ran[@]}" -eq 0 ]; then
  say "preflights: none (no repo-local preflight scripts present)"
else
  say "preflights: ${preflights_ran[*]}"
fi

# ---------------------------------------------------------------------------
# Optional local smoke
# ---------------------------------------------------------------------------
if [ "$smoke_given" -eq 1 ]; then
  say "local smoke: ${smoke_cmd[*]}"
  set +e
  if [ "${#smoke_cmd[@]}" -eq 1 ]; then
    # A single argument is a shell string, which may be a pipeline. Without
    # pipefail a failing first stage is hidden behind a successful last stage,
    # so the smoke would report green over a failed command.
    (cd "$REPO" && bash -c "set -o pipefail
${smoke_cmd[0]}")
  else
    # Argv form runs bare: this script adds no pipe of its own, so the
    # command's own status is the status we read.
    (cd "$REPO" && "${smoke_cmd[@]}")
  fi
  smoke_rc=$?
  set -e
  if [ "$smoke_rc" -ne 0 ]; then
    refuse "local smoke failed (rc=$smoke_rc): ${smoke_cmd[*]}"
  fi
  say "local smoke ok"
fi

# ---------------------------------------------------------------------------
# Push the train, let CI gate it, land on green - re-queue if main moved
# ---------------------------------------------------------------------------
# main can move during the ~11-16 minutes CI takes, and a sha tested on the old
# base says nothing about the rebased result. A moved main is therefore a new
# round rather than a hand-back: rebase onto the new main, re-push the branch,
# watch a fresh run. Bounded at 3 because retrying forever on a busy main is
# unbounded CI spend, and by the third loss the honest answer is that this train
# needs a quiet window.
max_rounds=3
round=1
# The sha a check actually ran green against. Only this sha may land.
verified_sha=""

# What we believe $remote/$train_ref points at. Tracked explicitly so every
# re-push leases against the sha WE pushed instead of trusting a remote-tracking
# ref to have been refreshed along the way.

push_train() {
  # A rebase changes the commit, so verify a pre-push PASS for the current SHA
  # on every round. CI is still checked after pushing.
  bash "$script_dir/prepush.sh" --require-pass "$head_sha" ||
    refuse "run scripts/prepush.sh for the train commit before pushing"
  if [ -z "$train_remote_sha" ]; then
    # Create with a plain push: a mistyped train name must not be able to
    # clobber a branch that already exists.
    say "creating $remote/$train_ref -> $head_sha"
    push_to_origin "$remote" "$head_sha:refs/heads/$train_ref" ||
      refuse "could not create $remote/$train_ref"
  else
    say "updating $remote/$train_ref -> $head_sha"
    push_to_origin --force-with-lease="refs/heads/$train_ref:$train_remote_sha" \
      "$remote" "$head_sha:refs/heads/$train_ref" ||
      refuse "could not update $remote/$train_ref (it moved since we pushed it — check who else is running this train)"
  fi
  train_remote_sha="$head_sha"
}

# Rebase the checked-out train onto the new main. A conflict ends the run: the
# resolution is a human judgement about two changes, and leaving a half-rebased
# tree behind would hand back a repository that cannot be used until someone
# figures out what state it is in.
rebase_onto_main() {
  local before="$1"
  local conflicted
  local now
  local merges

  # A plain rebase linearizes: it replays the non-merge commits and drops the
  # merge commit itself, so anything recorded only in that merge (a conflict
  # resolution, an integration fix) vanishes with exit 0 and the reduced tree
  # is what gets re-tested and landed. --rebase-merges does not help: it
  # re-performs the merges and loses the same adjustment unless rerere holds
  # it. A merge is a permitted train shape (see the header), so refuse the
  # automatic requeue and leave the remote train ref intact for the operator,
  # who knows what the merge resolved.
  merges="$(git -C "$REPO" rev-list --merges "$remote_default..$before" 2>/dev/null || true)"
  if [ -n "$merges" ]; then
    {
      printf 'train-push: %s/%s moved and the train carries merge commit(s) — not rebasing.\n' \
        "$remote" "$default_branch"
      printf '  A rebase would drop the merge and anything recorded only in it.\n'
      printf '%s\n' "$merges" | sed 's/^/    merge /'
      printf '  %s/%s still holds %s. Integrate %s/%s yourself (merge or re-pick),\n' \
        "$remote" "$train_ref" "$before" "$remote" "$default_branch"
      printf '  then re-run: scripts/train-push.sh %s\n' "$train_name"
    } >&2
    return 1
  fi

  if git -C "$REPO" rebase "$remote_default"; then
    return 0
  fi

  conflicted="$(git -C "$REPO" diff --name-only --diff-filter=U 2>/dev/null || true)"
  git -C "$REPO" rebase --abort >/dev/null 2>&1 || true
  now="$(git -C "$REPO" rev-parse HEAD)"
  {
    printf 'train-push: rebase onto %s/%s conflicted — stopping.\n' "$remote" "$default_branch"
    if [ -n "$conflicted" ]; then
      printf '  conflicting file(s):\n'
      printf '%s\n' "$conflicted" | sed 's/^/    /'
    fi
    if [ "$now" = "$before" ]; then
      printf '  The rebase was aborted; the tree is back at %s and %s/%s still holds it.\n' \
        "$before" "$remote" "$train_ref"
    else
      printf '  WARNING: the abort did not restore HEAD (now %s, was %s) — check the tree before continuing.\n' \
        "$now" "$before"
    fi
    printf '  Resolve by hand, then run: scripts/train-push.sh %s\n' "$train_name"
  } >&2
  return 1
}

while true; do
  push_train

  verified_sha=""
  say "watching CI for $head_sha on $train_ref in $repo_slug (round $round of $max_rounds)"
  set +e
  (cd "$REPO" && REPO="$repo_slug" WATCH_CI_BRANCH="$train_ref" WATCH_CI_HEARTBEAT="$watch_heartbeat" \
    WATCH_CI_WORKFLOW="$tests_workflow_name" "$script_dir/watch-ci.sh" "$head_sha") 2>&1 | tee "$watch_log"
  watch_rc="${PIPESTATUS[0]}"
  set -e

  run_url="$(grep -m1 '^CI_RUN_URL ' "$watch_log" 2>/dev/null | sed 's/^CI_RUN_URL //' || true)"
  [ -n "$run_url" ] || run_url="(run url not reported)"

  if [ "$watch_rc" -ne 0 ]; then
    if [ "$watch_rc" -eq 1 ]; then
      # Report the jobs by name: with three platforms in parallel, "CI failed"
      # is not enough to know whether this needs a local reproduction or a
      # platform-specific fix. The watch's early-fail line carries only the
      # name, so the job id is read back from the run's jobs listing: the skew
      # check needs it for the failing step names and the log tail.
      run_id="$(grep -o 'run=[0-9]\+' "$watch_log" 2>/dev/null | head -1 | sed 's/^run=//' || true)"
      [ -n "$run_id" ] || run_id="$(resolve_ci_run "$head_sha")"
      failing=""
      if [ -n "$run_id" ]; then
        failing="$("$OPERATOR_GH" run view "$run_id" --repo "$repo_slug" --json jobs \
          --jq '[.jobs[] | select(.conclusion=="failure") | .name] | .[]' 2>/dev/null || true)"
      fi
      if [ -n "$failing" ]; then
        printf 'train-push: CI red — failing job(s):\n' >&2
        # One name per line, not word-split: job names contain spaces.
        printf '%s\n' "$failing" | sed 's/^/  /' >&2
      else
        printf 'train-push: CI red — no job name reported (run conclusion was not success)\n' >&2
      fi
      # A red run never enters the re-queue loop below - that loop is for a
      # moved default branch and nothing else. Rebasing a red train carries the
      # same tree onto a new base, so the re-run is red for the same reason and
       # spends one of the bounded rounds proving it. Report the real failed
       # job and let the operator fix the reported failure.
      printf 'train-push: run %s\n' "$run_url" >&2
      printf 'train-push: %s/%s still holds %s — fix, commit, and re-run: scripts/train-push.sh %s\n' \
        "$remote" "$train_ref" "$head_sha" "$train_name" >&2
      exit 1
    fi
    printf 'train-push: could not watch CI for %s (watch-ci exit %s); %s/%s is pushed and unwatched\n' \
      "$head_sha" "$watch_rc" "$remote" "$train_ref" >&2
    exit 2
  fi

  verified_sha="$head_sha"
  say "CI green: $run_url"

  # Re-check right before the push, not just at the start of the script.
  require_repo_after_green "$head_sha" "$run_url"
  git -C "$REPO" fetch -q "$remote" "$default_branch" ||
    landing_failed "git fetch $remote $default_branch failed" "$head_sha" "$run_url"
  if git -C "$REPO" merge-base --is-ancestor "$remote_default" "$head_sha"; then
    break
  fi

  moved_sha="$(git -C "$REPO" rev-parse "$remote_default")"
  printf 'train-push: %s/%s moved to %s while CI ran (round %s of %s) — %s was tested on the old base\n' \
    "$remote" "$default_branch" "$moved_sha" "$round" "$max_rounds" "$head_sha" >&2

  if [ "$round" -ge "$max_rounds" ]; then
    {
      printf 'train-push: gave up after %s rounds — not landing.\n' "$max_rounds"
      printf '  %s/%s holds %s, rebased onto every %s this run saw.\n' \
        "$remote" "$train_ref" "$head_sha" "$remote/$default_branch"
      printf '  Re-run when %s is quieter: scripts/train-push.sh %s\n' \
        "$remote/$default_branch" "$train_name"
    } >&2
    exit 3
  fi

  if ! rebase_onto_main "$head_sha"; then
    exit 3
  fi
  head_sha="$(git -C "$REPO" rev-parse HEAD)"
  round=$((round + 1))
  say "rebased onto $moved_sha — train head is now $head_sha"
done

# The invariant, enforced rather than assumed: what lands is the sha the check
# ran against. If any future edit moves HEAD between the watch and this push,
# this stops main from fast-forwarding to a commit nothing verified.
if [ "$verified_sha" != "$head_sha" ]; then
  landing_failed "refusing to land $head_sha because the green check ran against ${verified_sha:-nothing}" \
    "$head_sha" "$run_url"
fi

land_verified_sha "$head_sha" "$run_url"
