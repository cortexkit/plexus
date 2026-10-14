#!/usr/bin/env bash
# Maintainer landing tool; outside contributors do not need this push lane.
# The Plexus wrapper for a train landing. train-push.sh defaults its workflow
# name to tests.yml, and that assignment happens before any repo-local hook is
# sourced, so the override must arrive from the environment at invocation.
# This wrapper is that invocation - and it is fewer keystrokes than the
# unguarded form, which is what makes it win during hurried landings.
#
# It enters its own repository first. train-push.sh lands whatever repository
# the working directory belongs to, so started from anywhere else this would
# either fail to find the script or, from inside another checkout, run plexus's
# landing script against that other repository.
cd "$(dirname "$0")/.." || exit 2
exec env WATCH_CI_WORKFLOW="${WATCH_CI_WORKFLOW:-ci.yml}" scripts/train-push.sh "$@"
