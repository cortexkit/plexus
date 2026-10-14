# Maintainer landing preflight; outside contributors need only the test gate.
# Sourced by scripts/train-push.sh before any push. Plexus preflight: the
# train preconditions checker - the same four assertions CI runs as its
# first step, run here so drift refuses BEFORE a branch is pushed rather
# than seven minutes into the run it would fail.
#
# The workflow-name override (this repo's gate is ci.yml, the shared
# script's default is tests.yml) cannot live here: the script assigns its
# workflow name before sourcing this hook. It rides scripts/train.sh, the
# invocation wrapper, instead.
say "preflight: train preconditions checker"
# By $REPO, which train-push.sh resolves before sourcing this hook, rather than
# relative to whatever directory the train happened to be started from.
if ! "$REPO/scripts/check-train-preconditions.sh"; then
  refuse "train preconditions checker failed (see lines above)"
fi
