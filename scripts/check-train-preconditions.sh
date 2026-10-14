#!/usr/bin/env bash
# Maintainer landing-policy check, also run by CI; no contributor push rights needed.
# Assert the CI-gated train preconditions hold for this repo's workflow.
#
# These facts were verified by hand when the train flow was adopted, but the
# workflow file keeps being edited while branch protection may be unavailable
# (a private repository on a free plan has none), so a hand verification
# expires silently. This runs as the
# first CI step and as a train preflight: drift fails in seconds, named,
# instead of being discovered on the day protection is finally enabled - the
# worst moment.
#
# The checking lives in scripts/lib/workflow-gates.py, which train-push.sh
# already uses to read the same workflow before every push. One parser and one
# condition classifier serve both gates: this file used to carry its own
# PyYAML-based reading, which needed a package the repository does not depend
# on and disagreed with the push-time gate about which trains a trigger admits
# and which `if:` conditions are path-dependent.
set -euo pipefail

cd "$(dirname "$0")/.."
exec python3 scripts/lib/workflow-gates.py --preconditions .github/workflows/ci.yml
