#!/usr/bin/env python3
"""Run the operator-script regression tests and refuse a vacuous result.

Called by scripts/rust-test-gate.sh. Before the real suite it runs a planted
failing test and a planted passing one through the same runner, so a runner
that has stopped reporting failures (or stopped running anything) cannot
produce the clean result the gate then reads.
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def run_suite(suite: unittest.TestSuite, verbosity: int = 1) -> unittest.TestResult:
    return unittest.TextTestRunner(stream=sys.stderr, verbosity=verbosity).run(suite)


class PlantedFailure(unittest.TestCase):
    def test_planted_failure(self):
        self.fail("planted failure: the runner must report this")


class PlantedPass(unittest.TestCase):
    def test_planted_pass(self):
        pass


def main() -> int:
    loader = unittest.TestLoader()
    with open(os.devnull, "w") as quiet:
        planted_fail = unittest.TextTestRunner(stream=quiet).run(loader.loadTestsFromTestCase(PlantedFailure))
        planted_pass = unittest.TextTestRunner(stream=quiet).run(loader.loadTestsFromTestCase(PlantedPass))
    if planted_fail.wasSuccessful() or planted_fail.testsRun != 1:
        print("refusing: the script test runner did not report its planted failure", file=sys.stderr)
        return 1
    if not planted_pass.wasSuccessful() or planted_pass.testsRun != 1:
        print("refusing: the script test runner failed its planted passing test", file=sys.stderr)
        return 1

    suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)
    result = run_suite(suite, verbosity=2)
    if result.testsRun == 0:
        print("refusing: no script tests were discovered", file=sys.stderr)
        return 1
    if not result.wasSuccessful():
        return 1
    # Skips are named, never folded silently into the pass count: a test that
    # could not run on this host verified nothing here.
    for test, reason in result.skipped:
        print(f"    skipped {test.id()}: {reason}")
    print(f"    ran {result.testsRun} script test(s), {len(result.skipped)} skipped; planted controls passed")
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
