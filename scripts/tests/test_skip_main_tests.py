"""Regression tests for fail-safe main-run skipping."""

import contextlib
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/skip_main_tests.py"
SPEC = importlib.util.spec_from_file_location("skip_main_tests", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the main-test skip helper")
SKIP_MAIN_TESTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SKIP_MAIN_TESTS)


class SkipMainTests(unittest.TestCase):
    def test_only_a_successful_run_of_this_workflow_on_the_same_train_sha_matches(self):
        sha = "a" * 40
        runs = [
            {"path": "other.yml", "event": "push", "head_sha": sha,
             "head_branch": "train/one", "conclusion": "success"},
            {"path": ".github/workflows/ci.yml", "event": "push", "head_sha": sha,
             "head_branch": "main", "conclusion": "success"},
            {"path": ".github/workflows/ci.yml", "event": "push", "head_sha": sha,
             "head_branch": "train/one", "conclusion": "failure"},
            {"path": ".github/workflows/ci.yml", "event": "push", "head_sha": sha,
             "head_branch": "train/proof", "conclusion": "success"},
        ]
        calls = []

        def open_api(request, timeout):
            calls.append((request, timeout))
            return io.BytesIO(json.dumps({"workflow_runs": runs}).encode())

        self.assertTrue(SKIP_MAIN_TESTS.has_successful_train_run(
            "cortexkit/plexus", sha, "read-only-token", opener=open_api))
        request, timeout = calls[0]
        self.assertEqual(timeout, 10)
        self.assertEqual(parse_qs(urlsplit(request.full_url).query)["head_sha"], [sha])
        self.assertEqual(request.get_header("Authorization"), "Bearer read-only-token")

    def test_nightly_dispatch_and_train_push_always_run_without_a_lookup(self):
        opener = Mock(side_effect=AssertionError("unexpected API lookup"))
        for event, ref in [
            ("schedule", "refs/heads/main"),
            ("workflow_dispatch", "refs/heads/main"),
            ("push", "refs/heads/train/ci-speed-proof"),
        ]:
            with self.subTest(event=event, ref=ref):
                self.assertFalse(SKIP_MAIN_TESTS.should_skip_tests(
                    event, ref, "cortexkit/plexus", "a" * 40, "token", opener=opener))
        opener.assert_not_called()

    def test_main_lookup_without_a_matching_run_fails_safe_to_full_ci(self):
        def no_matching_run(request, timeout):
            return io.BytesIO(json.dumps({"workflow_runs": []}).encode())

        self.assertFalse(SKIP_MAIN_TESTS.should_skip_tests(
            "push", "refs/heads/main", "cortexkit/plexus", "b" * 40,
            "read-only-token", opener=no_matching_run))

    def test_main_lookup_failure_fails_safe_to_running_full_ci(self):
        def unavailable(request, timeout):
            raise OSError("API unavailable")

        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            skip = SKIP_MAIN_TESTS.should_skip_tests(
                "push", "refs/heads/main", "cortexkit/plexus", "b" * 40,
                "read-only-token", opener=unavailable)
        self.assertFalse(skip)
        self.assertIn("running full CI", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
