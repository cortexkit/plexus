"""Mutation selection per CI event, and train pushes with and without a main branch."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_scripts import REPO

PLAN = REPO / "scripts/mutation-plan.py"
CATALOGUE = """
[[control]]
id = "first"
file = "src/a.rs"

[[control]]
id = "second"
file = "src/b.rs"
"""


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(cwd), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"})


def plan(cwd, event="push", ref="refs/heads/train/x"):
    output = subprocess.run([sys.executable, str(PLAN), "--event", event, "--ref", ref],
                            cwd=cwd, check=True, capture_output=True, text=True).stdout
    return dict(line.split("=", 1) for line in output.splitlines())


class MutationPlanTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.repo = Path(self.scratch.name)
        git(self.repo, "init", "-q", "-b", "train/x")
        (self.repo / "mutations.toml").write_text(CATALOGUE)
        git(self.repo, "add", "mutations.toml")
        git(self.repo, "commit", "-q", "-m", "initial")

    def tearDown(self):
        self.scratch.cleanup()

    def test_train_push_without_a_main_branch_plans_every_control(self):
        result = plan(self.repo)
        self.assertEqual(result["selection"], "--all")
        self.assertEqual(result["count"], "2")
        self.assertEqual(result["has-mutations"], "true")

    def test_train_push_matching_main_plans_nothing(self):
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        git(self.repo, "update-ref", "refs/remotes/origin/main", head)
        result = plan(self.repo)
        self.assertEqual(result["selection"], "--diff " + head)
        self.assertEqual(result["count"], "0")
        self.assertEqual(result["has-mutations"], "false")
        self.assertEqual(result["matrix"], '{"shard":[]}')

    # A commit lands on main only after its train replayed every touched row on
    # that exact commit, so a main push replaying the catalogue again would only
    # repeat that work. The broad nightly replay covers the whole catalogue.
    def test_main_push_selects_no_mutation_proofs(self):
        result = plan(self.repo, "push", "refs/heads/main")
        self.assertEqual(result["selection"], "", "a main push must not replay mutation proofs")
        self.assertEqual(result["count"], "0")
        self.assertEqual(result["has-mutations"], "false")
        self.assertEqual(result["matrix"], '{"shard":[]}')

    def test_schedule_and_dispatch_replay_every_row_broadly(self):
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                result = plan(self.repo, event, "refs/heads/main")
                self.assertEqual(result["selection"], "--all --broad")
                self.assertEqual(result["count"], "2")
                self.assertEqual(result["has-mutations"], "true")

    def test_pull_requests_select_no_mutation_proofs(self):
        result = plan(self.repo, "pull_request", "refs/pull/1/merge")
        self.assertEqual(result["selection"], "")
        self.assertEqual(result["has-mutations"], "false")


if __name__ == "__main__":
    unittest.main()
