"""Mutation selection per CI event, and train pushes with and without a main branch."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_scripts import REPO

PLAN = REPO / "scripts/mutation-plan.py"
PLAN_SPEC = importlib.util.spec_from_file_location("mutation_plan", PLAN)
if PLAN_SPEC is None or PLAN_SPEC.loader is None:
    raise RuntimeError("could not load the mutation planner")
MUTATION_PLAN = importlib.util.module_from_spec(PLAN_SPEC)
PLAN_SPEC.loader.exec_module(MUTATION_PLAN)
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


def plan(cwd, event="push", ref="refs/heads/train/x", main_train_verified=False):
    command = [sys.executable, str(PLAN), "--event", event, "--ref", ref]
    if main_train_verified:
        command.append("--main-train-verified")
    output = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True).stdout
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

    def test_main_push_without_a_verified_train_runs_every_mutation(self):
        result = plan(self.repo, "push", "refs/heads/main")
        self.assertEqual(result["selection"], "--all")
        self.assertEqual(result["count"], "2")
        self.assertEqual(result["has-mutations"], "true")

    def test_main_push_with_a_verified_train_skips_duplicate_mutations(self):
        result = plan(self.repo, "push", "refs/heads/main", main_train_verified=True)
        self.assertEqual(result["selection"], "")
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

    def test_landing_shard_size_is_twenty_three_rows(self):
        self.assertEqual(MUTATION_PLAN.ROWS_PER_SHARD, 23,
                         "landing rows should stay at the wait-time target")

    def test_shard_count_rounds_up_to_cover_selected_rows(self):
        planned = MUTATION_PLAN.plan_selection([{}] * 24, "--diff origin/main")
        self.assertEqual(planned["matrix"], {"shard": [1, 2], "total": [2]},
                         "every selected row must fit an allocated shard")

    def test_broad_shard_size_remains_eighty_rows(self):
        self.assertEqual(MUTATION_PLAN.BROAD_ROWS_PER_SHARD, 80,
                         "nightly broad shards keep their measured row target")
        self.assertEqual(MUTATION_PLAN.shard_total(81, broad=True), 2)

    def test_shard_count_respects_sixteen_shard_cap(self):
        self.assertEqual(MUTATION_PLAN.shard_total(1_000, broad=False), 16,
                         "mutation runner allocation must stay capped at 16 shards")

    def test_script_test_list_includes_mutation_control_names(self):
        test_name = "test_mutation_plan.MutationPlanTests.test_landing_shard_size_is_twenty_three_rows"
        listed = subprocess.run(
            [sys.executable, str(REPO / "scripts/tests/run-one.py"), "--list", test_name],
            cwd=REPO, check=True, capture_output=True, text=True,
        ).stdout
        self.assertEqual(json.loads(listed), [test_name])


if __name__ == "__main__":
    unittest.main()
