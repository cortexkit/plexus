"""Public-CI security policy and runner-allocation regressions."""

import unittest

from test_scripts import REPO, load_gates_module


WINDOWS_ACTION = "./.github/actions/windows-tests"


class PublicCiTests(unittest.TestCase):
    def setUp(self):
        parser = load_gates_module().parse_workflow
        self.workflow = parser(str(REPO / ".github/workflows/ci.yml"))
        self.jobs = self.workflow["jobs"]
        self.steps = [step for job in self.jobs.values() for step in job["steps"]]
        self.windows_action = parser(str(REPO / WINDOWS_ACTION / "action.yml"))["runs"]

    def test_workflow_has_read_only_permissions_and_unpersisted_checkout_credentials(self):
        permissions = self.workflow["permissions"]
        self.assertEqual(permissions, {"contents": "read", "actions": "read"})
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertEqual(job.get("permissions", permissions), permissions)
                checkouts = [step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")]
                self.assertTrue(checkouts, "the job must check out the reviewed commit")
                for checkout in checkouts:
                    self.assertEqual(checkout["with"]["persist-credentials"], "false")
                    self.assertNotIn("ref", checkout["with"])
                    self.assertNotIn("repository", checkout["with"])
        for step in self.windows_action["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertEqual(step["with"]["persist-credentials"], "false")

    def test_every_action_is_sha_pinned(self):
        for step in self.steps:
            action = step.get("uses")
            if action is not None and action != WINDOWS_ACTION:
                self.assertRegex(action, r"^[\w/-]+@[0-9a-f]{40}$")
        # The local entry point is versioned by the checkout. Its external
        # dependencies do not share that pin and must name their own SHAs.
        self.assertEqual(self.windows_action["using"], "composite")
        for step in self.windows_action["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"^[\w/-]+@[0-9a-f]{40}$")

    def test_train_preconditions_are_separate_and_preserve_the_test_gate(self):
        plan = self.jobs["plan"]
        self.assertEqual(plan["name"], "Train preconditions")
        plan_steps = plan["steps"]
        names = [step.get("name") for step in plan_steps]
        self.assertLess(names.index("Train preconditions"),
                        names.index("Check for an already successful train run"))
        self.assertIn("./scripts/check-train-preconditions.sh", [step.get("run") for step in plan_steps])
        for name in ("test", "windows"):
            with self.subTest(job=name):
                self.assertEqual(self.jobs[name].get("needs"), "plan")
                self.assertEqual(self.jobs[name].get("if"), "needs.plan.outputs.skip-test != 'true'")
        self.assertEqual(self.jobs["test"]["timeout-minutes"], "40")
        self.assertEqual(set(self.jobs), {"plan", "test", "guest", "windows"})
        self.assertEqual(load_gates_module().precondition_failures(self.workflow), [])

    def test_windows_runs_the_locked_workspace_suite_on_both_native_runners(self):
        job = self.jobs["windows"]
        self.assertEqual(job["runs-on"], "${{ matrix.runner }}")
        self.assertCountEqual(job["strategy"]["matrix"]["include"], [
            {"target": "windows-x64", "runner": "windows-latest"},
            {"target": "windows-arm64", "runner": "windows-11-arm"},
        ])
        self.assertEqual(job["strategy"]["fail-fast"], "false")
        self.assertEqual(job["timeout-minutes"], "45")
        self.assertNotIn("continue-on-error", job)
        uses = [step.get("uses", "") for step in job["steps"]]
        checkout = next(i for i, action in enumerate(uses) if action.startswith("actions/checkout@"))
        toolchain = next(i for i, action in enumerate(uses) if action.startswith("dtolnay/rust-toolchain@"))
        gate = uses.index(WINDOWS_ACTION)
        self.assertLess(checkout, toolchain)
        self.assertLess(toolchain, gate)
        suite = next(step for step in self.windows_action["steps"]
                     if step.get("run") == "cargo test --locked --workspace --no-fail-fast")
        self.assertEqual(suite["shell"], "pwsh")
        for step in (job["steps"][checkout], job["steps"][toolchain], job["steps"][gate], suite):
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)

    def test_main_test_skip_uses_only_a_read_only_fail_safe_lookup(self):
        self.assertEqual(self.workflow["permissions"]["actions"], "read")
        lookup = next(step for step in self.jobs["plan"]["steps"]
                      if step.get("name") == "Check for an already successful train run")
        self.assertEqual(lookup["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertEqual(lookup["run"], "python3 scripts/skip_main_tests.py")
        self.assertEqual(self.jobs["plan"]["outputs"]["skip-test"],
                         "${{ steps.main-duplicate.outputs.skip-test }}")

    def test_guest_rebuild_is_pinned_and_compares_without_installing(self):
        job = self.jobs["guest"]
        toolchain = next(step for step in job["steps"] if step.get("uses", "").startswith("dtolnay/rust-toolchain@"))
        self.assertEqual(toolchain["with"]["toolchain"], "1.99.0")
        self.assertIn("bash scripts/build-probe-guest.sh --check", [step.get("run") for step in job["steps"]])

    def test_main_verification_is_not_cancelled_by_a_later_main_push(self):
        self.assertEqual(self.workflow['concurrency']['cancel-in-progress'], "${{ github.ref != 'refs/heads/main' }}")

    def test_test_job_has_nats_setup_and_layout_runs_once_in_the_gate(self):
        installers = [step for step in self.steps if step.get('name') == 'Install pinned nats-server']
        self.assertEqual(len(installers), 1)
        self.assertTrue(all(step.get('run') == 'bash scripts/install-nats-server.sh' for step in installers))
        self.assertNotIn('CortexKit layout', [step.get('name') for step in self.steps])

    def test_host_compiler_continues_tracking_stable(self):
        host = next(step for step in self.jobs['test']['steps']
                    if step.get('uses', '').startswith('dtolnay/rust-toolchain@'))
        self.assertEqual(host['uses'], 'dtolnay/rust-toolchain@686976e191b89faba57d3206551f0f330d8cb249')
        self.assertNotIn('toolchain', host['with'], 'the host must continue tracking stable')
