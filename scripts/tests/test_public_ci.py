"""Public-CI security policy and runner-allocation regressions."""

import unittest

from test_scripts import REPO, load_gates_module


class PublicCiTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_gates_module().parse_workflow(str(REPO / ".github/workflows/ci.yml"))
        self.jobs = self.workflow["jobs"]
        self.steps = [step for job in self.jobs.values() for step in job["steps"]]

    def test_workflow_has_read_only_permissions_and_unpersisted_checkout_credentials(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read", "actions": "read"})
        checkouts = [step for step in self.steps if step.get("uses", "").startswith("actions/checkout@")]
        self.assertEqual(len(checkouts), 3)
        for checkout in checkouts:
            self.assertEqual(checkout["with"]["persist-credentials"], "false")

    def test_every_action_is_sha_pinned(self):
        actions = [step["uses"] for step in self.steps if "uses" in step]
        self.assertEqual(len(actions), 6)
        for action in actions:
            self.assertRegex(action, r"^[\w/-]+@[0-9a-f]{40}$")

    def test_train_preconditions_are_separate_and_preserve_the_test_gate(self):
        plan = self.jobs["plan"]
        self.assertEqual(plan["name"], "Train preconditions")
        plan_steps = plan["steps"]
        names = [step.get("name") for step in plan_steps]
        self.assertLess(names.index("Train preconditions"),
                        names.index("Check for an already successful train run"))
        self.assertIn("./scripts/check-train-preconditions.sh", [step.get("run") for step in plan_steps])
        self.assertEqual(self.jobs["test"]["needs"], "plan")
        self.assertEqual(self.jobs["test"]["if"], "needs.plan.outputs.skip-test != 'true'")
        self.assertEqual(self.jobs["test"]["timeout-minutes"], "40")
        self.assertEqual(set(self.jobs), {"plan", "test", "guest"})
        self.assertEqual(load_gates_module().precondition_failures(self.workflow), [])

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
