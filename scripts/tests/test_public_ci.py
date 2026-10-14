"""Public-CI security policy and runner-allocation regressions."""

import unittest

from test_scripts import REPO, load_gates_module


class PublicCiTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_gates_module().parse_workflow(str(REPO / ".github/workflows/ci.yml"))
        self.jobs = self.workflow["jobs"]
        self.steps = [step for job in self.jobs.values() for step in job["steps"]]

    def test_workflow_has_read_only_permissions_and_unpersisted_checkout_credentials(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        checkouts = [step for step in self.steps if step.get("uses", "").startswith("actions/checkout@")]
        self.assertEqual(len(checkouts), 2)
        for checkout in checkouts:
            self.assertEqual(checkout["with"]["persist-credentials"], "false")

    def test_every_action_is_sha_pinned_and_mutation_artifacts_expire_in_fourteen_days(self):
        actions = [step["uses"] for step in self.steps if "uses" in step]
        self.assertEqual(len(actions), 7)
        for action in actions:
            self.assertRegex(action, r"^[\w/-]+@[0-9a-f]{40}$")
        uploads = [step for step in self.steps if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"]["retention-days"], "14")

    def test_pr_mutation_jobs_are_excluded_without_changing_push_dependencies_or_timeouts(self):
        self.assertEqual(self.jobs["mutations"]["if"],
                         "github.event_name != 'pull_request' && needs.test.outputs.has-mutations == 'true'")
        self.assertEqual(self.jobs["mutations"]["needs"], "test")
        self.assertEqual(self.jobs["test"]["timeout-minutes"], "40")
        self.assertEqual(self.jobs["mutations"]["timeout-minutes"], "180")
        self.assertEqual(set(self.jobs), {"test", "mutations"})
        self.assertEqual(load_gates_module().precondition_failures(self.workflow), [])
