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
        self.assertEqual(len(checkouts), 3)
        for checkout in checkouts:
            self.assertEqual(checkout["with"]["persist-credentials"], "false")

    def test_every_action_is_sha_pinned_and_mutation_artifacts_expire_in_fourteen_days(self):
        actions = [step["uses"] for step in self.steps if "uses" in step]
        self.assertEqual(len(actions), 11)
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
        self.assertEqual(set(self.jobs), {"test", "mutations", "guest"})
        self.assertEqual(load_gates_module().precondition_failures(self.workflow), [])

    def test_probe_replay_jobs_install_the_wasi_rust_target_with_the_pinned_toolchain(self):
        for job_name in ("test", "mutations"):
            toolchains = [step for step in self.jobs[job_name]["steps"]
                          if step.get("uses", "").startswith("dtolnay/rust-toolchain@")]
            self.assertEqual(len(toolchains), 1, job_name)
            self.assertEqual(toolchains[0]["uses"],
                             "dtolnay/rust-toolchain@686976e191b89faba57d3206551f0f330d8cb249")
            self.assertEqual(toolchains[0]["with"]["targets"], "wasm32-wasip1", job_name)

    def test_guest_rebuild_is_pinned_and_compares_without_installing(self):
        job = self.jobs["guest"]
        toolchain = next(step for step in job["steps"] if step.get("uses", "").startswith("dtolnay/rust-toolchain@"))
        self.assertEqual(toolchain["with"]["toolchain"], "1.99.0")
        self.assertIn("bash scripts/build-probe-guest.sh --check", [step.get("run") for step in job["steps"]])

    def test_mutation_jobs_only_restore_the_public_build_cache(self):
        caches = [step for step in self.jobs["mutations"]["steps"] if step.get("name") == "Restore Rust build"]
        self.assertEqual(len(caches), 1)
        self.assertTrue(caches[0]["uses"].startswith("actions/cache/restore@"))
        self.assertNotIn("~/.cargo/config", caches[0]["with"]["path"])

    def test_main_verification_is_not_cancelled_by_a_later_main_push(self):
        self.assertEqual(self.workflow['concurrency']['cancel-in-progress'], "${{ github.ref != 'refs/heads/main' }}")

    def test_ci_jobs_share_nats_setup_and_layout_runs_once_in_the_gate(self):
        installers = [step for step in self.steps if step.get('name') == 'Install pinned nats-server']
        self.assertEqual(len(installers), 2)
        self.assertTrue(all(step.get('run') == 'bash scripts/install-nats-server.sh' for step in installers))
        self.assertNotIn('CortexKit layout', [step.get('name') for step in self.steps])

    def test_guest_replay_compiler_is_installed_without_pinning_host_stable(self):
        install = 'rustup toolchain install 1.99.0 --profile minimal --target wasm32-wasip1'
        for job_name in ('test', 'mutations'):
            job = self.jobs[job_name]
            self.assertIn(install, [step.get('run') for step in job['steps']], job_name)
            host = next(step for step in job['steps'] if step.get('uses', '').startswith('dtolnay/rust-toolchain@'))
            self.assertNotIn('toolchain', host['with'], 'the host must continue tracking stable')
