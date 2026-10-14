"""Regressions for operator tooling.

Cover private executable copies for catalog checks, mutation-job selection by
changed files, packed build stamps and the CI run watcher's workflow and limits.
"""
import importlib.util
import os
import subprocess
import shutil
from pathlib import Path

from test_scripts import Scratch, SCRIPTS, REPO, SYSTEM_PATH, run, write_executable


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OperatorWorkflowTests(Scratch):
    def test_packed_build_stamps_use_one_git_batch(self):
        head = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
        binary = self.tmp / 'packed-binary'
        binary.write_text('a' * 24 + head + '\n')
        tools = self.tmp / 'bin'
        count = self.tmp / 'git-calls'
        real_git = shutil.which('git', path=SYSTEM_PATH)
        write_executable(tools / 'git', f'#!/bin/sh\necho call >> "{count}"\nexec "{real_git}" "$@"\n')
        result = run(['python3', SCRIPTS / 'lib/embedded-commit.py', binary, REPO, '40'],
                     env={'PATH':f'{tools}:{SYSTEM_PATH}'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), head)
        self.assertEqual(count.read_text().splitlines(), ['call'], "packed stamps must use one Git batch, not one process per window")

    def test_watch_defaults_to_the_local_ci_workflow(self):
        tools = self.tmp / 'bin'
        write_executable(tools / 'gh', '''#!/bin/sh
case "$*" in
  *"run list"*) case "$*" in *"--workflow ci.yml"*) echo 12345;; esac;;
  *"--json jobs"*) echo '';;
  *status*) echo completed;;
  *conclusion*) echo success;;
  *url*) echo https://example.invalid/run;;
esac
''')
        result = run(['bash', SCRIPTS / 'watch-ci.sh', 'HEAD'], cwd=REPO,
                     env={'PATH':f'{tools}:{SYSTEM_PATH}', 'REPO':'owner/repo',
                          'OPERATOR_GH_FALLBACK_PATHS':'', 'WATCH_CI_RESOLVE_ATTEMPTS':'1',
                          'WATCH_CI_RESOLVE_SLEEP':'0', 'WATCH_CI_POLL_SLEEP':'0', 'TMPDIR':str(self.tmp)})
        self.assertEqual(result.returncode, 0, "default watcher must find ci.yml: " + result.stdout + result.stderr)

    def test_catalog_check_copies_are_private_and_independent(self):
        binary = write_executable(self.tmp / "candidate", "#!/bin/sh\necho candidate\n")
        command = ['sh', '-c', '. "$1"; private_executable_copy "$2"', 'copy',
                   SCRIPTS / 'lib/private-copy.sh', binary]
        copies = []
        try:
            for _ in range(2):
                result = run(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                copies.append(Path(result.stdout.strip()))
            self.assertNotEqual(copies[0], copies[1], "concurrent catalog checks must use independent directories")
            for copy in copies:
                self.assertEqual(copy.stat().st_mode & 0o777, 0o700, "catalog check directory must be owner-only")
                self.assertEqual(run([copy / 'ckdev-plexus']).stdout.strip(), 'candidate')
            shutil.rmtree(copies[0])
            self.assertTrue((copies[1] / 'ckdev-plexus').exists())
        finally:
            for copy in copies:
                shutil.rmtree(copy, ignore_errors=True)

    def test_optional_watch_bounds_are_validated(self):
        for key, name in [("WATCH_CI_RESOLVE_ATTEMPTS", "RESOLVE_ATTEMPTS"),
                          ("WATCH_CI_RESOLVE_SLEEP", "RESOLVE_SLEEP"),
                          ("WATCH_CI_POLL_SLEEP", "POLL_SLEEP")]:
            result = run(['bash', SCRIPTS / 'watch-ci.sh'], env={"REPO":"owner/repo", key:"invalid"})
            self.assertEqual(result.returncode, 2, "invalid watch bounds must be refused by name: " + result.stdout + result.stderr)
            self.assertIn(name + " must be", result.stderr, "invalid watch bounds must be refused by name")

    def test_mutation_planner_skips_empty_shards_and_tracks_diff_inputs(self):
        planner = load_script('mutation-plan')
        rows = [{"id":str(i), "file":"source", "test_file":"tests"} for i in range(5)]
        self.assertEqual(planner.plan(rows, 'pull_request', 'refs/pull/1/merge')['matrix'], {"shard":[]}, "PRs must not allocate mutation runners")
        self.assertEqual(planner.plan(rows[:1], 'push', 'refs/heads/train/x')['matrix'], {"shard":[1]}, "empty shards must not allocate runners")
        current = {"control":rows}
        self.assertEqual(planner.selected_rows(current, current, {'docs'}), [])
        self.assertEqual(planner.selected_rows(current, current, {'source'}), rows)
        self.assertEqual(planner.selected_rows(current, current, {'tests'}), rows)
        self.assertEqual(planner.selected_rows({**current, 'prebuild':['build']}, current, set()), rows)
        self.assertEqual(planner.selected_rows({'control':rows + [{'id':'new'}]}, current, set()), [{'id':'new'}])
