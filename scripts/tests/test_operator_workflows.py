"""Regressions for operator tooling.

Cover private executable copies for catalog checks, packed build stamps and the
CI run watcher's workflow and limits.
"""
import os
import subprocess
import shutil
from pathlib import Path

from test_scripts import Scratch, SCRIPTS, REPO, SYSTEM_PATH, run, write_executable


class OperatorWorkflowTests(Scratch):
    def test_refused_restage_preserves_the_published_artifact(self):
        from test_scripts import git
        if not shutil.which('shasum', path=SYSTEM_PATH):
            self.skipTest('shasum is required by the staging script')
        checkout = self.tmp / 'checkout'
        checkout.mkdir()
        shutil.copytree(SCRIPTS / 'lib', checkout / 'scripts/lib')
        shutil.copy2(SCRIPTS / 'stage-binaries.sh', checkout / 'scripts/stage-binaries.sh')
        (checkout / '.gitignore').write_text('target/\n')
        for args in [('init', '-q'), ('add', '.'), ('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')]:
            result = git(*args, cwd=checkout)
            self.assertEqual(result.returncode, 0, result.stderr)
        sha = git('rev-parse', 'HEAD', cwd=checkout).stdout.strip()
        short = git('rev-parse', '--short=7', 'HEAD', cwd=checkout).stdout.strip()
        candidate = checkout / 'target/release/ck-plexus'
        body = f'#!/bin/sh\ncase "$1" in --version) echo "ck-plexus 0.1.0 (commit {sha}, lock 123abc)";; --check-catalog) echo catalog-ok;; --smoke-probe) echo smoke-ok;; esac\n'
        write_executable(candidate, body)
        write_executable(checkout / 'target/release/ck-plexus-admin', '#!/bin/sh\nexit 0\n')
        tools = self.tmp / 'tools'
        write_executable(tools / 'uname', '#!/bin/sh\necho Darwin\n')
        write_executable(tools / 'dwarfdump', '#!/bin/sh\necho "UUID: test"\n')
        write_executable(tools / 'codesign', '#!/bin/sh\ncase "$1" in -dv) echo "flags=0x10000(runtime)" >&2;; esac\n')
        staging = self.tmp / 'staging'
        catalog = self.tmp / 'catalog'
        catalog.mkdir()
        env = {'PATH': f'{tools}:{SYSTEM_PATH}', 'PLEXUS_STAGING_DIR': str(staging)}
        command = ['bash', checkout / 'scripts/stage-binaries.sh', '--catalog-dir', catalog, '--marker', 'none']
        first = run(command, cwd=checkout, env=env)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        artifact = staging / f'SIGNED.ck-plexus.{short}'
        before = artifact.read_bytes()
        pointer = (staging / 'ck-plexus.current').read_bytes()
        write_executable(candidate, body.replace('echo smoke-ok', 'exit 1'))
        second = run(command, cwd=checkout, env=env)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(artifact.read_bytes(), before, 'refusal must not overwrite published bytes')
        self.assertEqual((staging / 'ck-plexus.current').read_bytes(), pointer)
        self.assertEqual(list(staging.glob('.candidate.*')), [])
        write_executable(candidate, body)
        third = run(command, cwd=checkout, env=env)
        self.assertNotEqual(third.returncode, 0, 'same-commit artifacts must be immutable')
        self.assertIn('immutable staging artifact', third.stderr)
        self.assertEqual(artifact.read_bytes(), before)

    def test_a_failed_run_with_only_skipped_jobs_is_not_green(self):
        tools = self.tmp / 'bin'
        write_executable(tools / 'gh', '''#!/bin/sh
case "$*" in
  *"--json jobs"*)
    case "$*" in
      *".jobs | length"*) echo 1;;
      *"bad="*) echo bad=;;
      *'select(.conclusion=="success")'*) echo 0;;
    esac;;
  *"--json status"*) echo completed;;
  *"--json conclusion"*) echo failure;;
  *"--json url"*) echo https://example.invalid/run;;
esac
''')
        result = run(['bash', SCRIPTS / 'watch-ci.sh', '12345'],
                     env={'PATH': f'{tools}:{SYSTEM_PATH}', 'REPO': 'owner/repo',
                          'OPERATOR_GH_FALLBACK_PATHS': '', 'WATCH_CI_POLL_SLEEP': '0',
                          'WATCH_CI_VERDICT_RETRY_SLEEP': '0'})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_provenance_requires_the_exact_clean_reported_commit(self):
        sha = 'a' * 40
        binary = self.tmp / 'candidate'
        for stamp, accepted in [(sha, True), (sha + '-dirty', False), ('b' * 40, False),
                                ('fixture-revision', False), (sha + '0', False), (sha[:12], False)]:
            with self.subTest(stamp=stamp):
                write_executable(binary, f'#!/bin/sh\necho "ck-plexus 0.1.0 (commit {stamp}, lock 123abc)"\n')
                result = run(['bash', SCRIPTS / 'lib/verify-build-commit.sh', binary, sha])
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_conformance_list_failure_cannot_be_hidden_by_partial_output(self):
        from test_scripts import load_gates_module
        step = next(step for step in load_gates_module().parse_workflow(str(REPO / '.github/workflows/ci.yml'))['jobs']['test']['steps']
                    if step.get('name') == 'Conformance fixtures')
        harness = write_executable(self.tmp / 'harness', '#!/bin/sh\necho partial\nexit 1\n')
        source = step['run']
        start = source.index('fixture_list=') if 'fixture_list=' in source else source.index('mapfile -t fixtures')
        end = source.index('echo "Fixtures:')
        result = run(['bash', '-c', 'set -euo pipefail\nharness="$1"\n' + source[start:end], 'test', harness])
        self.assertNotEqual(result.returncode, 0, 'a failed catalogue producer must refuse the step')

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

    def test_embedded_commit_resolves_dirty_candidates_and_keeps_binary_order(self):
        commits = [subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', ref], text=True).strip()
                   for ref in ['HEAD', 'HEAD~1']]
        binary = self.tmp / 'stamps'
        binary.write_text('0' * 40 + '-dirty\n' + commits[0] + '\n')
        command = ['python3', SCRIPTS / 'lib/embedded-commit.py', binary, REPO, '40']
        result = run(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), commits[0], 'unresolvable dirty stamps must be ignored')
        first, second = sorted(commits, reverse=True)
        binary.write_text(first + '\n' + second + '\n')
        result = run(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), first, 'candidate order must follow the binary, not lexical sorting')

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
