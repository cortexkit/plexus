"""Exact-commit pre-push receipts and no-compile/remote phase ordering."""
import json
import shutil
import time

from test_scripts import REPO, SCRIPTS, SYSTEM_PATH, Scratch, git, run, write_executable


class PrepushTests(Scratch):
    def setUp(self):
        super().setUp()
        self.checkout = self.tmp / 'checkout with spaces'
        (self.checkout / 'scripts').mkdir(parents=True)
        shutil.copy2(SCRIPTS / 'prepush.sh', self.checkout / 'scripts/prepush.sh')
        self.log = self.tmp / 'phases'
        write_executable(self.checkout / 'scripts/rust-test-gate.sh', '''#!/bin/sh
echo "fast $*" >> "$PHASE_LOG"
exit "${FAST_RC:-0}"
''')
        tools = self.tmp / 'bin'
        write_executable(tools / 'ck', '''#!/bin/sh
echo "remote $*" >> "$PHASE_LOG"
if [ "${MOVE_HEAD:-0}" = 1 ]; then
  git -c user.name=Test -c user.email=test@example.invalid commit -q --allow-empty -m moved
fi
exit "${REMOTE_RC:-0}"
''')
        self.env = {'PATH': f'{tools}:{SYSTEM_PATH}', 'PHASE_LOG': str(self.log),
                    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
        git('init', '-q', cwd=self.checkout)
        self.commit()

    def commit(self):
        git('add', '.', cwd=self.checkout)
        result = git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                     'commit', '-q', '--allow-empty', '-m', 'source', cwd=self.checkout)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.sha = git('rev-parse', 'HEAD', cwd=self.checkout).stdout.strip()

    def prepush(self, *args, **env):
        return run(['bash', self.checkout / 'scripts/prepush.sh', *args],
                   cwd=self.tmp, env={**self.env, **env})

    def receipt(self):
        return self.checkout / '.git/plexus-prepush' / (self.sha + '.json')

    def test_pass_runs_fast_first_then_linux_at_16c_and_binds_exact_commit(self):
        result = self.prepush()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'PASS prepush: {self.sha}', result.stdout)
        phases = self.log.read_text().splitlines()
        self.assertEqual(phases[0], 'fast --fast')
        self.assertIn('--platform linux --vcpus 16 --net', phases[1])
        self.assertTrue(phases[1].endswith('-- bash scripts/prepush.sh --full'))
        self.assertEqual(self.prepush('--require-pass', self.sha).returncode, 0)
        tag = git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                  'tag', '-a', 'annotated', '-m', 'tag', cwd=self.checkout)
        self.assertEqual(tag.returncode, 0, tag.stderr)
        self.assertEqual(self.prepush('--require-pass', 'annotated').returncode, 0)
        old = self.sha
        self.commit()
        self.assertNotEqual(self.prepush('--require-pass', self.sha).returncode, 0)
        self.assertEqual(self.prepush('--require-pass', old).returncode, 0)

    def test_fast_failure_never_dispatches_and_names_the_step(self):
        result = self.prepush(FAST_RC='17')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'FAIL prepush: {self.sha} (fast local preflight)', result.stderr)
        self.assertEqual(self.log.read_text().splitlines(), ['fast --fast'])
        self.assertFalse(self.receipt().exists())

    def test_failed_remote_retry_invalidates_an_older_pass(self):
        self.assertEqual(self.prepush().returncode, 0)
        result = self.prepush(REMOTE_RC='23')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'FAIL prepush: {self.sha} (Linux CI parity gate', result.stderr)
        self.assertFalse(self.receipt().exists())

    def test_fast_entry_point_never_dispatches_and_names_the_commit(self):
        result = self.prepush('--fast')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'PASS prepush-fast: {self.sha}', result.stdout)
        self.assertEqual(self.log.read_text().splitlines(), ['fast --fast'])
        self.assertFalse(self.receipt().exists())

    def test_full_entry_point_runs_gate_without_motor_and_names_the_commit(self):
        result = self.prepush('--full')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'PASS prepush-full: {self.sha}', result.stdout)
        self.assertEqual(self.log.read_text().splitlines(), ['fast --ci'])
        self.assertFalse(self.receipt().exists())
        failed = self.prepush('--full', FAST_RC='7')
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(f'FAIL prepush-full: {self.sha}', failed.stderr)

    def test_dirty_checkout_and_head_movement_cannot_receive_a_pass(self):
        dirty = self.checkout / 'untracked'
        dirty.write_text('not committed')
        result = self.prepush()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('clean committed source', result.stderr)
        self.assertFalse(self.log.exists(), 'dirty source must refuse before either phase starts')
        dirty.unlink()
        result = self.prepush(MOVE_HEAD='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('source unchanged during gate', result.stderr)
        self.assertFalse(self.receipt().exists())

    def test_missing_stale_future_malformed_and_wrong_tree_receipts_refuse(self):
        self.assertNotEqual(self.prepush('--require-pass', self.sha).returncode, 0)
        self.assertEqual(self.prepush().returncode, 0)
        original = json.loads(self.receipt().read_text())
        for change in [{'passed_at': time.time() - 86401}, {'passed_at': time.time() + 3600},
                       {'tree': '0' * 40}, {'sha': '0' * 40}, {'passed_at': 'not a time'}]:
            with self.subTest(change=change):
                self.receipt().write_text(json.dumps({**original, **change}))
                self.assertNotEqual(self.prepush('--require-pass', self.sha).returncode, 0)
        self.receipt().write_text('not json')
        self.assertNotEqual(self.prepush('--require-pass', self.sha).returncode, 0)

    def prepare_hook(self):
        (self.checkout / '.githooks').mkdir()
        shutil.copy2(REPO / '.githooks/pre-push', self.checkout / '.githooks/pre-push')
        write_executable(self.checkout / 'scripts/lib/repository-identity.sh',
                         'require_github_repository() { echo cortexkit/plexus; }\n')
        write_executable(self.checkout / 'scripts/lib/operator-gh.sh', 'OPERATOR_GH=gh\n')
        tools = self.tmp / 'bin'
        write_executable(tools / 'gh', '''#!/bin/sh
printf 'Test (ubuntu)\t%s\n' "${CI_CONCLUSION:-success}"
''')
        self.commit()

    def hook(self, updates, **env):
        return run(['bash', self.checkout / '.githooks/pre-push', 'origin'],
                   cwd=self.checkout, env={**self.env, **env}, input_text=updates)

    def test_hook_requires_pass_for_train_and_tags_but_not_deletions(self):
        self.prepare_hook()
        for ref in ['refs/heads/train/work', 'refs/tags/v1']:
            update = f'refs/heads/work {self.sha} {ref} {"0" * 40}\n'
            self.assertNotEqual(self.hook(update).returncode, 0)
        self.assertEqual(self.prepush().returncode, 0)
        update = f'refs/heads/work {self.sha} refs/heads/train/work {"0" * 40}\n'
        self.assertEqual(self.hook(update).returncode, 0)
        old = self.sha
        self.commit()
        second = f'refs/heads/work {self.sha} refs/heads/other {"0" * 40}\n'
        self.assertNotEqual(self.hook(update + second).returncode, 0)
        deletion = f'(delete) {"0" * 40} refs/heads/train/old {old}\n'
        self.assertEqual(self.hook(deletion).returncode, 0)

    def test_local_pass_does_not_replace_main_green_ci(self):
        self.prepare_hook()
        self.assertEqual(self.prepush().returncode, 0)
        update = f'refs/heads/work {self.sha} refs/heads/main {"0" * 40}\n'
        self.assertEqual(self.hook(update).returncode, 0)
        failed = self.hook(update, CI_CONCLUSION='failure')
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('Test (ubuntu) did not succeed', failed.stderr)

    def test_train_requires_the_current_sha_on_every_push_round(self):
        self.assertEqual(self.prepush().returncode, 0)
        tested = self.sha
        self.commit()
        source = (SCRIPTS / 'train-push.sh').read_text()
        push_train = source[source.index('push_train() {'):source.index('\n# Rebase the checked-out train')]
        result = run(['bash', '-c', '''set -eu
refuse() { echo "$*" >&2; exit 19; }
say() { :; }
push_to_origin() { echo pushed; }
remote=origin train_ref=train/test train_remote_sha= head_sha="$1" script_dir="$3"
''' + push_train + '''
push_train
head_sha="$2"
push_train
''', 'test', tested, self.sha, self.checkout / 'scripts'], cwd=self.checkout, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'recent PASS verified for {tested}', result.stdout)
        self.assertIn('no PASS in the last 24 hours', result.stderr)
        self.assertEqual(result.stdout.splitlines().count('pushed'), 1)


class CiParityTests(Scratch):
    def ci_mode(self):
        checkout = self.tmp / 'checkout'
        (checkout / 'scripts/lib').mkdir(parents=True)
        (checkout / '.github/workflows').mkdir(parents=True)
        for relative in ['scripts/rust-test-gate.sh', 'scripts/lib/workflow-gates.py',
                         '.github/workflows/ci.yml']:
            shutil.copy2(REPO / relative, checkout / relative)
        tools = self.tmp / 'bin'
        log = self.tmp / 'commands'
        write_executable(tools / 'rustup', '#!/bin/sh\necho "rustup $* home=$RUSTUP_HOME" >> "$COMMAND_LOG"\n')
        write_executable(tools / 'bash', '''#!/bin/sh
echo "$*" >> "$COMMAND_LOG"
case "$1" in
  *install-nats-server.sh) echo "nats-dir=$NATS_SERVER_INSTALL_DIR" >> "$COMMAND_LOG"; [ "$NATS_SERVER_VERSION" = 2.15.0 ] ;;
  *rust-test-gate.sh) exit 7 ;;
  *run-conformance-fixtures.sh) exit 0 ;;
  *build-probe-guest.sh) [ "$2" = --check ] ;;
  *) exit 99 ;;
esac
''')
        result = run(['/bin/bash', checkout / 'scripts/rust-test-gate.sh', '--ci'],
                     env={'PATH': f'{tools}:{SYSTEM_PATH}', 'COMMAND_LOG': str(log)})
        return result, log.read_text(), checkout

    def test_ci_mode_keeps_conformance_and_guest_answers_after_host_failure(self):
        result, commands, _checkout = self.ci_mode()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('scripts/run-conformance-fixtures.sh', commands)
        self.assertIn('scripts/build-probe-guest.sh --check', commands)
        self.assertIn('FAIL rust-test-gate: Rust workspace gate', result.stderr)

    def test_ci_mode_keeps_tool_installs_in_writable_workspace_output(self):
        _result, commands, checkout = self.ci_mode()
        self.assertIn(f'home={checkout}/target/prepush-tools/rustup', commands)
        self.assertIn(f'nats-dir={checkout}/target/prepush-tools/bin', commands)

    def test_ci_mode_never_self_updates_the_shared_rustup_binary(self):
        _result, commands, _checkout = self.ci_mode()
        installs = [line for line in commands.splitlines() if line.startswith('rustup toolchain install ')]
        self.assertEqual(len(installs), 2)
        for install in installs:
            self.assertIn('--no-self-update', install)


class PinnedFixturesTests(Scratch):
    def setUp(self):
        super().setUp()
        import importlib.util
        spec = importlib.util.spec_from_file_location('pinned', SCRIPTS / 'check-pinned-fixtures.py')
        assert spec is not None and spec.loader is not None
        self.checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checker)

    def test_pinned_bytes_are_checked_and_corruption_refuses(self):
        manifest = self.tmp / 'SHA256SUMS'
        fixture = self.tmp / 'records.json'
        fixture.write_bytes(b'abc')
        manifest.write_text('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  records.json\n')
        self.assertEqual(self.checker.verify_manifest(manifest), 1)
        fixture.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            self.checker.verify_manifest(manifest)
        fixture.unlink()
        with self.assertRaises(OSError):
            self.checker.verify_manifest(manifest)

    def test_permissions_only_checks_the_documented_vendored_subset(self):
        corpus = self.tmp / 'permissions-v1'
        corpus.mkdir()
        (corpus / 'provider-ok.json').write_bytes(b'abc')
        manifest = corpus / 'SHA256SUMS'
        manifest.write_text('0' * 64 + '  list-all-not-vendored.json\n' +
                            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  provider-ok.json\n')
        self.assertEqual(self.checker.verify_manifest(manifest), 1)
        manifest.write_text('0' * 64 + '  list-all-not-vendored.json\n')
        with self.assertRaisesRegex(ValueError, 'no copied fixture'):
            self.checker.verify_manifest(manifest)

    def test_malformed_and_empty_manifests_refuse(self):
        manifest = self.tmp / 'SHA256SUMS'
        for content in ['', 'not a checksum\n']:
            with self.subTest(content=content):
                manifest.write_text(content)
                with self.assertRaises(ValueError):
                    self.checker.verify_manifest(manifest)
