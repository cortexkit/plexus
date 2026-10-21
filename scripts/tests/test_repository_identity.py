"""Repository-identity landing guards, with GitHub reads and network Git stubbed."""

import shutil

from test_scripts import REPO, SCRIPTS, SYSTEM_PATH, Scratch, git, run, write_executable


PRIVATE_ID = "1309965040"
PUBLIC_ID = "42"


class RepositoryIdentityTests(Scratch):
    def setUp(self):
        super().setUp()
        self.checkout = self.tmp / "checkout"
        (self.checkout / ".github").mkdir(parents=True)
        self.identity = self.checkout / ".github/repository-id"
        self.identity.write_text(PRIVATE_ID + "\n")
        shutil.copytree(SCRIPTS / "lib", self.checkout / "scripts/lib")
        shutil.copy2(SCRIPTS / "train-push.sh", self.checkout / "scripts/train-push.sh")
        shutil.copy2(SCRIPTS / "install-hooks.sh", self.checkout / "scripts/install-hooks.sh")
        (self.checkout / ".githooks").mkdir()
        shutil.copy2(REPO / ".githooks/pre-push", self.checkout / ".githooks/pre-push")
        self.assertEqual(git("init", "-q", cwd=self.checkout).returncode, 0)
        self.origin = "https://github.com/cortexkit/plexus.git"
        self.assertEqual(git("remote", "add", "origin", self.origin, cwd=self.checkout).returncode, 0)
        self.tools = self.tmp / "bin"
        self.calls = self.tmp / "gh-calls"
        self.sentinel = self.tmp / "git-sentinel"
        write_executable(self.tools / "gh", '''#!/bin/sh
printf '%s\n' "$*" >> "$GH_CALLS"
case "$1:$2" in
  api:repos/*/commits/*/check-runs) printf '%b\n' "${MOCK_VERDICTS:-Test (ubuntu)\tsuccess}" ;;
  api:repos/*)
    [ "${MOCK_API_FAILURE:-0}" = 0 ] || exit 1
    case "$2" in
      repos/cortexkit/plexus-private) echo 1309965040 ;;
      repos/cortexkit/plexus) echo "${MOCK_ORIGIN_ID-1309965040}" ;;
      *) echo 42 ;;
    esac ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
''')
        real_git = shutil.which("git", path=SYSTEM_PATH)
        # Stop a passing train immediately after its guard, before locks, remote
        # reads or pushes. The refusal path must never reach this sentinel.
        write_executable(self.tools / "git", f'''#!/bin/sh
case "$*" in
  *--absolute-git-dir*) echo TEST_STOP_AFTER_IDENTITY > "$GIT_SENTINEL"; exit 89 ;;
  *" push "*|*" ls-remote "*|*" fetch "*) echo UNEXPECTED_NETWORK_GIT >&2; exit 90 ;;
esac
exec "{real_git}" "$@"
''')
        self.env = {"PATH": f"{self.tools}:{SYSTEM_PATH}", "GH_CALLS": str(self.calls),
                    "TMPDIR": str(self.tmp), "GIT_SENTINEL": str(self.sentinel), "OPERATOR_GH_FALLBACK_PATHS": "",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}

    def hook(self, ref="refs/heads/main", sha="a" * 40, **env):
        return run(["sh", self.checkout / ".githooks/pre-push", "origin", self.origin],
                   cwd=self.checkout, env={**self.env, **env},
                   input_text=f"refs/heads/work {sha} {ref} {'b' * 40}\n")

    def train(self, **env):
        return run(["bash", self.checkout / "scripts/train-push.sh", "identity-test"],
                   cwd=self.checkout, env={**self.env, **env})

    def assert_refused_identity(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"expects repository ID {PRIVATE_ID}", result.stderr)
        self.assertIn(f"repository ID {PUBLIC_ID}", result.stderr)
        self.assertIn("cortexkit/plexus-private", result.stderr)
        self.assertFalse(self.sentinel.exists(), "identity refusal must precede the next train phase")
        self.assertNotIn("UNEXPECTED_NETWORK_GIT", result.stderr)

    def test_hook_refuses_reused_origin_on_non_main_refs(self):
        for ref, sha in [("refs/heads/train/work", "a" * 40),
                         ("refs/tags/v1", "a" * 40), ("refs/heads/main", "0" * 40)]:
            with self.subTest(ref=ref, sha=sha):
                self.assert_refused_identity(self.hook(ref, sha, MOCK_ORIGIN_ID=PUBLIC_ID))
        self.assertNotIn("check-runs", self.calls.read_text())

    def test_hook_accepts_matching_identity_then_checks_main_ci(self):
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("repos/cortexkit/plexus --hostname github.com --jq .id", self.calls.read_text())
        self.assertIn(f"repos/cortexkit/plexus/commits/{'a' * 40}/check-runs", self.calls.read_text())
        red = self.hook(MOCK_VERDICTS="Test (ubuntu)\\tfailure")
        self.assertEqual(red.returncode, 1, red.stderr)
        self.assertIn("no check is green", red.stderr)

    def test_unrelated_green_check_cannot_substitute_for_the_test_job(self):
        result = self.hook(MOCK_VERDICTS="Unrelated app\\tsuccess")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Test (ubuntu)", result.stderr)

    def test_hook_installation_is_explicit_and_preserves_custom_hooks(self):
        result = run(['bash', self.checkout / 'scripts/install-hooks.sh'], cwd=self.checkout, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(git('config', '--get', 'core.hooksPath', cwd=self.checkout).stdout.strip(), str(self.checkout / '.githooks'))
        git('config', 'core.hooksPath', '/custom/hooks', cwd=self.checkout)
        refused = run(['bash', self.checkout / 'scripts/install-hooks.sh'], cwd=self.checkout, env=self.env)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(git('config', '--get', 'core.hooksPath', cwd=self.checkout).stdout.strip(), '/custom/hooks')

    def test_matching_identity_is_read_once_per_distinct_repository(self):
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        identity_calls = [line for line in self.calls.read_text().splitlines() if '--jq .id' in line]
        self.assertEqual(len(identity_calls), 1)

    def test_hook_accepts_skipped_mutation_shards_only_beside_a_green_test_job(self):
        # A skipped matrix job keeps its unexpanded name.
        shard = "Mutation proofs (${{ matrix.shard }}/${{ matrix.total }})\\tskipped"
        accepted = self.hook(MOCK_VERDICTS=f"Test (ubuntu)\\tsuccess\\n{shard}")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for label, verdicts, message in [
            ("test job failed", f"Test (ubuntu)\\tfailure\\n{shard}", "no check is green"),
            ("no test job", shard, "no check is green"),
            # Only the test job plans the shards, so another check's success
            # must not excuse a skipped shard.
            ("another green check but no test job", f"Lint\\tsuccess\\n{shard}", "not every check is green"),
            ("another skipped check", "Test (ubuntu)\\tsuccess\\nLint\\tskipped", "not every check is green"),
            ("a failed shard", "Test (ubuntu)\\tsuccess\\nMutation proofs (1/9)\\tfailure", "not every check is green"),
        ]:
            with self.subTest(label=label):
                refused = self.hook(MOCK_VERDICTS=verdicts)
                self.assertEqual(refused.returncode, 1, refused.stderr)
                self.assertIn(message, refused.stderr)

    # The planner sizes the shard count to the selection, so the hook must not
    # depend on any particular count of shards.
    def test_hook_reads_every_shard_of_a_sized_mutation_matrix(self):
        shards = [f"Mutation proofs ({i}/9)" for i in range(1, 10)]
        green = "\\n".join(["Test (ubuntu)\\tsuccess"] + [f"{name}\\tsuccess" for name in shards])
        accepted = self.hook(MOCK_VERDICTS=green)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for red_shard in (1, 6, 9):
            with self.subTest(red_shard=red_shard):
                verdicts = "\\n".join(["Test (ubuntu)\\tsuccess"] + [
                    f"{name}\\t{'failure' if i == red_shard else 'success'}"
                    for i, name in enumerate(shards, start=1)])
                refused = self.hook(MOCK_VERDICTS=verdicts)
                self.assertEqual(refused.returncode, 1, refused.stderr)
                self.assertIn("not every check is green", refused.stderr)
                self.assertIn("failure", refused.stderr)

    def test_hook_accepts_renamed_repository_with_the_same_id(self):
        for url in ["https://github.com/cortexkit/plexus-private.git",
                    "git@github.com:cortexkit/plexus-private.git",
                    "ssh://git@github.com/cortexkit/plexus-private.git"]:
            with self.subTest(url=url):
                self.origin = url
                git("remote", "set-url", "origin", url, cwd=self.checkout)
                result = self.hook()
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"repos/cortexkit/plexus-private/commits/{'a' * 40}/check-runs", self.calls.read_text())

    def test_hook_refuses_a_different_push_url_even_with_a_safe_origin(self):
        git("config", "--add", "remote.origin.pushurl", self.origin, cwd=self.checkout)
        git("config", "--add", "remote.origin.pushurl", "https://github.com/other/repo.git", cwd=self.checkout)
        result = self.hook("refs/heads/work")
        self.assert_refused_identity(result)
        self.assertIn("origin push URL resolved to other/repo", result.stderr)

    def test_hook_checks_the_actual_destination_not_only_origin(self):
        self.origin = "https://github.com/other/repo.git"
        result = self.hook("refs/heads/work")
        self.assert_refused_identity(result)
        self.assertIn("push destination resolved to other/repo", result.stderr)

    def test_train_refuses_a_reused_origin_name(self):
        result = self.train(MOCK_ORIGIN_ID=PUBLIC_ID)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assert_refused_identity(result)
        self.assertNotIn("check-runs", self.calls.read_text())

    def test_train_matching_identity_reaches_the_next_phase_without_pushing(self):
        result = self.train()
        self.assertEqual(result.returncode, 89, result.stdout + result.stderr)
        self.assertEqual(self.sentinel.read_text().strip(), "TEST_STOP_AFTER_IDENTITY")
        self.assertIn("repos/cortexkit/plexus --hostname github.com --jq .id", self.calls.read_text())
        self.assertNotIn("UNEXPECTED_NETWORK_GIT", result.stderr)

    def test_train_ci_repository_override_cannot_select_another_id(self):
        result = self.train(REPO="other/repo")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assert_refused_identity(result)
        self.assertIn("CI repository override resolved to other/repo", result.stderr)

    def test_identity_resolution_fails_closed_on_api_errors_and_invalid_ids(self):
        for env in [{"MOCK_API_FAILURE": "1"}, {"MOCK_ORIGIN_ID": "null"},
                    {"MOCK_ORIGIN_ID": ""}, {"MOCK_ORIGIN_ID": "0"}]:
            with self.subTest(env=env):
                for result in [self.hook("refs/heads/work", **env), self.train(**env)]:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn("repository guard: refusing", result.stderr)
                    self.assertIn("nothing was verified", result.stderr)
                    self.assertIn(PRIVATE_ID, result.stderr)
                    self.assertFalse(self.sentinel.exists(), "identity refusal must precede the next train phase")

    def test_missing_or_malformed_expected_identity_never_uses_origin_as_a_default(self):
        for content in [None, "", "not-an-id\n", "0\n", PRIVATE_ID + "\n42\n"]:
            with self.subTest(content=content):
                if content is None:
                    self.identity.unlink()
                else:
                    self.identity.write_text(content)
                for result in [self.hook("refs/heads/work"), self.train()]:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn("repository guard: refusing", result.stderr)
                    self.assertFalse(self.sentinel.exists(), "identity refusal must precede the next train phase")
        self.assertFalse(self.calls.exists(), "invalid expected identity must fail before any API request")

    def test_missing_gh_fails_closed_without_attempting_to_push(self):
        self.tools.joinpath("gh").unlink()
        # Use a PATH containing only the commands the hook needs before gh, so
        # a host-installed authenticated CLI cannot stand in for the missing one.
        for tool in ["git", "cat"]:
            target = self.tools / tool
            if target.exists():
                target.unlink()
            tool_path = shutil.which(tool, path=SYSTEM_PATH)
            assert tool_path is not None, f"required system tool is missing: {tool}"
            target.symlink_to(tool_path)
        result = run(["/bin/sh", self.checkout / ".githooks/pre-push", "origin", self.origin],
                     cwd=self.checkout, env={**self.env, "PATH": str(self.tools)},
                     input_text=f"refs/heads/work {'a' * 40} refs/heads/work {'b' * 40}\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("gh is required to resolve origin's repository ID", result.stderr)
        self.assertIn("nothing was verified", result.stderr)
        self.assertFalse(self.calls.exists())

    def test_fresh_public_clone_uses_its_own_tracked_identity_without_git_config(self):
        self.identity.write_text(PUBLIC_ID + "\n")
        result = self.hook(MOCK_ORIGIN_ID=PUBLIC_ID)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check-runs", self.calls.read_text())

    def test_non_github_origin_is_not_an_identity_bypass(self):
        git("remote", "set-url", "origin", "https://example.invalid/owner/repo.git", cwd=self.checkout)
        for result in [self.hook("refs/heads/work"), self.train()]:
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("not a supported GitHub repository URL", result.stderr)
        self.assertFalse(self.calls.exists())
