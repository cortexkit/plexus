"""Exercise the real EXIT handlers without running builds, downloads or pushes."""

import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
GUARDS = {
    "build-probe-guest.sh": [("extracted",)],
    "install-nats-server.sh": [("install_dir",)],
    "lib/verify-build-commit.sh": [("directory",)],
    "stage-binaries.sh": [("CHECK_DIR",), ("CHECK_DIR", "STAGING", "PUBLISH_LOCK"), ("CHECK_DIR", "PUBLISH_LOCK")],
    "train-push.sh": [("TRAIN_PUSH_EXEC_COPY",), ("watch_log", "push_log", "TRAIN_PUSH_EXEC_COPY")],
}
DIRECTORIES = ("extracted", "install_dir", "directory", "CHECK_DIR", "STAGING", "PUBLISH_LOCK")
FILES = ("TRAIN_PUSH_EXEC_COPY", "watch_log", "push_log", "HEARTBEAT_TMP", "HEARTBEAT", "STATUS_FILE")


def trap_fragments(text):
    """Extract each installed trap and its named handler, not a copied guard."""
    fragments = []
    for trap in re.findall(r"(?m)^[ \t]*trap[ \t]+[^\n]+[ \t]+EXIT[ \t]*$", text):
        action = shlex.split(trap)[1]
        handler = ""
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", action):
            match = re.search(r"(?ms)^" + action + r"\(\) \{\n.*?^\}", text)
            if match is None:
                raise AssertionError("cannot extract EXIT handler " + action)
            handler = match[0] + "\n"
        fragments.append(handler + trap + "\n")
    return fragments


class ExitTrapHarness(unittest.TestCase):
    def setUp(self):
        scratch = REPO / "target" / "scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="exit-traps-", dir=scratch))
        self.addCleanup(shutil.rmtree, self.tmp)

    def exercise(self, name, index, body, *, bash="/bin/bash", cleanup_failure=False):
        text = (SCRIPTS / name).read_text()
        settings = re.search(r"(?m)^set -[^\n]+", text)
        if settings is None:
            raise AssertionError("cannot extract shell options from " + name)
        options = settings[0]
        initialization = "finished=0\n" if re.search(r"(?m)^finished=0$", text) else ""
        paths = {}
        for variable in DIRECTORIES + FILES:
            path = self.tmp / variable
            if variable in DIRECTORIES:
                path.mkdir(exist_ok=True)
            else:
                path.touch()
            paths[variable] = path
            initialization += f"{variable}={shlex.quote(str(path))}\n"
        initialization += 'SLEEP_PID=""\n'
        fragments = trap_fragments(text)
        expected_count = len(GUARDS[name]) if name in GUARDS else 1
        self.assertEqual(len(fragments), expected_count, name)
        stubs = "rm() { return 9; }; rmdir() { return 9; }\n" if cleanup_failure else ""
        result = subprocess.run(
            [bash, "-c", options + "\nunset __plexus_guard_unset\n" + initialization + stubs + fragments[index] + body],
            cwd=REPO, capture_output=True, text=True, timeout=10,
        )
        return result, paths

    def assert_cleanup(self, paths, removed):
        for variable in DIRECTORIES + FILES:
            self.assertEqual(paths[variable].exists(), variable not in removed, variable)


class ExitTrapContractTests(ExitTrapHarness):
    def test_success_and_failure_statuses_and_cleanup(self):
        cases = (
            ("unmarked success", "exit 0\n", 1),
            ("normal completion", "finished=1\n", 0),
            ("explicit success", "finished=1\nexit 0\n", 0),
            ("explicit failure", "exit 7\n", 7),
            ("failure after marking", "finished=1\nexit 7\n", 7),
            ("errexit", "false\n", 1),
        )
        for name, guards in GUARDS.items():
            for index, removed in enumerate(guards):
                for label, body, expected in cases:
                    with self.subTest(script=name, trap=index, case=label):
                        result, paths = self.exercise(name, index, body)
                        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                        self.assert_cleanup(paths, removed)

    def test_cleanup_failure_keeps_original_failure_and_cannot_report_success(self):
        for name, guards in GUARDS.items():
            for index in range(len(guards)):
                for body, expected in (("exit 7\n", 7), ("finished=1\n", 9)):
                    with self.subTest(script=name, trap=index, status=expected):
                        result, _ = self.exercise(name, index, body, cleanup_failure=True)
                        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_success_paths_mark_completion(self):
        for name in GUARDS:
            with self.subTest(script=name):
                text = (SCRIPTS / name).read_text()
                self.assertRegex(text, r"(?m)^finished=0$")
                self.assertEqual(text.rstrip().splitlines()[-1], "finished=1")
                for match in re.finditer(r"(?m)^.*\bexit 0\b.*$", text):
                    if match[0].lstrip().startswith("#"):
                        continue
                    self.assertEqual(text[:match.start()].rstrip().splitlines()[-1].strip(), "finished=1")


class Bash32ExitTrapTests(ExitTrapHarness):
    @classmethod
    def setUpClass(cls):
        if not Path("/bin/bash").exists():
            raise unittest.SkipTest("/bin/bash is absent; Bash 3.2 regression requires macOS /bin/bash")
        version = subprocess.check_output(["/bin/bash", "-c", 'printf "%s" "$BASH_VERSION"'], text=True)
        if not version.startswith("3.2."):
            raise unittest.SkipTest(f"/bin/bash is {version}, not 3.2; run the nounset regression on macOS")

    def assert_nounset_fails(self, name):
        for index, removed in enumerate(GUARDS[name]):
            for expression in ('"$__plexus_guard_unset"', '"${__plexus_guard_empty[@]}"'):
                with self.subTest(script=name, trap=index, expression=expression):
                    body = f"__plexus_guard_empty=()\nprintf '%s\\n' {expression}\necho after-injection\n"
                    result, paths = self.exercise(name, index, body)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("unbound variable", result.stderr)
                    self.assertNotIn("after-injection", result.stdout)
                    self.assert_cleanup(paths, removed)

    def test_build_probe_guest(self):
        self.assert_nounset_fails("build-probe-guest.sh")

    def test_install_nats_server(self):
        self.assert_nounset_fails("install-nats-server.sh")

    def test_verify_build_commit(self):
        self.assert_nounset_fails("lib/verify-build-commit.sh")

    def test_stage_binaries_all_three_traps(self):
        self.assert_nounset_fails("stage-binaries.sh")

    def test_train_push_both_traps(self):
        self.assert_nounset_fails("train-push.sh")

    def test_old_trap_control_masks_nounset(self):
        directory = self.tmp / "old-cleanup"
        directory.mkdir()
        result = subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail; unset __plexus_guard_unset; d=' + shlex.quote(str(directory))
             + '; trap \'rm -rf "$d"\' EXIT; echo "$__plexus_guard_unset"; echo after-injection'],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unbound variable", result.stderr)
        self.assertNotIn("after-injection", result.stdout)
        self.assertFalse(directory.exists())

    def test_watch_ci_without_errexit_is_not_exposed(self):
        text = (SCRIPTS / "watch-ci.sh").read_text()
        self.assertRegex(text, r"(?m)^set -uo pipefail$")
        self.assertNotRegex(text, r"(?m)^\s*set -[a-zA-Z]*e")
        result, paths = self.exercise("watch-ci.sh", 0, 'echo "$__plexus_guard_unset"\necho after-injection\n')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unbound variable", result.stderr)
        self.assertNotIn("after-injection", result.stdout)
        self.assert_cleanup(paths, ("HEARTBEAT_TMP", "HEARTBEAT", "STATUS_FILE"))


class ExitTrapLayoutTests(ExitTrapHarness):
    def test_tracked_scripts_are_checked_after_planted_controls(self):
        repo = self.tmp / "repo"
        (repo / "scripts").mkdir(parents=True)
        shutil.copy2(SCRIPTS / "check-exit-traps.py", repo / "scripts")
        env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}

        def git(*args):
            result = subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        git("init", "-q")
        unsafe = '#!/bin/bash\nset -euo pipefail\ntrap \'rm -rf "$d"\' EXIT\n'
        (repo / "unsafe.sh").write_text(unsafe + "# finished=1\n")
        (repo / "no-extension").write_text(unsafe.replace("-euo pipefail", "-e"))
        (repo / "guarded.sh").write_text(unsafe + "finished=1\n")
        (repo / "watch.sh").write_text(unsafe.replace("-euo pipefail", "-uo pipefail"))
        (repo / "err-only.sh").write_text(unsafe.replace("EXIT", "ERR"))
        (repo / "untracked.sh").write_text(unsafe)
        git("add", "unsafe.sh", "no-extension", "guarded.sh", "watch.sh", "err-only.sh")

        def check():
            return subprocess.run(
                [sys.executable, "-B", repo / "scripts" / "check-exit-traps.py"],
                cwd=self.tmp, env=env, capture_output=True, text=True, timeout=10,
            )

        result = check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("controls passed", result.stdout)
        self.assertIn("unsafe.sh:", result.stderr)
        self.assertIn("no-extension:", result.stderr)
        for name in ("guarded.sh", "watch.sh", "err-only.sh", "untracked.sh"):
            self.assertNotIn(name, result.stderr)
        (repo / "unsafe.sh").write_text(unsafe + "finished=1\n")
        (repo / "no-extension").write_text(unsafe + "finished=1\n")
        result = check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("checked 5 tracked shell scripts", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
