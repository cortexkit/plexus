"""Regression tests for the operator scripts under scripts/.

Each test drives a real script the way an operator or CI does, with the
external tools it calls (gh, dwarfdump, the ck CLI, cargo) replaced by small
stubs on PATH, and asserts on the script's exit status and output. They run on
macOS and Linux; a test that needs a tool the host lacks is skipped and named
in the summary rather than passing silently.

Run from the repository root with scripts/tests/run.py, which the Rust test
gate calls.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
# Base PATH for scripts under test: the system tools only, so nothing from the
# invoking shell (a real gh, an AFT shim) can answer in place of a stub.
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def write_executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def run(args, *, env=None, cwd=None, timeout=60, input_text=None):
    merged = {"PATH": SYSTEM_PATH, "HOME": os.environ.get("HOME", "/tmp"), "LC_ALL": "C"}
    if env:
        merged.update(env)
    return subprocess.run(
        [str(a) for a in args],
        env=merged,
        cwd=str(cwd or REPO),
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
    )


def git(*args, cwd):
    return run(["git", *args], cwd=cwd, env={"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})


class Scratch(unittest.TestCase):
    """A per-test temporary directory, removed afterwards."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="plexus-script-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# scripts/lib/workflow-gates.py and scripts/check-train-preconditions.sh
# ---------------------------------------------------------------------------
GATES = SCRIPTS / "lib" / "workflow-gates.py"


def workflow(branches: str, steps: str = "      - run: true\n", job_if: str = "") -> str:
    job_condition = f"    if: {job_if}\n" if job_if else ""
    return (
        "name: CI\n"
        "on:\n"
        "  push:\n"
        f"    branches: {branches}\n"
        "concurrency:\n"
        "  group: ci-${{ github.ref }}\n"
        "jobs:\n"
        "  test:\n"
        f"{job_condition}"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        f"{steps}"
    )


class WorkflowGatesTests(Scratch):
    def gates(self, *args):
        return run(["python3", "-B", GATES, *args])

    def test_plain_scalar_continuations_cannot_hide_a_ref_gate(self):
        path = self.tmp / "ci.yml"
        for condition in ["github.ref == 'refs/heads/main'", "github.event_name == 'push'"]:
            with self.subTest(condition=condition):
                path.write_text(workflow("[main, 'train/**']",
                    "      - if: success() &&\n          " + condition + "\n        run: true\n"))
                if "github.ref" in condition:
                    self.assertIn("ref|", self.gates(path).stdout)
                result = self.gates("--preconditions", path)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("path-dependent condition", result.stdout)

    def test_a_single_star_does_not_admit_a_nested_train(self):
        # GitHub's `*` stops at `/`, so `train/*` never matches train/a/b.
        # fnmatch's `*` also matches `/`, so a gate using it reports a match for
        # a branch on which no CI run would ever start.
        path = self.tmp / "ci.yml"
        path.write_text(workflow("[main, 'train/*']"))
        result = self.gates("--train-ref", "train/a/b", "--tests-workflow", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("trigger|missing", result.stdout)
        # Positive controls: the flat name, and `**` for the nested one.
        self.assertIn("trigger|ok", self.gates("--train-ref", "train/a", "--tests-workflow", path).stdout)
        path.write_text(workflow("[main, 'train/**']"))
        result = self.gates("--train-ref", "train/a/b", "--tests-workflow", path)
        self.assertIn("trigger|ok", result.stdout)

    def test_ref_contexts_are_matched_by_name_not_substring(self):
        path = self.tmp / "ci.yml"
        # ref_type only says branch or tag; it is not a ref gate.
        path.write_text(workflow("[main, 'train/**']", "      - if: github.ref_type == 'branch'\n        run: true\n"))
        result = self.gates(path)
        self.assertNotIn("ref|", result.stdout)
        # head_ref is empty on every push, so a job gated on it never runs on a
        # train branch; the gate must report it as a ref condition.
        path.write_text(workflow("[main, 'train/**']", job_if="github.head_ref == 'release'"))
        result = self.gates(path)
        self.assertIn("ref|  job test: github.head_ref == 'release'", result.stdout)

    def test_a_flag_without_its_value_is_a_usage_error(self):
        result = self.gates("--train-ref")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--train-ref needs a value", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_preconditions_refuse_a_single_star_train_trigger(self):
        path = self.tmp / "ci.yml"
        path.write_text(workflow("[main, 'train/*']"))
        result = self.gates("--preconditions", path)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("does not run on train/precondition/probe", result.stdout)

    def test_preconditions_refuse_an_event_gated_step(self):
        path = self.tmp / "ci.yml"
        path.write_text(workflow("[main, 'train/**']", "      - if: github.event_name == 'push'\n        run: true\n"))
        result = self.gates("--preconditions", path)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("path-dependent condition", result.stdout)

    def test_preconditions_allow_only_the_exact_proven_test_output_condition(self):
        path = self.tmp / "ci.yml"
        condition = "needs.plan.outputs.skip-test != 'true'"
        path.write_text(workflow("[main, 'train/**']", job_if=condition))
        result = self.gates("--preconditions", path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for unsafe in [
            condition + " && github.ref == 'refs/heads/main'",
            condition + " || github.event_name == 'push'",
        ]:
            with self.subTest(condition=unsafe):
                path.write_text(workflow("[main, 'train/**']", job_if=unsafe))
                result = self.gates("--preconditions", path)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("path-dependent condition", result.stdout)

    def test_check_train_preconditions_needs_no_pyyaml(self):
        # The checker used to import yaml, which this repository does not
        # depend on. A planted module that refuses to import stands in for a
        # host without PyYAML; the checker must not notice it.
        fake = self.tmp / "pythonpath"
        fake.mkdir()
        (fake / "yaml.py").write_text("raise ImportError('PyYAML is not installed here')\n")
        result = run([SCRIPTS / "check-train-preconditions.sh"], env={"PYTHONPATH": str(fake)}, cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("train preconditions ok:", result.stdout)


# ---------------------------------------------------------------------------
# .github/workflows/ci.yml, the conformance fixtures step
# ---------------------------------------------------------------------------
def load_gates_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("workflow_gates", GATES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def modern_bash() -> str | None:
    """A bash new enough for `mapfile` (4+), which the CI step uses. macOS's
    /bin/bash is 3.2; CI runs on Ubuntu, where /bin/bash qualifies."""
    for candidate in ("/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash"):
        if os.access(candidate, os.X_OK):
            version = run([candidate, "-c", "echo ${BASH_VERSINFO[0]}"]).stdout.strip()
            if version.isdigit() and int(version) >= 4:
                return candidate
    return None


class CiFixtureLoopTests(Scratch):
    def test_every_fixture_runs_after_one_fails(self):
        import json
        bash = modern_bash()
        if bash is None:
            self.skipTest("no bash 4+ on this host to run the CI step (it uses mapfile)")
        document = load_gates_module().parse_workflow(str(REPO / ".github/workflows/ci.yml"))
        steps = document["jobs"]["test"]["steps"]
        script = next(step["run"] for step in steps if step.get("name") == "Conformance fixtures")
        log = self.tmp / "ran.log"
        # The built harness lists three fixtures and fails the middle one.
        harness = write_executable(self.tmp / "harness", f'''#!/bin/sh
case "$*" in
  list) printf 'alpha\\nbravo\\ncharlie\\n';;
  *"--fixture "*) eval "fixture=\\${{$#}}"; echo "$fixture" >> {log}; [ "$fixture" != bravo ];;
esac
''')
        artifact = json.dumps({"reason":"compiler-artifact", "target":{"name":"plexus-conformance"}, "executable":str(harness)})
        write_executable(self.tmp / "bin" / "cargo", f"#!/bin/sh\nprintf '%s\\n' '{artifact}'\n")
        result = run([bash, "-c", script], env={"PATH": f"{self.tmp / 'bin'}:{SYSTEM_PATH}"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(log.read_text().split(), ["alpha", "bravo", "charlie"])
        self.assertIn("failed fixtures: bravo", result.stdout)
        self.assertIn("2 of 3 fixtures passed", result.stdout)



# ---------------------------------------------------------------------------
# scripts/watch-ci.sh and scripts/lib/operator-gh.sh
# ---------------------------------------------------------------------------
class WatchCiTests(Scratch):
    def watch(self, gh_body: str, extra_env: dict, timeout: int = 60):
        bin_dir = self.tmp / "bin"
        write_executable(bin_dir / "gh", gh_body)
        env = {
            "PATH": f"{bin_dir}:{SYSTEM_PATH}",
            "REPO": "owner/name",
            "OPERATOR_GH_FALLBACK_PATHS": "",
            "WATCH_CI_POLL_SLEEP": "0",
            "WATCH_CI_VERDICT_RETRY_SLEEP": "0",
            "TMPDIR": str(self.tmp),
        }
        env.update(extra_env)
        return run(["bash", SCRIPTS / "watch-ci.sh", "12345"], env=env, timeout=timeout)

    def test_a_gh_that_keeps_failing_ends_the_watch(self):
        # Every status poll failing used to read as `poll-error` forever.
        result = self.watch("#!/bin/sh\nexit 1\n", {"WATCH_CI_MAX_POLL_ERRORS": "3"}, timeout=30)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("could not be read 3 times in a row", result.stderr)

    def test_a_run_that_never_finishes_ends_at_the_deadline(self):
        gh = """
        #!/bin/sh
        case "$*" in
          *status*) echo in_progress ;;
          *url*) echo https://example.invalid/run ;;
          *) echo "" ;;
        esac
        """
        started = time.monotonic()
        result = self.watch(gh, {"WATCH_CI_TIMEOUT": "2", "WATCH_CI_POLL_SLEEP": "1"}, timeout=30)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("did not finish within 2s", result.stderr)
        self.assertLess(time.monotonic() - started, 15)

    def test_a_completed_green_run_still_lands(self):
        # Positive control: the bounds must not end a watch that has a verdict.
        gh = """
        #!/bin/sh
        case "$*" in
          *"--json jobs"*) echo "" ;;
          *status*) echo completed ;;
          *conclusion*) echo success ;;
          *url*) echo https://example.invalid/run ;;
          *) echo "" ;;
        esac
        """
        result = self.watch(gh, {"WATCH_CI_MAX_POLL_ERRORS": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CI_DONE run=12345 conclusion=success", result.stdout)

    def test_failed_train_preconditions_are_red_even_when_test_is_skipped(self):
        gh = """
        #!/bin/sh
        case "$*" in
          *"--json jobs"*) echo "Train preconditions|123" ;;
          *status*) echo in_progress ;;
          *url*) echo https://example.invalid/run ;;
          *) echo "" ;;
        esac
        """
        result = self.watch(gh, {"WATCH_CI_MAX_POLL_ERRORS": "1"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CI_EARLY_FAIL job='Train preconditions'", result.stdout)


class OperatorGhTests(Scratch):
    def resolve(self, path_value: str, cwd: Path):
        # The system directories follow the entries under test so the resolver
        # can run its own tools; a host gh there may legitimately be found.
        script = f'PATH="{path_value}:{SYSTEM_PATH}"; source "{SCRIPTS / "lib" / "operator-gh.sh"}" && printf "%s\\n" "$OPERATOR_GH"'
        return run(["/bin/bash", "-c", script], env={"OPERATOR_GH_FALLBACK_PATHS": ""}, cwd=cwd)

    def test_an_empty_path_entry_does_not_select_gh_in_the_current_directory(self):
        checkout = self.tmp / "checkout"
        write_executable(checkout / "gh", "#!/bin/sh\necho planted\n")
        empty = self.tmp / "empty"
        empty.mkdir()
        for path_value in (f":{empty}", f"{empty}::{empty}", f"{empty}:", f".:{empty}"):
            with self.subTest(PATH=path_value):
                result = self.resolve(path_value, checkout)
                chosen = result.stdout.strip()
                self.assertFalse(chosen and not chosen.startswith("/"), f"relative gh chosen: {chosen}")
                self.assertNotIn(str(checkout), chosen)

    def test_an_absolute_entry_still_resolves(self):
        bin_dir = self.tmp / "bin"
        write_executable(bin_dir / "gh", "#!/bin/sh\n")
        result = self.resolve(f":{bin_dir}", self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"{bin_dir}/gh")


# ---------------------------------------------------------------------------
# scripts/verify-deployed-binary.sh
# ---------------------------------------------------------------------------
class VerifyDeployedBinaryTests(Scratch):
    def test_the_inode_check_works_with_the_hosts_stat_and_still_fails_on_a_restage(self):
        if shutil.which("lsof", path=SYSTEM_PATH) is None:
            self.skipTest("lsof is not installed")
        # A short name: Linux truncates the accounting name to 15 characters.
        binary = self.tmp / "vdbprobe"
        codesign = shutil.which("codesign", path=SYSTEM_PATH)
        if codesign:
            # macOS: a copy of sleep, ad-hoc signed because macOS kills a
            # relocated platform binary on launch. copy, not copy2: the system
            # binary's file flags cannot be copied.
            shutil.copy(shutil.which("sleep", path=SYSTEM_PATH), binary)
            run([codesign, "--force", "--sign", "-", binary])
            command = [str(binary), "60"]
        else:
            # Elsewhere sleep may be a multicall binary (coreutils) that refuses
            # to run under another name, so copy this Python interpreter instead.
            shutil.copy(os.path.realpath(sys.executable), binary)
            command = [str(binary), "-c", "import time; print('ready', flush=True); time.sleep(60)"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        if not codesign:
            # Wait until the interpreter is really running the copied file, not
            # merely forked: only then does the process hold the file it is
            # being checked against.
            self.assertEqual(process.stdout.readline().strip(), "ready")
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        deadline = time.monotonic() + 10
        while run(["ps", "-p", str(process.pid)]).returncode != 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        result = run(["sh", SCRIPTS / "verify-deployed-binary.sh", binary])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"OK: pid {process.pid} is executing", result.stdout)
        # Planted control: a restaged file (new inode at the deploy path) while
        # the old process runs must read as a mismatch, or the OK above proves
        # nothing.
        restaged = self.tmp / "restaged"
        shutil.copy(binary, restaged)
        os.replace(restaged, binary)
        result = run(["sh", SCRIPTS / "verify-deployed-binary.sh", binary])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MISMATCH", result.stderr)


# ---------------------------------------------------------------------------
# scripts/train.sh, scripts/train-push.sh, scripts/train-push.local.sh
# ---------------------------------------------------------------------------
class TrainScriptTests(Scratch):
    """Argument handling only: every case here refuses before any network
    call, lock or push."""

    def test_train_sh_works_from_outside_the_repository(self):
        result = run(["bash", SCRIPTS / "train.sh"], cwd=self.tmp, env={"TMPDIR": str(self.tmp)})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("no train name given", result.stderr)

    def test_train_push_refuses_malformed_arguments(self):
        cases = [
            ([], "no train name given"),
            (["-x"], "must not look like a flag"),
            (["name", "--bogus"], "unexpected argument '--bogus'"),
            (["name", "--land", "extra"], "--land does not accept a smoke command"),
            (["name", "--"], "-- given without a smoke command"),
            (["bad..name"], "is not a usable branch name component"),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                result = run(["bash", SCRIPTS / "train-push.sh", *args], env={"TMPDIR": str(self.tmp)})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)

    def test_the_local_preflight_does_not_depend_on_the_working_directory(self):
        script = (
            'say() { printf "say: %s\\n" "$1"; }; '
            'refuse() { printf "refused: %s\\n" "$1"; exit 2; }; '
            f'REPO="{REPO}"; . "{SCRIPTS / "train-push.local.sh"}"; echo preflight-passed'
        )
        result = run(["bash", "-c", script], cwd=self.tmp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("preflight-passed", result.stdout)


# ---------------------------------------------------------------------------
# scripts/check-cortexkit-layout.sh
# ---------------------------------------------------------------------------
LAYOUT_BLOCK = (
    '# CortexKit layout: see WORKSPACE.md "Where files go"\n'
    "/.cortexkit/*\n"
    "!/.cortexkit/release-notes/\n"
    "!/.cortexkit/skills/\n"
    "!/.cortexkit/rules/\n"
    "!/.cortexkit/WORKER.md\n"
)


class CortexkitLayoutTests(Scratch):
    """Each case runs a copy of the script in a scratch repository whose
    .gitignore and index the test controls, so all three exits are reached."""

    def setUp(self) -> None:
        super().setUp()
        if shutil.which("git", path=SYSTEM_PATH) is None:
            self.skipTest("git is not installed")
        self.repo = self.tmp / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        # A developer's global excludes file could ignore .cortexkit/ on its
        # own and hide a missing block, so git reads no user or system config.
        self.env = {"HOME": str(self.tmp), "XDG_CONFIG_HOME": str(self.tmp), "GIT_CONFIG_NOSYSTEM": "1"}
        shutil.copy2(SCRIPTS / "check-cortexkit-layout.sh", self.repo / "scripts")
        self.git("init", "-q")

    def git(self, *args):
        result = run(["git", *args], cwd=self.repo, env=self.env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def write(self, relative: str, text: str = "x\n") -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def check(self):
        return run(["bash", self.repo / "scripts" / "check-cortexkit-layout.sh"], cwd=self.tmp, env=self.env)

    def test_a_clean_tree_with_allowed_files_tracked_passes(self):
        self.write(".gitignore", LAYOUT_BLOCK)
        self.write(".cortexkit/release-notes/v1.md")
        self.write(".cortexkit/WORKER.md")
        self.write(".cortexkit/notes/plan.md")
        self.git("add", ".gitignore", ".cortexkit")
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no disallowed file is tracked", result.stdout)

    def test_a_force_added_internal_file_is_named(self):
        self.write(".gitignore", LAYOUT_BLOCK)
        self.write(".cortexkit/notes/ledger.md")
        self.git("add", ".gitignore")
        self.git("add", "-f", ".cortexkit/notes/ledger.md")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(".cortexkit/notes/ledger.md", result.stderr)

    def test_a_missing_ignore_block_is_blind_not_clean(self):
        # Without the block nothing under .cortexkit/ is ignored, so a tracked
        # internal file would not show up as an ignored one; the script must
        # refuse rather than report a clean tree.
        self.write(".gitignore", "/target\n")
        self.write(".cortexkit/notes/ledger.md")
        self.git("add", ".gitignore", ".cortexkit")
        result = self.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("BLIND", result.stderr)

    def test_a_block_without_its_allow_lines_is_blind(self):
        self.write(".gitignore", "/.cortexkit/\n")
        self.git("add", ".gitignore")
        result = self.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("release-notes", result.stderr)

    def test_an_ignored_worker_guide_is_blind(self):
        self.write(".gitignore", LAYOUT_BLOCK.replace("!/.cortexkit/WORKER.md\n", ""))
        result = self.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("WORKER.md", result.stderr)
