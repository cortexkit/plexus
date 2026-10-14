#!/usr/bin/env python3
# Maintainer landing-policy helper; outside contributors need only the test gate.
"""Report the parts of a GitHub Actions workflow that decide whether a train's
CI run means anything.

train-push.sh calls this before pushing a train, and
scripts/check-train-preconditions.sh (CI's first step, and a train preflight)
calls its --preconditions mode. Both read the workflow through the one parser
and the one condition classifier below, so the two gates cannot disagree about
what a workflow file says. Two questions are answered:

  1. does `on.push.branches` match the train branch about to be pushed, and
  2. which job-level and step-level `if:` conditions gate on something the
     landing path never satisfies.

Both answers have to come from the parsed document rather than from matching
lines. `if:` is very often written as a folded scalar:

    if: >-
      github.ref == 'refs/heads/main'

so a line-oriented search for `if:.*github.ref` finds nothing on exactly the
workflows whose behaviour depends on the ref - the ones this check exists for.
The same goes for a `branches:` list written in flow style.

PyYAML is not a dependency of this repository and a gate that behaves
differently depending on whether it happens to be installed is worse than no
gate, so the block/flow subset that workflow files actually use is parsed here.

Output is one record per line for the shell to consume:

    trigger|ok                      the push trigger matches the train ref
    trigger|missing                 it does not (no push trigger, or no match)
    ref|<text>                      a finding that refuses the push
    warn|<text>                     a finding that is reported and no more

Usage:
  workflow-gates.py --train-ref train/foo --tests-workflow FILE WORKFLOW...
  workflow-gates.py --preconditions FILE

--preconditions asserts the facts the train flow depends on and exits 1 naming
each one that no longer holds: the push trigger runs on train branches
(including nested names such as train/a/b) and on main, no job or step `if:`
changes the gates between train and main pushes, and the concurrency group is
per-ref. The planner-driven mutation job explicitly excludes PR events.
"""

from __future__ import annotations

import re
import sys
from typing import Any

BLOCK_SCALAR_HEADS = ("|", ">", "|-", ">-", "|+", ">+")


# --------------------------------------------------------------------------
# A parser for the YAML subset workflow files are written in: block mappings,
# block sequences, flow sequences, quoted and plain scalars, and block scalars.
# --------------------------------------------------------------------------
def _strip_comment(text: str) -> str:
    """Drop a trailing comment, ignoring '#' inside quoted strings."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i]
    return text


def _split_key(text: str) -> tuple[str, str] | None:
    """Split 'key: value' at the first colon that is not inside quotes."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1 :].strip()
    return None


def _scalar(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _flow_sequence(text: str) -> list[str]:
    inner = text.strip()[1:-1]
    return [_scalar(part) for part in inner.split(",") if part.strip()]


class _Reader:
    def __init__(self, source: str) -> None:
        self.lines = source.splitlines()
        self.i = 0

    def indent(self, index: int) -> int:
        line = self.lines[index]
        return len(line) - len(line.lstrip(" "))

    def skip_blanks(self) -> None:
        while self.i < len(self.lines):
            stripped = _strip_comment(self.lines[self.i]).strip()
            if stripped:
                return
            self.i += 1

    def at_end(self) -> bool:
        self.skip_blanks()
        return self.i >= len(self.lines)

    def block_scalar(self, head: str, parent_indent: int) -> str:
        """Collect the lines of a `|`/`>` scalar and fold them like YAML does."""
        collected: list[str] = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if not line.strip():
                collected.append("")
                self.i += 1
                continue
            if self.indent(self.i) <= parent_indent:
                break
            collected.append(line.strip())
            self.i += 1
        if head.startswith(">"):
            return " ".join(part for part in collected if part)
        return "\n".join(collected)

    def parse(self, indent: int) -> Any:
        if self.at_end():
            return None
        if _strip_comment(self.lines[self.i]).strip().startswith("- "):
            return self.parse_sequence(indent)
        if _strip_comment(self.lines[self.i]).strip() == "-":
            return self.parse_sequence(indent)
        return self.parse_mapping(indent)

    def parse_sequence(self, indent: int) -> list[Any]:
        items: list[Any] = []
        while not self.at_end():
            if self.indent(self.i) != indent:
                break
            content = _strip_comment(self.lines[self.i]).strip()
            if not content.startswith("-"):
                break
            rest = content[1:].strip()
            item_indent = self.indent(self.i) + (len(content) - len(content[1:].lstrip()))
            if not rest:
                self.i += 1
                items.append(self.parse(indent + 2) if not self.at_end() else None)
                continue
            pair = _split_key(rest)
            if pair is None:
                items.append(_scalar(rest))
                self.i += 1
                continue
            # `- key: value` starts a mapping whose keys line up after the dash.
            self.lines[self.i] = " " * item_indent + rest
            items.append(self.parse_mapping(item_indent))
        return items

    def parse_mapping(self, indent: int) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        while not self.at_end():
            if self.indent(self.i) != indent:
                break
            content = _strip_comment(self.lines[self.i]).strip()
            if content.startswith("- "):
                break
            pair = _split_key(content)
            if pair is None:
                self.i += 1
                continue
            key, value = pair
            key = _scalar(key)
            self.i += 1
            if value in BLOCK_SCALAR_HEADS:
                mapping[key] = self.block_scalar(value, indent)
            elif value.startswith("[") and value.endswith("]"):
                mapping[key] = _flow_sequence(value)
            elif value:
                mapping[key] = _scalar(value)
            elif self.at_end() or self.indent(self.i) <= indent:
                mapping[key] = None
            else:
                mapping[key] = self.parse(self.indent(self.i))
        return mapping


def parse_workflow(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        document = _Reader(handle.read()).parse(0)
    return document if isinstance(document, dict) else {}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def on_section(workflow: dict[str, Any]) -> Any:
    # `on` is also YAML's boolean true, which some parsers hand back as a
    # different key; accept both spellings rather than silently reading nothing.
    for key in ("on", True, "true", "True"):
        if key in workflow:
            return workflow[key]
    return None


def trigger_summary(workflow: dict[str, Any]) -> str:
    section = on_section(workflow)
    if section is None:
        return "?"
    if isinstance(section, str):
        return section
    if isinstance(section, list):
        return ", ".join(section)

    parts = []
    for event, body in section.items():
        detail = ""
        if isinstance(body, dict):
            branches = as_list(body.get("branches"))
            tags = as_list(body.get("tags"))
            if branches:
                detail = "branches: " + ", ".join(branches)
            if tags:
                detail = (detail + "; " if detail else "") + "tags: " + ", ".join(tags)
        if not detail and event in ("push", "pull_request"):
            detail = "branches: all"
        parts.append(f"{event} ({detail})" if detail else event)
    return ", ".join(parts) or "?"


def push_matches(workflow: dict[str, Any], train_ref: str) -> bool:
    section = on_section(workflow)
    if isinstance(section, str):
        return section.strip() == "push"
    if isinstance(section, list):
        return "push" in section
    if not isinstance(section, dict) or "push" not in section:
        return False
    body = section["push"]
    if not isinstance(body, dict):
        # `push:` with nothing under it triggers on every branch.
        return True
    branches = as_list(body.get("branches"))
    if not branches:
        # A push trigger with no branches list runs on every branch. A
        # branches-ignore list is a filter we do not interpret; treat it as a
        # match and let the trigger probe be the judge.
        return True
    return branch_patterns_include(train_ref, branches)


def github_glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a GitHub Actions branch filter pattern.

    GitHub's filter syntax is not fnmatch: `*` matches any run of characters
    EXCEPT `/`, `**` matches any run including `/`, `?` makes the preceding
    character optional, `+` repeats the preceding character, and `[...]` is a
    character class. fnmatch lets `*` cross `/`, so under it `train/*` approved
    a train named `train/a/b` that GitHub never builds - the gate passed and no
    CI run ever arrived.
    """
    atoms: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                atoms.append(".*")
                i += 2
            else:
                atoms.append("[^/]*")
                i += 1
            continue
        if ch in "?+" and atoms:
            atoms[-1] = f"(?:{atoms[-1]}){ch}"
            i += 1
            continue
        if ch == "[":
            close = pattern.find("]", i + 1)
            if close > i + 1:
                body = pattern[i + 1 : close].replace("\\", "\\\\")
                atoms.append(f"[{body}]")
                i = close + 1
                continue
        if ch == "\\" and i + 1 < len(pattern):
            atoms.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        atoms.append(re.escape(ch))
        i += 1
    return re.compile("".join(atoms) + r"\Z")


def github_glob_match(ref: str, pattern: str) -> bool:
    return github_glob_regex(pattern).match(ref) is not None


def branch_patterns_include(ref: str, patterns: list[str]) -> bool:
    """Evaluate a GitHub `branches:` list the way GitHub does: in order, a
    positive pattern includes the ref, a later `!` pattern excludes it, and a
    later positive pattern re-includes it. `any()` over the positives approved
    branches GitHub would never build (for example `train/**` followed by
    `!train/blocked/**`), and the trigger probe cannot catch that because its
    own ref is one the list legitimately includes."""
    included = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if github_glob_match(ref, pattern[1:]):
                included = False
        elif github_glob_match(ref, pattern):
            included = True
    return included


def step_label(step: Any) -> str:
    if not isinstance(step, dict):
        return ""
    for key in ("name", "id", "uses", "run"):
        value = step.get(key)
        if isinstance(value, str) and value.strip():
            label = value.strip().splitlines()[0]
            return label if len(label) <= 48 else label[:45] + "..."
    return ""


# Contexts whose value names the branch. Matched as whole context names, not
# as a substring: "github.ref" is a prefix of github.ref_type, which says only
# "branch" or "tag", and a substring test also never sees github.head_ref,
# which is EMPTY on every push event - so a step gated on it is dead under
# trains exactly like one gated on refs/heads/main.
REF_CONTEXT = re.compile(r"\bgithub\.(?:ref|ref_name|head_ref)\b")
# Contexts that depend on how the run was started rather than on which branch.
LANDING_CONTEXT = re.compile(r"\bgithub\.(?:ref_type|event_name)\b|\bevent_name\s*==")
# A concurrency group is per-ref only if it names the pushed ref itself.
PER_REF_GROUP = re.compile(r"\bgithub\.(?:ref|ref_name)\b")


def classify(condition: str) -> str | None:
    """ref = provably dead under trains, warn = depends on the landing path."""
    # This exact planner-driven exclusion treats train and main pushes alike.
    # Do not allow arbitrary event expressions: an OR or a ref clause could
    # silently skip a gate that the landing flow relies on.
    if condition == "github.event_name != 'pull_request' && needs.test.outputs.has-mutations == 'true'":
        return None
    if REF_CONTEXT.search(condition):
        if "train/" in condition:
            return None
        tag_only = "refs/tags/" in condition and "refs/heads/" not in condition
        if tag_only and "ref_name" not in condition:
            # A tag gate belongs to the release event, not to the landing path,
            # and widening it to train branches would be wrong.
            return "warn"
        return "ref"
    if LANDING_CONTEXT.search(condition):
        return "warn"
    return None


def concurrency_group(workflow: dict[str, Any]) -> str:
    concurrency = workflow.get("concurrency")
    if isinstance(concurrency, dict):
        return str(concurrency.get("group") or "")
    if isinstance(concurrency, str):
        return concurrency
    return ""


def condition_findings(workflow: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Every job- and step-level `if:` that classify() flags, as (refs, warns)."""
    refs: list[str] = []
    warns: list[str] = []
    jobs = workflow.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            entries = [("", job.get("if"))]
            steps = job.get("steps")
            if isinstance(steps, list):
                entries += [(step_label(s), s.get("if")) for s in steps if isinstance(s, dict)]
            for label, condition in entries:
                if not isinstance(condition, str) or not condition.strip():
                    continue
                condition = " ".join(condition.split())
                kind = classify(condition)
                if kind is None:
                    continue
                where = f"  job {job_id}"
                if label:
                    where += f", step {label}"
                (refs if kind == "ref" else warns).append(f"{where}: {condition}")
    return refs, warns


def scan(path: str) -> tuple[list[str], list[str], str]:
    workflow = parse_workflow(path)

    refs, warns = condition_findings(workflow)
    group = concurrency_group(workflow)
    if group and not PER_REF_GROUP.search(group):
        # A group shared across refs cancels in-flight runs of other refs, so
        # pushing a train would kill a running default-branch run.
        warns.insert(0, f"  concurrency group is not per-ref: {group}")

    header = f"{path} [on: {trigger_summary(workflow)}]"
    header += f" [concurrency: {group}]" if group else " [concurrency: none]"
    return refs, warns, header


# Train refs the push trigger must match. The nested one is deliberate: a train
# name may contain '/', and a `train/*` filter matches `train/foo` but not
# `train/foo/bar`, while `train/**` matches both.
PRECONDITION_TRAIN_REFS = ("train/precondition-probe", "train/precondition/probe")


def precondition_failures(workflow: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    section = on_section(workflow)
    push = section.get("push") if isinstance(section, dict) else None
    branches = as_list(push.get("branches")) if isinstance(push, dict) else []

    # Arm 1: a train push must produce a check at all. Without this trigger,
    # enabling required status checks would make main unpushable with no check
    # ever arriving.
    for ref in PRECONDITION_TRAIN_REFS:
        if not push_matches(workflow, ref):
            failures.append(f"push trigger does not run on {ref} (has: {branches})")

    # The default branch must also stay in the trigger while this repo is
    # unprotected: its push run is the only observer of an off-train push, so a
    # workflow gone train-only silently loses the last thing watching main.
    if not push_matches(workflow, "main"):
        failures.append(
            f"push trigger no longer includes main (has: {branches}) - while "
            "unprotected, the main run is the only observer of an off-train push"
        )

    # Arm 2: a workflow can fire on a train push while a job or step gated on
    # the ref, or on the event that started the run, is skipped - and the run
    # still reports green, so the gate everyone relies on is silently absent.
    # Such conditions fail here except the exact planner-driven PR exclusion,
    # which cannot distinguish a train push from a main push. This is stricter than the scan
    # train-push.sh runs before each push (main() below without
    # --preconditions), which only warns on event conditions, because CI and
    # the preflight must keep train and main runs identical.
    refs, warns = condition_findings(workflow)
    for finding in refs + warns:
        failures.append(f"path-dependent condition: {finding.strip()}")

    # Arm 3: a concurrency group without the ref makes a train push cancel an
    # in-flight main run - the train flow DDoSes its own default branch.
    group = concurrency_group(workflow)
    if not PER_REF_GROUP.search(group):
        failures.append(f"concurrency group does not key on github.ref: {group!r}")
    return failures


def precondition_controls() -> list[str]:
    """Planted inputs whose verdicts are known, run before every real check.

    A checker that has stopped seeing anything reports a clean workflow, so each
    arm must first be shown to fail on a planted bad shape and pass on a good one.
    """
    problems: list[str] = []
    good = {
        "on": {"push": {"branches": ["main", "train/**"]}},
        "concurrency": {"group": "ci-${{ github.ref }}"},
        "jobs": {"test": {"steps": [{"run": "true"}]}},
    }
    if precondition_failures(good):
        problems.append(f"a known-good workflow was refused: {precondition_failures(good)}")
    single_star = dict(good, on={"push": {"branches": ["main", "train/*"]}})
    if not any("train/precondition/probe" in f for f in precondition_failures(single_star)):
        problems.append("`train/*` was read as admitting the nested train ref")
    ref_gated = dict(good, jobs={"test": {"steps": [{"if": "github.ref == 'refs/heads/main'"}]}})
    if not any("path-dependent" in f for f in precondition_failures(ref_gated)):
        problems.append("a step gated on github.ref was not flagged")
    head_ref_gated = dict(good, jobs={"test": {"if": "github.head_ref != ''"}})
    if not any("path-dependent" in f for f in precondition_failures(head_ref_gated)):
        problems.append("a job gated on github.head_ref was not flagged")
    shared_group = dict(good, concurrency={"group": "ci-${{ github.ref_type }}"})
    if not any("concurrency" in f for f in precondition_failures(shared_group)):
        problems.append("a concurrency group keyed on github.ref_type was read as per-ref")
    return problems


def check_preconditions(path: str) -> int:
    problems = precondition_controls()
    if problems:
        for problem in problems:
            print(f"train-precondition FAILED: control: {problem}")
        return 1
    try:
        workflow = parse_workflow(path)
    except OSError as error:
        print(f"train-precondition FAILED: cannot read {path}: {error}")
        return 1
    failures = precondition_failures(workflow)
    # Name what was examined, never just a verdict: a parse that silently found
    # zero jobs produces the same clean silence as a healthy workflow.
    jobs = workflow.get("jobs")
    job_count = len(jobs) if isinstance(jobs, dict) else 0
    if job_count == 0:
        failures.append("parsed zero jobs - wrong file or shape")
    if failures:
        for failure in failures:
            print(f"train-precondition FAILED: {failure}")
        return 1
    section = on_section(workflow)
    push = section.get("push") if isinstance(section, dict) else None
    branches = as_list(push.get("branches")) if isinstance(push, dict) else []
    print(
        f"train preconditions ok: branches={branches} jobs={job_count} "
        f"group={concurrency_group(workflow)!r}"
    )
    return 0


USAGE = (
    "usage: workflow-gates.py --train-ref REF --tests-workflow FILE WORKFLOW...\n"
    "       workflow-gates.py --preconditions FILE"
)


def main(argv: list[str]) -> int:
    train_ref = ""
    tests_workflow = ""
    preconditions = ""
    workflows: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] in ("--train-ref", "--tests-workflow", "--preconditions"):
            # A flag with its value missing is a usage error with a name, not a
            # traceback - the caller reports this script's exit status.
            if i + 1 >= len(argv):
                print(f"workflow-gates.py: {argv[i]} needs a value\n{USAGE}", file=sys.stderr)
                return 2
            value = argv[i + 1]
            if argv[i] == "--train-ref":
                train_ref = value
            elif argv[i] == "--tests-workflow":
                tests_workflow = value
            else:
                preconditions = value
            i += 2
        else:
            workflows.append(argv[i])
            i += 1

    if preconditions:
        if train_ref or tests_workflow or workflows:
            print(f"workflow-gates.py: --preconditions takes only its file\n{USAGE}", file=sys.stderr)
            return 2
        return check_preconditions(preconditions)

    if tests_workflow:
        try:
            matched = push_matches(parse_workflow(tests_workflow), train_ref)
        except OSError:
            matched = False
        print("trigger|ok" if matched else "trigger|missing")

    for path in workflows:
        try:
            refs, warns, header = scan(path)
        except OSError:
            continue
        for kind, findings in (("ref", refs), ("warn", warns)):
            if not findings:
                continue
            print(f"{kind}|{header}")
            for finding in findings:
                print(f"{kind}|{finding}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
