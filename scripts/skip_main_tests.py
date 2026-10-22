#!/usr/bin/env python3
"""Skip duplicate main checks only after the same sha passed on a train ref."""

import json
import os
import sys
from urllib.parse import urlencode
from urllib.request import Request, urlopen

WORKFLOW_PATH = ".github/workflows/ci.yml"
PAGE_SIZE = 100


def has_successful_train_run(repository, sha, token, opener=None):
    """Return whether this workflow has a successful run for sha on a train ref."""
    if not token:
        raise RuntimeError("the read-only GitHub token is unavailable")
    opener = opener or urlopen
    page = 1
    while True:
        query = urlencode({"head_sha": sha, "per_page": PAGE_SIZE, "page": page})
        request = Request(
            f"https://api.github.com/repos/{repository}/actions/runs?{query}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "plexus-ci",
            },
        )
        with opener(request, timeout=10) as response:
            payload = json.load(response)
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise ValueError("GitHub Actions API response has no workflow_runs list")
        for run in runs:
            if (run.get("path") == WORKFLOW_PATH
                    and run.get("event") == "push"
                    and run.get("head_sha") == sha
                    and run.get("head_branch", "").startswith("train/")
                    and run.get("conclusion") == "success"):
                return True
        if len(runs) < PAGE_SIZE:
            return False
        page += 1


def should_skip_tests(event, ref, repository, sha, token, opener=None):
    """Fail safe: only verified main pushes skip; lookup errors run full CI."""
    if event != "push" or ref != "refs/heads/main":
        return False
    try:
        return has_successful_train_run(repository, sha, token, opener=opener)
    except Exception as error:
        print(
            f"::warning::Could not verify a successful train run for {sha}; "
            f"running full CI ({type(error).__name__}: {error})",
            file=sys.stderr,
        )
        return False


def main():
    skip = should_skip_tests(
        os.environ.get("GITHUB_EVENT_NAME", ""),
        os.environ.get("GITHUB_REF", ""),
        os.environ.get("GITHUB_REPOSITORY", ""),
        os.environ.get("GITHUB_SHA", ""),
        os.environ.get("GH_TOKEN", ""),
    )
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"skip-test={str(skip).lower()}\n")
    print(f"skip-test={str(skip).lower()}")


if __name__ == "__main__":
    main()
