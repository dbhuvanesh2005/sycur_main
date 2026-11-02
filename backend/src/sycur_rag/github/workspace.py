from __future__ import annotations

import base64
import os
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sycur_rag.github.pull_request import (
    GitHubPullRequestMetadata,
)


def _run_git(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "Unknown git error."
        )

        raise RuntimeError(
            f"Git command failed: {message}"
        )

    return result.stdout.strip()


def _git_environment(
    *,
    token: str,
) -> dict[str, str]:
    if not isinstance(
        token,
        str,
    ):
        raise TypeError(
            "GitHub token must be a string."
        )

    cleaned_token = token.strip()

    if not cleaned_token:
        raise ValueError(
            "GitHub token cannot be empty."
        )

    credentials = (
        f"x-access-token:{cleaned_token}"
    )

    encoded = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("ascii")

    env = os.environ.copy()

    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": (
                "http.extraHeader"
            ),
            "GIT_CONFIG_VALUE_0": (
                f"Authorization: Basic {encoded}"
            ),
            "GIT_CONFIG_KEY_1": (
                "credential.helper"
            ),
            "GIT_CONFIG_VALUE_1": "",
        }
    )

    return env


@contextmanager
def github_pull_request_workspace(
    *,
    metadata: GitHubPullRequestMetadata,
    token: str,
) -> Iterator[Path]:
    """
    Create a temporary checkout containing
    the exact GitHub pull-request head commit.

    The workspace is automatically deleted
    when the context exits.
    """

    if not isinstance(
        metadata,
        GitHubPullRequestMetadata,
    ):
        raise TypeError(
            "metadata must be "
            "GitHubPullRequestMetadata."
        )

    env = _git_environment(
        token=token,
    )

    repository_url = (
        "https://github.com/"
        f"{metadata.repository}.git"
    )

    pull_ref = (
        "refs/pull/"
        f"{metadata.pull_request_number}"
        "/head"
    )

    with tempfile.TemporaryDirectory(
        prefix="sycur-github-pr-"
    ) as temp:
        workspace = Path(temp)

        _run_git(
            ["init", "--quiet"],
            cwd=workspace,
            env=env,
        )

        _run_git(
            [
                "remote",
                "add",
                "origin",
                repository_url,
            ],
            cwd=workspace,
            env=env,
        )

        _run_git(
            [
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "origin",
                pull_ref,
            ],
            cwd=workspace,
            env=env,
        )

        fetched_sha = _run_git(
            [
                "rev-parse",
                "FETCH_HEAD",
            ],
            cwd=workspace,
            env=env,
        )

        if (
            fetched_sha.casefold()
            != metadata.head_sha.casefold()
        ):
            raise RuntimeError(
                "Fetched GitHub PR commit "
                "does not match the expected "
                "head SHA."
            )

        _run_git(
            [
                "checkout",
                "--quiet",
                "--detach",
                fetched_sha,
            ],
            cwd=workspace,
            env=env,
        )

        checked_out_sha = _run_git(
            [
                "rev-parse",
                "HEAD",
            ],
            cwd=workspace,
            env=env,
        )

        if (
            checked_out_sha.casefold()
            != metadata.head_sha.casefold()
        ):
            raise RuntimeError(
                "Checked-out GitHub PR commit "
                "does not match the expected "
                "head SHA."
            )

        yield workspace