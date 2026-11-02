"""SYCUR GitHub PR Conversation comment publisher."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

from sycur_rag.github.app_auth import (
    create_installation_access_token,
)
from sycur_rag.github.check_publisher import (
    build_check_run_failure_payload,
    build_check_run_payload,
    build_check_run_progress_payload,
    build_review_external_id,
)
from sycur_rag.models.review import ReviewResult


API_URL = "https://api.github.com"


def _request_json(
    url: str,
    token: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }

    data = None

    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    request = Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    with urlopen(request, timeout=20) as response:
        return json.load(response)


def _safe_scanner_events(events):
    """Never publish raw scanner exception messages."""
    if events is None:
        return None

    return [
        {**event, "error_message": None}
        for event in events
    ]


def build_conversation_comment(
    *,
    repository: str,
    pr_number: int,
    head_sha: str,
    stage: str | None = None,
    review: ReviewResult | None = None,
    failure_type: str | None = None,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> str:
    """Render one developer-facing PR Conversation comment."""

    build_review_external_id(
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
    )

    supplied_modes = sum(
        item is not None
        for item in (stage, review, failure_type)
    )

    if supplied_modes != 1:
        raise ValueError(
            "Exactly one conversation review mode is required."
        )

    scanner_events = _safe_scanner_events(scanner_events)

    if failure_type is not None:
        payload = build_check_run_failure_payload(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            error_type=failure_type,
            scanner_events=scanner_events,
            stage_events=stage_events,
            total_duration_ms=total_duration_ms,
        )
        state = "EXECUTION FAILED"

    elif review is not None:
        payload = build_check_run_payload(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            review=review,
            scanner_events=scanner_events,
            stage_events=stage_events,
            total_duration_ms=total_duration_ms,
        )
        state = "FINAL"

    else:
        payload = build_check_run_progress_payload(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            stage=stage,
            scanner_events=scanner_events,
            stage_events=stage_events,
            total_duration_ms=total_duration_ms,
        )
        state = "SCANNING"

    marker = f"<!-- sycur:pr-review:{head_sha.lower()} -->"
    summary = payload["output"]["summary"]

    checks_url = (
        f"https://github.com/{repository}"
        f"/pull/{pr_number}/checks"
    )

    body = (
        f"{marker}\n"
        f"**Review state:** {state}\n\n"
        f"{summary}\n\n"
        f"[View detailed GitHub Checks]({checks_url})\n\n"
        f"---\n"
        f"*SYCUR automated security intelligence · "
        f"Commit `{head_sha[:12]}`*"
    )

    if len(body) > 60000:
        body = (
            f"{marker}\n"
            f"## TMT | SYCUR\n\n"
            f"**Review state:** {state}\n\n"
            "The security report exceeds the Conversation "
            "preview limit. See the detailed GitHub Check.\n\n"
            f"[View detailed GitHub Checks]({checks_url})"
        )

    return body


def upsert_conversation_comment(
    *,
    repository: str,
    installation_id: int,
    pr_number: int,
    head_sha: str,
    body: str,
) -> dict:
    """Create or update the same bot comment for a PR head."""

    build_review_external_id(
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
    )

    if type(installation_id) is not int or installation_id < 1:
        raise ValueError("Invalid installation ID.")

    if not isinstance(body, str) or not body.strip():
        raise ValueError("Conversation comment cannot be empty.")

    marker = f"<!-- sycur:pr-review:{head_sha.lower()} -->"

    if not body.startswith(marker + "\n"):
        raise ValueError("Missing SYCUR comment identity.")

    token = create_installation_access_token(
        installation_id=installation_id,
        repository_full_name=repository,
    )

    endpoint = (
        f"{API_URL}/repos/{repository}"
        f"/issues/{pr_number}/comments"
    )

    existing = None

    for page in range(1, 21):
        comments = _request_json(
            f"{endpoint}?per_page=100&page={page}",
            token,
        )

        if not isinstance(comments, list):
            raise RuntimeError(
                "Invalid GitHub conversation response."
            )

        for comment in comments:
            comment_body = comment.get("body") or ""
            author = comment.get("user") or {}

            # Never edit an ordinary developer's comment.
            if author.get("type") != "Bot":
                continue

            if comment_body.startswith(marker + "\n"):
                existing = comment
                break

        if existing is not None or len(comments) < 100:
            break
    else:
        raise RuntimeError(
            "Conversation history exceeds the safe search limit."
        )

    if existing is not None:
        if existing.get("body") == body:
            return existing

        comment_id = existing["id"]

        if type(comment_id) is not int:
            raise RuntimeError("Invalid GitHub comment ID.")

        # PATCH updates the existing comment; no new timeline item.
        return _request_json(
            f"{API_URL}/repos/{repository}"
            f"/issues/comments/{comment_id}",
            token,
            method="PATCH",
            payload={"body": body},
        )

    # POST only once when this commit has no SYCUR comment.
    return _request_json(
        endpoint,
        token,
        method="POST",
        payload={"body": body},
    )
