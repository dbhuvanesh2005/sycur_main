import json
import os
import sqlite3
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status

from sycur_rag.core.config import get_settings
from sycur_rag.github.pr_event import ValidatedPREvent
from sycur_rag.github.review_queue import enqueue_review_job
from sycur_rag.github.webhook_security import verify_github_signature

router = APIRouter()


@router.post("/webhooks/github")
async def receive_github_webhook(request: Request):
    payload = await request.body()

    signature = request.headers.get("X-Hub-Signature-256")

    settings = get_settings()

    is_valid = verify_github_signature(
        payload=payload,
        signature=signature,
        secret=settings.GITHUB_WEBHOOK_SECRET.get_secret_value(),
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        event = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )

    if not isinstance(event, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook payload must be a JSON object",
        )

    github_event = request.headers.get("X-GitHub-Event")

    if github_event != "pull_request":
        return {
            "status": "ignored",
            "reason": "Unsupported GitHub event",
        }

    supported_actions = {"opened", "synchronize", "reopened"}
    action = event.get("action")

    if action not in supported_actions:
        return {
            "status": "ignored",
            "reason": "Unsupported pull request action",
        }

    repository = event.get("repository")
    pull_request = event.get("pull_request")
    installation = event.get("installation")

    if not all(
        isinstance(item, dict)
        for item in (repository, pull_request, installation)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or invalid PR metadata",
        )

    repository_name = repository.get("full_name")
    pr_number = pull_request.get("number")
    head = pull_request.get("head")
    installation_id = installation.get("id")

    if not isinstance(head, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or invalid PR metadata",
        )

    head_sha = head.get("sha")

    if not (
        isinstance(repository_name, str)
        and repository_name.strip()
        and isinstance(pr_number, int)
        and not isinstance(pr_number, bool)
        and pr_number > 0
        and isinstance(head_sha, str)
        and len(head_sha) == 40
        and all(c in "0123456789abcdefABCDEF" for c in head_sha)
        and isinstance(installation_id, int)
        and not isinstance(installation_id, bool)
        and installation_id > 0
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or invalid PR metadata",
        )

    delivery_id = request.headers.get("X-GitHub-Delivery")

    try:
        if not delivery_id:
            raise ValueError("Missing delivery ID")
        uuid.UUID(delivery_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or invalid GitHub delivery ID",
        )

    validated_pr_event = ValidatedPREvent(
        delivery_id=delivery_id,
        installation_id=installation_id,
        repository=repository_name,
        pr_number=pr_number,
        head_sha=head_sha,
        action=action,
    )

    default_db_path = (
        Path.home()
        / ".local"
        / "share"
        / "sycur"
        / "review_jobs.db"
    )
    db_path = Path(
        os.environ.get(
            "SYCUR_REVIEW_QUEUE_DB",
            str(default_db_path),
        )
    ).expanduser()

    try:
        inserted = enqueue_review_job(
            event=validated_pr_event,
            db_path=db_path,
        )
    except (sqlite3.Error, OSError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to persist review job",
        ) from exc

    return {
        "status": "queued" if inserted else "duplicate",
    }
