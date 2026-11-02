from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

from sycur_rag.core.config import get_settings
from sycur_rag.github.app_auth import (
    create_installation_access_token,
)
from sycur_rag.github.check_publisher import (
    publish_github_check_failure,
    publish_github_check_progress,
    publish_github_check_run,
)
from sycur_rag.github.conversation_publisher import (
    build_conversation_comment,
    upsert_conversation_comment,
)
from sycur_rag.github.client import GitHubClient
from sycur_rag.github.pr_review_handler import review_github_pr_job
from sycur_rag.github.pull_request import (
    parse_github_rest_pull_request_metadata,
)
from sycur_rag.github.review_queue import recover_expired_review_jobs
from sycur_rag.github.review_queue import requeue_due_failed_review_jobs
from sycur_rag.github.review_worker import run_next_review_job
from sycur_rag.models.review import ReviewResult


logger = logging.getLogger(__name__)


def review_github_pr_for_worker(job: dict) -> ReviewResult:
    """Scan the PR and validate its latest commit."""

    review = review_github_pr_job(job)

    # Recheck the live PR after scanning.
    token = create_installation_access_token(
        installation_id=job["installation_id"],
        repository_full_name=job["repository"],
    )

    client = GitHubClient(token=token)

    latest_pr = client.get_pull_request(
        repository=job["repository"],
        pull_request_number=job["pr_number"],
    )

    latest_metadata = (
        parse_github_rest_pull_request_metadata(latest_pr)
    )

    if (
        latest_pr.get("state") != "open"
        or latest_metadata.head_sha.lower()
        != job["head_sha"].lower()
    ):
        raise RuntimeError(
            "PR changed or closed during review; "
            "GitHub Check publishing cancelled."
        )

    return review


def publish_review_conversation_to_github(
    job: dict,
    *,
    stage: str | None = None,
    review: ReviewResult | None = None,
    failure_type: str | None = None,
) -> None:
    """Update the single SYCUR PR Conversation comment."""

    try:
        body = build_conversation_comment(
            repository=job["repository"],
            pr_number=job["pr_number"],
            head_sha=job["head_sha"],
            stage=stage,
            review=review,
            failure_type=failure_type,
            scanner_events=job.get("_scanner_events"),
            stage_events=job.get("_stage_events"),
            total_duration_ms=job.get("_total_duration_ms"),
        )

        result = upsert_conversation_comment(
            repository=job["repository"],
            installation_id=job["installation_id"],
            pr_number=job["pr_number"],
            head_sha=job["head_sha"],
            body=body,
        )

        logger.info(
            "SYCUR PR Conversation updated: %s",
            result.get("html_url", "no URL returned"),
        )

    except Exception:
        # A GitHub comment failure must never change
        # the security verdict or break the scanner pipeline.
        logger.warning(
            "SYCUR PR Conversation publishing failed "
            "for %s PR #%s.",
            job["repository"],
            job["pr_number"],
            exc_info=True,
        )


def publish_review_progress_to_github(
    job: dict,
    stage: str,
) -> None:
    """Publish review progress to the existing GitHub Check Run."""

    published = publish_github_check_progress(
        repository=job["repository"],
        installation_id=job["installation_id"],
        head_sha=job["head_sha"],
        pr_number=job["pr_number"],
        stage=stage,
        scanner_events=job.get("_scanner_events"),
        stage_events=job.get("_stage_events"),
        total_duration_ms=job.get("_total_duration_ms"),
    )

    print(
        f"SYCUR REVIEW PROGRESS: {stage} "
        f"| {published['html_url']}",
        flush=True,
    )

    publish_review_conversation_to_github(
        job,
        stage=stage,
    )


def publish_review_report_to_github(
    job: dict,
    review: ReviewResult,
    report_token: str,
) -> None:
    """Publish the Check Run with the SYCUR report URL."""

    base_url = get_settings().SYCUR_PUBLIC_BASE_URL

    if not base_url or not base_url.startswith("https://"):
        raise RuntimeError(
            "A valid HTTPS SYCUR public URL is required."
        )

    details_url = (
        f"{base_url.rstrip('/')}/reports/{report_token}"
    )

    published = publish_github_check_run(
        repository=job["repository"],
        installation_id=job["installation_id"],
        head_sha=job["head_sha"],
        review=review,
        pr_number=job["pr_number"],
        details_url=details_url,
        scanner_events=job.get("_scanner_events"),
        stage_events=job.get("_stage_events"),
        total_duration_ms=job.get("_total_duration_ms"),
    )

    print(
        f"SYCUR GITHUB CHECK: {published['html_url']}",
        flush=True,
    )

    publish_review_conversation_to_github(
        job,
        review=review,
    )


def publish_review_failure_to_github(
    job: dict,
    error: Exception,
) -> None:
    """Publish a terminal GitHub Check Run on execution failure."""

    published = publish_github_check_failure(
        repository=job["repository"],
        installation_id=job["installation_id"],
        head_sha=job["head_sha"],
        pr_number=job["pr_number"],
        error_type=type(error).__name__,
        scanner_events=job.get("_scanner_events"),
        stage_events=job.get("_stage_events"),
        total_duration_ms=job.get("_total_duration_ms"),
    )

    print(
        "SYCUR GITHUB EXECUTION FAILURE: "
        f"{published['html_url']}",
        flush=True,
    )

    publish_review_conversation_to_github(
        job,
        failure_type=type(error).__name__,
    )


def process_one_review(
    *,
    db_path: str | Path,
    review_handler: Callable[
        [dict], bool | ReviewResult
    ] = review_github_pr_for_worker,
    publish_handler: Callable[
        [dict, ReviewResult, str], None
    ] | None = publish_review_report_to_github,
    failure_handler: Callable[
        [dict, Exception], None
    ] | None = publish_review_failure_to_github,
    progress_handler: Callable[
        [dict, str], None
    ] | None = publish_review_progress_to_github,
) -> bool:
    """Process one job from the persistent review queue."""

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    return run_next_review_job(
        db_path=database_path,
        review_handler=review_handler,
        publish_handler=publish_handler,
        failure_handler=failure_handler,
        progress_handler=progress_handler,
    )


def main() -> int:
    default_db = os.environ.get(
        "SYCUR_REVIEW_QUEUE_DB",
        str(
            Path.home()
            / ".local"
            / "share"
            / "sycur"
            / "review_jobs.db"
        ),
    )

    parser = argparse.ArgumentParser(
        description="Process SYCUR GitHub PR review jobs."
    )

    parser.add_argument(
        "--db",
        default=default_db,
        help="SQLite review queue database path.",
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously poll for queued reviews.",
    )

    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=2.0,
        help="Delay when the queue is empty.",
    )

    parser.add_argument(
        "--max-polls",
        type=int,
        default=0,
        help="Stop after N polls; 0 means unlimited.",
    )

    args = parser.parse_args()

    if not (0 < args.poll_seconds <= 3600):
        parser.error("--poll-seconds must be between 0 and 3600.")

    if args.max_polls < 0:
        parser.error("--max-polls cannot be negative.")

    polls = 0

    try:
        while True:
            database_path = Path(args.db).expanduser()
            if args.watch and database_path.is_file():
                recovered = recover_expired_review_jobs(
                    db_path=database_path,
                    max_attempts=3,
                )
                if recovered["requeued"] or recovered["exhausted"]:
                    print(
                        "SYCUR RECOVERY: "
                        f"{recovered['requeued']} requeued, "
                        f"{recovered['exhausted']} exhausted",
                        flush=True,
                    )
                retried = requeue_due_failed_review_jobs(
                    db_path=database_path,
                    max_attempts=3,
                )
                if retried["requeued"] or retried["exhausted"]:
                    print(
                        "SYCUR RETRY: "
                        f"{retried['requeued']} requeued, "
                        f"{retried['exhausted']} exhausted",
                        flush=True,
                    )
            if args.watch and not database_path.exists():
                # The first webhook has not created
                # the SQLite queue database yet.
                processed = False
            else:
                try:
                    processed = process_one_review(
                        db_path=args.db
                    )
                except Exception as exc:
                    if not args.watch:
                        raise
                    print(
                        "SYCUR REVIEW JOB ERROR: "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )
                    processed = False

            polls += 1

            if processed:
                print(
                    "SYCUR REVIEW JOB: PROCESSED",
                    flush=True,
                )

            elif not args.watch:
                print("SYCUR REVIEW QUEUE: EMPTY")

            if not args.watch:
                return 0

            if args.max_polls and polls >= args.max_polls:
                print("SYCUR REVIEW WATCH: STOPPED")
                return 0

            if not processed:
                time.sleep(args.poll_seconds)

    except KeyboardInterrupt:
        print("\nSYCUR REVIEW WATCH: INTERRUPTED")
        return 0

    except Exception as exc:
        print(
            f"Review worker failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
