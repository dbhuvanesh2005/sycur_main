from __future__ import annotations

import logging
from pathlib import Path
from threading import Event

from sycur_rag.github.review_queue import (
    recover_expired_review_jobs,
    requeue_due_failed_review_jobs,
)
from sycur_rag.github.review_runner import process_one_review


logger = logging.getLogger(__name__)


def run_review_worker(
    *,
    stop_event: Event,
    db_path: str | Path,
    poll_seconds: float = 2.0,
    max_attempts: int = 3,
) -> None:
    """Continuously process queued PR reviews until stopped."""

    if not 0 < poll_seconds <= 3600:
        raise ValueError("Invalid polling interval.")

    database_path = Path(db_path).expanduser()

    while not stop_event.is_set():
        processed = False

        try:
            if database_path.is_file():
                recovered = recover_expired_review_jobs(
                    db_path=database_path,
                    max_attempts=max_attempts,
                )

                if recovered["requeued"] or recovered["exhausted"]:
                    logger.info("SYCUR recovery: %s", recovered)

                retried = requeue_due_failed_review_jobs(
                    db_path=database_path,
                    max_attempts=max_attempts,
                )

                if retried["requeued"] or retried["exhausted"]:
                    logger.info("SYCUR retry: %s", retried)

                processed = process_one_review(
                    db_path=database_path,
                )

        except Exception:
            logger.exception("SYCUR review worker iteration failed")

        if processed:
            logger.info("SYCUR review job processed")
        else:
            stop_event.wait(poll_seconds)

    logger.info("SYCUR review worker stopped")
