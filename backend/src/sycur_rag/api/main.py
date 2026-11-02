from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Event, Thread

from fastapi import FastAPI

from sycur_rag.api.webhook.github import (
    router as github_webhook_router,
)
from sycur_rag.api.report import (
    router as report_router,
)
from sycur_rag.github.review_worker_service import (
    run_review_worker,
)


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the automatic SYCUR review worker lifecycle."""

    enabled = os.getenv(
        "SYCUR_REVIEW_WORKER_ENABLED", "true"
    ).strip().lower()

    if enabled not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError("Invalid SYCUR_REVIEW_WORKER_ENABLED value.")

    worker_enabled = enabled in {"true", "1", "yes"}

    worker_thread = None
    stop_event = Event()

    if worker_enabled:
        db_path = Path(
            os.getenv(
                "SYCUR_REVIEW_QUEUE_DB",
                str(
                    Path.home()
                    / ".local"
                    / "share"
                    / "sycur"
                    / "review_jobs.db"
                ),
            )
        ).expanduser()

        poll_seconds = float(
            os.getenv("SYCUR_REVIEW_POLL_SECONDS", "2")
        )

        worker_thread = Thread(
            target=run_review_worker,
            kwargs={
                "stop_event": stop_event,
                "db_path": db_path,
                "poll_seconds": poll_seconds,
            },
            name="sycur-review-worker",
            daemon=True,
        )

        worker_thread.start()
        app.state.review_worker_thread = worker_thread

        logger.info("SYCUR review worker started.")

    try:
        yield
    finally:
        stop_event.set()

        if worker_thread is not None:
            worker_thread.join(timeout=30)

            if worker_thread.is_alive():
                logger.warning(
                    "SYCUR review worker did not stop within 30 seconds."
                )
            else:
                logger.info("SYCUR review worker stopped.")


app = FastAPI(
    title="SYCUR API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(github_webhook_router)
app.include_router(report_router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "sycur-api",
    }
