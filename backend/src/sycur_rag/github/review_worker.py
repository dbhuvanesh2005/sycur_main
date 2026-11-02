from __future__ import annotations

import logging
import secrets
import threading
from collections.abc import Callable
from pathlib import Path

from sycur_rag.github.review_queue import (
    claim_next_review_job,
    finish_review_job_with_lease,
    get_review_progress_snapshot_for_run,
    queue_review_scanner_events_with_lease,
    renew_review_job_lease,
    save_review_result_with_lease,
    update_review_job_progress_with_lease,
    update_review_scanner_event_with_lease,
)
from sycur_rag.models.review import ReviewResult


logger = logging.getLogger(__name__)


def _run_with_heartbeat(
    *,
    job: dict,
    db_path: str | Path,
    review_handler: Callable[[dict], bool | ReviewResult],
    lease_seconds: int,
    heartbeat_seconds: float,
) -> bool | ReviewResult:
    """Keep the job lease active while its review runs."""
    stop = threading.Event()
    errors: list[Exception] = []

    def heartbeat() -> None:
        while not stop.wait(heartbeat_seconds):
            try:
                renewed = renew_review_job_lease(
                    delivery_id=job["delivery_id"],
                    lease_token=job["lease_token"],
                    db_path=db_path,
                    lease_seconds=lease_seconds,
                )
                if not renewed:
                    raise RuntimeError(
                        "Worker lost its review lease."
                    )
            except Exception as exc:
                errors.append(exc)
                stop.set()
                return

    thread = threading.Thread(
        target=heartbeat,
        daemon=True,
    )
    thread.start()

    try:
        outcome = review_handler(job)
    finally:
        stop.set()
        thread.join()

    if errors:
        raise errors[0]

    return outcome


def run_next_review_job(
    *,
    db_path: str | Path,
    review_handler: Callable[[dict], bool | ReviewResult],
    publish_handler: Callable[
        [dict, ReviewResult, str], None
    ] | None = None,
    failure_handler: Callable[
        [dict, Exception], None
    ] | None = None,
    progress_handler: Callable[
        [dict, str], None
    ] | None = None,
    lease_seconds: int = 900,
    heartbeat_seconds: float = 60.0,
) -> bool:
    """
    Process one queued review job.

    Scan -> Persist report -> Publish GitHub Check
    -> Complete job.
    """

    if not callable(review_handler):
        raise TypeError(
            "review_handler must be callable."
        )

    if (
        publish_handler is not None
        and not callable(publish_handler)
    ):
        raise TypeError(
            "publish_handler must be callable."
        )

    if (
        progress_handler is not None
        and not callable(progress_handler)
    ):
        raise TypeError(
            "progress_handler must be callable."
        )

    if (
        failure_handler is not None
        and not callable(failure_handler)
    ):
        raise TypeError(
            "failure_handler must be callable."
        )

    if type(lease_seconds) is not int or lease_seconds < 1:
        raise ValueError("Invalid lease duration.")

    if (
        isinstance(heartbeat_seconds, bool)
        or not isinstance(heartbeat_seconds, (int, float))
        or not (0 < heartbeat_seconds < lease_seconds)
    ):
        raise ValueError("Invalid heartbeat interval.")

    job = claim_next_review_job(
        db_path=db_path,
        lease_seconds=lease_seconds,
    )

    if job is None:
        return False

    def process_review(
        current_job: dict,
    ) -> bool | ReviewResult:

        review_job = dict(current_job)

        current_stage = "CODE_SCAN"

        # Scanner callbacks can execute concurrently.
        # Serialize GitHub progress publishing to avoid
        # older snapshots overwriting newer snapshots.
        progress_publish_lock = threading.Lock()

        def publish_progress_snapshot(stage: str) -> None:

            if progress_handler is None:
                return

            try:
                with progress_publish_lock:

                    snapshot = (
                        get_review_progress_snapshot_for_run(
                            run_id=current_job["run_id"],
                            db_path=db_path,
                        )
                    )

                    progress_job = dict(current_job)

                    progress_job["_scanner_events"] = (
                        snapshot["scanner_events"]
                    )

                    progress_job["_stage_events"] = (
                        snapshot["stage_events"]
                    )

                    progress_job["_total_duration_ms"] = (
                        snapshot["total_duration_ms"]
                    )

                    progress_handler(
                        progress_job,
                        stage,
                    )

            except Exception:
                logger.warning(
                    "SYCUR scanner progress publishing failed "
                    "for delivery %s at stage %s. "
                    "Continuing security review.",
                    current_job["delivery_id"],
                    stage,
                    exc_info=True,
                )

        def report_progress(stage: str) -> None:
            nonlocal current_stage

            if (
                not isinstance(stage, str)
                or not stage.strip()
            ):
                raise ValueError(
                    "Invalid review progress stage."
                )

            # First: persist progress using the active lease.
            persisted = update_review_job_progress_with_lease(
                delivery_id=current_job["delivery_id"],
                lease_token=current_job["lease_token"],
                stage=stage,
                db_path=db_path,
            )

            if not persisted:
                raise RuntimeError(
                    "Worker lost its review lease; "
                    "cannot persist review progress."
                )

            current_stage = stage
            publish_progress_snapshot(stage)

        def report_scanner_event(
            event: str,
            *,
            scanner_plan=None,
            scanner: str | None = None,
            findings_count: int = 0,
            error_type: str | None = None,
            error_message: str | None = None,
        ) -> None:

            if event == "plan":
                if scanner_plan is None:
                    raise ValueError(
                        "Scanner plan is required."
                    )

                persisted = queue_review_scanner_events_with_lease(
                    delivery_id=current_job["delivery_id"],
                    lease_token=current_job["lease_token"],
                    scanner_plan=scanner_plan,
                    db_path=db_path,
                )

            else:
                statuses = {
                    "start": "running",
                    "complete": "completed",
                    "failure": "failed",
                }

                if event not in statuses:
                    raise ValueError(
                        "Invalid scanner lifecycle event."
                    )

                if not scanner:
                    raise ValueError(
                        "Scanner name is required."
                    )

                persisted = update_review_scanner_event_with_lease(
                    delivery_id=current_job["delivery_id"],
                    lease_token=current_job["lease_token"],
                    scanner=scanner,
                    status=statuses[event],
                    db_path=db_path,
                    findings_count=findings_count,
                    error_type=error_type,
                    error_message=error_message,
                )

            if not persisted:
                raise RuntimeError(
                    "Worker lost its review lease; "
                    "cannot persist scanner execution."
                )

            publish_progress_snapshot(current_stage)

        # Expose an internal progress callback
        # to the review execution pipeline.
        review_job["_progress_callback"] = (
            report_progress
        )
        review_job["_scanner_event_callback"] = (
            report_scanner_event
        )

        # Start the visible review lifecycle.
        report_progress("CODE_SCAN")

        outcome = review_handler(review_job)

        if isinstance(outcome, ReviewResult):
            report_token = secrets.token_urlsafe(32)

            # First: securely persist the complete report.
            save_review_result_with_lease(
                delivery_id=current_job["delivery_id"],
                lease_token=current_job["lease_token"],
                review=outcome,
                report_token=report_token,
                db_path=db_path,
            )

            # Second: capture the final execution snapshot.
            final_snapshot = (
                get_review_progress_snapshot_for_run(
                    run_id=current_job["run_id"],
                    db_path=db_path,
                )
            )

            # The review has returned successfully.
            # Close the active stage in the presentation snapshot.
            final_stage_events = []

            for stage_event in final_snapshot["stage_events"]:
                event = dict(stage_event)

                if event["status"] == "in_progress":
                    event["status"] = "completed"

                final_stage_events.append(event)

            # Preserve the original job and attach final metrics.
            final_publish_job = dict(current_job)

            final_publish_job["_stage_events"] = (
                final_stage_events
            )

            # Preserve the complete final scanner execution history.
            final_publish_job["_scanner_events"] = (
                final_snapshot["scanner_events"]
            )

            final_publish_job["_total_duration_ms"] = (
                final_snapshot["total_duration_ms"]
            )

            # Third: publish the completed execution timeline.
            if publish_handler is not None:
                publish_handler(
                    final_publish_job,
                    outcome,
                    report_token,
                )

        return outcome

    try:
        outcome = _run_with_heartbeat(
            job=job,
            db_path=db_path,
            review_handler=process_review,
            lease_seconds=lease_seconds,
            heartbeat_seconds=heartbeat_seconds,
        )

        if not isinstance(outcome, ReviewResult) and outcome is not True:
            raise RuntimeError(
                "Review handler did not confirm success."
            )

    except Exception as exc:
        failure_snapshot = None

        if failure_handler is not None:
            try:
                failure_snapshot = (
                    get_review_progress_snapshot_for_run(
                        run_id=job["run_id"],
                        db_path=db_path,
                    )
                )
            except Exception:
                logger.exception(
                    "SYCUR terminal failure snapshot failed "
                    "for delivery %s.",
                    job["delivery_id"],
                )

        failure_recorded = False

        try:
            finish_review_job_with_lease(
                delivery_id=job["delivery_id"],
                lease_token=job["lease_token"],
                final_status="failed",
                db_path=db_path,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )

            # Successful return proves the active lease finalized the job.
            failure_recorded = True
        except ValueError:
            pass

        if failure_recorded and failure_handler is not None:
            try:
                failure_job = dict(job)

                if failure_snapshot is not None:
                    failure_stage_events = []

                    for stage_event in failure_snapshot["stage_events"]:
                        event = dict(stage_event)

                        if event["status"] == "in_progress":
                            event["status"] = "failed"

                        failure_stage_events.append(event)

                    failure_job["_scanner_events"] = failure_snapshot[
                        "scanner_events"
                    ]
                    failure_job["_stage_events"] = (
                        failure_stage_events
                    )
                    failure_job["_total_duration_ms"] = (
                        failure_snapshot["total_duration_ms"]
                    )

                failure_handler(failure_job, exc)

            except Exception:
                logger.exception(
                    "SYCUR terminal GitHub failure publishing failed "
                    "for delivery %s.",
                    job["delivery_id"],
                )

        raise

    # Complete only after publication succeeds.
    finish_review_job_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        final_status="completed",
        db_path=db_path,
    )

    return True
