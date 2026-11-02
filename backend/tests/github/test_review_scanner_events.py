import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest

from sycur_rag.github.pr_event import ValidatedPREvent
from sycur_rag.github.review_queue import (
    enqueue_review_job,
    claim_next_review_job,
    finish_review_job_with_lease,
    requeue_due_failed_review_jobs,
    queue_review_scanner_events_with_lease,
    update_review_scanner_event_with_lease,
)


SCANNER_PLAN = [
    ("gitleaks", ["src/app.py"]),
    ("semgrep", ["src/app.py"]),
    ("bandit", ["src/app.py"]),
]


def create_claimed_job(db_path):
    event = ValidatedPREvent(
        delivery_id=uuid4(),
        installation_id=1,
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        action="opened",
    )

    assert enqueue_review_job(
        event=event,
        db_path=db_path,
    )

    job = claim_next_review_job(db_path=db_path)

    assert job is not None

    return job


def read_scanner_events(db_path, run_id):
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        return connection.execute(
            """
            SELECT *
            FROM review_scanner_events
            WHERE run_id = ?
            ORDER BY scanner
            """,
            (run_id,),
        ).fetchall()


def expire_lease(db_path, delivery_id):
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE review_jobs
            SET lease_expires_at = 0
            WHERE delivery_id = ?
            """,
            (delivery_id,),
        )


def test_queue_creates_independent_scanner_events(tmp_path):
    db_path = tmp_path / "review_jobs.db"
    job = create_claimed_job(db_path)

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=SCANNER_PLAN,
        db_path=db_path,
    )

    events = read_scanner_events(
        db_path,
        job["run_id"],
    )

    assert len(events) == 3

    assert {event["scanner"] for event in events} == {
        "gitleaks",
        "semgrep",
        "bandit",
    }

    for event in events:
        assert event["status"] == "queued"
        assert event["queued_at"]
        assert json.loads(event["file_paths_json"]) == [
            "src/app.py"
        ]


def test_scanner_event_records_completed_duration(tmp_path):
    db_path = tmp_path / "review_jobs.db"
    job = create_claimed_job(db_path)

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=[
            ("semgrep", ["src/app.py"]),
        ],
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="semgrep",
        status="running",
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="semgrep",
        status="completed",
        findings_count=2,
        db_path=db_path,
    )

    events = read_scanner_events(db_path, job["run_id"])

    event = events[0]

    assert event["status"] == "completed"
    assert event["started_at"]
    assert event["completed_at"]
    assert event["started_at_epoch_ms"] is not None
    assert event["duration_ms"] >= 0
    assert event["findings_count"] == 2

    assert event["error_type"] is None
    assert event["error_message"] is None


def test_scanner_event_records_failure_details(tmp_path):
    db_path = tmp_path / "review_jobs.db"
    job = create_claimed_job(db_path)

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=[
            ("gitleaks", ["src/app.py"]),
        ],
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="gitleaks",
        status="running",
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="gitleaks",
        status="failed",
        error_type="RuntimeError",
        error_message="Simulated scanner failure",
        db_path=db_path,
    )

    event = read_scanner_events(
        db_path,
        job["run_id"],
    )[0]

    assert event["status"] == "failed"
    assert event["completed_at"]
    assert event["duration_ms"] >= 0
    assert event["error_type"] == "RuntimeError"
    assert event["error_message"] == (
        "Simulated scanner failure"
    )


def test_scanner_events_update_independently_under_concurrency(
    tmp_path,
):
    db_path = tmp_path / "review_jobs.db"
    job = create_claimed_job(db_path)

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=SCANNER_PLAN,
        db_path=db_path,
    )

    barrier = Barrier(3)

    def complete_scanner(scanner, findings_count):
        barrier.wait(timeout=5)

        assert update_review_scanner_event_with_lease(
            delivery_id=job["delivery_id"],
            lease_token=job["lease_token"],
            scanner=scanner,
            status="running",
            db_path=db_path,
        )

        assert update_review_scanner_event_with_lease(
            delivery_id=job["delivery_id"],
            lease_token=job["lease_token"],
            scanner=scanner,
            status="completed",
            findings_count=findings_count,
            db_path=db_path,
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(
                complete_scanner,
                "gitleaks",
                1,
            ),
            executor.submit(
                complete_scanner,
                "semgrep",
                2,
            ),
            executor.submit(
                complete_scanner,
                "bandit",
                3,
            ),
        ]

        for future in futures:
            future.result(timeout=15)

    events = read_scanner_events(
        db_path,
        job["run_id"],
    )

    assert len(events) == 3

    assert all(
        event["status"] == "completed"
        for event in events
    )

    actual_counts = {
        event["scanner"]: event["findings_count"]
        for event in events
    }

    assert actual_counts == {
        "gitleaks": 1,
        "semgrep": 2,
        "bandit": 3,
    }


def test_expired_lease_cannot_queue_scanner_events(tmp_path):
    db_path = tmp_path / "expired_queue.db"
    job = create_claimed_job(db_path)

    expire_lease(
        db_path,
        job["delivery_id"],
    )

    result = queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=SCANNER_PLAN,
        db_path=db_path,
    )

    assert result is False

    events = read_scanner_events(
        db_path,
        job["run_id"],
    )

    assert len(events) == 0


def test_expired_lease_cannot_update_scanner_event(tmp_path):
    db_path = tmp_path / "expired_update.db"
    job = create_claimed_job(db_path)

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=[
            ("semgrep", ["src/app.py"]),
        ],
        db_path=db_path,
    )

    expire_lease(
        db_path,
        job["delivery_id"],
    )

    result = update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="semgrep",
        status="running",
        db_path=db_path,
    )

    assert result is False

    event = read_scanner_events(
        db_path,
        job["run_id"],
    )[0]

    assert event["status"] == "queued"
    assert event["started_at"] is None


def test_invalid_scanner_transitions_are_rejected(tmp_path):
    db_path = tmp_path / "review_jobs.db"
    job = create_claimed_job(db_path)

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=[
            ("semgrep", ["src/app.py"]),
        ],
        db_path=db_path,
    )

    with pytest.raises(RuntimeError):
        update_review_scanner_event_with_lease(
            delivery_id=job["delivery_id"],
            lease_token=job["lease_token"],
            scanner="semgrep",
            status="completed",
            findings_count=2,
            db_path=db_path,
        )

    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="semgrep",
        status="running",
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="semgrep",
        status="completed",
        findings_count=2,
        db_path=db_path,
    )

    # Identical completion is idempotent.
    assert update_review_scanner_event_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner="semgrep",
        status="completed",
        findings_count=2,
        db_path=db_path,
    )

    # A completed scanner cannot become failed.
    with pytest.raises(RuntimeError):
        update_review_scanner_event_with_lease(
            delivery_id=job["delivery_id"],
            lease_token=job["lease_token"],
            scanner="semgrep",
            status="failed",
            error_type="RuntimeError",
            error_message="Invalid transition",
            db_path=db_path,
        )


def test_retry_creates_independent_scanner_history(tmp_path):
    db_path = tmp_path / "review_jobs.db"
    first_job = create_claimed_job(db_path)

    scanner_plan = [
        ("gitleaks", ["src/app.py"]),
    ]

    assert queue_review_scanner_events_with_lease(
        delivery_id=first_job["delivery_id"],
        lease_token=first_job["lease_token"],
        scanner_plan=scanner_plan,
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=first_job["delivery_id"],
        lease_token=first_job["lease_token"],
        scanner="gitleaks",
        status="running",
        db_path=db_path,
    )

    assert update_review_scanner_event_with_lease(
        delivery_id=first_job["delivery_id"],
        lease_token=first_job["lease_token"],
        scanner="gitleaks",
        status="completed",
        findings_count=1,
        db_path=db_path,
    )

    finish_review_job_with_lease(
        delivery_id=first_job["delivery_id"],
        lease_token=first_job["lease_token"],
        final_status="failed",
        retry_delay_seconds=1,
        error_type="RuntimeError",
        error_message="Simulated review failure",
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE review_jobs
            SET retry_after = 0
            WHERE delivery_id = ?
            """,
            (first_job["delivery_id"],),
        )

    retry_result = requeue_due_failed_review_jobs(
        db_path=db_path,
        max_attempts=3,
    )

    assert retry_result["requeued"] == 1

    second_job = claim_next_review_job(db_path=db_path)

    assert second_job is not None
    assert second_job["run_id"] != first_job["run_id"]
    assert second_job["attempts"] == 2

    assert queue_review_scanner_events_with_lease(
        delivery_id=second_job["delivery_id"],
        lease_token=second_job["lease_token"],
        scanner_plan=scanner_plan,
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        events = connection.execute(
            """
            SELECT
                se.run_id,
                se.scanner,
                se.status,
                rr.attempt_number
            FROM review_scanner_events se
            JOIN review_runs rr
                ON rr.run_id = se.run_id
            WHERE rr.delivery_id = ?
            ORDER BY rr.attempt_number
            """,
            (first_job["delivery_id"],),
        ).fetchall()

    assert len(events) == 2

    assert events[0]["run_id"] == first_job["run_id"]
    assert events[0]["attempt_number"] == 1
    assert events[0]["status"] == "completed"

    assert events[1]["run_id"] == second_job["run_id"]
    assert events[1]["attempt_number"] == 2
    assert events[1]["status"] == "queued"
