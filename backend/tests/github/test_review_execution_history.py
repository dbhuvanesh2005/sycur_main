import sqlite3
from uuid import uuid4

import pytest

from sycur_rag.core.enums import (
    PolicyAction,
    ReviewStatus,
    Severity,
)
from sycur_rag.github.pr_event import ValidatedPREvent
from sycur_rag.github.review_queue import (
    enqueue_review_job,
    claim_next_review_job,
    finish_review_job_with_lease,
    get_review_progress_snapshot_for_run,
    get_review_report_by_token,
    queue_review_scanner_events_with_lease,
    requeue_due_failed_review_jobs,
    save_review_result_with_lease,
    update_review_job_progress_with_lease,
    update_review_scanner_event_with_lease,
)
from sycur_rag.models.review import ReviewResult


STAGES = [
    "CODE_SCAN",
    "FINDING_ANALYSIS",
    "RAG_EVALUATION",
    "AI_EXPLANATION",
    "POLICY_EVALUATION",
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


def test_completed_review_records_all_stage_durations(tmp_path):
    db_path = tmp_path / "review_jobs.db"

    job = create_claimed_job(db_path)

    # Execute all five lifecycle transitions.
    for stage in STAGES:
        assert update_review_job_progress_with_lease(
            delivery_id=job["delivery_id"],
            lease_token=job["lease_token"],
            stage=stage,
            db_path=db_path,
        )

    # Finalize the complete execution.
    finish_review_job_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        final_status="completed",
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        run = connection.execute(
            """
            SELECT *
            FROM review_runs
            WHERE run_id = ?
            """,
            (job["run_id"],),
        ).fetchone()

        stages = connection.execute(
            """
            SELECT *
            FROM review_stage_events
            WHERE run_id = ?
            ORDER BY rowid
            """,
            (job["run_id"],),
        ).fetchall()

        queue_job = connection.execute(
            """
            SELECT *
            FROM review_jobs
            WHERE delivery_id = ?
            """,
            (job["delivery_id"],),
        ).fetchone()

    # Verify execution identity and timing.
    assert run["status"] == "completed"
    assert run["started_at"]
    assert run["completed_at"]
    assert run["duration_ms"] is not None
    assert run["duration_ms"] >= 0

    # Verify all lifecycle stages.
    assert len(stages) == 5
    assert [stage["stage"] for stage in stages] == STAGES

    for stage in stages:
        assert stage["status"] == "completed"
        assert stage["started_at"]
        assert stage["completed_at"]
        assert stage["duration_ms"] is not None
        assert stage["duration_ms"] >= 0

    # Verify final queue state.
    assert queue_job["status"] == "completed"
    assert queue_job["active_run_id"] is None

    print("PASS: Unique execution ID persisted")
    print("PASS: All five stages recorded")
    print("PASS: Individual stage durations recorded")
    print("PASS: Total execution duration recorded")
    print("PASS: Final execution timestamp recorded")
    print("PASS: Completed queue state persisted")


def test_failed_review_records_failure_timing(tmp_path):
    db_path = tmp_path / "review_jobs.db"

    job = create_claimed_job(db_path)

    assert update_review_job_progress_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        stage="AI_EXPLANATION",
        db_path=db_path,
    )

    finish_review_job_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        final_status="failed",
        retry_delay_seconds=1,
        error_type="RuntimeError",
        error_message="Simulated AI explanation failure",
        db_path=db_path,
    )

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        run = connection.execute(
            """
            SELECT *
            FROM review_runs
            WHERE run_id = ?
            """,
            (job["run_id"],),
        ).fetchone()

        stage = connection.execute(
            """
            SELECT *
            FROM review_stage_events
            WHERE run_id = ?
            """,
            (job["run_id"],),
        ).fetchone()

    assert run["status"] == "failed"
    assert run["failure_stage"] == "AI_EXPLANATION"
    assert run["error_type"] == "RuntimeError"
    assert run["error_message"] == (
        "Simulated AI explanation failure"
    )
    assert run["duration_ms"] is not None

    assert stage["status"] == "failed"
    assert stage["duration_ms"] is not None
    assert stage["completed_at"]

    print("PASS: Failed execution preserved")
    print("PASS: Failure stage identified")
    print("PASS: Exception details persisted")
    print("PASS: Failed stage duration recorded")


def test_retry_creates_new_execution_without_overwriting_history(
    tmp_path,
):
    db_path = tmp_path / "review_jobs.db"

    first_job = create_claimed_job(db_path)

    update_review_job_progress_with_lease(
        delivery_id=first_job["delivery_id"],
        lease_token=first_job["lease_token"],
        stage="CODE_SCAN",
        db_path=db_path,
    )

    finish_review_job_with_lease(
        delivery_id=first_job["delivery_id"],
        lease_token=first_job["lease_token"],
        final_status="failed",
        retry_delay_seconds=1,
        error_type="RuntimeError",
        error_message="Simulated failure",
        db_path=db_path,
    )

    # Make retry immediately eligible.
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

    with sqlite3.connect(db_path) as connection:
        runs = connection.execute(
            """
            SELECT run_id, attempt_number, status, duration_ms
            FROM review_runs
            WHERE delivery_id = ?
            ORDER BY attempt_number
            """,
            (first_job["delivery_id"],),
        ).fetchall()

    assert len(runs) == 2

    assert runs[0][0] == first_job["run_id"]
    assert runs[0][2] == "failed"
    assert runs[0][3] is not None

    assert runs[1][0] == second_job["run_id"]
    assert runs[1][2] == "running"

    print("PASS: Retry generated a unique execution ID")
    print("PASS: Attempt number incremented")
    print("PASS: Previous execution history preserved")
    print("PASS: New execution independently recorded")


def test_report_retrieval_includes_execution_history(tmp_path):
    db_path = tmp_path / "review_jobs.db"

    job = create_claimed_job(db_path)

    # Queue independent scanner execution events.
    scanner_plan = [
        ("gitleaks", ("src/app.py", "requirements.txt")),
        ("semgrep", ("src/app.py",)),
    ]

    assert queue_review_scanner_events_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        scanner_plan=scanner_plan,
        db_path=db_path,
    )

    # Record actual scanner lifecycle transitions.
    for scanner, findings_count in [
        ("gitleaks", 1),
        ("semgrep", 2),
    ]:
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

    # Execute all five lifecycle stages.
    for stage in STAGES:
        assert update_review_job_progress_with_lease(
            delivery_id=job["delivery_id"],
            lease_token=job["lease_token"],
            stage=stage,
            db_path=db_path,
        )

    # Create a valid security review.
    review = ReviewResult(
        status=ReviewStatus.PASS,
        action=PolicyAction.ALLOW,
        severity=Severity.NOT_APPLICABLE,
        reason="No security findings detected.",
    )

    report_token = "report-token-" + "a" * 40

    # Persist the report before completing the execution.
    save_review_result_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        review=review,
        report_token=report_token,
        db_path=db_path,
    )

    finish_review_job_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        final_status="completed",
        db_path=db_path,
    )

    # Retrieve the report using its original token.
    report = get_review_report_by_token(
        report_token=report_token,
        db_path=db_path,
    )

    assert report is not None
    assert report["repository"] == "test-owner/test-repo"
    assert report["pr_number"] == 17
    assert report["review"].status == ReviewStatus.PASS

    history = report["execution_history"]

    assert len(history) == 1

    execution = history[0]

    assert execution["attempt_number"] == 1
    assert execution["run_id"] == job["run_id"]
    assert execution["head_sha"] == "a" * 40
    assert execution["status"] == "completed"
    assert execution["started_at"]
    assert execution["completed_at"]
    assert execution["duration_ms"] >= 0

    # Verify all five stage timings.
    stages = execution["stages"]

    assert [stage["stage"] for stage in stages] == STAGES

    for stage in stages:
        assert stage["status"] == "completed"
        assert stage["started_at"]
        assert stage["completed_at"]
        assert stage["duration_ms"] >= 0

    # Verify independent scanner execution history.
    scanners = execution["scanners"]

    assert len(scanners) == 2

    scanner_map = {
        item["scanner"]: item
        for item in scanners
    }

    assert set(scanner_map) == {
        "gitleaks",
        "semgrep",
    }

    for name, expected_count in [
        ("gitleaks", 1),
        ("semgrep", 2),
    ]:
        scanner = scanner_map[name]

        assert scanner["status"] == "completed"
        assert scanner["queued_at"]
        assert scanner["started_at"]
        assert scanner["completed_at"]
        assert scanner["duration_ms"] >= 0
        assert scanner["findings_count"] == expected_count

    assert scanner_map["gitleaks"]["file_paths"] == [
        "src/app.py",
        "requirements.txt",
    ]

    assert scanner_map["semgrep"]["file_paths"] == [
        "src/app.py",
    ]

    # Invalid report tokens must be rejected.
    with pytest.raises(ValueError, match="Invalid report token"):
        get_review_report_by_token(
            report_token="invalid",
            db_path=db_path,
        )

    print("PASS: Secure report retrieval")
    print("PASS: Invalid report token rejected")
    print("PASS: Execution history retrieved")
    print("PASS: Total execution duration retrieved")
    print("PASS: All five stage timings retrieved")
    print("\nSYCUR REPORT HISTORY RETRIEVAL: SUCCESS")


def test_live_progress_snapshot_includes_stage_and_scanner_data(
    tmp_path,
):
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

    assert update_review_job_progress_with_lease(
        delivery_id=job["delivery_id"],
        lease_token=job["lease_token"],
        stage="CODE_SCAN",
        db_path=db_path,
    )

    snapshot = get_review_progress_snapshot_for_run(
        run_id=job["run_id"],
        db_path=db_path,
    )

    assert snapshot["total_duration_ms"] >= 0

    assert len(snapshot["stage_events"]) == 1

    stage = snapshot["stage_events"][0]

    assert stage["stage"] == "CODE_SCAN"
    assert stage["status"] == "in_progress"
    assert stage["duration_ms"] >= 0
    assert stage["started_at"]
    assert stage["completed_at"] is None

    scanners = snapshot["scanner_events"]

    assert len(scanners) == 1
    assert scanners[0]["scanner"] == "gitleaks"
    assert scanners[0]["status"] == "queued"
