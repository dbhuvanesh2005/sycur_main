import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from sycur_rag.core.enums import (
    PolicyAction,
    ReviewStatus,
    Severity,
)
from sycur_rag.github.pr_event import ValidatedPREvent
from sycur_rag.github.review_queue import enqueue_review_job
from sycur_rag.github.review_worker import run_next_review_job
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.models.review import ReviewResult
from sycur_rag.scanners.base import ScannerAdapter
from sycur_rag.scanners.orchestrator import (
    SUPPORTED_SCANNERS,
    ScannerOrchestrator,
)


class FakeScannerAdapter(ScannerAdapter):

    def __init__(self, name, *, fail=False, findings=None):
        self._name = name
        self._fail = fail
        self._findings = findings or []

    @property
    def scanner_name(self):
        return self._name

    def scan(self, target_path):
        if self._fail:
            raise RuntimeError(
                f"Simulated {self._name} scanner failure."
            )

        return list(self._findings)


def create_queued_review(db_path):
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

    return str(event.delivery_id)


def create_repository(root):
    source = root / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "print('test application')\n",
        encoding="utf-8",
    )

    return root


def create_finding():
    return ScannerFinding(
        scanner="semgrep",
        rule_id="TEST-001",
        title="Test security finding",
        message="Simulated security issue.",
        severity=Severity.MEDIUM,
        file_path="src/app.py",
        line_start=1,
        line_end=1,
    )


def create_review_handler(
    repository_root,
    *,
    failing_scanners=(),
):
    adapters = {
        name: FakeScannerAdapter(
            name,
            fail=name in failing_scanners,
            findings=(
                [create_finding()]
                if name == "semgrep"
                else []
            ),
        )
        for name in SUPPORTED_SCANNERS
    }

    orchestrator = ScannerOrchestrator(
        repository_root=repository_root,
        adapters=adapters,
        max_workers=3,
    )

    def review_handler(job):
        scanner_callback = job[
            "_scanner_event_callback"
        ]

        def report_plan(plan):
            scanner_callback(
                "plan",
                scanner_plan=[
                    (item.scanner, item.file_paths)
                    for item in plan
                ],
            )

        def report_start(item):
            scanner_callback(
                "start",
                scanner=item.scanner,
            )

        def report_complete(item, findings_count):
            scanner_callback(
                "complete",
                scanner=item.scanner,
                findings_count=findings_count,
            )

        def report_failure(item, error):
            scanner_callback(
                "failure",
                scanner=item.scanner,
                error_type=type(error).__name__,
                error_message=str(error),
            )

        result = orchestrator.run(
            ["src/app.py"],
            fail_fast=False,
            on_plan=report_plan,
            on_scanner_start=report_start,
            on_scanner_complete=report_complete,
            on_scanner_failure=report_failure,
        )

        if result.failed_runs:
            raise RuntimeError(
                "Scanner execution incomplete."
            )

        return True

    return review_handler


def read_execution_state(db_path, delivery_id):
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row

        run = connection.execute(
            """
            SELECT *
            FROM review_runs
            WHERE delivery_id = ?
            """,
            (delivery_id,),
        ).fetchone()

        job = connection.execute(
            """
            SELECT *
            FROM review_jobs
            WHERE delivery_id = ?
            """,
            (delivery_id,),
        ).fetchone()

        events = []

        if run is not None:
            events = connection.execute(
                """
                SELECT *
                FROM review_scanner_events
                WHERE run_id = ?
                ORDER BY scanner
                """,
                (run["run_id"],),
            ).fetchall()

        return run, job, events


def test_worker_persists_complete_scanner_execution(
    tmp_path,
):
    db_path = tmp_path / "review_jobs.db"

    repository = create_repository(
        tmp_path / "repository",
    )

    delivery_id = create_queued_review(db_path)

    review_handler = create_review_handler(
        repository,
    )

    assert run_next_review_job(
        db_path=db_path,
        review_handler=review_handler,
    )

    run, job, events = read_execution_state(
        db_path,
        delivery_id,
    )

    assert run is not None
    assert run["status"] == "completed"

    assert job["status"] == "completed"

    assert len(events) == 3

    assert {
        event["scanner"]
        for event in events
    } == {
        "gitleaks",
        "semgrep",
        "bandit",
    }

    for event in events:
        assert event["status"] == "completed"
        assert event["started_at"]
        assert event["completed_at"]
        assert event["duration_ms"] is not None
        assert event["duration_ms"] >= 0
        assert event["error_type"] is None
        assert event["error_message"] is None

    semgrep = next(
        event
        for event in events
        if event["scanner"] == "semgrep"
    )

    assert semgrep["findings_count"] == 1


def test_worker_preserves_scanner_failure_history(
    tmp_path,
):
    db_path = tmp_path / "review_jobs.db"

    repository = create_repository(
        tmp_path / "repository",
    )

    delivery_id = create_queued_review(db_path)

    review_handler = create_review_handler(
        repository,
        failing_scanners={"semgrep"},
    )

    failures_published = []

    def capture_failure(job, error):
        failures_published.append((job, error))

    with pytest.raises(
        RuntimeError,
        match="Scanner execution incomplete.",
    ):
        run_next_review_job(
            db_path=db_path,
            review_handler=review_handler,
            failure_handler=capture_failure,
        )

    run, job, events = read_execution_state(
        db_path,
        delivery_id,
    )

    assert run is not None
    assert run["status"] == "failed"

    assert job["status"] == "failed"

    assert len(events) == 3

    semgrep = next(
        event
        for event in events
        if event["scanner"] == "semgrep"
    )

    assert semgrep["status"] == "failed"
    assert semgrep["error_type"] == "RuntimeError"
    assert semgrep["error_message"] == (
        "Simulated semgrep scanner failure."
    )
    assert semgrep["completed_at"]
    assert semgrep["duration_ms"] is not None

    successful_scanners = {
        event["scanner"]
        for event in events
        if event["status"] == "completed"
    }

    assert successful_scanners == {
        "gitleaks",
        "bandit",
    }

    assert len(failures_published) == 1

    failure_job, failure_error = failures_published[0]

    assert isinstance(failure_error, RuntimeError)
    assert failure_job["_scanner_events"] is not None

    failed_scanners = {
        event["scanner"]
        for event in failure_job["_scanner_events"]
        if event["status"] == "failed"
    }

    assert failed_scanners == {"semgrep"}


def test_worker_publishes_live_scanner_progress(
    tmp_path,
):
    db_path = tmp_path / "review_jobs.db"

    repository = create_repository(
        tmp_path / "repository",
    )

    delivery_id = create_queued_review(db_path)

    review_handler = create_review_handler(
        repository,
    )

    progress_updates = []

    def capture_progress(job, stage):
        events = job.get("_scanner_events")

        if events is not None:
            progress_updates.append({
                "stage": stage,
                "scanners": events,
                "stage_events": job.get("_stage_events"),
                "total_duration_ms": job.get(
                    "_total_duration_ms"
                ),
            })

    assert run_next_review_job(
        db_path=db_path,
        review_handler=review_handler,
        progress_handler=capture_progress,
    )

    assert progress_updates

    # Verify scanner plan was published.
    assert any(
        any(
            event["status"] == "queued"
            for event in update["scanners"]
        )
        for update in progress_updates
    )

    # Verify scanner lifecycle reached completion.
    final_update = progress_updates[-1]

    assert final_update["stage"] == "CODE_SCAN"

    scanners = final_update["scanners"]

    assert len(scanners) == 3

    assert all(
        event["status"] == "completed"
        for event in scanners
    )

    assert all(
        event["duration_ms"] is not None
        for event in scanners
    )

    semgrep = next(
        event
        for event in scanners
        if event["scanner"] == "semgrep"
    )

    assert semgrep["findings_count"] == 1

    # Verify live review stage timing.
    stage_events = final_update["stage_events"]

    assert stage_events

    code_scan = next(
        event
        for event in stage_events
        if event["stage"] == "CODE_SCAN"
    )

    assert code_scan["status"] == "in_progress"
    assert code_scan["duration_ms"] >= 0
    assert code_scan["started_at"]

    # Verify total review elapsed time.
    assert final_update["total_duration_ms"] >= 0


def test_worker_final_handoff_includes_scanner_snapshot(
    tmp_path,
):
    db_path = tmp_path / "review_jobs.db"

    repository = create_repository(
        tmp_path / "repository",
    )

    create_queued_review(db_path)

    scan_handler = create_review_handler(
        repository,
    )

    def review_handler(job):
        assert scan_handler(job) is True

        return ReviewResult(
            status=ReviewStatus.PASS,
            action=PolicyAction.ALLOW,
            severity=Severity.NOT_APPLICABLE,
            reason="Security scan completed.",
        )

    published_jobs = []

    def publish_handler(job, review, report_token):
        published_jobs.append({
            "job": dict(job),
            "review": review,
            "report_token": report_token,
        })

    assert run_next_review_job(
        db_path=db_path,
        review_handler=review_handler,
        publish_handler=publish_handler,
    )

    assert len(published_jobs) == 1

    published = published_jobs[0]
    final_job = published["job"]
    scanner_events = final_job["_scanner_events"]

    assert isinstance(scanner_events, list)
    assert len(scanner_events) == 3
    assert all(
        event["status"] == "completed"
        for event in scanner_events
    )
    assert {
        event["scanner"]
        for event in scanner_events
    } == {
        "gitleaks",
        "semgrep",
        "bandit",
    }
    assert all(
        event["duration_ms"] is not None
        for event in scanner_events
    )
    assert final_job["_stage_events"]
    assert all(
        event["status"] != "in_progress"
        for event in final_job["_stage_events"]
    )
    assert final_job["_total_duration_ms"] >= 0
    assert published["review"] is not None
    assert published["report_token"]
