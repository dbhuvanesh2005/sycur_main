from types import SimpleNamespace

from sycur_rag.core.enums import (
    PolicyAction,
    ReviewStatus,
    Severity,
)
from sycur_rag.github import review_runner
from sycur_rag.models.review import ReviewResult


def test_runner_forwards_scanner_events_unchanged(
    monkeypatch,
):
    scanner_events = [
        {
            "scanner": "semgrep",
            "status": "completed",
            "targeted_files": ["src/app.py"],
            "targeted_file_count": 1,
            "started_at": "2026-11-02T10:00:00.000Z",
            "completed_at": "2026-11-02T10:00:01.000Z",
            "duration_ms": 1000,
            "findings_count": 1,
            "error_type": None,
            "error_message": None,
        }
    ]
    stage_events = [
        {
            "stage": "CODE_SCAN",
            "status": "completed",
            "duration_ms": 1000,
        }
    ]
    job = {
        "repository": "test-owner/test-repo",
        "installation_id": 1,
        "head_sha": "a" * 40,
        "pr_number": 17,
        "_scanner_events": scanner_events,
        "_stage_events": stage_events,
        "_total_duration_ms": 1250,
    }
    review = ReviewResult(
        status=ReviewStatus.PASS,
        action=PolicyAction.ALLOW,
        severity=Severity.NOT_APPLICABLE,
        reason="No security findings detected.",
    )
    captured = {}

    monkeypatch.setattr(
        review_runner,
        "get_settings",
        lambda: SimpleNamespace(
            SYCUR_PUBLIC_BASE_URL="https://sycur.example"
        ),
    )

    def fake_publish_github_check_run(**kwargs):
        captured.update(kwargs)
        return {
            "id": 10,
            "html_url": "https://github.example/check/10",
        }

    monkeypatch.setattr(
        review_runner,
        "publish_github_check_run",
        fake_publish_github_check_run,
    )

    review_runner.publish_review_report_to_github(
        job,
        review,
        "r" * 43,
    )

    assert captured["scanner_events"] is scanner_events
    assert captured["stage_events"] is stage_events
    assert captured["total_duration_ms"] == 1250
    assert captured["repository"] == "test-owner/test-repo"
    assert captured["installation_id"] == 1
    assert captured["head_sha"] == "a" * 40
    assert captured["pr_number"] == 17
    assert captured["details_url"] == (
        "https://sycur.example/reports/" + "r" * 43
    )
