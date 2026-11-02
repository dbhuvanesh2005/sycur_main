import json
from types import SimpleNamespace

import pytest

from sycur_rag.core.enums import PolicyAction, ReviewStatus, Severity
from sycur_rag.github import check_publisher as publisher_module
from sycur_rag.github.check_publisher import (
    CHECK_NAME,
    build_check_run_failure_payload,
    build_check_run_payload,
    build_check_run_progress_payload,
    publish_github_check_failure,
    publish_github_check_progress,
)
from sycur_rag.models.review import ReviewResult


def create_scanner_events():
    return [
        {
            "scanner": "gitleaks",
            "status": "completed",
            "duration_ms": 1250,
            "findings_count": 1,
        },
        {
            "scanner": "semgrep",
            "status": "running",
            "duration_ms": None,
            "findings_count": 2,
        },
        {
            "scanner": "bandit",
            "status": "queued",
            "duration_ms": None,
            "findings_count": 0,
        },
        {
            "scanner": "trivy",
            "status": "failed",
            "duration_ms": 250,
            "findings_count": 1,
        },
    ]


def create_final_scanner_events():
    """Six scanners completed successfully with file targets."""

    return [
        {
            "scanner": "gitleaks",
            "status": "completed",
            "duration_ms": 1250,
            "findings_count": 0,
            "targeted_files": [
                "src/auth.py",
                "src/config.py",
            ],
            "targeted_file_count": 2,
        },
        {
            "scanner": "semgrep",
            "status": "completed",
            "duration_ms": 2840,
            "findings_count": 0,
            "targeted_files": [
                "src/auth.py",
                "src/api/routes.py",
            ],
            "targeted_file_count": 2,
        },
        {
            "scanner": "bandit",
            "status": "completed",
            "duration_ms": 920,
            "findings_count": 0,
            "targeted_files": [
                "src/auth.py",
                "src/api/routes.py",
            ],
            "targeted_file_count": 2,
        },
        {
            "scanner": "trivy",
            "status": "completed",
            "duration_ms": 3410,
            "findings_count": 0,
            "targeted_files": [
                "requirements.txt",
                "Dockerfile",
            ],
            "targeted_file_count": 2,
        },
        {
            "scanner": "osv",
            "status": "completed",
            "duration_ms": 1980,
            "findings_count": 0,
            "targeted_files": [
                "requirements.txt",
            ],
            "targeted_file_count": 1,
        },
        {
            "scanner": "checkov",
            "status": "completed",
            "duration_ms": 1760,
            "findings_count": 0,
            "targeted_files": [
                "infra/main.tf",
                "infra/network.tf",
            ],
            "targeted_file_count": 2,
        },
    ]


def create_incomplete_scanner_events():
    """Five completed scanners and one failed scanner."""

    events = create_final_scanner_events()

    events[-1].update({
        "status": "failed",
        "duration_ms": 680,
        "error_type": "ScannerExecutionError",
        "error_message": (
            "Checkov could not parse infra/main.tf: "
            "unsupported attribute."
        ),
    })

    return events


def create_stage_events():
    return [
        {
            "stage": "CODE_SCAN",
            "status": "completed",
            "duration_ms": 1250,
        },
        {
            "stage": "FINDING_ANALYSIS",
            "status": "completed",
            "duration_ms": 500,
        },
        {
            "stage": "RAG_EVALUATION",
            "status": "in_progress",
            "duration_ms": 2000,
        },
    ]


def test_progress_payload_contains_scanner_execution_details():

    payload = build_check_run_progress_payload(
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        stage="CODE_SCAN",
        scanner_events=create_scanner_events(),
    )

    assert payload["name"] == CHECK_NAME
    assert payload["status"] == "in_progress"

    summary = payload["output"]["summary"]

    # Overall scanner progress.
    assert "2/4 finished" in summary
    assert "1 completed" in summary
    assert "1 failed" in summary
    assert "1 running" in summary
    assert "1 queued" in summary

    # Total findings.
    assert "Total findings detected:** 4" in summary

    # Scanner names.
    assert "Gitleaks" in summary
    assert "Semgrep" in summary
    assert "Bandit" in summary
    assert "Trivy" in summary

    # Individual execution statuses.
    assert "Completed" in summary
    assert "Running" in summary
    assert "Queued" in summary
    assert "Failed" in summary

    # Execution durations.
    assert "1.25 s" in summary
    assert "250 ms" in summary
    assert "In progress" in summary

    # Individual findings.
    assert "| Gitleaks |" in summary
    assert "| Semgrep |" in summary


def test_progress_payload_without_scanner_events():

    payload = build_check_run_progress_payload(
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        stage="CODE_SCAN",
    )

    summary = payload["output"]["summary"]

    assert payload["status"] == "in_progress"
    assert "Scanner Execution" not in summary


def test_progress_payload_rejects_invalid_scanner():

    events = create_scanner_events()

    events[0]["scanner"] = "unknown"

    with pytest.raises(ValueError):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            scanner_events=events,
        )


def test_progress_payload_rejects_invalid_scanner_status():

    events = create_scanner_events()

    events[0]["status"] = "unknown"

    with pytest.raises(ValueError):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            scanner_events=events,
        )


def test_scanner_progress_contains_targets_and_redacted_diagnostic():
    events = create_scanner_events()
    events[0].update({
        "targeted_files": [
            "src/auth.py",
            "src/`unsafe`.py",
        ],
        "targeted_file_count": 2,
    })
    events[3].update({
        "targeted_files": ["requirements.txt"],
        "targeted_file_count": 1,
        "error_type": "ScannerExecutionError",
        "error_message": (
            "Authorization: secret-value "
            "password=hunter2 "
            "Bearer bearer-value"
        ),
    })

    payload = build_check_run_progress_payload(
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        stage="CODE_SCAN",
        scanner_events=events,
    )

    summary = payload["output"]["summary"]

    assert "Scanner File Targets" in summary
    assert "Files targeted (2)" in summary
    assert "`src/auth.py`" in summary
    assert "`src/ˋunsafeˋ.py`" in summary
    assert "Scanner Diagnostics" in summary
    assert "ScannerExecutionError" in summary
    assert "[REDACTED]" in summary
    assert "secret-value" not in summary
    assert "hunter2" not in summary
    assert "bearer-value" not in summary


def test_scanner_progress_rejects_file_count_mismatch():
    events = create_scanner_events()
    events[0].update({
        "targeted_files": ["src/auth.py"],
        "targeted_file_count": 2,
    })

    with pytest.raises(
        ValueError,
        match="Scanner file count mismatch",
    ):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            scanner_events=events,
        )


def test_final_payload_contains_stage_and_scanner_intelligence():
    review = ReviewResult(
        status=ReviewStatus.PASS,
        action=PolicyAction.ALLOW,
        severity=Severity.NOT_APPLICABLE,
        reason="No security findings detected.",
    )

    payload = build_check_run_payload(
        head_sha="a" * 40,
        review=review,
        scanner_events=create_scanner_events(),
        stage_events=create_stage_events(),
        total_duration_ms=3750,
    )

    summary = payload["output"]["summary"]

    assert "SYCUR Review Pipeline" in summary
    assert "Scanner Execution" in summary
    assert "2/5 completed" in summary
    assert "2/4 finished" in summary


def test_progress_payload_contains_complete_review_timeline():

    payload = build_check_run_progress_payload(
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        stage="RAG_EVALUATION",
        stage_events=create_stage_events(),
        total_duration_ms=3750,
    )

    summary = payload["output"]["summary"]

    # Review pipeline progress.
    assert "2/5 completed" in summary
    assert "1 running" in summary
    assert "2 pending" in summary

    # All five stages.
    assert "Code Security Analysis" in summary
    assert "Finding Analysis" in summary
    assert "Security Evidence Evaluation" in summary
    assert "Security Explanation" in summary
    assert "Policy Evaluation" in summary

    # Stage statuses.
    assert "Completed" in summary
    assert "Running" in summary
    assert "Pending" in summary

    # Individual durations.
    assert "1.25 s" in summary
    assert "500 ms" in summary
    assert "2.00 s" in summary

    # Total execution duration.
    assert "3.75 s" in summary


def test_progress_payload_rejects_invalid_review_stage():

    events = create_stage_events()
    events[0]["stage"] = "UNKNOWN"

    with pytest.raises(ValueError):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            stage_events=events,
            total_duration_ms=3750,
        )


def test_progress_payload_rejects_invalid_review_stage_status():

    events = create_stage_events()
    events[0]["status"] = "unknown"

    with pytest.raises(ValueError):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            stage_events=events,
            total_duration_ms=3750,
        )


def test_progress_payload_rejects_duplicate_review_stages():

    events = create_stage_events()
    events.append(events[0].copy())

    with pytest.raises(ValueError):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            stage_events=events,
            total_duration_ms=3750,
        )


def test_progress_payload_rejects_negative_total_duration():

    with pytest.raises(ValueError):
        build_check_run_progress_payload(
            repository="test-owner/test-repo",
            pr_number=17,
            head_sha="a" * 40,
            stage="CODE_SCAN",
            stage_events=create_stage_events(),
            total_duration_ms=-100,
        )


class FakeGitHubResponse:

    def __init__(self, status, payload):
        self.status = status
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, *args, **kwargs):
        return self.body


def install_publisher_mocks(monkeypatch, existing):

    captured = {}

    monkeypatch.setattr(
        publisher_module,
        "get_settings",
        lambda: SimpleNamespace(GITHUB_APP_ID=5441706),
    )

    monkeypatch.setattr(
        publisher_module,
        "create_installation_access_token",
        lambda **kwargs: "test-installation-token",
    )

    def fake_find_existing(**kwargs):
        captured["lookup"] = kwargs
        return existing

    monkeypatch.setattr(
        publisher_module,
        "find_existing_github_check_run",
        fake_find_existing,
    )

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout

        return FakeGitHubResponse(
            status=200 if existing else 201,
            payload={
                "id": 987,
                "html_url": (
                    "https://github.com/test-owner/"
                    "test-repo/runs/987"
                ),
            },
        )

    monkeypatch.setattr(
        publisher_module,
        "urlopen",
        fake_urlopen,
    )

    return captured


@pytest.mark.parametrize(
    ("existing", "expected_method", "expected_url"),
    [
        (
            None,
            "POST",
            "https://api.github.com/repos/"
            "test-owner/test-repo/check-runs",
        ),
        (
            {"id": 123},
            "PATCH",
            "https://api.github.com/repos/"
            "test-owner/test-repo/check-runs/123",
        ),
    ],
)
def test_progress_publisher_creates_or_updates_check_run(
    monkeypatch,
    existing,
    expected_method,
    expected_url,
):

    captured = install_publisher_mocks(
        monkeypatch,
        existing,
    )

    scanner_events = [
        {
            "scanner": "gitleaks",
            "status": "completed",
            "duration_ms": 1200,
            "findings_count": 2,
        }
    ]

    stage_events = create_stage_events()

    result = publish_github_check_progress(
        repository="test-owner/test-repo",
        installation_id=1,
        head_sha="a" * 40,
        pr_number=17,
        stage="CODE_SCAN",
        scanner_events=scanner_events,
        stage_events=stage_events,
        total_duration_ms=3750,
    )

    # Verify publisher response.
    assert result["id"] == 987
    assert result["html_url"].endswith("/runs/987")

    request = captured["request"]

    # Verify GitHub API operation.
    assert request.get_method() == expected_method
    assert request.full_url == expected_url
    assert captured["timeout"] == 20

    # Verify authentication.
    assert request.get_header("Authorization") == (
        "Bearer test-installation-token"
    )

    # Inspect actual outgoing GitHub payload.
    payload = json.loads(
        request.data.decode("utf-8")
    )

    assert payload["status"] == "in_progress"

    # POST creates a Check Run with head_sha.
    # PATCH updates the existing Check Run without head_sha.
    if expected_method == "POST":
        assert payload["head_sha"] == "a" * 40
    else:
        assert "head_sha" not in payload

    # Verify scanner information reaches GitHub.
    summary = payload["output"]["summary"]

    assert "Gitleaks" in summary
    assert "Completed" in summary
    assert "1.20 s" in summary
    assert "Total findings detected:** 2" in summary

    # Verify review-stage information reaches GitHub.
    assert "2/5 completed" in summary
    assert "Code Security Analysis" in summary
    assert "Security Evidence Evaluation" in summary
    assert "3.75 s" in summary


def test_final_payload_renders_all_six_completed_scanners():
    review = ReviewResult(
        status=ReviewStatus.PASS,
        action=PolicyAction.ALLOW,
        severity=Severity.NOT_APPLICABLE,
        reason="No security findings detected.",
    )

    payload = build_check_run_payload(
        head_sha="a" * 40,
        review=review,
        scanner_events=create_final_scanner_events(),
    )

    summary = payload["output"]["summary"]

    assert "6/6 finished" in summary
    assert "6 completed" in summary
    assert "0 failed" in summary
    assert "0 running" in summary
    assert "0 queued" in summary

    assert "Total findings detected:** 0" in summary

    for scanner in (
        "Gitleaks",
        "Semgrep",
        "Bandit",
        "Trivy",
        "OSV-Scanner",
        "Checkov",
    ):
        assert scanner in summary

    assert "Scanner File Targets" in summary

    for path in (
        "src/auth.py",
        "src/api/routes.py",
        "requirements.txt",
        "Dockerfile",
        "infra/main.tf",
        "infra/network.tf",
    ):
        assert f"`{path}`" in summary


def test_incomplete_final_payload_exposes_scanner_failure():
    review = ReviewResult(
        status=ReviewStatus.PASS,
        action=PolicyAction.ALLOW,
        severity=Severity.NOT_APPLICABLE,
        reason="No security findings detected.",
    )

    payload = build_check_run_payload(
        head_sha="a" * 40,
        review=review,
        scanner_events=create_incomplete_scanner_events(),
    )

    summary = payload["output"]["summary"]

    assert "6/6 finished" in summary
    assert "5 completed" in summary
    assert "1 failed" in summary

    assert "Scanner Diagnostics" in summary
    assert "Checkov" in summary
    assert "ScannerExecutionError" in summary
    assert "unsupported attribute" in summary

    assert "`infra/main.tf`" in summary

    # Coverage-based PASS/INCOMPLETE enforcement
    # will be implemented in SY-01D.2.


def test_insufficient_evidence_has_action_required_conclusion():
    assert (
        publisher_module.CONCLUSIONS["INSUFFICIENT_EVIDENCE"]
        == "action_required"
    )

    assert publisher_module.CONCLUSIONS["PASS"] == "success"
    assert publisher_module.CONCLUSIONS["WARNING"] == "neutral"
    assert publisher_module.CONCLUSIONS["FAIL"] == "failure"


def test_terminal_failure_payload_closes_check_run():
    payload = build_check_run_failure_payload(
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        error_type="RuntimeError",
        scanner_events=create_incomplete_scanner_events(),
    )

    assert payload["status"] == "completed"
    assert payload["conclusion"] == "failure"

    assert payload["output"]["annotations"] == []

    summary = payload["output"]["summary"]

    assert "Security Assessment Incomplete" in summary
    assert "NOT ISSUED" in summary
    assert "6/6 finished" in summary
    assert "Checkov" in summary
    assert "ScannerExecutionError" in summary
    assert "`infra/main.tf`" in summary


def test_terminal_failure_payload_does_not_leak_exception():
    events = create_incomplete_scanner_events()
    events[-1]["error_message"] = (
        "private-token-value-that-must-not-appear"
    )

    payload = build_check_run_failure_payload(
        repository="test-owner/test-repo",
        pr_number=17,
        head_sha="a" * 40,
        error_type="RuntimeError",
        scanner_events=events,
    )

    summary = payload["output"]["summary"]

    assert "private-token-value" not in summary
    assert "RuntimeError" in summary
    assert "ScannerExecutionError" in summary


@pytest.mark.parametrize(
    ("existing", "expected_method", "expected_url"),
    [
        (
            None,
            "POST",
            "https://api.github.com/repos/"
            "test-owner/test-repo/check-runs",
        ),
        (
            {"id": 123},
            "PATCH",
            "https://api.github.com/repos/"
            "test-owner/test-repo/check-runs/123",
        ),
    ],
)
def test_terminal_failure_publisher_posts_or_patches(
    monkeypatch,
    existing,
    expected_method,
    expected_url,
):
    from io import BytesIO

    captured = {}

    monkeypatch.setattr(
        publisher_module,
        "get_settings",
        lambda: SimpleNamespace(GITHUB_APP_ID=123),
    )
    monkeypatch.setattr(
        publisher_module,
        "create_installation_access_token",
        lambda **kwargs: "test-installation-token",
    )
    monkeypatch.setattr(
        publisher_module,
        "find_existing_github_check_run",
        lambda **kwargs: existing,
    )

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout

        return BytesIO(
            json.dumps({
                "id": 987,
                "html_url": (
                    "https://github.com/test-owner/"
                    "test-repo/runs/987"
                ),
            }).encode("utf-8")
        )

    monkeypatch.setattr(
        publisher_module,
        "urlopen",
        fake_urlopen,
    )

    result = publish_github_check_failure(
        repository="test-owner/test-repo",
        installation_id=1,
        head_sha="a" * 40,
        pr_number=17,
        error_type="RuntimeError",
        scanner_events=create_incomplete_scanner_events(),
    )

    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))

    assert request.get_method() == expected_method
    assert request.full_url == expected_url
    assert captured["timeout"] == 20

    assert request.get_header("Authorization") == (
        "Bearer test-installation-token"
    )

    assert payload["status"] == "completed"
    assert payload["conclusion"] == "failure"
    assert "Security Assessment Incomplete" in (
        payload["output"]["title"]
    )
    assert payload["external_id"]

    if expected_method == "POST":
        assert payload["head_sha"] == "a" * 40
    else:
        assert "head_sha" not in payload

    assert result["id"] == 987


def test_terminal_failure_publisher_surfaces_github_api_error(
    monkeypatch,
):
    monkeypatch.setattr(
        publisher_module,
        "get_settings",
        lambda: SimpleNamespace(GITHUB_APP_ID=123),
    )
    monkeypatch.setattr(
        publisher_module,
        "create_installation_access_token",
        lambda **kwargs: "test-installation-token",
    )
    monkeypatch.setattr(
        publisher_module,
        "find_existing_github_check_run",
        lambda **kwargs: None,
    )

    def failing_urlopen(request, timeout):
        raise OSError("Simulated GitHub API outage")

    monkeypatch.setattr(
        publisher_module,
        "urlopen",
        failing_urlopen,
    )

    with pytest.raises(
        OSError,
        match="Simulated GitHub API outage",
    ):
        publish_github_check_failure(
            repository="test-owner/test-repo",
            installation_id=1,
            head_sha="a" * 40,
            pr_number=17,
            error_type="RuntimeError",
        )
