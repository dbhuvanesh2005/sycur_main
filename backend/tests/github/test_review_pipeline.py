import pytest

import sycur_rag.github.review_pipeline as review_pipeline

from sycur_rag.core.enums import (
    ReviewStatus,
    Severity,
)
from sycur_rag.github.review_pipeline import (
    evaluate_completed_scan,
)
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.orchestrator import (
    ScannerOrchestrationResult,
    ScannerPlanItem,
    ScannerRunFailure,
)


def create_scan_result():
    findings = (
        ScannerFinding(
            scanner="semgrep",
            rule_id="TEST-001",
            title="First security finding",
            message="First test security issue.",
            severity=Severity.MEDIUM,
            file_path="src/first.py",
            line_start=10,
            line_end=10,
        ),
        ScannerFinding(
            scanner="semgrep",
            rule_id="TEST-002",
            title="Second security finding",
            message="Second test security issue.",
            severity=Severity.HIGH,
            file_path="src/second.py",
            line_start=20,
            line_end=20,
        ),
    )

    return ScannerOrchestrationResult(
        findings=findings,
        failures=(),
        plan=(
            ScannerPlanItem(
                scanner="semgrep",
                file_paths=(
                    "src/first.py",
                    "src/second.py",
                ),
            ),
        ),
        successful_runs=1,
    )


def test_all_explanations_finish_before_policy(monkeypatch):
    result = create_scan_result()
    events = []

    original_policy = (
        review_pipeline.decide_finding_policy
    )

    def tracked_policy(policy_input):
        events.append("POLICY")
        return original_policy(policy_input)

    def explain_finding(finding):
        events.append(
            f"EXPLANATION:{finding.rule_id}"
        )
        return None

    def progress_callback(stage):
        events.append(f"STAGE:{stage}")

    monkeypatch.setattr(
        review_pipeline,
        "decide_finding_policy",
        tracked_policy,
    )

    review = evaluate_completed_scan(
        result,
        explain_finding=explain_finding,
        progress_callback=progress_callback,
    )

    explanation_positions = [
        index
        for index, event in enumerate(events)
        if event.startswith("EXPLANATION:")
    ]

    policy_stage_position = events.index(
        "STAGE:POLICY_EVALUATION"
    )

    policy_positions = [
        index
        for index, event in enumerate(events)
        if event == "POLICY"
    ]

    assert len(explanation_positions) == 2
    assert len(policy_positions) == 2

    assert max(explanation_positions) < policy_stage_position
    assert policy_stage_position < min(policy_positions)

    assert len(review.findings) == 2

    print("PASS: All explanations completed first")
    print("PASS: Policy evaluation started afterward")
    print("PASS: Final review aggregated")


def test_ai_failure_preserves_deterministic_policy():
    result = create_scan_result()

    def failing_explanation(finding):
        raise RuntimeError(
            "Simulated AI explanation failure."
        )

    review = evaluate_completed_scan(
        result,
        explain_finding=failing_explanation,
    )

    findings_by_rule = {
        item.finding.rule_id: item
        for item in review.findings
    }

    assert review.status == ReviewStatus.FAIL

    assert len(review.findings) == 2

    assert (
        findings_by_rule["TEST-001"].status
        == ReviewStatus.WARNING
    )

    assert (
        findings_by_rule["TEST-002"].status
        == ReviewStatus.FAIL
    )

    assert all(
        not item.explanation_available
        for item in review.findings
    )

    print("PASS: AI failure handled")
    print("PASS: Medium finding remains WARNING")
    print("PASS: High finding remains FAIL")
    print("PASS: Deterministic policy preserved")


def test_incomplete_scan_is_rejected():
    result = ScannerOrchestrationResult(
        findings=(),
        failures=(
            ScannerRunFailure(
                scanner="semgrep",
                file_paths=("src/example.py",),
                error_type="RuntimeError",
                message="Simulated scanner failure.",
            ),
        ),
        plan=(
            ScannerPlanItem(
                scanner="semgrep",
                file_paths=("src/example.py",),
            ),
        ),
        successful_runs=0,
    )

    with pytest.raises(
        RuntimeError,
        match="incomplete security scan",
    ):
        evaluate_completed_scan(result)

    print("PASS: Incomplete scan rejected")
    print("PASS: Incomplete scan cannot produce PASS")
