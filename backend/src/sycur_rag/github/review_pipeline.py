from __future__ import annotations

import logging
from collections.abc import Callable

from sycur_rag.correlation import correlate_findings
from sycur_rag.llm import GroundedExplanation
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.models.review import ReviewResult
from sycur_rag.policy_engine import (
    PolicyInput,
    decide_finding_policy,
)
from sycur_rag.review_aggregator import aggregate_review
from sycur_rag.review_assembler import assemble_reviewed_finding
from sycur_rag.scanners.orchestrator import (
    ScannerOrchestrationResult,
)


logger = logging.getLogger(__name__)


def evaluate_completed_scan(
    result: ScannerOrchestrationResult,
    *,
    explain_finding: (
        Callable[[ScannerFinding], GroundedExplanation | None]
        | None
    ) = None,
    progress_callback: Callable[[str], None] | None = None,
) -> ReviewResult:
    """
    Convert a complete security scan into
    a deterministic policy review.

    Incomplete or empty scan plans cannot
    produce a PASS review.
    """

    if not isinstance(result, ScannerOrchestrationResult):
        raise TypeError("Invalid scanner result.")

    if (
        progress_callback is not None
        and not callable(progress_callback)
    ):
        raise TypeError(
            "progress_callback must be callable."
        )

    if (
        result.attempted_runs == 0
        or not result.is_complete
        or result.successful_runs != result.attempted_runs
    ):
        raise RuntimeError(
            "Cannot evaluate an incomplete security scan."
        )

    groups = correlate_findings(
        list(result.findings)
    )

    # PASS 1: Complete RAG and AI explanation
    # for every correlated finding before policy evaluation.

    explained_findings: list[
        tuple[
            ScannerFinding,
            GroundedExplanation | None,
        ]
    ] = []

    for group in groups:
        finding = group.primary
        explanation = None

        if explain_finding is not None:
            try:
                explanation = explain_finding(finding)

                if (
                    explanation is not None
                    and not isinstance(
                        explanation,
                        GroundedExplanation,
                    )
                ):
                    raise TypeError(
                        "Invalid AI explanation type."
                    )

            except Exception:
                logger.warning(
                    "AI explanation unavailable; "
                    "preserving deterministic review.",
                    exc_info=True,
                )
                explanation = None

        explained_findings.append(
            (finding, explanation)
        )

    # PASS 2: Begin deterministic policy evaluation
    # only after all finding explanations are complete.

    if progress_callback is not None:
        progress_callback("POLICY_EVALUATION")

    reviewed = []

    for finding, explanation in explained_findings:

        decision = decide_finding_policy(
            PolicyInput(
                severity=finding.severity,
                finding_present=True,
                evidence_sufficient=(
                    not finding.requires_evidence
                ),
                requires_evidence=finding.requires_evidence,
                rule_id=finding.rule_id,
            )
        )

        reviewed.append(
            assemble_reviewed_finding(
                finding=finding,
                policy_decision=decision,
                explanation=explanation,
            )
        )

    return aggregate_review(reviewed)
