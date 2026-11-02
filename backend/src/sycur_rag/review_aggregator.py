from __future__ import annotations

from sycur_rag.models.finding import (
    ReviewedFinding,
)
from sycur_rag.models.review import (
    ReviewResult,
)
from sycur_rag.policy_engine import (
    PolicyDecision,
    aggregate_review_decisions,
)


def aggregate_review(
    findings: list[ReviewedFinding],
) -> ReviewResult:
    if not isinstance(
        findings,
        list,
    ):
        raise TypeError(
            "findings must be a list."
        )

    for index, finding in enumerate(
        findings
    ):
        if not isinstance(
            finding,
            ReviewedFinding,
        ):
            raise TypeError(
                "Finding at index "
                f"{index} must be a "
                "ReviewedFinding."
            )

    # ------------------------------------------
    # Defensive duplicate detection before
    # aggregation.
    # ------------------------------------------

    finding_ids = [
        finding.finding_id
        for finding in findings
    ]

    if len(
        finding_ids
    ) != len(
        set(
            finding_ids
        )
    ):
        raise ValueError(
            "Cannot aggregate duplicate "
            "reviewed findings."
        )

    # ------------------------------------------
    # Convert canonical reviewed findings back
    # into the deterministic policy contract.
    #
    # We do NOT rerun policy rules here.
    # ------------------------------------------

    decisions = [
        PolicyDecision(
            status=finding.status,
            action=finding.action,
            severity=(
                finding.finding.severity
            ),
            reason=(
                finding.policy_reason
            ),
            rule_id=(
                finding.finding.rule_id
            ),
        )
        for finding in findings
    ]

    overall = (
        aggregate_review_decisions(
            decisions
        )
    )

    return ReviewResult(
        status=overall.status,
        action=overall.action,
        severity=overall.severity,
        reason=overall.reason,
        findings=tuple(
            findings
        ),
    )