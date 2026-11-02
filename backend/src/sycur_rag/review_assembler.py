from __future__ import annotations

from sycur_rag.llm import (
    GroundedExplanation,
)
from sycur_rag.models.finding import (
    ReviewedFinding,
    ScannerFinding,
)
from sycur_rag.policy_engine import (
    PolicyDecision,
)


def assemble_reviewed_finding(
    *,
    finding: ScannerFinding,
    policy_decision: PolicyDecision,
    explanation: GroundedExplanation | None = None,
) -> ReviewedFinding:
    if not isinstance(
        finding,
        ScannerFinding,
    ):
        raise TypeError(
            "finding must be a ScannerFinding."
        )

    if not isinstance(
        policy_decision,
        PolicyDecision,
    ):
        raise TypeError(
            "policy_decision must be a "
            "PolicyDecision."
        )

    if (
        explanation is not None
        and not isinstance(
            explanation,
            GroundedExplanation,
        )
    ):
        raise TypeError(
            "explanation must be a "
            "GroundedExplanation or None."
        )

    # ==========================================
    # Policy must belong to this finding
    # ==========================================

    if (
        policy_decision.severity
        != finding.severity
    ):
        raise ValueError(
            "Policy decision severity does not "
            "match scanner finding severity."
        )

    if (
        policy_decision.rule_id
        is not None
        and policy_decision.rule_id
        != finding.rule_id
    ):
        raise ValueError(
            "Policy decision rule_id does not "
            "match scanner finding rule_id."
        )

    # ==========================================
    # LLM unavailable / skipped
    #
    # Deterministic scanner + policy result
    # still survives.
    # ==========================================

    if explanation is None:
        return ReviewedFinding(
            finding=finding,

            status=(
                policy_decision.status
            ),

            action=(
                policy_decision.action
            ),

            policy_reason=(
                policy_decision.reason
            ),

            explanation_available=False,

            finding_summary=None,
            risk_explanation=None,
            required_action=None,

            evidence_sufficient=False,

            source_ids=(),
        )

    # ==========================================
    # Grounded explanation available
    # ==========================================

    return ReviewedFinding(
        finding=finding,

        status=(
            policy_decision.status
        ),

        action=(
            policy_decision.action
        ),

        policy_reason=(
            policy_decision.reason
        ),

        explanation_available=True,

        finding_summary=(
            explanation.finding_summary
        ),

        risk_explanation=(
            explanation.risk_explanation
        ),

        required_action=(
            explanation.required_action
        ),

        evidence_sufficient=(
            explanation.evidence_sufficient
        ),

        source_ids=tuple(
            explanation.source_ids
        ),
        evidence_references=(
            explanation.evidence_references
        ),
    )
