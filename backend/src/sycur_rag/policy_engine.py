from __future__ import annotations

from dataclasses import dataclass

from sycur_rag.core.enums import (
    PolicyAction,
    ReviewStatus,
    Severity,
)


@dataclass(frozen=True)
class PolicyInput:
    severity: Severity

    finding_present: bool = True

    evidence_sufficient: bool = True

    # Some future compliance decisions may depend
    # on retrieved regulatory/standards evidence.
    #
    # Scanner findings normally set this False.
    requires_evidence: bool = False

    rule_id: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    status: ReviewStatus
    action: PolicyAction
    severity: Severity

    reason: str

    rule_id: str | None = None


def _validate_policy_input(
    policy_input: PolicyInput,
) -> None:
    if not isinstance(
        policy_input,
        PolicyInput,
    ):
        raise TypeError(
            "policy_input must be a PolicyInput."
        )

    if not isinstance(
        policy_input.severity,
        Severity,
    ):
        raise TypeError(
            "severity must be a Severity."
        )

    for field_name, value in (
        (
            "finding_present",
            policy_input.finding_present,
        ),
        (
            "evidence_sufficient",
            policy_input.evidence_sufficient,
        ),
        (
            "requires_evidence",
            policy_input.requires_evidence,
        ),
    ):
        if not isinstance(
            value,
            bool,
        ):
            raise TypeError(
                f"{field_name} must be a boolean."
            )

    if policy_input.rule_id is not None:
        if not isinstance(
            policy_input.rule_id,
            str,
        ):
            raise TypeError(
                "rule_id must be a string or None."
            )

        if not policy_input.rule_id.strip():
            raise ValueError(
                "rule_id cannot be blank."
            )


def decide_finding_policy(
    policy_input: PolicyInput,
) -> PolicyDecision:
    _validate_policy_input(
        policy_input
    )

    # ==========================================
    # No actual finding
    # ==========================================

    if not policy_input.finding_present:
        return PolicyDecision(
            status=ReviewStatus.PASS,
            action=PolicyAction.ALLOW,
            severity=(
                Severity.NOT_APPLICABLE
            ),
            reason=(
                "No applicable security "
                "finding is present."
            ),
            rule_id=(
                policy_input.rule_id
            ),
        )

    # ==========================================
    # Not applicable
    # ==========================================

    if (
        policy_input.severity
        == Severity.NOT_APPLICABLE
    ):
        return PolicyDecision(
            status=ReviewStatus.PASS,
            action=PolicyAction.ALLOW,
            severity=(
                Severity.NOT_APPLICABLE
            ),
            reason=(
                "The finding is marked "
                "not applicable."
            ),
            rule_id=(
                policy_input.rule_id
            ),
        )

    # ==========================================
    # Critical / High scanner findings
    #
    # These remain blocking even when RAG or
    # explanatory evidence is unavailable.
    # ==========================================

    if policy_input.severity in {
        Severity.CRITICAL,
        Severity.HIGH,
    }:
        return PolicyDecision(
            status=ReviewStatus.FAIL,
            action=PolicyAction.BLOCK,
            severity=(
                policy_input.severity
            ),
            reason=(
                "A blocking security finding "
                f"with severity "
                f"{policy_input.severity.value} "
                "is present."
            ),
            rule_id=(
                policy_input.rule_id
            ),
        )

    # ==========================================
    # Evidence-dependent decisions
    #
    # Only use INSUFFICIENT_EVIDENCE when the
    # policy decision actually requires external
    # evidence.
    # ==========================================

    if (
        policy_input.requires_evidence
        and not policy_input.evidence_sufficient
    ):
        return PolicyDecision(
            status=(
                ReviewStatus
                .INSUFFICIENT_EVIDENCE
            ),
            action=(
                PolicyAction
                .MANUAL_REVIEW
            ),
            severity=(
                policy_input.severity
            ),
            reason=(
                "The decision requires trusted "
                "evidence, but sufficient "
                "evidence was not available."
            ),
            rule_id=(
                policy_input.rule_id
            ),
        )

    # ==========================================
    # Medium / Low
    # ==========================================

    if policy_input.severity in {
        Severity.MEDIUM,
        Severity.LOW,
    }:
        return PolicyDecision(
            status=ReviewStatus.WARNING,
            action=PolicyAction.WARN,
            severity=(
                policy_input.severity
            ),
            reason=(
                "A non-blocking security "
                f"finding with severity "
                f"{policy_input.severity.value} "
                "is present."
            ),
            rule_id=(
                policy_input.rule_id
            ),
        )

    raise RuntimeError(
        "No deterministic policy rule "
        "matched the supplied input."
    )


def aggregate_review_decisions(
    decisions: list[PolicyDecision],
) -> PolicyDecision:
    if not isinstance(
        decisions,
        list,
    ):
        raise TypeError(
            "decisions must be a list."
        )

    if not decisions:
        return PolicyDecision(
            status=ReviewStatus.PASS,
            action=PolicyAction.ALLOW,
            severity=(
                Severity.NOT_APPLICABLE
            ),
            reason=(
                "No security findings "
                "require action."
            ),
        )

    for index, decision in enumerate(
        decisions
    ):
        if not isinstance(
            decision,
            PolicyDecision,
        ):
            raise TypeError(
                "Decision at index "
                f"{index} must be a "
                "PolicyDecision."
            )

    # ==========================================
    # Overall review precedence
    #
    # FAIL
    # ↓
    # INSUFFICIENT_EVIDENCE
    # ↓
    # WARNING
    # ↓
    # PASS
    # ==========================================

    failures = [
        decision
        for decision in decisions
        if decision.status
        == ReviewStatus.FAIL
    ]

    if failures:
        highest = _highest_severity(
            failures
        )

        return PolicyDecision(
            status=ReviewStatus.FAIL,
            action=PolicyAction.BLOCK,
            severity=highest,
            reason=(
                f"{len(failures)} blocking "
                "security finding(s) are present."
            ),
        )

    insufficient = [
        decision
        for decision in decisions
        if decision.status
        == ReviewStatus.INSUFFICIENT_EVIDENCE
    ]

    if insufficient:
        highest = _highest_severity(
            insufficient
        )

        return PolicyDecision(
            status=(
                ReviewStatus
                .INSUFFICIENT_EVIDENCE
            ),
            action=(
                PolicyAction
                .MANUAL_REVIEW
            ),
            severity=highest,
            reason=(
                "At least one security decision "
                "requires manual review because "
                "trusted evidence is insufficient."
            ),
        )

    warnings = [
        decision
        for decision in decisions
        if decision.status
        == ReviewStatus.WARNING
    ]

    if warnings:
        highest = _highest_severity(
            warnings
        )

        return PolicyDecision(
            status=ReviewStatus.WARNING,
            action=PolicyAction.WARN,
            severity=highest,
            reason=(
                f"{len(warnings)} warning "
                "finding(s) are present."
            ),
        )

    return PolicyDecision(
        status=ReviewStatus.PASS,
        action=PolicyAction.ALLOW,
        severity=(
            Severity.NOT_APPLICABLE
        ),
        reason=(
            "All evaluated findings passed "
            "deterministic policy."
        ),
    )


def _highest_severity(
    decisions: list[PolicyDecision],
) -> Severity:
    priority = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.NOT_APPLICABLE: 0,
    }

    return max(
        (
            decision.severity
            for decision in decisions
        ),
        key=lambda severity: (
            priority[
                severity
            ]
        ),
    )