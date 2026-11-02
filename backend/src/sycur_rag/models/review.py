from __future__ import annotations

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from sycur_rag.core.enums import (
    PolicyAction,
    ReviewStatus,
    Severity,
)
from sycur_rag.models.finding import (
    ReviewedFinding,
)


class ReviewResult(BaseModel):
    """
    Canonical review-level result.

    Represents the final deterministic outcome
    for a collection of reviewed findings.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    status: ReviewStatus
    action: PolicyAction
    severity: Severity

    reason: str = Field(
        min_length=1,
    )

    findings: tuple[
        ReviewedFinding,
        ...
    ] = ()

    @field_validator(
        "reason",
    )
    @classmethod
    def normalize_reason(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "reason cannot be blank."
            )

        return cleaned

    @model_validator(
        mode="after"
    )
    def validate_review_consistency(
        self,
    ) -> ReviewResult:
        finding_ids = [
            finding.finding_id
            for finding in self.findings
        ]

        if len(
            finding_ids
        ) != len(
            set(
                finding_ids
            )
        ):
            raise ValueError(
                "ReviewResult cannot contain "
                "duplicate findings."
            )

        if not self.findings:
            if (
                self.status
                != ReviewStatus.PASS
            ):
                raise ValueError(
                    "An empty review must "
                    "have PASS status."
                )

            if (
                self.action
                != PolicyAction.ALLOW
            ):
                raise ValueError(
                    "An empty review must "
                    "have ALLOW action."
                )

            if (
                self.severity
                != Severity.NOT_APPLICABLE
            ):
                raise ValueError(
                    "An empty review must "
                    "have N/A severity."
                )

            return self

        statuses = {
            finding.status
            for finding in self.findings
        }

        if (
            self.status
            == ReviewStatus.FAIL
            and ReviewStatus.FAIL
            not in statuses
        ):
            raise ValueError(
                "FAIL review requires at least "
                "one FAIL finding."
            )

        if (
            self.status
            == ReviewStatus
            .INSUFFICIENT_EVIDENCE
            and ReviewStatus.FAIL
            in statuses
        ):
            raise ValueError(
                "INSUFFICIENT_EVIDENCE cannot "
                "override a FAIL finding."
            )

        if (
            self.status
            == ReviewStatus.WARNING
            and (
                ReviewStatus.FAIL
                in statuses
                or ReviewStatus
                .INSUFFICIENT_EVIDENCE
                in statuses
            )
        ):
            raise ValueError(
                "WARNING cannot override FAIL "
                "or INSUFFICIENT_EVIDENCE."
            )

        if (
            self.status
            == ReviewStatus.PASS
            and any(
                status
                != ReviewStatus.PASS
                for status in statuses
            )
        ):
            raise ValueError(
                "PASS review cannot contain "
                "non-PASS findings."
            )

        expected_action = {
            ReviewStatus.PASS:
                PolicyAction.ALLOW,

            ReviewStatus.WARNING:
                PolicyAction.WARN,

            ReviewStatus.FAIL:
                PolicyAction.BLOCK,

            ReviewStatus.INSUFFICIENT_EVIDENCE:
                PolicyAction.MANUAL_REVIEW,
        }[
            self.status
        ]

        if self.action != expected_action:
            raise ValueError(
                "Review action does not match "
                "review status."
            )

        return self

    @computed_field
    @property
    def finding_count(
        self,
    ) -> int:
        return len(
            self.findings
        )

    @computed_field
    @property
    def blocking_count(
        self,
    ) -> int:
        return sum(
            finding.status
            == ReviewStatus.FAIL
            for finding in self.findings
        )

    @computed_field
    @property
    def warning_count(
        self,
    ) -> int:
        return sum(
            finding.status
            == ReviewStatus.WARNING
            for finding in self.findings
        )

    @computed_field
    @property
    def insufficient_evidence_count(
        self,
    ) -> int:
        return sum(
            finding.status
            == ReviewStatus
            .INSUFFICIENT_EVIDENCE
            for finding in self.findings
        )

    @computed_field
    @property
    def explained_count(
        self,
    ) -> int:
        return sum(
            finding.explanation_available
            for finding in self.findings
        )