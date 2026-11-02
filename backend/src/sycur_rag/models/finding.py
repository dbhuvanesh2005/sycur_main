from __future__ import annotations

import hashlib
import re

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


CWE_PATTERN = re.compile(
    r"^CWE-\d+$",
    re.IGNORECASE,
)

SHA256_PATTERN = re.compile(
    r"^[0-9a-f]{64}$"
)

VULNERABILITY_FINGERPRINT_VERSION = "v1"


def _normalize_fingerprint_text(
    value: str,
) -> str:
    """Normalize case-insensitive identity components."""

    return value.strip().casefold()


def _normalize_fingerprint_path(
    value: str,
) -> str:
    """Normalize a repository-relative path without changing case."""

    normalized = value.replace("\\", "/")

    while normalized.startswith("./"):
        normalized = normalized[2:]

    return normalized


def _normalize_code_context(
    value: str,
) -> str:
    """Ignore indentation-only changes in available code context."""

    return "\n".join(
        line.strip()
        for line in value.strip().splitlines()
    )


class ScannerFinding(BaseModel):
    """
    Canonical normalized scanner finding.

    Scanner adapters such as Semgrep, Bandit,
    Gitleaks, Trivy, OSV and Checkov will later
    convert their native output into this model.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    scanner: str = Field(
        min_length=1,
    )

    rule_id: str = Field(
        min_length=1,
    )

    title: str = Field(
        min_length=1,
    )

    message: str = Field(
        min_length=1,
    )

    severity: Severity

    file_path: str = Field(
        min_length=1,
    )

    line_start: int | None = Field(
        default=None,
        ge=1,
    )

    line_end: int | None = Field(
        default=None,
        ge=1,
    )

    code_snippet: str | None = None

    cwe_ids: tuple[str, ...] = ()

    vulnerability_aliases: tuple[str, ...] = ()

    package_name: str | None = None

    package_ecosystem: str | None = None

    tracking_fingerprint: str | None = None

    requires_evidence: bool = False

    @field_validator(
        "scanner",
        "rule_id",
        "title",
        "message",
        "file_path",
    )
    @classmethod
    def normalize_required_text(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "Required finding text "
                "cannot be blank."
            )

        return cleaned

    @field_validator(
        "file_path",
    )
    @classmethod
    def normalize_file_path(
        cls,
        value: str,
    ) -> str:
        return value.replace(
            "\\",
            "/",
        )

    @field_validator(
        "code_snippet",
    )
    @classmethod
    def normalize_code_snippet(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not value.strip():
            raise ValueError(
                "code_snippet cannot be blank."
            )

        return value

    @field_validator(
        "package_name",
        "package_ecosystem",
    )
    @classmethod
    def normalize_optional_identity_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "Package identity fields "
                "cannot be blank."
            )

        return cleaned

    @field_validator(
        "tracking_fingerprint",
    )
    @classmethod
    def normalize_tracking_fingerprint(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()

        if cleaned.lower().startswith("sha256:"):
            cleaned = cleaned[7:]

        cleaned = cleaned.lower()

        if not SHA256_PATTERN.fullmatch(
            cleaned
        ):
            raise ValueError(
                "tracking_fingerprint must be "
                "a valid SHA-256 hex digest."
            )

        return cleaned

    @field_validator(
        "cwe_ids",
    )
    @classmethod
    def normalize_cwe_ids(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized: list[str] = []

        for value in values:
            cleaned = value.strip().upper()

            if not CWE_PATTERN.fullmatch(
                cleaned
            ):
                raise ValueError(
                    f"Invalid CWE ID: {value}"
                )

            if cleaned not in normalized:
                normalized.append(
                    cleaned
                )

        return tuple(
            normalized
        )

    @field_validator("vulnerability_aliases")
    @classmethod
    def normalize_vulnerability_aliases(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = set()

        for value in values:
            if not isinstance(value, str):
                raise ValueError(
                    "Vulnerability aliases must be strings."
                )

            cleaned = value.strip().upper()

            if not cleaned:
                raise ValueError(
                    "Vulnerability aliases cannot be blank."
                )

            if not re.fullmatch(
                r"[A-Z0-9][A-Z0-9._:-]*",
                cleaned,
            ):
                raise ValueError(
                    f"Invalid vulnerability alias: {value}"
                )

            normalized.add(cleaned)

        return tuple(sorted(normalized))

    @model_validator(
        mode="after"
    )
    def validate_location(
        self,
    ) -> ScannerFinding:
        if (
            self.package_ecosystem is not None
            and self.package_name is None
        ):
            raise ValueError(
                "package_ecosystem requires "
                "package_name."
            )

        if (
            self.line_start is None
            and self.line_end is not None
        ):
            raise ValueError(
                "line_end cannot exist "
                "without line_start."
            )

        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end
            < self.line_start
        ):
            raise ValueError(
                "line_end cannot be before "
                "line_start."
            )

        return self

    @computed_field
    @property
    def finding_id(
        self,
    ) -> str:
        """
        Deterministic scanner-finding identity.

        Severity is intentionally excluded:
        changing policy/severity mapping must not
        create a completely new finding identity.
        """

        identity = "\x1f".join(
            [
                self.scanner,
                self.rule_id,
                self.file_path,
                (
                    str(self.line_start)
                    if self.line_start
                    is not None
                    else ""
                ),
                (
                    str(self.line_end)
                    if self.line_end
                    is not None
                    else ""
                ),
                self.message,
            ]
        )

        return hashlib.sha256(
            identity.encode(
                "utf-8"
            )
        ).hexdigest()

    @property
    def tracking_identity(
        self,
    ) -> str:
        """
        Stable tracking identity.

        Prefer the scanner-provided fingerprint.
        Fall back to the existing finding_id
        for backward compatibility.
        """

        if self.tracking_fingerprint is not None:
            return self.tracking_fingerprint

        return self.finding_id

    @property
    def vulnerability_fingerprint(
        self,
    ) -> str:
        """
        Stable, versioned vulnerability identity.

        Unlike ``finding_id``, this identity excludes scanner message
        wording and normally excludes line numbers. Package identity,
        canonical CVE/rule identity, CWE classifications, repository path,
        and available code context are included. Location is used only as a
        conservative fallback when no package or code context is available.
        """

        normalized_rule_id = (
            self.rule_id.strip().upper()
            if re.fullmatch(
                r"CVE-\d{4}-\d{4,}",
                self.rule_id,
                re.IGNORECASE,
            )
            else _normalize_fingerprint_text(
                self.rule_id
            )
        )

        package_identity = ""

        if self.package_name is not None:
            package_identity = ":".join(
                [
                    _normalize_fingerprint_text(
                        self.package_ecosystem or ""
                    ),
                    _normalize_fingerprint_text(
                        self.package_name
                    ),
                ]
            )

        if self.code_snippet is not None:
            context_identity = (
                "code:"
                + _normalize_code_context(
                    self.code_snippet
                )
            )
        elif package_identity:
            context_identity = "package"
        else:
            context_identity = "location:" + ":".join(
                [
                    (
                        str(self.line_start)
                        if self.line_start is not None
                        else ""
                    ),
                    (
                        str(self.line_end)
                        if self.line_end is not None
                        else ""
                    ),
                ]
            )

        identity = "\x1f".join(
            [
                VULNERABILITY_FINGERPRINT_VERSION,
                _normalize_fingerprint_text(
                    self.scanner
                ),
                normalized_rule_id,
                package_identity,
                _normalize_fingerprint_path(
                    self.file_path
                ),
                ",".join(
                    sorted(self.cwe_ids)
                ),
                context_identity,
            ]
        )

        return hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()


class EvidenceReference(BaseModel):
    """Verified metadata for a retrieved evidence source."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    source_id: int = Field(gt=0)
    document_name: str = Field(min_length=1)
    title: str = Field(min_length=1)
    control_id: str | None = None


class ReviewedFinding(BaseModel):
    """
    Final canonical finding consumed by report,
    GitHub and audit layers.

    It contains scanner truth + deterministic
    policy outcome + optional grounded explanation.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    finding: ScannerFinding

    status: ReviewStatus
    action: PolicyAction

    policy_reason: str = Field(
        min_length=1,
    )

    explanation_available: bool

    finding_summary: str | None = None

    risk_explanation: str | None = None

    required_action: str | None = None

    evidence_sufficient: bool = False

    source_ids: tuple[
        int,
        ...
    ] = ()

    evidence_references: tuple[
        EvidenceReference, ...
    ] = ()

    @computed_field
    @property
    def finding_id(
        self,
    ) -> str:
        return self.finding.finding_id

    @field_validator(
        "policy_reason",
    )
    @classmethod
    def normalize_policy_reason(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "policy_reason cannot be blank."
            )

        return cleaned

    @field_validator(
        "finding_summary",
        "risk_explanation",
        "required_action",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "Explanation fields cannot "
                "be blank."
            )

        return cleaned

    @field_validator(
        "source_ids",
    )
    @classmethod
    def validate_source_ids(
        cls,
        values: tuple[
            int,
            ...
        ],
    ) -> tuple[int, ...]:
        if any(
            value <= 0
            for value in values
        ):
            raise ValueError(
                "source_ids must contain only "
                "positive integers."
            )

        if len(values) != len(
            set(values)
        ):
            raise ValueError(
                "source_ids cannot contain "
                "duplicates."
            )

        return values

    @model_validator(
        mode="after"
    )
    def validate_explanation_state(
        self,
    ) -> ReviewedFinding:
        explanation_fields = (
            self.finding_summary,
            self.risk_explanation,
            self.required_action,
        )

        if self.explanation_available:
            if any(
                value is None
                for value
                in explanation_fields
            ):
                raise ValueError(
                    "All explanation fields are "
                    "required when explanation "
                    "is available."
                )

        else:
            if any(
                value is not None
                for value
                in explanation_fields
            ):
                raise ValueError(
                    "Explanation fields must be "
                    "None when explanation is "
                    "unavailable."
                )

            if self.evidence_sufficient:
                raise ValueError(
                    "Evidence cannot be marked "
                    "sufficient when no "
                    "explanation is available."
                )

            if self.source_ids:
                raise ValueError(
                    "source_ids must be empty "
                    "when explanation is "
                    "unavailable."
                )

        if (
            self.evidence_sufficient
            and not self.source_ids
        ):
            raise ValueError(
                "Sufficient evidence requires "
                "at least one cited source."
            )

        if self.evidence_references:
            if not self.explanation_available:
                raise ValueError(
                    "Evidence references require an explanation."
                )

            reference_ids = [
                ref.source_id
                for ref in self.evidence_references
            ]

            if len(reference_ids) != len(set(reference_ids)):
                raise ValueError(
                    "Duplicate evidence reference IDs."
                )

            if not set(reference_ids).issubset(
                set(self.source_ids)
            ):
                raise ValueError(
                    "Evidence references must match cited source IDs."
                )

        return self
