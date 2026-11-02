from __future__ import annotations

import hashlib
import re

from pydantic import (
    BaseModel,
    ConfigDict,
    computed_field,
)

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding


CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE,
)


SEVERITY_RANK = {
    Severity.NOT_APPLICABLE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class CorrelatedFinding(BaseModel):
    """
    One developer-facing issue backed by one
    or more raw scanner findings.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    primary: ScannerFinding

    findings: tuple[
        ScannerFinding,
        ...
    ]

    @computed_field
    @property
    def scanners(
        self,
    ) -> tuple[str, ...]:
        scanners: list[str] = []

        for finding in self.findings:
            if finding.scanner not in scanners:
                scanners.append(
                    finding.scanner
                )

        return tuple(scanners)

    @computed_field
    @property
    def cwe_ids(
        self,
    ) -> tuple[str, ...]:
        values: list[str] = []

        for finding in self.findings:
            for cwe_id in finding.cwe_ids:
                if cwe_id not in values:
                    values.append(
                        cwe_id
                    )

        return tuple(values)

    @computed_field
    @property
    def severity(
        self,
    ) -> Severity:
        return max(
            (
                finding.severity
                for finding in self.findings
            ),
            key=lambda severity: (
                SEVERITY_RANK[severity]
            ),
        )

    @computed_field
    @property
    def correlation_id(
        self,
    ) -> str:
        finding_ids = sorted(
            finding.finding_id
            for finding in self.findings
        )

        identity = "\x1f".join(
            finding_ids
        )

        return hashlib.sha256(
            identity.encode(
                "utf-8"
            )
        ).hexdigest()


def _normalized_rule_id(
    finding: ScannerFinding,
) -> str:
    return (
        finding.rule_id
        .strip()
        .upper()
    )


def _is_cve_finding(
    finding: ScannerFinding,
) -> bool:
    return bool(
        CVE_PATTERN.fullmatch(
            _normalized_rule_id(
                finding
            )
        )
    )


def _line_range(
    finding: ScannerFinding,
) -> tuple[int, int] | None:
    if finding.line_start is None:
        return None

    end = (
        finding.line_end
        if finding.line_end is not None
        else finding.line_start
    )

    return (
        finding.line_start,
        end,
    )


def _lines_overlap(
    left: ScannerFinding,
    right: ScannerFinding,
) -> bool:
    left_range = _line_range(
        left
    )

    right_range = _line_range(
        right
    )

    if (
        left_range is None
        or right_range is None
    ):
        return False

    left_start, left_end = (
        left_range
    )

    right_start, right_end = (
        right_range
    )

    return (
        left_start <= right_end
        and right_start <= left_end
    )


def _shared_cwe(
    left: ScannerFinding,
    right: ScannerFinding,
) -> bool:
    return bool(
        set(left.cwe_ids)
        & set(right.cwe_ids)
    )


def _advisory_identifiers(
    finding: ScannerFinding,
) -> set[str]:
    """
    Collect recognized vulnerability advisory IDs.

    Explicit aliases supplied by scanners may connect
    different primary advisory identifiers.
    """

    identifiers = {
        finding.rule_id,
        *finding.vulnerability_aliases,
    }

    advisory_pattern = re.compile(
        r"^(?:"
        r"CVE-\d{4}-\d{4,}"
        r"|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"
        r"|(?:PYSEC|GO|RUSTSEC|OSV)-\d{4}-[A-Z0-9-]+"
        r")$",
        re.IGNORECASE,
    )

    return {
        value.strip().upper()
        for value in identifiers
        if advisory_pattern.fullmatch(
            value.strip()
        )
    }


def _same_dependency_vulnerability(
    left: ScannerFinding,
    right: ScannerFinding,
) -> bool:
    # The findings must belong to the same
    # repository-relative dependency file.
    if left.file_path != right.file_path:
        return False

    left_ids = _advisory_identifiers(left)
    right_ids = _advisory_identifiers(right)

    # Require an actual shared advisory identifier,
    # not just matching package names or CWE IDs.
    if not left_ids or not right_ids:
        return False

    if not left_ids.intersection(right_ids):
        return False

    # Preserve the established legacy behavior:
    # identical CVE IDs with no package metadata.
    if (
        left.package_name is None
        and right.package_name is None
    ):
        return (
            _is_cve_finding(left)
            and _is_cve_finding(right)
            and _normalized_rule_id(left)
            == _normalized_rule_id(right)
        )

    # Cross-advisory matching requires package
    # identity on both sides.
    if (
        left.package_name is None
        or right.package_name is None
    ):
        return False

    if (
        left.package_name.strip().casefold()
        != right.package_name.strip().casefold()
    ):
        return False

    return (
        (left.package_ecosystem or "").strip().casefold()
        ==
        (right.package_ecosystem or "").strip().casefold()
    )


def _same_code_issue(
    left: ScannerFinding,
    right: ScannerFinding,
) -> bool:
    if (
        left.file_path
        != right.file_path
    ):
        return False

    if not _shared_cwe(
        left,
        right,
    ):
        return False

    return _lines_overlap(
        left,
        right,
    )


def findings_correlate(
    left: ScannerFinding,
    right: ScannerFinding,
) -> bool:
    if not isinstance(
        left,
        ScannerFinding,
    ):
        raise TypeError(
            "left must be a ScannerFinding."
        )

    if not isinstance(
        right,
        ScannerFinding,
    ):
        raise TypeError(
            "right must be a ScannerFinding."
        )

    # Correlation here is specifically for
    # independent scanner confirmation.
    if left.scanner == right.scanner:
        return False

    if _same_dependency_vulnerability(
        left,
        right,
    ):
        return True

    if _same_code_issue(
        left,
        right,
    ):
        return True

    return False


def _choose_primary(
    findings: list[ScannerFinding],
) -> ScannerFinding:
    if not findings:
        raise ValueError(
            "findings cannot be empty."
        )

    return max(
        findings,
        key=lambda finding: (
            SEVERITY_RANK[
                finding.severity
            ],
            1
            if finding.code_snippet
            else 0,
            len(
                finding.cwe_ids
            ),
            -(
                finding.line_start
                if finding.line_start
                is not None
                else 10**9
            ),
            finding.scanner,
            finding.rule_id,
        ),
    )


def correlate_findings(
    findings: list[ScannerFinding],
) -> list[CorrelatedFinding]:
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
            ScannerFinding,
        ):
            raise TypeError(
                f"Finding at index {index} "
                "must be a ScannerFinding."
            )

    if not findings:
        return []

    # Union-Find / Disjoint Set.
    #
    # If:
    # A correlates with B
    # B correlates with C
    #
    # all three become one group.
    parents = list(
        range(
            len(findings)
        )
    )

    def find(
        index: int,
    ) -> int:
        while (
            parents[index]
            != index
        ):
            parents[index] = (
                parents[
                    parents[index]
                ]
            )

            index = parents[
                index
            ]

        return index

    def union(
        left_index: int,
        right_index: int,
    ) -> None:
        left_root = find(
            left_index
        )

        right_root = find(
            right_index
        )

        if left_root == right_root:
            return

        # Deterministic root.
        if left_root < right_root:
            parents[
                right_root
            ] = left_root
        else:
            parents[
                left_root
            ] = right_root

    for left_index in range(
        len(findings)
    ):
        for right_index in range(
            left_index + 1,
            len(findings),
        ):
            if findings_correlate(
                findings[left_index],
                findings[right_index],
            ):
                union(
                    left_index,
                    right_index,
                )

    grouped: dict[
        int,
        list[ScannerFinding],
    ] = {}

    for index, finding in enumerate(
        findings
    ):
        root = find(
            index
        )

        grouped.setdefault(
            root,
            [],
        ).append(
            finding
        )

    correlated: list[
        CorrelatedFinding
    ] = []

    for root in sorted(
        grouped
    ):
        group = grouped[
            root
        ]

        primary = _choose_primary(
            group
        )

        ordered = tuple(
            sorted(
                group,
                key=lambda finding: (
                    finding.scanner,
                    finding.rule_id,
                    finding.file_path,
                    finding.line_start
                    or 0,
                    finding.line_end
                    or 0,
                ),
            )
        )

        correlated.append(
            CorrelatedFinding(
                primary=primary,
                findings=ordered,
            )
        )

    return correlated
