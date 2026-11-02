from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding


CWE_PATTERN = re.compile(
    r"^CWE-\d+$",
    re.IGNORECASE,
)


class ScannerAdapter(ABC):
    """
    Common contract for all SYCUR scanner adapters.

    Concrete adapters:
    - Semgrep
    - Bandit
    - Gitleaks
    - Trivy
    - OSV-Scanner
    - Checkov

    must convert their native output into
    ScannerFinding objects.
    """

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def scan(
        self,
        target_path: str | Path,
    ) -> list[ScannerFinding]:
        raise NotImplementedError


def normalize_scanner_path(
    file_path: str | Path,
    *,
    repository_root: str | Path | None = None,
) -> str:
    if not isinstance(
        file_path,
        (str, Path),
    ):
        raise TypeError(
            "file_path must be a string or Path."
        )

    raw = str(
        file_path
    ).strip()

    if not raw:
        raise ValueError(
            "file_path cannot be empty."
        )

    path = Path(
        raw
    ).expanduser()

    if repository_root is not None:
        if not isinstance(
            repository_root,
            (str, Path),
        ):
            raise TypeError(
                "repository_root must be "
                "a string, Path, or None."
            )

        root = Path(
            repository_root
        ).expanduser().resolve()

        if path.is_absolute():
            resolved = path.resolve()

            try:
                return resolved.relative_to(
                    root
                ).as_posix()

            except ValueError:
                return resolved.as_posix()

    return path.as_posix()


def normalize_cwe_ids(
    values: list[str] | tuple[str, ...] | None,
) -> tuple[str, ...]:
    if values is None:
        return ()

    if not isinstance(
        values,
        (list, tuple),
    ):
        raise TypeError(
            "CWE values must be a list, "
            "tuple, or None."
        )

    normalized: list[str] = []

    for index, value in enumerate(
        values
    ):
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "CWE value at index "
                f"{index} must be a string."
            )

        cleaned = (
            value.strip().upper()
        )

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


def normalize_scanner_severity(
    value: str | Severity,
    *,
    aliases: dict[str, Severity] | None = None,
) -> Severity:
    if isinstance(
        value,
        Severity,
    ):
        return value

    if not isinstance(
        value,
        str,
    ):
        raise TypeError(
            "Scanner severity must be "
            "a string or Severity."
        )

    cleaned = (
        value.strip().upper()
    )

    if not cleaned:
        raise ValueError(
            "Scanner severity cannot be empty."
        )

    # Exact SYCUR severity values are always valid.
    for severity in Severity:
        if cleaned == severity.value.upper():
            return severity

    if aliases is not None:
        normalized_aliases = {
            key.strip().upper():
            severity
            for key, severity
            in aliases.items()
        }

        mapped = (
            normalized_aliases.get(
                cleaned
            )
        )

        if mapped is not None:
            if not isinstance(
                mapped,
                Severity,
            ):
                raise TypeError(
                    "Severity alias values must "
                    "be Severity enums."
                )

            return mapped

    raise ValueError(
        "Unsupported scanner severity: "
        f"{value}"
    )


def deduplicate_scanner_findings(
    findings: list[ScannerFinding],
) -> list[ScannerFinding]:
    if not isinstance(
        findings,
        list,
    ):
        raise TypeError(
            "findings must be a list."
        )

    output: list[
        ScannerFinding
    ] = []

    seen: set[str] = set()

    for index, finding in enumerate(
        findings
    ):
        if not isinstance(
            finding,
            ScannerFinding,
        ):
            raise TypeError(
                "Finding at index "
                f"{index} must be a "
                "ScannerFinding."
            )

        if finding.finding_id in seen:
            continue

        seen.add(
            finding.finding_id
        )

        output.append(
            finding
        )

    return output