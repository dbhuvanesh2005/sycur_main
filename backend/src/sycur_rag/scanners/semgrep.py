from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import (
    ScannerAdapter,
    deduplicate_scanner_findings,
    normalize_cwe_ids,
    normalize_scanner_path,
    normalize_scanner_severity,
)


CWE_SEARCH_PATTERN = re.compile(
    r"\bCWE-\d+\b",
    re.IGNORECASE,
)


SEMGREP_SEVERITY_ALIASES = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "EXPERIMENT": Severity.LOW,
}


def _required_dict(
    value: object,
    *,
    field_name: str,
) -> dict:
    if not isinstance(value, dict):
        raise ValueError(
            f"{field_name} must be an object."
        )

    return value


def _required_text(
    value: object,
    *,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    return cleaned


def _optional_positive_int(
    value: object,
    *,
    field_name: str,
) -> int | None:
    if value is None:
        return None

    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
    ):
        raise ValueError(
            f"{field_name} must be a positive integer."
        )

    return value


def _extract_line(
    location: object,
    *,
    field_name: str,
) -> int | None:
    if location is None:
        return None

    location_dict = _required_dict(
        location,
        field_name=field_name,
    )

    return _optional_positive_int(
        location_dict.get("line"),
        field_name=f"{field_name}.line",
    )


def _extract_cwe_values(
    value: object,
) -> list[str]:
    """
    Semgrep metadata may expose CWE information as:

    "CWE-89"

    or

    "CWE-89: SQL Injection"

    or

    [
        "CWE-89",
        "CWE-20: Improper Input Validation"
    ]
    """

    if value is None:
        return []

    raw_values: list[str] = []

    if isinstance(value, str):
        raw_values.append(value)

    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str):
                raw_values.append(item)

    else:
        return []

    cwes: list[str] = []

    for raw_value in raw_values:
        for match in CWE_SEARCH_PATTERN.finditer(
            raw_value
        ):
            cwes.append(
                match.group(0).upper()
            )

    return cwes


def _extract_cwes(
    metadata: dict,
) -> tuple[str, ...]:
    values: list[str] = []

    for key in (
        "cwe",
        "cwes",
        "CWE",
    ):
        values.extend(
            _extract_cwe_values(
                metadata.get(key)
            )
        )

    return normalize_cwe_ids(
        values
    )


def _extract_title(
    *,
    check_id: str,
    message: str,
    metadata: dict,
) -> str:
    for key in (
        "title",
        "short_description",
        "shortDescription",
    ):
        value = metadata.get(key)

        if (
            isinstance(value, str)
            and value.strip()
        ):
            return value.strip()

    # check_id is more stable than using the
    # full finding message as the title.
    return check_id


def _extract_code_snippet(
    extra: dict,
) -> str | None:
    for key in (
        "lines",
        "snippet",
    ):
        value = extra.get(key)

        if (
            isinstance(value, str)
            and value.strip()
        ):
            return value

    return None


def _parse_semgrep_result(
    raw_result: object,
    *,
    repository_root: str | Path | None,
) -> ScannerFinding:
    result = _required_dict(
        raw_result,
        field_name="Semgrep result",
    )

    check_id = _required_text(
        result.get("check_id"),
        field_name="check_id",
    )

    file_path = _required_text(
        result.get("path"),
        field_name="path",
    )

    extra = _required_dict(
        result.get("extra"),
        field_name="extra",
    )

    message = _required_text(
        extra.get("message"),
        field_name="extra.message",
    )

    raw_severity = _required_text(
        extra.get("severity"),
        field_name="extra.severity",
    )

    severity = normalize_scanner_severity(
        raw_severity,
        aliases=SEMGREP_SEVERITY_ALIASES,
    )

    metadata_raw = extra.get(
        "metadata",
        {},
    )

    if metadata_raw is None:
        metadata_raw = {}

    metadata = _required_dict(
        metadata_raw,
        field_name="extra.metadata",
    )

    line_start = _extract_line(
        result.get("start"),
        field_name="start",
    )

    line_end = _extract_line(
        result.get("end"),
        field_name="end",
    )

    if (
        line_start is not None
        and line_end is None
    ):
        line_end = line_start

    normalized_path = (
        normalize_scanner_path(
            file_path,
            repository_root=(
                repository_root
            ),
        )
    )

    cwe_ids = _extract_cwes(
        metadata
    )

    title = _extract_title(
        check_id=check_id,
        message=message,
        metadata=metadata,
    )

    code_snippet = (
        _extract_code_snippet(
            extra
        )
    )

    return ScannerFinding(
        scanner="semgrep",
        rule_id=check_id,
        title=title,
        message=message,
        severity=severity,
        file_path=normalized_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=code_snippet,
        cwe_ids=cwe_ids,
        requires_evidence=False,
    )


def parse_semgrep_output(
    payload: object,
    *,
    repository_root: str | Path | None = None,
) -> list[ScannerFinding]:
    data = _required_dict(
        payload,
        field_name="Semgrep payload",
    )

    raw_results = data.get(
        "results",
    )

    if not isinstance(
        raw_results,
        list,
    ):
        raise ValueError(
            "Semgrep payload must contain "
            "a results list."
        )

    findings = [
        _parse_semgrep_result(
            raw_result,
            repository_root=(
                repository_root
            ),
        )
        for raw_result in raw_results
    ]

    return deduplicate_scanner_findings(
        findings
    )


class SemgrepAdapter(ScannerAdapter):
    def __init__(
        self,
        *,
        config: str = "auto",
        executable: str = "semgrep",
        timeout_seconds: int = 300,
        repository_root: str | Path | None = None,
    ) -> None:
        if not isinstance(
            config,
            str,
        ):
            raise TypeError(
                "config must be a string."
            )

        config = config.strip()

        if not config:
            raise ValueError(
                "config cannot be empty."
            )

        if not isinstance(
            executable,
            str,
        ):
            raise TypeError(
                "executable must be a string."
            )

        executable = executable.strip()

        if not executable:
            raise ValueError(
                "executable cannot be empty."
            )

        if (
            not isinstance(
                timeout_seconds,
                int,
            )
            or isinstance(
                timeout_seconds,
                bool,
            )
            or timeout_seconds <= 0
        ):
            raise ValueError(
                "timeout_seconds must be a "
                "positive integer."
            )

        self._config = config
        self._executable = executable
        self._timeout_seconds = (
            timeout_seconds
        )

        self._repository_root = (
            repository_root
        )

    @property
    def scanner_name(
        self,
    ) -> str:
        return "semgrep"

    def scan(
        self,
        target_path: str | Path,
    ) -> list[ScannerFinding]:
        if not isinstance(
            target_path,
            (str, Path),
        ):
            raise TypeError(
                "target_path must be a "
                "string or Path."
            )

        raw_target = str(
            target_path
        ).strip()

        if not raw_target:
            raise ValueError(
                "target_path cannot be empty."
            )

        target = Path(
            raw_target
        ).expanduser()

        if not target.exists():
            raise FileNotFoundError(
                f"Scan target does not exist: "
                f"{target}"
            )

        executable_path = shutil.which(
            self._executable
        )

        if executable_path is None:
            raise RuntimeError(
                "Semgrep executable was not found."
            )

        command = [
            executable_path,
            "scan",
            "--json",
            "--config",
            self._config,
            str(target),
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=(
                    self._timeout_seconds
                ),
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Semgrep scan timed out."
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                "Failed to execute Semgrep."
            ) from exc

        if completed.returncode != 0:
            stderr = (
                completed.stderr.strip()
            )

            message = (
                "Semgrep scan failed with "
                f"exit code "
                f"{completed.returncode}."
            )

            if stderr:
                message += (
                    f" stderr: {stderr}"
                )

            raise RuntimeError(
                message
            )

        stdout = (
            completed.stdout.strip()
        )

        if not stdout:
            raise RuntimeError(
                "Semgrep returned empty output."
            )

        try:
            payload = json.loads(
                stdout
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Semgrep returned invalid JSON."
            ) from exc

        return parse_semgrep_output(
            payload,
            repository_root=(
                self._repository_root
            ),
        )