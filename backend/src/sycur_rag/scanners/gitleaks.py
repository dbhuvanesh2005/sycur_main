from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import (
    ScannerAdapter,
    deduplicate_scanner_findings,
    normalize_scanner_path,
)


GITLEAKS_DEFAULT_SEVERITY = Severity.HIGH


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


def _positive_int(
    value: object,
    *,
    field_name: str,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
    ):
        raise ValueError(
            f"{field_name} must be a "
            "positive integer."
        )

    return value


def _extract_end_line(
    value: object,
    *,
    line_start: int,
) -> int:
    if value is None:
        return line_start

    line_end = _positive_int(
        value,
        field_name="EndLine",
    )

    if line_end < line_start:
        raise ValueError(
            "EndLine cannot be before StartLine."
        )

    return line_end


def _parse_gitleaks_finding(
    raw_finding: object,
    *,
    repository_root: str | Path | None,
) -> ScannerFinding:
    finding = _required_dict(
        raw_finding,
        field_name="Gitleaks finding",
    )

    rule_id = _required_text(
        finding.get("RuleID"),
        field_name="RuleID",
    )

    description = _required_text(
        finding.get("Description"),
        field_name="Description",
    )

    file_path = _required_text(
        finding.get("File"),
        field_name="File",
    )

    line_start = _positive_int(
        finding.get("StartLine"),
        field_name="StartLine",
    )

    line_end = _extract_end_line(
        finding.get("EndLine"),
        line_start=line_start,
    )

    normalized_path = normalize_scanner_path(
        file_path,
        repository_root=repository_root,
    )

    # SECURITY:
    #
    # Do NOT copy these Gitleaks fields:
    #
    # - Secret
    # - Match
    # - Line
    #
    # They can contain real credentials.
    #
    # Gitleaks is also executed with --redact=100,
    # but we enforce the boundary again here.

    message = (
        "Gitleaks detected a potential secret "
        f"matching rule '{description}'."
    )

    return ScannerFinding(
        scanner="gitleaks",
        rule_id=rule_id,
        title=description,
        message=message,
        severity=GITLEAKS_DEFAULT_SEVERITY,
        file_path=normalized_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=None,
        cwe_ids=(),
        requires_evidence=False,
    )


def parse_gitleaks_output(
    payload: object,
    *,
    repository_root: str | Path | None = None,
) -> list[ScannerFinding]:
    if not isinstance(
        payload,
        list,
    ):
        raise ValueError(
            "Gitleaks JSON report must be a list."
        )

    findings = [
        _parse_gitleaks_finding(
            raw_finding,
            repository_root=repository_root,
        )
        for raw_finding in payload
    ]

    return deduplicate_scanner_findings(
        findings
    )


class GitleaksAdapter(ScannerAdapter):
    def __init__(
        self,
        *,
        executable: str = "gitleaks",
        timeout_seconds: int = 300,
        repository_root: str | Path | None = None,
    ) -> None:
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
        return "gitleaks"

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
                "Gitleaks scan target "
                f"does not exist: {target}"
            )

        executable_path = shutil.which(
            self._executable
        )

        if executable_path is None:
            raise RuntimeError(
                "Gitleaks executable was not found."
            )

        with tempfile.TemporaryDirectory(
            prefix="sycur-gitleaks-"
        ) as temporary_directory:
            report_path = (
                Path(temporary_directory)
                / "gitleaks-report.json"
            )

            command = [
                executable_path,
                "dir",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--redact=100",
                "--exit-code",
                "0",
                "--no-banner",
                "--no-color",
                str(target),
            ]

            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds,
                    check=False,
                )

            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    "Gitleaks scan timed out."
                ) from exc

            except OSError as exc:
                raise RuntimeError(
                    "Failed to execute Gitleaks."
                ) from exc

            if completed.returncode != 0:
                stderr = (
                    completed.stderr.strip()
                )

                message = (
                    "Gitleaks scan failed with "
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

            if not report_path.exists():
                raise RuntimeError(
                    "Gitleaks did not create "
                    "the requested JSON report."
                )

            raw_report = report_path.read_text(
                encoding="utf-8"
            ).strip()

            if not raw_report:
                raise RuntimeError(
                    "Gitleaks returned an "
                    "empty report."
                )

            try:
                payload = json.loads(
                    raw_report
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Gitleaks returned invalid JSON."
                ) from exc

            return parse_gitleaks_output(
                payload,
                repository_root=(
                    self._repository_root
                ),
            )
