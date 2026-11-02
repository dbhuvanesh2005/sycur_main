from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import (
    ScannerAdapter,
    deduplicate_scanner_findings,
    normalize_cwe_ids,
    normalize_scanner_path,
    normalize_scanner_severity,
)


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


def _optional_text(
    value: object,
    *,
    field_name: str,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    cleaned = value.strip()

    if not cleaned:
        return None

    return cleaned


def _extract_cwe_ids(
    vulnerability: dict,
) -> tuple[str, ...]:
    raw_cwes = vulnerability.get(
        "CweIDs"
    )

    if raw_cwes is None:
        return ()

    if not isinstance(
        raw_cwes,
        list,
    ):
        raise ValueError(
            "CweIDs must be a list."
        )

    return normalize_cwe_ids(
        raw_cwes
    )


def _build_title(
    *,
    vulnerability_id: str,
    package_name: str,
    vulnerability: dict,
) -> str:
    title = _optional_text(
        vulnerability.get("Title"),
        field_name="Title",
    )

    if title is not None:
        return title

    return (
        f"{vulnerability_id} in "
        f"{package_name}"
    )


def _build_message(
    *,
    vulnerability_id: str,
    package_name: str,
    installed_version: str,
    fixed_version: str | None,
) -> str:
    message = (
        f"{vulnerability_id} affects "
        f"{package_name} "
        f"{installed_version}."
    )

    if fixed_version is not None:
        message += (
            f" Fixed version: "
            f"{fixed_version}."
        )

    return message


def _parse_trivy_vulnerability(
    vulnerability: object,
    *,
    target: str,
    repository_root: str | Path | None,
) -> ScannerFinding:
    item = _required_dict(
        vulnerability,
        field_name="Trivy vulnerability",
    )

    vulnerability_id = _required_text(
        item.get("VulnerabilityID"),
        field_name="VulnerabilityID",
    )

    package_name = _required_text(
        item.get("PkgName"),
        field_name="PkgName",
    )

    installed_version = _required_text(
        item.get("InstalledVersion"),
        field_name="InstalledVersion",
    )

    raw_severity = _required_text(
        item.get("Severity"),
        field_name="Severity",
    )

    # Do not invent a severity for UNKNOWN.
    #
    # If Trivy cannot classify it, the adapter
    # fails explicitly so orchestration can
    # surface scanner uncertainty instead of
    # silently downgrading the vulnerability.
    if raw_severity.upper() == "UNKNOWN":
        raise ValueError(
            "Trivy vulnerability has "
            "UNKNOWN severity: "
            f"{vulnerability_id}"
        )

    severity = normalize_scanner_severity(
        raw_severity
    )

    fixed_version = _optional_text(
        item.get("FixedVersion"),
        field_name="FixedVersion",
    )

    title = _build_title(
        vulnerability_id=(
            vulnerability_id
        ),
        package_name=package_name,
        vulnerability=item,
    )

    message = _build_message(
        vulnerability_id=(
            vulnerability_id
        ),
        package_name=package_name,
        installed_version=(
            installed_version
        ),
        fixed_version=fixed_version,
    )

    cwe_ids = _extract_cwe_ids(
        item
    )

    file_path = normalize_scanner_path(
        target,
        repository_root=repository_root,
    )

    return ScannerFinding(
        scanner="trivy",
        rule_id=vulnerability_id,
        title=title,
        message=message,
        severity=severity,
        file_path=file_path,
        line_start=None,
        line_end=None,
        code_snippet=None,
        cwe_ids=cwe_ids,
        requires_evidence=False,
    )


def parse_trivy_output(
    payload: object,
    *,
    repository_root: str | Path | None = None,
) -> list[ScannerFinding]:
    data = _required_dict(
        payload,
        field_name="Trivy payload",
    )

    raw_results = data.get(
        "Results"
    )

    if not isinstance(
        raw_results,
        list,
    ):
        raise ValueError(
            "Trivy payload must contain "
            "a Results list."
        )

    findings: list[
        ScannerFinding
    ] = []

    for raw_result in raw_results:
        result = _required_dict(
            raw_result,
            field_name="Trivy result",
        )

        target = _required_text(
            result.get("Target"),
            field_name="Target",
        )

        vulnerabilities = result.get(
            "Vulnerabilities"
        )

        # Trivy commonly uses null when a
        # particular target has no findings.
        if vulnerabilities is None:
            continue

        if not isinstance(
            vulnerabilities,
            list,
        ):
            raise ValueError(
                "Vulnerabilities must be "
                "a list or null."
            )

        for vulnerability in vulnerabilities:
            findings.append(
                _parse_trivy_vulnerability(
                    vulnerability,
                    target=target,
                    repository_root=(
                        repository_root
                    ),
                )
            )

    return deduplicate_scanner_findings(
        findings
    )


class TrivyAdapter(ScannerAdapter):
    def __init__(
        self,
        *,
        executable: str = "trivy",
        timeout_seconds: int = 600,
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
        return "trivy"

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
                "Trivy scan target "
                f"does not exist: {target}"
            )

        executable_path = shutil.which(
            self._executable
        )

        if executable_path is None:
            raise RuntimeError(
                "Trivy executable was not found."
            )

        with tempfile.TemporaryDirectory(
            prefix="sycur-trivy-"
        ) as temporary_directory:
            report_path = (
                Path(temporary_directory)
                / "trivy-report.json"
            )

            command = [
                executable_path,
                "fs",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--output",
                str(report_path),
                "--exit-code",
                "0",
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
                    "Trivy scan timed out."
                ) from exc

            except OSError as exc:
                raise RuntimeError(
                    "Failed to execute Trivy."
                ) from exc

            if completed.returncode != 0:
                stderr = (
                    completed.stderr.strip()
                )

                message = (
                    "Trivy scan failed with "
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
                    "Trivy did not create "
                    "the requested JSON report."
                )

            raw_report = report_path.read_text(
                encoding="utf-8"
            ).strip()

            if not raw_report:
                raise RuntimeError(
                    "Trivy returned an "
                    "empty report."
                )

            try:
                payload = json.loads(
                    raw_report
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Trivy returned invalid JSON."
                ) from exc

            return parse_trivy_output(
                payload,
                repository_root=(
                    self._repository_root
                ),
            )