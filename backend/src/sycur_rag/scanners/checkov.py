from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import (
    ScannerAdapter,
    deduplicate_scanner_findings,
    normalize_scanner_path,
    normalize_scanner_severity,
)


DEFAULT_CHECKOV_SEVERITY = Severity.MEDIUM


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
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    cleaned = value.strip()

    return cleaned or None


def _validate_default_severity(
    value: Severity,
) -> Severity:
    if not isinstance(
        value,
        Severity,
    ):
        raise TypeError(
            "default_severity must be Severity."
        )

    if value == Severity.NOT_APPLICABLE:
        raise ValueError(
            "Checkov default severity cannot "
            "be NOT_APPLICABLE."
        )

    return value


def _normalize_overrides(
    value: dict[str, Severity] | None,
) -> dict[str, Severity]:
    if value is None:
        return {}

    if not isinstance(
        value,
        dict,
    ):
        raise TypeError(
            "severity_overrides must be "
            "a dict or None."
        )

    output: dict[str, Severity] = {}

    for raw_check_id, severity in value.items():
        if not isinstance(
            raw_check_id,
            str,
        ):
            raise TypeError(
                "Checkov severity override "
                "IDs must be strings."
            )

        check_id = (
            raw_check_id.strip()
        )

        if not check_id:
            raise ValueError(
                "Checkov severity override "
                "ID cannot be empty."
            )

        if not isinstance(
            severity,
            Severity,
        ):
            raise TypeError(
                "Checkov severity override "
                "values must be Severity."
            )

        if (
            severity
            == Severity.NOT_APPLICABLE
        ):
            raise ValueError(
                "Checkov severity override "
                "cannot be NOT_APPLICABLE."
            )

        output[check_id] = severity

    return output


def _resolve_severity(
    finding: dict,
    *,
    check_id: str,
    default_severity: Severity,
    severity_overrides: dict[str, Severity],
) -> Severity:
    raw_severity = finding.get(
        "severity"
    )

    if raw_severity is not None:
        if not isinstance(
            raw_severity,
            str,
        ):
            raise ValueError(
                "Checkov severity must "
                "be a string."
            )

        if raw_severity.strip():
            return normalize_scanner_severity(
                raw_severity
            )

    override = (
        severity_overrides.get(
            check_id
        )
    )

    if override is not None:
        return override

    return default_severity


def _extract_line_range(
    finding: dict,
) -> tuple[int | None, int | None]:
    raw_range = finding.get(
        "file_line_range"
    )

    if raw_range is None:
        return None, None

    if (
        not isinstance(
            raw_range,
            list,
        )
        or len(raw_range) != 2
    ):
        raise ValueError(
            "file_line_range must contain "
            "exactly two values."
        )

    start, end = raw_range

    for value in (
        start,
        end,
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise ValueError(
                "Checkov line numbers must "
                "be non-negative integers."
            )

    # Terraform-plan JSON can legitimately
    # produce line 0.
    if start == 0:
        return None, None

    if end == 0:
        end = start

    if end < start:
        raise ValueError(
            "Checkov end line cannot be "
            "before start line."
        )

    return start, end


def _extract_file_path(
    finding: dict,
    *,
    repository_root: str | Path | None,
) -> str:
    absolute = _optional_text(
        finding.get(
            "file_abs_path"
        )
    )

    if (
        absolute is not None
        and repository_root is not None
    ):
        return normalize_scanner_path(
            absolute,
            repository_root=(
                repository_root
            ),
        )

    relative = (
        _optional_text(
            finding.get(
                "repo_file_path"
            )
        )
        or _optional_text(
            finding.get(
                "file_path"
            )
        )
    )

    if relative is None:
        raise ValueError(
            "Checkov finding has no file path."
        )

    # Checkov commonly returns paths such as
    # /main.tf even though they are repository
    # relative.
    relative = relative.lstrip(
        "/\\"
    )

    return normalize_scanner_path(
        relative
    )


def _build_message(
    *,
    check_name: str,
    resource: str | None,
    framework: str,
) -> str:
    message = (
        f"Checkov {framework} policy failed: "
        f"{check_name}."
    )

    if resource is not None:
        message += (
            f" Resource: {resource}."
        )

    return message


def _parse_failed_check(
    raw_finding: object,
    *,
    framework: str,
    repository_root: str | Path | None,
    default_severity: Severity,
    severity_overrides: dict[str, Severity],
) -> ScannerFinding:
    finding = _required_dict(
        raw_finding,
        field_name="Checkov failed check",
    )

    check_id = _required_text(
        finding.get("check_id"),
        field_name="check_id",
    )

    check_name = _required_text(
        finding.get("check_name"),
        field_name="check_name",
    )

    resource = _optional_text(
        finding.get("resource")
    )

    severity = _resolve_severity(
        finding,
        check_id=check_id,
        default_severity=(
            default_severity
        ),
        severity_overrides=(
            severity_overrides
        ),
    )

    file_path = _extract_file_path(
        finding,
        repository_root=(
            repository_root
        ),
    )

    line_start, line_end = (
        _extract_line_range(
            finding
        )
    )

    message = _build_message(
        check_name=check_name,
        resource=resource,
        framework=framework,
    )

    return ScannerFinding(
        scanner="checkov",
        rule_id=check_id,
        title=check_name,
        message=message,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=None,
        cwe_ids=(),
        requires_evidence=False,
    )


def _normalize_checkov_documents(
    payload: object,
) -> list[dict]:
    if isinstance(
        payload,
        dict,
    ):
        return [payload]

    if isinstance(
        payload,
        list,
    ):
        documents: list[dict] = []

        for index, item in enumerate(
            payload
        ):
            if not isinstance(
                item,
                dict,
            ):
                raise ValueError(
                    "Checkov result at index "
                    f"{index} must be an object."
                )

            documents.append(
                item
            )

        return documents

    raise ValueError(
        "Checkov JSON must be an object "
        "or list of objects."
    )


def parse_checkov_output(
    payload: object,
    *,
    repository_root: str | Path | None = None,
    default_severity: Severity = (
        DEFAULT_CHECKOV_SEVERITY
    ),
    severity_overrides: (
        dict[str, Severity] | None
    ) = None,
) -> list[ScannerFinding]:
    default_severity = (
        _validate_default_severity(
            default_severity
        )
    )

    normalized_overrides = (
        _normalize_overrides(
            severity_overrides
        )
    )

    documents = (
        _normalize_checkov_documents(
            payload
        )
    )

    findings: list[
        ScannerFinding
    ] = []

    for document in documents:
        framework = _required_text(
            document.get("check_type"),
            field_name="check_type",
        )

        results = _required_dict(
            document.get("results"),
            field_name="results",
        )

        parsing_errors = results.get(
            "parsing_errors",
            [],
        )

        if parsing_errors is None:
            parsing_errors = []

        if not isinstance(
            parsing_errors,
            list,
        ):
            raise ValueError(
                "Checkov parsing_errors "
                "must be a list."
            )

        # Never silently accept a partial
        # IaC scan.
        if parsing_errors:
            raise RuntimeError(
                "Checkov reported parsing "
                "errors: "
                + json.dumps(
                    parsing_errors,
                    ensure_ascii=False,
                )
            )

        failed_checks = results.get(
            "failed_checks",
            [],
        )

        if failed_checks is None:
            failed_checks = []

        if not isinstance(
            failed_checks,
            list,
        ):
            raise ValueError(
                "Checkov failed_checks "
                "must be a list."
            )

        for raw_finding in failed_checks:
            findings.append(
                _parse_failed_check(
                    raw_finding,
                    framework=framework,
                    repository_root=(
                        repository_root
                    ),
                    default_severity=(
                        default_severity
                    ),
                    severity_overrides=(
                        normalized_overrides
                    ),
                )
            )

    return deduplicate_scanner_findings(
        findings
    )


class CheckovAdapter(ScannerAdapter):
    def __init__(
        self,
        *,
        executable: str = "checkov",
        timeout_seconds: int = 600,
        repository_root: str | Path | None = None,
        default_severity: Severity = (
            DEFAULT_CHECKOV_SEVERITY
        ),
        severity_overrides: (
            dict[str, Severity] | None
        ) = None,
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

        self._default_severity = (
            _validate_default_severity(
                default_severity
            )
        )

        self._severity_overrides = (
            _normalize_overrides(
                severity_overrides
            )
        )

    @property
    def scanner_name(
        self,
    ) -> str:
        return "checkov"

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
                "Checkov scan target "
                f"does not exist: {target}"
            )

        executable_path = shutil.which(
            self._executable
        )

        if executable_path is None:
            raise RuntimeError(
                "Checkov executable "
                "was not found."
            )

        command = [
            executable_path,
        ]

        if target.is_dir():
            command.extend(
                [
                    "--directory",
                    str(target),
                ]
            )
        else:
            command.extend(
                [
                    "--file",
                    str(target),
                ]
            )

        command.extend(
            [
                "--output",
                "json",
                "--soft-fail",
                "--skip-results-upload",
                "--skip-framework",
                "secrets",
                "sca_package",
                "sca_image",
            ]
        )

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
                "Checkov scan timed out."
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                "Failed to execute Checkov."
            ) from exc

        if completed.returncode != 0:
            stderr = (
                completed.stderr.strip()
            )

            message = (
                "Checkov scan failed with "
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
                "Checkov returned empty output."
            )

        try:
            payload = json.loads(
                stdout
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Checkov returned invalid JSON."
            ) from exc

        return parse_checkov_output(
            payload,
            repository_root=(
                self._repository_root
            ),
            default_severity=(
                self._default_severity
            ),
            severity_overrides=(
                self._severity_overrides
            ),
        )