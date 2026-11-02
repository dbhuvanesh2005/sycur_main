from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import (
    ScannerAdapter,
    deduplicate_scanner_findings,
    normalize_cwe_ids,
    normalize_scanner_path,
    normalize_scanner_severity,
)

from sycur_rag.scanners.isolated_runner import run_isolated_command


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


def _extract_line_end(
    raw_result: dict,
    *,
    line_start: int,
) -> int:
    line_range = raw_result.get(
        "line_range"
    )

    if line_range is None:
        return line_start

    if not isinstance(
        line_range,
        list,
    ):
        raise ValueError(
            "line_range must be a list."
        )

    valid_lines: list[int] = []

    for value in line_range:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        ):
            raise ValueError(
                "line_range contains an "
                "invalid line number."
            )

        valid_lines.append(
            value
        )

    if not valid_lines:
        return line_start

    return max(
        line_start,
        max(valid_lines),
    )


def _extract_cwe(
    raw_result: dict,
) -> tuple[str, ...]:
    issue_cwe = raw_result.get(
        "issue_cwe"
    )

    if issue_cwe is None:
        return ()

    if not isinstance(
        issue_cwe,
        dict,
    ):
        raise ValueError(
            "issue_cwe must be an object."
        )

    raw_id = issue_cwe.get(
        "id"
    )

    if raw_id is None:
        return ()

    if isinstance(
        raw_id,
        bool,
    ):
        raise ValueError(
            "issue_cwe.id is invalid."
        )

    if isinstance(
        raw_id,
        int,
    ):
        if raw_id <= 0:
            raise ValueError(
                "issue_cwe.id must be positive."
            )

        cwe = f"CWE-{raw_id}"

    elif isinstance(
        raw_id,
        str,
    ):
        cleaned = raw_id.strip()

        if not cleaned:
            return ()

        if cleaned.upper().startswith(
            "CWE-"
        ):
            cwe = cleaned
        elif cleaned.isdigit():
            cwe = f"CWE-{cleaned}"
        else:
            raise ValueError(
                "issue_cwe.id is invalid."
            )

    else:
        raise ValueError(
            "issue_cwe.id is invalid."
        )

    return normalize_cwe_ids(
        [cwe]
    )


def _extract_code(
    raw_result: dict,
) -> str | None:
    value = raw_result.get(
        "code"
    )

    if value is None:
        return None

    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            "code must be a string."
        )

    if not value.strip():
        return None

    return value


def _parse_bandit_result(
    raw_result: object,
    *,
    repository_root: str | Path | None,
) -> ScannerFinding:
    result = _required_dict(
        raw_result,
        field_name="Bandit result",
    )

    test_id = _required_text(
        result.get("test_id"),
        field_name="test_id",
    )

    test_name = _required_text(
        result.get("test_name"),
        field_name="test_name",
    )

    message = _required_text(
        result.get("issue_text"),
        field_name="issue_text",
    )

    severity = (
        normalize_scanner_severity(
            _required_text(
                result.get(
                    "issue_severity"
                ),
                field_name=(
                    "issue_severity"
                ),
            )
        )
    )

    filename = _required_text(
        result.get("filename"),
        field_name="filename",
    )

    line_start = _positive_int(
        result.get("line_number"),
        field_name="line_number",
    )

    line_end = _extract_line_end(
        result,
        line_start=line_start,
    )

    file_path = normalize_scanner_path(
        filename,
        repository_root=(
            repository_root
        ),
    )

    cwe_ids = _extract_cwe(
        result
    )

    code_snippet = _extract_code(
        result
    )

    return ScannerFinding(
        scanner="bandit",
        rule_id=test_id,
        title=test_name,
        message=message,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=code_snippet,
        cwe_ids=cwe_ids,
        requires_evidence=False,
    )


def parse_bandit_output(
    payload: object,
    *,
    repository_root: str | Path | None = None,
) -> list[ScannerFinding]:
    data = _required_dict(
        payload,
        field_name="Bandit payload",
    )

    errors = data.get(
        "errors",
        [],
    )

    if not isinstance(
        errors,
        list,
    ):
        raise ValueError(
            "Bandit errors must be a list."
        )

    # Never silently accept a partial scan.
    if errors:
        raise RuntimeError(
            "Bandit reported scan errors: "
            + json.dumps(
                errors,
                ensure_ascii=False,
            )
        )

    raw_results = data.get(
        "results"
    )

    if not isinstance(
        raw_results,
        list,
    ):
        raise ValueError(
            "Bandit payload must contain "
            "a results list."
        )

    findings = [
        _parse_bandit_result(
            result,
            repository_root=(
                repository_root
            ),
        )
        for result in raw_results
    ]

    return deduplicate_scanner_findings(
        findings
    )


class BanditAdapter(ScannerAdapter):
    def __init__(
        self,
        *,
        executable: str = "bandit",
        timeout_seconds: int = 300,
        repository_root: str | Path | None = None,
        isolated: bool = False,
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

        if type(isolated) is not bool:
            raise TypeError("isolated must be bool.")
        self._isolated = isolated

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
        return "bandit"

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
                "Bandit scan target "
                f"does not exist: {target}"
            )

        if self._isolated:
            workspace = (
                target.resolve()
                if target.is_dir()
                else target.parent.resolve()
            )

            command = [
                "bandit",
                "-f", "json",
                "--exit-zero",
            ]

            if target.is_dir():
                command.append("-r")

            command.append(
                "." if target.is_dir() else target.name
            )

            completed = run_isolated_command(
                workspace=workspace,
                image="sycur-bandit:1.9.4",
                command=command,
                timeout_seconds=self._timeout_seconds,
            )

            # Convert container paths back to original
            # workspace paths for existing SYCUR parsing.
            try:
                report = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Bandit returned invalid JSON "
                    "from isolated execution."
                ) from exc

            if (
                not isinstance(report, dict)
                or not isinstance(report.get("results"), list)
            ):
                raise RuntimeError("Invalid isolated Bandit report.")

            for entry in report["results"]:
                if not isinstance(entry, dict):
                    raise RuntimeError("Invalid Bandit finding.")

                filename = entry.get("filename")

                if not isinstance(filename, str):
                    raise RuntimeError("Invalid Bandit filename.")

                if filename.startswith("/workspace/"):
                    relative = filename[len("/workspace/"):]
                else:
                    relative = filename.removeprefix("./")

                relative_path = Path(relative)

                if (
                    not relative
                    or relative_path.is_absolute()
                    or ".." in relative_path.parts
                ):
                    raise RuntimeError("Unsafe Bandit finding path.")

                resolved = (workspace / relative_path).resolve()

                if (
                    not resolved.is_relative_to(workspace)
                    or not resolved.is_file()
                ):
                    raise RuntimeError(
                        "Bandit finding escaped the workspace."
                    )

                entry["filename"] = str(resolved)

            completed = subprocess.CompletedProcess(
                args=completed.args,
                returncode=completed.returncode,
                stdout=json.dumps(report),
                stderr=completed.stderr,
            )

        else:
            executable_path = shutil.which(
                self._executable
            )

            if executable_path is None:
                raise RuntimeError(
                    "Bandit executable was not found."
                )

            command = [
                executable_path,
                "-f",
                "json",
                "--exit-zero",
            ]

            if target.is_dir():
                command.append(
                    "-r"
                )

            command.append(
                str(target)
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
                    "Bandit scan timed out."
                ) from exc

            except OSError as exc:
                raise RuntimeError(
                    "Failed to execute Bandit."
                ) from exc

        if completed.returncode != 0:
            stderr = (
                completed.stderr.strip()
            )

            message = (
                "Bandit scan failed with "
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
                "Bandit returned empty output."
            )

        try:
            payload = json.loads(
                stdout
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Bandit returned invalid JSON."
            ) from exc

        return parse_bandit_output(
            payload,
            repository_root=(
                self._repository_root
            ),
        )
