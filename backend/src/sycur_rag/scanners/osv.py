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
    normalize_cwe_ids,
    normalize_scanner_path,
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
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    cleaned = value.strip()

    return cleaned or None


def _severity_from_cvss(
    value: object,
) -> Severity:
    if isinstance(value, bool):
        raise ValueError(
            "OSV max_severity is invalid."
        )

    if isinstance(
        value,
        (int, float),
    ):
        score = float(value)

    elif isinstance(value, str):
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "OSV vulnerability group "
                "has no severity score."
            )

        try:
            score = float(cleaned)

        except ValueError as exc:
            raise ValueError(
                "OSV max_severity must be "
                "a numeric CVSS score."
            ) from exc

    else:
        raise ValueError(
            "OSV max_severity must be "
            "a numeric CVSS score."
        )

    if not (
        0.0 <= score <= 10.0
    ):
        raise ValueError(
            "OSV CVSS score must be "
            "between 0.0 and 10.0."
        )

    if score >= 9.0:
        return Severity.CRITICAL

    if score >= 7.0:
        return Severity.HIGH

    if score >= 4.0:
        return Severity.MEDIUM

    if score > 0.0:
        return Severity.LOW

    # A known vulnerability with CVSS 0.0
    # cannot safely be mapped to one of
    # our actionable security severities.
    raise ValueError(
        "OSV vulnerability has CVSS 0.0."
    )


def _normalize_identifier_list(
    values: object,
    *,
    field_name: str,
) -> tuple[str, ...]:
    if values is None:
        return ()

    if not isinstance(
        values,
        list,
    ):
        raise ValueError(
            f"{field_name} must be a list."
        )

    output: list[str] = []

    for index, value in enumerate(
        values
    ):
        if not isinstance(value, str):
            raise ValueError(
                f"{field_name}[{index}] "
                "must be a string."
            )

        cleaned = value.strip()

        if (
            cleaned
            and cleaned not in output
        ):
            output.append(
                cleaned
            )

    return tuple(output)


def _choose_canonical_id(
    identifiers: tuple[str, ...],
) -> str:
    if not identifiers:
        raise ValueError(
            "OSV vulnerability group "
            "contains no identifiers."
        )

    for prefix in (
        "CVE-",
        "GHSA-",
    ):
        for identifier in identifiers:
            if identifier.upper().startswith(
                prefix
            ):
                return identifier

    return identifiers[0]


def _extract_cwes(
    vulnerabilities: list[dict],
) -> tuple[str, ...]:
    raw_cwes: list[str] = []

    for vulnerability in vulnerabilities:
        database_specific = (
            vulnerability.get(
                "database_specific"
            )
        )

        if database_specific is None:
            continue

        if not isinstance(
            database_specific,
            dict,
        ):
            raise ValueError(
                "database_specific must "
                "be an object."
            )

        values = database_specific.get(
            "cwe_ids"
        )

        if values is None:
            continue

        if not isinstance(
            values,
            list,
        ):
            raise ValueError(
                "database_specific.cwe_ids "
                "must be a list."
            )

        for value in values:
            if not isinstance(
                value,
                str,
            ):
                raise ValueError(
                    "OSV CWE IDs must "
                    "be strings."
                )

            raw_cwes.append(
                value
            )

    return normalize_cwe_ids(
        raw_cwes
    )


def _extract_fixed_versions(
    vulnerabilities: list[dict],
) -> tuple[str, ...]:
    fixed_versions: list[str] = []

    for vulnerability in vulnerabilities:
        affected = vulnerability.get(
            "affected",
            [],
        )

        if affected is None:
            continue

        if not isinstance(
            affected,
            list,
        ):
            raise ValueError(
                "OSV affected must be a list."
            )

        for affected_item in affected:
            affected_dict = _required_dict(
                affected_item,
                field_name="affected item",
            )

            ranges = affected_dict.get(
                "ranges",
                [],
            )

            if not isinstance(
                ranges,
                list,
            ):
                raise ValueError(
                    "OSV ranges must be a list."
                )

            for raw_range in ranges:
                range_dict = _required_dict(
                    raw_range,
                    field_name="OSV range",
                )

                events = range_dict.get(
                    "events",
                    [],
                )

                if not isinstance(
                    events,
                    list,
                ):
                    raise ValueError(
                        "OSV events must "
                        "be a list."
                    )

                for raw_event in events:
                    event = _required_dict(
                        raw_event,
                        field_name="OSV event",
                    )

                    fixed = _optional_text(
                        event.get("fixed")
                    )

                    if (
                        fixed is not None
                        and fixed
                        not in fixed_versions
                    ):
                        fixed_versions.append(
                            fixed
                        )

    return tuple(
        fixed_versions
    )


def _find_group_vulnerabilities(
    vulnerabilities: list[dict],
    identifiers: tuple[str, ...],
) -> list[dict]:
    identifier_set = {
        identifier.upper()
        for identifier in identifiers
    }

    matches: list[dict] = []

    for vulnerability in vulnerabilities:
        vulnerability_id = (
            _optional_text(
                vulnerability.get("id")
            )
        )

        aliases = (
            _normalize_identifier_list(
                vulnerability.get(
                    "aliases",
                    []
                ),
                field_name="aliases",
            )
        )

        candidate_ids = set(
            alias.upper()
            for alias in aliases
        )

        if vulnerability_id:
            candidate_ids.add(
                vulnerability_id.upper()
            )

        if (
            candidate_ids
            & identifier_set
        ):
            matches.append(
                vulnerability
            )

    return matches


def _build_title(
    vulnerabilities: list[dict],
    *,
    canonical_id: str,
    package_name: str,
) -> str:
    for vulnerability in vulnerabilities:
        summary = _optional_text(
            vulnerability.get(
                "summary"
            )
        )

        if summary is not None:
            return summary

    return (
        f"{canonical_id} in "
        f"{package_name}"
    )


def _build_message(
    *,
    canonical_id: str,
    package_name: str,
    package_version: str,
    ecosystem: str,
    fixed_versions: tuple[str, ...],
) -> str:
    message = (
        f"{canonical_id} affects "
        f"{package_name} "
        f"{package_version} "
        f"in {ecosystem}."
    )

    if fixed_versions:
        message += (
            " Fixed version(s): "
            + ", ".join(
                fixed_versions
            )
            + "."
        )

    return message


def _parse_package(
    raw_package_result: object,
    *,
    source_path: str,
    repository_root: str | Path | None,
) -> list[ScannerFinding]:
    package_result = _required_dict(
        raw_package_result,
        field_name="OSV package result",
    )

    package = _required_dict(
        package_result.get("package"),
        field_name="package",
    )

    package_name = _required_text(
        package.get("name"),
        field_name="package.name",
    )

    package_version = _required_text(
        package.get("version"),
        field_name="package.version",
    )

    ecosystem = _required_text(
        package.get("ecosystem"),
        field_name="package.ecosystem",
    )

    raw_vulnerabilities = (
        package_result.get(
            "vulnerabilities",
            [],
        )
    )

    if not isinstance(
        raw_vulnerabilities,
        list,
    ):
        raise ValueError(
            "OSV vulnerabilities "
            "must be a list."
        )

    vulnerabilities = [
        _required_dict(
            item,
            field_name="OSV vulnerability",
        )
        for item in raw_vulnerabilities
    ]

    raw_groups = package_result.get(
        "groups",
        [],
    )

    if not isinstance(
        raw_groups,
        list,
    ):
        raise ValueError(
            "OSV groups must be a list."
        )

    findings: list[
        ScannerFinding
    ] = []

    for raw_group in raw_groups:
        group = _required_dict(
            raw_group,
            field_name="OSV group",
        )

        ids = _normalize_identifier_list(
            group.get("ids"),
            field_name="group.ids",
        )

        aliases = _normalize_identifier_list(
            group.get(
                "aliases",
                [],
            ),
            field_name="group.aliases",
        )

        all_identifiers: list[str] = []

        for identifier in (
            *ids,
            *aliases,
        ):
            if (
                identifier
                not in all_identifiers
            ):
                all_identifiers.append(
                    identifier
                )

        identifiers = tuple(
            all_identifiers
        )

        canonical_id = (
            _choose_canonical_id(
                identifiers
            )
        )

        severity = _severity_from_cvss(
            group.get("max_severity")
        )

        group_vulnerabilities = (
            _find_group_vulnerabilities(
                vulnerabilities,
                identifiers,
            )
        )

        title = _build_title(
            group_vulnerabilities,
            canonical_id=canonical_id,
            package_name=package_name,
        )

        fixed_versions = (
            _extract_fixed_versions(
                group_vulnerabilities
            )
        )

        cwe_ids = _extract_cwes(
            group_vulnerabilities
        )

        message = _build_message(
            canonical_id=canonical_id,
            package_name=package_name,
            package_version=(
                package_version
            ),
            ecosystem=ecosystem,
            fixed_versions=(
                fixed_versions
            ),
        )

        file_path = (
            normalize_scanner_path(
                source_path,
                repository_root=(
                    repository_root
                ),
            )
        )

        findings.append(
            ScannerFinding(
                scanner="osv",
                rule_id=canonical_id,
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
        )

    return findings


def parse_osv_output(
    payload: object,
    *,
    repository_root: str | Path | None = None,
) -> list[ScannerFinding]:
    data = _required_dict(
        payload,
        field_name="OSV payload",
    )

    raw_results = data.get(
        "results"
    )

    if not isinstance(
        raw_results,
        list,
    ):
        raise ValueError(
            "OSV payload must contain "
            "a results list."
        )

    findings: list[
        ScannerFinding
    ] = []

    for raw_result in raw_results:
        result = _required_dict(
            raw_result,
            field_name="OSV result",
        )

        source = _required_dict(
            result.get("source"),
            field_name="source",
        )

        source_path = _required_text(
            source.get("path"),
            field_name="source.path",
        )

        packages = result.get(
            "packages",
            [],
        )

        if not isinstance(
            packages,
            list,
        ):
            raise ValueError(
                "OSV packages must be a list."
            )

        for package in packages:
            findings.extend(
                _parse_package(
                    package,
                    source_path=source_path,
                    repository_root=(
                        repository_root
                    ),
                )
            )

    return deduplicate_scanner_findings(
        findings
    )


class OSVScannerAdapter(ScannerAdapter):
    def __init__(
        self,
        *,
        executable: str = "osv-scanner",
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
        return "osv"

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
                "OSV scan target "
                f"does not exist: {target}"
            )

        executable_path = shutil.which(
            self._executable
        )

        if executable_path is None:
            raise RuntimeError(
                "OSV-Scanner executable "
                "was not found."
            )

        command = [
            executable_path,
            "scan",
            "source",
            "--format",
            "json",
        ]

        if target.is_dir():
            command.extend(
                [
                    "--recursive",
                    str(target),
                ]
            )
        else:
            command.extend(
                [
                    "--lockfile",
                    str(target),
                ]
            )

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
                "OSV-Scanner timed out."
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                "Failed to execute "
                "OSV-Scanner."
            ) from exc

        # OSV-Scanner:
        # 0 = clean
        # 1 = vulnerabilities found
        #
        # Both represent a successful scan.
        if completed.returncode not in (
            0,
            1,
        ):
            stderr = (
                completed.stderr.strip()
            )

            message = (
                "OSV-Scanner failed with "
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
                "OSV-Scanner returned "
                "empty JSON output."
            )

        try:
            payload = json.loads(
                stdout
            )
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "OSV-Scanner returned "
                "invalid JSON."
            ) from exc

        return parse_osv_output(
            payload,
            repository_root=(
                self._repository_root
            ),
        )