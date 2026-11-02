import json
import subprocess
from pathlib import Path

import pytest

from sycur_rag.core.enums import Severity
from sycur_rag.scanners import trivy as trivy_module
from sycur_rag.scanners.trivy import (
    TrivyAdapter,
    parse_trivy_output,
)


def create_vulnerability():
    return {
        "VulnerabilityID": "CVE-2025-12345",
        "PkgName": "requests",
        "InstalledVersion": "2.28.0",
        "FixedVersion": "2.31.0",
        "Severity": "HIGH",
        "Title": "Example vulnerability",
        "CweIDs": ["CWE-79", "CWE-89"],
    }


def create_payload():
    return {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    create_vulnerability()
                ],
            }
        ]
    }


def create_target(tmp_path):
    target = tmp_path / "requirements.txt"
    target.write_text(
        "requests==2.28.0\n",
        encoding="utf-8",
    )
    return target


def install_successful_trivy(
    monkeypatch,
    payload,
):
    calls = []

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))

        report_path = Path(
            command[command.index("--output") + 1]
        )

        report_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    return calls


# ============================================================
# PARSER TESTS
# ============================================================


def test_valid_trivy_finding(tmp_path):
    target = str(tmp_path / "requirements.txt")

    payload = create_payload()
    payload["Results"][0]["Target"] = target

    findings = parse_trivy_output(
        payload,
        repository_root=tmp_path,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == "trivy"
    assert finding.rule_id == "CVE-2025-12345"
    assert finding.title == "Example vulnerability"
    assert finding.severity == Severity.HIGH
    assert finding.file_path == "requirements.txt"

    assert finding.message == (
        "CVE-2025-12345 affects requests 2.28.0. "
        "Fixed version: 2.31.0."
    )

    assert finding.line_start is None
    assert finding.line_end is None
    assert finding.code_snippet is None

    assert finding.cwe_ids == (
        "CWE-79",
        "CWE-89",
    )

    assert finding.requires_evidence is False


def test_trivy_empty_report_returns_no_findings():
    findings = parse_trivy_output(
        {"Results": []}
    )

    assert findings == []


def test_trivy_null_vulnerabilities_returns_no_findings():
    payload = create_payload()

    payload["Results"][0]["Vulnerabilities"] = None

    findings = parse_trivy_output(payload)

    assert findings == []


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        "invalid",
        {"Results": None},
        {"Results": {}},
    ],
)
def test_trivy_rejects_invalid_payload(payload):
    with pytest.raises(ValueError):
        parse_trivy_output(payload)


def test_trivy_rejects_invalid_result_object():
    with pytest.raises(ValueError):
        parse_trivy_output(
            {"Results": [None]}
        )


def test_trivy_rejects_missing_target():
    with pytest.raises(ValueError):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Vulnerabilities": []
                    }
                ]
            }
        )


def test_trivy_rejects_invalid_vulnerabilities():
    payload = create_payload()

    payload["Results"][0]["Vulnerabilities"] = {}

    with pytest.raises(ValueError):
        parse_trivy_output(payload)


def test_trivy_rejects_invalid_vulnerability_object():
    with pytest.raises(ValueError):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [None],
                    }
                ]
            }
        )


@pytest.mark.parametrize(
    "field",
    [
        "VulnerabilityID",
        "PkgName",
        "InstalledVersion",
        "Severity",
    ],
)
def test_trivy_rejects_missing_required_fields(field):
    vulnerability = create_vulnerability()

    del vulnerability[field]

    with pytest.raises(ValueError):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            vulnerability
                        ],
                    }
                ]
            }
        )


# ============================================================
# SEVERITY TESTS
# ============================================================


@pytest.mark.parametrize(
    ("raw_severity", "expected_severity"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
    ],
)
def test_trivy_severity_mapping(
    raw_severity,
    expected_severity,
):
    vulnerability = create_vulnerability()

    vulnerability["Severity"] = raw_severity

    findings = parse_trivy_output(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        vulnerability
                    ],
                }
            ]
        }
    )

    assert findings[0].severity == expected_severity


def test_trivy_rejects_unknown_severity():
    vulnerability = create_vulnerability()

    vulnerability["Severity"] = "UNKNOWN"

    with pytest.raises(
        ValueError,
        match="UNKNOWN severity",
    ):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            vulnerability
                        ],
                    }
                ]
            }
        )


def test_trivy_rejects_unsupported_severity():
    vulnerability = create_vulnerability()

    vulnerability["Severity"] = "UNDEFINED"

    with pytest.raises(ValueError):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            vulnerability
                        ],
                    }
                ]
            }
        )


# ============================================================
# TITLE AND FIXED VERSION TESTS
# ============================================================


def test_trivy_uses_fallback_title():
    vulnerability = create_vulnerability()

    vulnerability["Title"] = None

    findings = parse_trivy_output(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        vulnerability
                    ],
                }
            ]
        }
    )

    assert findings[0].title == (
        "CVE-2025-12345 in requests"
    )


def test_trivy_handles_missing_fixed_version():
    vulnerability = create_vulnerability()

    vulnerability["FixedVersion"] = None

    findings = parse_trivy_output(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        vulnerability
                    ],
                }
            ]
        }
    )

    assert "Fixed version:" not in findings[0].message


def test_trivy_handles_empty_fixed_version():
    vulnerability = create_vulnerability()

    vulnerability["FixedVersion"] = ""

    findings = parse_trivy_output(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        vulnerability
                    ],
                }
            ]
        }
    )

    assert "Fixed version:" not in findings[0].message


# ============================================================
# CWE TESTS
# ============================================================


def test_trivy_normalizes_cwe_ids():
    vulnerability = create_vulnerability()

    vulnerability["CweIDs"] = [
        "cwe-79",
        "CWE-89",
        "CWE-79",
    ]

    findings = parse_trivy_output(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        vulnerability
                    ],
                }
            ]
        }
    )

    assert findings[0].cwe_ids == (
        "CWE-79",
        "CWE-89",
    )


def test_trivy_handles_missing_cwe_ids():
    vulnerability = create_vulnerability()

    vulnerability["CweIDs"] = None

    findings = parse_trivy_output(
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        vulnerability
                    ],
                }
            ]
        }
    )

    assert findings[0].cwe_ids == ()


@pytest.mark.parametrize(
    "invalid_cwes",
    [
        "CWE-79",
        {},
    ],
)
def test_trivy_rejects_invalid_cwe_collection(
    invalid_cwes,
):
    vulnerability = create_vulnerability()

    vulnerability["CweIDs"] = invalid_cwes

    with pytest.raises(ValueError):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            vulnerability
                        ],
                    }
                ]
            }
        )


def test_trivy_rejects_invalid_cwe_identifier():
    vulnerability = create_vulnerability()

    vulnerability["CweIDs"] = ["INVALID"]

    with pytest.raises(ValueError):
        parse_trivy_output(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            vulnerability
                        ],
                    }
                ]
            }
        )


# ============================================================
# ADAPTER EXECUTION TESTS
# ============================================================


def test_trivy_adapter_successful_execution(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    calls = install_successful_trivy(
        monkeypatch,
        {
            "Results": [
                {
                    "Target": str(target),
                    "Vulnerabilities": [
                        create_vulnerability()
                    ],
                }
            ]
        },
    )

    adapter = TrivyAdapter(
        timeout_seconds=120,
        repository_root=tmp_path,
    )

    findings = adapter.scan(target)

    assert adapter.scanner_name == "trivy"
    assert len(findings) == 1

    assert findings[0].scanner == "trivy"
    assert findings[0].file_path == "requirements.txt"

    assert len(calls) == 1

    command, kwargs = calls[0]

    assert command[0] == "/usr/local/bin/trivy"
    assert command[1] == "fs"

    assert command[
        command.index("--scanners") + 1
    ] == "vuln"

    assert command[
        command.index("--format") + 1
    ] == "json"

    assert command[
        command.index("--exit-code") + 1
    ] == "0"

    assert command[-1] == str(target)

    assert kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 120,
        "check": False,
    }


def test_trivy_rejects_invalid_target_type():
    adapter = TrivyAdapter()

    with pytest.raises(TypeError):
        adapter.scan(123)


def test_trivy_rejects_empty_target():
    adapter = TrivyAdapter()

    with pytest.raises(ValueError):
        adapter.scan("")


def test_trivy_rejects_missing_target(tmp_path):
    adapter = TrivyAdapter()

    with pytest.raises(FileNotFoundError):
        adapter.scan(
            tmp_path / "missing.txt"
        )


def test_trivy_rejects_missing_executable(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: None,
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        RuntimeError,
        match="executable was not found",
    ):
        adapter.scan(target)


def test_trivy_rejects_nonzero_exit_code(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            2,
            "",
            "Database unavailable.",
        )

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        RuntimeError,
        match="Database unavailable",
    ):
        adapter.scan(target)


def test_trivy_handles_execution_timeout(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            timeout=kwargs["timeout"],
        )

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    adapter = TrivyAdapter(
        timeout_seconds=10
    )

    with pytest.raises(
        RuntimeError,
        match="Trivy scan timed out",
    ):
        adapter.scan(target)


def test_trivy_handles_execution_os_error(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    def fake_run(command, **kwargs):
        raise OSError("Execution failed.")

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        RuntimeError,
        match="Failed to execute Trivy",
    ):
        adapter.scan(target)


# ============================================================
# REPORT HANDLING TESTS
# ============================================================


def test_trivy_rejects_missing_report(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        RuntimeError,
        match="did not create",
    ):
        adapter.scan(target)


def test_trivy_rejects_empty_report(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    def fake_run(command, **kwargs):
        report_path = Path(
            command[command.index("--output") + 1]
        )

        report_path.write_text(
            "",
            encoding="utf-8",
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        RuntimeError,
        match="empty report",
    ):
        adapter.scan(target)


def test_trivy_rejects_invalid_json_report(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    def fake_run(command, **kwargs):
        report_path = Path(
            command[command.index("--output") + 1]
        )

        report_path.write_text(
            "{invalid json",
            encoding="utf-8",
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    monkeypatch.setattr(
        trivy_module.shutil,
        "which",
        lambda _: "/usr/local/bin/trivy",
    )

    monkeypatch.setattr(
        trivy_module.subprocess,
        "run",
        fake_run,
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        RuntimeError,
        match="invalid JSON",
    ):
        adapter.scan(target)


def test_trivy_rejects_invalid_json_structure(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    install_successful_trivy(
        monkeypatch,
        {},
    )

    adapter = TrivyAdapter()

    with pytest.raises(
        ValueError,
        match="Results list",
    ):
        adapter.scan(target)


# ============================================================
# CONSTRUCTOR VALIDATION
# ============================================================


def test_trivy_rejects_invalid_executable_type():
    with pytest.raises(TypeError):
        TrivyAdapter(executable=None)


def test_trivy_rejects_empty_executable():
    with pytest.raises(ValueError):
        TrivyAdapter(executable="")


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        1.5,
        True,
    ],
)
def test_trivy_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        TrivyAdapter(
            timeout_seconds=timeout
        )
