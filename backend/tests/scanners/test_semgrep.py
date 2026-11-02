import json
import subprocess

import pytest

from sycur_rag.core.enums import Severity
from sycur_rag.scanners import semgrep as semgrep_module
from sycur_rag.scanners.semgrep import (
    SemgrepAdapter,
    parse_semgrep_output,
)


def create_semgrep_result():
    return {
        "check_id": "python.security.sql-injection",
        "path": "src/app.py",
        "start": {"line": 10, "col": 1},
        "end": {"line": 12, "col": 20},
        "extra": {
            "message": "Potential SQL injection vulnerability.",
            "severity": "ERROR",
            "metadata": {
                "title": "SQL Injection",
                "cwe": "CWE-89: SQL Injection",
            },
            "lines": "cursor.execute(query)",
        },
    }


def create_payload():
    return {
        "results": [
            create_semgrep_result()
        ]
    }


# ============================================================
# PARSER TESTS
# ============================================================


def test_valid_semgrep_finding(tmp_path):
    findings = parse_semgrep_output(
        create_payload(),
        repository_root=tmp_path,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == "semgrep"
    assert finding.rule_id == "python.security.sql-injection"
    assert finding.title == "SQL Injection"
    assert finding.message == (
        "Potential SQL injection vulnerability."
    )
    assert finding.severity == Severity.HIGH
    assert finding.file_path == "src/app.py"
    assert finding.line_start == 10
    assert finding.line_end == 12
    assert finding.code_snippet == "cursor.execute(query)"
    assert "CWE-89" in finding.cwe_ids
    assert finding.requires_evidence is False


def test_semgrep_empty_report_returns_no_findings():
    findings = parse_semgrep_output(
        {"results": []}
    )

    assert findings == []


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        "invalid",
        {"results": None},
        {"results": {}},
    ],
)
def test_semgrep_rejects_invalid_payload(payload):
    with pytest.raises(ValueError):
        parse_semgrep_output(payload)


def test_semgrep_rejects_invalid_result_object():
    with pytest.raises(ValueError):
        parse_semgrep_output(
            {"results": [None]}
        )


@pytest.mark.parametrize(
    "field",
    [
        "check_id",
        "path",
        "extra",
    ],
)
def test_semgrep_rejects_missing_required_fields(field):
    result = create_semgrep_result()
    del result[field]

    with pytest.raises(ValueError):
        parse_semgrep_output(
            {"results": [result]}
        )


@pytest.mark.parametrize(
    "field",
    [
        "message",
        "severity",
    ],
)
def test_semgrep_rejects_missing_extra_fields(field):
    result = create_semgrep_result()
    del result["extra"][field]

    with pytest.raises(ValueError):
        parse_semgrep_output(
            {"results": [result]}
        )


# ============================================================
# SEVERITY TESTS
# ============================================================


@pytest.mark.parametrize(
    ("raw_severity", "expected_severity"),
    [
        ("ERROR", Severity.HIGH),
        ("WARNING", Severity.MEDIUM),
        ("INFO", Severity.LOW),
        ("EXPERIMENT", Severity.LOW),
    ],
)
def test_semgrep_severity_mapping(
    raw_severity,
    expected_severity,
):
    result = create_semgrep_result()

    result["extra"]["severity"] = raw_severity

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].severity == expected_severity


def test_semgrep_rejects_unsupported_severity():
    result = create_semgrep_result()

    result["extra"]["severity"] = "UNKNOWN"

    with pytest.raises(ValueError):
        parse_semgrep_output(
            {"results": [result]}
        )


# ============================================================
# CWE EXTRACTION TESTS
# ============================================================


def test_semgrep_extracts_cwes_from_all_supported_keys():
    result = create_semgrep_result()

    result["extra"]["metadata"] = {
        "cwe": "CWE-89: SQL Injection",
        "cwes": [
            "CWE-20: Improper Input Validation",
            "CWE-89",
        ],
        "CWE": "CWE-79: Cross-Site Scripting",
    }

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    cwes = findings[0].cwe_ids

    assert set(cwes) == {
        "CWE-89",
        "CWE-20",
        "CWE-79",
    }

    assert len(cwes) == 3


def test_semgrep_ignores_unsupported_cwe_metadata_types():
    result = create_semgrep_result()

    result["extra"]["metadata"] = {
        "cwe": 89,
        "cwes": [None, 123, False],
        "CWE": {"identifier": "CWE-89"},
    }

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].cwe_ids == ()


def test_semgrep_accepts_missing_metadata():
    result = create_semgrep_result()

    result["extra"]["metadata"] = None

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].cwe_ids == ()


def test_semgrep_rejects_invalid_metadata_object():
    result = create_semgrep_result()

    result["extra"]["metadata"] = "invalid"

    with pytest.raises(ValueError):
        parse_semgrep_output(
            {"results": [result]}
        )


# ============================================================
# TITLE EXTRACTION TESTS
# ============================================================


@pytest.mark.parametrize(
    ("metadata", "expected_title"),
    [
        (
            {"title": "Primary Title"},
            "Primary Title",
        ),
        (
            {"short_description": "Short Description"},
            "Short Description",
        ),
        (
            {"shortDescription": "Camel Case Title"},
            "Camel Case Title",
        ),
        (
            {},
            "python.security.sql-injection",
        ),
    ],
)
def test_semgrep_title_extraction(
    metadata,
    expected_title,
):
    result = create_semgrep_result()

    result["extra"]["metadata"] = metadata

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].title == expected_title


def test_semgrep_title_uses_highest_priority_metadata():
    result = create_semgrep_result()

    result["extra"]["metadata"] = {
        "title": "Primary",
        "short_description": "Secondary",
        "shortDescription": "Tertiary",
    }

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].title == "Primary"


# ============================================================
# LINE NUMBER AND CODE SNIPPET TESTS
# ============================================================


def test_semgrep_missing_end_line_defaults_to_start():
    result = create_semgrep_result()

    result["start"] = {"line": 15}
    result["end"] = None

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].line_start == 15
    assert findings[0].line_end == 15


def test_semgrep_accepts_missing_line_locations():
    result = create_semgrep_result()

    result["start"] = None
    result["end"] = None

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].line_start is None
    assert findings[0].line_end is None


@pytest.mark.parametrize(
    "invalid_line",
    [
        0,
        -1,
        True,
        "10",
    ],
)
def test_semgrep_rejects_invalid_line_numbers(invalid_line):
    result = create_semgrep_result()

    result["start"] = {
        "line": invalid_line
    }

    with pytest.raises(ValueError):
        parse_semgrep_output(
            {"results": [result]}
        )


def test_semgrep_extracts_snippet_fallback():
    result = create_semgrep_result()

    result["extra"]["lines"] = ""
    result["extra"]["snippet"] = "SELECT * FROM users"

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].code_snippet == (
        "SELECT * FROM users"
    )


def test_semgrep_returns_none_without_code_snippet():
    result = create_semgrep_result()

    result["extra"].pop("lines")
    result["extra"].pop("snippet", None)

    findings = parse_semgrep_output(
        {"results": [result]}
    )

    assert findings[0].code_snippet is None


# ============================================================
# DEDUPLICATION TESTS
# ============================================================


def test_semgrep_deduplicates_findings():
    result = create_semgrep_result()

    findings = parse_semgrep_output(
        {
            "results": [
                result,
                result.copy(),
            ]
        }
    )

    assert len(findings) == 1


# ============================================================
# ADAPTER EXECUTION TESTS
# ============================================================


def test_semgrep_executes_with_expected_configuration(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    captured = {}

    payload = create_payload()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: "/usr/local/bin/semgrep",
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        semgrep_module.subprocess,
        "run",
        fake_run,
    )

    adapter = SemgrepAdapter(
        config="p/security-audit",
        timeout_seconds=60,
        repository_root=tmp_path,
    )

    findings = adapter.scan(target)

    assert adapter.scanner_name == "semgrep"

    assert captured["command"] == [
        "/usr/local/bin/semgrep",
        "scan",
        "--json",
        "--config",
        "p/security-audit",
        str(target),
    ]

    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "timeout": 60,
        "check": False,
    }

    assert len(findings) == 1


def test_semgrep_rejects_missing_target(tmp_path):
    adapter = SemgrepAdapter()

    with pytest.raises(FileNotFoundError):
        adapter.scan(
            tmp_path / "missing"
        )


def test_semgrep_rejects_invalid_target_type():
    adapter = SemgrepAdapter()

    with pytest.raises(TypeError):
        adapter.scan(123)


def test_semgrep_rejects_empty_target():
    adapter = SemgrepAdapter()

    with pytest.raises(ValueError):
        adapter.scan("   ")


def test_semgrep_missing_executable(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: None,
    )

    adapter = SemgrepAdapter()

    with pytest.raises(
        RuntimeError,
        match="executable was not found",
    ):
        adapter.scan(target)


def test_semgrep_timeout(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: "/usr/local/bin/semgrep",
    )

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            timeout=300,
        )

    monkeypatch.setattr(
        semgrep_module.subprocess,
        "run",
        fake_run,
    )

    adapter = SemgrepAdapter()

    with pytest.raises(
        RuntimeError,
        match="timed out",
    ):
        adapter.scan(target)


def test_semgrep_execution_os_error(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: "/usr/local/bin/semgrep",
    )

    def fake_run(command, **kwargs):
        raise OSError("Simulated execution failure")

    monkeypatch.setattr(
        semgrep_module.subprocess,
        "run",
        fake_run,
    )

    adapter = SemgrepAdapter()

    with pytest.raises(
        RuntimeError,
        match="Failed to execute Semgrep",
    ):
        adapter.scan(target)


def test_semgrep_nonzero_exit_code(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: "/usr/local/bin/semgrep",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr="Invalid Semgrep configuration",
        )

    monkeypatch.setattr(
        semgrep_module.subprocess,
        "run",
        fake_run,
    )

    adapter = SemgrepAdapter()

    with pytest.raises(
        RuntimeError,
        match="Invalid Semgrep configuration",
    ):
        adapter.scan(target)


def test_semgrep_empty_output(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: "/usr/local/bin/semgrep",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="   ",
            stderr="",
        )

    monkeypatch.setattr(
        semgrep_module.subprocess,
        "run",
        fake_run,
    )

    adapter = SemgrepAdapter()

    with pytest.raises(
        RuntimeError,
        match="empty output",
    ):
        adapter.scan(target)


def test_semgrep_invalid_json_output(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "repository"
    target.mkdir()

    monkeypatch.setattr(
        semgrep_module.shutil,
        "which",
        lambda _: "/usr/local/bin/semgrep",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="{invalid json",
            stderr="",
        )

    monkeypatch.setattr(
        semgrep_module.subprocess,
        "run",
        fake_run,
    )

    adapter = SemgrepAdapter()

    with pytest.raises(
        RuntimeError,
        match="invalid JSON",
    ):
        adapter.scan(target)


# ============================================================
# CONSTRUCTOR VALIDATION
# ============================================================


def test_semgrep_rejects_empty_config():
    with pytest.raises(ValueError):
        SemgrepAdapter(config="   ")


def test_semgrep_rejects_invalid_config_type():
    with pytest.raises(TypeError):
        SemgrepAdapter(config=None)


def test_semgrep_rejects_empty_executable():
    with pytest.raises(ValueError):
        SemgrepAdapter(executable="   ")


def test_semgrep_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        SemgrepAdapter(timeout_seconds=0)


def test_semgrep_rejects_boolean_timeout():
    with pytest.raises(ValueError):
        SemgrepAdapter(timeout_seconds=True)
