import json
import subprocess

import pytest

from sycur_rag.core.enums import Severity
from sycur_rag.scanners import bandit as bandit_module
from sycur_rag.scanners.bandit import (
    BanditAdapter,
    parse_bandit_output,
)


def create_bandit_result():
    return {
        "test_id": "B608",
        "test_name": "hardcoded_sql_expressions",
        "issue_text": "Possible SQL injection vulnerability.",
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "filename": "src/app.py",
        "line_number": 10,
        "line_range": [10, 12],
        "issue_cwe": {
            "id": 89,
        },
        "code": "cursor.execute(query)",
    }


def create_payload():
    return {
        "errors": [],
        "results": [
            create_bandit_result()
        ],
    }


def completed_process(payload, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=["bandit"],
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr=stderr,
    )


# ============================================================
# PARSER TESTS
# ============================================================


def test_valid_bandit_finding(tmp_path):
    findings = parse_bandit_output(
        create_payload(),
        repository_root=tmp_path,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == "bandit"
    assert finding.rule_id == "B608"
    assert finding.title == "hardcoded_sql_expressions"
    assert finding.message == (
        "Possible SQL injection vulnerability."
    )
    assert finding.severity == Severity.HIGH
    assert finding.file_path == "src/app.py"
    assert finding.line_start == 10
    assert finding.line_end == 12
    assert finding.code_snippet == "cursor.execute(query)"
    assert "CWE-89" in finding.cwe_ids
    assert finding.requires_evidence is False


def test_bandit_empty_report_returns_no_findings():
    assert parse_bandit_output(
        {"errors": [], "results": []}
    ) == []


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
def test_bandit_rejects_invalid_payload(payload):
    with pytest.raises(ValueError):
        parse_bandit_output(payload)


def test_bandit_rejects_invalid_result_object():
    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [None]}
        )


@pytest.mark.parametrize(
    "field",
    [
        "test_id",
        "test_name",
        "issue_text",
        "issue_severity",
        "filename",
        "line_number",
    ],
)
def test_bandit_rejects_missing_required_fields(field):
    result = create_bandit_result()
    del result[field]

    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [result]}
        )


# ============================================================
# SEVERITY TESTS
# ============================================================


@pytest.mark.parametrize(
    ("raw_severity", "expected_severity"),
    [
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
    ],
)
def test_bandit_severity_mapping(
    raw_severity,
    expected_severity,
):
    result = create_bandit_result()
    result["issue_severity"] = raw_severity

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].severity == expected_severity


def test_bandit_rejects_unsupported_severity():
    result = create_bandit_result()
    result["issue_severity"] = "UNKNOWN"

    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [result]}
        )


# ============================================================
# CWE EXTRACTION TESTS
# ============================================================


@pytest.mark.parametrize(
    ("cwe_id", "expected"),
    [
        (89, "CWE-89"),
        ("89", "CWE-89"),
        ("CWE-89", "CWE-89"),
    ],
)
def test_bandit_cwe_extraction(cwe_id, expected):
    result = create_bandit_result()
    result["issue_cwe"]["id"] = cwe_id

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert expected in findings[0].cwe_ids


def test_bandit_missing_cwe_returns_empty_tuple():
    result = create_bandit_result()
    result.pop("issue_cwe")

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].cwe_ids == ()


def test_bandit_rejects_invalid_cwe_object():
    result = create_bandit_result()
    result["issue_cwe"] = "invalid"

    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [result]}
        )


@pytest.mark.parametrize(
    "cwe_id",
    [
        True,
        0,
        -1,
        "invalid",
    ],
)
def test_bandit_rejects_invalid_cwe_identifier(cwe_id):
    result = create_bandit_result()
    result["issue_cwe"]["id"] = cwe_id

    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [result]}
        )


# ============================================================
# LINE NUMBER TESTS
# ============================================================


def test_bandit_missing_line_range_uses_start_line():
    result = create_bandit_result()
    result.pop("line_range")

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].line_start == 10
    assert findings[0].line_end == 10


def test_bandit_empty_line_range_uses_start_line():
    result = create_bandit_result()
    result["line_range"] = []

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].line_end == 10


def test_bandit_line_range_uses_highest_line():
    result = create_bandit_result()
    result["line_range"] = [10, 15, 12]

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].line_end == 15


@pytest.mark.parametrize(
    "line_range",
    [
        "invalid",
        [10, 0],
        [10, -1],
        [10, True],
        [10, "12"],
    ],
)
def test_bandit_rejects_invalid_line_range(line_range):
    result = create_bandit_result()
    result["line_range"] = line_range

    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [result]}
        )


# ============================================================
# CODE AND REPORT VALIDATION
# ============================================================


def test_bandit_missing_code_returns_none():
    result = create_bandit_result()
    result["code"] = None

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].code_snippet is None


def test_bandit_empty_code_returns_none():
    result = create_bandit_result()
    result["code"] = "   "

    findings = parse_bandit_output(
        {"results": [result]}
    )

    assert findings[0].code_snippet is None


def test_bandit_rejects_invalid_code_type():
    result = create_bandit_result()
    result["code"] = 123

    with pytest.raises(ValueError):
        parse_bandit_output(
            {"results": [result]}
        )


def test_bandit_rejects_report_errors():
    payload = create_payload()
    payload["errors"] = [
        {"filename": "src/app.py"}
    ]

    with pytest.raises(RuntimeError):
        parse_bandit_output(payload)


def test_bandit_rejects_invalid_errors_type():
    with pytest.raises(ValueError):
        parse_bandit_output(
            {
                "errors": "invalid",
                "results": [],
            }
        )


def test_bandit_deduplicates_findings():
    result = create_bandit_result()

    findings = parse_bandit_output(
        {
            "results": [
                result,
                result.copy(),
            ]
        }
    )

    assert len(findings) == 1


# ============================================================
# ADAPTER CONFIGURATION TESTS
# ============================================================


def test_bandit_adapter_name():
    adapter = BanditAdapter()

    assert adapter.scanner_name == "bandit"


def test_bandit_rejects_invalid_executable():
    with pytest.raises(TypeError):
        BanditAdapter(executable=123)


def test_bandit_rejects_empty_executable():
    with pytest.raises(ValueError):
        BanditAdapter(executable="   ")


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        True,
        1.5,
    ],
)
def test_bandit_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        BanditAdapter(timeout_seconds=timeout)


def test_bandit_rejects_invalid_isolated_type():
    with pytest.raises(TypeError):
        BanditAdapter(isolated=1)


# ============================================================
# NORMAL SUBPROCESS EXECUTION TESTS
# ============================================================


def test_bandit_normal_execution(tmp_path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text(
        "cursor.execute(query)\n",
        encoding="utf-8",
    )

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return completed_process(create_payload())

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda executable: "/usr/bin/bandit",
    )

    monkeypatch.setattr(
        bandit_module.subprocess,
        "run",
        fake_run,
    )

    adapter = BanditAdapter(
        repository_root=tmp_path,
    )

    findings = adapter.scan(target)

    assert len(findings) == 1
    assert findings[0].scanner == "bandit"

    command, kwargs = calls[0]

    assert command[0] == "/usr/bin/bandit"
    assert "-f" in command
    assert "json" in command
    assert "--exit-zero" in command
    assert str(target) in command

    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 300


def test_bandit_directory_execution_uses_recursive_flag(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "app.py").write_text(
        "print('test')\n",
        encoding="utf-8",
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return completed_process(
            {"errors": [], "results": []}
        )

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda _: "/usr/bin/bandit",
    )

    monkeypatch.setattr(
        bandit_module.subprocess,
        "run",
        fake_run,
    )

    BanditAdapter().scan(tmp_path)

    assert "-r" in captured["command"]


def test_bandit_rejects_missing_executable(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda _: None,
    )

    with pytest.raises(
        RuntimeError,
        match="executable was not found",
    ):
        BanditAdapter().scan(target)


def test_bandit_rejects_nonzero_exit_code(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda _: "/usr/bin/bandit",
    )

    monkeypatch.setattr(
        bandit_module.subprocess,
        "run",
        lambda *args, **kwargs: completed_process(
            {},
            returncode=2,
            stderr="Simulated failure",
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated failure",
    ):
        BanditAdapter().scan(target)


def test_bandit_handles_timeout(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda _: "/usr/bin/bandit",
    )

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="bandit",
            timeout=300,
        )

    monkeypatch.setattr(
        bandit_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="timed out",
    ):
        BanditAdapter().scan(target)


def test_bandit_handles_execution_os_error(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda _: "/usr/bin/bandit",
    )

    def fake_run(*args, **kwargs):
        raise OSError("Simulated OS error")

    monkeypatch.setattr(
        bandit_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="Failed to execute Bandit",
    ):
        BanditAdapter().scan(target)


@pytest.mark.parametrize(
    ("stdout", "expected_message"),
    [
        ("", "empty output"),
        ("invalid-json", "invalid JSON"),
    ],
)
def test_bandit_rejects_invalid_subprocess_output(
    tmp_path,
    monkeypatch,
    stdout,
    expected_message,
):
    target = tmp_path / "app.py"
    target.write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module.shutil,
        "which",
        lambda _: "/usr/bin/bandit",
    )

    monkeypatch.setattr(
        bandit_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["bandit"],
            returncode=0,
            stdout=stdout,
            stderr="",
        ),
    )

    with pytest.raises(
        RuntimeError,
        match=expected_message,
    ):
        BanditAdapter().scan(target)


# ============================================================
# ISOLATED EXECUTION TESTS
# ============================================================


def test_bandit_isolated_execution(tmp_path, monkeypatch):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        "cursor.execute(query)\n",
        encoding="utf-8",
    )

    report = create_payload()

    report["results"][0]["filename"] = (
        "/workspace/src/app.py"
    )

    calls = []

    def fake_isolated(**kwargs):
        calls.append(kwargs)

        return completed_process(report)

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        fake_isolated,
    )

    adapter = BanditAdapter(
        isolated=True,
        repository_root=tmp_path,
    )

    findings = adapter.scan(tmp_path)

    assert len(findings) == 1
    assert findings[0].file_path == "src/app.py"

    call = calls[0]

    assert call["workspace"] == tmp_path.resolve()
    assert call["image"] == "sycur-bandit:1.9.4"
    assert call["timeout_seconds"] == 300

    assert call["command"] == [
        "bandit",
        "-f",
        "json",
        "--exit-zero",
        "-r",
        ".",
    ]


def test_bandit_isolated_file_execution(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("print('test')\n")

    report = create_payload()
    report["results"][0]["filename"] = (
        "/workspace/app.py"
    )

    captured = {}

    def fake_isolated(**kwargs):
        captured.update(kwargs)
        return completed_process(report)

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        fake_isolated,
    )

    findings = BanditAdapter(
        isolated=True,
        repository_root=tmp_path,
    ).scan(target)

    assert len(findings) == 1
    assert captured["workspace"] == tmp_path.resolve()

    assert captured["command"] == [
        "bandit",
        "-f",
        "json",
        "--exit-zero",
        "app.py",
    ]


def test_bandit_isolated_rejects_invalid_json(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "app.py").write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        lambda **kwargs: subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="invalid-json",
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError):
        BanditAdapter(
            isolated=True,
        ).scan(tmp_path)


def test_bandit_isolated_rejects_invalid_report(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "app.py").write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        lambda **kwargs: completed_process(
            {"results": "invalid"}
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="Invalid isolated Bandit report",
    ):
        BanditAdapter(isolated=True).scan(tmp_path)


def test_bandit_isolated_rejects_invalid_finding(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "app.py").write_text("print('test')\n")

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        lambda **kwargs: completed_process(
            {"results": [None]}
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="Invalid Bandit finding",
    ):
        BanditAdapter(isolated=True).scan(tmp_path)


@pytest.mark.parametrize(
    "filename",
    [
        "../outside.py",
        "/workspace/../outside.py",
        "/etc/passwd",
    ],
)
def test_bandit_isolated_rejects_unsafe_paths(
    tmp_path,
    monkeypatch,
    filename,
):
    (tmp_path / "app.py").write_text("print('test')\n")

    report = create_payload()
    report["results"][0]["filename"] = filename

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        lambda **kwargs: completed_process(report),
    )

    with pytest.raises(
        RuntimeError,
        match="Unsafe Bandit finding path",
    ):
        BanditAdapter(isolated=True).scan(tmp_path)


def test_bandit_isolated_rejects_missing_workspace_file(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "app.py").write_text("print('test')\n")

    report = create_payload()
    report["results"][0]["filename"] = (
        "/workspace/missing.py"
    )

    monkeypatch.setattr(
        bandit_module,
        "run_isolated_command",
        lambda **kwargs: completed_process(report),
    )

    with pytest.raises(
        RuntimeError,
        match="escaped the workspace",
    ):
        BanditAdapter(isolated=True).scan(tmp_path)
