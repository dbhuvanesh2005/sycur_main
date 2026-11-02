import json
import subprocess
from pathlib import Path

import pytest

import sycur_rag.scanners.gitleaks as gitleaks_module

from sycur_rag.core.enums import Severity
from sycur_rag.scanners.gitleaks import (
    GitleaksAdapter,
    parse_gitleaks_output,
)


def create_finding(root):
    return {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": str(root / "src" / "app.py"),
        "StartLine": 10,
        "EndLine": 11,
        "Secret": "SUPER_SECRET_TOKEN_123",
        "Match": "api_key=SUPER_SECRET_TOKEN_123",
        "Line": "api_key=SUPER_SECRET_TOKEN_123",
    }


def create_target(tmp_path):
    target = tmp_path / "repository"
    source = target / "src" / "app.py"

    source.parent.mkdir(parents=True)
    source.write_text(
        "api_key = 'test'\n",
        encoding="utf-8",
    )

    return target


def mock_executable(monkeypatch):
    monkeypatch.setattr(
        gitleaks_module.shutil,
        "which",
        lambda _: "/usr/local/bin/gitleaks",
    )


def mock_report(monkeypatch, payload):
    mock_executable(monkeypatch)

    def fake_run(command, **kwargs):
        report_path = Path(
            command[
                command.index("--report-path") + 1
            ]
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
        gitleaks_module.subprocess,
        "run",
        fake_run,
    )


# =====================================================
# PARSER TESTS
# =====================================================

def test_valid_gitleaks_finding(tmp_path):
    root = tmp_path / "repository"

    finding = parse_gitleaks_output(
        [create_finding(root)],
        repository_root=root,
    )[0]

    assert finding.scanner == "gitleaks"
    assert finding.rule_id == "generic-api-key"
    assert finding.title == "Generic API Key"
    assert finding.severity == Severity.HIGH

    assert finding.file_path == "src/app.py"
    assert finding.line_start == 10
    assert finding.line_end == 11


def test_gitleaks_empty_report_returns_no_findings():
    findings = parse_gitleaks_output([])

    assert findings == []


def test_gitleaks_rejects_invalid_payload():
    with pytest.raises(
        ValueError,
        match="must be a list",
    ):
        parse_gitleaks_output({})


@pytest.mark.parametrize(
    "field",
    [
        "RuleID",
        "Description",
        "File",
        "StartLine",
    ],
)
def test_gitleaks_rejects_missing_required_fields(
    tmp_path,
    field,
):
    payload = create_finding(tmp_path)
    payload.pop(field)

    with pytest.raises(ValueError):
        parse_gitleaks_output([payload])


def test_gitleaks_rejects_invalid_line_range(tmp_path):
    payload = create_finding(tmp_path)

    payload["StartLine"] = 15
    payload["EndLine"] = 10

    with pytest.raises(
        ValueError,
        match="cannot be before",
    ):
        parse_gitleaks_output([payload])


def test_gitleaks_deduplicates_findings(tmp_path):
    payload = create_finding(tmp_path)

    findings = parse_gitleaks_output(
        [payload, payload]
    )

    assert len(findings) == 1


def test_gitleaks_never_exposes_secret_values(tmp_path):
    payload = create_finding(tmp_path)

    findings = parse_gitleaks_output(
        [payload],
        repository_root=tmp_path,
    )

    finding = findings[0]

    assert finding.code_snippet is None

    assert (
        "SUPER_SECRET_TOKEN_123"
        not in repr(finding)
    )


# =====================================================
# ADAPTER EXECUTION TESTS
# =====================================================

def test_gitleaks_executes_with_secure_configuration(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    payload = [
        create_finding(target)
    ]

    mock_report(
        monkeypatch,
        payload,
    )

    commands = []

    original_run = gitleaks_module.subprocess.run

    def capture_run(command, **kwargs):
        commands.append(command)

        assert kwargs["timeout"] == 300
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is False

        return original_run(command, **kwargs)

    monkeypatch.setattr(
        gitleaks_module.subprocess,
        "run",
        capture_run,
    )

    adapter = GitleaksAdapter(
        repository_root=target,
    )

    findings = adapter.scan(target)

    assert len(findings) == 1

    command = commands[0]

    assert command[1] == "dir"
    assert "--redact=100" in command
    assert "--exit-code" in command
    assert command[
        command.index("--exit-code") + 1
    ] == "0"

    assert "--report-format" in command
    assert "json" in command


def test_gitleaks_missing_executable(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    monkeypatch.setattr(
        gitleaks_module.shutil,
        "which",
        lambda _: None,
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="executable was not found",
    ):
        adapter.scan(target)


def test_gitleaks_timeout(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    mock_executable(monkeypatch)

    def timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="gitleaks",
            timeout=300,
        )

    monkeypatch.setattr(
        gitleaks_module.subprocess,
        "run",
        timeout_run,
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="timed out",
    ):
        adapter.scan(target)


def test_gitleaks_execution_os_error(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    mock_executable(monkeypatch)

    def failed_run(*args, **kwargs):
        raise OSError("Simulated execution failure")

    monkeypatch.setattr(
        gitleaks_module.subprocess,
        "run",
        failed_run,
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="Failed to execute",
    ):
        adapter.scan(target)


def test_gitleaks_nonzero_exit_code(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    mock_executable(monkeypatch)

    def failed_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            2,
            "",
            "Simulated scanner failure",
        )

    monkeypatch.setattr(
        gitleaks_module.subprocess,
        "run",
        failed_run,
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="exit code 2",
    ):
        adapter.scan(target)


def test_gitleaks_missing_report_file(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    mock_executable(monkeypatch)

    monkeypatch.setattr(
        gitleaks_module.subprocess,
        "run",
        lambda command, **kwargs: (
            subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )
        ),
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="did not create",
    ):
        adapter.scan(target)


def test_gitleaks_empty_report_file(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    mock_executable(monkeypatch)

    def empty_report(command, **kwargs):
        report_path = Path(
            command[
                command.index("--report-path") + 1
            ]
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
        gitleaks_module.subprocess,
        "run",
        empty_report,
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="empty report",
    ):
        adapter.scan(target)


def test_gitleaks_invalid_json_report(
    tmp_path,
    monkeypatch,
):
    target = create_target(tmp_path)

    mock_executable(monkeypatch)

    def invalid_report(command, **kwargs):
        report_path = Path(
            command[
                command.index("--report-path") + 1
            ]
        )

        report_path.write_text(
            "INVALID JSON",
            encoding="utf-8",
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    monkeypatch.setattr(
        gitleaks_module.subprocess,
        "run",
        invalid_report,
    )

    adapter = GitleaksAdapter()

    with pytest.raises(
        RuntimeError,
        match="invalid JSON",
    ):
        adapter.scan(target)
