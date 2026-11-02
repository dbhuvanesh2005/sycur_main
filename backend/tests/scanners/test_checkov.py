import json
import subprocess

import pytest

from sycur_rag.core.enums import Severity
from sycur_rag.scanners import checkov as checkov_module
from sycur_rag.scanners.checkov import (
    CheckovAdapter,
    parse_checkov_output,
)


def create_failed_check(**overrides):
    finding = {
        "check_id": "CKV_AWS_1",
        "check_name": "Ensure S3 bucket encryption",
        "resource": "aws_s3_bucket.example",
        "file_path": "/main.tf",
        "file_line_range": [10, 12],
    }

    finding.update(overrides)
    return finding


def create_document(failed_checks=None):
    results = {}

    if failed_checks is not None:
        results["failed_checks"] = failed_checks

    return {
        "check_type": "terraform",
        "results": results,
    }


def create_payload():
    return create_document(
        [create_failed_check()]
    )


# ============================================================
# PARSER TESTS
# ============================================================


def test_valid_checkov_finding(tmp_path):
    findings = parse_checkov_output(
        create_payload(),
        repository_root=tmp_path,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == "checkov"
    assert finding.rule_id == "CKV_AWS_1"
    assert finding.title == "Ensure S3 bucket encryption"
    assert finding.severity == Severity.MEDIUM
    assert finding.file_path == "main.tf"
    assert finding.line_start == 10
    assert finding.line_end == 12
    assert finding.code_snippet is None
    assert finding.cwe_ids == ()
    assert finding.requires_evidence is False

    assert "terraform" in finding.message
    assert "aws_s3_bucket.example" in finding.message


def test_checkov_accepts_list_of_documents():
    payload = [
        create_document([create_failed_check()]),
        create_document([
            create_failed_check(
                check_id="CKV_AWS_2",
                check_name="Ensure bucket logging",
                file_path="/logging.tf",
            )
        ]),
    ]

    findings = parse_checkov_output(payload)

    assert len(findings) == 2
    assert findings[0].rule_id == "CKV_AWS_1"
    assert findings[1].rule_id == "CKV_AWS_2"


def test_checkov_empty_document_returns_no_findings():
    assert parse_checkov_output(
        create_document()
    ) == []


def test_checkov_empty_document_list_returns_no_findings():
    assert parse_checkov_output([]) == []


def test_checkov_accepts_none_failed_checks():
    document = create_document()
    document["results"]["failed_checks"] = None

    assert parse_checkov_output(document) == []


def test_checkov_deduplicates_identical_findings():
    payload = create_document([
        create_failed_check(),
        create_failed_check(),
    ])

    findings = parse_checkov_output(payload)

    assert len(findings) == 1


# ============================================================
# PAYLOAD VALIDATION
# ============================================================


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "invalid",
        123,
        True,
    ],
)
def test_checkov_rejects_invalid_payload(payload):
    with pytest.raises(ValueError):
        parse_checkov_output(payload)


def test_checkov_rejects_invalid_document():
    with pytest.raises(ValueError):
        parse_checkov_output([None])


def test_checkov_rejects_missing_framework():
    document = create_document()

    del document["check_type"]

    with pytest.raises(ValueError):
        parse_checkov_output(document)


def test_checkov_rejects_missing_results():
    document = {
        "check_type": "terraform",
    }

    with pytest.raises(ValueError):
        parse_checkov_output(document)


def test_checkov_rejects_invalid_results():
    document = create_document()
    document["results"] = []

    with pytest.raises(ValueError):
        parse_checkov_output(document)


def test_checkov_rejects_invalid_failed_checks():
    document = create_document()
    document["results"]["failed_checks"] = {}

    with pytest.raises(ValueError):
        parse_checkov_output(document)


def test_checkov_rejects_invalid_finding():
    document = create_document([None])

    with pytest.raises(ValueError):
        parse_checkov_output(document)


# ============================================================
# REQUIRED FINDING FIELD VALIDATION
# ============================================================


@pytest.mark.parametrize(
    "field",
    [
        "check_id",
        "check_name",
        "file_path",
    ],
)
def test_checkov_rejects_missing_required_finding_fields(
    field,
):
    finding = create_failed_check()
    del finding[field]

    with pytest.raises(ValueError):
        parse_checkov_output(
            create_document([finding])
        )


# ============================================================
# PARSING ERROR VALIDATION
# ============================================================


def test_checkov_rejects_partial_scan():
    document = create_payload()

    document["results"]["parsing_errors"] = [
        "Failed to parse infrastructure file."
    ]

    with pytest.raises(
        RuntimeError,
        match="parsing errors",
    ):
        parse_checkov_output(document)


def test_checkov_rejects_invalid_parsing_errors():
    document = create_document()
    document["results"]["parsing_errors"] = "invalid"

    with pytest.raises(ValueError):
        parse_checkov_output(document)


def test_checkov_accepts_none_parsing_errors():
    document = create_payload()
    document["results"]["parsing_errors"] = None

    findings = parse_checkov_output(document)

    assert len(findings) == 1


# ============================================================
# SEVERITY TESTS
# ============================================================


def test_checkov_default_severity_is_medium():
    findings = parse_checkov_output(
        create_payload()
    )

    assert findings[0].severity == Severity.MEDIUM


def test_checkov_uses_configured_default_severity():
    findings = parse_checkov_output(
        create_payload(),
        default_severity=Severity.HIGH,
    )

    assert findings[0].severity == Severity.HIGH


def test_checkov_explicit_severity_overrides_configuration():
    finding = create_failed_check(
        severity="LOW"
    )

    findings = parse_checkov_output(
        create_document([finding]),
        severity_overrides={
            "CKV_AWS_1": Severity.CRITICAL,
        },
        default_severity=Severity.HIGH,
    )

    assert findings[0].severity == Severity.LOW


def test_checkov_configured_override_is_used():
    findings = parse_checkov_output(
        create_payload(),
        severity_overrides={
            "CKV_AWS_1": Severity.CRITICAL,
        },
    )

    assert findings[0].severity == Severity.CRITICAL


def test_checkov_override_is_used_for_blank_severity():
    finding = create_failed_check(severity=" ")

    findings = parse_checkov_output(
        create_document([finding]),
        severity_overrides={
            "CKV_AWS_1": Severity.HIGH,
        },
    )

    assert findings[0].severity == Severity.HIGH


def test_checkov_override_key_is_normalized():
    findings = parse_checkov_output(
        create_payload(),
        severity_overrides={
            " CKV_AWS_1 ": Severity.CRITICAL,
        },
    )

    assert findings[0].severity == Severity.CRITICAL


def test_checkov_rejects_unsupported_severity():
    finding = create_failed_check(
        severity="UNKNOWN"
    )

    with pytest.raises(ValueError):
        parse_checkov_output(
            create_document([finding])
        )


def test_checkov_rejects_non_string_severity():
    finding = create_failed_check(
        severity=123
    )

    with pytest.raises(ValueError):
        parse_checkov_output(
            create_document([finding])
        )


# ============================================================
# FILE PATH TESTS
# ============================================================


def test_checkov_prefers_repository_relative_path():
    finding = create_failed_check(
        repo_file_path="/repo.tf",
        file_path="/fallback.tf",
    )

    findings = parse_checkov_output(
        create_document([finding])
    )

    assert findings[0].file_path == "repo.tf"


def test_checkov_uses_absolute_path_with_repository_root(
    tmp_path,
):
    absolute_path = tmp_path / "main.tf"

    finding = create_failed_check(
        file_abs_path=str(absolute_path),
    )

    findings = parse_checkov_output(
        create_document([finding]),
        repository_root=tmp_path,
    )

    assert findings[0].file_path == "main.tf"


def test_checkov_rejects_missing_file_path():
    finding = create_failed_check()

    del finding["file_path"]

    with pytest.raises(ValueError):
        parse_checkov_output(
            create_document([finding])
        )


# ============================================================
# LINE RANGE TESTS
# ============================================================


def test_checkov_preserves_valid_line_range():
    findings = parse_checkov_output(
        create_payload()
    )

    assert findings[0].line_start == 10
    assert findings[0].line_end == 12


def test_checkov_handles_zero_start_line():
    finding = create_failed_check(
        file_line_range=[0, 12]
    )

    findings = parse_checkov_output(
        create_document([finding])
    )

    assert findings[0].line_start is None
    assert findings[0].line_end is None


def test_checkov_handles_zero_end_line():
    finding = create_failed_check(
        file_line_range=[10, 0]
    )

    findings = parse_checkov_output(
        create_document([finding])
    )

    assert findings[0].line_start == 10
    assert findings[0].line_end == 10


def test_checkov_handles_missing_line_range():
    finding = create_failed_check(
        file_line_range=None
    )

    findings = parse_checkov_output(
        create_document([finding])
    )

    assert findings[0].line_start is None
    assert findings[0].line_end is None


@pytest.mark.parametrize(
    "line_range",
    [
        [10],
        [10, 12, 14],
        [-1, 10],
        [10, -1],
        [12, 10],
        [True, 10],
        ["10", 12],
        {},
    ],
)
def test_checkov_rejects_invalid_line_ranges(
    line_range,
):
    finding = create_failed_check(
        file_line_range=line_range
    )

    with pytest.raises(ValueError):
        parse_checkov_output(
            create_document([finding])
        )


# ============================================================
# OPTIONAL RESOURCE TESTS
# ============================================================


def test_checkov_handles_missing_resource():
    finding = create_failed_check()
    del finding["resource"]

    findings = parse_checkov_output(
        create_document([finding])
    )

    assert "Resource:" not in findings[0].message


# ============================================================
# ADAPTER CONFIGURATION TESTS
# ============================================================


def test_checkov_adapter_name():
    adapter = CheckovAdapter()

    assert adapter.scanner_name == "checkov"


@pytest.mark.parametrize(
    ("kwargs", "exception"),
    [
        ({"executable": ""}, ValueError),
        ({"timeout_seconds": 0}, ValueError),
        ({"timeout_seconds": True}, ValueError),
        ({"default_severity": "HIGH"}, TypeError),
        (
            {
                "default_severity": Severity.NOT_APPLICABLE
            },
            ValueError,
        ),
        ({"severity_overrides": []}, TypeError),
        (
            {
                "severity_overrides": {
                    "CKV_AWS_1": "HIGH"
                }
            },
            TypeError,
        ),
        (
            {
                "severity_overrides": {
                    "CKV_AWS_1": Severity.NOT_APPLICABLE
                }
            },
            ValueError,
        ),
    ],
)
def test_checkov_adapter_rejects_invalid_configuration(
    kwargs,
    exception,
):
    with pytest.raises(exception):
        CheckovAdapter(**kwargs)


# ============================================================
# ADAPTER TARGET VALIDATION
# ============================================================


def test_checkov_adapter_rejects_invalid_target_type():
    adapter = CheckovAdapter()

    with pytest.raises(TypeError):
        adapter.scan(None)


def test_checkov_adapter_rejects_empty_target():
    adapter = CheckovAdapter()

    with pytest.raises(ValueError):
        adapter.scan(" ")


def test_checkov_adapter_rejects_missing_target(tmp_path):
    adapter = CheckovAdapter()

    with pytest.raises(FileNotFoundError):
        adapter.scan(tmp_path / "missing.tf")


# ============================================================
# ADAPTER EXECUTION TESTS
# ============================================================


def test_checkov_adapter_executes_directory_scan(
    tmp_path,
    monkeypatch,
):
    captured = {}

    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(create_payload()),
            stderr="",
        )

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    adapter = CheckovAdapter()

    findings = adapter.scan(tmp_path)

    command = captured["command"]

    assert command[0] == "/usr/bin/checkov"
    assert command[1:3] == [
        "--directory",
        str(tmp_path),
    ]

    assert "--output" in command
    assert "json" in command
    assert "--soft-fail" in command
    assert "--skip-results-upload" in command
    assert "--skip-framework" in command

    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["timeout"] == 600

    assert len(findings) == 1


def test_checkov_adapter_executes_file_scan(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "main.tf"
    target.write_text(
        'resource "aws_s3_bucket" "example" {}',
        encoding="utf-8",
    )

    captured = {}

    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        captured["command"] = command

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(create_document()),
            stderr="",
        )

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    adapter = CheckovAdapter()

    findings = adapter.scan(target)

    assert captured["command"][1:3] == [
        "--file",
        str(target),
    ]

    assert findings == []


def test_checkov_adapter_rejects_missing_executable(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: None,
    )

    adapter = CheckovAdapter()

    with pytest.raises(
        RuntimeError,
        match="executable",
    ):
        adapter.scan(tmp_path)


def test_checkov_adapter_handles_timeout(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            kwargs["timeout"],
        )

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="timed out",
    ):
        CheckovAdapter().scan(tmp_path)


def test_checkov_adapter_handles_os_error(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        raise OSError("Simulated execution failure.")

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="Failed to execute",
    ):
        CheckovAdapter().scan(tmp_path)


def test_checkov_adapter_rejects_nonzero_exit_code(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr="Simulated Checkov failure.",
        )

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="exit code 2",
    ):
        CheckovAdapter().scan(tmp_path)


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "invalid-json",
    ],
)
def test_checkov_adapter_rejects_invalid_output(
    tmp_path,
    monkeypatch,
    stdout,
):
    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(RuntimeError):
        CheckovAdapter().scan(tmp_path)


def test_checkov_adapter_rejects_partial_scan_output(
    tmp_path,
    monkeypatch,
):
    document = create_document()
    document["results"]["parsing_errors"] = [
        "Terraform parsing failed."
    ]

    monkeypatch.setattr(
        checkov_module.shutil,
        "which",
        lambda _: "/usr/bin/checkov",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(document),
            stderr="",
        )

    monkeypatch.setattr(
        checkov_module.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="parsing errors",
    ):
        CheckovAdapter().scan(tmp_path)
