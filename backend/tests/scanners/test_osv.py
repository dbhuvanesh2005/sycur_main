import json
import subprocess

import pytest

from sycur_rag.core.enums import Severity
from sycur_rag.scanners import osv as osv_module
from sycur_rag.scanners.osv import (
    OSVScannerAdapter,
    parse_osv_output,
)


def create_vulnerability():
    return {
        "id": "GHSA-abcd-1234-efgh",
        "aliases": [
            "CVE-2025-12345",
        ],
        "summary": "Example dependency vulnerability",
        "database_specific": {
            "cwe_ids": [
                "CWE-79",
                "CWE-89",
            ],
        },
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.1.0"},
                            {"fixed": "2.2.0"},
                        ],
                    },
                ],
            },
        ],
    }


def create_payload(
    max_severity="9.8",
    groups=None,
    vulnerabilities=None,
):
    if groups is None:
        groups = [
            {
                "ids": [
                    "GHSA-abcd-1234-efgh",
                ],
                "aliases": [
                    "CVE-2025-12345",
                ],
                "max_severity": max_severity,
            },
        ]

    if vulnerabilities is None:
        vulnerabilities = [
            create_vulnerability(),
        ]

    return {
        "results": [
            {
                "source": {
                    "path": "requirements.txt",
                },
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.0.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": vulnerabilities,
                        "groups": groups,
                    },
                ],
            },
        ],
    }


# ============================================================
# PARSER TESTS
# ============================================================


def test_valid_osv_finding(tmp_path):
    findings = parse_osv_output(
        create_payload(),
        repository_root=tmp_path,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == "osv"
    assert finding.rule_id == "CVE-2025-12345"

    assert finding.title == (
        "Example dependency vulnerability"
    )

    assert finding.severity == Severity.CRITICAL
    assert finding.file_path == "requirements.txt"

    assert finding.line_start is None
    assert finding.line_end is None
    assert finding.code_snippet is None

    assert finding.cwe_ids == (
        "CWE-79",
        "CWE-89",
    )

    assert finding.requires_evidence is False

    assert finding.message == (
        "CVE-2025-12345 affects "
        "requests 2.0.0 in PyPI. "
        "Fixed version(s): 2.1.0, 2.2.0."
    )


def test_osv_empty_report_returns_no_findings():
    assert parse_osv_output(
        {"results": []}
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
def test_osv_rejects_invalid_payload(payload):
    with pytest.raises(ValueError):
        parse_osv_output(payload)


def test_osv_rejects_invalid_result():
    with pytest.raises(ValueError):
        parse_osv_output(
            {"results": [None]}
        )


def test_osv_rejects_missing_source():
    with pytest.raises(ValueError):
        parse_osv_output(
            {
                "results": [
                    {
                        "packages": [],
                    },
                ],
            }
        )


def test_osv_rejects_missing_source_path():
    with pytest.raises(ValueError):
        parse_osv_output(
            {
                "results": [
                    {
                        "source": {},
                        "packages": [],
                    },
                ],
            }
        )


def test_osv_rejects_invalid_packages():
    with pytest.raises(ValueError):
        parse_osv_output(
            {
                "results": [
                    {
                        "source": {
                            "path": "requirements.txt",
                        },
                        "packages": {},
                    },
                ],
            }
        )


# ============================================================
# CVSS SEVERITY TESTS
# ============================================================


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        ("9.8", Severity.CRITICAL),
        ("9.0", Severity.CRITICAL),
        ("8.5", Severity.HIGH),
        ("7.0", Severity.HIGH),
        ("6.0", Severity.MEDIUM),
        ("4.0", Severity.MEDIUM),
        ("3.9", Severity.LOW),
        ("0.1", Severity.LOW),
    ],
)
def test_osv_cvss_severity_mapping(
    score,
    expected,
):
    findings = parse_osv_output(
        create_payload(max_severity=score)
    )

    assert findings[0].severity == expected


@pytest.mark.parametrize(
    "score",
    [
        True,
        False,
        None,
        "",
        "invalid",
        "-1.0",
        "10.1",
        "0.0",
        0,
    ],
)
def test_osv_rejects_invalid_cvss_scores(score):
    with pytest.raises(ValueError):
        osv_module._severity_from_cvss(score)


# ============================================================
# IDENTIFIER NORMALIZATION TESTS
# ============================================================


def test_osv_identifier_normalization():
    result = osv_module._normalize_identifier_list(
        [
            " CVE-2025-12345 ",
            "GHSA-abcd-1234-efgh",
            "CVE-2025-12345",
            "",
        ],
        field_name="ids",
    )

    assert result == (
        "CVE-2025-12345",
        "GHSA-abcd-1234-efgh",
    )


def test_osv_none_identifiers_return_empty_tuple():
    assert osv_module._normalize_identifier_list(
        None,
        field_name="ids",
    ) == ()


def test_osv_rejects_invalid_identifier_list():
    with pytest.raises(ValueError):
        osv_module._normalize_identifier_list(
            "CVE-2025-12345",
            field_name="ids",
        )


def test_osv_rejects_non_string_identifier():
    with pytest.raises(ValueError):
        osv_module._normalize_identifier_list(
            [123],
            field_name="ids",
        )


@pytest.mark.parametrize(
    ("identifiers", "expected"),
    [
        (
            (
                "GHSA-abcd-1234-efgh",
                "CVE-2025-12345",
            ),
            "CVE-2025-12345",
        ),
        (
            (
                "OSV-2025-123",
                "GHSA-abcd-1234-efgh",
            ),
            "GHSA-abcd-1234-efgh",
        ),
        (
            ("OSV-2025-123",),
            "OSV-2025-123",
        ),
    ],
)
def test_osv_canonical_identifier_selection(
    identifiers,
    expected,
):
    assert osv_module._choose_canonical_id(
        identifiers
    ) == expected


def test_osv_rejects_missing_canonical_identifier():
    with pytest.raises(ValueError):
        osv_module._choose_canonical_id(())


# ============================================================
# CWE EXTRACTION TESTS
# ============================================================


def test_osv_extracts_and_deduplicates_cwes():
    vulnerabilities = [
        {
            "database_specific": {
                "cwe_ids": [
                    "CWE-79",
                    "CWE-89",
                ],
            },
        },
        {
            "database_specific": {
                "cwe_ids": [
                    "CWE-79",
                ],
            },
        },
    ]

    assert osv_module._extract_cwes(
        vulnerabilities
    ) == (
        "CWE-79",
        "CWE-89",
    )


def test_osv_missing_cwes_returns_empty_tuple():
    assert osv_module._extract_cwes(
        [
            {},
            {"database_specific": None},
        ]
    ) == ()


def test_osv_rejects_invalid_cwe_container():
    with pytest.raises(ValueError):
        osv_module._extract_cwes(
            [
                {
                    "database_specific": [],
                },
            ]
        )


def test_osv_rejects_invalid_cwe_list():
    with pytest.raises(ValueError):
        osv_module._extract_cwes(
            [
                {
                    "database_specific": {
                        "cwe_ids": "CWE-79",
                    },
                },
            ]
        )


def test_osv_rejects_invalid_cwe_identifier():
    with pytest.raises(ValueError):
        osv_module._extract_cwes(
            [
                {
                    "database_specific": {
                        "cwe_ids": [
                            "INVALID-CWE",
                        ],
                    },
                },
            ]
        )


# ============================================================
# FIXED VERSION EXTRACTION TESTS
# ============================================================


def test_osv_extracts_fixed_versions():
    vulnerabilities = [
        create_vulnerability(),
    ]

    assert osv_module._extract_fixed_versions(
        vulnerabilities
    ) == (
        "2.1.0",
        "2.2.0",
    )


def test_osv_deduplicates_fixed_versions():
    vulnerabilities = [
        create_vulnerability(),
        create_vulnerability(),
    ]

    assert osv_module._extract_fixed_versions(
        vulnerabilities
    ) == (
        "2.1.0",
        "2.2.0",
    )


def test_osv_missing_fixed_versions_returns_empty():
    assert osv_module._extract_fixed_versions(
        [
            {
                "affected": [
                    {
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "0"},
                                ],
                            },
                        ],
                    },
                ],
            },
        ]
    ) == ()


# ============================================================
# VULNERABILITY MATCHING AND TITLE TESTS
# ============================================================


def test_osv_matches_vulnerability_aliases():
    vulnerability = create_vulnerability()

    result = osv_module._find_group_vulnerabilities(
        [vulnerability],
        ("CVE-2025-12345",),
    )

    assert result == [vulnerability]


def test_osv_fallback_title_without_summary():
    findings = parse_osv_output(
        create_payload(
            vulnerabilities=[
                {
                    "id": "GHSA-abcd-1234-efgh",
                    "aliases": [
                        "CVE-2025-12345",
                    ],
                },
            ],
        )
    )

    assert findings[0].title == (
        "CVE-2025-12345 in requests"
    )


# ============================================================
# ADAPTER EXECUTION TESTS
# ============================================================


@pytest.mark.parametrize(
    "returncode",
    [0, 1],
)
def test_osv_adapter_accepts_successful_exit_codes(
    tmp_path,
    monkeypatch,
    returncode,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command

        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout=json.dumps(create_payload()),
            stderr="",
        )

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter(
        repository_root=tmp_path,
    )

    findings = adapter.scan(tmp_path)

    assert len(findings) == 1

    assert captured["command"][:5] == [
        "/usr/bin/osv-scanner",
        "scan",
        "source",
        "--format",
        "json",
    ]

    assert "--recursive" in captured["command"]


def test_osv_adapter_uses_lockfile_argument(
    tmp_path,
    monkeypatch,
):
    lockfile = tmp_path / "requirements.lock"
    lockfile.write_text(
        "requests==2.0.0\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {"results": []}
            ),
            stderr="",
        )

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter()

    assert adapter.scan(lockfile) == []

    assert "--lockfile" in captured["command"]
    assert str(lockfile) in captured["command"]


def test_osv_adapter_rejects_missing_executable(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: None,
    )

    adapter = OSVScannerAdapter()

    with pytest.raises(
        RuntimeError,
        match="executable",
    ):
        adapter.scan(tmp_path)


def test_osv_adapter_rejects_missing_target(tmp_path):
    adapter = OSVScannerAdapter()

    with pytest.raises(FileNotFoundError):
        adapter.scan(
            tmp_path / "missing"
        )


def test_osv_adapter_handles_timeout(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            kwargs["timeout"],
        )

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter()

    with pytest.raises(
        RuntimeError,
        match="timed out",
    ):
        adapter.scan(tmp_path)


def test_osv_adapter_handles_os_error(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    def fake_run(command, **kwargs):
        raise OSError("Execution failed")

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter()

    with pytest.raises(
        RuntimeError,
        match="Failed to execute",
    ):
        adapter.scan(tmp_path)


def test_osv_adapter_rejects_unexpected_exit_code(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr="Scanner execution failed",
        )

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter()

    with pytest.raises(
        RuntimeError,
        match="exit code 2",
    ):
        adapter.scan(tmp_path)


def test_osv_adapter_rejects_empty_output(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter()

    with pytest.raises(
        RuntimeError,
        match="empty JSON",
    ):
        adapter.scan(tmp_path)


def test_osv_adapter_rejects_invalid_json(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        osv_module.shutil,
        "which",
        lambda _: "/usr/bin/osv-scanner",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="{invalid json",
            stderr="",
        )

    monkeypatch.setattr(
        osv_module.subprocess,
        "run",
        fake_run,
    )

    adapter = OSVScannerAdapter()

    with pytest.raises(
        RuntimeError,
        match="invalid JSON",
    ):
        adapter.scan(tmp_path)
