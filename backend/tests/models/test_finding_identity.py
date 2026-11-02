import hashlib

import pytest
from pydantic import ValidationError

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding


def create_finding(**overrides):
    values = {
        "scanner": "semgrep",
        "rule_id": "python.security.sql-injection",
        "title": "SQL Injection",
        "message": "Potential SQL injection vulnerability.",
        "severity": Severity.HIGH,
        "file_path": "src/database.py",
        "line_start": 10,
        "line_end": 12,
        "code_snippet": "cursor.execute(query)",
        "cwe_ids": ("CWE-89",),
    }
    values.update(overrides)
    return ScannerFinding(**values)


def _make_tracking_finding(**overrides):
    values = {
        "scanner": "semgrep",
        "rule_id": "python.security.test",
        "title": "Potential security issue",
        "message": "Potential unsafe operation",
        "severity": Severity.HIGH,
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 12,
        "code_snippet": "subprocess.call(user_input)",
        "cwe_ids": ("CWE-78",),
    }

    values.update(overrides)

    return ScannerFinding(**values)


def test_existing_finding_id_algorithm_is_unchanged():
    finding = create_finding()

    legacy_identity = "\x1f".join(
        [
            "semgrep",
            "python.security.sql-injection",
            "src/database.py",
            "10",
            "12",
            "Potential SQL injection vulnerability.",
        ]
    )

    assert finding.finding_id == hashlib.sha256(
        legacy_identity.encode("utf-8")
    ).hexdigest()


def test_legacy_finding_payload_remains_valid():
    payload = create_finding().model_dump(
        exclude={
            "finding_id",
            "package_name",
            "package_ecosystem",
        }
    )

    restored = ScannerFinding.model_validate(payload)

    assert restored.package_name is None
    assert restored.package_ecosystem is None
    assert restored.finding_id == create_finding().finding_id


def test_fingerprint_survives_message_and_line_changes():
    original = create_finding()
    moved = create_finding(
        title="SQL injection detected",
        message="Scanner wording changed.",
        severity=Severity.CRITICAL,
        line_start=110,
        line_end=112,
        code_snippet="    cursor.execute(query)",
    )

    assert original.finding_id != moved.finding_id
    assert (
        original.vulnerability_fingerprint
        == moved.vulnerability_fingerprint
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule_id": "python.security.command-injection"},
        {"file_path": "src/admin.py"},
        {"code_snippet": "cursor.execute(safe_query)"},
        {"cwe_ids": ("CWE-78",)},
    ],
)
def test_fingerprint_distinguishes_security_identity(overrides):
    assert (
        create_finding().vulnerability_fingerprint
        != create_finding(**overrides).vulnerability_fingerprint
    )


def test_dependency_fingerprint_uses_cve_and_package_identity():
    requests_finding = create_finding(
        scanner="trivy",
        rule_id="cve-2025-12345",
        title="Dependency vulnerability",
        message="Original scanner message.",
        file_path="requirements.txt",
        line_start=None,
        line_end=None,
        code_snippet=None,
        cwe_ids=("cwe-79", "CWE-89"),
        package_name="Requests",
        package_ecosystem="PyPI",
    )
    same_vulnerability = create_finding(
        scanner="TRIVY",
        rule_id="CVE-2025-12345",
        title="Renamed title",
        message="Updated scanner message.",
        file_path="./requirements.txt",
        line_start=None,
        line_end=None,
        code_snippet=None,
        cwe_ids=("CWE-89", "CWE-79"),
        package_name="requests",
        package_ecosystem="pypi",
    )
    different_package = same_vulnerability.model_copy(
        update={"package_name": "urllib3"}
    )

    assert (
        requests_finding.vulnerability_fingerprint
        == same_vulnerability.vulnerability_fingerprint
    )
    assert (
        requests_finding.vulnerability_fingerprint
        != different_package.vulnerability_fingerprint
    )


def test_location_is_only_fallback_without_stable_context():
    first = create_finding(
        scanner="gitleaks",
        rule_id="generic-api-key",
        code_snippet=None,
        cwe_ids=(),
        line_start=10,
        line_end=10,
    )
    second = first.model_copy(
        update={
            "line_start": 20,
            "line_end": 20,
        }
    )

    assert (
        first.vulnerability_fingerprint
        != second.vulnerability_fingerprint
    )


def test_fingerprint_is_sha256_and_not_serialized():
    finding = create_finding()

    assert len(finding.vulnerability_fingerprint) == 64
    assert all(
        character in "0123456789abcdef"
        for character in finding.vulnerability_fingerprint
    )
    assert "vulnerability_fingerprint" not in finding.model_dump()


@pytest.mark.parametrize(
    "field",
    [
        "package_name",
        "package_ecosystem",
    ],
)
def test_package_identity_rejects_blank_values(field):
    with pytest.raises(ValueError):
        create_finding(**{field: "   "})


def test_package_ecosystem_requires_package_name():
    with pytest.raises(ValueError):
        create_finding(
            package_ecosystem="PyPI",
        )


def test_tracking_identity_falls_back_to_finding_id():
    finding = _make_tracking_finding()

    assert finding.tracking_fingerprint is None

    assert (
        finding.tracking_identity
        == finding.finding_id
    )

    assert (
        "tracking_identity"
        not in finding.model_dump()
    )


def test_tracking_identity_prefers_native_fingerprint():
    fingerprint = "a" * 64

    finding = _make_tracking_finding(
        tracking_fingerprint=fingerprint,
    )

    assert (
        finding.tracking_identity
        == fingerprint
    )


def test_tracking_fingerprint_normalizes_sha256_prefix():
    fingerprint = "A" * 64

    finding = _make_tracking_finding(
        tracking_fingerprint=f"sha256:{fingerprint}",
    )

    assert (
        finding.tracking_fingerprint
        == fingerprint.lower()
    )


@pytest.mark.parametrize(
    "fingerprint",
    [
        "",
        " ",
        "invalid",
        "g" * 64,
        "sha256:invalid",
    ],
)
def test_invalid_tracking_fingerprint_is_rejected(
    fingerprint,
):
    with pytest.raises(ValidationError):
        _make_tracking_finding(
            tracking_fingerprint=fingerprint,
        )


def test_tracking_identity_survives_location_and_message_changes():
    fingerprint = "b" * 64

    original = _make_tracking_finding(
        tracking_fingerprint=fingerprint,
    )

    updated = _make_tracking_finding(
        tracking_fingerprint=fingerprint,
        file_path="src/renamed_app.py",
        line_start=40,
        line_end=45,
        message="Updated scanner message",
    )

    assert original.finding_id != updated.finding_id

    assert (
        original.tracking_identity
        == updated.tracking_identity
    )


def test_old_finding_json_remains_compatible():
    original = _make_tracking_finding()

    old_payload = original.model_dump(
        exclude={
            "finding_id",
            "tracking_fingerprint",
        }
    )

    restored = ScannerFinding.model_validate(
        old_payload
    )

    assert restored.tracking_fingerprint is None

    assert (
        restored.tracking_identity
        == restored.finding_id
    )


def test_vulnerability_aliases_are_normalized():
    finding = _make_tracking_finding(
        vulnerability_aliases=(
            " ghsa-abcd-efgh-ijkl ",
            "CVE-2024-12345",
            "GHSA-ABCD-EFGH-IJKL",
        ),
    )

    assert finding.vulnerability_aliases == (
        "CVE-2024-12345",
        "GHSA-ABCD-EFGH-IJKL",
    )


def test_blank_vulnerability_alias_is_rejected():
    with pytest.raises(ValidationError):
        _make_tracking_finding(
            vulnerability_aliases=(" ",),
        )
