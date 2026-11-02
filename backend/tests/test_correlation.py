from sycur_rag.correlation import findings_correlate
from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding


def make_finding(
    scanner: str,
    package: str | None = None,
    ecosystem: str | None = None,
    rule_id: str = "CVE-2024-12345",
    aliases: tuple[str, ...] = (),
) -> ScannerFinding:
    return ScannerFinding(
        scanner=scanner,
        rule_id=rule_id,
        title="Dependency vulnerability",
        message="Vulnerable dependency detected",
        severity=Severity.HIGH,
        file_path="requirements.txt",
        vulnerability_aliases=aliases,
        package_name=package,
        package_ecosystem=ecosystem,
    )


def test_matching_package_correlates():
    assert findings_correlate(
        make_finding("trivy", "django", "PyPI"),
        make_finding("osv", "Django", "pypi"),
    )


def test_different_packages_do_not_correlate():
    assert not findings_correlate(
        make_finding("trivy", "django", "PyPI"),
        make_finding("osv", "requests", "PyPI"),
    )


def test_different_ecosystems_do_not_correlate():
    assert not findings_correlate(
        make_finding("trivy", "django", "PyPI"),
        make_finding("osv", "django", "npm"),
    )


def test_partial_package_metadata_does_not_correlate():
    assert not findings_correlate(
        make_finding("trivy", "django", "PyPI"),
        make_finding("osv"),
    )


def test_legacy_findings_remain_compatible():
    assert findings_correlate(
        make_finding("trivy"),
        make_finding("osv"),
    )


def test_different_cves_do_not_correlate():
    assert not findings_correlate(
        make_finding("trivy", "django", "PyPI"),
        make_finding(
            "osv",
            "django",
            "PyPI",
            rule_id="CVE-2024-99999",
        ),
    )


def test_cve_and_ghsa_aliases_correlate():
    cve = make_finding(
        "trivy",
        "django",
        "PyPI",
        rule_id="CVE-2024-12345",
    )

    ghsa = make_finding(
        "osv",
        "django",
        "PyPI",
        rule_id="GHSA-ABCD-EFGH-IJKL",
        aliases=("CVE-2024-12345",),
    )

    assert findings_correlate(cve, ghsa)
    assert findings_correlate(ghsa, cve)


def test_osv_advisory_alias_correlates():
    first = make_finding(
        "trivy",
        "django",
        "PyPI",
        rule_id="CVE-2024-12345",
        aliases=("PYSEC-2024-100",),
    )

    second = make_finding(
        "osv",
        "django",
        "PyPI",
        rule_id="PYSEC-2024-100",
    )

    assert findings_correlate(first, second)


def test_shared_alias_different_packages_not_merged():
    first = make_finding(
        "trivy",
        "django",
        "PyPI",
        aliases=("GHSA-ABCD-EFGH-IJKL",),
    )

    second = make_finding(
        "osv",
        "requests",
        "PyPI",
        rule_id="GHSA-ABCD-EFGH-IJKL",
    )

    assert not findings_correlate(first, second)


def test_same_package_disjoint_advisories_not_merged():
    first = make_finding(
        "trivy",
        "django",
        "PyPI",
        rule_id="CVE-2024-12345",
    )

    second = make_finding(
        "osv",
        "django",
        "PyPI",
        rule_id="GHSA-ABCD-EFGH-IJKL",
    )

    assert not findings_correlate(first, second)


def test_cross_alias_without_package_not_merged():
    first = make_finding(
        "trivy",
        rule_id="CVE-2024-12345",
    )

    second = make_finding(
        "osv",
        rule_id="GHSA-ABCD-EFGH-IJKL",
        aliases=("CVE-2024-12345",),
    )

    assert not findings_correlate(first, second)


def test_unrelated_rule_identifiers_not_merged():
    first = make_finding(
        "trivy",
        "django",
        "PyPI",
        rule_id="UNRELATED-RULE",
    )

    second = make_finding(
        "osv",
        "django",
        "PyPI",
        rule_id="UNRELATED-RULE",
    )

    assert not findings_correlate(first, second)
