from __future__ import annotations

import re
from dataclasses import dataclass

from sycur_rag.evidence.pack import (
    EvidencePack,
    EvidenceSource,
)


CWE_PATTERN = re.compile(
    r"\bCWE-\d+\b",
    re.IGNORECASE,
)

OWASP_TOP10_PATTERN = re.compile(
    r"\bA\d{2}:20\d{2}\b",
    re.IGNORECASE,
)

API_TOP10_PATTERN = re.compile(
    r"\bAPI\d{1,2}:20\d{2}\b",
    re.IGNORECASE,
)

WSTG_PATTERN = re.compile(
    r"\bWSTG-[A-Z0-9-]+\b",
    re.IGNORECASE,
)

ASVS_V_PATTERN = re.compile(
    r"\bV\d+\.\d+\.\d+\b",
    re.IGNORECASE,
)

ASVS_NAMED_PATTERN = re.compile(
    r"\bASVS\s+(V?\d+\.\d+\.\d+)\b",
    re.IGNORECASE,
)

ACRONYM_PATTERN = re.compile(
    r"\b[A-Z]{2,10}s?\b"
)

STANDARD_TECHNICAL_TERMS = frozenset({
    "API",
    "TLS",
    "CWE",
})


FRAMEWORK_PATTERNS = {
    "OWASP Top 10": re.compile(
        r"\bOWASP\s+Top\s+10\b",
        re.IGNORECASE,
    ),
    "OWASP ASVS": re.compile(
        r"\b(?:OWASP\s+)?ASVS\b",
        re.IGNORECASE,
    ),
    "OWASP WSTG": re.compile(
        r"\b(?:OWASP\s+)?WSTG\b",
        re.IGNORECASE,
    ),
    "OWASP API Security Top 10": re.compile(
        r"\bOWASP\s+API\s+Security\s+Top\s+10\b",
        re.IGNORECASE,
    ),
    "MITRE CWE": re.compile(
        r"\bMITRE\s+CWE\b",
        re.IGNORECASE,
    ),
    "NIST": re.compile(
        r"\bNIST\b",
        re.IGNORECASE,
    ),
    "PCI DSS": re.compile(
        r"\bPCI\s+DSS\b",
        re.IGNORECASE,
    ),
    "ISO 27001": re.compile(
        r"\bISO\s+27001\b",
        re.IGNORECASE,
    ),
    "SOC 2": re.compile(
        r"\bSOC\s+2\b",
        re.IGNORECASE,
    ),
}


POLICY_DECISION_PATTERNS = (
    re.compile(
        r"\b(?:status|decision|result)"
        r"\s*(?:is|=|:)\s*"
        r"(?:PASS|WARNING|FAIL)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bseverity\s*(?:is|=|:)\s*"
        r"(?:critical|high|medium|low)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bpolicy\s+action\s*"
        r"(?:is|=|:)",
        re.IGNORECASE,
    ),
)


@dataclass(frozen=True)
class FactValidationResult:
    cited_source_ids: tuple[int, ...]

    checked_identifiers: tuple[str, ...]
    checked_frameworks: tuple[str, ...]
    checked_terms: tuple[str, ...]

    unsupported_identifiers: tuple[str, ...]
    unsupported_frameworks: tuple[str, ...]
    unsupported_terms: tuple[str, ...]

    forbidden_policy_claims: tuple[str, ...]

    @property
    def is_valid(self) -> bool:
        return not (
            self.unsupported_identifiers
            or self.unsupported_frameworks
            or self.unsupported_terms
            or self.forbidden_policy_claims
        )


def _normalize_acronym(
    value: str,
) -> str:
    value = value.strip()

    if (
        value.endswith("s")
        and len(value) > 2
        and value[:-1].isupper()
    ):
        value = value[:-1]

    return value.upper()


def _unique(
    values: list[str],
) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            values
        )
    )


def _source_support_text(
    source: EvidenceSource,
) -> str:
    values = [
        source.title,
        source.content,
        source.document_name,
        source.framework or "",
        source.layer or "",
        source.language or "",
        source.topic or "",
        source.subtopic or "",
        source.control_id or "",
        " ".join(
            source.cwe_ids
        ),
        source.source_path or "",
    ]

    return "\n".join(
        values
    )


def _extract_identifiers(
    text: str,
) -> tuple[str, ...]:
    identifiers: list[str] = []

    patterns = (
        CWE_PATTERN,
        OWASP_TOP10_PATTERN,
        API_TOP10_PATTERN,
        WSTG_PATTERN,
        ASVS_V_PATTERN,
    )

    for pattern in patterns:
        identifiers.extend(
            match.group(0).upper()
            for match in pattern.finditer(
                text
            )
        )

    for match in (
        ASVS_NAMED_PATTERN.finditer(
            text
        )
    ):
        identifiers.append(
            match.group(1).upper()
        )

    return _unique(
        identifiers
    )


def _extract_frameworks(
    text: str,
) -> tuple[str, ...]:
    found: list[str] = []

    for (
        framework,
        pattern,
    ) in FRAMEWORK_PATTERNS.items():
        if pattern.search(
            text
        ):
            found.append(
                framework
            )

    return tuple(
        found
    )


def _extract_acronyms(
    text: str,
) -> tuple[str, ...]:
    values = []

    cwe_matches = tuple(
        CWE_PATTERN.finditer(text)
    )

    for match in ACRONYM_PATTERN.finditer(text):
        belongs_to_cwe_identifier = any(
            cwe.start() <= match.start()
            and match.end() <= cwe.end()
            for cwe in cwe_matches
        )

        if belongs_to_cwe_identifier:
            continue

        values.append(
            _normalize_acronym(
                match.group(0)
            )
        )

    return _unique(values)


def _contains_term(
    text: str,
    term: str,
) -> bool:
    normalized_text = (
        text.upper()
    )

    normalized_term = (
        term.upper()
    )

    pattern = re.compile(
        r"(?<![A-Z0-9])"
        + re.escape(
            normalized_term
        )
        + r"S?"
        + r"(?![A-Z0-9])"
    )

    return bool(
        pattern.search(
            normalized_text
        )
    )


def _find_policy_decisions(
    text: str,
) -> tuple[str, ...]:
    matches: list[str] = []

    for pattern in (
        POLICY_DECISION_PATTERNS
    ):
        matches.extend(
            match.group(0).strip()
            for match in pattern.finditer(
                text
            )
        )

    return _unique(
        matches
    )


def validate_grounded_facts(
    *,
    finding_summary: str,
    risk_explanation: str,
    required_action: str,
    source_ids: list[int],
    evidence_pack: EvidencePack,
    trusted_cwe_ids: tuple[str, ...] = (),
) -> FactValidationResult:
    if not isinstance(
        evidence_pack,
        EvidencePack,
    ):
        raise TypeError(
            "evidence_pack must be an "
            "EvidencePack."
        )

    for name, value in (
        (
            "finding_summary",
            finding_summary,
        ),
        (
            "risk_explanation",
            risk_explanation,
        ),
        (
            "required_action",
            required_action,
        ),
    ):
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{name} must be a string."
            )

        if not value.strip():
            raise ValueError(
                f"{name} cannot be empty."
            )

    if not isinstance(
        source_ids,
        list,
    ):
        raise TypeError(
            "source_ids must be a list."
        )

    if not all(
        isinstance(
            source_id,
            int,
        )
        and source_id > 0
        for source_id in source_ids
    ):
        raise ValueError(
            "source_ids contains an "
            "invalid source ID."
        )

    if len(
        source_ids
    ) != len(
        set(
            source_ids
        )
    ):
        raise ValueError(
            "source_ids contains duplicates."
        )

    if not isinstance(trusted_cwe_ids, tuple):
        raise TypeError(
            "trusted_cwe_ids must be a tuple."
        )

    trusted_cwe_id_set: set[str] = set()

    for cwe_id in trusted_cwe_ids:
        if not isinstance(cwe_id, str):
            raise TypeError(
                "Trusted CWE identifiers must be strings."
            )

        normalized_cwe = cwe_id.strip().upper()

        if not CWE_PATTERN.fullmatch(normalized_cwe):
            raise ValueError(
                f"Invalid trusted CWE identifier: {cwe_id}"
            )

        trusted_cwe_id_set.add(normalized_cwe)

    source_map = {
        source.source_id:
        source
        for source in (
            evidence_pack.sources
        )
    }

    missing_source_ids = [
        source_id
        for source_id
        in source_ids
        if source_id
        not in source_map
    ]

    if missing_source_ids:
        raise ValueError(
            "source_ids contains source IDs "
            "not present in EvidencePack: "
            + ", ".join(
                str(source_id)
                for source_id
                in missing_source_ids
            )
        )

    generated_text = "\n".join(
        [
            finding_summary.strip(),
            risk_explanation.strip(),
            required_action.strip(),
        ]
    )

    cited_sources = [
        source_map[
            source_id
        ]
        for source_id in source_ids
    ]

    cited_support_text = "\n".join(
        _source_support_text(
            source
        )
        for source in cited_sources
    )

    identifiers = (
        _extract_identifiers(
            generated_text
        )
    )

    frameworks = (
        _extract_frameworks(
            generated_text
        )
    )

    terms = _extract_acronyms(
        generated_text
    )

    unsupported_identifiers = tuple(
        identifier
        for identifier in identifiers
        if (
            identifier not in trusted_cwe_id_set
            and not _contains_term(
                cited_support_text,
                identifier,
            )
        )
    )

    unsupported_frameworks = tuple(
        framework
        for framework in frameworks
        if framework.lower()
        not in (
            cited_support_text.lower()
        )
    )

    unsupported_terms = tuple(
        term
        for term in terms
        if (
            term not in STANDARD_TECHNICAL_TERMS
            and not _contains_term(
                cited_support_text,
                term,
            )
        )
    )

    forbidden_policy_claims = (
        _find_policy_decisions(
            generated_text
        )
    )

    return FactValidationResult(
        cited_source_ids=tuple(
            source_ids
        ),

        checked_identifiers=(
            identifiers
        ),

        checked_frameworks=(
            frameworks
        ),

        checked_terms=(
            terms
        ),

        unsupported_identifiers=(
            unsupported_identifiers
        ),

        unsupported_frameworks=(
            unsupported_frameworks
        ),

        unsupported_terms=(
            unsupported_terms
        ),

        forbidden_policy_claims=(
            forbidden_policy_claims
        ),
    )


def require_grounded_facts(
    *,
    finding_summary: str,
    risk_explanation: str,
    required_action: str,
    source_ids: list[int],
    evidence_pack: EvidencePack,
    trusted_cwe_ids: tuple[str, ...] = (),
) -> FactValidationResult:
    result = validate_grounded_facts(
        finding_summary=(
            finding_summary
        ),
        risk_explanation=(
            risk_explanation
        ),
        required_action=(
            required_action
        ),
        source_ids=(
            source_ids
        ),
        evidence_pack=(
            evidence_pack
        ),
        trusted_cwe_ids=trusted_cwe_ids,
    )

    if not result.is_valid:
        reasons: list[str] = []

        if (
            result.unsupported_identifiers
        ):
            reasons.append(
                "unsupported identifiers: "
                + ", ".join(
                    result
                    .unsupported_identifiers
                )
            )

        if (
            result.unsupported_frameworks
        ):
            reasons.append(
                "unsupported frameworks: "
                + ", ".join(
                    result
                    .unsupported_frameworks
                )
            )

        if result.unsupported_terms:
            reasons.append(
                "unsupported technical terms: "
                + ", ".join(
                    result
                    .unsupported_terms
                )
            )

        if (
            result.forbidden_policy_claims
        ):
            reasons.append(
                "LLM attempted policy "
                "decision: "
                + ", ".join(
                    result
                    .forbidden_policy_claims
                )
            )

        raise RuntimeError(
            "Grounded fact validation failed: "
            + "; ".join(
                reasons
            )
        )

    return result
