import re
from dataclasses import dataclass
from pathlib import Path

from sycur_rag.chunker import PolicyChunk
from sycur_rag.core.constants import (
    DOMAIN_WEB_APPLICATION_SECURITY,
)
from sycur_rag.core.enums import KnowledgeLayer


CWE_PATTERN = re.compile(
    r"\bCWE-\d+\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ChunkMetadata:
    domain: str
    layer: str
    framework: str
    language: str
    topic: str | None
    subtopic: str | None
    cwe_ids: tuple[str, ...]


def _normalize_text(
    value: str,
) -> str:
    return " ".join(
        value.lower().split()
    )


def _detect_layer(
    source_path: Path,
) -> str:
    parts = {
        part.lower()
        for part in source_path.parts
    }

    if "01_requirements" in parts:
        return KnowledgeLayer.REQUIREMENTS.value

    if "02_testing" in parts:
        return KnowledgeLayer.TESTING.value

    if "03_risk_taxonomy" in parts:
        return KnowledgeLayer.RISK_TAXONOMY.value

    if "04_remediation" in parts:
        return KnowledgeLayer.REMEDIATION.value

    if "05_api_security" in parts:
        return KnowledgeLayer.API_SECURITY.value

    if "06_weakness_taxonomy" in parts:
        return KnowledgeLayer.WEAKNESS_TAXONOMY.value

    if "07_stack_guidance" in parts:
        return KnowledgeLayer.STACK_GUIDANCE.value

    raise ValueError(
        f"Unknown SYCUR knowledge layer: {source_path}"
    )


def _detect_framework(
    source_path: Path,
    layer: str,
) -> str:
    path_text = str(
        source_path
    ).lower()

    if layer == KnowledgeLayer.REQUIREMENTS.value:
        return "OWASP ASVS"

    if layer == KnowledgeLayer.TESTING.value:
        return "OWASP WSTG"

    if layer == KnowledgeLayer.RISK_TAXONOMY.value:
        return "OWASP Top 10"

    if layer == KnowledgeLayer.REMEDIATION.value:
        return "OWASP Cheat Sheet Series"

    if layer == KnowledgeLayer.API_SECURITY.value:
        return "OWASP API Security Top 10"

    if layer == KnowledgeLayer.WEAKNESS_TAXONOMY.value:
        return "MITRE CWE"

    if "django" in path_text:
        return "Django"

    if "spring" in path_text:
        return "Spring Security"

    if "asp.net" in path_text:
        return "ASP.NET Core"

    if "/python/" in path_text:
        return "Python"

    if "/java/" in path_text:
        return "Java"

    return "generic"


def _detect_language(
    source_path: Path,
) -> str:
    path_text = str(
        source_path
    ).lower()

    if "/python/" in path_text:
        return "python"

    if "django" in path_text:
        return "python"

    if "/java/" in path_text:
        return "java"

    if "spring" in path_text:
        return "java"

    if "asp.net" in path_text:
        return "csharp"

    return "generic"


def _extract_cwe_ids(
    chunk: PolicyChunk,
) -> tuple[str, ...]:
    text = " ".join(
        [
            chunk.title,
            chunk.content,
            chunk.control_id or "",
        ]
    )

    matches = {
        match.upper()
        for match in CWE_PATTERN.findall(text)
    }

    return tuple(
        sorted(
            matches,
            key=lambda value: int(
                value.split("-")[1]
            ),
        )
    )


def _detect_topic(
    chunk: PolicyChunk,
) -> tuple[str | None, str | None]:
    text = _normalize_text(
        " ".join(
            [
                chunk.title,
                chunk.section or "",
                chunk.content,
            ]
        )
    )

    rules = [
        (
            (
                "sql injection",
                "sql command",
            ),
            "injection",
            "sql_injection",
        ),
        (
            (
                "cross-site scripting",
                "cross site scripting",
                "xss",
            ),
            "injection",
            "cross_site_scripting",
        ),
        (
            (
                "command injection",
                "os command",
            ),
            "injection",
            "command_injection",
        ),
        (
            (
                "injection",
                "untrusted input",
            ),
            "injection",
            None,
        ),
        (
            (
                "broken object level authorization",
                "object level authorization",
                "bola",
            ),
            "access_control",
            "broken_object_level_authorization",
        ),
        (
            (
                "broken function level authorization",
                "function level authorization",
            ),
            "access_control",
            "broken_function_level_authorization",
        ),
        (
            (
                "access control",
                "authorization",
                "permission",
                "privilege",
            ),
            "access_control",
            None,
        ),
        (
            (
                "authentication",
                "credential",
                "password",
                "login",
            ),
            "authentication",
            None,
        ),
        (
            (
                "session",
                "cookie",
            ),
            "session_management",
            None,
        ),
        (
            (
                "cryptographic",
                "cryptography",
                "encryption",
                "tls",
            ),
            "cryptography",
            None,
        ),
        (
            (
                "security misconfiguration",
                "configuration",
            ),
            "security_configuration",
            None,
        ),
        (
            (
                "logging",
                "monitoring",
                "alerting",
            ),
            "logging_monitoring",
            None,
        ),
        (
            (
                "server-side request forgery",
                "server side request forgery",
                "ssrf",
            ),
            "ssrf",
            None,
        ),
        (
            (
                "software supply chain",
                "dependency",
                "dependencies",
            ),
            "supply_chain",
            None,
        ),
        (
            (
                "secret",
                "api key",
                "credential storage",
            ),
            "secrets_management",
            None,
        ),
        (
            (
                "exception",
                "error handling",
            ),
            "error_handling",
            None,
        ),
        (
            (
                "input validation",
                "output encoding",
                "sanitization",
                "escaping",
            ),
            "input_validation",
            None,
        ),
    ]

    for keywords, topic, subtopic in rules:
        if any(
            keyword in text
            for keyword in keywords
        ):
            return (
                topic,
                subtopic,
            )

    return (
        None,
        None,
    )


def extract_chunk_metadata(
    chunk: PolicyChunk,
    source_path: str | Path,
) -> ChunkMetadata:
    if not isinstance(chunk, PolicyChunk):
        raise TypeError(
            "chunk must be a PolicyChunk."
        )

    path = Path(
        source_path
    )

    layer = _detect_layer(
        path
    )

    framework = _detect_framework(
        path,
        layer,
    )

    language = _detect_language(
        path
    )

    topic, subtopic = _detect_topic(
        chunk
    )

    cwe_ids = _extract_cwe_ids(
        chunk
    )

    return ChunkMetadata(
        domain=DOMAIN_WEB_APPLICATION_SECURITY,
        layer=layer,
        framework=framework,
        language=language,
        topic=topic,
        subtopic=subtopic,
        cwe_ids=cwe_ids,
    )