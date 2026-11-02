from pathlib import Path

from sycur_rag.core.config import get_settings
from sycur_rag.core.enums import KnowledgeLayer
from sycur_rag.models.retrieval import RetrievalQuery


LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".cs": "csharp",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


TOPIC_RULES = [
    (
        (
            "sql injection",
            "sql command",
            "cwe-89",
        ),
        "injection",
        "sql_injection",
    ),
    (
        (
            "cross-site scripting",
            "cross site scripting",
            "xss",
            "cwe-79",
        ),
        "injection",
        "cross_site_scripting",
    ),
    (
        (
            "command injection",
            "os command",
            "cwe-78",
        ),
        "injection",
        "command_injection",
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
            "server-side request forgery",
            "server side request forgery",
            "ssrf",
            "cwe-918",
        ),
        "ssrf",
        None,
    ),
    (
        (
            "secret",
            "api key",
            "hardcoded credential",
        ),
        "secrets_management",
        None,
    ),
    (
        (
            "dependency",
            "supply chain",
            "vulnerable package",
        ),
        "supply_chain",
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
            "cryptographic",
            "encryption",
            "tls",
        ),
        "cryptography",
        None,
    ),
]


def _detect_language(
    file_path: str | None,
) -> str:
    if not file_path:
        return "generic"

    suffix = Path(
        file_path
    ).suffix.lower()

    return LANGUAGE_BY_EXTENSION.get(
        suffix,
        "generic",
    )


def _detect_framework(
    file_path: str | None,
) -> str:
    if not file_path:
        return "generic"

    lowered = file_path.lower()

    if "django" in lowered:
        return "Django"

    if (
        "spring" in lowered
        or "pom.xml" in lowered
        or "build.gradle" in lowered
    ):
        return "Spring Security"

    if (
        "asp.net" in lowered
        or ".csproj" in lowered
    ):
        return "ASP.NET Core"

    return "generic"


def _detect_topic(
    query_text: str,
    cwe_ids: list[str],
    rule_id: str | None,
) -> tuple[str | None, str | None]:
    searchable = " ".join(
        [
            query_text,
            " ".join(cwe_ids),
            rule_id or "",
        ]
    ).lower()

    for keywords, topic, subtopic in TOPIC_RULES:
        if any(
            keyword in searchable
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


def _preferred_layers(
    *,
    topic: str | None,
    file_path: str | None,
) -> list[str]:
    layers = [
        KnowledgeLayer.REQUIREMENTS.value,
        KnowledgeLayer.WEAKNESS_TAXONOMY.value,
        KnowledgeLayer.RISK_TAXONOMY.value,
        KnowledgeLayer.REMEDIATION.value,
        KnowledgeLayer.TESTING.value,
    ]

    lowered_path = (
        file_path.lower()
        if file_path
        else ""
    )

    if (
        "/api/" in lowered_path
        or "controller" in lowered_path
        or "route" in lowered_path
        or "endpoint" in lowered_path
    ):
        layers.insert(
            1,
            KnowledgeLayer.API_SECURITY.value,
        )

    if file_path:
        layers.append(
            KnowledgeLayer.STACK_GUIDANCE.value
        )

    return layers


def route_retrieval_query(
    *,
    query_text: str,
    cwe_ids: list[str] | None = None,
    scanner: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    topic: str | None = None,
    subtopic: str | None = None,
    framework: str | None = None,
    language: str | None = None,
    preferred_layers: list[str] | None = None,
    top_k: int | None = None,
) -> RetrievalQuery:
    settings = get_settings()

    normalized_cwes = [
        value.strip().upper()
        for value in (cwe_ids or [])
    ]

    detected_topic, detected_subtopic = (
        _detect_topic(
            query_text=query_text,
            cwe_ids=normalized_cwes,
            rule_id=rule_id,
        )
    )

    final_topic = (
        topic
        if topic is not None
        else detected_topic
    )

    final_subtopic = (
        subtopic
        if subtopic is not None
        else detected_subtopic
    )

    detected_language = _detect_language(
        file_path
    )

    final_language = (
        language
        if language is not None
        else detected_language
    )

    detected_framework = _detect_framework(
        file_path
    )

    final_framework = (
        framework
        if framework is not None
        else detected_framework
    )

    final_layers = (
        list(preferred_layers)
        if preferred_layers is not None
        else _preferred_layers(
            topic=final_topic,
            file_path=file_path,
        )
    )

    return RetrievalQuery(
        query_text=query_text,
        topic=final_topic,
        subtopic=final_subtopic,
        cwe_ids=normalized_cwes,
        frameworks=[
            final_framework
        ],
        languages=[
            final_language
        ],
        preferred_layers=final_layers,
        scanner=scanner,
        rule_id=rule_id,
        file_path=file_path,
        top_k=(
            top_k
            if top_k is not None
            else settings.FINAL_TOP_K
        ),
    )