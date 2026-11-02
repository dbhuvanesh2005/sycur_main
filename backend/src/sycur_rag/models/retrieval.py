from dataclasses import dataclass, field


@dataclass(frozen=True)
class RetrievalQuery:
    query_text: str

    domain: str = "web_application_security"

    topic: str | None = None
    subtopic: str | None = None

    cwe_ids: list[str] = field(
        default_factory=list
    )

    frameworks: list[str] = field(
        default_factory=lambda: [
            "generic"
        ]
    )

    languages: list[str] = field(
        default_factory=lambda: [
            "generic"
        ]
    )

    preferred_layers: list[str] = field(
        default_factory=list
    )

    scanner: str | None = None
    rule_id: str | None = None
    file_path: str | None = None

    top_k: int = 10

    def __post_init__(self) -> None:
        query_text = self.query_text.strip()

        if not query_text:
            raise ValueError(
                "query_text cannot be empty."
            )

        if self.top_k <= 0:
            raise ValueError(
                "top_k must be greater than zero."
            )

        normalized_cwes = []

        for cwe_id in self.cwe_ids:
            value = cwe_id.strip().upper()

            if not value.startswith("CWE-"):
                raise ValueError(
                    f"Invalid CWE ID: {cwe_id}"
                )

            normalized_cwes.append(
                value
            )

        object.__setattr__(
            self,
            "query_text",
            query_text,
        )

        object.__setattr__(
            self,
            "cwe_ids",
            normalized_cwes,
        )