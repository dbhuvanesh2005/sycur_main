from __future__ import annotations

import json
from dataclasses import dataclass

from sycur_rag.evidence.knapsack import (
    EvidenceSelection,
)


@dataclass(frozen=True)
class EvidenceSource:
    source_id: int

    title: str
    content: str
    document_name: str

    framework: str | None
    layer: str | None
    language: str | None

    topic: str | None
    subtopic: str | None

    control_id: str | None
    cwe_ids: tuple[str, ...]

    source_path: str | None
    chunk_index: int | None
    content_hash: str

    estimated_tokens: int

    retrieval_signals: tuple[str, ...]

    keyword_rank: int | None
    vector_rank: int | None
    graph_rank: int | None

    graph_depth: int | None
    graph_matched_seeds: tuple[str, ...]


@dataclass(frozen=True)
class EvidencePack:
    query_text: str

    sources: tuple[
        EvidenceSource,
        ...
    ]

    estimated_tokens: int
    token_budget: int

    selection_strategy: str
    excluded_count: int

    @property
    def source_ids(
        self,
    ) -> tuple[int, ...]:
        return tuple(
            source.source_id
            for source in self.sources
        )

    @property
    def has_evidence(
        self,
    ) -> bool:
        return bool(
            self.sources
        )


def _validate_query_text(
    query_text: str,
) -> str:
    if not isinstance(
        query_text,
        str,
    ):
        raise TypeError(
            "query_text must be a string."
        )

    normalized = (
        query_text.strip()
    )

    if not normalized:
        raise ValueError(
            "query_text cannot be empty."
        )

    return normalized


def build_evidence_pack(
    query_text: str,
    selection: EvidenceSelection,
) -> EvidencePack:
    normalized_query = (
        _validate_query_text(
            query_text
        )
    )

    if not isinstance(
        selection,
        EvidenceSelection,
    ):
        raise TypeError(
            "selection must be an "
            "EvidenceSelection."
        )

    if (
        selection.estimated_tokens
        > selection.token_budget
    ):
        raise ValueError(
            "Evidence selection exceeds "
            "its token budget."
        )

    sources: list[
        EvidenceSource
    ] = []

    seen_keys: set[str] = set()

    for source_id, item in enumerate(
        selection.selected,
        start=1,
    ):
        candidate = item.candidate

        if (
            candidate.evidence_key
            in seen_keys
        ):
            raise ValueError(
                "Duplicate evidence detected "
                "while building EvidencePack."
            )

        seen_keys.add(
            candidate.evidence_key
        )

        title = (
            candidate.title.strip()
        )

        content = (
            candidate.content.strip()
        )

        document_name = (
            candidate.document_name.strip()
        )

        if not title:
            raise ValueError(
                "Evidence source title "
                "cannot be empty."
            )

        if not content:
            raise ValueError(
                "Evidence source content "
                "cannot be empty."
            )

        if not document_name:
            raise ValueError(
                "Evidence source document_name "
                "cannot be empty."
            )

        if item.estimated_tokens <= 0:
            raise ValueError(
                "Evidence estimated_tokens "
                "must be greater than zero."
            )

        sources.append(
            EvidenceSource(
                source_id=source_id,

                title=title,
                content=content,
                document_name=(
                    document_name
                ),

                framework=(
                    candidate.framework
                ),

                layer=(
                    candidate.layer
                ),

                language=(
                    candidate.language
                ),

                topic=(
                    candidate.topic
                ),

                subtopic=(
                    candidate.subtopic
                ),

                control_id=(
                    candidate.control_id
                ),

                cwe_ids=tuple(
                    candidate.cwe_ids
                ),

                source_path=(
                    candidate.source_path
                ),

                chunk_index=(
                    candidate.chunk_index
                ),

                content_hash=(
                    candidate.content_hash
                ),

                estimated_tokens=(
                    item.estimated_tokens
                ),

                retrieval_signals=tuple(
                    candidate.retrieval_signals
                ),

                keyword_rank=(
                    candidate.keyword_rank
                ),

                vector_rank=(
                    candidate.vector_rank
                ),

                graph_rank=(
                    candidate.graph_rank
                ),

                graph_depth=(
                    candidate.graph_depth
                ),

                graph_matched_seeds=tuple(
                    candidate.graph_matched_seeds
                ),
            )
        )

    calculated_tokens = sum(
        source.estimated_tokens
        for source in sources
    )

    if (
        calculated_tokens
        != selection.estimated_tokens
    ):
        raise ValueError(
            "Evidence token accounting "
            "does not match selection."
        )

    return EvidencePack(
        query_text=(
            normalized_query
        ),

        sources=tuple(
            sources
        ),

        estimated_tokens=(
            calculated_tokens
        ),

        token_budget=(
            selection.token_budget
        ),

        selection_strategy=(
            selection.strategy
        ),

        excluded_count=(
            selection.excluded_count
        ),
    )


def evidence_pack_to_dict(
    pack: EvidencePack,
) -> dict:
    if not isinstance(
        pack,
        EvidencePack,
    ):
        raise TypeError(
            "pack must be an EvidencePack."
        )

    return {
        "query": pack.query_text,

        "evidence": [
            {
                "source_id": (
                    source.source_id
                ),

                "title": (
                    source.title
                ),

                "content": (
                    source.content
                ),

                "document_name": (
                    source.document_name
                ),

                "framework": (
                    source.framework
                ),

                "layer": (
                    source.layer
                ),

                "language": (
                    source.language
                ),

                "topic": (
                    source.topic
                ),

                "subtopic": (
                    source.subtopic
                ),

                "control_id": (
                    source.control_id
                ),

                "cwe_ids": list(
                    source.cwe_ids
                ),

                "source_path": (
                    source.source_path
                ),

                "chunk_index": (
                    source.chunk_index
                ),

                "content_hash": (
                    source.content_hash
                ),
            }
            for source in pack.sources
        ],
    }


def render_evidence_context(
    pack: EvidencePack,
) -> str:
    """
    Render deterministic JSON for the LLM.

    Evidence content is treated as untrusted
    data by the LLM prompt. JSON encoding also
    prevents document text from changing the
    surrounding prompt structure.
    """

    payload = (
        evidence_pack_to_dict(
            pack
        )
    )

    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )