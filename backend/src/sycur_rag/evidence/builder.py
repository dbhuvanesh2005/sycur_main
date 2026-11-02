from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from sycur_rag.retrieval.hybrid import (
    HybridSearchResult,
)


SHA256_PATTERN = re.compile(
    r"^[0-9a-f]{64}$"
)


@dataclass(frozen=True)
class EvidenceCandidate:
    evidence_key: str

    title: str
    content: str
    document_name: str

    retrieval_rank: int
    rrf_score: float

    layer: str | None
    framework: str | None
    language: str | None

    topic: str | None
    subtopic: str | None

    control_id: str | None
    cwe_ids: tuple[str, ...]

    source_path: str | None
    chunk_index: int | None
    content_hash: str

    retrieval_signals: tuple[str, ...]

    keyword_rank: int | None
    vector_rank: int | None
    graph_rank: int | None

    graph_depth: int | None
    graph_matched_seeds: tuple[str, ...]


def _stable_content_hash(
    result: HybridSearchResult,
) -> str:
    raw_hash = (
        result.content_hash.strip().lower()
        if result.content_hash
        else ""
    )

    if SHA256_PATTERN.fullmatch(
        raw_hash
    ):
        return raw_hash

    fallback = "\n".join(
        [
            result.source_path or "",
            (
                str(result.chunk_index)
                if result.chunk_index
                is not None
                else ""
            ),
            result.title.strip(),
            result.content.strip(),
        ]
    )

    return hashlib.sha256(
        fallback.encode("utf-8")
    ).hexdigest()


def _retrieval_signals(
    result: HybridSearchResult,
) -> tuple[str, ...]:
    signals: list[str] = []

    if result.keyword_rank is not None:
        signals.append(
            "keyword"
        )

    if result.vector_rank is not None:
        signals.append(
            "vector"
        )

    if result.graph_rank is not None:
        signals.append(
            "graph"
        )

    return tuple(
        signals
    )


def build_evidence_candidates(
    results: list[HybridSearchResult],
) -> list[EvidenceCandidate]:
    if not isinstance(
        results,
        list,
    ):
        raise TypeError(
            "results must be a list."
        )

    if not results:
        return []

    seen: set[str] = set()

    evidence: list[
        EvidenceCandidate
    ] = []

    for index, result in enumerate(
        results
    ):
        if not isinstance(
            result,
            HybridSearchResult,
        ):
            raise TypeError(
                "Result at index "
                f"{index} must be a "
                "HybridSearchResult."
            )

        title = result.title.strip()
        content = result.content.strip()
        document_name = (
            result.document_name.strip()
        )

        if not title:
            raise ValueError(
                "Evidence title cannot be empty."
            )

        if not content:
            raise ValueError(
                "Evidence content cannot be empty."
            )

        if not document_name:
            raise ValueError(
                "Evidence document_name "
                "cannot be empty."
            )

        content_hash = (
            _stable_content_hash(
                result
            )
        )

        evidence_key = (
            f"sha256:{content_hash}"
        )

        # HashSet defensive deduplication.
        if evidence_key in seen:
            continue

        seen.add(
            evidence_key
        )

        signals = _retrieval_signals(
            result
        )

        if not signals:
            raise ValueError(
                "Evidence candidate has no "
                "retrieval provenance."
            )

        evidence.append(
            EvidenceCandidate(
                evidence_key=evidence_key,

                title=title,
                content=content,
                document_name=(
                    document_name
                ),

                retrieval_rank=(
                    len(evidence) + 1
                ),

                rrf_score=float(
                    result.rrf_score
                ),

                layer=result.layer,
                framework=(
                    result.framework
                ),
                language=(
                    result.language
                ),

                topic=result.topic,
                subtopic=(
                    result.subtopic
                ),

                control_id=(
                    result.control_id
                ),

                cwe_ids=tuple(
                    result.cwe_ids or ()
                ),

                source_path=(
                    result.source_path
                ),

                chunk_index=(
                    result.chunk_index
                ),

                content_hash=(
                    content_hash
                ),

                retrieval_signals=(
                    signals
                ),

                keyword_rank=(
                    result.keyword_rank
                ),

                vector_rank=(
                    result.vector_rank
                ),

                graph_rank=(
                    result.graph_rank
                ),

                graph_depth=(
                    result.graph_depth
                ),

                graph_matched_seeds=tuple(
                    result.graph_matched_seeds
                    or ()
                ),
            )
        )

    return evidence
