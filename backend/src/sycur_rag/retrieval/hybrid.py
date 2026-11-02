import hashlib
import logging
from dataclasses import dataclass

from sycur_rag.core.config import get_settings
from sycur_rag.database import SearchResult
from sycur_rag.embeddings import embed_text
from sycur_rag.models.retrieval import RetrievalQuery
from sycur_rag.retrieval.graph import (
    GraphSearchResult,
    search_graph_chunks,
)
from sycur_rag.retrieval.keyword import (
    KeywordSearchResult,
    search_keyword_chunks,
)
from sycur_rag.retrieval.router import route_retrieval_query
from sycur_rag.retrieval.vector import search_vector_chunks


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HybridSearchResult:
    title: str
    content: str
    document_name: str
    policy_type: str | None
    section: str | None
    control_id: str | None

    rrf_score: float

    keyword_rank: int | None
    vector_rank: int | None

    keyword_score: float | None
    vector_similarity: float | None

    domain: str | None
    layer: str | None
    framework: str | None
    language: str | None
    topic: str | None
    subtopic: str | None
    cwe_ids: tuple[str, ...]

    chunk_index: int | None
    content_hash: str | None
    source_path: str | None

    graph_rank: int | None = None
    graph_depth: int | None = None
    graph_matched_seeds: tuple[str, ...] = ()


def _result_key(
    *,
    content_hash: str | None,
    source_path: str | None,
    chunk_index: int | None,
    title: str,
    content: str,
) -> str:
    if content_hash:
        return f"hash:{content_hash}"

    if (
        source_path is not None
        and chunk_index is not None
    ):
        return (
            f"source:{source_path}"
            f":chunk:{chunk_index}"
        )

    fallback = (
        title.strip()
        + "\n"
        + content.strip()
    )

    digest = hashlib.sha256(
        fallback.encode("utf-8")
    ).hexdigest()

    return f"fallback:{digest}"


def _validate_positive(
    name: str,
    value: int,
) -> int:
    if not isinstance(value, int):
        raise TypeError(
            f"{name} must be an integer."
        )

    if value <= 0:
        raise ValueError(
            f"{name} must be greater than zero."
        )

    return value


def _rrf_fuse(
    keyword_results: list[KeywordSearchResult],
    vector_results: list[SearchResult],
    *,
    graph_results: list[GraphSearchResult] | None = None,
    final_top_k: int,
    rrf_k: int = 60,
) -> list[HybridSearchResult]:
    _validate_positive(
        "final_top_k",
        final_top_k,
    )

    _validate_positive(
        "rrf_k",
        rrf_k,
    )

    graph_results = (
        graph_results
        if graph_results is not None
        else []
    )

    combined: dict[str, dict] = {}

    for rank, result in enumerate(
        keyword_results,
        start=1,
    ):
        key = _result_key(
            content_hash=result.content_hash,
            source_path=result.source_path,
            chunk_index=result.chunk_index,
            title=result.title,
            content=result.content,
        )

        combined[key] = {
            "result": result,
            "rrf_score": (
                1.0 / (rrf_k + rank)
            ),
            "keyword_rank": rank,
            "vector_rank": None,
            "keyword_score": result.rank,
            "vector_similarity": None,
            "graph_rank": None,
            "graph_depth": None,
            "graph_matched_seeds": (),
        }

    for rank, result in enumerate(
        vector_results,
        start=1,
    ):
        key = _result_key(
            content_hash=result.content_hash,
            source_path=result.source_path,
            chunk_index=result.chunk_index,
            title=result.title,
            content=result.content,
        )

        score = (
            1.0 / (rrf_k + rank)
        )

        if key in combined:
            combined[key]["rrf_score"] += (
                score
            )

            combined[key]["vector_rank"] = (
                rank
            )

            combined[key][
                "vector_similarity"
            ] = result.similarity

        else:
            combined[key] = {
                "result": result,
                "rrf_score": score,
                "keyword_rank": None,
                "vector_rank": rank,
                "keyword_score": None,
                "vector_similarity": (
                    result.similarity
                ),
                "graph_rank": None,
                "graph_depth": None,
                "graph_matched_seeds": (),
            }

    for rank, result in enumerate(
        graph_results,
        start=1,
    ):
        key = _result_key(
            content_hash=result.content_hash,
            source_path=result.source_path,
            chunk_index=result.chunk_index,
            title=result.title,
            content=result.content,
        )

        score = 1.0 / (rrf_k + rank)

        if key in combined:
            combined[key]["rrf_score"] += score
            combined[key]["graph_rank"] = rank
            combined[key]["graph_depth"] = (
                result.graph_depth
            )
            combined[key]["graph_matched_seeds"] = (
                result.matched_seeds
            )
        else:
            combined[key] = {
                "result": result,
                "rrf_score": score,
                "keyword_rank": None,
                "vector_rank": None,
                "keyword_score": None,
                "vector_similarity": None,
                "graph_rank": rank,
                "graph_depth": result.graph_depth,
                "graph_matched_seeds": (
                    result.matched_seeds
                ),
            }

    ordered = sorted(
        combined.values(),
        key=lambda item: (
            -item["rrf_score"],
            item["keyword_rank"]
            if item["keyword_rank"] is not None
            else 10**9,
            item["vector_rank"]
            if item["vector_rank"] is not None
            else 10**9,
            item["graph_rank"]
            if item["graph_rank"] is not None
            else 10**9,
        ),
    )

    output: list[HybridSearchResult] = []

    for item in ordered[
        :final_top_k
    ]:
        result = item["result"]

        output.append(
            HybridSearchResult(
                title=result.title,
                content=result.content,
                document_name=(
                    result.document_name
                ),
                policy_type=(
                    result.policy_type
                ),
                section=result.section,
                control_id=result.control_id,

                rrf_score=float(
                    item["rrf_score"]
                ),

                keyword_rank=(
                    item["keyword_rank"]
                ),
                vector_rank=(
                    item["vector_rank"]
                ),

                keyword_score=(
                    item["keyword_score"]
                ),
                vector_similarity=(
                    item["vector_similarity"]
                ),

                domain=result.domain,
                layer=result.layer,
                framework=result.framework,
                language=result.language,
                topic=result.topic,
                subtopic=result.subtopic,
                cwe_ids=tuple(
                    result.cwe_ids or ()
                ),

                chunk_index=(
                    result.chunk_index
                ),
                content_hash=(
                    result.content_hash
                ),
                source_path=(
                    result.source_path
                ),
                graph_rank=(
                    item["graph_rank"]
                ),
                graph_depth=(
                    item["graph_depth"]
                ),
                graph_matched_seeds=(
                    item["graph_matched_seeds"]
                ),
            )
        )

    return output


def _search_graph_safely(
    query: RetrievalQuery,
    *,
    top_k: int,
) -> list[GraphSearchResult]:
    try:
        return search_graph_chunks(
            query,
            top_k=top_k,
        )
    except Exception:
        logger.exception(
            "Security graph retrieval failed. "
            "Continuing with keyword/vector retrieval."
        )
        return []


def search_retrieval_query(
    query: RetrievalQuery,
) -> list[HybridSearchResult]:
    if not isinstance(query, RetrievalQuery):
        raise TypeError(
            "query must be a RetrievalQuery."
        )

    settings = get_settings()

    graph_top_k = max(
        settings.KEYWORD_TOP_K,
        settings.VECTOR_TOP_K,
        query.top_k,
    )
    graph_results = _search_graph_safely(
        query,
        top_k=graph_top_k,
    )

    keyword_results = search_keyword_chunks(
        query_text=query.query_text,
        top_k=settings.KEYWORD_TOP_K,
        domain=query.domain,
        topic=query.topic,
        subtopic=query.subtopic,
        cwe_ids=(
            query.cwe_ids
            if query.cwe_ids
            else None
        ),
    )

    query_embedding = embed_text(
        query.query_text
    )

    vector_results = search_vector_chunks(
        query_embedding=query_embedding,
        top_k=settings.VECTOR_TOP_K,
        domain=query.domain,
        topic=query.topic,
        subtopic=query.subtopic,
        cwe_ids=(
            query.cwe_ids
            if query.cwe_ids
            else None
        ),
    )

    fused = _rrf_fuse(
        keyword_results=keyword_results,
        vector_results=vector_results,
        graph_results=graph_results,
        final_top_k=query.top_k,
    )

    if len(fused) >= query.top_k:
        return fused

    relaxed_keyword = search_keyword_chunks(
        query_text=query.query_text,
        top_k=settings.KEYWORD_TOP_K,
        domain=query.domain,
    )

    relaxed_vector = search_vector_chunks(
        query_embedding=query_embedding,
        top_k=settings.VECTOR_TOP_K,
        domain=query.domain,
    )

    relaxed_fused = _rrf_fuse(
        keyword_results=relaxed_keyword,
        vector_results=relaxed_vector,
        graph_results=graph_results,
        final_top_k=query.top_k,
    )

    output: list[HybridSearchResult] = []
    seen: set[str] = set()

    for result in [
        *fused,
        *relaxed_fused,
    ]:
        key = _result_key(
            content_hash=result.content_hash,
            source_path=result.source_path,
            chunk_index=result.chunk_index,
            title=result.title,
            content=result.content,
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(result)

        if len(output) >= query.top_k:
            break

    return output


def search_hybrid(
    query_text: str,
    *,
    cwe_ids: list[str] | None = None,
    scanner: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    topic: str | None = None,
    subtopic: str | None = None,
    framework: str | None = None,
    language: str | None = None,
    preferred_layers: list[str] | None = None,
    final_top_k: int | None = None,
) -> list[HybridSearchResult]:
    query = route_retrieval_query(
        query_text=query_text,
        cwe_ids=cwe_ids,
        scanner=scanner,
        rule_id=rule_id,
        file_path=file_path,
        topic=topic,
        subtopic=subtopic,
        framework=framework,
        language=language,
        preferred_layers=preferred_layers,
        top_k=final_top_k,
    )

    return search_retrieval_query(query)
