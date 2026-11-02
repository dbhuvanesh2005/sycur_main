from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

from sycur_rag.database import _connect
from sycur_rag.knowledge.graph import (
    SecurityGraph,
)
from sycur_rag.knowledge.graph_builder import (
    build_security_graph,
    framework_node_id,
    language_node_id,
    subtopic_node_id,
    topic_node_id,
)
from sycur_rag.models.retrieval import (
    RetrievalQuery,
)


@dataclass(frozen=True)
class GraphSearchResult:
    title: str
    content: str
    document_name: str
    policy_type: str | None
    section: str | None
    control_id: str | None

    graph_rank: int
    graph_depth: int
    matched_seeds: tuple[str, ...]

    domain: str | None = None
    layer: str | None = None
    framework: str | None = None
    language: str | None = None
    topic: str | None = None
    subtopic: str | None = None
    cwe_ids: tuple[str, ...] = ()

    chunk_index: int | None = None
    content_hash: str | None = None
    source_path: str | None = None


def _graph_version() -> tuple[
    int,
    int,
    datetime | None,
]:
    """
    Cheap corpus fingerprint.

    If active corpus rows change, the cached
    in-memory graph will be rebuilt.
    """

    with _connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*),
                    COALESCE(MAX(id), 0),
                    MAX(updated_at)
                FROM policy_chunks
                WHERE
                    active = TRUE
                    AND source_path IS NOT NULL
                """
            )

            row = cursor.fetchone()

    if row is None:
        return (
            0,
            0,
            None,
        )

    return (
        int(row[0]),
        int(row[1]),
        row[2],
    )


@lru_cache(maxsize=4)
def _cached_graph(
    version: tuple[
        int,
        int,
        datetime | None,
    ],
) -> SecurityGraph:
    # version is intentionally part of the
    # cache key.
    _ = version

    return build_security_graph()


def get_security_graph() -> SecurityGraph:
    return _cached_graph(
        _graph_version()
    )


def clear_security_graph_cache() -> None:
    _cached_graph.cache_clear()


def _candidate_seed_ids(
    query: RetrievalQuery,
    graph: SecurityGraph,
) -> list[str]:
    seeds: list[str] = []

    # =====================================
    # Strongest signal: CWE
    # =====================================

    for cwe_id in query.cwe_ids:
        if graph.get_node(
            cwe_id
        ) is not None:
            seeds.append(
                cwe_id
            )

    # =====================================
    # Topic
    # =====================================

    if query.topic:
        node_id = topic_node_id(
            query.topic
        )

        if graph.get_node(
            node_id
        ) is not None:
            seeds.append(
                node_id
            )

    # =====================================
    # Subtopic
    # =====================================

    if query.subtopic:
        node_id = subtopic_node_id(
            query.subtopic
        )

        if graph.get_node(
            node_id
        ) is not None:
            seeds.append(
                node_id
            )

    # =====================================
    # Framework
    #
    # "generic" is intentionally ignored:
    # it is too broad to be a useful graph
    # starting point.
    # =====================================

    for framework in query.frameworks:
        if framework.lower() == "generic":
            continue

        node_id = framework_node_id(
            framework
        )

        if graph.get_node(
            node_id
        ) is not None:
            seeds.append(
                node_id
            )

    # =====================================
    # Language
    # =====================================

    for language in query.languages:
        if language.lower() == "generic":
            continue

        node_id = language_node_id(
            language
        )

        if graph.get_node(
            node_id
        ) is not None:
            seeds.append(
                node_id
            )

    # Preserve order but remove duplicates.

    return list(
        dict.fromkeys(
            seeds
        )
    )


def _fetch_chunk_rows(
    database_ids: list[int],
) -> dict[int, tuple]:
    if not database_ids:
        return {}

    with _connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    title,
                    content,
                    document_name,
                    policy_type,
                    section,
                    control_id,
                    domain,
                    layer,
                    framework,
                    language,
                    topic,
                    subtopic,
                    cwe_ids,
                    chunk_index,
                    content_hash,
                    source_path

                FROM policy_chunks

                WHERE
                    active = TRUE
                    AND id = ANY(%s)
                """,
                (
                    database_ids,
                ),
            )

            rows = cursor.fetchall()

    return {
        int(row[0]): row
        for row in rows
    }


def search_graph_chunks(
    query: RetrievalQuery,
    *,
    graph: SecurityGraph | None = None,
    max_depth: int | None = None,
    top_k: int | None = None,
) -> list[GraphSearchResult]:
    if not isinstance(
        query,
        RetrievalQuery,
    ):
        raise TypeError(
            "query must be a RetrievalQuery."
        )

    if graph is None:
        graph = get_security_graph()

    if max_depth is None:
        from sycur_rag.core.config import (
            get_settings,
        )

        max_depth = (
            get_settings().GRAPH_MAX_DEPTH
        )

    if max_depth < 0:
        raise ValueError(
            "max_depth cannot be negative."
        )

    if top_k is None:
        top_k = query.top_k

    if top_k <= 0:
        raise ValueError(
            "top_k must be greater than zero."
        )

    seeds = _candidate_seed_ids(
        query=query,
        graph=graph,
    )

    # Graph retrieval is optional.
    # No reliable graph seed means:
    # do not invent one.
    if not seeds:
        return []

    # database_id -> candidate metadata
    candidates: dict[
        int,
        dict,
    ] = {}

    order_counter = 0

    for seed_index, seed_id in enumerate(
        seeds
    ):
        traversal = graph.bfs(
            [seed_id],
            max_depth=max_depth,
            max_results=500,
        )

        for result in traversal:
            if (
                result.node.node_type
                != "chunk"
            ):
                continue

            raw_database_id = (
                result.node.metadata.get(
                    "database_id"
                )
            )

            if not raw_database_id:
                raise RuntimeError(
                    "Graph chunk node is missing "
                    "database_id metadata."
                )

            try:
                database_id = int(
                    raw_database_id
                )
            except ValueError as exc:
                raise RuntimeError(
                    "Graph chunk node contains "
                    "an invalid database_id."
                ) from exc

            existing = candidates.get(
                database_id
            )

            if existing is None:
                candidates[
                    database_id
                ] = {
                    "depth": result.depth,
                    "seed_index": seed_index,
                    "first_seen": (
                        order_counter
                    ),
                    "matched_seeds": {
                        seed_id
                    },
                }

                order_counter += 1

            else:
                existing[
                    "matched_seeds"
                ].add(
                    seed_id
                )

                existing["depth"] = min(
                    existing["depth"],
                    result.depth,
                )

                existing[
                    "seed_index"
                ] = min(
                    existing[
                        "seed_index"
                    ],
                    seed_index,
                )

    if not candidates:
        return []

    rows_by_id = _fetch_chunk_rows(
        list(
            candidates.keys()
        )
    )

    preferred_layer_rank = {
        layer: index
        for index, layer
        in enumerate(
            query.preferred_layers
        )
    }

    ranked: list[
        tuple[
            tuple,
            int,
            tuple,
            dict,
        ]
    ] = []

    for database_id, candidate in (
        candidates.items()
    ):
        row = rows_by_id.get(
            database_id
        )

        # Row may have become inactive between
        # graph build and DB fetch.
        if row is None:
            continue

        layer = row[8]

        layer_rank = (
            preferred_layer_rank.get(
                layer,
                len(
                    preferred_layer_rank
                )
                + 1,
            )
        )

        matched_count = len(
            candidate[
                "matched_seeds"
            ]
        )

        sort_key = (
            -matched_count,
            candidate["depth"],
            layer_rank,
            candidate[
                "seed_index"
            ],
            candidate[
                "first_seen"
            ],
            database_id,
        )

        ranked.append(
            (
                sort_key,
                database_id,
                row,
                candidate,
            )
        )

    ranked.sort(
        key=lambda item: item[0]
    )

    output: list[
        GraphSearchResult
    ] = []

    for graph_rank, (
        _,
        _database_id,
        row,
        candidate,
    ) in enumerate(
        ranked[:top_k],
        start=1,
    ):
        output.append(
            GraphSearchResult(
                title=row[1],
                content=row[2],
                document_name=row[3],
                policy_type=row[4],
                section=row[5],
                control_id=row[6],

                graph_rank=graph_rank,
                graph_depth=(
                    candidate["depth"]
                ),
                matched_seeds=tuple(
                    sorted(
                        candidate[
                            "matched_seeds"
                        ]
                    )
                ),

                domain=row[7],
                layer=row[8],
                framework=row[9],
                language=row[10],
                topic=row[11],
                subtopic=row[12],
                cwe_ids=tuple(
                    row[13] or []
                ),
                chunk_index=row[14],
                content_hash=row[15],
                source_path=row[16],
            )
        )

    return output