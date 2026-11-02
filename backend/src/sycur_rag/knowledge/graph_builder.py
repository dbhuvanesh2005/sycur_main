from __future__ import annotations

import hashlib

from sycur_rag.database import _connect
from sycur_rag.knowledge.graph import (
    GraphEdge,
    GraphNode,
    SecurityGraph,
)


def _stable_id(
    prefix: str,
    value: str,
) -> str:
    digest = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:24]

    return f"{prefix}:{digest}"


def document_node_id(
    source_path: str,
) -> str:
    return _stable_id(
        "DOCUMENT",
        source_path,
    )


def chunk_node_id(
    source_path: str,
    chunk_index: int,
) -> str:
    return _stable_id(
        "CHUNK",
        f"{source_path}:{chunk_index}",
    )


def control_node_id(
    framework: str,
    control_id: str,
) -> str:
    normalized = control_id.strip().upper()

    # CWE identifiers are globally meaningful
    # weakness identifiers, so do not create
    # a second CONTROL:CWE-* identity.
    if normalized.startswith("CWE-"):
        return normalized

    return (
        "CONTROL:"
        f"{framework.strip()}:"
        f"{control_id.strip()}"
    )


def topic_node_id(
    topic: str,
) -> str:
    return (
        "TOPIC:"
        + topic.strip().lower()
    )


def subtopic_node_id(
    subtopic: str,
) -> str:
    return (
        "SUBTOPIC:"
        + subtopic.strip().lower()
    )


def framework_node_id(
    framework: str,
) -> str:
    return (
        "FRAMEWORK:"
        + framework.strip()
    )


def layer_node_id(
    layer: str,
) -> str:
    return (
        "LAYER:"
        + layer.strip().lower()
    )


def language_node_id(
    language: str,
) -> str:
    return (
        "LANGUAGE:"
        + language.strip().lower()
    )


def _add_bidirectional_edge(
    graph: SecurityGraph,
    *,
    source_id: str,
    target_id: str,
    forward_relation: str,
    reverse_relation: str,
) -> None:
    graph.add_edge(
        GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relation=forward_relation,
        )
    )

    graph.add_edge(
        GraphEdge(
            source_id=target_id,
            target_id=source_id,
            relation=reverse_relation,
        )
    )


def build_security_graph() -> SecurityGraph:
    graph = SecurityGraph()

    with _connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    title,
                    document_name,
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
                    AND source_path IS NOT NULL

                ORDER BY
                    source_path,
                    chunk_index,
                    id
                """
            )

            rows = cursor.fetchall()

    for row in rows:
        (
            database_id,
            title,
            document_name,
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
            source_path,
        ) = row

        if (
            not source_path
            or chunk_index is None
        ):
            continue

        # =====================================
        # Chunk
        # =====================================

        chunk_id = chunk_node_id(
            source_path,
            chunk_index,
        )

        graph.add_node(
            GraphNode(
                node_id=chunk_id,
                node_type="chunk",
                label=title,
                metadata={
                    "database_id": str(
                        database_id
                    ),
                    "document_name": (
                        document_name or ""
                    ),
                    "source_path": source_path,
                    "chunk_index": str(
                        chunk_index
                    ),
                    "content_hash": (
                        content_hash or ""
                    ),
                    "domain": domain or "",
                },
            )
        )

        # =====================================
        # Document
        # =====================================

        document_id = document_node_id(
            source_path
        )

        graph.add_node(
            GraphNode(
                node_id=document_id,
                node_type="document",
                label=(
                    document_name
                    or source_path
                ),
                metadata={
                    "source_path": source_path,
                },
            )
        )

        _add_bidirectional_edge(
            graph,
            source_id=document_id,
            target_id=chunk_id,
            forward_relation=(
                "contains_chunk"
            ),
            reverse_relation=(
                "part_of_document"
            ),
        )

        # =====================================
        # Framework
        # =====================================

        if framework:
            framework_id = (
                framework_node_id(
                    framework
                )
            )

            graph.add_node(
                GraphNode(
                    node_id=framework_id,
                    node_type="framework",
                    label=framework,
                )
            )

            _add_bidirectional_edge(
                graph,
                source_id=framework_id,
                target_id=chunk_id,
                forward_relation=(
                    "has_evidence"
                ),
                reverse_relation=(
                    "from_framework"
                ),
            )

        # =====================================
        # Knowledge layer
        # =====================================

        if layer:
            layer_id = layer_node_id(
                layer
            )

            graph.add_node(
                GraphNode(
                    node_id=layer_id,
                    node_type="layer",
                    label=layer,
                )
            )

            _add_bidirectional_edge(
                graph,
                source_id=layer_id,
                target_id=chunk_id,
                forward_relation=(
                    "contains_evidence"
                ),
                reverse_relation=(
                    "in_layer"
                ),
            )

        # =====================================
        # Language
        # =====================================

        if (
            language
            and language != "generic"
        ):
            language_id = (
                language_node_id(
                    language
                )
            )

            graph.add_node(
                GraphNode(
                    node_id=language_id,
                    node_type="language",
                    label=language,
                )
            )

            _add_bidirectional_edge(
                graph,
                source_id=language_id,
                target_id=chunk_id,
                forward_relation=(
                    "has_guidance"
                ),
                reverse_relation=(
                    "applies_to_language"
                ),
            )

        # =====================================
        # Topic
        # =====================================

        if topic:
            topic_id = topic_node_id(
                topic
            )

            graph.add_node(
                GraphNode(
                    node_id=topic_id,
                    node_type="topic",
                    label=topic,
                )
            )

            _add_bidirectional_edge(
                graph,
                source_id=topic_id,
                target_id=chunk_id,
                forward_relation=(
                    "has_evidence"
                ),
                reverse_relation=(
                    "classified_as"
                ),
            )

        # =====================================
        # Subtopic
        # =====================================

        if subtopic:
            subtopic_id = (
                subtopic_node_id(
                    subtopic
                )
            )

            graph.add_node(
                GraphNode(
                    node_id=subtopic_id,
                    node_type="subtopic",
                    label=subtopic,
                )
            )

            _add_bidirectional_edge(
                graph,
                source_id=subtopic_id,
                target_id=chunk_id,
                forward_relation=(
                    "has_evidence"
                ),
                reverse_relation=(
                    "classified_as_subtopic"
                ),
            )

        # =====================================
        # Primary control
        # =====================================

        if control_id:
            current_framework = (
                framework or "generic"
            )

            control_graph_id = (
                control_node_id(
                    current_framework,
                    control_id,
                )
            )

            if control_graph_id.startswith("CWE-"):
                graph_node = GraphNode(
                    node_id=control_graph_id,
                    node_type="weakness",
                    label=control_graph_id,
                )
            else:
                graph_node = GraphNode(
                    node_id=control_graph_id,
                    node_type="control",
                    label=control_id,
                    metadata={
                        "framework": current_framework,
                    },
                )

            graph.add_node(graph_node)

            _add_bidirectional_edge(
                graph,
                source_id=(
                    control_graph_id
                ),
                target_id=chunk_id,
                forward_relation=(
                    "represented_by"
                ),
                reverse_relation=(
                    "has_control"
                ),
            )

        # =====================================
        # CWE references
        # =====================================

        for cwe_id in (
            cwe_ids or []
        ):
            normalized_cwe = (
                cwe_id.strip().upper()
            )

            if not normalized_cwe:
                continue

            graph.add_node(
                GraphNode(
                    node_id=normalized_cwe,
                    node_type="weakness",
                    label=normalized_cwe,
                )
            )

            _add_bidirectional_edge(
                graph,
                source_id=normalized_cwe,
                target_id=chunk_id,
                forward_relation=(
                    "referenced_by"
                ),
                reverse_relation=(
                    "references_cwe"
                ),
            )

    graph.validate()

    return graph
