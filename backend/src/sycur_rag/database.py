import re
from dataclasses import dataclass
from math import isfinite
from pathlib import Path

import psycopg

from sycur_rag.chunker import PolicyChunk
from sycur_rag.core.config import PROJECT_ROOT, get_settings
from sycur_rag.ingestion.metadata import ChunkMetadata


SHA256_PATTERN = re.compile(
    r"^[0-9a-f]{64}$"
)


@dataclass(frozen=True)
class SearchResult:
    title: str
    content: str
    document_name: str
    policy_type: str | None
    section: str | None
    control_id: str | None
    similarity: float

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


def _connect():
    settings = get_settings()

    return psycopg.connect(
        dbname=settings.DB_NAME,
        user=settings.DB_USER,
        password=settings.db_password_value,
        host=settings.DB_HOST,
        port=settings.DB_PORT,
    )


def _validate_embedding(
    values: list[float],
) -> None:
    settings = get_settings()

    if not values:
        raise ValueError(
            "Embedding cannot be empty."
        )

    if len(values) != settings.EMBEDDING_DIMENSION:
        raise ValueError(
            "Embedding dimension mismatch: "
            f"expected {settings.EMBEDDING_DIMENSION}, "
            f"got {len(values)}."
        )

    try:
        numeric_values = [
            float(value)
            for value in values
        ]
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Embedding contains non-numeric values."
        ) from exc

    if not all(
        isfinite(value)
        for value in numeric_values
    ):
        raise ValueError(
            "Embedding contains non-finite values."
        )


def _vector_literal(
    values: list[float],
) -> str:
    _validate_embedding(values)

    return "[" + ",".join(
        str(float(value))
        for value in values
    ) + "]"


def _normalize_source_path(
    source_path: str | Path,
) -> str:
    if not isinstance(
        source_path,
        (str, Path),
    ):
        raise TypeError(
            "source_path must be a string or Path."
        )

    raw_value = str(
        source_path
    ).strip()

    if not raw_value:
        raise ValueError(
            "source_path cannot be empty."
        )

    path = Path(
        raw_value
    ).expanduser()

    if path.is_absolute():
        resolved = path.resolve()

        try:
            return resolved.relative_to(
                PROJECT_ROOT
            ).as_posix()
        except ValueError:
            return resolved.as_posix()

    return path.as_posix()


def _validate_ingestion_records(
    chunks: list[PolicyChunk],
    embeddings: list[list[float]],
    metadata: list[ChunkMetadata],
) -> None:
    if not chunks:
        raise ValueError(
            "No chunks were provided for ingestion."
        )

    if len(chunks) != len(embeddings):
        raise ValueError(
            "Chunk count and embedding count do not match."
        )

    if len(chunks) != len(metadata):
        raise ValueError(
            "Chunk count and metadata count do not match."
        )

    document_name = chunks[0].document_name

    if any(
        chunk.document_name != document_name
        for chunk in chunks
    ):
        raise ValueError(
            "All chunks must belong to the same document."
        )

    indexes: set[int] = set()

    for index, (
        chunk,
        embedding,
        item_metadata,
    ) in enumerate(
        zip(
            chunks,
            embeddings,
            metadata,
            strict=True,
        )
    ):
        if not isinstance(
            chunk,
            PolicyChunk,
        ):
            raise TypeError(
                f"Chunk at index {index} "
                "must be a PolicyChunk."
            )

        if not isinstance(
            item_metadata,
            ChunkMetadata,
        ):
            raise TypeError(
                f"Metadata at index {index} "
                "must be ChunkMetadata."
            )

        _validate_embedding(
            embedding
        )

        if chunk.chunk_index < 0:
            raise ValueError(
                "chunk_index cannot be negative."
            )

        if chunk.chunk_index in indexes:
            raise ValueError(
                "Duplicate chunk_index detected."
            )

        indexes.add(
            chunk.chunk_index
        )

        if not SHA256_PATTERN.fullmatch(
            chunk.content_hash
        ):
            raise ValueError(
                f"Chunk at index {index} "
                "has an invalid SHA-256 content hash."
            )

        for field_name, value in (
            ("domain", item_metadata.domain),
            ("layer", item_metadata.layer),
            ("framework", item_metadata.framework),
            ("language", item_metadata.language),
        ):
            if (
                not isinstance(value, str)
                or not value.strip()
            ):
                raise ValueError(
                    f"Metadata field {field_name} "
                    f"is invalid at index {index}."
                )


def replace_document_chunks(
    chunks: list[PolicyChunk],
    embeddings: list[list[float]],
    *,
    metadata: list[ChunkMetadata],
    source_path: str | Path,
) -> None:
    _validate_ingestion_records(
        chunks=chunks,
        embeddings=embeddings,
        metadata=metadata,
    )

    normalized_source_path = (
        _normalize_source_path(
            source_path
        )
    )

    document_name = (
        chunks[0].document_name
    )

    rows = []

    for (
        chunk,
        embedding,
        item_metadata,
    ) in zip(
        chunks,
        embeddings,
        metadata,
        strict=True,
    ):
        vector = _vector_literal(
            embedding
        )

        rows.append(
            (
                chunk.title,
                chunk.content,
                chunk.document_name,
                chunk.policy_type,
                chunk.section,
                chunk.control_id,
                vector,
                item_metadata.domain,
                item_metadata.layer,
                item_metadata.framework,
                item_metadata.language,
                item_metadata.topic,
                item_metadata.subtopic,
                list(
                    item_metadata.cwe_ids
                ),
                chunk.chunk_index,
                chunk.content_hash,
                normalized_source_path,
            )
        )

    with _connect() as connection:
        with connection.cursor() as cursor:

            # source_path is the canonical document identity.
            #
            # The document_name condition only removes
            # legacy PoC rows which predate source_path.
            cursor.execute(
                """
                DELETE FROM policy_chunks
                WHERE
                    source_path = %s
                    OR (
                        source_path IS NULL
                        AND document_name = %s
                    )
                """,
                (
                    normalized_source_path,
                    document_name,
                ),
            )

            cursor.executemany(
                """
                INSERT INTO policy_chunks
                (
                    title,
                    content,
                    document_name,
                    policy_type,
                    section,
                    control_id,
                    embedding,
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
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s::vector,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                rows,
            )


def search_similar_chunks(
    query_embedding: list[float],
    top_k: int,
) -> list[SearchResult]:
    if top_k <= 0:
        raise ValueError(
            "top_k must be greater than zero."
        )

    vector = _vector_literal(
        query_embedding
    )

    with _connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    title,
                    content,
                    document_name,
                    policy_type,
                    section,
                    control_id,

                    1 - (
                        embedding <=> %s::vector
                    ) AS similarity,

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
                    embedding IS NOT NULL
                    AND active = TRUE

                ORDER BY
                    embedding <=> %s::vector

                LIMIT %s
                """,
                (
                    vector,
                    vector,
                    top_k,
                ),
            )

            rows = cursor.fetchall()

    return [
        SearchResult(
            title=row[0],
            content=row[1],
            document_name=row[2],
            policy_type=row[3],
            section=row[4],
            control_id=row[5],
            similarity=float(row[6]),
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
        for row in rows
    ]
