from sycur_rag.database import (
    SearchResult,
    _connect,
    _vector_literal,
)


def search_vector_chunks(
    query_embedding: list[float],
    top_k: int,
    *,
    domain: str | None = None,
    layers: list[str] | None = None,
    frameworks: list[str] | None = None,
    languages: list[str] | None = None,
    topic: str | None = None,
    subtopic: str | None = None,
    cwe_ids: list[str] | None = None,
) -> list[SearchResult]:
    if top_k <= 0:
        raise ValueError(
            "top_k must be greater than zero."
        )

    vector = _vector_literal(
        query_embedding
    )

    where = [
        "embedding IS NOT NULL",
        "active = TRUE",
    ]

    params: list[object] = [
        vector,
    ]

    if domain:
        where.append(
            "domain = %s"
        )
        params.append(domain)

    if layers:
        where.append(
            "layer = ANY(%s)"
        )
        params.append(layers)

    if frameworks:
        where.append(
            "framework = ANY(%s)"
        )
        params.append(frameworks)

    if languages:
        where.append(
            "language = ANY(%s)"
        )
        params.append(languages)

    if topic:
        where.append(
            "topic = %s"
        )
        params.append(topic)

    if subtopic:
        where.append(
            "subtopic = %s"
        )
        params.append(subtopic)

    if cwe_ids:
        normalized_cwes = [
            value.strip().upper()
            for value in cwe_ids
        ]

        where.append(
            "cwe_ids && %s::TEXT[]"
        )
        params.append(
            normalized_cwes
        )

    params.extend(
        [
            vector,
            top_k,
        ]
    )

    query = f"""
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
            {" AND ".join(where)}

        ORDER BY
            embedding <=> %s::vector

        LIMIT %s
    """

    with _connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                query,
                params,
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