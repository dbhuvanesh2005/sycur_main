from dataclasses import dataclass

from sycur_rag.database import _connect


@dataclass(frozen=True)
class KeywordSearchResult:
    title: str
    content: str
    document_name: str
    policy_type: str | None
    section: str | None
    control_id: str | None
    rank: float

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


def _validate_query(
    query_text: str,
) -> str:
    if not isinstance(query_text, str):
        raise TypeError(
            "query_text must be a string."
        )

    cleaned = query_text.strip()

    if not cleaned:
        raise ValueError(
            "query_text cannot be empty."
        )

    return cleaned


def _validate_optional_filter(
    name: str,
    value: str | None,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string or None."
        )

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(
            f"{name} cannot be empty."
        )

    return cleaned


def search_keyword_chunks(
    query_text: str,
    top_k: int,
    *,
    domain: str | None = None,
    layer: str | None = None,
    framework: str | None = None,
    language: str | None = None,
    topic: str | None = None,
    subtopic: str | None = None,
    cwe_ids: list[str] | None = None,
) -> list[KeywordSearchResult]:
    query_text = _validate_query(
        query_text
    )

    if top_k <= 0:
        raise ValueError(
            "top_k must be greater than zero."
        )

    filters = {
        "domain": _validate_optional_filter(
            "domain",
            domain,
        ),
        "layer": _validate_optional_filter(
            "layer",
            layer,
        ),
        "framework": _validate_optional_filter(
            "framework",
            framework,
        ),
        "language": _validate_optional_filter(
            "language",
            language,
        ),
        "topic": _validate_optional_filter(
            "topic",
            topic,
        ),
        "subtopic": _validate_optional_filter(
            "subtopic",
            subtopic,
        ),
    }

    if cwe_ids is not None:
        if not isinstance(cwe_ids, list):
            raise TypeError(
                "cwe_ids must be a list or None."
            )

        if not all(
            isinstance(value, str)
            and value.strip()
            for value in cwe_ids
        ):
            raise ValueError(
                "cwe_ids contains an invalid value."
            )

        cwe_ids = [
            value.strip().upper()
            for value in cwe_ids
        ]

    where_clauses = [
        "pc.active = TRUE",
        "pc.search_vector @@ q.query",
    ]

    params: list[object] = [
        query_text
    ]

    for column, value in filters.items():
        if value is not None:
            where_clauses.append(
                f"pc.{column} = %s"
            )
            params.append(
                value
            )

    if cwe_ids:
        where_clauses.append(
            "pc.cwe_ids && %s::TEXT[]"
        )
        params.append(
            cwe_ids
        )

    params.append(
        top_k
    )

    query = f"""
        WITH q AS (
            SELECT websearch_to_tsquery(
                'english',
                %s
            ) AS query
        )
        SELECT
            pc.title,
            pc.content,
            pc.document_name,
            pc.policy_type,
            pc.section,
            pc.control_id,

            ts_rank_cd(
                pc.search_vector,
                q.query
            ) AS rank,

            pc.domain,
            pc.layer,
            pc.framework,
            pc.language,
            pc.topic,
            pc.subtopic,
            pc.cwe_ids,
            pc.chunk_index,
            pc.content_hash,
            pc.source_path

        FROM policy_chunks AS pc
        CROSS JOIN q

        WHERE
            {" AND ".join(where_clauses)}

        ORDER BY
            rank DESC,
            pc.id ASC

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
        KeywordSearchResult(
            title=row[0],
            content=row[1],
            document_name=row[2],
            policy_type=row[3],
            section=row[4],
            control_id=row[5],
            rank=float(row[6]),
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