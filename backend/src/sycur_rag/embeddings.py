from math import isfinite

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sycur_rag.core.config import get_settings


def _validate_texts(texts: list[str]) -> None:
    if not isinstance(texts, list):
        raise TypeError(
            "texts must be a list of strings."
        )

    for index, text in enumerate(texts):
        if not isinstance(text, str):
            raise TypeError(
                f"Text at index {index} must be a string."
            )

        if not text.strip():
            raise ValueError(
                f"Text at index {index} cannot be empty."
            )


def _validate_embeddings(
    embeddings: object,
    expected_count: int,
) -> list[list[float]]:
    settings = get_settings()

    if not isinstance(embeddings, list):
        raise RuntimeError(
            "Ollama returned embeddings in an invalid format."
        )

    if len(embeddings) != expected_count:
        raise RuntimeError(
            "Ollama returned an unexpected number of embeddings: "
            f"expected {expected_count}, got {len(embeddings)}."
        )

    validated: list[list[float]] = []

    for embedding_index, embedding in enumerate(embeddings):
        if not isinstance(embedding, list):
            raise RuntimeError(
                f"Embedding at index {embedding_index} "
                "is not a list."
            )

        if len(embedding) != settings.EMBEDDING_DIMENSION:
            raise RuntimeError(
                f"Embedding at index {embedding_index} "
                "has an invalid dimension: "
                f"expected {settings.EMBEDDING_DIMENSION}, "
                f"got {len(embedding)}."
            )

        converted: list[float] = []

        for value_index, value in enumerate(embedding):
            try:
                numeric_value = float(value)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Embedding {embedding_index} contains "
                    f"a non-numeric value at index {value_index}."
                ) from exc

            if not isfinite(numeric_value):
                raise RuntimeError(
                    f"Embedding {embedding_index} contains "
                    f"a non-finite value at index {value_index}."
                )

            converted.append(numeric_value)

        validated.append(converted)

    return validated


def _create_ollama_session() -> requests.Session:
    settings = get_settings()

    retry_policy = Retry(
        total=settings.OLLAMA_MAX_RETRIES,
        connect=settings.OLLAMA_MAX_RETRIES,
        read=settings.OLLAMA_MAX_RETRIES,
        status=settings.OLLAMA_MAX_RETRIES,
        backoff_factor=settings.OLLAMA_RETRY_BACKOFF_SECONDS,
        status_forcelist=(
            408,
            429,
            500,
            502,
            503,
            504,
        ),
        allowed_methods=frozenset({"POST"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_policy,
    )

    session = requests.Session()

    session.mount(
        "http://",
        adapter,
    )

    session.mount(
        "https://",
        adapter,
    )

    return session


def _request_embedding_batch(
    texts: list[str],
    session: requests.Session,
) -> list[list[float]]:
    settings = get_settings()

    try:
        response = session.post(
            settings.ollama_embed_url,
            json={
                "model": settings.EMBED_MODEL,
                "input": texts,
            },
            timeout=settings.OLLAMA_TIMEOUT_SECONDS,
        )

        response.raise_for_status()

    except requests.RequestException as exc:
        raise RuntimeError(
            "Failed to request embeddings from Ollama."
        ) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "Ollama returned an invalid JSON response."
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(
            "Ollama returned an invalid response object."
        )

    return _validate_embeddings(
        embeddings=data.get("embeddings"),
        expected_count=len(texts),
    )


def embed_texts(
    texts: list[str],
) -> list[list[float]]:
    _validate_texts(texts)

    if not texts:
        return []

    settings = get_settings()
    batch_size = settings.EMBEDDING_BATCH_SIZE

    all_embeddings: list[list[float]] = []

    with _create_ollama_session() as session:
        for start_index in range(
            0,
            len(texts),
            batch_size,
        ):
            batch = texts[
                start_index:start_index + batch_size
            ]

            batch_embeddings = _request_embedding_batch(
                texts=batch,
                session=session,
            )

            all_embeddings.extend(
                batch_embeddings
            )

    if len(all_embeddings) != len(texts):
        raise RuntimeError(
            "Embedding pipeline returned an unexpected "
            "number of embeddings."
        )

    return all_embeddings


def embed_text(
    text: str,
) -> list[float]:
    return embed_texts([text])[0]