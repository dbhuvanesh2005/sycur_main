import argparse

from sycur_rag.core.config import get_settings
from sycur_rag.database import search_similar_chunks
from sycur_rag.embeddings import embed_text
from sycur_rag.llm import generate_grounded_explanation


def _validate_top_k(
    value: int,
) -> int:
    if value <= 0:
        raise ValueError(
            "top_k must be greater than zero."
        )

    return value


def search_question(
    question: str,
    top_k: int | None = None,
):
    if not isinstance(question, str):
        raise TypeError(
            "question must be a string."
        )

    question = question.strip()

    if not question:
        raise ValueError(
            "Question cannot be empty."
        )

    settings = get_settings()

    if top_k is None:
        top_k = settings.VECTOR_TOP_K

    _validate_top_k(top_k)

    print(
        "Creating query embedding with "
        f"{settings.EMBED_MODEL}..."
    )

    query_embedding = embed_text(
        question
    )

    results = search_similar_chunks(
        query_embedding=query_embedding,
        top_k=top_k,
    )

    if not results:
        return None

    print(
        f"Retrieved {len(results)} "
        "evidence chunks:"
    )

    for index, result in enumerate(
        results,
        start=1,
    ):
        control = (
            result.control_id
            or result.title
        )

        print(
            f"  [{index}] {control} "
            f"(vector_similarity="
            f"{result.similarity:.4f})"
        )

    return generate_grounded_explanation(
        question=question,
        evidence=results,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Search the current SYCUR vector "
            "knowledge store."
        )
    )

    parser.add_argument(
        "question",
        nargs="*",
        help="Security question to search.",
    )

    parser.add_argument(
        "--top-k",
        type=int,
        default=None,
        help=(
            "Number of vector results. "
            "Defaults to VECTOR_TOP_K."
        ),
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> None:
    parser = _build_parser()

    args = parser.parse_args(
        argv
    )

    question = " ".join(
        args.question
    ).strip()

    if not question:
        question = input(
            "Security question: "
        ).strip()

    answer = search_question(
        question=question,
        top_k=args.top_k,
    )

    if answer is None:
        print(
            "No security evidence was found. "
            "Run ingestion first."
        )
        return

    print()
    print("SYCUR Grounded Explanation")
    print()

    print(
        answer.model_dump_json(
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
