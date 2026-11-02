import argparse
from pathlib import Path

from sycur_rag.chunker import build_policy_chunks
from sycur_rag.core.config import get_settings
from sycur_rag.database import replace_document_chunks
from sycur_rag.document_loader import load_document
from sycur_rag.embeddings import embed_texts
from sycur_rag.ingestion.metadata import extract_chunk_metadata


def _validate_non_empty(
    value: str,
) -> str:
    cleaned = value.strip()

    if not cleaned:
        raise argparse.ArgumentTypeError(
            "Value cannot be empty."
        )

    return cleaned


def ingest_document(
    document_path: Path,
    policy_type: str,
    document_name: str | None = None,
) -> int:
    path = document_path.expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(
            f"Document does not exist: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Document path is not a file: {path}"
        )

    policy_type = policy_type.strip()

    if not policy_type:
        raise ValueError(
            "policy_type cannot be empty."
        )

    if document_name is None:
        document_name = path.stem
    else:
        document_name = document_name.strip()

        if not document_name:
            raise ValueError(
                "document_name cannot be empty."
            )

    settings = get_settings()

    print(
        f"Loading document: {path.name}"
    )

    paragraphs = load_document(
        path
    )

    if not paragraphs:
        raise RuntimeError(
            "Document loader returned no content."
        )

    print(
        f"Non-empty paragraphs: {len(paragraphs)}"
    )

    chunks = build_policy_chunks(
        paragraphs=paragraphs,
        document_name=document_name,
        policy_type=policy_type,
    )

    if not chunks:
        raise RuntimeError(
            "Chunking produced zero chunks."
        )

    print(
        f"Chunks created: {len(chunks)}"
    )

    print(
        "Creating embeddings with "
        f"{settings.EMBED_MODEL}..."
    )

    embeddings = embed_texts(
        [
            chunk.content
            for chunk in chunks
        ]
    )

    if len(embeddings) != len(chunks):
        raise RuntimeError(
            "Embedding count does not match "
            "chunk count."
        )

    print("Extracting chunk metadata...")

    metadata = [
        extract_chunk_metadata(
            chunk=chunk,
            source_path=path,
        )
        for chunk in chunks
    ]

    if len(metadata) != len(chunks):
        raise RuntimeError(
            "Metadata count does not match "
            "chunk count."
        )

    print(
        "Writing chunks, metadata, and embeddings "
        "to PostgreSQL..."
    )

    replace_document_chunks(
        chunks,
        embeddings,
        metadata=metadata,
        source_path=path,
    )

    print(
        "Ingestion complete: "
        f"{len(chunks)} chunks stored."
    )

    return len(chunks)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Ingest a document into the "
            "SYCUR knowledge store."
        )
    )

    parser.add_argument(
        "document_path",
        type=Path,
        help="Path to the document.",
    )

    parser.add_argument(
        "--policy-type",
        required=True,
        type=_validate_non_empty,
        help=(
            "Policy or knowledge type "
            "for this document."
        ),
    )

    parser.add_argument(
        "--document-name",
        type=_validate_non_empty,
        default=None,
        help=(
            "Optional document name. "
            "Defaults to the file name."
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

    ingest_document(
        document_path=args.document_path,
        policy_type=args.policy_type,
        document_name=args.document_name,
    )


if __name__ == "__main__":
    main()
