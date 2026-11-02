import csv
from pathlib import Path

from sycur_rag.ingestion.cleaners.html_cleaner import clean_html
from docx import Document
from pypdf import PdfReader


SUPPORTED_EXTENSIONS = {
    ".docx",
    ".pdf",
    ".html",
    ".htm",
    ".md",
    ".markdown",
    ".csv",
}


def _clean_blocks(
    blocks: list[str],
) -> list[str]:
    return [
        block.strip()
        for block in blocks
        if isinstance(block, str)
        and block.strip()
    ]


def _load_docx(
    path: Path,
) -> list[str]:
    document = Document(path)

    return _clean_blocks(
        [
            paragraph.text
            for paragraph in document.paragraphs
        ]
    )


def _load_pdf(
    path: Path,
) -> list[str]:
    reader = PdfReader(path)

    blocks: list[str] = []

    for page in reader.pages:
        text = page.extract_text()

        if not text:
            continue

        blocks.extend(
            text.splitlines()
        )

    return _clean_blocks(blocks)


def _load_html(
    path: Path,
) -> list[str]:
    html = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return clean_html(
        html
    )


def _load_markdown(
    path: Path,
) -> list[str]:
    content = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    return _clean_blocks(
        content.splitlines()
    )


def _load_csv(
    path: Path,
) -> list[str]:
    blocks: list[str] = []

    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as csv_file:
        reader = csv.DictReader(
            csv_file
        )

        if not reader.fieldnames:
            raise ValueError(
                "CSV file has no header row."
            )

        for row in reader:
            values = []

            for field_name in reader.fieldnames:
                value = row.get(
                    field_name,
                    "",
                )

                if value is None:
                    continue

                cleaned = str(
                    value
                ).strip()

                if not cleaned:
                    continue

                values.append(
                    f"{field_name}: {cleaned}"
                )

            if values:
                blocks.append(
                    " | ".join(values)
                )

    return blocks


def load_document(
    file_path: str | Path,
) -> list[str]:
    path = Path(
        file_path
    ).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(
            f"Document not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Document path is not a file: {path}"
        )

    extension = path.suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            "Unsupported document type: "
            f"{extension or '<no extension>'}"
        )

    loaders = {
        ".docx": _load_docx,
        ".pdf": _load_pdf,
        ".html": _load_html,
        ".htm": _load_html,
        ".md": _load_markdown,
        ".markdown": _load_markdown,
        ".csv": _load_csv,
    }

    blocks = loaders[
        extension
    ](path)

    if not blocks:
        raise RuntimeError(
            f"No readable content found in: {path.name}"
        )

    return blocks
