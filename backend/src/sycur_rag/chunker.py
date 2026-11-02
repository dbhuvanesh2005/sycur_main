import hashlib
import re
from dataclasses import dataclass


ACCESS_CONTROL_PATTERN = re.compile(
    r"^(AM-\d{2})\b[\s:–—-]*(.*)$",
    re.IGNORECASE,
)

ASVS_CONTROL_PATTERN = re.compile(
    r"^(V?\d+(?:\.\d+){2})\b[\s:–—-]*(.*)$",
    re.IGNORECASE,
)

WSTG_CONTROL_PATTERN = re.compile(
    r"^(WSTG-[A-Z0-9]+-\d+)\b[\s:–—-]*(.*)$",
    re.IGNORECASE,
)

OWASP_CATEGORY_PATTERN = re.compile(
    r"^((?:A\d{2}|API\d{1,2}):\d{4})"
    r"\b[\s:–—-]*(.*)$",
    re.IGNORECASE,
)

CWE_CSV_PATTERN = re.compile(
    r"^\s*CWE-ID\s*:\s*(\d+)\b",
    re.IGNORECASE,
)

MARKDOWN_HEADING_PATTERN = re.compile(
    r"^(#{1,6})\s+(.+)$"
)

OLD_MAIN_SECTIONS = {
    "Purpose",
    "Scope",
    "Policy Sanctions",
    "Safeguards",
}


@dataclass(frozen=True)
class PolicyChunk:
    title: str
    content: str
    document_name: str
    policy_type: str
    section: str | None
    control_id: str | None

    chunk_index: int = 0
    content_hash: str = ""


def _content_hash(
    content: str,
) -> str:
    normalized = " ".join(
        content.split()
    )

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def _normalize_blocks(
    paragraphs: list[str],
) -> list[str]:
    if not isinstance(paragraphs, list):
        raise TypeError(
            "paragraphs must be a list."
        )

    blocks: list[str] = []

    for index, paragraph in enumerate(
        paragraphs
    ):
        if not isinstance(paragraph, str):
            raise TypeError(
                f"Paragraph at index {index} "
                "must be a string."
            )

        cleaned = paragraph.strip()

        if cleaned:
            blocks.append(
                cleaned
            )

    return blocks


def _validate_metadata(
    document_name: str,
    policy_type: str,
) -> tuple[str, str]:
    if not isinstance(document_name, str):
        raise TypeError(
            "document_name must be a string."
        )

    if not isinstance(policy_type, str):
        raise TypeError(
            "policy_type must be a string."
        )

    document_name = document_name.strip()
    policy_type = policy_type.strip()

    if not document_name:
        raise ValueError(
            "document_name cannot be empty."
        )

    if not policy_type:
        raise ValueError(
            "policy_type cannot be empty."
        )

    return (
        document_name,
        policy_type,
    )


def _looks_like_heading(
    text: str,
) -> bool:
    markdown_match = (
        MARKDOWN_HEADING_PATTERN.match(text)
    )

    if markdown_match:
        return True

    if text in OLD_MAIN_SECTIONS:
        return True

    if "\n" in text:
        return False

    if len(text) > 120:
        return False

    words = text.split()

    if not words or len(words) > 12:
        return False

    if text.endswith(
        (".", ",", ";")
    ):
        return False

    letters = [
        char
        for char in text
        if char.isalpha()
    ]

    if letters and text.upper() == text:
        return True

    return text.istitle()


def _heading_text(
    text: str,
) -> str:
    match = MARKDOWN_HEADING_PATTERN.match(
        text
    )

    if match:
        return match.group(2).strip()

    return text.strip()


def _extract_control(
    text: str,
) -> tuple[str, str] | None:
    text = _heading_text(text)

    cwe_csv_match = CWE_CSV_PATTERN.search(
        text
    )

    if cwe_csv_match:
        return (
            f"CWE-{cwe_csv_match.group(1)}",
            text,
        )

    for pattern in (
        ACCESS_CONTROL_PATTERN,
        ASVS_CONTROL_PATTERN,
        WSTG_CONTROL_PATTERN,
        OWASP_CATEGORY_PATTERN,
    ):
        match = pattern.match(text)

        if match:
            control_id = (
                match.group(1)
                .strip()
                .upper()
            )

            remainder = (
                match.group(2)
                .strip()
            )

            return (
                control_id,
                remainder,
            )

    return None


def _split_words(
    text: str,
    max_words: int,
    overlap_words: int,
) -> list[str]:
    words = text.split()

    if len(words) <= max_words:
        return [
            text.strip()
        ]

    pieces: list[str] = []

    start = 0

    while start < len(words):
        end = min(
            start + max_words,
            len(words),
        )

        pieces.append(
            " ".join(
                words[start:end]
            )
        )

        if end >= len(words):
            break

        start = end - overlap_words

    return pieces


def _append_chunk(
    chunks: list[PolicyChunk],
    *,
    title: str,
    content: str,
    document_name: str,
    policy_type: str,
    section: str | None,
    control_id: str | None,
    max_words: int,
    overlap_words: int,
) -> None:
    cleaned_content = " ".join(
        content.split()
    ).strip()

    if not cleaned_content:
        return

    # Atomic controls do not need prose overlap.
    effective_overlap = (
        0
        if control_id
        else overlap_words
    )

    pieces = _split_words(
        cleaned_content,
        max_words=max_words,
        overlap_words=effective_overlap,
    )

    for part_index, piece in enumerate(
        pieces,
        start=1,
    ):
        part_title = title

        if len(pieces) > 1:
            part_title = (
                f"{title} "
                f"(part {part_index}/{len(pieces)})"
            )

        chunks.append(
            PolicyChunk(
                title=part_title,
                content=piece,
                document_name=document_name,
                policy_type=policy_type,
                section=section,
                control_id=control_id,
                chunk_index=len(chunks),
                content_hash=_content_hash(
                    piece
                ),
            )
        )


def _build_cwe_chunks(
    blocks: list[str],
    document_name: str,
    policy_type: str,
    max_words: int,
) -> list[PolicyChunk]:
    chunks: list[PolicyChunk] = []

    for block in blocks:
        control = _extract_control(
            block
        )

        control_id = (
            control[0]
            if control
            else None
        )

        title = (
            control_id
            or "CWE Entry"
        )

        _append_chunk(
            chunks,
            title=title,
            content=block,
            document_name=document_name,
            policy_type=policy_type,
            section="CWE",
            control_id=control_id,
            max_words=max_words,
            overlap_words=0,
        )

    return chunks


def build_policy_chunks(
    paragraphs: list[str],
    document_name: str,
    policy_type: str,
    max_words: int = 700,
    overlap_words: int = 80,
) -> list[PolicyChunk]:
    document_name, policy_type = (
        _validate_metadata(
            document_name,
            policy_type,
        )
    )

    if max_words <= 0:
        raise ValueError(
            "max_words must be greater than zero."
        )

    if overlap_words < 0:
        raise ValueError(
            "overlap_words cannot be negative."
        )

    if overlap_words >= max_words:
        raise ValueError(
            "overlap_words must be smaller "
            "than max_words."
        )

    blocks = _normalize_blocks(
        paragraphs
    )

    if not blocks:
        return []

    # CWE CSV rows are already natural atomic units.
    if "cwe" in policy_type.lower():
        return _build_cwe_chunks(
            blocks=blocks,
            document_name=document_name,
            policy_type=policy_type,
            max_words=max_words,
        )

    chunks: list[PolicyChunk] = []

    current_title: str | None = None
    current_section: str | None = None
    current_control_id: str | None = None
    current_content: list[str] = []

    def save_current() -> None:
        nonlocal current_content

        if (
            current_title
            and current_content
        ):
            _append_chunk(
                chunks,
                title=current_title,
                content=" ".join(
                    current_content
                ),
                document_name=document_name,
                policy_type=policy_type,
                section=current_section,
                control_id=current_control_id,
                max_words=max_words,
                overlap_words=overlap_words,
            )

        current_content = []

    for block in blocks:
        control = _extract_control(
            block
        )

        if control:
            save_current()

            control_id, remainder = control

            current_control_id = (
                control_id
            )

            current_title = (
                control_id
            )

            if remainder:
                current_content = [
                    remainder
                ]
            else:
                current_content = []

            continue

        if _looks_like_heading(
            block
        ):
            save_current()

            heading = _heading_text(
                block
            )

            current_section = heading
            current_title = heading
            current_control_id = None
            current_content = []

            continue

        if current_title is None:
            current_title = document_name
            current_section = None
            current_control_id = None

        current_content.append(
            block
        )

    save_current()

    return chunks
