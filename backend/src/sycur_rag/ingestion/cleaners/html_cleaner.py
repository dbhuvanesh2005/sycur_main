import re

from bs4 import BeautifulSoup, Tag


NOISE_TAGS = {
    "script",
    "style",
    "noscript",
    "svg",
    "canvas",
    "iframe",
    "form",
    "nav",
    "footer",
    "aside",
}

NOISE_ROLES = {
    "navigation",
    "search",
    "complementary",
    "contentinfo",
}

NOISE_PATTERNS = (
    "breadcrumb",
    "cookie",
    "consent",
    "footer",
    "navbar",
    "navigation",
    "sidebar",
    "side-nav",
    "sidenav",
    "search",
    "pagination",
    "version-selector",
    "version-switcher",
    "theme-switcher",
)


def _normalize_prose(
    text: str,
) -> str:
    return " ".join(
        text.split()
    )


def _normalize_code(
    text: str,
) -> str:
    lines = [
        line.rstrip()
        for line in text.splitlines()
    ]

    while lines and not lines[0].strip():
        lines.pop(0)

    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)


def _is_noise_container(
    tag: Tag,
) -> bool:
    if tag.name in NOISE_TAGS:
        return True

    role = tag.get("role")

    if isinstance(role, str):
        if role.lower() in NOISE_ROLES:
            return True

    identifiers: list[str] = []

    tag_id = tag.get("id")

    if isinstance(tag_id, str):
        identifiers.append(tag_id)

    classes = tag.get("class")

    if isinstance(classes, list):
        identifiers.extend(
            str(value)
            for value in classes
        )

    combined = " ".join(
        identifiers
    ).lower()

    return any(
        pattern in combined
        for pattern in NOISE_PATTERNS
    )


def _remove_noise(
    soup: BeautifulSoup,
) -> None:
    for tag in list(
        soup.find_all(True)
    ):
        if (
            tag.parent is not None
            and _is_noise_container(tag)
        ):
            tag.decompose()


def clean_html(
    html: str,
) -> list[str]:
    if not isinstance(html, str):
        raise TypeError(
            "html must be a string."
        )

    if not html.strip():
        return []

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    _remove_noise(
        soup
    )

    blocks: list[str] = []
    previous_block: str | None = None

    for element in soup.find_all(
        [
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "p",
            "li",
            "pre",
            "code",
            "tr",
        ]
    ):
        # Avoid duplicate nested content.
        if element.name == "p":
            if element.find_parent("li"):
                continue

        if element.name == "code":
            if element.find_parent(
                ["pre", "p", "li"]
            ):
                continue

        if element.name == "tr":
            cells = element.find_all(
                ["th", "td"],
                recursive=False,
            )

            text = " | ".join(
                _normalize_prose(
                    cell.get_text(
                        " ",
                        strip=True,
                    )
                )
                for cell in cells
                if cell.get_text(
                    " ",
                    strip=True,
                )
            )

        elif element.name == "pre":
            text = _normalize_code(
                element.get_text()
            )

        else:
            text = _normalize_prose(
                element.get_text(
                    " ",
                    strip=True,
                )
            )

        if not text:
            continue

        # Remove only immediate duplicate blocks.
        if text == previous_block:
            continue

        blocks.append(
            text
        )

        previous_block = text

    return blocks
