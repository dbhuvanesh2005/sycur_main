from __future__ import annotations

from sycur_rag.models.changeset import (
    PullRequestChangeSet,
    PullRequestFileChange,
)


SUPPORTED_GITHUB_FILE_STATUSES = {
    "added",
    "modified",
    "removed",
    "renamed",
    "copied",
    "changed",
    "unchanged",
}


def _required_dict(
    value: object,
    *,
    field_name: str,
) -> dict:
    if not isinstance(
        value,
        dict,
    ):
        raise ValueError(
            f"{field_name} must be an object."
        )

    return value


def _required_text(
    value: object,
    *,
    field_name: str,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            f"{field_name} must be a string."
        )

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    return cleaned


def _optional_text(
    value: object,
    *,
    field_name: str,
) -> str | None:
    if value is None:
        return None

    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            f"{field_name} must be a string "
            "or null."
        )

    cleaned = value.strip()

    if not cleaned:
        return None

    return cleaned


def _required_non_negative_int(
    value: object,
    *,
    field_name: str,
) -> int:
    if (
        not isinstance(
            value,
            int,
        )
        or isinstance(
            value,
            bool,
        )
        or value < 0
    ):
        raise ValueError(
            f"{field_name} must be a "
            "non-negative integer."
        )

    return value


def _parse_github_file(
    raw_file: object,
    *,
    index: int,
) -> PullRequestFileChange:
    item = _required_dict(
        raw_file,
        field_name=(
            f"GitHub changed file "
            f"at index {index}"
        ),
    )

    filename = _required_text(
        item.get(
            "filename"
        ),
        field_name=(
            f"files[{index}].filename"
        ),
    )

    status = _required_text(
        item.get(
            "status"
        ),
        field_name=(
            f"files[{index}].status"
        ),
    ).lower()

    if (
        status
        not in SUPPORTED_GITHUB_FILE_STATUSES
    ):
        raise ValueError(
            "Unsupported GitHub file "
            f"status at index {index}: "
            f"{status}"
        )

    sha = _required_text(
        item.get(
            "sha"
        ),
        field_name=(
            f"files[{index}].sha"
        ),
    )

    additions = (
        _required_non_negative_int(
            item.get(
                "additions"
            ),
            field_name=(
                f"files[{index}].additions"
            ),
        )
    )

    deletions = (
        _required_non_negative_int(
            item.get(
                "deletions"
            ),
            field_name=(
                f"files[{index}].deletions"
            ),
        )
    )

    changes = (
        _required_non_negative_int(
            item.get(
                "changes"
            ),
            field_name=(
                f"files[{index}].changes"
            ),
        )
    )

    patch = _optional_text(
        item.get(
            "patch"
        ),
        field_name=(
            f"files[{index}].patch"
        ),
    )

    previous_filename = (
        _optional_text(
            item.get(
                "previous_filename"
            ),
            field_name=(
                "files"
                f"[{index}]"
                ".previous_filename"
            ),
        )
    )

    # GitHub only uses previous_filename
    # for renamed files.
    if (
        status == "renamed"
        and previous_filename is None
    ):
        raise ValueError(
            "GitHub renamed file at "
            f"index {index} is missing "
            "previous_filename."
        )

    if (
        status != "renamed"
        and previous_filename is not None
    ):
        raise ValueError(
            "GitHub previous_filename "
            "is only valid for renamed "
            f"files. Index: {index}."
        )

    return PullRequestFileChange(
        path=filename,
        status=status,
        previous_path=(
            previous_filename
        ),
        blob_sha=sha,
        patch=patch,
        additions=additions,
        deletions=deletions,
        changes=changes,
    )


def parse_github_changed_files(
    *,
    repository: str,
    pull_request_number: int,
    base_sha: str,
    head_sha: str,
    files: list[object],
) -> PullRequestChangeSet:
    """
    Convert GitHub Pull Request changed-file
    API objects into SYCUR's canonical
    PullRequestChangeSet.

    This function performs no network calls.
    Pagination must already be complete before
    this parser is called.
    """

    if not isinstance(
        files,
        list,
    ):
        raise TypeError(
            "files must be a list."
        )

    parsed_files = tuple(
        _parse_github_file(
            raw_file,
            index=index,
        )
        for index, raw_file
        in enumerate(
            files
        )
    )

    return PullRequestChangeSet(
        repository=repository,
        pull_request_number=(
            pull_request_number
        ),
        base_sha=base_sha,
        head_sha=head_sha,
        files=parsed_files,
    )