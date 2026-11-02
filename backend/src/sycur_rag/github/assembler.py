from __future__ import annotations

from sycur_rag.github.changeset import (
    parse_github_changed_files,
)
from sycur_rag.github.pull_request import (
    GitHubPullRequestMetadata,
)
from sycur_rag.models.changeset import (
    PullRequestChangeSet,
)


def assemble_github_pull_request_changeset(
    *,
    metadata: GitHubPullRequestMetadata,
    file_pages: list[list[object]],
) -> PullRequestChangeSet:
    """
    Combine validated GitHub PR metadata
    with all changed-file API pages.

    This function performs no network calls.

    The caller must retrieve every GitHub
    changed-files page before calling this
    function.
    """

    if not isinstance(
        metadata,
        GitHubPullRequestMetadata,
    ):
        raise TypeError(
            "metadata must be "
            "GitHubPullRequestMetadata."
        )

    if not isinstance(
        file_pages,
        list,
    ):
        raise TypeError(
            "file_pages must be a list."
        )

    expected_count = metadata.changed_files

    flattened_files: list[object] = []

    for page_index, page in enumerate(
        file_pages
    ):
        if not isinstance(
            page,
            list,
        ):
            raise ValueError(
                "GitHub changed-files page "
                f"{page_index} must be a list."
            )

        flattened_files.extend(
            page
        )

    if len(flattened_files) != expected_count:
        raise ValueError(
            "Incomplete GitHub changed-files "
            "collection: expected "
            f"{expected_count}, received "
            f"{len(flattened_files)}."
        )

    return parse_github_changed_files(
        repository=metadata.repository,
        pull_request_number=(
            metadata.pull_request_number
        ),
        base_sha=metadata.base_sha,
        head_sha=metadata.head_sha,
        files=flattened_files,
    )
