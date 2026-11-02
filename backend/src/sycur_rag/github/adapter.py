from __future__ import annotations

from pydantic import (
    BaseModel,
    ConfigDict,
    model_validator,
)

from sycur_rag.github.assembler import (
    assemble_github_pull_request_changeset,
)
from sycur_rag.github.client import (
    GitHubClient,
)
from sycur_rag.github.pull_request import (
    GitHubPullRequestMetadata,
    parse_github_rest_pull_request_metadata,
)
from sycur_rag.models.changeset import (
    PullRequestChangeSet,
)


class GitHubPullRequestSnapshot(
    BaseModel
):
    """
    Complete normalized view of one
    GitHub pull request revision.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    metadata: GitHubPullRequestMetadata
    changeset: PullRequestChangeSet

    @model_validator(
        mode="after",
    )
    def validate_alignment(
        self,
    ) -> "GitHubPullRequestSnapshot":
        metadata = self.metadata
        changeset = self.changeset

        if (
            metadata.repository.casefold()
            != changeset.repository.casefold()
        ):
            raise ValueError(
                "GitHub metadata and "
                "changeset repository "
                "do not match."
            )

        if (
            metadata.pull_request_number
            != changeset.pull_request_number
        ):
            raise ValueError(
                "GitHub metadata and "
                "changeset pull request "
                "numbers do not match."
            )

        if (
            metadata.base_sha
            != changeset.base_sha
        ):
            raise ValueError(
                "GitHub metadata and "
                "changeset base SHA "
                "do not match."
            )

        if (
            metadata.head_sha
            != changeset.head_sha
        ):
            raise ValueError(
                "GitHub metadata and "
                "changeset head SHA "
                "do not match."
            )

        return self


def fetch_github_pull_request_snapshot(
    *,
    client: GitHubClient,
    repository: str,
    pull_request_number: int,
) -> GitHubPullRequestSnapshot:
    """
    Fetch and normalize one complete
    GitHub pull request revision.

    Network access is delegated entirely
    to GitHubClient.
    """

    raw_pull_request = (
        client.get_pull_request(
            repository=repository,
            pull_request_number=(
                pull_request_number
            ),
        )
    )

    metadata = (
        parse_github_rest_pull_request_metadata(
            raw_pull_request
        )
    )

    requested_repository = (
        repository.strip()
    )

    if (
        metadata.repository.casefold()
        != requested_repository.casefold()
    ):
        raise ValueError(
            "GitHub returned pull request "
            "metadata for a different "
            "repository."
        )

    if (
        metadata.pull_request_number
        != pull_request_number
    ):
        raise ValueError(
            "GitHub returned a different "
            "pull request number."
        )

    file_pages = (
        client.list_pull_request_file_pages(
            repository=repository,
            pull_request_number=(
                pull_request_number
            ),
        )
    )

    confirmation_raw_pull_request = (
        client.get_pull_request(
            repository=repository,
            pull_request_number=(
                pull_request_number
            ),
        )
    )

    confirmation_metadata = (
        parse_github_rest_pull_request_metadata(
            confirmation_raw_pull_request
        )
    )

    if confirmation_metadata != metadata:
        raise RuntimeError(
            "GitHub pull request changed "
            "while changed files were being "
            "collected. Retry with the latest "
            "pull request revision."
        )

    changeset = (
        assemble_github_pull_request_changeset(
            metadata=metadata,
            file_pages=file_pages,
        )
    )

    return GitHubPullRequestSnapshot(
        metadata=metadata,
        changeset=changeset,
    )
