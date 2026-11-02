from __future__ import annotations

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


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


def _required_positive_int(
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
        or value <= 0
    ):
        raise ValueError(
            f"{field_name} must be a "
            "positive integer."
        )

    return value


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


def _validate_repository_name(
    value: str,
    *,
    field_name: str,
) -> str:
    cleaned = _required_text(
        value,
        field_name=field_name,
    )

    parts = cleaned.split(
        "/"
    )

    if (
        len(parts) != 2
        or not parts[0]
        or not parts[1]
    ):
        raise ValueError(
            f"{field_name} must use "
            "'owner/repository' format."
        )

    return cleaned


class GitHubPullRequestMetadata(
    BaseModel
):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    repository: str

    pull_request_number: int = Field(
        ge=1,
    )
    changed_files: int = Field(
        ge=0,
    )

    base_sha: str
    head_sha: str

    base_ref: str
    head_ref: str

    head_repository: str

    @field_validator(
        "repository",
        "head_repository",
    )
    @classmethod
    def validate_repository(
        cls,
        value: str,
    ) -> str:
        return _validate_repository_name(
            value,
            field_name="repository",
        )

    @field_validator(
        "base_sha",
        "head_sha",
        "base_ref",
        "head_ref",
    )
    @classmethod
    def validate_required_text(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "GitHub PR metadata value "
                "cannot be empty."
            )

        return cleaned

    @model_validator(
        mode="after",
    )
    def validate_shas(
        self,
    ) -> "GitHubPullRequestMetadata":
        if self.base_sha == self.head_sha:
            raise ValueError(
                "base_sha and head_sha "
                "must be different."
            )

        return self

    @computed_field
    @property
    def is_fork(
        self,
    ) -> bool:
        return (
            self.head_repository
            != self.repository
        )


def _parse_github_pr_object(
    *,
    pull_request: object,
    repository_name: str,
    field_prefix: str,
) -> GitHubPullRequestMetadata:
    pr = _required_dict(
        pull_request,
        field_name=field_prefix,
    )

    pull_request_number = (
        _required_positive_int(
            pr.get(
                "number"
            ),
            field_name=(
                f"{field_prefix}.number"
            ),
        )
    )

    changed_files = (
        _required_non_negative_int(
            pr.get(
                "changed_files"
            ),
            field_name=(
                f"{field_prefix}.changed_files"
            ),
        )
    )

    base = _required_dict(
        pr.get(
            "base"
        ),
        field_name=(
            f"{field_prefix}.base"
        ),
    )

    head = _required_dict(
        pr.get(
            "head"
        ),
        field_name=(
            f"{field_prefix}.head"
        ),
    )

    base_sha = _required_text(
        base.get(
            "sha"
        ),
        field_name=(
            f"{field_prefix}.base.sha"
        ),
    )

    head_sha = _required_text(
        head.get(
            "sha"
        ),
        field_name=(
            f"{field_prefix}.head.sha"
        ),
    )

    base_ref = _required_text(
        base.get(
            "ref"
        ),
        field_name=(
            f"{field_prefix}.base.ref"
        ),
    )

    head_ref = _required_text(
        head.get(
            "ref"
        ),
        field_name=(
            f"{field_prefix}.head.ref"
        ),
    )

    head_repo = _required_dict(
        head.get(
            "repo"
        ),
        field_name=(
            f"{field_prefix}.head.repo"
        ),
    )

    head_repository = (
        _validate_repository_name(
            head_repo.get(
                "full_name"
            ),
            field_name=(
                f"{field_prefix}."
                "head.repo.full_name"
            ),
        )
    )

    return GitHubPullRequestMetadata(
        repository=repository_name,
        pull_request_number=(
            pull_request_number
        ),
        changed_files=changed_files,
        base_sha=base_sha,
        head_sha=head_sha,
        base_ref=base_ref,
        head_ref=head_ref,
        head_repository=(
            head_repository
        ),
    )


def parse_github_pull_request_metadata(
    payload: object,
) -> GitHubPullRequestMetadata:
    """
    Parse GitHub pull_request webhook
    payload into SYCUR metadata.
    """

    root = _required_dict(
        payload,
        field_name="GitHub webhook payload",
    )

    repository = _required_dict(
        root.get(
            "repository"
        ),
        field_name="repository",
    )

    repository_name = (
        _validate_repository_name(
            repository.get(
                "full_name"
            ),
            field_name=(
                "repository.full_name"
            ),
        )
    )

    return _parse_github_pr_object(
        pull_request=root.get(
            "pull_request"
        ),
        repository_name=repository_name,
        field_prefix="pull_request",
    )


def parse_github_rest_pull_request_metadata(
    payload: object,
) -> GitHubPullRequestMetadata:
    """
    Parse GitHub REST
    GET /repos/{owner}/{repo}/pulls/{number}
    response into SYCUR metadata.
    """

    root = _required_dict(
        payload,
        field_name=(
            "GitHub REST pull request response"
        ),
    )

    base = _required_dict(
        root.get(
            "base"
        ),
        field_name="base",
    )

    base_repo = _required_dict(
        base.get(
            "repo"
        ),
        field_name="base.repo",
    )

    repository_name = (
        _validate_repository_name(
            base_repo.get(
                "full_name"
            ),
            field_name=(
                "base.repo.full_name"
            ),
        )
    )

    return _parse_github_pr_object(
        pull_request=root,
        repository_name=repository_name,
        field_prefix="pull_request",
    )
