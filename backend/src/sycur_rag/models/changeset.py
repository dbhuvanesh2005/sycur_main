from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


PullRequestFileStatus = Literal[
    "added",
    "modified",
    "removed",
    "renamed",
    "copied",
    "changed",
    "unchanged",
]


def _normalize_repository_path(
    value: str,
    *,
    field_name: str,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise TypeError(
            f"{field_name} must be a string."
        )

    cleaned = (
        value
        .strip()
        .replace("\\", "/")
    )

    if not cleaned:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    path = PurePosixPath(
        cleaned
    )

    if path.is_absolute():
        raise ValueError(
            f"{field_name} must be "
            "repository-relative."
        )

    if ".." in path.parts:
        raise ValueError(
            f"{field_name} cannot escape "
            "the repository."
        )

    normalized = path.as_posix()

    if normalized in {
        ".",
        "",
    }:
        raise ValueError(
            f"{field_name} must identify "
            "a file."
        )

    return normalized


class PullRequestFileChange(
    BaseModel
):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    path: str

    status: PullRequestFileStatus

    previous_path: str | None = None

    blob_sha: str | None = None

    patch: str | None = None

    additions: int = Field(
        default=0,
        ge=0,
    )

    deletions: int = Field(
        default=0,
        ge=0,
    )

    changes: int = Field(
        default=0,
        ge=0,
    )

    @field_validator(
        "path",
    )
    @classmethod
    def validate_path(
        cls,
        value: str,
    ) -> str:
        return _normalize_repository_path(
            value,
            field_name="path",
        )

    @field_validator(
        "previous_path",
    )
    @classmethod
    def validate_previous_path(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return _normalize_repository_path(
            value,
            field_name="previous_path",
        )

    @field_validator(
        "blob_sha",
    )
    @classmethod
    def validate_blob_sha(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "blob_sha cannot be blank."
            )

        return cleaned

    @field_validator(
        "patch",
    )
    @classmethod
    def normalize_patch(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        # Empty patch is equivalent to GitHub
        # not supplying patch content.
        if not value.strip():
            return None

        return value

    @model_validator(
        mode="after",
    )
    def validate_rename_contract(
        self,
    ) -> "PullRequestFileChange":
        if self.status == "renamed":
            if self.previous_path is None:
                raise ValueError(
                    "Renamed PR files must "
                    "include previous_path."
                )

            if (
                self.previous_path
                == self.path
            ):
                raise ValueError(
                    "Renamed PR file must "
                    "change its path."
                )

        elif self.previous_path is not None:
            raise ValueError(
                "previous_path is only valid "
                "for renamed PR files."
            )

        return self

    @computed_field
    @property
    def exists_in_head(
        self,
    ) -> bool:
        return self.status != "removed"

    @computed_field
    @property
    def is_scannable(
        self,
    ) -> bool:
        return (
            self.exists_in_head
            and self.status
            != "unchanged"
        )

    @computed_field
    @property
    def has_patch(
        self,
    ) -> bool:
        return self.patch is not None


class PullRequestChangeSet(
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

    base_sha: str

    head_sha: str

    files: tuple[
        PullRequestFileChange,
        ...,
    ]

    @field_validator(
        "repository",
    )
    @classmethod
    def validate_repository(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "repository cannot be empty."
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
                "repository must use "
                "'owner/repository' format."
            )

        return cleaned

    @field_validator(
        "base_sha",
        "head_sha",
    )
    @classmethod
    def validate_commit_sha(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "Commit SHA cannot be empty."
            )

        return cleaned

    @model_validator(
        mode="after",
    )
    def validate_change_set(
        self,
    ) -> "PullRequestChangeSet":
        if self.base_sha == self.head_sha:
            raise ValueError(
                "base_sha and head_sha "
                "must be different."
            )

        paths: set[str] = set()

        for file_change in self.files:
            if file_change.path in paths:
                raise ValueError(
                    "Duplicate PR file path: "
                    f"{file_change.path}"
                )

            paths.add(
                file_change.path
            )

        return self

    @computed_field
    @property
    def changed_file_count(
        self,
    ) -> int:
        return len(
            self.files
        )

    @computed_field
    @property
    def scannable_paths(
        self,
    ) -> tuple[str, ...]:
        return tuple(
            file_change.path
            for file_change
            in self.files
            if file_change.is_scannable
        )

    @computed_field
    @property
    def removed_paths(
        self,
    ) -> tuple[str, ...]:
        return tuple(
            file_change.path
            for file_change
            in self.files
            if file_change.status
            == "removed"
        )

    @computed_field
    @property
    def total_additions(
        self,
    ) -> int:
        return sum(
            file_change.additions
            for file_change
            in self.files
        )

    @computed_field
    @property
    def total_deletions(
        self,
    ) -> int:
        return sum(
            file_change.deletions
            for file_change
            in self.files
        )