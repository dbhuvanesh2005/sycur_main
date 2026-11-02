from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ValidatedPREvent(BaseModel):
    delivery_id: UUID
    installation_id: int = Field(gt=0)
    repository: str = Field(min_length=1)
    pr_number: int = Field(gt=0)
    head_sha: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    action: Literal["opened", "synchronize", "reopened"]
