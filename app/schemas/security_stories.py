"""Validated operator workflow requests for Security Stories."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SecurityStoryUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    expected_version: int = Field(ge=1)
    status: Literal["OPEN", "ACKNOWLEDGED", "CLOSED"]
    notes: str | None = Field(default=None, max_length=2000)
