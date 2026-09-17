"""The records every module passes around. Typed, so nothing travels as free text."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IncidentSource(StrEnum):
    GITHUB_PUSH = "github_push"
    AWS_QUARANTINE = "aws_quarantine"


class IncidentStatus(StrEnum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    CONTAINING = "containing"
    CONTAINED = "contained"
    FAILED = "failed"


def incident_id_for(access_key_id: str) -> str:
    """One leaked key is one incident, so the key id derives the partition key.

    Both triggers can then write the same id and let DynamoDB settle who was first.
    """
    return f"inc-{access_key_id}"


class IncidentRecord(BaseModel):
    incident_id: str
    access_key_id: str
    source: IncidentSource
    detected_at: datetime
    status: IncidentStatus = IncidentStatus.DETECTED
    repository: str | None = None
    commit_sha: str | None = None
    key_owner: str | None = None
    approval_token: str | None = None
    notes: list[str] = Field(default_factory=list)

    def to_item(self) -> dict[str, Any]:
        item = self.model_dump(mode="json")
        return {key: value for key, value in item.items() if value is not None}

    @classmethod
    def from_item(cls, item: dict[str, Any]) -> IncidentRecord:
        return cls.model_validate(item)
