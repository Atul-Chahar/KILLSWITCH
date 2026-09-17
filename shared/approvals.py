"""Approvals and the audit trail.

Both live in the incident table under the same partition key, separated by a sort key,
so a decision and the actions taken under it can never drift into different stores.

Audit rows are append-only items rather than a list attribute on the incident: two
containment steps writing at once would otherwise overwrite each other's history, which
is the one thing an audit trail may not do.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

INCIDENT_SORT_KEY = "incident"
APPROVAL_PREFIX = "approval#"
AUDIT_PREFIX = "audit#"


class ApprovalState(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"


class AuditStage(StrEnum):
    BEFORE = "before"
    AFTER = "after"
    REFUSED = "refused"
    FAILED = "failed"


def action_signature(action_type: str, target: str, region: str | None) -> str:
    """The identity of one action. An approval is scoped to exactly this string."""
    return f"{action_type}:{target}:{region or '-'}"


class ApprovalRecord(BaseModel):
    incident_id: str
    sk: str
    action_signature: str
    state: ApprovalState
    # The task token the workflow was waiting on when this decision was made. Containment
    # compares it with the token currently on the incident, so a decision recorded against
    # an earlier, superseded approval round cannot authorise anything now.
    approval_token: str
    decided_by: str
    decided_at: datetime

    @classmethod
    def create(
        cls,
        *,
        incident_id: str,
        action_signature: str,
        state: ApprovalState,
        approval_token: str,
        decided_by: str,
        decided_at: datetime | None = None,
    ) -> ApprovalRecord:
        return cls(
            incident_id=incident_id,
            sk=f"{APPROVAL_PREFIX}{action_signature}",
            action_signature=action_signature,
            state=state,
            approval_token=approval_token,
            decided_by=decided_by,
            decided_at=decided_at or datetime.now(UTC),
        )

    def to_item(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AuditEntry(BaseModel):
    incident_id: str
    sk: str
    stage: AuditStage
    action_signature: str
    recorded_at: datetime
    outcome: str | None = None
    details: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        incident_id: str,
        action_signature: str,
        stage: AuditStage,
        recorded_at: datetime | None = None,
        outcome: str | None = None,
        details: dict[str, str] | None = None,
    ) -> AuditEntry:
        when = recorded_at or datetime.now(UTC)
        return cls(
            incident_id=incident_id,
            sk=f"{AUDIT_PREFIX}{when.isoformat()}#{uuid.uuid4()}",
            stage=stage,
            action_signature=action_signature,
            recorded_at=when,
            outcome=outcome,
            details=details or {},
        )

    def to_item(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
