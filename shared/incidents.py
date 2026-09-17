"""Incident storage. The conditional write is what makes two triggers safe."""

from __future__ import annotations

from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from shared.approvals import (
    APPROVAL_PREFIX,
    AUDIT_PREFIX,
    INCIDENT_SORT_KEY,
    ApprovalRecord,
    AuditEntry,
)
from shared.models import IncidentRecord

CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"


class IncidentStore:
    def __init__(self, table: Any) -> None:
        self._table = table

    def create_if_absent(self, record: IncidentRecord) -> tuple[IncidentRecord, bool]:
        """Store the incident, or return the one already there.

        Returns (incident, created). DynamoDB decides the race, not us: whichever
        trigger writes first owns the record, and the loser reads it back rather
        than overwriting a detection that is already under way.
        """
        item = record.to_item() | {"sk": INCIDENT_SORT_KEY}
        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(incident_id)",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != CONDITIONAL_CHECK_FAILED:
                raise
            existing = self.get(record.incident_id)
            if existing is None:
                raise
            return existing, False
        return record, True

    def get(self, incident_id: str) -> IncidentRecord | None:
        response = self._table.get_item(Key={"incident_id": incident_id, "sk": INCIDENT_SORT_KEY})
        item = response.get("Item")
        if item is None:
            return None
        return IncidentRecord.from_item(item)

    def set_approval_token(self, incident_id: str, approval_token: str) -> None:
        """Record the token the workflow is waiting on, so containment can check it."""
        self._table.update_item(
            Key={"incident_id": incident_id, "sk": INCIDENT_SORT_KEY},
            UpdateExpression="SET approval_token = :token, #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":token": approval_token, ":status": "awaiting_approval"},
        )

    def save_artifacts(self, incident_id: str, artifacts: dict[str, Any]) -> None:
        """Persist what the console has to render: the evidence, the plan and the tiers.

        These live in the workflow's execution state, which the console cannot read, so
        they are written to the incident before the execution pauses for approval.
        """
        if not artifacts:
            return
        names = {f"#{key}": key for key in artifacts}
        values = {f":{key}": value for key, value in artifacts.items()}
        assignments = ", ".join(f"#{key} = :{key}" for key in artifacts)
        self._table.update_item(
            Key={"incident_id": incident_id, "sk": INCIDENT_SORT_KEY},
            UpdateExpression=f"SET {assignments}",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    def raw_incident(self, incident_id: str) -> dict[str, Any] | None:
        """The stored item as-is, including artifacts the typed record does not model."""
        response = self._table.get_item(Key={"incident_id": incident_id, "sk": INCIDENT_SORT_KEY})
        item = response.get("Item")
        return dict(item) if item else None

    def record_decision(self, decision: ApprovalRecord) -> None:
        self._table.put_item(Item=decision.to_item())

    def decision_for(self, incident_id: str, action_signature: str) -> ApprovalRecord | None:
        response = self._table.get_item(
            Key={"incident_id": incident_id, "sk": f"{APPROVAL_PREFIX}{action_signature}"}
        )
        item = response.get("Item")
        if item is None:
            return None
        return ApprovalRecord.model_validate(item)

    def append_audit(self, entry: AuditEntry) -> None:
        self._table.put_item(Item=entry.to_item())

    def audit_trail(self, incident_id: str) -> list[AuditEntry]:
        response = self._table.query(
            KeyConditionExpression=Key("incident_id").eq(incident_id)
            & Key("sk").begins_with(AUDIT_PREFIX)
        )
        return [AuditEntry.model_validate(item) for item in response.get("Items", [])]
