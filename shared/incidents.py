"""Incident storage. The conditional write is what makes two triggers safe."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

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
        try:
            self._table.put_item(
                Item=record.to_item(),
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
        response = self._table.get_item(Key={"incident_id": incident_id})
        item = response.get("Item")
        if item is None:
            return None
        return IncidentRecord.from_item(item)
