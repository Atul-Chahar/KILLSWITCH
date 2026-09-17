"""Trigger two: AWS attaches its own quarantine policy to the compromised user.

There is no dedicated "quarantine" event. AWS attaches a managed policy, CloudTrail
records the AttachUserPolicy call, and EventBridge delivers that. The event names a
user, never a key, so the key ids are resolved through IAM before an incident opens.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from investigate.identify import active_access_key_ids
from shared.incidents import IncidentStore
from shared.models import IncidentRecord, IncidentSource, incident_id_for

QUARANTINE_POLICY_MARKER = "AWSCompromisedKeyQuarantine"
QUARANTINE_EVENT_NAMES = {"AttachUserPolicy", "PutUserPolicy"}


def is_quarantine_event(detail: dict[str, Any]) -> bool:
    """True only for AWS attaching a quarantine policy, whatever version it is on.

    Matching the marker rather than an exact ARN means a bump from V2 to V3 to V4
    does not silently stop the trigger from firing.
    """
    if detail.get("eventName") not in QUARANTINE_EVENT_NAMES:
        return False
    parameters = detail.get("requestParameters") or {}
    policy_arn = str(parameters.get("policyArn", ""))
    return QUARANTINE_POLICY_MARKER in policy_arn


def user_name_from_event(detail: dict[str, Any]) -> str:
    parameters = detail.get("requestParameters") or {}
    return str(parameters.get("userName", ""))


def handle_quarantine(
    event: dict[str, Any],
    iam_client: Any,
    store: IncidentStore,
    *,
    now: datetime | None = None,
) -> list[IncidentRecord]:
    detail = event.get("detail") or {}
    if not is_quarantine_event(detail):
        return []

    user_name = user_name_from_event(detail)
    if not user_name:
        return []

    detected_at = now or datetime.now(UTC)
    incidents: list[IncidentRecord] = []
    for access_key_id in active_access_key_ids(iam_client, user_name):
        record, _created = store.create_if_absent(
            IncidentRecord(
                incident_id=incident_id_for(access_key_id),
                access_key_id=access_key_id,
                source=IncidentSource.AWS_QUARANTINE,
                detected_at=detected_at,
                key_owner=user_name,
            )
        )
        incidents.append(record)
    return incidents


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    import boto3

    table = boto3.resource("dynamodb").Table(os.environ["INCIDENT_TABLE_NAME"])
    incidents = handle_quarantine(event, boto3.client("iam"), IncidentStore(table))
    return {"incidents": [incident.incident_id for incident in incidents]}
