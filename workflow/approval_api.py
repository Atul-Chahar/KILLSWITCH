"""The API behind the console: read one incident, and answer the approval it is waiting on.

Submitting decisions does two things in this order: write each decision to DynamoDB, then
release the Step Functions task token. The order matters. Containment re-reads the stored
decisions before it acts, so if the token were released first, the workflow could reach
containment before the decisions it is meant to obey had landed.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

import boto3

from shared.approvals import ApprovalRecord, ApprovalState
from shared.incidents import IncidentStore

ARTIFACT_FIELDS = ("blast_radius", "verification", "tiers", "summary", "end_state")


def _store() -> IncidentStore:
    table = boto3.resource("dynamodb").Table(os.environ["INCIDENT_TABLE_NAME"])
    return IncidentStore(table)


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def incident_view(store: IncidentStore, incident_id: str) -> dict[str, Any] | None:
    """Everything the console renders, assembled from the record and its audit rows."""
    item = store.raw_incident(incident_id)
    if item is None:
        return None

    view: dict[str, Any] = {
        "incident_id": item.get("incident_id"),
        "access_key_id": item.get("access_key_id"),
        "source": item.get("source"),
        "status": item.get("status"),
        "detected_at": item.get("detected_at"),
        "repository": item.get("repository"),
        "commit_sha": item.get("commit_sha"),
        "key_owner": item.get("key_owner"),
        "audit": [entry.model_dump(mode="json") for entry in store.audit_trail(incident_id)],
    }
    for field in ARTIFACT_FIELDS:
        view[field] = item.get(field)
    if view.get("tiers") is None:
        view["tiers"] = []
    return view


def record_decisions(
    store: IncidentStore,
    incident_id: str,
    decisions: list[dict[str, Any]],
    *,
    decided_by: str,
    now: datetime | None = None,
) -> str:
    """Write every decision against the token the incident is currently waiting on."""
    incident = store.get(incident_id)
    if incident is None:
        raise LookupError(f"no incident {incident_id}")
    if not incident.approval_token:
        raise LookupError(f"incident {incident_id} is not waiting for an approval")

    when = now or datetime.now(UTC)
    for decision in decisions:
        store.record_decision(
            ApprovalRecord.create(
                incident_id=incident_id,
                action_signature=str(decision["action_signature"]),
                state=ApprovalState(str(decision["state"])),
                approval_token=incident.approval_token,
                decided_by=decided_by,
                decided_at=when,
            )
        )
    return incident.approval_token


def _caller(event: dict[str, Any]) -> str:
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    claims = authorizer.get("claims") or authorizer
    return str(claims.get("email") or claims.get("cognito:username") or "unknown")


def lambda_handler(
    event: dict[str, Any],
    _context: Any = None,
    *,
    store: IncidentStore | None = None,
    step_functions: Any | None = None,
) -> dict[str, Any]:
    store = store or _store()
    incident_id = str((event.get("pathParameters") or {}).get("incident_id", ""))
    if not incident_id:
        return _response(400, {"error": "no incident id in the path"})

    method = str(event.get("httpMethod", "GET")).upper()

    if method == "GET":
        view = incident_view(store, incident_id)
        if view is None:
            return _response(404, {"error": f"no incident {incident_id}"})
        return _response(200, view)

    if method == "POST":
        body = json.loads(event.get("body") or "{}")
        decisions = body.get("decisions") or []
        if not decisions:
            return _response(400, {"error": "no decisions submitted"})

        try:
            token = record_decisions(store, incident_id, decisions, decided_by=_caller(event))
        except (LookupError, ValueError) as error:
            return _response(409, {"error": str(error)})

        client = step_functions or boto3.client("stepfunctions")
        client.send_task_success(taskToken=token, output=json.dumps({"decided": True}))

        view = incident_view(store, incident_id)
        return _response(200, view or {"incident_id": incident_id})

    return _response(405, {"error": f"{method} is not supported"})
