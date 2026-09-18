"""Starts the response workflow when a new incident appears.

The trigger is the incident table's stream rather than a call from the detection Lambdas,
for two reasons.

1. **It is the same signal for both triggers.** A GitHub push and an AWS quarantine both
   end in one conditional write, and only the write that wins produces an INSERT. The
   loser of the race produces no stream record at all, so the workflow starts exactly
   once without either detector knowing the other exists.
2. **It breaks a stack cycle.** The response stack already depends on the incident table.
   Having the detection Lambdas call Step Functions would make the detection stack depend
   on the state machine, and the two stacks would import each other.

The execution name is derived from the incident, so a redelivered stream record cannot
start a second execution of the same incident: Step Functions rejects a duplicate name,
and that rejection is the idempotency rather than something to work around.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from shared.approvals import INCIDENT_SORT_KEY

EXECUTION_NAME_MAX = 80
UNSAFE_IN_EXECUTION_NAME = re.compile(r"[^A-Za-z0-9_-]")
ALREADY_STARTED = "ExecutionAlreadyExists"


def execution_name(incident_id: str, detected_at: str) -> str:
    """A name that is stable for one incident and different for the next one.

    Stable, so a redelivered record is refused. Different across incidents for the same
    key, so re-running the demo after clearing the table is not blocked by the name of an
    execution that finished days ago.
    """
    name = UNSAFE_IN_EXECUTION_NAME.sub("-", f"{incident_id}-{detected_at}")
    return name[:EXECUTION_NAME_MAX]


def _attribute(image: dict[str, Any], key: str) -> str:
    return str((image.get(key) or {}).get("S", ""))


def new_incident_ids(event: dict[str, Any]) -> list[tuple[str, str]]:
    """The (incident id, detected at) pairs this batch opened.

    Only INSERTs of the incident row itself. Approval and audit rows share the partition
    and would otherwise each look like a new incident.
    """
    found: list[tuple[str, str]] = []
    for record in event.get("Records", []):
        if record.get("eventName") != "INSERT":
            continue
        stream = record.get("dynamodb") or {}
        keys = stream.get("Keys") or {}
        if _attribute(keys, "sk") != INCIDENT_SORT_KEY:
            continue
        incident_id = _attribute(keys, "incident_id")
        if not incident_id:
            continue
        found.append((incident_id, _attribute(stream.get("NewImage") or {}, "detected_at")))
    return found


def start_workflows(
    event: dict[str, Any], step_functions: Any, state_machine_arn: str
) -> list[str]:
    """Start one execution per new incident. Returns the ids actually started."""
    started: list[str] = []
    for incident_id, detected_at in new_incident_ids(event):
        try:
            step_functions.start_execution(
                stateMachineArn=state_machine_arn,
                name=execution_name(incident_id, detected_at),
                input=json.dumps({"incident_id": incident_id}),
            )
        except Exception as error:  # noqa: BLE001 - the duplicate case is the normal one
            if ALREADY_STARTED in type(error).__name__ or ALREADY_STARTED in str(error):
                continue
            raise
        started.append(incident_id)
    return started


def lambda_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    import boto3

    started = start_workflows(event, boto3.client("stepfunctions"), os.environ["STATE_MACHINE_ARN"])
    return {"started": started}
