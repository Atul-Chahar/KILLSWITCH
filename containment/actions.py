"""The only module in KILLSWITCH that destroys anything.

Every function here follows the same shape, and the shape is the safety property:

    refuse unless this exact action is approved  ->  audit BEFORE
    ->  act  ->  audit AFTER, or audit FAILED

A failure is recorded as a failure. Nothing in here reports success it did not observe.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

from containment.guard import NotApproved, require_approval
from shared.approvals import AuditEntry, AuditStage, action_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord
from verifier.plan import ProposedAction

INACTIVE = "Inactive"
TERMINAL_STATES = {"shutting-down", "terminated"}

# Opens a PR removing the secret. Injected so the GitHub API stays out of unit tests.
PullRequestOpener = Callable[[str, str], str]


class ContainmentResult(BaseModel):
    action_signature: str
    succeeded: bool
    already_done: bool = False
    details: dict[str, str] = Field(default_factory=dict)


def _audit(
    store: IncidentStore,
    incident: IncidentRecord,
    signature: str,
    stage: AuditStage,
    when: datetime,
    *,
    outcome: str | None = None,
    details: dict[str, str] | None = None,
) -> None:
    store.append_audit(
        AuditEntry.create(
            incident_id=incident.incident_id,
            action_signature=signature,
            stage=stage,
            recorded_at=when,
            outcome=outcome,
            details=details,
        )
    )


def _start(
    store: IncidentStore, incident: IncidentRecord, action: ProposedAction, when: datetime
) -> str:
    """Check approval and open the audit trail, or record the refusal and raise."""
    signature = action_signature(action.action_type, action.target, action.region)
    try:
        require_approval(store, incident, action)
    except NotApproved as refusal:
        _audit(store, incident, signature, AuditStage.REFUSED, when, outcome=str(refusal))
        raise
    _audit(store, incident, signature, AuditStage.BEFORE, when)
    return signature


def _failed(
    store: IncidentStore,
    incident: IncidentRecord,
    signature: str,
    when: datetime,
    error: Exception,
) -> ContainmentResult:
    _audit(store, incident, signature, AuditStage.FAILED, when, outcome=str(error))
    return ContainmentResult(action_signature=signature, succeeded=False)


def terminate_instance(
    ec2_client: Any,
    store: IncidentStore,
    incident: IncidentRecord,
    action: ProposedAction,
    *,
    now: datetime | None = None,
) -> ContainmentResult:
    when = now or datetime.now(UTC)
    signature = _start(store, incident, action, when)

    try:
        response = ec2_client.terminate_instances(InstanceIds=[action.target])
    except (ClientError, BotoCoreError) as error:
        return _failed(store, incident, signature, when, error)

    terminating = response.get("TerminatingInstances", [])
    previous = str(terminating[0]["PreviousState"]["Name"]) if terminating else ""
    current = str(terminating[0]["CurrentState"]["Name"]) if terminating else ""

    _audit(
        store,
        incident,
        signature,
        AuditStage.AFTER,
        when,
        outcome=current,
        details={"previous_state": previous, "current_state": current},
    )
    return ContainmentResult(
        action_signature=signature,
        succeeded=True,
        already_done=previous in TERMINAL_STATES,
        details={"current_state": current},
    )


def _key_status(iam_client: Any, user_name: str, access_key_id: str) -> str | None:
    for key in iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
        if key.get("AccessKeyId") == access_key_id:
            return str(key.get("Status", ""))
    return None


def deactivate_key(
    iam_client: Any,
    store: IncidentStore,
    incident: IncidentRecord,
    action: ProposedAction,
    *,
    now: datetime | None = None,
) -> ContainmentResult:
    when = now or datetime.now(UTC)
    signature = _start(store, incident, action, when)

    # IAM cannot deactivate a key without its owning user, and guessing one would be a
    # destructive call against a principal nobody identified.
    if not incident.key_owner:
        return _failed(
            store,
            incident,
            signature,
            when,
            RuntimeError("the owning IAM user is unknown, so the key cannot be deactivated"),
        )

    try:
        if _key_status(iam_client, incident.key_owner, action.target) == INACTIVE:
            _audit(store, incident, signature, AuditStage.AFTER, when, outcome=INACTIVE)
            return ContainmentResult(action_signature=signature, succeeded=True, already_done=True)
        iam_client.update_access_key(
            UserName=incident.key_owner, AccessKeyId=action.target, Status=INACTIVE
        )
    except (ClientError, BotoCoreError) as error:
        return _failed(store, incident, signature, when, error)

    _audit(store, incident, signature, AuditStage.AFTER, when, outcome=INACTIVE)
    return ContainmentResult(
        action_signature=signature, succeeded=True, details={"status": INACTIVE}
    )


def open_pull_request(
    opener: PullRequestOpener,
    store: IncidentStore,
    incident: IncidentRecord,
    action: ProposedAction,
    *,
    now: datetime | None = None,
) -> ContainmentResult:
    when = now or datetime.now(UTC)
    signature = _start(store, incident, action, when)

    try:
        url = opener(action.target, incident.access_key_id)
    except Exception as error:  # noqa: BLE001 - injected opener, any failure must be recorded
        return _failed(store, incident, signature, when, error)

    _audit(
        store,
        incident,
        signature,
        AuditStage.AFTER,
        when,
        outcome="opened",
        details={"pull_request_url": url},
    )
    return ContainmentResult(
        action_signature=signature, succeeded=True, details={"pull_request_url": url}
    )
