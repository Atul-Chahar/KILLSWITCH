"""The only module in KILLSWITCH that destroys anything.

Every function here follows the same shape, and the shape is the safety property:

    refuse unless this exact action is approved  ->  audit BEFORE
    ->  act  ->  audit AFTER, or audit FAILED

A failure is recorded as a failure. Nothing in here reports success it did not observe.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

from containment.guard import NotApproved, require_approval
from investigate.identify import IdentificationError, owner_of_access_key
from shared.approvals import AuditEntry, AuditStage, action_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord
from verifier.plan import ProposedAction

INACTIVE = "Inactive"
TERMINAL_STATES = {"shutting-down", "terminated"}

# Deactivating a key stops it minting new sessions. It does nothing to sessions the
# attacker already holds: credentials from sts:GetSessionToken or sts:AssumeRole keep
# working until they expire, which can be hours. AWS's own "revoke sessions" control
# attaches exactly this policy, and without it "contained" is a claim we cannot make.
SESSION_REVOCATION_POLICY_NAME = "KillswitchSessionRevocation"


def session_revocation_policy(issued_before: datetime) -> str:
    """Deny everything to credentials issued before now, and nothing issued after.

    Scoped by issue time rather than blanket-denying the user, so recovering the account
    later does not require remembering to unpick this policy first.
    """
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "DateLessThan": {
                            "aws:TokenIssueTime": issued_before.astimezone(UTC).isoformat()
                        }
                    },
                }
            ],
        }
    )


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


def _owner_of(iam_client: Any, incident: IncidentRecord, target: str) -> str | None:
    """Which IAM user this key belongs to.

    The incident's own key uses the owner investigation already established and persisted;
    guessing a different one would be a destructive call against a principal nobody named.
    A key the attacker minted is a different user's problem entirely, so it is resolved
    here, fresh, against IAM.
    """
    if target == incident.access_key_id:
        return incident.key_owner
    try:
        return owner_of_access_key(iam_client, target)
    except IdentificationError:
        return None


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

    # IAM cannot deactivate a key without its owning user.
    owner = _owner_of(iam_client, incident, action.target)
    if not owner:
        return _failed(
            store,
            incident,
            signature,
            when,
            RuntimeError(
                f"the owning IAM user of {action.target} is unknown, so it cannot be deactivated"
            ),
        )

    try:
        # An already-inactive key still needs its live sessions revoked, so this records
        # that the deactivation was a no-op rather than returning early.
        already_inactive = _key_status(iam_client, owner, action.target) == INACTIVE
        if not already_inactive:
            iam_client.update_access_key(UserName=owner, AccessKeyId=action.target, Status=INACTIVE)
    except (ClientError, BotoCoreError) as error:
        return _failed(store, incident, signature, when, error)

    # The key is inactive. Sessions minted from it before now are still live, so the
    # action is not finished until they are denied too.
    try:
        iam_client.put_user_policy(
            UserName=owner,
            PolicyName=SESSION_REVOCATION_POLICY_NAME,
            PolicyDocument=session_revocation_policy(when),
        )
    except (ClientError, BotoCoreError) as error:
        _audit(
            store,
            incident,
            signature,
            AuditStage.FAILED,
            when,
            outcome=f"key is {INACTIVE} but existing sessions could not be revoked: {error}",
            details={"status": INACTIVE, "owner": owner},
        )
        return ContainmentResult(
            action_signature=signature,
            succeeded=False,
            details={"status": INACTIVE, "owner": owner},
        )

    _audit(
        store,
        incident,
        signature,
        AuditStage.AFTER,
        when,
        outcome=INACTIVE,
        details={"sessions_revoked": SESSION_REVOCATION_POLICY_NAME, "owner": owner},
    )
    return ContainmentResult(
        action_signature=signature,
        succeeded=True,
        already_done=already_inactive,
        details={
            "status": INACTIVE,
            "sessions_revoked": SESSION_REVOCATION_POLICY_NAME,
            # Carried so confirmation re-reads the same user rather than assuming the
            # incident's owner, which is not the owner of an attacker-minted key.
            "owner": owner,
        },
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
