"""Re-read AWS and confirm what actually happened.

Containment reports what each call returned. This module asks AWS again, afterwards,
because "the API accepted my request" and "the key is inactive" are different claims and
only the second one is worth showing a judge.

Anything it cannot confirm is reported as unconfirmed. There is no third option.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

from shared.models import IncidentRecord
from verifier.verify import ActionType, VerifiedAction

INACTIVE = "Inactive"
TERMINAL_STATES = {"shutting-down", "terminated"}


class ConfirmedTarget(BaseModel):
    action_type: str
    target: str
    region: str | None = None
    observed_state: str | None = None
    confirmed: bool = False
    aws_error_code: str | None = None


class EndState(BaseModel):
    incident_id: str
    targets: list[ConfirmedTarget] = Field(default_factory=list)

    @property
    def all_confirmed(self) -> bool:
        return bool(self.targets) and all(target.confirmed for target in self.targets)


def _key_status(iam_client: Any, user_name: str, access_key_id: str) -> str | None:
    for key in iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
        if key.get("AccessKeyId") == access_key_id:
            return str(key.get("Status", ""))
    return None


def _instance_state(ec2_client: Any, instance_id: str) -> str | None:
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            if instance.get("InstanceId") == instance_id:
                return str(instance.get("State", {}).get("Name", ""))
    return None


def _confirm_key(
    target: ConfirmedTarget, incident: IncidentRecord, iam_client: Any, access_key_id: str
) -> None:
    if not incident.key_owner:
        target.aws_error_code = "UnknownKeyOwner"
        return
    target.observed_state = _key_status(iam_client, incident.key_owner, access_key_id)
    target.confirmed = target.observed_state == INACTIVE


def _confirm_instance(
    target: ConfirmedTarget, verified: VerifiedAction, ec2_clients: dict[str, Any]
) -> None:
    region = verified.evidence.region if verified.evidence else verified.action.region
    client = ec2_clients.get(region or "")
    if client is None:
        target.aws_error_code = "NoClientForRegion"
        return
    target.observed_state = _instance_state(client, verified.action.target)
    target.confirmed = target.observed_state in TERMINAL_STATES


def confirm_end_state(
    incident: IncidentRecord,
    actions: list[VerifiedAction],
    *,
    iam_client: Any,
    ec2_clients: dict[str, Any],
) -> EndState:
    """Check each acted-on target against AWS itself."""
    end_state = EndState(incident_id=incident.incident_id)

    for verified in actions:
        action = verified.action
        target = ConfirmedTarget(
            action_type=action.action_type, target=action.target, region=action.region
        )

        try:
            if action.action_type == ActionType.DEACTIVATE_KEY:
                _confirm_key(target, incident, iam_client, action.target)
            elif action.action_type == ActionType.TERMINATE_INSTANCE:
                _confirm_instance(target, verified, ec2_clients)
            elif action.action_type == ActionType.OPEN_PR:
                # A pull request is confirmed by the url containment recorded. There is
                # nothing to re-read from AWS, and pretending otherwise would be theatre.
                target.confirmed = True
                target.observed_state = "recorded"
        except (ClientError, BotoCoreError) as error:
            code = None
            if isinstance(error, ClientError):
                code = error.response.get("Error", {}).get("Code")
            target.aws_error_code = str(code) if code else type(error).__name__
            target.confirmed = False

        end_state.targets.append(target)

    return end_state
