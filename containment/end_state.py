"""Re-read AWS and confirm what actually happened.

Containment reports what each call returned. This module asks AWS again, afterwards,
because "the API accepted my request" and "the key is inactive" are different claims and
only the second one is worth showing a judge.

Anything it cannot confirm is reported as unconfirmed. There is no third option.
"""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

from containment.actions import SESSION_REVOCATION_POLICY_NAME
from shared.approvals import action_signature
from shared.models import IncidentRecord
from verifier.plan import ProposedAction
from verifier.verify import ActionType, VerifiedAction

INACTIVE = "Inactive"
TERMINAL_STATES = {"shutting-down", "terminated"}

# IAM is eventually consistent: ListAccessKeys can still report Active for a moment after
# UpdateAccessKey returned. Re-reading once and calling it unconfirmed would report a
# working containment as a failure, so the read is retried briefly before we believe it.
KEY_STATUS_ATTEMPTS = 3
KEY_STATUS_PAUSE_SECONDS = 2.0


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


def _sessions_revoked(iam_client: Any, user_name: str) -> bool:
    try:
        iam_client.get_user_policy(UserName=user_name, PolicyName=SESSION_REVOCATION_POLICY_NAME)
    except (ClientError, BotoCoreError):
        return False
    return True


def _instance_state(ec2_client: Any, instance_id: str) -> str | None:
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            if instance.get("InstanceId") == instance_id:
                return str(instance.get("State", {}).get("Name", ""))
    return None


def _confirm_key(
    target: ConfirmedTarget,
    incident: IncidentRecord,
    iam_client: Any,
    access_key_id: str,
    *,
    owner: str | None = None,
    sleep: Any = time.sleep,
) -> None:
    # The owner containment used, not the incident's: an attacker-minted key belongs to
    # whichever user the attacker created it under.
    key_owner = owner or incident.key_owner
    if not key_owner:
        target.aws_error_code = "UnknownKeyOwner"
        return
    for attempt in range(KEY_STATUS_ATTEMPTS):
        target.observed_state = _key_status(iam_client, key_owner, access_key_id)
        if target.observed_state == INACTIVE:
            break
        if attempt == KEY_STATUS_ATTEMPTS - 1:
            return
        sleep(KEY_STATUS_PAUSE_SECONDS)

    # Inactive alone is not containment: it stops new sessions, not the ones the attacker
    # already holds. The revocation policy is what denies those, so its absence means the
    # key is deactivated and the attacker may still be inside.
    if not _sessions_revoked(iam_client, key_owner):
        target.aws_error_code = "SessionsNotRevoked"
        return
    target.confirmed = True


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


def action_signature_of(action: ProposedAction) -> str:
    return action_signature(action.action_type, action.target, action.region)


def confirm_end_state(
    incident: IncidentRecord,
    actions: list[VerifiedAction],
    *,
    iam_client: Any,
    ec2_clients: dict[str, Any],
    containment_details: dict[str, dict[str, str]] | None = None,
    sleep: Any = time.sleep,
) -> EndState:
    """Check each acted-on target against AWS itself.

    `actions` is what containment actually attempted, not everything the verifier
    approved. An action the operator denied was never run, and re-reading its target
    would report the incident as unconfirmed because the human did their job.
    """
    details = containment_details or {}
    end_state = EndState(incident_id=incident.incident_id)

    for verified in actions:
        action = verified.action
        target = ConfirmedTarget(
            action_type=action.action_type, target=action.target, region=action.region
        )

        try:
            if action.action_type == ActionType.DEACTIVATE_KEY:
                _confirm_key(
                    target,
                    incident,
                    iam_client,
                    action.target,
                    owner=details.get(action_signature_of(action), {}).get("owner"),
                    sleep=sleep,
                )
            elif action.action_type == ActionType.TERMINATE_INSTANCE:
                _confirm_instance(target, verified, ec2_clients)
            elif action.action_type == ActionType.OPEN_PR:
                # There is nothing to re-read from AWS, so the only evidence a pull
                # request exists is the url containment recorded. No url means the action
                # did not happen -- and marking it confirmed anyway would be the one thing
                # this module exists to prevent.
                url = details.get(action_signature_of(action), {}).get("pull_request_url")
                target.observed_state = url or None
                target.confirmed = bool(url)
                if not url:
                    target.aws_error_code = "NoPullRequestRecorded"
        except (ClientError, BotoCoreError) as error:
            code = None
            if isinstance(error, ClientError):
                code = error.response.get("Error", {}).get("Code")
            target.aws_error_code = str(code) if code else type(error).__name__
            target.confirmed = False

        end_state.targets.append(target)

    return end_state
