"""Which actions a machine may take alone, and which need a person.

Amazon Verified Permissions holds the policy. This module asks it, and falls back to the
table below if the service cannot answer, because an incident response that stops dead
because a policy store is unreachable has failed in the least useful way possible.

The fallback is deliberately the strict one: anything destructive needs a human. A
fallback that guessed "allow" would turn an outage into an unsupervised deletion.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

NAMESPACE = "Killswitch"
AUTOMATION_PRINCIPAL_ID = "workflow"

READ_ACTIONS = frozenset({"read_evidence", "tag_resource"})
DESTRUCTIVE_ACTIONS = frozenset({"deactivate_key", "terminate_instance", "open_pr"})


class ApprovalTier(StrEnum):
    AUTOMATIC = "automatic"
    HUMAN = "human"


class DecisionSource(StrEnum):
    VERIFIED_PERMISSIONS = "verified_permissions"
    FALLBACK_TABLE = "fallback_table"


class TierDecision(BaseModel):
    action_type: str
    tier: ApprovalTier
    source: DecisionSource
    # From Cedar's determiningPolicies, so the console can show which policy decided.
    determining_policy_ids: list[str] = Field(default_factory=list)
    aws_error_code: str | None = None


def fallback_tier(action_type: str) -> ApprovalTier:
    """The table the cut list describes. Unknown actions are treated as destructive."""
    if action_type in READ_ACTIONS:
        return ApprovalTier.AUTOMATIC
    return ApprovalTier.HUMAN


def tier_from_cedar_decision(decision: str) -> ApprovalTier:
    """ALLOW means the automation may act alone. Anything else means ask a person."""
    return ApprovalTier.AUTOMATIC if decision.upper() == "ALLOW" else ApprovalTier.HUMAN


def approval_tier_for(
    action_type: str,
    *,
    incident_id: str,
    verified_permissions_client: Any | None = None,
    policy_store_id: str | None = None,
) -> TierDecision:
    """Ask Verified Permissions whether the automation may take this action unattended."""
    if verified_permissions_client is None or not policy_store_id:
        return TierDecision(
            action_type=action_type,
            tier=fallback_tier(action_type),
            source=DecisionSource.FALLBACK_TABLE,
        )

    try:
        response = verified_permissions_client.is_authorized(
            policyStoreId=policy_store_id,
            principal={
                "entityType": f"{NAMESPACE}::Automation",
                "entityId": AUTOMATION_PRINCIPAL_ID,
            },
            action={"actionType": f"{NAMESPACE}::Action", "actionId": action_type},
            resource={"entityType": f"{NAMESPACE}::Incident", "entityId": incident_id},
            context={"contextMap": {"human_approved": {"boolean": False}}},
        )
    except (ClientError, BotoCoreError) as error:
        code = None
        if isinstance(error, ClientError):
            code = error.response.get("Error", {}).get("Code")
        return TierDecision(
            action_type=action_type,
            tier=fallback_tier(action_type),
            source=DecisionSource.FALLBACK_TABLE,
            aws_error_code=str(code) if code else type(error).__name__,
        )

    determining = [
        str(policy.get("policyId", ""))
        for policy in response.get("determiningPolicies", [])
        if policy.get("policyId")
    ]
    return TierDecision(
        action_type=action_type,
        tier=tier_from_cedar_decision(str(response.get("decision", "DENY"))),
        source=DecisionSource.VERIFIED_PERMISSIONS,
        determining_policy_ids=determining,
    )
