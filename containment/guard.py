"""The gate every destructive call passes through.

An approval is scoped to one action and to one round of approval. Both halves matter:
scoping to the action stops a single click authorising everything, and scoping to the
task token stops a decision from an earlier, superseded round authorising anything now.
"""

from __future__ import annotations

from shared.approvals import ApprovalState, action_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord
from verifier.plan import ProposedAction


class NotApproved(Exception):
    """Raised when an action has not been approved by a human, for any reason."""


def require_approval(
    store: IncidentStore, incident: IncidentRecord, action: ProposedAction
) -> None:
    """Return quietly if this exact action is approved. Raise otherwise. Never return False."""
    signature = action_signature(action.action_type, action.target, action.region)

    if not incident.approval_token:
        raise NotApproved(
            f"incident {incident.incident_id} carries no approval token, so {signature} "
            "is not authorised"
        )

    decision = store.decision_for(incident.incident_id, signature)
    if decision is None:
        raise NotApproved(f"no decision recorded for {signature}")
    if decision.state is ApprovalState.DENIED:
        raise NotApproved(f"{signature} was denied by {decision.decided_by}")
    if decision.approval_token != incident.approval_token:
        raise NotApproved(
            f"{signature} was approved against a different approval token, so the decision "
            "belongs to a superseded round"
        )
