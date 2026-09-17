"""The shape a proposed plan arrives in. Deliberately permissive, so the verifier judges it.

action_type is a plain string, not an enum. If it were an enum, an unrecognised action
would fail at the parser with a validation error, and the plan would be rejected wholesale
with nothing to show the operator. The verifier rejects it instead, per action, with a
reason the console can render.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProposedAction(BaseModel):
    action_type: str
    target: str
    region: str | None = None
    # The model's justification. Carried so a human can read it. Never consulted.
    reason: str | None = None


class ProposedPlan(BaseModel):
    summary: str = ""
    actions: list[ProposedAction] = Field(default_factory=list)
