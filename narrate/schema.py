"""The only shape the model is allowed to answer in.

`verifier/plan.py` is deliberately permissive, because the verifier's job is to judge a
plan action by action and report a reason a human can read. This module is the opposite:
it is the door the model's output has to fit through, and it is deliberately narrow.

Anything that does not fit is an error, not something to repair. A repaired plan is a
plan nobody proposed, and there would be no honest way to tell a human who wrote it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator

from verifier.plan import ProposedAction, ProposedPlan


class NarrationError(RuntimeError):
    """The narrator did not produce a usable plan. The step fails; nothing is guessed."""


def _must_not_be_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


class NarratedAction(BaseModel):
    # extra="forbid" so a field the model invented is an error rather than something
    # silently dropped on the way to the verifier.
    model_config = ConfigDict(extra="forbid")

    action_type: str
    target: str
    # Required and nullable. A forgotten region and a deliberate "no region" are
    # different claims about which machine this is, and the model has to pick one.
    region: str | None
    # Required, because this is the sentence the approver reads before clicking.
    reason: str

    @field_validator("action_type", "target", "reason")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        return _must_not_be_blank(value)


class NarratedIncident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    # No default. Proposing nothing has to be stated, not left out: omission is the one
    # failure the verifier cannot see, so we at least make the model commit to it.
    actions: list[NarratedAction]

    @field_validator("summary")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        return _must_not_be_blank(value)

    def to_proposed_plan(self) -> ProposedPlan:
        """Hand the plan over to the verifier, unchanged."""
        return ProposedPlan(
            summary=self.summary,
            actions=[
                ProposedAction(
                    action_type=action.action_type,
                    target=action.target,
                    region=action.region,
                    reason=action.reason,
                )
                for action in self.actions
            ],
        )
