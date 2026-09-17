"""The Strands agent on Amazon Bedrock. It reads evidence and proposes. Nothing else.

Two decisions in here are load-bearing, and both were taken by reading the installed
strands-agents source rather than trusting the documentation:

1. **The model gets one turn.** Strands implements structured output on Bedrock as a tool
   call, and when the pydantic model rejects the tool input it hands the validation error
   back to the model as a tool error so the model can try again. That is a sensible
   default for a chatbot and the wrong default here: it lets the component we have
   decided not to trust argue with the schema until it gets through. `limits={"turns": 1}`
   stops the loop at the first turn boundary, so a schema failure ends the step.
   The cost of that choice is real and is stated in the README: Strands also uses a second
   turn to re-ask a model that replied in prose instead of calling the tool, and we give
   up that nudge too. A model that answers in prose fails the step.
2. **The model does not stream.** `converse_stream` would need
   `bedrock:InvokeModelWithResponseStream` on top of `bedrock:InvokeModel`, and a Lambda
   has nobody to stream to. Non-streaming keeps the grant down to one action.
"""

from __future__ import annotations

import os
from typing import Any

from strands import Agent
from strands.models import BedrockModel

from investigate.blast_radius import BlastRadius
from narrate.prompt import SYSTEM_PROMPT, evidence_prompt
from narrate.schema import NarratedIncident, NarrationError

MAX_TURNS = 1


def bedrock_model_id() -> str:
    """The model id, from the environment. Unset is an error, not a default.

    Silently falling back to whatever model the SDK prefers would mean the incident
    record could not say which model wrote the plan.
    """
    model_id = os.environ.get("BEDROCK_MODEL_ID", "").strip()
    if not model_id:
        raise NarrationError("BEDROCK_MODEL_ID is not set, so there is no model to ask")
    return model_id


def build_bedrock_agent(*, model_id: str | None = None, region: str | None = None) -> Agent:
    """An agent with a system prompt and no tools. It has no way to touch anything."""
    return Agent(
        model=BedrockModel(
            model_id=model_id or bedrock_model_id(),
            region_name=region or os.environ.get("AWS_REGION") or None,
            streaming=False,
        ),
        system_prompt=SYSTEM_PROMPT,
        tools=[],
    )


def narrate(
    radius: BlastRadius,
    *,
    repository: str | None,
    key_owner: str | None,
    agent: Any | None = None,
) -> NarratedIncident:
    """Ask the model for a summary and a plan. Anything short of a valid one raises."""
    agent = agent or build_bedrock_agent()

    result = agent(
        evidence_prompt(radius, repository=repository, key_owner=key_owner),
        structured_output_model=NarratedIncident,
        limits={"turns": MAX_TURNS},
    )

    narration = getattr(result, "structured_output", None)
    if narration is None:
        # Either the model never called the structured output tool, or what it passed
        # failed validation and the retry we disabled would have been its second chance.
        raise NarrationError(
            "the model produced no valid structured output "
            f"(stop_reason={getattr(result, 'stop_reason', None)!r})"
        )
    if not isinstance(narration, NarratedIncident):
        raise NarrationError(
            f"the model produced a {type(narration).__name__}, not a NarratedIncident"
        )
    return narration
