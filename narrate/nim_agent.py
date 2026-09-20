"""Narrator backed by NVIDIA NIM via LiteLLM (OpenAI-compatible endpoint).

NVIDIA NIM exposes an OpenAI-compatible API at https://integrate.api.nvidia.com/v1.
LiteLLMModel in strands-agents wraps it transparently so the rest of the workflow
(verifier, authorize, containment) is completely unchanged.

Required environment variables
--------------------------------
NVIDIA_API_KEY   The nvapi-… key from build.nvidia.com
NIM_MODEL_ID     The NIM model id. Defaults to DEFAULT_NIM_MODEL below.

The model must support tool/function calling, because strands implements structured
output as a tool call. A model without it fails the Narrate step rather than
returning a plan — which is the correct outcome, but a confusing one to debug.

Confirm the id against the live catalogue before relying on it; NVIDIA's model
list changes and an id that has been renamed or retired fails at the first call:

    curl -s https://integrate.api.nvidia.com/v1/models \\
      -H "Authorization: Bearer $NVIDIA_API_KEY" | jq -r '.data[].id'
"""

from __future__ import annotations

import os
from typing import Any

from strands import Agent
from strands.models import LiteLLMModel

from investigate.blast_radius import BlastRadius
from narrate.prompt import SYSTEM_PROMPT, evidence_prompt
from narrate.schema import NarratedIncident, NarrationError

MAX_TURNS = 1
NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NIM_MODEL = "deepseek-ai/deepseek-v4-flash-0731"


def nim_model_id() -> str:
    """The NIM model id, from the environment. Falls back to a known-good default."""
    return os.environ.get("NIM_MODEL_ID", "").strip() or DEFAULT_NIM_MODEL


def nim_api_key() -> str:
    """The NVIDIA API key. Unset is an error — we refuse to call without one."""
    key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not key:
        raise NarrationError(
            "NVIDIA_API_KEY is not set. Set it to your nvapi-… key from build.nvidia.com"
        )
    return key


def build_nim_agent(*, model_id: str | None = None) -> Agent:
    """An agent with a system prompt and no tools, backed by NVIDIA NIM."""
    effective_model = model_id or nim_model_id()
    # LiteLLMModel routes by provider prefix. "openai/" tells LiteLLM to use the
    # OpenAI-compatible path; api_base and api_key re-point it at NVIDIA.
    #
    # Endpoint credentials go in client_args, not params. Both reach
    # litellm.acompletion on the normal agent path, but LiteLLMModel's
    # _structured_output_using_response_schema builds its call from client_args
    # alone and ignores params — so a key passed as a param silently goes to
    # api.openai.com on any model litellm reports as supporting response schemas.
    # params stays for real inference knobs.
    return Agent(
        model=LiteLLMModel(
            client_args={
                "api_base": NIM_BASE_URL,
                "api_key": nim_api_key(),
            },
            model_id=f"openai/{effective_model}",
            params={
                "temperature": 0.1,  # low temperature for deterministic plans
                "max_tokens": 2048,
            },
        ),
        system_prompt=SYSTEM_PROMPT,
        tools=[],
    )


def narrate_via_nim(
    radius: BlastRadius,
    *,
    repository: str | None,
    key_owner: str | None,
    agent: Any | None = None,
) -> NarratedIncident:
    """Ask the NVIDIA NIM model for a summary and a plan."""
    agent = agent or build_nim_agent()

    result = agent(
        evidence_prompt(radius, repository=repository, key_owner=key_owner),
        structured_output_model=NarratedIncident,
        limits={"turns": MAX_TURNS},
    )

    narration = getattr(result, "structured_output", None)
    if narration is None:
        raise NarrationError(
            "the NIM model produced no valid structured output "
            f"(stop_reason={getattr(result, 'stop_reason', None)!r})"
        )
    if not isinstance(narration, NarratedIncident):
        raise NarrationError(
            f"the NIM model produced a {type(narration).__name__}, not a NarratedIncident"
        )
    return narration
