"""The NVIDIA NIM narrator.

Same contract as the Bedrock one: it proposes, the verifier disposes, and it gets
exactly one turn. These tests exist because swapping the model provider is exactly
the kind of change that quietly loosens a safety property nobody re-checked.

No test here reaches the network or needs a key.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from investigate.blast_radius import BlastRadius, CreatedResource, ResourceKind
from narrate.narrator import NarratorMode, narration_for, narrator_mode
from narrate.nim_agent import MAX_TURNS, build_nim_agent, narrate_via_nim, nim_model_id
from narrate.schema import NarratedAction, NarratedIncident, NarrationError
from verifier.verify import ActionType, RejectionReason, verify_plan

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
REPOSITORY = "octo/private-demo-repo"
LAUNCHED = "i-0a1b2c3d4e5f60001"
UNOWNED = "i-0999999999ffffff9"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)
NIM_MODULE = Path(__file__).resolve().parent.parent / "narrate" / "nim_agent.py"


def radius() -> BlastRadius:
    return BlastRadius(
        access_key_id=KEY,
        regions_searched=["ap-south-1"],
        window_start=NOW,
        window_end=NOW,
        resources=[
            CreatedResource(
                resource_id=LAUNCHED,
                kind=ResourceKind.EC2_INSTANCE,
                event_name="RunInstances",
                region="ap-south-1",
                event_time=NOW,
                source_ip="203.0.113.10",
                event_id="event-1",
            )
        ],
    )


def narration(*actions: NarratedAction) -> NarratedIncident:
    return NarratedIncident(summary="what the NIM model wrote", actions=list(actions))


class StubAgent:
    """Stands in for the LiteLLM-backed agent. Records the call, reaches no network."""

    def __init__(self, structured_output: object, stop_reason: str = "end_turn") -> None:
        self._structured_output = structured_output
        self._stop_reason = stop_reason
        self.calls: list[dict[str, object]] = []

    def __call__(self, prompt: str, **kwargs: object) -> SimpleNamespace:
        self.calls.append({"prompt": prompt, **kwargs})
        return SimpleNamespace(
            structured_output=self._structured_output, stop_reason=self._stop_reason
        )


def test_the_nim_model_also_gets_exactly_one_turn():
    """The decision that stops the model negotiating with the schema is provider-agnostic."""
    agent = StubAgent(narration())

    narrate_via_nim(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)

    assert MAX_TURNS == 1
    assert agent.calls[0]["limits"] == {"turns": 1}


def test_the_nim_model_is_asked_for_our_schema():
    agent = StubAgent(narration())

    narrate_via_nim(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)

    assert agent.calls[0]["structured_output_model"] is NarratedIncident


def test_output_that_never_validated_fails_the_step():
    agent = StubAgent(None, stop_reason="limit_turns")

    with pytest.raises(NarrationError) as raised:
        narrate_via_nim(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)

    assert "limit_turns" in str(raised.value)


def test_a_missing_api_key_is_an_error_rather_than_an_unauthenticated_call(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)

    with pytest.raises(NarrationError, match="NVIDIA_API_KEY"):
        build_nim_agent()


def test_the_model_id_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("NIM_MODEL_ID", "meta/llama-3.3-70b-instruct")

    assert nim_model_id() == "meta/llama-3.3-70b-instruct"


def test_the_endpoint_credentials_go_in_client_args_not_params(monkeypatch):
    """params is ignored by LiteLLM's response-schema path; a key there leaks to OpenAI."""
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-" + "stub")

    model = build_nim_agent().model

    assert model.client_args["api_base"] == "https://integrate.api.nvidia.com/v1"
    assert model.client_args["api_key"] == "nvapi-" + "stub"
    assert "api_key" not in (model.get_config().get("params") or {})


def test_the_nim_narrator_is_built_with_no_tools(monkeypatch):
    """It proposes. It cannot act, because it is handed nothing that acts."""
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-" + "stub")

    assert build_nim_agent().tool_names == []


def test_nim_mode_routes_through_the_dispatcher():
    assert narrator_mode("nim") is NarratorMode.NIM


def test_a_hallucinated_instance_is_still_struck_out_under_nim():
    """The guardrail is the verifier, not the provider. Swapping models must not move it."""
    facts = radius()
    agent = StubAgent(
        narration(
            NarratedAction(
                action_type=ActionType.DEACTIVATE_KEY, target=KEY, region=None, reason="leaked"
            ),
            NarratedAction(
                action_type=ActionType.TERMINATE_INSTANCE,
                target=LAUNCHED,
                region="ap-south-1",
                reason="launched by the leaked key",
            ),
            NarratedAction(
                action_type=ActionType.TERMINATE_INSTANCE,
                target=UNOWNED,
                region="ap-south-1",
                reason="the model made this one up",
            ),
        )
    )

    plan = narrate_via_nim(
        facts, repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent
    ).to_proposed_plan()
    result = verify_plan(plan, facts, access_key_id=KEY, repository=REPOSITORY)

    assert len(result.approved) == 2
    assert [rejected.reason for rejected in result.rejected] == [
        RejectionReason.TARGET_NOT_IN_BLAST_RADIUS
    ]
    assert result.rejected[0].action.target == UNOWNED


def test_the_nim_narrator_cannot_reach_the_module_that_destroys_things():
    imported: set[str] = set()
    for node in ast.walk(ast.parse(NIM_MODULE.read_text())):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "containment" not in imported


def test_rehearsal_still_needs_no_key_or_network(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)

    result = narration_for(
        radius(),
        mode=NarratorMode.REHEARSAL,
        repository=REPOSITORY,
        key_owner="demo-leaky-user",
    )

    assert result.actions
