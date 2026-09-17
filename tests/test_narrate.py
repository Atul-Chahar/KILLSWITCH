"""The narrator. It is the one component in KILLSWITCH we have decided not to trust.

These tests are about what happens to its output, not about whether it writes well:
the schema it must satisfy, the fact that a schema failure ends the step instead of
being negotiated away, and the fact that it is handed no way to act.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from narrate.agent import MAX_TURNS, build_bedrock_agent, narrate
from narrate.narrator import NarratorMode, narration_for, narrator_mode
from narrate.prompt import SYSTEM_PROMPT, evidence_prompt
from narrate.rehearsal import REHEARSAL_UNOWNED_INSTANCE, rehearsal_narration
from narrate.schema import NarratedAction, NarratedIncident, NarrationError
from pydantic import ValidationError

from investigate.blast_radius import BlastRadius, CreatedResource, ResourceKind
from verifier.plan import ProposedAction
from verifier.verify import ActionType, RejectionReason, verify_plan

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
REPOSITORY = "octo/private-demo-repo"
LAUNCHED = "i-0a1b2c3d4e5f60001"
SECOND_LAUNCHED = "i-0f9e8d7c6b5a40002"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)
NARRATE_DIR = Path(__file__).resolve().parent.parent / "narrate"


def created(resource_id: str, region: str = "ap-south-1") -> CreatedResource:
    return CreatedResource(
        resource_id=resource_id,
        kind=ResourceKind.EC2_INSTANCE,
        event_name="RunInstances",
        region=region,
        event_time=NOW,
        source_ip="203.0.113.10",
        event_id=f"event-{resource_id}",
    )


def radius(*resources: CreatedResource) -> BlastRadius:
    return BlastRadius(
        access_key_id=KEY,
        regions_searched=["ap-south-1", "us-east-1"],
        window_start=NOW,
        window_end=NOW,
        resources=list(resources),
    )


def narration(*actions: NarratedAction) -> NarratedIncident:
    return NarratedIncident(summary="the model's prose", actions=list(actions))


def narrated(action_type: str, target: str, region: str | None = "ap-south-1") -> NarratedAction:
    return NarratedAction(
        action_type=action_type, target=target, region=region, reason="because the model said so"
    )


class StubAgent:
    """Stands in for the Strands agent. Records how it was called and calls nothing."""

    def __init__(self, structured_output: object, stop_reason: str = "end_turn") -> None:
        self._structured_output = structured_output
        self._stop_reason = stop_reason
        self.calls: list[dict[str, object]] = []

    def __call__(self, prompt: str, **kwargs: object) -> SimpleNamespace:
        self.calls.append({"prompt": prompt, **kwargs})
        return SimpleNamespace(
            structured_output=self._structured_output, stop_reason=self._stop_reason
        )


# --- the schema the model must satisfy -----------------------------------------------


def test_a_well_formed_narration_becomes_a_proposed_plan():
    plan = narration(
        narrated(ActionType.DEACTIVATE_KEY, KEY, region=None),
        narrated(ActionType.TERMINATE_INSTANCE, LAUNCHED),
    ).to_proposed_plan()

    assert [action.action_type for action in plan.actions] == [
        ActionType.DEACTIVATE_KEY,
        ActionType.TERMINATE_INSTANCE,
    ]
    assert plan.actions[1].target == LAUNCHED
    assert plan.actions[1].region == "ap-south-1"
    assert plan.summary == "the model's prose"


def test_the_narrator_may_only_emit_fields_the_verifier_already_understands():
    """Drift between the two shapes would mean the verifier judging a plan it misread."""
    assert set(NarratedAction.model_fields) == set(ProposedAction.model_fields)


def test_a_field_the_model_invented_is_rejected():
    with pytest.raises(ValidationError):
        NarratedAction.model_validate(
            {
                "action_type": ActionType.TERMINATE_INSTANCE,
                "target": LAUNCHED,
                "region": "ap-south-1",
                "reason": "because",
                "urgency": "critical",
            }
        )


def test_an_action_with_no_reason_is_rejected_because_a_human_has_to_read_one():
    with pytest.raises(ValidationError):
        NarratedAction.model_validate(
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "region": None}
        )


def test_a_blank_reason_is_rejected_too():
    with pytest.raises(ValidationError):
        NarratedAction.model_validate(
            {
                "action_type": ActionType.TERMINATE_INSTANCE,
                "target": LAUNCHED,
                "region": None,
                "reason": "   ",
            }
        )


def test_an_omitted_region_is_rejected_so_the_model_has_to_say_it_means_none():
    """A forgotten region and a deliberate null are different claims about an instance."""
    with pytest.raises(ValidationError):
        NarratedAction.model_validate(
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "reason": "because"}
        )


def test_an_empty_summary_is_rejected():
    with pytest.raises(ValidationError):
        NarratedIncident.model_validate({"summary": "", "actions": []})


def test_an_omitted_actions_list_is_rejected():
    """Proposing nothing must be stated, not left out. Omission is the attack we fear most."""
    with pytest.raises(ValidationError):
        NarratedIncident.model_validate({"summary": "nothing to do here"})


def test_an_explicitly_empty_plan_is_accepted_and_carries_no_actions():
    parsed = NarratedIncident.model_validate({"summary": "nothing to do", "actions": []})

    assert parsed.actions == []


# --- one shot, no negotiating with the validator --------------------------------------


def test_the_model_gets_exactly_one_turn_so_it_cannot_talk_its_way_past_the_schema():
    """Strands returns a schema failure to the model and lets it retry. We do not."""
    agent = StubAgent(narration())

    narrate(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)

    assert MAX_TURNS == 1
    assert agent.calls[0]["limits"] == {"turns": 1}


def test_the_narrator_is_asked_for_our_schema_and_not_for_free_text():
    agent = StubAgent(narration())

    narrate(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)

    assert agent.calls[0]["structured_output_model"] is NarratedIncident


def test_output_that_never_validated_fails_the_step():
    agent = StubAgent(None, stop_reason="limit_turns")

    with pytest.raises(NarrationError) as raised:
        narrate(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)

    assert "limit_turns" in str(raised.value)


def test_output_of_the_wrong_type_fails_the_step_rather_than_being_coerced():
    agent = StubAgent(ProposedAction(action_type="terminate_instance", target=LAUNCHED))

    with pytest.raises(NarrationError):
        narrate(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)


def test_a_missing_model_id_is_an_error_rather_than_a_silent_default(monkeypatch):
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

    with pytest.raises(NarrationError):
        build_bedrock_agent()


def test_the_model_id_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("BEDROCK_MODEL_ID", "test.model.v1")
    monkeypatch.setenv("AWS_REGION", "ap-south-1")

    agent = build_bedrock_agent()

    assert agent.model.config["model_id"] == "test.model.v1"


def test_the_narrator_is_built_with_no_tools_at_all(monkeypatch):
    """It proposes. It cannot act, because it is handed nothing that acts."""
    monkeypatch.setenv("BEDROCK_MODEL_ID", "test.model.v1")

    assert build_bedrock_agent().tool_names == []


def test_the_narrator_does_not_stream_so_one_iam_action_covers_it(monkeypatch):
    """Streaming would need bedrock:InvokeModelWithResponseStream on top of InvokeModel."""
    monkeypatch.setenv("BEDROCK_MODEL_ID", "test.model.v1")

    assert build_bedrock_agent().model.config["streaming"] is False


def test_nothing_in_narrate_can_reach_the_module_that_destroys_things():
    imported: set[str] = set()
    for path in NARRATE_DIR.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

    assert "containment" not in imported


# --- the prompt carries evidence, not conclusions -------------------------------------


def test_the_prompt_carries_every_resource_cloudtrail_recorded():
    prompt = evidence_prompt(
        radius(created(LAUNCHED), created(SECOND_LAUNCHED, "us-east-1")),
        repository=REPOSITORY,
        key_owner="demo-leaky-user",
    )

    assert LAUNCHED in prompt
    assert SECOND_LAUNCHED in prompt
    assert KEY in prompt
    assert REPOSITORY in prompt
    assert "demo-leaky-user" in prompt


def test_the_prompt_says_plainly_that_nothing_outside_the_evidence_exists():
    prompt = evidence_prompt(radius(), repository=None, key_owner=None)

    assert "no repository" in prompt.lower()
    assert "unknown" in prompt.lower()


def test_the_system_prompt_tells_the_model_it_cannot_act():
    lowered = SYSTEM_PROMPT.lower()

    assert "propose" in lowered
    assert "verifier" in lowered


# --- the rehearsal narrator, which exists to show the guardrail working ----------------


def test_the_rehearsal_plan_proposes_one_thing_the_verifier_strikes_out():
    facts = radius(created(LAUNCHED), created(SECOND_LAUNCHED, "us-east-1"))

    result = verify_plan(
        rehearsal_narration(facts).to_proposed_plan(),
        facts,
        access_key_id=KEY,
        repository=REPOSITORY,
    )

    assert [rejected.reason for rejected in result.rejected] == [
        RejectionReason.TARGET_NOT_IN_BLAST_RADIUS
    ]
    assert result.rejected[0].action.target == REHEARSAL_UNOWNED_INSTANCE


def test_the_rehearsal_plan_still_contains_the_real_containment():
    facts = radius(created(LAUNCHED), created(SECOND_LAUNCHED, "us-east-1"))

    result = verify_plan(
        rehearsal_narration(facts).to_proposed_plan(),
        facts,
        access_key_id=KEY,
        repository=REPOSITORY,
    )
    approved = {(item.action.action_type, item.action.target) for item in result.approved}

    assert approved == {
        (ActionType.DEACTIVATE_KEY, KEY),
        (ActionType.TERMINATE_INSTANCE, LAUNCHED),
        (ActionType.TERMINATE_INSTANCE, SECOND_LAUNCHED),
    }


def test_the_rehearsal_plan_never_proposes_a_pull_request():
    """containment.open_pull_request works, but the opener it calls is not built."""
    facts = radius(created(LAUNCHED))

    types = {action.action_type for action in rehearsal_narration(facts).actions}

    assert ActionType.OPEN_PR not in types


def test_the_rehearsal_summary_says_it_was_not_written_by_the_model():
    """On camera this prose sits in a block labelled 'written by the model'. It was not."""
    summary = rehearsal_narration(radius(created(LAUNCHED))).summary.lower()

    assert "rehearsal" in summary
    assert "not written by the model" in summary


def test_the_rehearsal_narrator_refuses_if_its_unowned_instance_turns_out_to_be_owned():
    facts = radius(created(REHEARSAL_UNOWNED_INSTANCE))

    with pytest.raises(NarrationError):
        rehearsal_narration(facts)


# --- choosing a narrator --------------------------------------------------------------


def test_the_default_narrator_is_the_model():
    assert narrator_mode(None) is NarratorMode.BEDROCK
    assert narrator_mode("") is NarratorMode.BEDROCK


def test_an_unrecognised_narrator_mode_is_an_error_not_a_silent_fallback():
    with pytest.raises(NarrationError):
        narrator_mode("whatever-is-cheapest")


def test_rehearsal_mode_never_reaches_bedrock(monkeypatch):
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "unused-by-this-path")

    result = narration_for(
        radius(created(LAUNCHED)),
        mode=NarratorMode.REHEARSAL,
        repository=REPOSITORY,
        key_owner="demo-leaky-user",
    )

    assert result.actions


# --- the workflow step ----------------------------------------------------------------


def test_the_narrate_task_emits_a_plan_a_summary_and_the_narrator_that_wrote_them(monkeypatch):
    from workflow import tasks

    monkeypatch.setenv("NARRATOR_MODE", NarratorMode.REHEARSAL.value)
    event = {
        "incident_id": f"inc-{KEY}",
        "access_key_id": KEY,
        "repository": REPOSITORY,
        "key_owner": "demo-leaky-user",
        "blast_radius": radius(created(LAUNCHED)).model_dump(mode="json"),
    }

    result = tasks.narrate_task(event)

    assert result["narrator"] == NarratorMode.REHEARSAL.value
    assert result["summary"]
    assert result["plan"]["actions"]
    assert result["blast_radius"] == event["blast_radius"]


def test_the_narrate_task_calls_no_aws_service_when_it_is_rehearsing(monkeypatch):
    """Rehearsal is for the days there is no account. It must not need one."""
    import boto3

    from workflow import tasks

    monkeypatch.setenv("NARRATOR_MODE", NarratorMode.REHEARSAL.value)
    monkeypatch.setattr(
        boto3, "client", lambda *args, **kwargs: pytest.fail("the narrator called AWS")
    )
    monkeypatch.setattr(
        boto3, "resource", lambda *args, **kwargs: pytest.fail("the narrator called AWS")
    )

    tasks.narrate_task(
        {
            "incident_id": f"inc-{KEY}",
            "access_key_id": KEY,
            "repository": REPOSITORY,
            "key_owner": "demo-leaky-user",
            "blast_radius": radius(created(LAUNCHED)).model_dump(mode="json"),
        }
    )


def test_a_bad_narrator_mode_stops_the_workflow_step(monkeypatch):
    from workflow import tasks

    monkeypatch.setenv("NARRATOR_MODE", "make-something-up")

    with pytest.raises(NarrationError):
        tasks.narrate_task({"blast_radius": radius().model_dump(mode="json")})
