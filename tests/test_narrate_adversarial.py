"""What happens when the model proposes something it should not.

Every other narrator test asks whether a well-behaved model is handled correctly. This
file asks the opposite question, which is the one the whole architecture exists to answer:
a model that hallucinates, over-reaches, or is steered by an attacker proposes a plan, and
nothing but deterministic code stands between that plan and a destroyed resource.

The plans here are handed to the real `narrate()` through a stub agent, so they travel the
same path a Bedrock answer would: through the schema, into `to_proposed_plan()`, into the
verifier. Nothing is asserted about the model. Everything is asserted about the code that
does not trust it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from investigate.blast_radius import BlastRadius, CreatedResource, ResourceKind
from narrate.agent import narrate
from narrate.schema import NarratedIncident, NarrationError
from verifier.verify import ActionType, RejectionReason, verify_plan

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
ATTACKER_KEY = "AKIA" + "7QRS4TUVWX9YZ1B2C3"[:16]
SOMEONE_ELSES_KEY = "AKIA" + "ZZZZZZZZZZZZZZZZ"
REPOSITORY = "octo/private-demo-repo"
PRIMARY = "ap-south-1"
SECONDARY = "us-east-1"
LAUNCHED = "i-0a1b2c3d4e5f60001"
PRODUCTION = "i-0deadbeefdeadbeef"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)


class StubAgent:
    """Stands in for the Bedrock agent, returning whatever plan a test wants to try."""

    def __init__(self, narration: NarratedIncident | None, stop_reason: str = "end_turn") -> None:
        self._narration = narration
        self._stop_reason = stop_reason
        self.calls: list[dict[str, Any]] = []

    def __call__(self, prompt: str, **kwargs: Any) -> Any:
        self.calls.append({"prompt": prompt, **kwargs})

        class Result:
            structured_output = self._narration
            stop_reason = self._stop_reason

        return Result()


def created(resource_id: str, kind: ResourceKind, region: str) -> CreatedResource:
    return CreatedResource(
        resource_id=resource_id,
        kind=kind,
        event_name="RunInstances" if kind is ResourceKind.EC2_INSTANCE else "CreateAccessKey",
        region=region,
        event_time=NOW,
        source_ip="203.0.113.10",
        event_id=f"event-{resource_id}",
    )


def radius() -> BlastRadius:
    """What the leaked key actually did: one instance, and one key it minted."""
    return BlastRadius(
        access_key_id=KEY,
        regions_searched=[PRIMARY, SECONDARY],
        window_start=NOW,
        window_end=NOW,
        resources=[
            created(LAUNCHED, ResourceKind.EC2_INSTANCE, PRIMARY),
            created(ATTACKER_KEY, ResourceKind.IAM_ACCESS_KEY, SECONDARY),
        ],
    )


def proposing(*actions: dict[str, Any]) -> StubAgent:
    return StubAgent(
        NarratedIncident(
            summary="A plan, proposed by something we do not trust.",
            actions=[
                {"region": None, "reason": "because I said so", **action}  # type: ignore[list-item]
                for action in actions
            ],
        )
    )


def judged(agent: StubAgent):
    """Run the model's plan the whole way to a verdict, as the workflow would."""
    narration = narrate(radius(), repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent)
    return verify_plan(
        narration.to_proposed_plan(), radius(), access_key_id=KEY, repository=REPOSITORY
    )


def rejections(result) -> list[RejectionReason]:
    return [rejected.reason for rejected in result.rejected]


# --- the model names something that was never there --------------------------------


def test_an_instance_the_key_never_created_is_struck_out():
    """The headline guarantee. A hallucinated id is the easiest way to destroy the wrong box."""
    result = judged(
        proposing(
            {
                "action_type": ActionType.TERMINATE_INSTANCE,
                "target": PRODUCTION,
                "region": PRIMARY,
            }
        )
    )

    assert result.approved == []
    assert rejections(result) == [RejectionReason.TARGET_NOT_IN_BLAST_RADIUS]


def test_the_right_instance_in_the_wrong_region_is_struck_out():
    """An instance id is unique per region, so the same id elsewhere is a different machine."""
    result = judged(
        proposing(
            {
                "action_type": ActionType.TERMINATE_INSTANCE,
                "target": LAUNCHED,
                "region": SECONDARY,
            }
        )
    )

    assert result.approved == []
    assert rejections(result) == [RejectionReason.REGION_MISMATCH]


def test_deactivating_an_unrelated_key_is_struck_out():
    """Someone else's credential. Deactivating it would be an outage we caused."""
    result = judged(
        proposing({"action_type": ActionType.DEACTIVATE_KEY, "target": SOMEONE_ELSES_KEY})
    )

    assert result.approved == []
    assert rejections(result) == [RejectionReason.KEY_MISMATCH]


def test_a_pull_request_against_a_repository_that_did_not_leak_is_struck_out():
    result = judged(
        proposing({"action_type": ActionType.OPEN_PR, "target": "octo/some-other-repo"})
    )

    assert result.approved == []
    assert rejections(result) == [RejectionReason.REPOSITORY_MISMATCH]


# --- the model invents capabilities ------------------------------------------------


def test_an_action_type_killswitch_does_not_have_is_struck_out():
    """The model asking to empty an S3 bucket does not give KILLSWITCH a way to do it."""
    result = judged(proposing({"action_type": "delete_bucket", "target": "customer-backups-prod"}))

    assert result.approved == []
    assert rejections(result) == [RejectionReason.UNKNOWN_ACTION_TYPE]


@pytest.mark.parametrize(
    "target",
    [
        "i-0a1b2c3d4e5f60001; aws ec2 terminate-instances --instance-ids i-0deadbeefdeadbeef",
        "i-0a1b2c3d4e5f60001 OR 1=1",
        "*",
        "../../i-0a1b2c3d4e5f60001",
        "i-0a1b2c3d4e5f6000",
        "I-0A1B2C3D4E5F60001",
    ],
)
def test_a_target_that_is_not_a_well_formed_id_is_struck_out(target: str):
    """The target is matched against a pattern, never interpolated into anything.

    None of these can reach an AWS call, so none of them are injection in the usual sense.
    They are rejected one layer earlier than that, which is the point.
    """
    result = judged(
        proposing(
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": target, "region": PRIMARY}
        )
    )

    assert result.approved == []
    assert rejections(result) == [RejectionReason.MALFORMED_TARGET]


# --- the model over-reaches from something real ------------------------------------


def test_one_good_action_does_not_carry_a_bad_one_through():
    """Plans are judged per action. A valid first action is not a licence for the second."""
    result = judged(
        proposing(
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "region": PRIMARY},
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": PRODUCTION, "region": PRIMARY},
        )
    )

    assert [item.action.target for item in result.approved] == [LAUNCHED]
    assert rejections(result) == [RejectionReason.TARGET_NOT_IN_BLAST_RADIUS]


def test_asking_twice_does_not_get_two_approvals():
    """Repetition is not evidence, and it must not become two buttons for one machine."""
    result = judged(
        proposing(
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "region": PRIMARY},
            {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "region": None},
        )
    )

    assert len(result.approved) == 1
    assert rejections(result) == [RejectionReason.DUPLICATE_ACTION]


def test_an_attacker_minted_key_is_the_one_extra_key_that_may_be_deactivated():
    """The evidence-bound exception, asserted next to the rejections so it stays bound."""
    result = judged(proposing({"action_type": ActionType.DEACTIVATE_KEY, "target": ATTACKER_KEY}))

    assert result.rejected == []
    (approved,) = result.approved
    assert approved.evidence is not None
    assert approved.evidence.event_name == "CreateAccessKey"


# --- the model refuses to answer in the shape it was given -------------------------


def test_a_model_that_replies_in_prose_fails_the_step():
    """No structured output means no plan. There is nothing here to repair."""
    with pytest.raises(NarrationError):
        narrate(radius(), repository=REPOSITORY, key_owner=None, agent=StubAgent(None))


def test_the_model_is_given_one_turn_and_no_tools():
    """Asserted on the call the plan travelled through, not on the constructor."""
    agent = proposing(
        {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "region": PRIMARY}
    )
    judged(agent)

    (call,) = agent.calls
    assert call["limits"] == {"turns": 1}
    assert call["structured_output_model"] is NarratedIncident


def test_the_model_is_shown_the_same_evidence_the_verifier_will_check():
    """So it cannot claim it was shown something else, and neither can we."""
    agent = proposing(
        {"action_type": ActionType.TERMINATE_INSTANCE, "target": LAUNCHED, "region": PRIMARY}
    )
    judged(agent)

    prompt = agent.calls[0]["prompt"]
    assert LAUNCHED in prompt
    assert PRODUCTION not in prompt
