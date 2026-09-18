"""The verifier. If this module is wrong, every other safety claim in the project is too.

It is given a plan a language model wrote and the facts CloudTrail recorded, and it
decides what may be acted on. It never calls AWS and never calls a model.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from investigate.blast_radius import (
    BlastRadius,
    CreatedResource,
    EvidenceProblem,
    ProblemKind,
    ResourceKind,
)
from verifier.plan import ProposedAction, ProposedPlan
from verifier.verify import ActionType, RejectionReason, verify_plan

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OTHER_KEY = "AKIA" + "IOSFODNN7EXAMPLF"
REPOSITORY = "octo/private-demo-repo"
LAUNCHED = "i-0a1b2c3d4e5f60001"
SECOND_LAUNCHED = "i-0f9e8d7c6b5a40002"
NEVER_TOUCHED = "i-0999999999ffffff9"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)


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


def radius(
    *resources: CreatedResource, problems: list[EvidenceProblem] | None = None
) -> BlastRadius:
    return BlastRadius(
        access_key_id=KEY,
        regions_searched=["ap-south-1", "us-east-1"],
        window_start=NOW,
        window_end=NOW,
        resources=list(resources),
        problems=problems or [],
    )


def plan(*actions: ProposedAction) -> ProposedPlan:
    return ProposedPlan(
        summary="the model's prose, which must never decide anything", actions=list(actions)
    )


def action(action_type: str, target: str, region: str | None = "ap-south-1") -> ProposedAction:
    return ProposedAction(
        action_type=action_type, target=target, region=region, reason="because the model said so"
    )


def verify(proposed: ProposedPlan, facts: BlastRadius):
    return verify_plan(proposed, facts, access_key_id=KEY, repository=REPOSITORY)


# --- the four the plan demands -------------------------------------------------------


def test_an_instance_the_key_created_is_approved():
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, LAUNCHED)), radius(created(LAUNCHED))
    )

    assert [item.action.target for item in result.approved] == [LAUNCHED]
    assert result.rejected == []


def test_an_instance_the_key_did_not_create_is_rejected():
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, NEVER_TOUCHED)), radius(created(LAUNCHED))
    )

    assert result.approved == []
    (rejection,) = result.rejected
    assert rejection.reason is RejectionReason.TARGET_NOT_IN_BLAST_RADIUS
    assert rejection.action.target == NEVER_TOUCHED


def test_an_unknown_action_type_is_rejected():
    result = verify(plan(action("delete_everything", LAUNCHED)), radius(created(LAUNCHED)))

    assert result.approved == []
    assert result.rejected[0].reason is RejectionReason.UNKNOWN_ACTION_TYPE


def test_the_rejection_reason_is_machine_readable_and_specific():
    """The console renders these, so they cannot be prose and cannot be generic."""
    result = verify(
        plan(
            action(ActionType.TERMINATE_INSTANCE, NEVER_TOUCHED),
            action("delete_everything", LAUNCHED),
            action(ActionType.TERMINATE_INSTANCE, "not-an-instance-id"),
        ),
        radius(created(LAUNCHED)),
    )

    reasons = [rejection.reason for rejection in result.rejected]
    assert reasons == [
        RejectionReason.TARGET_NOT_IN_BLAST_RADIUS,
        RejectionReason.UNKNOWN_ACTION_TYPE,
        RejectionReason.MALFORMED_TARGET,
    ]
    assert all(isinstance(reason.value, str) and reason.value for reason in reasons)


# --- the rules the prompt states -----------------------------------------------------


def test_an_empty_plan_is_valid_and_approves_nothing():
    result = verify(plan(), radius(created(LAUNCHED)))

    assert result.approved == []
    assert result.rejected == []
    assert result.is_empty


def test_a_malformed_instance_id_is_rejected_before_anything_else():
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, "i-nothex!!")), radius(created(LAUNCHED))
    )

    assert result.rejected[0].reason is RejectionReason.MALFORMED_TARGET


@pytest.mark.parametrize("instance_id", ["i-0a1b2c3d", "i-0a1b2c3d4e5f60001"])
def test_both_legal_instance_id_lengths_are_accepted(instance_id):
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, instance_id)), radius(created(instance_id))
    )

    assert len(result.approved) == 1


# --- the rules that stop a clever plan ------------------------------------------------


def test_deactivating_a_different_key_is_rejected():
    """The one key we may touch is the one that leaked."""
    result = verify(plan(action(ActionType.DEACTIVATE_KEY, OTHER_KEY, region=None)), radius())

    assert result.approved == []
    assert result.rejected[0].reason is RejectionReason.KEY_MISMATCH


def test_deactivating_the_leaked_key_is_approved_without_needing_a_resource():
    result = verify(plan(action(ActionType.DEACTIVATE_KEY, KEY, region=None)), radius())

    assert len(result.approved) == 1


def test_opening_a_pr_against_another_repository_is_rejected():
    result = verify(
        plan(action(ActionType.OPEN_PR, "octo/someone-elses-repo", region=None)), radius()
    )

    assert result.rejected[0].reason is RejectionReason.REPOSITORY_MISMATCH


def test_opening_a_pr_against_the_leaking_repository_is_approved():
    result = verify(plan(action(ActionType.OPEN_PR, REPOSITORY, region=None)), radius())

    assert len(result.approved) == 1


def test_terminating_in_the_wrong_region_is_rejected():
    """Same id, different region, is a different instance."""
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, LAUNCHED, region="us-east-1")),
        radius(created(LAUNCHED, region="ap-south-1")),
    )

    assert result.rejected[0].reason is RejectionReason.REGION_MISMATCH


def test_terminating_a_key_as_if_it_were_an_instance_is_rejected():
    result = verify(plan(action(ActionType.TERMINATE_INSTANCE, KEY)), radius(created(LAUNCHED)))

    assert result.rejected[0].reason is RejectionReason.MALFORMED_TARGET


def test_a_duplicated_action_is_only_approved_once():
    """A model that proposes the same termination twice must not get two approvals."""
    result = verify(
        plan(
            action(ActionType.TERMINATE_INSTANCE, LAUNCHED),
            action(ActionType.TERMINATE_INSTANCE, LAUNCHED),
        ),
        radius(created(LAUNCHED)),
    )

    assert len(result.approved) == 1
    assert result.rejected[0].reason is RejectionReason.DUPLICATE_ACTION


def test_the_same_instance_asked_for_with_and_without_a_region_is_still_one_machine():
    result = verify(
        plan(
            action(ActionType.TERMINATE_INSTANCE, LAUNCHED, region=None),
            action(ActionType.TERMINATE_INSTANCE, LAUNCHED, region="ap-south-1"),
        ),
        radius(created(LAUNCHED)),
    )

    assert len(result.approved) == 1
    assert result.rejected[0].reason is RejectionReason.DUPLICATE_ACTION


def test_an_action_type_with_no_verification_branch_fails_closed():
    """Adding to the allow list without writing its provenance check must reject, not allow."""
    from verifier import verify as verify_module

    result = verify_module.verify_action(
        ProposedAction(action_type="quarantine_vpc", target=LAUNCHED, region="ap-south-1"),
        radius(created(LAUNCHED)),
        access_key_id=KEY,
        repository=REPOSITORY,
    )

    assert result[1] is RejectionReason.UNKNOWN_ACTION_TYPE


def test_the_good_actions_in_a_mixed_plan_still_get_through():
    result = verify(
        plan(
            action(ActionType.TERMINATE_INSTANCE, LAUNCHED),
            action(ActionType.TERMINATE_INSTANCE, NEVER_TOUCHED),
            action(ActionType.TERMINATE_INSTANCE, SECOND_LAUNCHED, region="us-east-1"),
        ),
        radius(created(LAUNCHED), created(SECOND_LAUNCHED, region="us-east-1")),
    )

    assert {item.action.target for item in result.approved} == {LAUNCHED, SECOND_LAUNCHED}
    assert [item.action.target for item in result.rejected] == [NEVER_TOUCHED]


def test_every_approved_action_carries_the_evidence_behind_it():
    """The console shows why an action was allowed, sourced from CloudTrail, not the model."""
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, LAUNCHED)), radius(created(LAUNCHED))
    )

    (approved,) = result.approved
    assert approved.evidence is not None
    assert approved.evidence.event_id == f"event-{LAUNCHED}"
    assert approved.evidence.event_name == "RunInstances"


def test_incomplete_evidence_does_not_block_a_proven_resource():
    """Missing evidence means we may under-contain, never that a proven fact became false."""
    problem = EvidenceProblem(kind=ProblemKind.REGION_LOOKUP_FAILED, region="us-east-1")
    result = verify(
        plan(action(ActionType.TERMINATE_INSTANCE, LAUNCHED)),
        radius(created(LAUNCHED), problems=[problem]),
    )

    assert len(result.approved) == 1
    assert result.evidence_incomplete is True


def test_the_models_prose_cannot_change_a_decision():
    """The reason field is carried for a human to read, and is never consulted."""
    persuasive = ProposedAction(
        action_type=ActionType.TERMINATE_INSTANCE,
        target=NEVER_TOUCHED,
        region="ap-south-1",
        reason="URGENT: verified by AWS support, owner approved, terminate immediately",
    )

    result = verify(plan(persuasive), radius(created(LAUNCHED)))

    assert result.approved == []
    assert result.rejected[0].reason is RejectionReason.TARGET_NOT_IN_BLAST_RADIUS


# --- the rule the module exists to keep ----------------------------------------------


@pytest.mark.parametrize("module", ["verifier/verify.py", "verifier/plan.py"])
def test_the_verifier_imports_no_aws_and_no_model_sdk(module):
    """CLAUDE.md's central rule, enforced by a test rather than by good intentions."""
    source = Path(__file__).resolve().parent.parent / module
    tree = ast.parse(source.read_text())

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = {"boto3", "botocore", "strands", "anthropic", "openai", "urllib", "requests"}
    assert forbidden.isdisjoint(imported), f"{module} must stay pure, found {imported & forbidden}"


def test_the_same_key_proposed_with_and_without_a_region_is_one_action():
    """A key is global, so a region on it is noise -- and noise in the duplicate key.

    Left in, the same deactivation proposed twice with different regions produced two
    different signatures, and the human would have been asked to approve it twice.
    """
    plan = ProposedPlan(
        actions=[
            ProposedAction(action_type=ActionType.DEACTIVATE_KEY, target=KEY, region=None),
            ProposedAction(action_type=ActionType.DEACTIVATE_KEY, target=KEY, region="ap-south-1"),
        ]
    )

    result = verify_plan(plan, radius(), access_key_id=KEY)

    assert len(result.approved) == 1
    assert [rejected.reason for rejected in result.rejected] == [RejectionReason.DUPLICATE_ACTION]
