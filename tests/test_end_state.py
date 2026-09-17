"""Post-action verification. A request that was accepted is not a resource that is gone."""

from __future__ import annotations

from datetime import UTC, datetime

from fakes import FakeEc2, FakeIam

from containment.end_state import confirm_end_state
from investigate.blast_radius import CreatedResource, ResourceKind
from shared.models import IncidentRecord, IncidentSource, incident_id_for
from verifier.plan import ProposedAction
from verifier.verify import ActionType, VerifiedAction

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
USER = "demo-leaky-user"
INSTANCE = "i-0a1b2c3d4e5f60001"
REGION = "ap-south-1"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)


def incident(**overrides) -> IncidentRecord:
    fields = {
        "incident_id": incident_id_for(KEY),
        "access_key_id": KEY,
        "source": IncidentSource.GITHUB_PUSH,
        "detected_at": NOW,
        "key_owner": USER,
    }
    fields.update(overrides)
    return IncidentRecord(**fields)


def verified(action_type: str, target: str, region: str | None = REGION) -> VerifiedAction:
    evidence = (
        CreatedResource(
            resource_id=target,
            kind=ResourceKind.EC2_INSTANCE,
            event_name="RunInstances",
            region=region or REGION,
            event_time=NOW,
            source_ip="203.0.113.10",
            event_id="event-1",
        )
        if action_type == ActionType.TERMINATE_INSTANCE
        else None
    )
    return VerifiedAction(
        action=ProposedAction(action_type=action_type, target=target, region=region),
        evidence=evidence,
    )


def test_a_deactivated_key_is_confirmed():
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Inactive"}]})

    state = confirm_end_state(
        incident(),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=iam,
        ec2_clients={},
    )

    assert state.all_confirmed
    assert state.targets[0].observed_state == "Inactive"


def test_a_key_that_is_still_active_is_not_confirmed():
    """This is the case that must never be reported as containment succeeding."""
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Active"}]})

    state = confirm_end_state(
        incident(),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=iam,
        ec2_clients={},
    )

    assert not state.all_confirmed
    assert state.targets[0].confirmed is False
    assert state.targets[0].observed_state == "Active"


def test_a_terminating_instance_is_confirmed():
    state = confirm_end_state(
        incident(),
        [verified(ActionType.TERMINATE_INSTANCE, INSTANCE)],
        iam_client=FakeIam({}),
        ec2_clients={REGION: FakeEc2({INSTANCE: "shutting-down"})},
    )

    assert state.all_confirmed


def test_an_instance_still_running_is_not_confirmed():
    state = confirm_end_state(
        incident(),
        [verified(ActionType.TERMINATE_INSTANCE, INSTANCE)],
        iam_client=FakeIam({}),
        ec2_clients={REGION: FakeEc2({INSTANCE: "running"})},
    )

    assert not state.all_confirmed
    assert state.targets[0].observed_state == "running"


def test_the_instance_is_checked_in_the_region_the_evidence_names():
    """The evidence knows where the instance is; the proposed action may not."""
    state = confirm_end_state(
        incident(),
        [verified(ActionType.TERMINATE_INSTANCE, INSTANCE, region=None)],
        iam_client=FakeIam({}),
        ec2_clients={REGION: FakeEc2({INSTANCE: "terminated"})},
    )

    assert state.all_confirmed


def test_an_aws_error_leaves_the_target_unconfirmed_with_its_code():
    state = confirm_end_state(
        incident(),
        [verified(ActionType.TERMINATE_INSTANCE, INSTANCE)],
        iam_client=FakeIam({}),
        ec2_clients={REGION: FakeEc2({})},
    )

    assert not state.all_confirmed
    assert state.targets[0].aws_error_code == "InvalidInstanceID.NotFound"


def test_a_missing_regional_client_is_reported_rather_than_assumed_fine():
    state = confirm_end_state(
        incident(),
        [verified(ActionType.TERMINATE_INSTANCE, INSTANCE, region="eu-west-1")],
        iam_client=FakeIam({}),
        ec2_clients={},
    )

    assert not state.all_confirmed
    assert state.targets[0].aws_error_code == "NoClientForRegion"


def test_a_key_with_no_known_owner_cannot_be_confirmed():
    state = confirm_end_state(
        incident(key_owner=None),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=FakeIam({}),
        ec2_clients={},
    )

    assert not state.all_confirmed
    assert state.targets[0].aws_error_code == "UnknownKeyOwner"


def test_nothing_acted_on_is_not_the_same_as_everything_confirmed():
    """An empty run must not report a confirmed, contained incident."""
    state = confirm_end_state(incident(), [], iam_client=FakeIam({}), ec2_clients={})

    assert state.all_confirmed is False


def test_mixed_results_are_not_confirmed_overall():
    state = confirm_end_state(
        incident(),
        [
            verified(ActionType.DEACTIVATE_KEY, KEY, region=None),
            verified(ActionType.TERMINATE_INSTANCE, INSTANCE),
        ],
        iam_client=FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Inactive"}]}),
        ec2_clients={REGION: FakeEc2({INSTANCE: "running"})},
    )

    assert not state.all_confirmed
    assert [target.confirmed for target in state.targets] == [True, False]
