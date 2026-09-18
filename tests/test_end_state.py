"""Post-action verification. A request that was accepted is not a resource that is gone."""

from __future__ import annotations

from datetime import UTC, datetime

from fakes import FakeEc2, FakeIam

from containment.actions import SESSION_REVOCATION_POLICY_NAME
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

# Confirmation retries IAM because it is eventually consistent. Tests assert the outcome,
# not the wall clock, so the pause is handed in as a no-op.
NO_PAUSE = lambda _seconds: None  # noqa: E731


def contained_key_iam(status: str = "Inactive", *, sessions_revoked: bool = True) -> FakeIam:
    """IAM as it looks after a successful deactivation: key inactive, sessions denied."""
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": status}]})
    if sessions_revoked:
        iam.user_policies[(USER, SESSION_REVOCATION_POLICY_NAME)] = "{}"
    return iam


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
    state = confirm_end_state(
        incident(),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=contained_key_iam(),
        ec2_clients={},
        sleep=NO_PAUSE,
    )

    assert state.all_confirmed
    assert state.targets[0].observed_state == "Inactive"


def test_an_inactive_key_whose_sessions_were_not_revoked_is_not_confirmed():
    """Inactive stops new sessions. It does nothing to the ones the attacker already has.

    Those credentials keep working until they expire, so a key that is merely Inactive is
    not containment and must not be reported as though it were.
    """
    state = confirm_end_state(
        incident(),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=contained_key_iam(sessions_revoked=False),
        ec2_clients={},
        sleep=NO_PAUSE,
    )

    assert not state.all_confirmed
    assert state.targets[0].aws_error_code == "SessionsNotRevoked"


def test_confirmation_retries_iam_before_believing_a_key_is_still_active():
    """IAM is eventually consistent, so one stale read must not fail a working containment."""
    iam = contained_key_iam(status="Active")
    reads: list[int] = []

    def flip_to_inactive(_seconds: float) -> None:
        reads.append(1)
        iam.keys_by_user[USER][0]["Status"] = "Inactive"

    state = confirm_end_state(
        incident(),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=iam,
        ec2_clients={},
        sleep=flip_to_inactive,
    )

    assert state.all_confirmed
    assert reads == [1]


def test_a_key_that_is_still_active_is_not_confirmed():
    """This is the case that must never be reported as containment succeeding."""
    state = confirm_end_state(
        incident(),
        [verified(ActionType.DEACTIVATE_KEY, KEY, region=None)],
        iam_client=contained_key_iam(status="Active"),
        ec2_clients={},
        sleep=NO_PAUSE,
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
        iam_client=contained_key_iam(),
        ec2_clients={REGION: FakeEc2({INSTANCE: "running"})},
        sleep=NO_PAUSE,
    )

    assert not state.all_confirmed
    assert [target.confirmed for target in state.targets] == [True, False]


# --- the one place the code used to do what this project says it never does -----------


def test_a_pull_request_nobody_opened_is_not_confirmed():
    """open_pr used to set confirmed = True without looking at anything.

    The PR opener is not built and raises, so containment records a failure -- and the end
    state would have rounded that failure up into a contained incident, which is exactly
    the claim the rest of this system exists to refuse.
    """
    state = confirm_end_state(
        incident(),
        [verified(ActionType.OPEN_PR, "octo/private-demo-repo", region=None)],
        iam_client=contained_key_iam(),
        ec2_clients={},
        containment_details={},
        sleep=NO_PAUSE,
    )

    assert not state.all_confirmed
    assert state.targets[0].aws_error_code == "NoPullRequestRecorded"


def test_a_pull_request_containment_recorded_is_confirmed_by_its_url():
    """There is nothing to re-read from AWS, so the recorded url is the only evidence."""
    url = "https://github.com/octo/private-demo-repo/pull/7"
    state = confirm_end_state(
        incident(),
        [verified(ActionType.OPEN_PR, "octo/private-demo-repo", region=None)],
        iam_client=contained_key_iam(),
        ec2_clients={},
        containment_details={"open_pr:octo/private-demo-repo:-": {"pull_request_url": url}},
        sleep=NO_PAUSE,
    )

    assert state.all_confirmed
    assert state.targets[0].observed_state == url
