"""The whole workflow, from blast radius to confirmed end state, against fakes.

Every other test here checks one module. This one checks that the modules fit together:
that what `narrate_task` emits is what `verify_task` reads, that an approval recorded
through the console's API is the one `contain_task` re-checks, and that a denial survives
all the way to the end state.

Nothing in here touches AWS. Every client is a fake from `tests/fakes.py` and the narrator
is the deterministic rehearsal one, so the assertions are about wiring, not about a model.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fakes import FakeCloudTrail, FakeEc2, FakeIam, FakeTable

from investigate.blast_radius import BlastRadius, CreatedResource, ResourceKind
from narrate.narrator import NarratorMode
from narrate.rehearsal import REHEARSAL_UNOWNED_INSTANCE
from shared.approvals import ApprovalState, AuditStage, action_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord, IncidentSource, IncidentStatus, incident_id_for
from verifier.verify import ActionType, RejectionReason
from workflow import approval_api, tasks

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
USER = "demo-leaky-user"
REPOSITORY = "octo/private-demo-repo"
PRIMARY = "ap-south-1"
SECONDARY = "us-east-1"
LAUNCHED = "i-0a1b2c3d4e5f60001"
SECOND_LAUNCHED = "i-0f9e8d7c6b5a40002"
TOKEN = "task-token-from-step-functions"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)
INCIDENT_ID = incident_id_for(KEY)


def run_instances_record(instance_id: str, region: str) -> dict:
    """A CloudTrail LookupEvents record, the shape investigate/ parses."""
    return {
        "EventId": f"event-{instance_id}",
        "EventName": "RunInstances",
        "EventTime": NOW,
        "CloudTrailEvent": json.dumps(
            {
                "awsRegion": region,
                "sourceIPAddress": "203.0.113.10",
                "responseElements": {"instancesSet": {"items": [{"instanceId": instance_id}]}},
            }
        ),
    }


def created(resource_id: str, region: str) -> CreatedResource:
    return CreatedResource(
        resource_id=resource_id,
        kind=ResourceKind.EC2_INSTANCE,
        event_name="RunInstances",
        region=region,
        event_time=NOW,
        source_ip="203.0.113.10",
        event_id=f"event-{resource_id}",
    )


def blast_radius() -> BlastRadius:
    return BlastRadius(
        access_key_id=KEY,
        regions_searched=[PRIMARY, SECONDARY],
        window_start=NOW,
        window_end=NOW,
        resources=[created(LAUNCHED, PRIMARY), created(SECOND_LAUNCHED, SECONDARY)],
    )


class World:
    """Every AWS service the workflow talks to, in memory."""

    def __init__(self) -> None:
        self.table = FakeTable()
        self.store = IncidentStore(self.table)
        self.iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Active"}]})
        self.ec2 = {
            PRIMARY: FakeEc2({LAUNCHED: "running"}),
            SECONDARY: FakeEc2({SECOND_LAUNCHED: "running"}),
        }
        self.cloudtrail = {
            PRIMARY: FakeCloudTrail([run_instances_record(LAUNCHED, PRIMARY)]),
            SECONDARY: FakeCloudTrail([run_instances_record(SECOND_LAUNCHED, SECONDARY)]),
        }

    def client(self, name: str, region_name: str | None = None, **_: object) -> object:
        if name == "iam":
            return self.iam
        if name == "ec2":
            return self.ec2[str(region_name)]
        if name == "cloudtrail":
            return self.cloudtrail[str(region_name)]
        raise AssertionError(f"the workflow asked for an unexpected client: {name}")

    def session(self) -> object:
        return SimpleNamespace(client=self.client)

    def resource(self, name: str, **_: object) -> object:
        assert name == "dynamodb"
        return SimpleNamespace(Table=lambda _name: self.table)


@pytest.fixture
def world(monkeypatch) -> World:
    built = World()
    monkeypatch.setenv("INCIDENT_TABLE_NAME", "killswitch-incidents")
    monkeypatch.setenv("AWS_REGION", PRIMARY)
    monkeypatch.setenv("AWS_SECONDARY_REGION", SECONDARY)
    monkeypatch.setenv("NARRATOR_MODE", NarratorMode.REHEARSAL.value)
    monkeypatch.delenv("VERIFIED_PERMISSIONS_POLICY_STORE_ID", raising=False)
    for module in (tasks, approval_api):
        monkeypatch.setattr(module.boto3, "client", built.client)
        monkeypatch.setattr(module.boto3, "resource", built.resource)
    monkeypatch.setattr(tasks.boto3, "Session", built.session)

    built.store.create_if_absent(
        IncidentRecord(
            incident_id=INCIDENT_ID,
            access_key_id=KEY,
            source=IncidentSource.GITHUB_PUSH,
            detected_at=NOW,
            repository=REPOSITORY,
            key_owner=USER,
        )
    )
    return built


def investigated() -> dict:
    """What investigate_task hands on. Built here so the chain needs no CloudTrail."""
    return {
        "incident_id": INCIDENT_ID,
        "access_key_id": KEY,
        "repository": REPOSITORY,
        "key_owner": USER,
        "status": IncidentStatus.INVESTIGATING.value,
        "blast_radius": blast_radius().model_dump(mode="json"),
    }


def up_to_approval(world: World) -> dict:
    state = tasks.narrate_task(investigated())
    state = tasks.verify_task(state)
    state = tasks.authorize_task(state)
    tasks.request_approval_task({**state, "task_token": TOKEN})
    return state


def submit(world: World, decisions: dict[str, ApprovalState]) -> None:
    """Answer through the console's own API, not by writing rows behind its back."""
    sent: list[str] = []
    approval_api.lambda_handler(
        {
            "httpMethod": "POST",
            "pathParameters": {"incident_id": INCIDENT_ID},
            "requestContext": {"authorizer": {"claims": {"email": "operator@example.com"}}},
            "body": (
                '{"decisions": ['
                + ", ".join(
                    f'{{"action_signature": "{signature}", "state": "{state.value}"}}'
                    for signature, state in decisions.items()
                )
                + "]}"
            ),
        },
        store=world.store,
        step_functions=SimpleNamespace(
            send_task_success=lambda **kwargs: sent.append(kwargs["taskToken"])
        ),
    )
    assert sent == [TOKEN], "the console must release exactly the token it was waiting on"


def signatures(state: dict) -> dict[str, str]:
    """Keyed by target, the way an operator thinks about the screen."""
    return {
        item["action"]["target"]: action_signature(
            item["action"]["action_type"], item["action"]["target"], item["action"]["region"]
        )
        for item in state["verification"]["approved"]
    }


def test_the_verifier_strikes_the_unowned_instance_before_a_human_sees_a_button(world):
    state = up_to_approval(world)

    rejected = state["verification"]["rejected"]
    assert [item["action"]["target"] for item in rejected] == [REHEARSAL_UNOWNED_INSTANCE]
    assert rejected[0]["reason"] == RejectionReason.TARGET_NOT_IN_BLAST_RADIUS
    assert REHEARSAL_UNOWNED_INSTANCE not in signatures(state)


def test_the_console_can_read_everything_it_has_to_render(world):
    """The artifacts live in execution state; the console only sees DynamoDB."""
    up_to_approval(world)

    view = approval_api.incident_view(world.store, INCIDENT_ID)

    assert view is not None
    assert view["status"] == IncidentStatus.AWAITING_APPROVAL.value
    assert view["narrator"] == NarratorMode.REHEARSAL.value
    assert view["summary"]
    assert view["blast_radius"]["resources"]
    assert view["verification"]["rejected"]
    assert {tier["action_type"] for tier in view["tiers"]} == {
        ActionType.DEACTIVATE_KEY,
        ActionType.TERMINATE_INSTANCE,
    }


def test_every_destructive_action_is_tiered_to_a_human(world):
    state = up_to_approval(world)

    assert state["needs_human"] is True
    assert all(tier["tier"] == "human" for tier in state["tiers"])


def test_an_approved_action_runs_and_a_denied_one_leaves_its_target_alone(world):
    state = up_to_approval(world)
    by_target = signatures(state)

    submit(
        world,
        {
            by_target[KEY]: ApprovalState.APPROVED,
            by_target[LAUNCHED]: ApprovalState.APPROVED,
            by_target[SECOND_LAUNCHED]: ApprovalState.DENIED,
        },
    )
    contained = tasks.contain_task(state)

    assert world.iam.keys_by_user[USER][0]["Status"] == "Inactive"
    assert world.ec2[PRIMARY].instances[LAUNCHED] == "shutting-down"
    assert world.ec2[SECONDARY].terminate_calls == []
    assert world.ec2[SECONDARY].instances[SECOND_LAUNCHED] == "running"
    assert sum(1 for result in contained["containment"] if result.get("refused")) == 1


def test_a_denial_is_reported_as_declined_and_never_as_contained(world):
    """A denied action is a human decision, not a failure and not a containment.

    The end state describes what KILLSWITCH did, so the denied instance is absent from it
    rather than sitting there unconfirmed: re-reading a target nobody touched and calling
    the result a failure punishes the operator for using the gate.
    """
    state = up_to_approval(world)
    by_target = signatures(state)

    submit(
        world,
        {
            by_target[KEY]: ApprovalState.APPROVED,
            by_target[LAUNCHED]: ApprovalState.APPROVED,
            by_target[SECOND_LAUNCHED]: ApprovalState.DENIED,
        },
    )
    final = tasks.confirm_task(tasks.contain_task(state))

    assert final["status"] == IncidentStatus.DECLINED.value
    observed = {target["target"]: target["confirmed"] for target in final["end_state"]["targets"]}
    assert observed == {KEY: True, LAUNCHED: True}
    # Still running, on purpose, and the status does not pretend otherwise.
    assert world.ec2[SECONDARY].instances[SECOND_LAUNCHED] == "running"


def test_an_action_that_ran_but_would_not_confirm_still_fails_the_execution(world):
    """The guarantee that matters: denial is not a failure, but an unconfirmed action is."""
    state = up_to_approval(world)
    submit(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    contained = tasks.contain_task(state)

    # AWS says the instance came back up between containment and confirmation.
    world.ec2[SECONDARY].instances[SECOND_LAUNCHED] = "running"
    final = tasks.confirm_task(contained)

    assert final["confirmed"] is False
    assert final["status"] == IncidentStatus.FAILED.value


def test_approving_everything_reaches_a_confirmed_contained_end_state(world):
    state = up_to_approval(world)
    submit(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})

    final = tasks.confirm_task(tasks.contain_task(state))

    assert final["confirmed"] is True
    assert final["status"] == IncidentStatus.CONTAINED.value
    assert world.ec2[SECONDARY].instances[SECOND_LAUNCHED] == "shutting-down"


def test_containment_refuses_outright_when_nobody_answered(world):
    """No decisions recorded at all. Every action must refuse, and say so in the audit."""
    state = up_to_approval(world)

    contained = tasks.contain_task(state)

    assert all(result.get("refused") for result in contained["containment"])
    assert world.iam.update_calls == []
    assert world.ec2[PRIMARY].terminate_calls == []
    stages = {entry.stage for entry in world.store.audit_trail(INCIDENT_ID)}
    assert stages == {AuditStage.REFUSED}


def test_the_audit_trail_records_every_action_before_and_after_it_happened(world):
    state = up_to_approval(world)
    submit(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    tasks.contain_task(state)

    trail = world.store.audit_trail(INCIDENT_ID)
    before = [entry for entry in trail if entry.stage is AuditStage.BEFORE]
    after = [entry for entry in trail if entry.stage is AuditStage.AFTER]

    assert len(before) == 3
    assert len(after) == 3
    assert [entry.sk for entry in trail] == sorted(entry.sk for entry in trail)


def test_a_push_incident_learns_its_key_owner_and_can_still_deactivate_the_key(world):
    """The GitHub trigger never knows the owning user. Only investigation can find it.

    If that answer lives only in the execution state, contain_task re-reads an incident
    with no owner and refuses to deactivate the key, which is the headline action.
    """
    world.table.items[(INCIDENT_ID, "incident")].pop("key_owner")

    state = tasks.investigate_task({"incident_id": INCIDENT_ID})
    state = tasks.narrate_task(state)
    state = tasks.verify_task(state)
    state = tasks.authorize_task(state)
    tasks.request_approval_task({**state, "task_token": TOKEN})
    submit(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    final = tasks.confirm_task(tasks.contain_task(state))

    assert world.store.get(INCIDENT_ID).key_owner == USER
    assert world.iam.keys_by_user[USER][0]["Status"] == "Inactive"
    assert final["confirmed"] is True
    assert final["status"] == IncidentStatus.CONTAINED.value


def test_investigation_rebuilds_the_same_blast_radius_the_rest_of_the_chain_expects(world):
    state = tasks.investigate_task({"incident_id": INCIDENT_ID})

    found = {
        (resource["resource_id"], resource["region"])
        for resource in state["blast_radius"]["resources"]
    }
    assert found == {(LAUNCHED, PRIMARY), (SECOND_LAUNCHED, SECONDARY)}
    assert state["blast_radius"]["problems"] == []


def test_the_console_can_see_the_confirmed_end_state_after_containment(world):
    """confirm_task's answer has to reach DynamoDB. The console cannot read execution state."""
    state = up_to_approval(world)
    submit(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    tasks.confirm_task(tasks.contain_task(state))

    view = approval_api.incident_view(world.store, INCIDENT_ID)

    assert view is not None
    assert view["status"] == IncidentStatus.CONTAINED.value
    assert view["end_state"] is not None
    assert {target["target"] for target in view["end_state"]["targets"]} == {
        KEY,
        LAUNCHED,
        SECOND_LAUNCHED,
    }
    assert all(target["confirmed"] for target in view["end_state"]["targets"])


def test_an_incident_that_ended_unconfirmed_says_so_on_the_screen(world):
    """The one status that must never be rounded up, as the console will read it."""
    state = up_to_approval(world)
    submit(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    contained = tasks.contain_task(state)
    world.ec2[SECONDARY].instances[SECOND_LAUNCHED] = "running"
    tasks.confirm_task(contained)

    view = approval_api.incident_view(world.store, INCIDENT_ID)

    assert view is not None
    assert view["status"] == IncidentStatus.FAILED.value
    unconfirmed = [t for t in view["end_state"]["targets"] if not t["confirmed"]]
    assert [t["target"] for t in unconfirmed] == [SECOND_LAUNCHED]


# --- CloudTrail does not answer immediately -------------------------------------------
#
# The demo detects a leak seconds after the push. CloudTrail delivers management events
# minutes after the call. So the first lookup finding nothing is the expected case, and
# the dangerous part is that it is indistinguishable from a key that created nothing.


def test_an_empty_first_lookup_is_not_treated_as_a_finished_search(world):
    """Nothing found yet. The workflow must come back rather than narrate an empty plan."""
    world.cloudtrail[PRIMARY].records = []
    world.cloudtrail[SECONDARY].records = []

    state = tasks.investigate_task({"incident_id": INCIDENT_ID})

    assert state["evidence_settled"] is False
    assert state["evidence_attempt"] == 1
    assert state["blast_radius"]["resources"] == []


def test_evidence_that_arrives_late_still_settles_the_search(world):
    """CloudTrail catching up is the normal path, not an edge case."""
    world.cloudtrail[PRIMARY].records = []
    world.cloudtrail[SECONDARY].records = []
    first = tasks.investigate_task({"incident_id": INCIDENT_ID})

    world.cloudtrail[PRIMARY].records = [run_instances_record(LAUNCHED, PRIMARY)]
    second = tasks.investigate_task({"incident_id": INCIDENT_ID, **first})

    assert second["evidence_attempt"] == 2
    assert second["evidence_settled"] is True
    assert [r["resource_id"] for r in second["blast_radius"]["resources"]] == [LAUNCHED]


def test_giving_up_empty_handed_is_recorded_as_unresolved_not_as_clean(world):
    """The failure mode this whole loop exists for.

    An empty blast radius reads exactly like a clean incident. Once the workflow stops
    waiting it has to say which of the two it actually established, or the console will
    show "the key created nothing" on evidence that never arrived.
    """
    world.cloudtrail[PRIMARY].records = []
    world.cloudtrail[SECONDARY].records = []

    state = tasks.investigate_task(
        {"incident_id": INCIDENT_ID, "evidence_attempt": tasks.MAX_EVIDENCE_ATTEMPTS - 1}
    )

    assert state["evidence_settled"] is True
    kinds = {problem["kind"] for problem in state["blast_radius"]["problems"]}
    assert kinds == {"evidence_not_yet_available"}


def test_an_unresolved_search_marks_the_verification_incomplete(world):
    """The console renders evidence_incomplete, so the gap has to reach it."""
    world.cloudtrail[PRIMARY].records = []
    world.cloudtrail[SECONDARY].records = []
    state = tasks.investigate_task(
        {"incident_id": INCIDENT_ID, "evidence_attempt": tasks.MAX_EVIDENCE_ATTEMPTS - 1}
    )

    state = tasks.verify_task(tasks.narrate_task(state))

    assert state["verification"]["evidence_incomplete"] is True
