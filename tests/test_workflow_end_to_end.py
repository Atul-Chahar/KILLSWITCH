"""The whole workflow, from blast radius to confirmed end state, against fakes.

Every other test here checks one module. This one checks that the modules fit together:
that what `narrate_task` emits is what `verify_task` reads, that an approval recorded
through the console's API is the one `contain_task` re-checks, and that a denial survives
all the way to the end state.

Nothing in here touches AWS. Every client is a fake from `tests/fakes.py` and the narrator
is the deterministic rehearsal one, so the assertions are about wiring, not about a model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fakes import FakeEc2, FakeIam, FakeTable

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

    def client(self, name: str, region_name: str | None = None, **_: object) -> object:
        if name == "iam":
            return self.iam
        if name == "ec2":
            return self.ec2[str(region_name)]
        raise AssertionError(f"the workflow asked for an unexpected client: {name}")

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


def test_a_denial_makes_the_end_state_unconfirmed_and_the_execution_fail(world):
    """The denied instance is still running, so KILLSWITCH must not claim containment."""
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

    assert final["confirmed"] is False
    assert final["status"] == IncidentStatus.FAILED.value
    observed = {target["target"]: target["confirmed"] for target in final["end_state"]["targets"]}
    assert observed == {KEY: True, LAUNCHED: True, SECOND_LAUNCHED: False}


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
