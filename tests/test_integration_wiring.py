"""Everything, from a GitHub push to a confirmed end state, with nothing seeded.

`test_workflow_end_to_end.py` starts from an incident that already exists. This file
starts from a webhook body and lets each stage produce the input to the next one, so the
joins nobody owns are the thing under test:

    push payload -> detect -> DynamoDB write -> table stream -> start_workflows
      -> the state machine's stages -> the console's API -> containment -> confirmation

The state machine itself is AWS's, so what runs here is a runner that follows the same
order. `test_the_runner_follows_the_deployed_state_machine` asserts that order against the
synthesized definition, so this file cannot quietly drift into testing a workflow that is
not the one deployed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template
from fakes import FakeCloudTrail, FakeEc2, FakeIam, FakeTable

from detect import handler as detect_handler
from infra.stacks.detection import DetectionStack
from infra.stacks.response import ResponseStack
from narrate.narrator import NarratorMode
from shared.approvals import ApprovalState, AuditStage
from shared.incidents import IncidentStore
from shared.models import IncidentStatus, incident_id_for
from verifier.verify import ActionType
from workflow import approval_api, tasks
from workflow.start import start_workflows

# A key shaped like a real one. Not AWS's documented example, because the scanner skips
# those on purpose and a demo key that the detector ignores would prove nothing.
LEAKED_KEY = "AKIA" + "QYSFN3XMPLE7RT4D"
ATTACKER_KEY = "AKIA" + "9WZK2BVQD8HN6LMX"
USER = "demo-leaky-user"
ATTACKER_USER = "backdoor-user"
REPOSITORY = "octo/private-demo-repo"
COMMIT = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
PRIMARY = "ap-south-1"
SECONDARY = "us-east-1"
LAUNCHED = "i-0a1b2c3d4e5f60001"
WEBHOOK_SECRET = "a-secret-shared-with-github"
TOKEN = "task-token-from-step-functions"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)
INCIDENT_ID = incident_id_for(LEAKED_KEY)
STATE_MACHINE = "arn:aws:states:ap-south-1:000000000000:stateMachine:Response"

# The order the deployed definition runs its stages in, asserted against the template
# below and followed by the runner in this file.
DEPLOYED_ORDER = [
    "Investigate",
    "Narrate",
    "Verify",
    "Authorize",
    "WaitForHumanApproval",
    "Contain",
    "ConfirmEndState",
]


# --- the attacker's CloudTrail trail --------------------------------------------------


def run_instances(instance_id: str, region: str) -> dict[str, Any]:
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


def create_access_key(key_id: str, user_name: str, region: str) -> dict[str, Any]:
    """Persistence: the attacker mints a credential of their own."""
    return {
        "EventId": f"event-{key_id}",
        "EventName": "CreateAccessKey",
        "EventTime": NOW,
        "CloudTrailEvent": json.dumps(
            {
                "awsRegion": region,
                "sourceIPAddress": "203.0.113.10",
                "requestParameters": {"userName": user_name},
                "responseElements": {"accessKey": {"accessKeyId": key_id, "userName": user_name}},
            }
        ),
    }


class World:
    """Every AWS service the whole chain talks to, in memory."""

    def __init__(self) -> None:
        self.table = FakeTable()
        self.store = IncidentStore(self.table)
        self.iam = FakeIam(
            {
                USER: [{"AccessKeyId": LEAKED_KEY, "Status": "Active"}],
                ATTACKER_USER: [{"AccessKeyId": ATTACKER_KEY, "Status": "Active"}],
            }
        )
        self.ec2 = {PRIMARY: FakeEc2({LAUNCHED: "running"}), SECONDARY: FakeEc2({})}
        self.cloudtrail = {
            PRIMARY: FakeCloudTrail([run_instances(LAUNCHED, PRIMARY)]),
            SECONDARY: FakeCloudTrail([create_access_key(ATTACKER_KEY, ATTACKER_USER, SECONDARY)]),
        }
        self.step_functions = FakeStepFunctions()

    def client(self, name: str, region_name: str | None = None, **_: object) -> object:
        if name == "iam":
            return self.iam
        if name == "ec2":
            return self.ec2[str(region_name)]
        if name == "cloudtrail":
            return self.cloudtrail[str(region_name)]
        if name == "stepfunctions":
            return self.step_functions
        raise AssertionError(f"unexpected client: {name}")

    def session(self) -> object:
        return SimpleNamespace(client=self.client)

    def resource(self, name: str, **_: object) -> object:
        assert name == "dynamodb"
        return SimpleNamespace(Table=lambda _n: self.table)


class FakeStepFunctions:
    def __init__(self) -> None:
        self.executions: list[dict[str, Any]] = []
        self.task_successes: list[dict[str, Any]] = []

    def start_execution(self, **kwargs: Any) -> dict[str, Any]:
        self.executions.append(dict(kwargs))
        return {"executionArn": f"{STATE_MACHINE}:{kwargs['name']}"}

    def send_task_success(self, **kwargs: Any) -> dict[str, Any]:
        self.task_successes.append(dict(kwargs))
        return {}


@pytest.fixture
def world(monkeypatch) -> World:
    built = World()
    monkeypatch.setenv("INCIDENT_TABLE_NAME", "killswitch-incidents")
    monkeypatch.setenv("AWS_REGION", PRIMARY)
    monkeypatch.setenv("AWS_SECONDARY_REGION", SECONDARY)
    monkeypatch.setenv("NARRATOR_MODE", NarratorMode.REHEARSAL.value)
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.delenv("VERIFIED_PERMISSIONS_POLICY_STORE_ID", raising=False)
    for module in (tasks, approval_api):
        monkeypatch.setattr(module.boto3, "client", built.client)
        monkeypatch.setattr(module.boto3, "resource", built.resource)
    monkeypatch.setattr(tasks.boto3, "Session", built.session)
    return built


# --- the chain ------------------------------------------------------------------------


def push_event(key: str = LEAKED_KEY) -> dict[str, Any]:
    """An API Gateway event carrying a signed GitHub push, as the webhook receives it."""
    body = json.dumps(
        {
            "repository": {"full_name": REPOSITORY},
            "commits": [{"id": COMMIT}],
        }
    )
    signature = hmac.new(WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return {
        "body": body,
        "headers": {"X-Hub-Signature-256": f"sha256={signature}"},
        "_leaked_key": key,
    }


def deliver_push(world: World, event: dict[str, Any]) -> dict[str, Any]:
    """Run the webhook handler, with the commit diff stubbed rather than GitHub called."""
    key = event.pop("_leaked_key")
    return detect_handler.lambda_handler(
        event,
        None,
        store=world.store,
        fetch_patch=lambda _repo, _sha: f"+AWS_ACCESS_KEY_ID={key}\n",
    )


def started_incidents(world: World) -> list[str]:
    """What the table stream told the starter to begin."""
    started = start_workflows({"Records": world.table.stream}, world.step_functions, STATE_MACHINE)
    world.table.stream.clear()
    return started


def run_to_approval(world: World, execution_input: dict[str, Any]) -> dict[str, Any]:
    """Investigate, Narrate, Verify, Authorize, then pause on the token, as deployed."""
    state = dict(execution_input)
    for _attempt in range(tasks.MAX_EVIDENCE_ATTEMPTS):
        state = tasks.investigate_task(state)
        if state["evidence_settled"]:
            break
    state = tasks.narrate_task(state)
    state = tasks.verify_task(state)
    state = tasks.authorize_task(state)
    tasks.request_approval_task({**state, "task_token": TOKEN})
    return state


def decide(world: World, decisions: dict[str, ApprovalState]) -> dict[str, Any]:
    """Answer through the console's real API, Cognito claim and all."""
    return approval_api.lambda_handler(
        {
            "httpMethod": "POST",
            "pathParameters": {"incident_id": INCIDENT_ID},
            "requestContext": {"authorizer": {"claims": {"email": "operator@example.com"}}},
            "body": json.dumps(
                {
                    "decisions": [
                        {"action_signature": signature, "state": state.value}
                        for signature, state in decisions.items()
                    ]
                }
            ),
        },
        None,
        store=world.store,
        step_functions=world.step_functions,
    )


def signatures(state: dict[str, Any]) -> dict[str, str]:
    """Approved actions by target, so tests name machines rather than strings."""
    return {
        item["action"]["target"]: "{action_type}:{target}:{region}".format(
            action_type=item["action"]["action_type"],
            target=item["action"]["target"],
            region=item["action"]["region"] or "-",
        )
        for item in state["verification"]["approved"]
    }


def finish(state: dict[str, Any]) -> dict[str, Any]:
    return tasks.confirm_task(tasks.contain_task(state))


# --- the runner is the deployed workflow ----------------------------------------------


def test_the_runner_follows_the_deployed_state_machine():
    """Otherwise this file tests a workflow nobody deploys."""
    code = Path(tempfile.mkdtemp())
    (code / "workflow").mkdir()
    (code / "workflow" / "tasks.py").write_text("# stand-in asset for synth\n")

    app = cdk.App()
    env = cdk.Environment(account="000000000000", region=PRIMARY)
    detection = DetectionStack(app, "WiringDetection", lambda_code_path=str(code), env=env)
    response = ResponseStack(
        app,
        "WiringResponse",
        lambda_code_path=str(code),
        incidents_table=detection.incidents,
        demo_regions=[PRIMARY, SECONDARY],
        bedrock_model_id="test.model.v1",
        env=env,
    )
    (machine,) = (
        Template.from_stack(response).find_resources("AWS::StepFunctions::StateMachine").values()
    )
    parts = machine["Properties"]["DefinitionString"]["Fn::Join"][1]
    states = json.loads("".join(p if isinstance(p, str) else "token" for p in parts))["States"]

    def onwards(state: dict[str, Any]) -> str | None:
        """Follow a Next, or the branch a Choice takes when things are going well."""
        if "Next" in state:
            return str(state["Next"])
        if "Choices" in state:
            return str(state["Choices"][0]["Next"])
        return None

    walked: list[str] = []
    current: str | None = DEPLOYED_ORDER[0]
    while current is not None and current in states:
        if current in DEPLOYED_ORDER:
            walked.append(current)
        current = onwards(states[current])

    assert walked == DEPLOYED_ORDER


# --- the whole thing ------------------------------------------------------------------


def test_a_push_becomes_a_contained_incident_without_anything_being_seeded(world):
    """The happy path, end to end, starting from a signed webhook body."""
    response = deliver_push(world, push_event())
    assert response["statusCode"] == 200

    assert started_incidents(world) == [INCIDENT_ID]
    (execution,) = world.step_functions.executions
    state = run_to_approval(world, json.loads(execution["input"]))

    by_target = signatures(state)
    assert set(by_target) == {LEAKED_KEY, LAUNCHED, ATTACKER_KEY}

    decide(world, {sig: ApprovalState.APPROVED for sig in by_target.values()})
    final = finish(state)

    assert final["status"] == IncidentStatus.CONTAINED.value
    assert world.iam.keys_by_user[USER][0]["Status"] == "Inactive"
    assert world.iam.keys_by_user[ATTACKER_USER][0]["Status"] == "Inactive"
    assert world.ec2[PRIMARY].instances[LAUNCHED] == "shutting-down"


def test_the_console_sees_the_same_incident_the_workflow_wrote(world):
    """The console reads DynamoDB, so anything it must show has to land there."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))
    decide(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    finish(state)

    view = approval_api.incident_view(world.store, INCIDENT_ID)

    assert view is not None
    assert view["repository"] == REPOSITORY
    assert view["key_owner"] == USER
    assert view["status"] == IncidentStatus.CONTAINED.value
    assert view["summary"] is not None
    assert view["narrator"] == NarratorMode.REHEARSAL.value
    assert {target["target"] for target in view["end_state"]["targets"]} == {
        LEAKED_KEY,
        LAUNCHED,
        ATTACKER_KEY,
    }


def test_the_credential_the_attacker_minted_is_found_and_deactivated(world):
    """Deactivating the leaked key is worth nothing if the attacker kept one of their own."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    minted = [
        resource
        for resource in state["blast_radius"]["resources"]
        if resource["kind"] == "iam_access_key"
    ]
    assert [resource["resource_id"] for resource in minted] == [ATTACKER_KEY]

    decide(world, {signatures(state)[ATTACKER_KEY]: ApprovalState.APPROVED})
    finish(state)

    assert world.iam.keys_by_user[ATTACKER_USER][0]["Status"] == "Inactive"


# --- the paths that must not destroy anything -----------------------------------------


def test_denying_everything_destroys_nothing_and_does_not_report_a_failure(world):
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    decide(world, {sig: ApprovalState.DENIED for sig in signatures(state).values()})
    final = finish(state)

    assert final["status"] == IncidentStatus.DECLINED.value
    assert world.iam.keys_by_user[USER][0]["Status"] == "Active"
    assert world.ec2[PRIMARY].instances[LAUNCHED] == "running"
    assert world.ec2[PRIMARY].terminate_calls == []


def test_nobody_answering_destroys_nothing_and_is_recorded_as_a_refusal(world):
    """The approval timed out, or the console was never opened. Containment still runs."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    final = finish(state)

    assert final["status"] == IncidentStatus.DECLINED.value
    assert world.iam.update_calls == []
    assert world.ec2[PRIMARY].terminate_calls == []
    assert {entry.stage for entry in world.store.audit_trail(INCIDENT_ID)} == {AuditStage.REFUSED}


def test_an_action_that_will_not_confirm_fails_the_execution(world):
    """The only outcome that must never be rounded up."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))
    decide(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})

    contained = tasks.contain_task(state)
    world.ec2[PRIMARY].instances[LAUNCHED] = "running"
    final = tasks.confirm_task(contained)

    assert final["confirmed"] is False
    assert final["status"] == IncidentStatus.FAILED.value


def test_the_verifier_strikes_an_action_out_before_any_human_sees_it(world):
    """The rehearsal narrator always proposes one instance the key never created."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    rejected = state["verification"]["rejected"]

    assert [item["reason"] for item in rejected] == ["target_not_in_blast_radius"]
    assert rejected[0]["action"]["target"] not in signatures(state)


# --- the joins that were never tested -------------------------------------------------


def test_an_unsigned_push_never_becomes_an_incident(world):
    event = push_event()
    event["headers"]["X-Hub-Signature-256"] = "sha256=" + "0" * 64

    response = deliver_push(world, event)

    assert response["statusCode"] == 401
    assert world.table.items == {}
    assert started_incidents(world) == []


def test_a_documented_example_key_never_becomes_an_incident(world):
    """AWS publishes these. An incident raised for one is a false positive on camera."""
    response = deliver_push(world, push_event(key="AKIA" + "IOSFODNN7EXAMPLE"))

    assert json.loads(response["body"])["incidents"] == 0
    assert started_incidents(world) == []


def test_the_same_push_delivered_twice_starts_one_execution(world):
    """GitHub redelivers. The conditional write and the execution name absorb it."""
    deliver_push(world, push_event())
    deliver_push(world, push_event())

    assert started_incidents(world) == [INCIDENT_ID]
    assert len(world.step_functions.executions) == 1


def test_approving_releases_the_task_token_the_workflow_is_waiting_on(world):
    """Decisions are written first, then the token. The workflow must not outrun them."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    decide(world, {signatures(state)[LAUNCHED]: ApprovalState.APPROVED})

    (success,) = world.step_functions.task_successes
    assert success["taskToken"] == TOKEN
    assert world.store.decision_for(INCIDENT_ID, signatures(state)[LAUNCHED]) is not None


def test_the_operator_who_decided_is_recorded(world):
    """The audit trail has to name a person, not a service."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    decide(world, {signatures(state)[LAUNCHED]: ApprovalState.APPROVED})

    decision = world.store.decision_for(INCIDENT_ID, signatures(state)[LAUNCHED])
    assert decision is not None
    assert decision.decided_by == "operator@example.com"


def test_a_decision_from_a_superseded_round_authorises_nothing(world):
    """A second approval round issues a new token; the old decision must not survive it."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))
    decide(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})

    # The workflow asks again, so the incident is now waiting on a different token.
    tasks.request_approval_task({**state, "task_token": "a-second-round-token"})
    final = finish(state)

    assert final["status"] == IncidentStatus.DECLINED.value
    assert world.ec2[PRIMARY].terminate_calls == []
    assert world.iam.update_calls == []


def test_evidence_that_has_not_arrived_yet_does_not_become_an_empty_plan(world):
    """CloudTrail is minutes behind. The first lookup finding nothing is the normal case."""
    world.cloudtrail[PRIMARY].records = []
    world.cloudtrail[SECONDARY].records = []
    deliver_push(world, push_event())
    started_incidents(world)

    state = tasks.investigate_task(json.loads(world.step_functions.executions[0]["input"]))

    assert state["evidence_settled"] is False
    assert state["blast_radius"]["resources"] == []


def test_giving_up_on_evidence_is_not_reported_as_a_clean_incident(world):
    world.cloudtrail[PRIMARY].records = []
    world.cloudtrail[SECONDARY].records = []
    deliver_push(world, push_event())
    started_incidents(world)
    execution_input = json.loads(world.step_functions.executions[0]["input"])

    state = run_to_approval(world, execution_input)

    assert state["verification"]["evidence_incomplete"] is True
    view = approval_api.incident_view(world.store, INCIDENT_ID)
    assert view is not None
    assert view["blast_radius"]["problems"] != []


def test_an_action_the_verifier_rejected_can_never_be_approved_into_existence(world):
    """Submitting a signature the plan does not contain must authorise nothing."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))
    struck_out = state["verification"]["rejected"][0]["action"]
    forged = "{action_type}:{target}:{region}".format(
        action_type=struck_out["action_type"],
        target=struck_out["target"],
        region=struck_out["region"] or "-",
    )

    decide(world, {forged: ApprovalState.APPROVED})
    final = finish(state)

    assert struck_out["target"] not in {
        target["target"] for target in final["end_state"]["targets"]
    }
    assert world.ec2[PRIMARY].terminate_calls == []
    assert final["status"] == IncidentStatus.DECLINED.value


def test_every_destructive_call_left_a_before_and_an_after(world):
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))
    decide(world, {sig: ApprovalState.APPROVED for sig in signatures(state).values()})
    finish(state)

    trail = world.store.audit_trail(INCIDENT_ID)
    before = [entry for entry in trail if entry.stage is AuditStage.BEFORE]
    after = [entry for entry in trail if entry.stage is AuditStage.AFTER]

    assert len(before) == 3
    assert len(after) == 3
    assert [entry.sk for entry in trail] == sorted(entry.sk for entry in trail)


def test_the_plan_only_ever_contains_actions_killswitch_can_take(world):
    """A guard on the seam between the narrator and containment."""
    deliver_push(world, push_event())
    started_incidents(world)
    state = run_to_approval(world, json.loads(world.step_functions.executions[0]["input"]))

    proposed = {item["action"]["action_type"] for item in state["verification"]["approved"]}

    assert proposed <= {ActionType.DEACTIVATE_KEY.value, ActionType.TERMINATE_INSTANCE.value}
