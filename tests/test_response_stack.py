"""The workflow's shape is a safety property, so it is asserted rather than eyeballed."""

from __future__ import annotations

import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra.stacks.detection import DetectionStack
from infra.stacks.response import ResponseStack
from narrate.narrator import NarratorMode

DEMO_REGIONS = ["ap-south-1", "us-east-1"]
DESTRUCTIVE_ACTIONS = {"ec2:TerminateInstances", "iam:UpdateAccessKey"}


@pytest.fixture(scope="module")
def template(tmp_path_factory) -> Template:
    code_path = tmp_path_factory.mktemp("lambda_asset")
    (code_path / "workflow").mkdir()
    (code_path / "workflow" / "tasks.py").write_text("# stand-in asset for synth\n")

    app = cdk.App()
    env = cdk.Environment(account="000000000000", region="ap-south-1")
    detection = DetectionStack(app, "TestDetection", lambda_code_path=str(code_path), env=env)
    response = ResponseStack(
        app,
        "TestResponse",
        lambda_code_path=str(code_path),
        incidents_table=detection.incidents,
        demo_regions=DEMO_REGIONS,
        bedrock_model_id="test.model.v1",
        env=env,
    )
    return Template.from_stack(response)


def state_machine_definition(template: Template) -> str:
    machines = template.find_resources("AWS::StepFunctions::StateMachine")
    (machine,) = machines.values()
    return json.dumps(machine["Properties"]["DefinitionString"])


def _statements_by_sid(template: Template) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for policy in template.find_resources("AWS::IAM::Policy").values():
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            sid = statement.get("Sid")
            if not sid:
                continue
            action = statement["Action"]
            found[sid] = [action] if isinstance(action, str) else list(action)
    return found


def parsed_definition(template: Template) -> dict:
    """The state machine definition as a dict, with CDK tokens stubbed out.

    String matching on the definition can tell you a state exists. It cannot tell you a
    state does *not* carry a Retry, and that is one of the things this file has to prove.
    """
    machines = template.find_resources("AWS::StepFunctions::StateMachine")
    (machine,) = machines.values()
    definition = machine["Properties"]["DefinitionString"]
    parts = definition["Fn::Join"][1]
    joined = "".join(part if isinstance(part, str) else "token" for part in parts)
    return json.loads(joined)


def _all_statements(template: Template) -> list[dict]:
    return [
        statement
        for policy in template.find_resources("AWS::IAM::Policy").values()
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]
    ]


def _task_environments(template: Template) -> list[dict]:
    """Environments of the seven workflow tasks, which is what these assertions are about.

    The stack also holds the function that starts the workflow. It runs none of the task
    code and needs none of the task configuration.
    """
    return [
        function["Properties"]["Environment"]["Variables"]
        for function in template.find_resources("AWS::Lambda::Function").values()
        if str(function["Properties"].get("Handler", "")).startswith("workflow.tasks.")
    ]


def test_the_approval_step_really_waits_for_a_task_token(template: Template):
    """Without waitForTaskToken the workflow would sail past the human."""
    assert "lambda:invoke.waitForTaskToken" in state_machine_definition(template)


def test_the_workflow_runs_the_steps_in_the_order_the_architecture_states(template: Template):
    definition = state_machine_definition(template)
    order = [
        definition.index(name)
        for name in (
            "Investigate",
            "Verify",
            "Authorize",
            "WaitForHumanApproval",
            "Contain",
            "ConfirmEndState",
        )
    ]

    assert order == sorted(order)


def test_verification_happens_before_the_human_is_asked(template: Template):
    """Nothing unverified may reach an approve button."""
    definition = state_machine_definition(template)

    assert definition.index("Verify") < definition.index("WaitForHumanApproval")


def test_containment_happens_only_after_the_approval_step(template: Template):
    """Matched on the escaped state name so it cannot accidentally match ContainmentUnconfirmed."""
    definition = state_machine_definition(template)

    assert definition.index("WaitForHumanApproval") < definition.index(r"\"Contain\"")


def test_an_unconfirmed_end_state_fails_the_execution(template: Template):
    definition = state_machine_definition(template)

    assert "ContainmentUnconfirmed" in definition


def test_it_is_a_standard_workflow_because_express_cannot_wait_for_a_human(template: Template):
    template.has_resource_properties(
        "AWS::StepFunctions::StateMachine", {"StateMachineType": "STANDARD"}
    )


def test_a_cedar_policy_store_is_created_with_a_strict_schema(template: Template):
    template.resource_count_is("AWS::VerifiedPermissions::PolicyStore", 1)
    (store,) = template.find_resources("AWS::VerifiedPermissions::PolicyStore").values()

    assert store["Properties"]["ValidationSettings"]["Mode"] == "STRICT"


def test_the_containment_policy_is_loaded_from_the_cedar_file(template: Template):
    (policy,) = template.find_resources("AWS::VerifiedPermissions::Policy").values()
    statement = policy["Properties"]["Definition"]["Static"]["Statement"]

    assert "forbid" in statement
    assert "context.human_approved == true" in statement


def test_only_the_containment_function_may_destroy_anything(template: Template):
    """Destructive rights live in containment's statements and nowhere else in the stack."""
    statements = _statements_by_sid(template)
    carrying_destructive = {
        sid for sid, actions in statements.items() if DESTRUCTIVE_ACTIONS & set(actions)
    }

    assert carrying_destructive == {
        "TerminateOnlyInTheRegionsWeSearch",
        "ContainTheLeakedIdentity",
    }


def test_destruction_is_fenced_in_by_iam_and_not_only_by_our_code(template: Template):
    """Application code decides what to destroy; IAM decides what it is able to destroy.

    Neither fence is tight enough to be the only one, which is why both are here.
    """
    (statement,) = [
        entry
        for entry in _all_statements(template)
        if entry.get("Sid") == "TerminateOnlyInTheRegionsWeSearch"
    ]
    assert statement["Condition"]["StringEquals"]["aws:RequestedRegion"] == DEMO_REGIONS

    (identity,) = [
        entry
        for entry in _all_statements(template)
        if entry.get("Sid") == "ContainTheLeakedIdentity"
    ]
    # Users only: the account root has no user ARN, so it is out of reach entirely.
    assert "user/*" in json.dumps(identity["Resource"])


def test_containment_can_revoke_the_sessions_a_leaked_key_already_minted(template: Template):
    """Deactivating a key does not touch credentials it has already handed out."""
    statements = _statements_by_sid(template)

    assert "iam:PutUserPolicy" in statements["ContainTheLeakedIdentity"]
    assert "iam:GetUserPolicy" in statements["ConfirmTheEndState"]


def test_investigation_gets_read_access_and_nothing_more(template: Template):
    statements = _statements_by_sid(template)

    assert set(statements["ReadTheEvidence"]) == {
        "cloudtrail:LookupEvents",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAccessKeys",
    }


def test_confirmation_can_only_look_not_touch(template: Template):
    statements = _statements_by_sid(template)

    assert set(statements["ConfirmTheEndState"]) == {
        "ec2:DescribeInstances",
        "iam:ListAccessKeys",
        "iam:GetUserPolicy",
    }


def test_every_task_knows_which_policy_store_to_ask(template: Template):
    """A missing policy store id would silently drop the workflow onto the fallback table."""
    assert all(
        "VERIFIED_PERMISSIONS_POLICY_STORE_ID" in variables
        for variables in _task_environments(template)
    )


def test_the_narrator_may_ask_the_model_and_do_nothing_else(template: Template):
    """One grant, one action. The component we do not trust gets the least we can give it."""
    statements = _statements_by_sid(template)

    assert set(statements["AskTheModelToPropose"]) == {"bedrock:InvokeModel"}


def test_no_other_principal_in_the_stack_may_call_bedrock(template: Template):
    statements = _statements_by_sid(template)
    carrying_bedrock = {
        sid
        for sid, actions in statements.items()
        if any(action.startswith("bedrock:") for action in actions)
    }

    assert carrying_bedrock == {"AskTheModelToPropose"}


def test_the_narrators_whole_role_is_bedrock_plus_the_incident_table(template: Template):
    """Asserted on the role's own policy, so an extra grant cannot hide behind a missing Sid."""
    policies = [
        policy
        for logical_id, policy in template.find_resources("AWS::IAM::Policy").items()
        if logical_id.startswith("NarrateFunctionServiceRole")
    ]
    granted: set[str] = set()
    for policy in policies:
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            action = statement["Action"]
            granted.update([action] if isinstance(action, str) else action)

    assert policies, "the narrator has no role policy, so this test proved nothing"
    assert {action for action in granted if not action.startswith("dynamodb:")} == {
        "bedrock:InvokeModel"
    }


def test_the_model_writes_the_plan_before_the_verifier_judges_it(template: Template):
    definition = state_machine_definition(template)

    assert definition.index("Investigate") < definition.index("Narrate")
    assert definition.index("Narrate") < definition.index("Verify")


def test_the_narrator_is_told_which_model_to_ask(template: Template):
    assert all("BEDROCK_MODEL_ID" in variables for variables in _task_environments(template))


def test_the_human_sees_the_summary_the_narrator_wrote(template: Template):
    """The summary lives in the execution state; the console can only read DynamoDB."""
    definition = state_machine_definition(template)

    assert "$.summary" in definition
    assert "$.narrator" in definition


def test_deploying_without_a_model_id_fails_at_synth_not_mid_incident(tmp_path):
    """A stack that deploys into a guaranteed runtime failure is worse than one that refuses."""
    (tmp_path / "workflow").mkdir()
    (tmp_path / "workflow" / "tasks.py").write_text("# stand-in asset for synth\n")
    app = cdk.App()
    env = cdk.Environment(account="000000000000", region="ap-south-1")
    detection = DetectionStack(app, "NoModel", lambda_code_path=str(tmp_path), env=env)

    with pytest.raises(ValueError, match="BEDROCK_MODEL_ID"):
        ResponseStack(
            app,
            "NoModelResponse",
            lambda_code_path=str(tmp_path),
            incidents_table=detection.incidents,
            demo_regions=DEMO_REGIONS,
            env=env,
        )


def test_the_rehearsal_narrator_needs_no_model_id(tmp_path):
    """Rehearsal exists for the days there is no Bedrock. It must not demand one."""
    (tmp_path / "workflow").mkdir()
    (tmp_path / "workflow" / "tasks.py").write_text("# stand-in asset for synth\n")
    app = cdk.App()
    env = cdk.Environment(account="000000000000", region="ap-south-1")
    detection = DetectionStack(app, "Rehearsing", lambda_code_path=str(tmp_path), env=env)

    stack = ResponseStack(
        app,
        "RehearsingResponse",
        lambda_code_path=str(tmp_path),
        incidents_table=detection.incidents,
        demo_regions=DEMO_REGIONS,
        narrator_mode=NarratorMode.REHEARSAL.value,
        env=env,
    )

    assert Template.from_stack(stack).find_resources("AWS::StepFunctions::StateMachine")


def test_something_actually_starts_the_workflow(template: Template):
    """The wire that was missing. Detection writes an incident; this is what responds.

    Every other test in this file asserts the shape of a workflow nothing invoked.
    """
    starters = [
        function
        for function in template.find_resources("AWS::Lambda::Function").values()
        if function["Properties"].get("Handler") == "workflow.start.lambda_handler"
    ]

    assert len(starters) == 1


def test_the_starter_is_driven_by_the_incident_table_stream(template: Template):
    """Not by a call from the detection Lambdas: that would make the two stacks circular."""
    mappings = template.find_resources("AWS::Lambda::EventSourceMapping")

    assert len(mappings) == 1
    (mapping,) = mappings.values()
    assert "StartingPosition" in mapping["Properties"]


def test_only_the_starter_may_begin_an_execution(template: Template):
    statements = _all_statements(template)
    starting = [
        entry
        for entry in statements
        if "states:StartExecution" in json.dumps(entry.get("Action", ""))
    ]

    assert len(starting) == 1


def test_investigation_polls_until_the_evidence_lands(template: Template):
    """CloudTrail delivers minutes after the call. A single lookup would find nothing."""
    states = parsed_definition(template)["States"]

    assert "WaitForEvidence" in states
    assert states["WaitForEvidence"]["Next"] == "Investigate"
    choice = states["HasTheEvidenceLanded"]
    assert choice["Choices"][0]["Variable"] == "$.evidence_settled"
    assert choice["Default"] == "WaitForEvidence"


def test_a_declined_incident_ends_successfully_and_says_which(template: Template):
    """Denying an action is a human using the gate, not the workflow breaking."""
    states = parsed_definition(template)["States"]

    assert states["DeclinedByOperator"]["Type"] == "Succeed"
    assert states["Contained"]["Type"] == "Succeed"
    assert states["ContainmentUnconfirmed"]["Type"] == "Fail"


def test_a_failure_to_run_our_code_is_retried_and_a_decision_is_not(template: Template):
    """Every task retries the same class of thing: the Lambda service failing to run us.

    A NarrationError, a refused approval or an unconfirmed end state is an answer. Retried,
    it would only be asked again, so no retry rule may name States.TaskFailed or States.ALL.
    """
    states = parsed_definition(template)["States"]
    tasks_with_retries = {name: state for name, state in states.items() if "Retry" in state}

    assert tasks_with_retries, "every LambdaInvoke should carry a retry policy"
    for name, state in tasks_with_retries.items():
        for rule in state["Retry"]:
            assert all(error.startswith("Lambda.") for error in rule["ErrorEquals"]), name


def test_the_approval_step_is_only_retried_when_it_never_ran(template: Template):
    """Re-invoking it mints a second token, so it may only be retried before one exists.

    A Lambda.* error means the invocation itself failed and no token was ever handed out.
    Anything broader would orphan the token the operator is already looking at.
    """
    approval = parsed_definition(template)["States"]["WaitForHumanApproval"]

    for rule in approval["Retry"]:
        assert all(error.startswith("Lambda.") for error in rule["ErrorEquals"])


def test_only_the_narrator_carries_the_nvidia_key(tmp_path):
    """A credential that can spend money does not belong on the function that destroys things."""
    (tmp_path / "workflow").mkdir()
    (tmp_path / "workflow" / "tasks.py").write_text("# stand-in asset for synth\n")
    app = cdk.App()
    env = cdk.Environment(account="000000000000", region="ap-south-1")
    detection = DetectionStack(app, "NimDetect", lambda_code_path=str(tmp_path), env=env)
    stack = ResponseStack(
        app,
        "NimResponse",
        lambda_code_path=str(tmp_path),
        incidents_table=detection.incidents,
        demo_regions=DEMO_REGIONS,
        narrator_mode=NarratorMode.NIM.value,
        nvidia_api_key="nvapi-" + "stub",
        env=env,
    )

    functions = Template.from_stack(stack).find_resources("AWS::Lambda::Function")
    carrying = {
        logical_id
        for logical_id, function in functions.items()
        if "NVIDIA_API_KEY" in function["Properties"]["Environment"]["Variables"]
    }

    assert len(carrying) == 1
    assert next(iter(carrying)).startswith("NarrateFunction")


def test_the_nim_narrator_needs_no_bedrock_model_id(tmp_path):
    """NARRATOR_MODE=nim is a legitimate way to deploy without Bedrock access at all."""
    (tmp_path / "workflow").mkdir()
    (tmp_path / "workflow" / "tasks.py").write_text("# stand-in asset for synth\n")
    app = cdk.App()
    env = cdk.Environment(account="000000000000", region="ap-south-1")
    detection = DetectionStack(app, "NimNoBedrock", lambda_code_path=str(tmp_path), env=env)

    stack = ResponseStack(
        app,
        "NimNoBedrockResponse",
        lambda_code_path=str(tmp_path),
        incidents_table=detection.incidents,
        demo_regions=DEMO_REGIONS,
        narrator_mode=NarratorMode.NIM.value,
        env=env,
    )

    assert Template.from_stack(stack).find_resources("AWS::StepFunctions::StateMachine")
