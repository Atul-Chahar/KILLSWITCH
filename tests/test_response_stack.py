"""The workflow's shape is a safety property, so it is asserted rather than eyeballed."""

from __future__ import annotations

import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra.stacks.detection import DetectionStack
from infra.stacks.response import ResponseStack

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
    """One statement in the whole stack carries destructive rights, and it is named for it."""
    statements = _statements_by_sid(template)
    carrying_destructive = {
        sid for sid, actions in statements.items() if DESTRUCTIVE_ACTIONS & set(actions)
    }

    assert carrying_destructive == {"ContainWhatTheHumanApproved"}


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
    }


def test_every_task_knows_which_policy_store_to_ask(template: Template):
    """A missing policy store id would silently drop the workflow onto the fallback table."""
    functions = template.find_resources("AWS::Lambda::Function")
    variables = [
        function["Properties"]["Environment"]["Variables"] for function in functions.values()
    ]

    assert all("VERIFIED_PERMISSIONS_POLICY_STORE_ID" in item for item in variables)
