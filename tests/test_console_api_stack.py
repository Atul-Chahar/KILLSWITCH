"""The approval route must not be reachable without logging in."""

from __future__ import annotations

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra.stacks.console_api import ConsoleApiStack
from infra.stacks.detection import DetectionStack
from infra.stacks.response import ResponseStack


@pytest.fixture(scope="module")
def template(tmp_path_factory) -> Template:
    code_path = tmp_path_factory.mktemp("lambda_asset")
    (code_path / "workflow").mkdir()
    (code_path / "workflow" / "approval_api.py").write_text("# stand-in asset for synth\n")

    app = cdk.App()
    env = cdk.Environment(account="000000000000", region="ap-south-1")
    detection = DetectionStack(app, "TestDetection", lambda_code_path=str(code_path), env=env)
    response = ResponseStack(
        app,
        "TestResponse",
        lambda_code_path=str(code_path),
        incidents_table=detection.incidents,
        demo_regions=["ap-south-1", "us-east-1"],
        env=env,
    )
    console = ConsoleApiStack(
        app,
        "TestConsoleApi",
        lambda_code_path=str(code_path),
        incidents_table=detection.incidents,
        state_machine=response.state_machine,
        env=env,
    )
    return Template.from_stack(console)


def granted_actions(template: Template) -> set[str]:
    return {
        action
        for policy in template.find_resources("AWS::IAM::Policy").values()
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]
        for action in (
            [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        )
        if isinstance(action, str)
    }


def test_every_route_requires_a_cognito_login(template: Template):
    methods = template.find_resources("AWS::ApiGateway::Method")
    guarded = [
        method["Properties"]
        for method in methods.values()
        if method["Properties"]["HttpMethod"] in {"GET", "POST"}
    ]

    assert guarded, "there should be routes to guard"
    for properties in guarded:
        assert properties["AuthorizationType"] == "COGNITO_USER_POOLS"
        assert "AuthorizerId" in properties


def test_operators_cannot_sign_themselves_up(template: Template):
    template.has_resource_properties(
        "AWS::Cognito::UserPool", {"AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True}}
    )


def test_the_api_can_release_a_task_token_and_nothing_else(template: Template):
    states_actions = {
        action for action in granted_actions(template) if action.startswith("states:")
    }

    assert states_actions == {"states:SendTaskSuccess"}


def test_the_api_is_never_granted_a_destructive_aws_action(template: Template):
    forbidden = {"ec2:TerminateInstances", "iam:UpdateAccessKey", "iam:DeleteAccessKey"}

    assert forbidden.isdisjoint(granted_actions(template))
