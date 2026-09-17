"""The detection stack: one table, two triggers, and no standing destructive rights."""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from infra.stacks.detection import DetectionStack


def _as_list(action: object) -> list[str]:
    if isinstance(action, str):
        return [action]
    if isinstance(action, list):
        return [item for item in action if isinstance(item, str)]
    return []


def _granted_actions(template: Template) -> set[str]:
    policies = template.find_resources("AWS::IAM::Policy")
    return {
        action
        for policy in policies.values()
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]
        for action in _as_list(statement["Action"])
    }


@pytest.fixture(scope="module")
def template(tmp_path_factory) -> Template:
    code_path = tmp_path_factory.mktemp("lambda_asset")
    (code_path / "detect").mkdir()
    (code_path / "detect" / "handler.py").write_text("# stand-in asset for synth\n")

    app = cdk.App()
    stack = DetectionStack(
        app,
        "TestDetection",
        lambda_code_path=str(code_path),
        env=cdk.Environment(account="000000000000", region="ap-south-1"),
    )
    return Template.from_stack(stack)


def test_the_incident_table_is_partitioned_by_incident_id(template: Template):
    template.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "KeySchema": [
                {"AttributeName": "incident_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "BillingMode": "PAY_PER_REQUEST",
        },
    )


def test_there_is_exactly_one_incident_table(template: Template):
    """Two tables would mean two sources of truth for the same incident."""
    template.resource_count_is("AWS::DynamoDB::Table", 1)


def test_both_triggers_have_a_function(template: Template):
    template.resource_count_is("AWS::Lambda::Function", 2)
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Handler": "detect.handler.lambda_handler", "Runtime": "python3.12"},
    )
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Handler": "detect.quarantine.lambda_handler", "Runtime": "python3.12"},
    )


def test_the_webhook_secret_is_empty_unless_supplied(template: Template):
    """A half-configured deploy must reject webhooks, never trust them."""
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Handler": "detect.handler.lambda_handler",
            "Environment": {"Variables": Match.object_like({"GITHUB_WEBHOOK_SECRET": ""})},
        },
    )


def test_the_quarantine_rule_matches_the_cloudtrail_attach_event(template: Template):
    template.has_resource_properties(
        "AWS::Events::Rule",
        {
            "EventPattern": {
                "source": ["aws.iam"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": ["AttachUserPolicy", "PutUserPolicy"],
                },
            }
        },
    )


def test_the_quarantine_function_can_only_read_iam(template: Template):
    """Detection identifies keys. It never deactivates them; that is containment's job."""
    iam_actions = {action for action in _granted_actions(template) if action.startswith("iam:")}

    assert iam_actions == {"iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"}


def test_detection_is_never_granted_a_destructive_action(template: Template):
    forbidden = {"iam:UpdateAccessKey", "iam:DeleteAccessKey", "ec2:TerminateInstances"}

    assert forbidden.isdisjoint(_granted_actions(template))


def test_the_webhook_is_exposed_over_api_gateway(template: Template):
    template.has_resource_properties("AWS::ApiGateway::Resource", {"PathPart": "webhook"})
    template.has_resource_properties("AWS::ApiGateway::Method", {"HttpMethod": "POST"})


def test_the_asset_path_must_exist(tmp_path: Path):
    app = cdk.App()
    with pytest.raises(Exception, match="Cannot find asset|no such file|does not exist"):
        DetectionStack(
            app,
            "MissingAsset",
            lambda_code_path=str(tmp_path / "not-built-yet"),
            env=cdk.Environment(account="000000000000", region="ap-south-1"),
        )
