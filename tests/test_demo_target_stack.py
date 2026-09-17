"""The demo user's cage is the only thing keeping the attack demo cheap and contained."""

from __future__ import annotations

from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra.stacks.demo_target import DEMO_INSTANCE_TYPE, DEMO_USER_NAME, DemoTargetStack

DEMO_REGIONS = ["ap-south-1", "us-east-1"]


@pytest.fixture(scope="module")
def template() -> Template:
    app = cdk.App()
    stack = DemoTargetStack(
        app,
        "TestDemoTarget",
        demo_regions=DEMO_REGIONS,
        env=cdk.Environment(account="000000000000", region="ap-south-1"),
    )
    return Template.from_stack(stack)


def statements(template: Template) -> list[dict[str, Any]]:
    policies = template.find_resources("AWS::IAM::Policy")
    assert policies, "the demo user must carry a policy"
    found: list[dict[str, Any]] = []
    for policy in policies.values():
        found.extend(policy["Properties"]["PolicyDocument"]["Statement"])
    return found


def by_sid(template: Template, sid: str) -> dict[str, Any]:
    for statement in statements(template):
        if statement.get("Sid") == sid:
            return statement
    raise AssertionError(f"no statement with Sid {sid}")


def test_creates_the_demo_user(template: Template):
    template.has_resource_properties("AWS::IAM::User", {"UserName": DEMO_USER_NAME})


def test_never_creates_an_access_key(template: Template):
    """A key created here would be readable in the CloudFormation template."""
    assert template.find_resources("AWS::IAM::AccessKey") == {}


def test_instance_type_condition_applies_to_the_instance_resource(template: Template):
    statement = by_sid(template, "LaunchOnlyTinyInstances")
    assert statement["Action"] == "ec2:RunInstances"
    assert statement["Condition"]["StringEquals"]["ec2:InstanceType"] == DEMO_INSTANCE_TYPE
    assert statement["Condition"]["StringEquals"]["aws:RequestedRegion"] == DEMO_REGIONS


def test_supporting_resources_carry_no_instance_type_condition(template: Template):
    """RunInstances also touches images, volumes and ENIs. An instance-type condition
    on those resources would deny every launch rather than restrict its size."""
    statement = by_sid(template, "SupportingResourcesForRunInstances")
    assert "ec2:InstanceType" not in statement["Condition"].get("StringEquals", {})
    assert statement["Condition"]["StringEquals"]["aws:RequestedRegion"] == DEMO_REGIONS


def test_tagging_is_limited_to_launch_time(template: Template):
    statement = by_sid(template, "TagAtLaunchOnly")
    assert statement["Condition"]["StringEquals"]["ec2:CreateAction"] == "RunInstances"


def test_everything_outside_the_allow_list_is_denied(template: Template):
    statement = by_sid(template, "DenyEverythingElse")
    assert statement["Effect"] == "Deny"
    assert set(statement["NotAction"]) == {
        "ec2:RunInstances",
        "ec2:CreateTags",
        "ssm:GetParameter",
        "ssm:GetParameters",
    }


def test_other_regions_are_denied(template: Template):
    statement = by_sid(template, "DenyOutsideDemoRegions")
    assert statement["Effect"] == "Deny"
    assert statement["Condition"]["StringNotEqualsIfExists"]["aws:RequestedRegion"] == DEMO_REGIONS


def test_larger_instance_types_are_denied_explicitly(template: Template):
    statement = by_sid(template, "DenyAnythingBiggerThanTheDemoInstanceType")
    assert statement["Effect"] == "Deny"
    condition = statement["Condition"]["StringNotEqualsIfExists"]["ec2:InstanceType"]
    assert condition == DEMO_INSTANCE_TYPE


def test_exactly_two_regions_are_required():
    app = cdk.App()
    with pytest.raises(ValueError, match="exactly two regions"):
        DemoTargetStack(app, "TooManyRegions", demo_regions=["ap-south-1"])
