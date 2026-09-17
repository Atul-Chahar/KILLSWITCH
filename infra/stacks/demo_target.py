"""The thing KILLSWITCH defends against: a deliberately leaky IAM user, tightly caged."""

from __future__ import annotations

from aws_cdk import CfnOutput, Stack
from aws_cdk import aws_iam as iam
from constructs import Construct

DEMO_USER_NAME = "demo-leaky-user"
DEMO_INSTANCE_TYPE = "t3.micro"

# The only mutating call this user can make is RunInstances. CreateTags is scoped to
# launch time, and the SSM read resolves the public Amazon Linux AMI alias.
ALLOWED_ACTIONS = [
    "ec2:RunInstances",
    "ec2:CreateTags",
    "ssm:GetParameter",
    "ssm:GetParameters",
]


class DemoTargetStack(Stack):
    """Creates demo-leaky-user. It deliberately does not create an access key.

    An access key created here would land in the CloudFormation template and the
    stack outputs. The operator mints it by CLI instead, and deletes it after the
    recording.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        demo_regions: list[str],
        instance_type: str = DEMO_INSTANCE_TYPE,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        if len(demo_regions) != 2:
            raise ValueError(f"the demo runs in exactly two regions, got {demo_regions!r}")

        user = iam.User(self, "DemoLeakyUser", user_name=DEMO_USER_NAME)
        in_demo_regions = {"aws:RequestedRegion": demo_regions}

        # RunInstances touches several resource types in a single call. ec2:InstanceType
        # is only evaluated against the instance resource, so putting it on the other
        # resource types would deny every launch outright rather than restrict its size.
        user.add_to_policy(
            iam.PolicyStatement(
                sid="LaunchOnlyTinyInstances",
                actions=["ec2:RunInstances"],
                resources=[f"arn:aws:ec2:*:{self.account}:instance/*"],
                conditions={"StringEquals": {"ec2:InstanceType": instance_type, **in_demo_regions}},
            )
        )
        user.add_to_policy(
            iam.PolicyStatement(
                sid="SupportingResourcesForRunInstances",
                actions=["ec2:RunInstances"],
                resources=[
                    "arn:aws:ec2:*::image/*",
                    f"arn:aws:ec2:*:{self.account}:volume/*",
                    f"arn:aws:ec2:*:{self.account}:network-interface/*",
                    f"arn:aws:ec2:*:{self.account}:security-group/*",
                    f"arn:aws:ec2:*:{self.account}:subnet/*",
                ],
                conditions={"StringEquals": in_demo_regions},
            )
        )
        user.add_to_policy(
            iam.PolicyStatement(
                sid="TagAtLaunchOnly",
                actions=["ec2:CreateTags"],
                resources=[f"arn:aws:ec2:*:{self.account}:*/*"],
                conditions={
                    "StringEquals": {"ec2:CreateAction": "RunInstances", **in_demo_regions}
                },
            )
        )
        user.add_to_policy(
            iam.PolicyStatement(
                sid="ResolveTheLatestAmazonLinuxAmi",
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=["arn:aws:ssm:*::parameter/aws/service/ami-amazon-linux-latest/*"],
                conditions={"StringEquals": in_demo_regions},
            )
        )

        user.add_to_policy(
            iam.PolicyStatement(
                sid="DenyEverythingElse",
                effect=iam.Effect.DENY,
                not_actions=ALLOWED_ACTIONS,
                resources=["*"],
            )
        )
        # IfExists so that global, region-less calls are judged by the deny above rather
        # than tripping on a condition key that is simply absent from the request.
        user.add_to_policy(
            iam.PolicyStatement(
                sid="DenyOutsideDemoRegions",
                effect=iam.Effect.DENY,
                actions=["*"],
                resources=["*"],
                conditions={"StringNotEqualsIfExists": in_demo_regions},
            )
        )
        user.add_to_policy(
            iam.PolicyStatement(
                sid="DenyAnythingBiggerThanTheDemoInstanceType",
                effect=iam.Effect.DENY,
                actions=["ec2:RunInstances"],
                resources=["*"],
                conditions={"StringNotEqualsIfExists": {"ec2:InstanceType": instance_type}},
            )
        )

        CfnOutput(self, "DemoUserName", value=user.user_name)
        CfnOutput(self, "DemoRegions", value=",".join(demo_regions))
        CfnOutput(
            self,
            "MintAccessKeyCommand",
            value=f"aws iam create-access-key --user-name {DEMO_USER_NAME}",
            description="Run this yourself. CDK never creates the key; delete it after the demo.",
        )
