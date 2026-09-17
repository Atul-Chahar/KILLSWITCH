#!/usr/bin/env python3
"""CDK entry point. Run through the cdk CLI from the repository root: `cdk synth`."""

from __future__ import annotations

import os

import aws_cdk as cdk

from infra.stacks.demo_target import DemoTargetStack

PRIMARY_REGION = os.environ.get("AWS_REGION", "ap-south-1")
SECONDARY_REGION = os.environ.get("AWS_SECONDARY_REGION", "us-east-1")

app = cdk.App()

DemoTargetStack(
    app,
    "KillswitchDemoTarget",
    demo_regions=[PRIMARY_REGION, SECONDARY_REGION],
    env=cdk.Environment(account=os.environ.get("CDK_DEFAULT_ACCOUNT"), region=PRIMARY_REGION),
)

app.synth()
