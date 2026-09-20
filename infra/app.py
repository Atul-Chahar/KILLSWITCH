#!/usr/bin/env python3
"""CDK entry point. Run through the cdk CLI from the repository root: `cdk synth`."""

from __future__ import annotations

import os
from pathlib import Path

import aws_cdk as cdk

from infra.stacks.console_api import ConsoleApiStack
from infra.stacks.demo_target import DemoTargetStack
from infra.stacks.detection import DetectionStack
from infra.stacks.response import ResponseStack

PRIMARY_REGION = os.environ.get("AWS_REGION", "ap-south-1")
SECONDARY_REGION = os.environ.get("AWS_SECONDARY_REGION", "us-east-1")
LAMBDA_CODE_PATH = Path("build/lambda")

if not LAMBDA_CODE_PATH.is_dir():
    raise SystemExit(
        f"{LAMBDA_CODE_PATH} does not exist. Run `make lambda-package` before synth or deploy."
    )

app = cdk.App()
env = cdk.Environment(account=os.environ.get("CDK_DEFAULT_ACCOUNT"), region=PRIMARY_REGION)

DemoTargetStack(
    app,
    "KillswitchDemoTarget",
    demo_regions=[PRIMARY_REGION, SECONDARY_REGION],
    env=env,
)

detection = DetectionStack(
    app,
    "KillswitchDetection",
    lambda_code_path=str(LAMBDA_CODE_PATH),
    github_webhook_secret=os.environ.get("GITHUB_WEBHOOK_SECRET", ""),
    github_app_token=os.environ.get("GITHUB_APP_TOKEN", ""),
    env=env,
)

response = ResponseStack(
    app,
    "KillswitchResponse",
    lambda_code_path=str(LAMBDA_CODE_PATH),
    incidents_table=detection.incidents,
    demo_regions=[PRIMARY_REGION, SECONDARY_REGION],
    bedrock_model_id=os.environ.get("BEDROCK_MODEL_ID", ""),
    narrator_mode=os.environ.get("NARRATOR_MODE", ""),
    nvidia_api_key=os.environ.get("NVIDIA_API_KEY", ""),
    nim_model_id=os.environ.get("NIM_MODEL_ID", ""),
    # Some accounts and regions cannot create a policy store at all. Set
    # USE_VERIFIED_PERMISSIONS=false to deploy on the strict fallback table instead.
    use_verified_permissions=os.environ.get("USE_VERIFIED_PERMISSIONS", "true").lower()
    not in {"false", "0", "no"},
    env=env,
)

ConsoleApiStack(
    app,
    "KillswitchConsoleApi",
    lambda_code_path=str(LAMBDA_CODE_PATH),
    incidents_table=detection.incidents,
    state_machine=response.state_machine,
    env=env,
)

app.synth()
