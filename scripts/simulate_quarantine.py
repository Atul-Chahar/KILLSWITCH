#!/usr/bin/env python3
"""Fire the quarantine trigger on purpose, because AWS will never fire it for us.

AWS's compromised-key quarantine only reacts to keys it finds in public exposure, and
the demo repository is deliberately private. Without this script the second trigger
could not be tested or shown at all, so it is simulated openly rather than implied.

It publishes an event shaped exactly like the CloudTrail AttachUserPolicy record that
EventBridge would deliver. Nothing is attached, and no IAM state changes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402

from shared.guards import (  # noqa: E402
    WrongAccountError,
    demo_account_id_from_env,
    mask_account_id,
    require_demo_account,
)

QUARANTINE_POLICY_ARN = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"


def quarantine_detail(user_name: str, account_id: str) -> dict[str, Any]:
    return {
        "eventVersion": "1.08",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "recipientAccountId": account_id,
        "requestParameters": {"userName": user_name, "policyArn": QUARANTINE_POLICY_ARN},
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-name", default="demo-leaky-user")
    parser.add_argument("--region", help="the region the detection stack was deployed to")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    region = args.region or os.environ.get("AWS_REGION")
    if not region:
        print("Set AWS_REGION or pass --region.", file=sys.stderr)
        return 2

    session = boto3.Session(region_name=region)
    try:
        expected_account = demo_account_id_from_env()
        account = require_demo_account(session.client("sts"), expected_account)
    except WrongAccountError as error:
        print(f"REFUSING TO RUN: {error}", file=sys.stderr)
        return 3

    detail = quarantine_detail(args.user_name, account)
    response = session.client("events").put_events(
        Entries=[
            {
                "Source": "aws.iam",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(detail),
            }
        ]
    )

    failed = response.get("FailedEntryCount", 0)
    print(
        f"published simulated quarantine for {args.user_name} "
        f"in account {mask_account_id(account)} ({region})"
    )
    if failed:
        print(f"FAILED to publish {failed} entr(y/ies): {response}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
