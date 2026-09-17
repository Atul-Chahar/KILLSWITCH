#!/usr/bin/env python3
"""Launch the attack KILLSWITCH answers: a leaked key starting instances in two regions.

Run this with the LEAKED demo key in the environment, never with your own credentials.
It refuses to run against any account other than DEMO_ACCOUNT_ID.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from shared.guards import (  # noqa: E402
    WrongAccountError,
    demo_account_id_from_env,
    mask_account_id,
    require_demo_account,
)

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
DEMO_TAG_KEY = "demo"
DEMO_TAG_VALUE = "killswitch-attack"
INSTANCE_TYPE = "t3.micro"


class Timeline:
    """Prints each step as it happens, with wall-clock and elapsed time, for the video."""

    def __init__(self) -> None:
        self._started = time.monotonic()

    def mark(self, message: str) -> None:
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        elapsed = time.monotonic() - self._started
        print(f"{stamp}  +{elapsed:6.1f}s  {message}", flush=True)


def resolve_ami(ssm_client: Any, parameter: str = AMI_PARAMETER) -> str:
    return str(ssm_client.get_parameter(Name=parameter)["Parameter"]["Value"])


def launch_instance(
    ec2_client: Any,
    ami_id: str,
    *,
    instance_type: str = INSTANCE_TYPE,
    tag_key: str = DEMO_TAG_KEY,
    tag_value: str = DEMO_TAG_VALUE,
) -> str:
    """Launch one instance, tagged at launch time, and return its id."""
    response = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": tag_key, "Value": tag_value}]}
        ],
    )
    return str(response["Instances"][0]["InstanceId"])


def attack_region(session: Any, region: str, timeline: Timeline, *, dry_run: bool) -> str:
    """Resolve an AMI and launch one instance in a single region. Returns the instance id."""
    ssm_client = session.client("ssm", region_name=region)
    ami_id = resolve_ami(ssm_client)
    timeline.mark(f"{region}: resolved Amazon Linux AMI {ami_id}")

    if dry_run:
        timeline.mark(f"{region}: DRY RUN, not calling RunInstances")
        return "i-dryrun"

    ec2_client = session.client("ec2", region_name=region)
    instance_id = launch_instance(ec2_client, ami_id)
    tag = f"{DEMO_TAG_KEY}={DEMO_TAG_VALUE}"
    timeline.mark(f"{region}: launched {instance_id} ({INSTANCE_TYPE}, tagged {tag})")
    return instance_id


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--regions",
        nargs="+",
        metavar="REGION",
        help="demo regions to attack (default: AWS_REGION and AWS_SECONDARY_REGION)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve the AMI and print the plan, but launch nothing",
    )
    return parser.parse_args(argv)


def regions_from_env(env: dict[str, str]) -> list[str]:
    regions = [env.get("AWS_REGION", "").strip(), env.get("AWS_SECONDARY_REGION", "").strip()]
    return [region for region in regions if region]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    timeline = Timeline()

    regions = args.regions or regions_from_env(dict(os.environ))
    if len(regions) < 2:
        print(
            "Set AWS_REGION and AWS_SECONDARY_REGION, or pass --regions. "
            "The demo attack runs in two regions.",
            file=sys.stderr,
        )
        return 2

    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        print("No AWS credentials in the environment. Load the leaked demo key.", file=sys.stderr)
        return 2

    try:
        expected_account = demo_account_id_from_env()
        account = require_demo_account(session.client("sts"), expected_account)
    except WrongAccountError as error:
        print(f"REFUSING TO RUN: {error}", file=sys.stderr)
        return 3

    timeline.mark(
        f"using access key {credentials.access_key} in account {mask_account_id(account)}"
    )
    timeline.mark(f"target regions: {', '.join(regions)}")

    launched: list[str] = []
    failures: list[str] = []
    for region in regions:
        try:
            launched.append(attack_region(session, region, timeline, dry_run=args.dry_run))
        except (ClientError, BotoCoreError) as error:
            failures.append(f"{region}: {error}")
            timeline.mark(f"{region}: FAILED, {error}")

    print()
    print(f"launched {len(launched)} instance(s): {', '.join(launched) or 'none'}")
    print(f"access key to investigate: {credentials.access_key}")
    print(f"read it back with: python scripts/lookup.py {credentials.access_key} --wait 900")

    if failures:
        print()
        print("FAILURES (the attack did not fully run):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
