#!/usr/bin/env python3
"""Read back, from CloudTrail, exactly what one access key did in the demo regions.

CloudTrail Event History is not instant. Use --wait to poll until the events land
rather than concluding, wrongly, that the key did nothing.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402

from investigate.blast_radius import BlastRadius, build_blast_radius  # noqa: E402
from shared.guards import (  # noqa: E402
    WrongAccountError,
    demo_account_id_from_env,
    mask_account_id,
    require_demo_account,
)

POLL_INTERVAL_SECONDS = 30


def print_report(radius: BlastRadius) -> None:
    if not radius.resources:
        print("no resources created by this key were found yet")
    else:
        print(f"{'created (UTC)':<22} {'region':<14} {'event':<16} {'source ip':<16} resource")
        for resource in radius.resources:
            when = resource.event_time.astimezone(UTC).isoformat(timespec="seconds")
            print(
                f"{when:<22} {resource.region:<14} {resource.event_name:<16} "
                f"{resource.source_ip:<16} {resource.resource_id}"
            )

    if radius.problems:
        print()
        print("EVIDENCE IS INCOMPLETE. Do not read this as a clean result:", file=sys.stderr)
        for problem in radius.problems:
            detail = f" ({problem.aws_error_code})" if problem.aws_error_code else ""
            print(f"  {problem.kind} in {problem.region}{detail}", file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("access_key_id", help="the leaked access key id to investigate")
    parser.add_argument("--regions", nargs="+", metavar="REGION")
    parser.add_argument("--hours", type=int, default=3, help="how far back to look (default 3)")
    parser.add_argument(
        "--wait",
        type=int,
        default=0,
        metavar="SECONDS",
        help="poll until at least one resource appears, for up to this many seconds",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    regions = args.regions or [
        region
        for region in (os.environ.get("AWS_REGION", ""), os.environ.get("AWS_SECONDARY_REGION", ""))
        if region
    ]
    if not regions:
        print("Set AWS_REGION and AWS_SECONDARY_REGION, or pass --regions.", file=sys.stderr)
        return 2

    session = boto3.Session()
    try:
        expected_account = demo_account_id_from_env()
        account = require_demo_account(session.client("sts"), expected_account)
    except WrongAccountError as error:
        print(f"REFUSING TO RUN: {error}", file=sys.stderr)
        return 3

    print(
        f"looking up {args.access_key_id} in account {mask_account_id(account)} "
        f"across {', '.join(regions)}"
    )

    deadline = time.monotonic() + args.wait
    while True:
        radius = build_blast_radius(session, args.access_key_id, regions, hours=args.hours)
        if radius.resources or time.monotonic() >= deadline:
            break
        print("nothing in CloudTrail yet, waiting 30s (Event History is not instant)", flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)

    print()
    print_report(radius)
    return 0 if radius.is_complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
