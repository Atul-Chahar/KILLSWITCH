#!/usr/bin/env python3
"""Read back, from CloudTrail, exactly what one access key did in the demo regions.

CloudTrail Event History is not instant. Use --wait to poll until the events land
rather than concluding, wrongly, that the key did nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from shared.guards import (  # noqa: E402
    WrongAccountError,
    demo_account_id_from_env,
    mask_account_id,
    require_demo_account,
)

# CloudTrail allows two lookup requests per second, per account, per region.
PAGE_PAUSE_SECONDS = 0.5
THROTTLE_BACKOFF_SECONDS = 2.0
MAX_THROTTLE_RETRIES = 5
POLL_INTERVAL_SECONDS = 30


class EvidenceError(RuntimeError):
    """Raised when a CloudTrail record cannot be read. Never downgraded to a warning."""


@dataclass(frozen=True)
class EventSummary:
    event_id: str
    event_time: datetime
    event_name: str
    region: str
    source_ip: str
    instance_ids: tuple[str, ...]


def _instance_ids_from_detail(detail: dict[str, Any], record: dict[str, Any]) -> tuple[str, ...]:
    response_elements = detail.get("responseElements") or {}
    items = (response_elements.get("instancesSet") or {}).get("items") or []
    from_response = tuple(
        str(item["instanceId"]) for item in items if isinstance(item, dict) and "instanceId" in item
    )
    if from_response:
        return from_response
    return tuple(
        str(resource["ResourceName"])
        for resource in record.get("Resources", [])
        if resource.get("ResourceType") == "AWS::EC2::Instance" and resource.get("ResourceName")
    )


def summarise_event(record: dict[str, Any]) -> EventSummary:
    """Turn one LookupEvents record into a summary, or raise if the evidence is unreadable."""
    raw = record.get("CloudTrailEvent")
    if not raw:
        raise EvidenceError(
            f"event {record.get('EventId', '<unknown>')} has no CloudTrailEvent body"
        )
    try:
        detail = json.loads(raw)
    except json.JSONDecodeError as error:
        event_id = record.get("EventId", "<unknown>")
        raise EvidenceError(
            f"event {event_id} has an unparseable CloudTrailEvent: {error}"
        ) from error

    return EventSummary(
        event_id=str(record.get("EventId", "")),
        event_time=record["EventTime"],
        event_name=str(record.get("EventName", detail.get("eventName", ""))),
        region=str(detail.get("awsRegion", "")),
        source_ip=str(detail.get("sourceIPAddress", "")),
        instance_ids=_instance_ids_from_detail(detail, record),
    )


def _lookup_with_retry(cloudtrail_client: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    for attempt in range(MAX_THROTTLE_RETRIES):
        try:
            return dict(cloudtrail_client.lookup_events(**kwargs))
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code not in {"ThrottlingException", "Throttling"}:
                raise
            if attempt == MAX_THROTTLE_RETRIES - 1:
                raise
            time.sleep(THROTTLE_BACKOFF_SECONDS * (attempt + 1))
    raise EvidenceError("unreachable: retry loop exited without a result")


def lookup_by_access_key(
    cloudtrail_client: Any,
    access_key_id: str,
    *,
    start_time: datetime,
    end_time: datetime,
) -> list[dict[str, Any]]:
    """Every event CloudTrail has for this key in one region, following pagination.

    LookupEvents accepts a single lookup attribute, so the event name is filtered by
    the caller rather than server side.
    """
    records: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": 50,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        response = _lookup_with_retry(cloudtrail_client, kwargs)
        records.extend(response.get("Events", []))
        next_token = response.get("NextToken")
        if not next_token:
            return records
        time.sleep(PAGE_PAUSE_SECONDS)


def collect(
    session: Any,
    access_key_id: str,
    regions: list[str],
    *,
    hours: int,
    event_name: str | None,
) -> tuple[list[EventSummary], list[str]]:
    """Returns (summaries, problems). Problems are never silently dropped."""
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(hours=hours)
    summaries: list[EventSummary] = []
    problems: list[str] = []

    for region in regions:
        client = session.client("cloudtrail", region_name=region)
        try:
            records = lookup_by_access_key(
                client, access_key_id, start_time=start_time, end_time=end_time
            )
        except ClientError as error:
            problems.append(f"{region}: CloudTrail lookup failed: {error}")
            continue

        for record in records:
            try:
                summary = summarise_event(record)
            except EvidenceError as error:
                problems.append(f"{region}: {error}")
                continue
            if event_name is None or summary.event_name == event_name:
                summaries.append(summary)

    summaries.sort(key=lambda item: item.event_time)
    return summaries, problems


def print_table(summaries: list[EventSummary]) -> None:
    if not summaries:
        print("no matching events found yet")
        return
    print(f"{'event time (UTC)':<22} {'region':<14} {'event':<16} {'source ip':<16} instances")
    for item in summaries:
        instances = ", ".join(item.instance_ids) or "-"
        when = item.event_time.astimezone(UTC).isoformat(timespec="seconds")
        print(
            f"{when:<22} {item.region:<14} {item.event_name:<16} {item.source_ip:<16} {instances}"
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("access_key_id", help="the leaked access key id to investigate")
    parser.add_argument("--regions", nargs="+", metavar="REGION")
    parser.add_argument("--hours", type=int, default=3, help="how far back to look (default 3)")
    parser.add_argument(
        "--event-name",
        default="RunInstances",
        help="only show this event name, or 'all' for everything (default RunInstances)",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=0,
        metavar="SECONDS",
        help="poll until at least one event appears, for up to this many seconds",
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

    event_name = None if args.event_name == "all" else args.event_name
    print(
        f"looking up {args.access_key_id} in account {mask_account_id(account)} "
        f"across {', '.join(regions)}"
    )

    deadline = time.monotonic() + args.wait
    while True:
        summaries, problems = collect(
            session, args.access_key_id, regions, hours=args.hours, event_name=event_name
        )
        if summaries or time.monotonic() >= deadline:
            break
        print("nothing in CloudTrail yet, waiting 30s (Event History is not instant)", flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)

    print()
    print_table(summaries)

    if problems:
        print()
        print(
            "PROBLEMS (evidence is incomplete, do not treat this as a clean result):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
