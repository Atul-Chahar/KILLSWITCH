#!/usr/bin/env python3
"""Capture a real CloudTrail response into a test fixture, scrubbed before it is written.

Account ids and ARNs hide inside the CloudTrailEvent field, which is itself a JSON
string. Scrubbing only the outer record would leave them in the repository, so the
nested body is parsed, scrubbed and re-serialised.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402

from investigate.cloudtrail import lookup_by_access_key  # noqa: E402
from shared.guards import (  # noqa: E402
    WrongAccountError,
    demo_account_id_from_env,
    require_demo_account,
)

SCRUBBED_ACCOUNT_ID = "000000000000"
SCRUBBED_IP = "203.0.113.10"
SCRUBBED_USER_AGENT = "scrubbed"
# AWS's own documented example. A real-looking key id here would fail check_secrets.sh.
SCRUBBED_ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

ACCOUNT_ID_PATTERN = re.compile(r"\b\d{12}\b")
ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def scrub_text(text: str) -> str:
    text = ACCOUNT_ID_PATTERN.sub(SCRUBBED_ACCOUNT_ID, text)
    text = ACCESS_KEY_PATTERN.sub(SCRUBBED_ACCESS_KEY, text)
    return IP_PATTERN.sub(SCRUBBED_IP, text)


def scrub_value(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {name: scrub_value(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [scrub_value(item) for item in value]
    if isinstance(value, str):
        if key == "userAgent":
            return SCRUBBED_USER_AGENT
        if key in {"sourceIPAddress", "sourceIpAddress"}:
            return SCRUBBED_IP
        return scrub_text(value)
    return value


def scrub_record(record: dict[str, Any]) -> dict[str, Any]:
    """Scrub the record, including the JSON document buried in CloudTrailEvent."""
    scrubbed = dict(record)

    raw = scrubbed.get("CloudTrailEvent")
    if isinstance(raw, str):
        detail = scrub_value(json.loads(raw))
        scrubbed["CloudTrailEvent"] = json.dumps(detail, separators=(",", ":"))

    event_time = scrubbed.get("EventTime")
    if isinstance(event_time, datetime):
        scrubbed["EventTime"] = event_time.astimezone(UTC).isoformat()

    for field in ("EventId", "EventName", "ReadOnly", "EventSource", "Username", "Resources"):
        if field in scrubbed:
            scrubbed[field] = scrub_value(scrubbed[field], field)
    if "AccessKeyId" in scrubbed:
        scrubbed["AccessKeyId"] = SCRUBBED_ACCESS_KEY
    return scrubbed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("access_key_id")
    parser.add_argument("--region", required=True)
    parser.add_argument("--hours", type=int, default=3)
    parser.add_argument("--out", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    session = boto3.Session(region_name=args.region)

    try:
        require_demo_account(session.client("sts"), demo_account_id_from_env())
    except WrongAccountError as error:
        print(f"REFUSING TO RUN: {error}", file=sys.stderr)
        return 3

    end_time = datetime.now(UTC)
    records = lookup_by_access_key(
        session.client("cloudtrail", region_name=args.region),
        args.access_key_id,
        start_time=end_time - timedelta(hours=args.hours),
        end_time=end_time,
    )
    if not records:
        print("no events found, nothing captured", file=sys.stderr)
        return 1

    payload = {"Events": [scrub_record(record) for record in records]}
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {len(records)} scrubbed event(s) to {args.out}")
    print("Read it before committing. The scrubber is a helper, not a guarantee.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
