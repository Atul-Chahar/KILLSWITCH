"""Reading CloudTrail. Pagination, throttling and unreadable records, handled honestly."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from botocore.exceptions import ClientError

# CloudTrail allows two lookup requests per second, per account, per region.
PAGE_PAUSE_SECONDS = 0.5
THROTTLE_BACKOFF_SECONDS = 2.0
MAX_THROTTLE_RETRIES = 5
MAX_RESULTS_PER_PAGE = 50
THROTTLE_CODES = {"ThrottlingException", "Throttling"}


class EvidenceError(RuntimeError):
    """Raised when a CloudTrail record cannot be read. Never downgraded to a warning."""


def _lookup_with_retry(cloudtrail_client: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    for attempt in range(MAX_THROTTLE_RETRIES):
        try:
            return dict(cloudtrail_client.lookup_events(**kwargs))
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code not in THROTTLE_CODES or attempt == MAX_THROTTLE_RETRIES - 1:
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
    """Every event CloudTrail holds for this key in one region, following pagination.

    LookupEvents takes a single lookup attribute, so filtering by event name as well
    has to happen on our side rather than in the request.
    """
    records: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": MAX_RESULTS_PER_PAGE,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        response = _lookup_with_retry(cloudtrail_client, kwargs)
        records.extend(response.get("Events", []))
        next_token = response.get("NextToken")
        if not next_token:
            return records
        time.sleep(PAGE_PAUSE_SECONDS)


def event_detail(record: dict[str, Any]) -> dict[str, Any]:
    """The parsed CloudTrailEvent body, or an error. An unreadable event is never skipped."""
    raw = record.get("CloudTrailEvent")
    if not raw:
        raise EvidenceError(f"event {record.get('EventId', '<unknown>')} has no CloudTrailEvent")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        event_id = record.get("EventId", "<unknown>")
        raise EvidenceError(f"event {event_id} has an unparseable CloudTrailEvent") from error
    if not isinstance(parsed, dict):
        raise EvidenceError(f"event {record.get('EventId', '<unknown>')} is not a JSON object")
    return parsed


def instance_ids(detail: dict[str, Any], record: dict[str, Any]) -> tuple[str, ...]:
    """Instance ids from the response body, falling back to the resource list."""
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
