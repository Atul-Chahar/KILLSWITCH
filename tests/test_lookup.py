"""Reading the evidence back. A missing event must never look like a clean result."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

EVENT_TIME = datetime(2026, 9, 18, 10, 30, 0, tzinfo=UTC)
SYNTHETIC_KEY = "AKIA" + "TESTFAKEKEY00001"


def cloudtrail_record(
    *,
    event_id: str = "11111111-2222-3333-4444-555555555555",
    event_name: str = "RunInstances",
    region: str = "ap-south-1",
    source_ip: str = "203.0.113.10",
    instance_ids: tuple[str, ...] = ("i-0abc123def4567890",),
    include_response_elements: bool = True,
    resources: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "eventVersion": "1.08",
        "eventTime": EVENT_TIME.isoformat(),
        "eventSource": "ec2.amazonaws.com",
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userIdentity": {"type": "IAMUser", "userName": "demo-leaky-user"},
    }
    if include_response_elements:
        detail["responseElements"] = {
            "instancesSet": {"items": [{"instanceId": i} for i in instance_ids]}
        }
    return {
        "EventId": event_id,
        "EventName": event_name,
        "EventTime": EVENT_TIME,
        "Username": "demo-leaky-user",
        "Resources": resources or [],
        "CloudTrailEvent": json.dumps(detail),
    }


class StubCloudTrail:
    """Serves prepared pages and records the kwargs it was called with."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def lookup_events(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.pages[len(self.calls) - 1]


class StubSession:
    def __init__(self, per_region: dict[str, Any]) -> None:
        self._per_region = per_region

    def client(self, service: str, region_name: str) -> Any:
        assert service == "cloudtrail"
        return self._per_region[region_name]


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch, lookup):
    monkeypatch.setattr(lookup.time, "sleep", lambda _seconds: None)


def test_summarise_event_reads_instance_ids_from_the_response(lookup):
    summary = lookup.summarise_event(cloudtrail_record())

    assert summary.instance_ids == ("i-0abc123def4567890",)
    assert summary.region == "ap-south-1"
    assert summary.source_ip == "203.0.113.10"
    assert summary.event_name == "RunInstances"


def test_summarise_event_falls_back_to_the_resources_list(lookup):
    record = cloudtrail_record(
        include_response_elements=False,
        resources=[{"ResourceType": "AWS::EC2::Instance", "ResourceName": "i-0fallback00000001"}],
    )

    assert lookup.summarise_event(record).instance_ids == ("i-0fallback00000001",)


def test_an_event_with_no_instance_id_is_reported_not_invented(lookup):
    record = cloudtrail_record(include_response_elements=False, resources=[])

    assert lookup.summarise_event(record).instance_ids == ()


def test_an_unreadable_event_body_raises(lookup):
    record = cloudtrail_record()
    record["CloudTrailEvent"] = "{not json"

    with pytest.raises(lookup.EvidenceError, match="unparseable"):
        lookup.summarise_event(record)


def test_a_missing_event_body_raises(lookup):
    record = cloudtrail_record()
    del record["CloudTrailEvent"]

    with pytest.raises(lookup.EvidenceError, match="no CloudTrailEvent body"):
        lookup.summarise_event(record)


def test_lookup_filters_by_access_key_id(lookup):
    client = StubCloudTrail([{"Events": [cloudtrail_record()]}])

    lookup.lookup_by_access_key(client, SYNTHETIC_KEY, start_time=EVENT_TIME, end_time=EVENT_TIME)

    attribute = client.calls[0]["LookupAttributes"][0]
    assert attribute["AttributeKey"] == "AccessKeyId"
    assert attribute["AttributeValue"] == SYNTHETIC_KEY


def test_lookup_follows_pagination_to_the_end(lookup):
    client = StubCloudTrail(
        [
            {"Events": [cloudtrail_record(event_id="page-1")], "NextToken": "more"},
            {"Events": [cloudtrail_record(event_id="page-2")]},
        ]
    )

    records = lookup.lookup_by_access_key(
        client, SYNTHETIC_KEY, start_time=EVENT_TIME, end_time=EVENT_TIME
    )

    assert [record["EventId"] for record in records] == ["page-1", "page-2"]
    assert client.calls[1]["NextToken"] == "more"


def test_collect_gathers_both_regions_and_filters_by_event_name(lookup):
    session = StubSession(
        {
            "ap-south-1": StubCloudTrail(
                [
                    {
                        "Events": [
                            cloudtrail_record(event_id="run-1"),
                            cloudtrail_record(
                                event_id="describe-1", event_name="DescribeInstances"
                            ),
                        ]
                    }
                ]
            ),
            "us-east-1": StubCloudTrail(
                [{"Events": [cloudtrail_record(event_id="run-2", region="us-east-1")]}]
            ),
        }
    )

    summaries, problems = lookup.collect(
        session,
        SYNTHETIC_KEY,
        ["ap-south-1", "us-east-1"],
        hours=3,
        event_name="RunInstances",
    )

    assert problems == []
    assert {summary.event_id for summary in summaries} == {"run-1", "run-2"}


def test_collect_reports_a_region_with_no_events_without_failing(lookup):
    session = StubSession({"ap-south-1": StubCloudTrail([{"Events": []}])})

    summaries, problems = lookup.collect(
        session, SYNTHETIC_KEY, ["ap-south-1"], hours=3, event_name=None
    )

    assert summaries == []
    assert problems == []


def test_collect_surfaces_unreadable_evidence_as_a_problem(lookup):
    broken = cloudtrail_record()
    broken["CloudTrailEvent"] = "{not json"
    session = StubSession({"ap-south-1": StubCloudTrail([{"Events": [broken]}])})

    summaries, problems = lookup.collect(
        session, SYNTHETIC_KEY, ["ap-south-1"], hours=3, event_name=None
    )

    assert summaries == []
    assert len(problems) == 1, "unreadable evidence must be reported, never dropped"
