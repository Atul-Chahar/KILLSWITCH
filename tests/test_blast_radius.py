"""The blast radius, built from CloudTrail fixtures. Gaps in evidence must stay visible."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

from investigate.blast_radius import (
    BlastRadius,
    ProblemKind,
    ResourceKind,
    build_blast_radius,
    resources_from_record,
)

FIXTURES = Path(__file__).parent / "fixtures"
KEY = "AKIA" + "IOSFODNN7EXAMPLE"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)


def load_fixture(name: str) -> dict[str, Any]:
    """Fixtures store EventTime as a string; boto3 hands back datetimes."""
    payload = json.loads((FIXTURES / name).read_text())
    for event in payload["Events"]:
        event["EventTime"] = datetime.fromisoformat(event["EventTime"])
    return payload


class StubCloudTrail:
    def __init__(
        self, pages: list[dict[str, Any]] | None = None, error: ClientError | None = None
    ) -> None:
        self.pages = pages or []
        self.error = error
        self.calls = 0

    def lookup_events(self, **kwargs: Any) -> dict[str, Any]:
        if self.error:
            raise self.error
        self.calls += 1
        return self.pages[self.calls - 1]


class StubSession:
    def __init__(self, per_region: dict[str, StubCloudTrail]) -> None:
        self._per_region = per_region

    def client(self, service: str, region_name: str) -> StubCloudTrail:
        assert service == "cloudtrail"
        return self._per_region[region_name]


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    import investigate.cloudtrail as cloudtrail

    monkeypatch.setattr(cloudtrail.time, "sleep", lambda _seconds: None)


def ap_south_client() -> StubCloudTrail:
    return StubCloudTrail([load_fixture("cloudtrail_ap_south_1.json")])


def us_east_client() -> StubCloudTrail:
    """The us-east-1 fixture carries a NextToken, so a second, empty page follows it."""
    return StubCloudTrail([load_fixture("cloudtrail_us_east_1.json"), {"Events": []}])


def ap_south_only() -> StubSession:
    return StubSession({"ap-south-1": ap_south_client()})


def test_the_fixture_yields_the_instance_the_key_launched():
    radius = build_blast_radius(ap_south_only(), KEY, ["ap-south-1"], now=NOW)

    assert [resource.resource_id for resource in radius.resources] == ["i-0a1b2c3d4e5f60001"]
    resource = radius.resources[0]
    assert resource.kind is ResourceKind.EC2_INSTANCE
    assert resource.region == "ap-south-1"
    assert resource.source_ip == "203.0.113.10"
    assert resource.event_name == "RunInstances"
    assert resource.event_time == datetime(2026, 9, 18, 10, 12, 41, tzinfo=UTC)


def test_read_only_calls_create_nothing():
    """The fixture also holds a DescribeInstances. Using a key is not creating a resource."""
    radius = build_blast_radius(ap_south_only(), KEY, ["ap-south-1"], now=NOW)

    assert len(radius.resources) == 1
    assert radius.is_complete


def test_both_regions_are_searched_and_merged():
    session = StubSession({"ap-south-1": ap_south_client(), "us-east-1": us_east_client()})

    radius = build_blast_radius(session, KEY, ["ap-south-1", "us-east-1"], now=NOW)

    assert radius.resource_ids() == {"i-0a1b2c3d4e5f60001", "i-0f9e8d7c6b5a40002"}
    assert radius.regions_searched == ["ap-south-1", "us-east-1"]


def test_pagination_is_followed_before_the_region_is_called_done():
    """The us-east-1 fixture carries a NextToken; stopping there would lose evidence."""
    client = us_east_client()

    build_blast_radius(StubSession({"us-east-1": client}), KEY, ["us-east-1"], now=NOW)

    assert client.calls == 2


def test_a_region_with_no_events_is_simply_empty():
    session = StubSession({"eu-west-1": StubCloudTrail([{"Events": []}])})

    radius = build_blast_radius(session, KEY, ["eu-west-1"], now=NOW)

    assert radius.resources == []
    assert radius.problems == []
    assert radius.is_complete


def test_a_failed_region_is_recorded_not_swallowed():
    error = ClientError({"Error": {"Code": "AccessDeniedException"}}, "LookupEvents")
    session = StubSession(
        {"ap-south-1": ap_south_client(), "us-east-1": StubCloudTrail(error=error)}
    )

    radius = build_blast_radius(session, KEY, ["ap-south-1", "us-east-1"], now=NOW)

    assert len(radius.resources) == 1, "the region that worked still contributes"
    assert not radius.is_complete, "a half-searched account must never look clean"
    (problem,) = radius.problems
    assert problem.kind is ProblemKind.REGION_LOOKUP_FAILED
    assert problem.region == "us-east-1"
    assert problem.aws_error_code == "AccessDeniedException"


def test_an_unreadable_event_is_recorded_as_a_problem():
    payload = load_fixture("cloudtrail_ap_south_1.json")
    payload["Events"][0]["CloudTrailEvent"] = "{not json"
    session = StubSession({"ap-south-1": StubCloudTrail([payload])})

    radius = build_blast_radius(session, KEY, ["ap-south-1"], now=NOW)

    assert radius.resources == []
    assert radius.problems[0].kind is ProblemKind.UNREADABLE_EVENT
    assert not radius.is_complete


def test_a_creation_event_with_no_resource_id_is_a_gap_not_an_empty_result():
    record = {
        "EventId": "no-ids",
        "EventName": "RunInstances",
        "EventTime": NOW,
        "Resources": [],
        "CloudTrailEvent": json.dumps({"awsRegion": "ap-south-1", "responseElements": None}),
    }

    resources, problems = resources_from_record(record, "ap-south-1")

    assert resources == []
    assert problems[0].kind is ProblemKind.CREATION_EVENT_WITHOUT_RESOURCE_ID


def test_resources_are_ordered_by_when_they_were_created():
    session = StubSession({"us-east-1": us_east_client(), "ap-south-1": ap_south_client()})

    radius = build_blast_radius(session, KEY, ["us-east-1", "ap-south-1"], now=NOW)

    times = [resource.event_time for resource in radius.resources]
    assert times == sorted(times)


def test_the_blast_radius_round_trips_through_json():
    """It crosses a Step Functions boundary, so it has to survive serialisation."""
    radius = build_blast_radius(ap_south_only(), KEY, ["ap-south-1"], now=NOW)

    restored = BlastRadius.model_validate_json(radius.model_dump_json())

    assert restored == radius
