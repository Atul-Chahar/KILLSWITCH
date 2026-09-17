"""What the leaked key actually created, as typed facts the verifier can check against.

Nothing in the return value is prose. Every field is an id, an enum, a timestamp or an
AWS error code, because the verifier and the console both have to reason about it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from botocore.exceptions import ClientError
from pydantic import BaseModel, Field

from investigate.cloudtrail import EvidenceError, event_detail, instance_ids, lookup_by_access_key

DEFAULT_WINDOW_HOURS = 3


class ResourceKind(StrEnum):
    EC2_INSTANCE = "ec2_instance"


# Only events that bring a resource into existence count. A Describe call tells us the
# key was used, but it creates nothing for containment to act on.
CREATION_EVENTS: dict[str, ResourceKind] = {
    "RunInstances": ResourceKind.EC2_INSTANCE,
}


class ProblemKind(StrEnum):
    REGION_LOOKUP_FAILED = "region_lookup_failed"
    UNREADABLE_EVENT = "unreadable_event"
    CREATION_EVENT_WITHOUT_RESOURCE_ID = "creation_event_without_resource_id"


class EvidenceProblem(BaseModel):
    kind: ProblemKind
    region: str
    event_id: str | None = None
    aws_error_code: str | None = None


class CreatedResource(BaseModel):
    resource_id: str
    kind: ResourceKind
    event_name: str
    region: str
    event_time: datetime
    source_ip: str
    event_id: str


class BlastRadius(BaseModel):
    access_key_id: str
    regions_searched: list[str]
    window_start: datetime
    window_end: datetime
    resources: list[CreatedResource] = Field(default_factory=list)
    problems: list[EvidenceProblem] = Field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """False whenever any evidence was missing. Callers must not treat gaps as clean."""
        return not self.problems

    def resource_ids(self) -> set[str]:
        return {resource.resource_id for resource in self.resources}


def resources_from_record(
    record: dict[str, Any], region: str
) -> tuple[list[CreatedResource], list[EvidenceProblem]]:
    """Turn one CloudTrail record into created resources, or into a recorded problem."""
    event_name = str(record.get("EventName", ""))
    kind = CREATION_EVENTS.get(event_name)
    if kind is None:
        return [], []

    try:
        detail = event_detail(record)
    except EvidenceError:
        return [], [
            EvidenceProblem(
                kind=ProblemKind.UNREADABLE_EVENT,
                region=region,
                event_id=str(record.get("EventId")) if record.get("EventId") else None,
            )
        ]

    event_id = str(record.get("EventId", ""))
    ids = instance_ids(detail, record)
    if not ids:
        # The key demonstrably created something and we cannot say what. That is a gap
        # in the evidence, not an empty result.
        return [], [
            EvidenceProblem(
                kind=ProblemKind.CREATION_EVENT_WITHOUT_RESOURCE_ID,
                region=region,
                event_id=event_id or None,
            )
        ]

    return [
        CreatedResource(
            resource_id=resource_id,
            kind=kind,
            event_name=event_name,
            region=str(detail.get("awsRegion", region)),
            event_time=record["EventTime"],
            source_ip=str(detail.get("sourceIPAddress", "")),
            event_id=event_id,
        )
        for resource_id in ids
    ], []


def build_blast_radius(
    session: Any,
    access_key_id: str,
    regions: list[str],
    *,
    hours: int = DEFAULT_WINDOW_HOURS,
    now: datetime | None = None,
) -> BlastRadius:
    """Everything this key created across the given regions, with every gap recorded."""
    window_end = now or datetime.now(UTC)
    window_start = window_end - timedelta(hours=hours)

    resources: list[CreatedResource] = []
    problems: list[EvidenceProblem] = []

    for region in regions:
        client = session.client("cloudtrail", region_name=region)
        try:
            records = lookup_by_access_key(
                client, access_key_id, start_time=window_start, end_time=window_end
            )
        except ClientError as error:
            problems.append(
                EvidenceProblem(
                    kind=ProblemKind.REGION_LOOKUP_FAILED,
                    region=region,
                    aws_error_code=str(error.response.get("Error", {}).get("Code", "")) or None,
                )
            )
            continue

        for record in records:
            found, issues = resources_from_record(record, region)
            resources.extend(found)
            problems.extend(issues)

    resources.sort(key=lambda resource: (resource.event_time, resource.resource_id))
    return BlastRadius(
        access_key_id=access_key_id,
        regions_searched=list(regions),
        window_start=window_start,
        window_end=window_end,
        resources=resources,
        problems=problems,
    )
