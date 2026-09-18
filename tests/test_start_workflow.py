"""The wire between detection and the response workflow.

This file exists because it was missing. Every module had tests, the whole chain had an
end-to-end test, and none of them called the thing that starts an execution -- because
nothing did. A detected incident was written to DynamoDB and then sat there.
"""

from __future__ import annotations

from typing import Any

import pytest

from shared.approvals import APPROVAL_PREFIX, AUDIT_PREFIX, INCIDENT_SORT_KEY
from workflow.start import execution_name, new_incident_ids, start_workflows

STATE_MACHINE = "arn:aws:states:ap-south-1:000000000000:stateMachine:Response"
KEY = "AKIA" + "IOSFODNN7EXAMPLE"
INCIDENT_ID = f"inc-{KEY}"
DETECTED_AT = "2026-09-18T10:13:10+00:00"


class ExecutionAlreadyExists(Exception):
    """Named as boto3 names it, because that is what the handler matches on."""


class FakeStepFunctions:
    def __init__(self, *, already_started: set[str] | None = None) -> None:
        self.started: list[dict[str, Any]] = []
        self.already_started = already_started or set()

    def start_execution(self, **kwargs: Any) -> dict[str, Any]:
        if kwargs["name"] in self.already_started:
            raise ExecutionAlreadyExists(kwargs["name"])
        self.already_started.add(kwargs["name"])
        self.started.append(dict(kwargs))
        return {"executionArn": f"{STATE_MACHINE}:{kwargs['name']}"}


def record(
    *, sort_key: str = INCIDENT_SORT_KEY, event_name: str = "INSERT", incident_id: str = INCIDENT_ID
) -> dict[str, Any]:
    return {
        "eventName": event_name,
        "dynamodb": {
            "Keys": {"incident_id": {"S": incident_id}, "sk": {"S": sort_key}},
            "NewImage": {"detected_at": {"S": DETECTED_AT}},
        },
    }


@pytest.fixture
def step_functions() -> FakeStepFunctions:
    return FakeStepFunctions()


def test_a_new_incident_starts_the_response_workflow(step_functions):
    started = start_workflows({"Records": [record()]}, step_functions, STATE_MACHINE)

    assert started == [INCIDENT_ID]
    (call,) = step_functions.started
    assert call["stateMachineArn"] == STATE_MACHINE
    assert f'"{INCIDENT_ID}"' in call["input"]


def test_approval_and_audit_rows_are_not_incidents(step_functions):
    """They share the partition key, so an unfiltered stream would start a run per row."""
    event = {
        "Records": [
            record(sort_key=f"{APPROVAL_PREFIX}deactivate_key:{KEY}:-"),
            record(sort_key=f"{AUDIT_PREFIX}2026-09-18T10:13:10+00:00#0#abc"),
        ]
    }

    assert start_workflows(event, step_functions, STATE_MACHINE) == []
    assert step_functions.started == []


def test_updating_an_incident_does_not_start_a_second_run(step_functions):
    """Every stage writes artifacts back to the incident. Only the insert is a new one."""
    event = {"Records": [record(event_name="MODIFY")]}

    assert start_workflows(event, step_functions, STATE_MACHINE) == []
    assert step_functions.started == []


def test_a_redelivered_record_cannot_start_a_second_execution(step_functions):
    """Streams deliver at least once. The execution name is what makes that harmless."""
    event = {"Records": [record()]}

    first = start_workflows(event, step_functions, STATE_MACHINE)
    second = start_workflows(event, step_functions, STATE_MACHINE)

    assert first == [INCIDENT_ID]
    assert second == []
    assert len(step_functions.started) == 1


def test_both_triggers_racing_produce_one_execution(step_functions):
    """Only the conditional write that wins produces an INSERT, so only one run starts."""
    assert start_workflows({"Records": [record(), record()]}, step_functions, STATE_MACHINE) == [
        INCIDENT_ID
    ]
    assert len(step_functions.started) == 1


def test_a_failure_that_is_not_a_duplicate_is_not_swallowed(step_functions):
    class Broken(FakeStepFunctions):
        def start_execution(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("states is unavailable")

    with pytest.raises(RuntimeError):
        start_workflows({"Records": [record()]}, Broken(), STATE_MACHINE)


def test_the_execution_name_is_stable_for_one_incident_and_not_for_the_next():
    same = execution_name(INCIDENT_ID, DETECTED_AT)

    assert same == execution_name(INCIDENT_ID, DETECTED_AT)
    # Re-running the demo with the same key must not collide with a finished execution.
    assert same != execution_name(INCIDENT_ID, "2026-09-19T11:00:00+00:00")


def test_the_execution_name_is_one_step_functions_will_accept():
    name = execution_name(INCIDENT_ID, DETECTED_AT)

    assert 0 < len(name) <= 80
    assert all(character.isalnum() or character in "-_" for character in name)


def test_a_record_without_an_incident_id_is_ignored(step_functions):
    broken = record()
    broken["dynamodb"]["Keys"]["incident_id"] = {"S": ""}

    assert new_incident_ids({"Records": [broken]}) == []
