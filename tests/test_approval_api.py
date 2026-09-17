"""The approval endpoint is the last gate in the system. It is tested like one."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from fakes import FakeTable

from shared.approvals import ApprovalState, action_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord, IncidentSource, IncidentStatus, incident_id_for
from workflow.approval_api import incident_view, lambda_handler, record_decisions

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
INCIDENT_ID = incident_id_for(KEY)
TOKEN = "task-token-from-step-functions"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)
SIGNATURE = action_signature("terminate_instance", "i-0a1b2c3d4e5f60001", "ap-south-1")


class StubStepFunctions:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def send_task_success(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {}


def store_with_incident(*, token: str | None = TOKEN) -> tuple[FakeTable, IncidentStore]:
    table = FakeTable()
    store = IncidentStore(table)
    store.create_if_absent(
        IncidentRecord(
            incident_id=INCIDENT_ID,
            access_key_id=KEY,
            source=IncidentSource.GITHUB_PUSH,
            detected_at=NOW,
            repository="octo/private-demo-repo",
            key_owner="demo-leaky-user",
            status=IncidentStatus.AWAITING_APPROVAL,
            approval_token=token,
        )
    )
    return table, store


def api_event(method: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "httpMethod": method,
        "pathParameters": {"incident_id": INCIDENT_ID},
        "body": json.dumps(body) if body else None,
        "requestContext": {"authorizer": {"claims": {"email": "operator@example.com"}}},
    }


def test_reading_an_incident_returns_what_the_console_renders():
    _table, store = store_with_incident()
    store.save_artifacts(INCIDENT_ID, {"tiers": [{"action_type": "terminate_instance"}]})

    view = incident_view(store, INCIDENT_ID)

    assert view is not None
    assert view["incident_id"] == INCIDENT_ID
    assert view["access_key_id"] == KEY
    assert view["tiers"] == [{"action_type": "terminate_instance"}]
    assert view["audit"] == []


def test_an_incident_with_no_artifacts_yet_still_renders():
    _table, store = store_with_incident()

    view = incident_view(store, INCIDENT_ID)

    assert view is not None
    assert view["blast_radius"] is None
    assert view["tiers"] == []


def test_an_unknown_incident_is_a_404():
    _table, store = store_with_incident()

    response = lambda_handler(
        {"httpMethod": "GET", "pathParameters": {"incident_id": "inc-nope"}}, None, store=store
    )

    assert response["statusCode"] == 404


def test_a_decision_is_recorded_against_the_current_token():
    _table, store = store_with_incident()

    token = record_decisions(
        store,
        INCIDENT_ID,
        [{"action_signature": SIGNATURE, "state": "approved"}],
        decided_by="operator@example.com",
        now=NOW,
    )

    assert token == TOKEN
    decision = store.decision_for(INCIDENT_ID, SIGNATURE)
    assert decision is not None
    assert decision.state is ApprovalState.APPROVED
    assert decision.approval_token == TOKEN
    assert decision.decided_by == "operator@example.com"


def test_a_denial_is_recorded_as_a_denial():
    _table, store = store_with_incident()

    record_decisions(
        store,
        INCIDENT_ID,
        [{"action_signature": SIGNATURE, "state": "denied"}],
        decided_by="operator@example.com",
        now=NOW,
    )

    decision = store.decision_for(INCIDENT_ID, SIGNATURE)
    assert decision is not None
    assert decision.state is ApprovalState.DENIED


def test_decisions_cannot_be_recorded_when_nothing_is_waiting():
    """Without a token there is no approval round to answer, so this must not be accepted."""
    _table, store = store_with_incident(token=None)

    with pytest.raises(LookupError, match="not waiting"):
        record_decisions(
            store,
            INCIDENT_ID,
            [{"action_signature": SIGNATURE, "state": "approved"}],
            decided_by="operator@example.com",
        )


def test_the_token_is_released_only_after_the_decisions_are_stored():
    """If the token went first, containment could run before the decisions landed."""
    _table, store = store_with_incident()
    step_functions = StubStepFunctions()

    response = lambda_handler(
        api_event("POST", {"decisions": [{"action_signature": SIGNATURE, "state": "approved"}]}),
        None,
        store=store,
        step_functions=step_functions,
    )

    assert response["statusCode"] == 200
    assert store.decision_for(INCIDENT_ID, SIGNATURE) is not None
    assert step_functions.calls[0]["taskToken"] == TOKEN


def test_an_empty_submission_is_rejected_and_releases_nothing():
    _table, store = store_with_incident()
    step_functions = StubStepFunctions()

    response = lambda_handler(
        api_event("POST", {"decisions": []}), None, store=store, step_functions=step_functions
    )

    assert response["statusCode"] == 400
    assert step_functions.calls == []


def test_submitting_against_a_finished_approval_conflicts_rather_than_acting():
    _table, store = store_with_incident(token=None)
    step_functions = StubStepFunctions()

    response = lambda_handler(
        api_event("POST", {"decisions": [{"action_signature": SIGNATURE, "state": "approved"}]}),
        None,
        store=store,
        step_functions=step_functions,
    )

    assert response["statusCode"] == 409
    assert step_functions.calls == []


def test_the_caller_identity_comes_from_the_cognito_claims():
    _table, store = store_with_incident()

    lambda_handler(
        api_event("POST", {"decisions": [{"action_signature": SIGNATURE, "state": "approved"}]}),
        None,
        store=store,
        step_functions=StubStepFunctions(),
    )

    decision = store.decision_for(INCIDENT_ID, SIGNATURE)
    assert decision is not None
    assert decision.decided_by == "operator@example.com"


def test_an_unsupported_method_is_refused():
    _table, store = store_with_incident()

    response = lambda_handler(api_event("DELETE"), None, store=store)

    assert response["statusCode"] == 405
