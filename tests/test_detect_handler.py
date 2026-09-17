"""The two triggers, end to end, against stubs. Neither may invent or duplicate an incident."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest
from fakes import FakeIam, FakeTable

from detect.handler import handle_push, lambda_handler
from detect.quarantine import handle_quarantine, is_quarantine_event
from investigate.identify import IdentificationError
from shared.incidents import IncidentStore
from shared.models import IncidentSource

KEY = "AKIA" + "TESTFAKEKEY00001"
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
SECRET = "test-webhook-secret"
NOW = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC)
COMMIT = "a" * 40

IAM = {"demo-leaky-user": [{"AccessKeyId": KEY, "Status": "Active"}]}


def push_payload(commit: str = COMMIT) -> dict:
    return {
        "ref": "refs/heads/main",
        "repository": {"full_name": "octo/private-demo-repo"},
        "commits": [{"id": commit, "message": "add config"}],
    }


def patch_fetcher_returning(patch: str):
    def fetch(repository: str, sha: str) -> str:
        assert repository == "octo/private-demo-repo"
        assert sha == COMMIT
        return patch

    return fetch


def test_a_key_in_the_pushed_diff_opens_one_incident():
    store = IncidentStore(FakeTable())

    incidents = handle_push(
        push_payload(),
        patch_fetcher_returning(f"+AWS_ACCESS_KEY_ID={KEY}\n"),
        store,
        now=NOW,
    )

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.access_key_id == KEY
    assert incident.source is IncidentSource.GITHUB_PUSH
    assert incident.repository == "octo/private-demo-repo"
    assert incident.commit_sha == COMMIT


def test_the_aws_example_key_opens_nothing():
    table = FakeTable()

    incidents = handle_push(
        push_payload(),
        patch_fetcher_returning(f"+AWS_ACCESS_KEY_ID={AWS_EXAMPLE_KEY}\n"),
        IncidentStore(table),
        now=NOW,
    )

    assert incidents == []
    assert table.items == {}


def test_a_clean_push_opens_nothing():
    table = FakeTable()

    incidents = handle_push(
        push_payload(), patch_fetcher_returning("+print('hello')\n"), IncidentStore(table), now=NOW
    )

    assert incidents == []
    assert table.items == {}


def test_replaying_the_same_push_leaves_one_incident():
    table = FakeTable()
    store = IncidentStore(table)
    fetch = patch_fetcher_returning(f"+AWS_ACCESS_KEY_ID={KEY}\n")

    handle_push(push_payload(), fetch, store, now=NOW)
    handle_push(push_payload(), fetch, store, now=NOW)

    assert len(table.items) == 1


def signed_event(body: dict, secret: str = SECRET) -> dict:
    raw = json.dumps(body)
    digest = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return {
        "body": raw,
        "headers": {"X-Hub-Signature-256": f"sha256={digest}", "X-GitHub-Event": "push"},
    }


def test_the_lambda_rejects_an_invalid_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    event = signed_event(push_payload(), secret="the-wrong-secret")

    response = lambda_handler(event, None, store=IncidentStore(FakeTable()), fetch_patch=None)

    assert response["statusCode"] == 401


def test_the_lambda_accepts_a_correctly_signed_push(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    table = FakeTable()

    response = lambda_handler(
        signed_event(push_payload()),
        None,
        store=IncidentStore(table),
        fetch_patch=patch_fetcher_returning(f"+KEY={KEY}\n"),
    )

    assert response["statusCode"] == 200
    assert json.loads(response["body"])["incidents"] == 1
    assert len(table.items) == 1


def quarantine_event(user: str = "demo-leaky-user") -> dict:
    return {
        "source": "aws.iam",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "requestParameters": {
                "userName": user,
                "policyArn": "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3",
            },
        },
    }


def test_a_quarantine_attachment_is_recognised():
    assert is_quarantine_event(quarantine_event()["detail"]) is True


def test_an_unrelated_policy_attachment_is_ignored():
    event = quarantine_event()
    event["detail"]["requestParameters"]["policyArn"] = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    assert is_quarantine_event(event["detail"]) is False


def test_the_quarantine_trigger_opens_the_same_incident_shape():
    store = IncidentStore(FakeTable())

    incidents = handle_quarantine(quarantine_event(), FakeIam(IAM), store, now=NOW)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.access_key_id == KEY
    assert incident.source is IncidentSource.AWS_QUARANTINE
    assert incident.key_owner == "demo-leaky-user"


def test_both_triggers_converge_on_one_incident():
    """Whichever fires first does the work. The second finds it already handled."""
    table = FakeTable()
    store = IncidentStore(table)

    handle_push(push_payload(), patch_fetcher_returning(f"+KEY={KEY}\n"), store, now=NOW)
    handle_quarantine(quarantine_event(), FakeIam(IAM), store, now=NOW)

    assert len(table.items) == 1


def test_a_quarantine_event_for_an_unknown_user_fails_loudly():
    with pytest.raises(IdentificationError):
        handle_quarantine(
            quarantine_event(user="no-such-user"),
            FakeIam(IAM),
            IncidentStore(FakeTable()),
            now=NOW,
        )
