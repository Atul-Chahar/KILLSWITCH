"""Containment is the only module that destroys anything, so it is the most suspicious one.

Every test here is really asking the same question: can this code be made to act without a
human having approved exactly this action?
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fakes import FakeEc2, FakeIam, FakeTable

from containment.actions import deactivate_key, open_pull_request, terminate_instance
from containment.guard import NotApproved, require_approval
from shared.approvals import ApprovalRecord, ApprovalState, AuditStage, action_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord, IncidentSource, incident_id_for
from verifier.plan import ProposedAction
from verifier.verify import ActionType

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
USER = "demo-leaky-user"
INSTANCE = "i-0a1b2c3d4e5f60001"
REGION = "ap-south-1"
REPOSITORY = "octo/private-demo-repo"
TOKEN = "task-token-from-step-functions"
STALE_TOKEN = "a-token-from-an-earlier-approval-round"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)
INCIDENT_ID = incident_id_for(KEY)


def incident(**overrides) -> IncidentRecord:
    fields = {
        "incident_id": INCIDENT_ID,
        "access_key_id": KEY,
        "source": IncidentSource.GITHUB_PUSH,
        "detected_at": NOW,
        "repository": REPOSITORY,
        "key_owner": USER,
        "approval_token": TOKEN,
    }
    fields.update(overrides)
    return IncidentRecord(**fields)


def action(action_type: str, target: str, region: str | None = REGION) -> ProposedAction:
    return ProposedAction(action_type=action_type, target=target, region=region)


def opened_store(**incident_fields) -> tuple[FakeTable, IncidentStore, IncidentRecord]:
    table = FakeTable()
    store = IncidentStore(table)
    record = incident(**incident_fields)
    store.create_if_absent(record)
    return table, store, record


def decide(
    store: IncidentStore, act: ProposedAction, state: ApprovalState, *, token: str = TOKEN
) -> None:
    store.record_decision(
        ApprovalRecord.create(
            incident_id=INCIDENT_ID,
            action_signature=action_signature(act.action_type, act.target, act.region),
            state=state,
            approval_token=token,
            decided_by="operator@example.com",
            decided_at=NOW,
        )
    )


def approve(store: IncidentStore, act: ProposedAction, *, token: str = TOKEN) -> None:
    decide(store, act, ApprovalState.APPROVED, token=token)


def deny(store: IncidentStore, act: ProposedAction) -> None:
    decide(store, act, ApprovalState.DENIED)


def stages(store: IncidentStore) -> list[AuditStage]:
    return [entry.stage for entry in store.audit_trail(INCIDENT_ID)]


# --- the guard ------------------------------------------------------------------------


def test_an_action_with_no_decision_at_all_is_refused():
    _table, store, record = opened_store()

    with pytest.raises(NotApproved, match="no decision"):
        require_approval(store, record, action(ActionType.TERMINATE_INSTANCE, INSTANCE))


def test_a_denied_action_is_refused():
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    deny(store, act)

    with pytest.raises(NotApproved, match="denied"):
        require_approval(store, record, act)


def test_an_approval_for_a_different_instance_does_not_authorise_this_one():
    """The approval is scoped to one action, not to the incident."""
    _table, store, record = opened_store()
    approve(store, action(ActionType.TERMINATE_INSTANCE, "i-0ffffffffffffffff"))

    with pytest.raises(NotApproved):
        require_approval(store, record, action(ActionType.TERMINATE_INSTANCE, INSTANCE))


def test_an_approval_from_a_superseded_round_is_refused():
    """A decision recorded against an old task token cannot authorise anything now."""
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act, token=STALE_TOKEN)

    with pytest.raises(NotApproved, match="token"):
        require_approval(store, record, act)


def test_an_incident_with_no_token_authorises_nothing():
    _table, store, record = opened_store(approval_token=None)
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act)

    with pytest.raises(NotApproved, match="token"):
        require_approval(store, record, act)


def test_a_correctly_approved_action_passes_the_guard():
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act)

    require_approval(store, record, act)


# --- terminate ------------------------------------------------------------------------


def test_an_unapproved_termination_never_reaches_ec2():
    _table, store, record = opened_store()
    ec2 = FakeEc2({INSTANCE: "running"})

    with pytest.raises(NotApproved):
        terminate_instance(
            ec2, store, record, action(ActionType.TERMINATE_INSTANCE, INSTANCE), now=NOW
        )

    assert ec2.terminate_calls == [], "EC2 must not be called at all"


def test_a_refusal_is_written_to_the_audit_trail():
    _table, store, record = opened_store()

    with pytest.raises(NotApproved):
        terminate_instance(
            FakeEc2({INSTANCE: "running"}),
            store,
            record,
            action(ActionType.TERMINATE_INSTANCE, INSTANCE),
            now=NOW,
        )

    assert AuditStage.REFUSED in stages(store)


def test_an_approved_termination_calls_ec2_once():
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act)
    ec2 = FakeEc2({INSTANCE: "running"})

    result = terminate_instance(ec2, store, record, act, now=NOW)

    assert ec2.terminate_calls == [[INSTANCE]]
    assert result.succeeded is True


def test_a_termination_writes_audit_rows_before_and_after():
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act)

    terminate_instance(FakeEc2({INSTANCE: "running"}), store, record, act, now=NOW)

    assert stages(store) == [AuditStage.BEFORE, AuditStage.AFTER]


def test_terminating_twice_is_safe():
    """Step Functions retries. A second run must not fail or double-report."""
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act)
    ec2 = FakeEc2({INSTANCE: "running"})

    first = terminate_instance(ec2, store, record, act, now=NOW)
    second = terminate_instance(ec2, store, record, act, now=NOW)

    assert first.succeeded and second.succeeded
    assert second.already_done is True


def test_a_failing_termination_is_recorded_as_failed_not_as_success():
    _table, store, record = opened_store()
    act = action(ActionType.TERMINATE_INSTANCE, INSTANCE)
    approve(store, act)
    ec2 = FakeEc2({})  # the instance is not there, so EC2 raises

    result = terminate_instance(ec2, store, record, act, now=NOW)

    assert result.succeeded is False
    assert AuditStage.FAILED in stages(store)


# --- deactivate -----------------------------------------------------------------------


def test_an_unapproved_deactivation_never_reaches_iam():
    _table, store, record = opened_store()
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Active"}]})

    with pytest.raises(NotApproved):
        deactivate_key(
            iam, store, record, action(ActionType.DEACTIVATE_KEY, KEY, region=None), now=NOW
        )

    assert iam.update_calls == []


def test_an_approved_deactivation_sets_the_key_inactive():
    _table, store, record = opened_store()
    act = action(ActionType.DEACTIVATE_KEY, KEY, region=None)
    approve(store, act)
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Active"}]})

    result = deactivate_key(iam, store, record, act, now=NOW)

    assert result.succeeded is True
    assert iam.keys_by_user[USER][0]["Status"] == "Inactive"
    assert iam.update_calls[0]["UserName"] == USER


def test_deactivation_needs_the_owning_user_and_says_so_when_it_is_missing():
    """IAM cannot deactivate a key without its user name, so an unidentified key fails."""
    _table, store, record = opened_store(key_owner=None)
    act = action(ActionType.DEACTIVATE_KEY, KEY, region=None)
    approve(store, act)
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Active"}]})

    result = deactivate_key(iam, store, record, act, now=NOW)

    assert result.succeeded is False
    assert iam.update_calls == []


def test_deactivating_an_already_inactive_key_is_not_an_error():
    _table, store, record = opened_store()
    act = action(ActionType.DEACTIVATE_KEY, KEY, region=None)
    approve(store, act)
    iam = FakeIam({USER: [{"AccessKeyId": KEY, "Status": "Inactive"}]})

    result = deactivate_key(iam, store, record, act, now=NOW)

    assert result.succeeded is True
    assert result.already_done is True


# --- pull request ---------------------------------------------------------------------


def test_an_unapproved_pull_request_is_never_opened():
    _table, store, record = opened_store()
    opened: list[str] = []

    def opener(repository: str, _key: str) -> str:
        opened.append(repository)
        return "https://example.invalid/pr/1"

    with pytest.raises(NotApproved):
        open_pull_request(
            opener, store, record, action(ActionType.OPEN_PR, REPOSITORY, region=None), now=NOW
        )

    assert opened == []


def test_an_approved_pull_request_records_its_url():
    _table, store, record = opened_store()
    act = action(ActionType.OPEN_PR, REPOSITORY, region=None)
    approve(store, act)

    result = open_pull_request(
        lambda _repository, _key: "https://example.invalid/pr/1", store, record, act, now=NOW
    )

    assert result.succeeded is True
    assert result.details["pull_request_url"] == "https://example.invalid/pr/1"
