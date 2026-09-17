"""One leaked key means one incident, no matter how many times we hear about it."""

from __future__ import annotations

from datetime import UTC, datetime

from fakes import FakeTable

from shared.incidents import IncidentStore
from shared.models import IncidentRecord, IncidentSource, IncidentStatus, incident_id_for

KEY = "AKIA" + "TESTFAKEKEY00001"
DETECTED_AT = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC)


def record(**overrides) -> IncidentRecord:
    fields = {
        "incident_id": incident_id_for(KEY),
        "access_key_id": KEY,
        "source": IncidentSource.GITHUB_PUSH,
        "detected_at": DETECTED_AT,
        "repository": "octo/private-demo-repo",
        "commit_sha": "a" * 40,
    }
    fields.update(overrides)
    return IncidentRecord(**fields)


def test_the_incident_id_is_derived_from_the_access_key_id():
    assert incident_id_for(KEY) == incident_id_for(KEY)
    assert KEY in incident_id_for(KEY)


def test_a_new_key_creates_an_incident():
    store = IncidentStore(FakeTable())

    stored, created = store.create_if_absent(record())

    assert created is True
    assert stored.access_key_id == KEY
    assert stored.status is IncidentStatus.DETECTED


def test_the_same_key_twice_leaves_one_incident():
    table = FakeTable()
    store = IncidentStore(table)

    store.create_if_absent(record())
    _stored, created = store.create_if_absent(record())

    assert created is False, "the second delivery must not create a second incident"
    assert len(table.items) == 1


def test_the_other_trigger_finds_the_incident_already_open():
    """Whichever trigger fires first does the work; the second must not duplicate it."""
    table = FakeTable()
    store = IncidentStore(table)

    store.create_if_absent(record(source=IncidentSource.GITHUB_PUSH))
    stored, created = store.create_if_absent(record(source=IncidentSource.AWS_QUARANTINE))

    assert created is False
    assert len(table.items) == 1
    assert stored.source is IncidentSource.GITHUB_PUSH, "the original detection is preserved"


def test_a_different_key_creates_its_own_incident():
    table = FakeTable()
    store = IncidentStore(table)
    other_key = "AKIA" + "TESTFAKEKEY00002"

    store.create_if_absent(record())
    store.create_if_absent(record(incident_id=incident_id_for(other_key), access_key_id=other_key))

    assert len(table.items) == 2


def test_a_stored_incident_can_be_read_back_unchanged():
    table = FakeTable()
    store = IncidentStore(table)
    store.create_if_absent(record())

    loaded = store.get(incident_id_for(KEY))

    assert loaded is not None
    assert loaded.access_key_id == KEY
    assert loaded.detected_at == DETECTED_AT
    assert loaded.repository == "octo/private-demo-repo"


def test_an_unknown_incident_reads_back_as_none():
    assert IncidentStore(FakeTable()).get("inc-does-not-exist") is None


def test_datetimes_are_stored_as_iso_strings_dynamodb_can_hold():
    table = FakeTable()
    IncidentStore(table).create_if_absent(record())

    (item,) = table.items.values()
    assert isinstance(item["detected_at"], str)
    assert item["detected_at"].startswith("2026-09-18T10:00:00")
