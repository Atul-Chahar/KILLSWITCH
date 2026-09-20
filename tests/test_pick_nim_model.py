"""The NIM model picker. It calls NVIDIA, so every test here stubs that out."""

from __future__ import annotations

from datetime import UTC

import pytest

from verifier.verify import ActionType, verify_plan

KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def test_a_missing_key_exits_with_instructions(pick_nim_model, monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)

    with pytest.raises(SystemExit) as raised:
        pick_nim_model.api_key()

    assert "build.nvidia.com" in str(raised.value)


def test_the_sample_incident_is_something_the_verifier_can_accept(pick_nim_model):
    """If the fixture itself were unverifiable, every model would look broken."""
    radius = pick_nim_model.sample_incident()

    assert radius.resources
    assert radius.access_key_id == KEY
    assert radius.window_start.tzinfo is UTC


def test_a_plan_the_verifier_accepts_counts_as_a_pass(pick_nim_model, monkeypatch):
    from narrate.schema import NarratedAction, NarratedIncident

    radius = pick_nim_model.sample_incident()
    instance = radius.resources[0].resource_id
    good = NarratedIncident(
        summary="stub",
        actions=[
            NarratedAction(
                action_type=ActionType.TERMINATE_INSTANCE,
                target=instance,
                region=radius.resources[0].region,
                reason="launched by the leaked key",
            )
        ],
    )
    monkeypatch.setattr(pick_nim_model, "build_nim_agent", lambda **kw: object())
    monkeypatch.setattr(pick_nim_model, "narrate_via_nim", lambda *a, **kw: good)

    passed, elapsed, detail = pick_nim_model.try_model("stub/model", radius, 30)

    assert passed is True
    assert elapsed >= 0
    assert "approved" in detail


def test_a_model_that_raises_is_reported_not_crashed(pick_nim_model, monkeypatch):
    """A provider failure is a result. One bad model must not end the sweep."""

    def boom(**kwargs):
        raise RuntimeError("404 model not found")

    monkeypatch.setattr(pick_nim_model, "build_nim_agent", boom)

    passed, _, detail = pick_nim_model.try_model("gone/model", pick_nim_model.sample_incident(), 30)

    assert passed is False
    assert "404" in detail


def test_an_empty_plan_does_not_count_as_a_working_model(pick_nim_model, monkeypatch):
    """A model that returns nothing is not a model that works."""
    from narrate.schema import NarratedIncident

    monkeypatch.setattr(pick_nim_model, "build_nim_agent", lambda **kw: object())
    monkeypatch.setattr(
        pick_nim_model,
        "narrate_via_nim",
        lambda *a, **kw: NarratedIncident(summary="nothing to do", actions=[]),
    )

    passed, _, detail = pick_nim_model.try_model("lazy/model", pick_nim_model.sample_incident(), 30)

    assert passed is False
    assert "verifier" in detail


def test_the_sample_plan_round_trips_through_the_verifier(pick_nim_model):
    """Belt and braces: the picker's own pass criterion is the real verifier."""
    from narrate.schema import NarratedAction, NarratedIncident

    radius = pick_nim_model.sample_incident()
    plan = NarratedIncident(
        summary="stub",
        actions=[
            NarratedAction(
                action_type=ActionType.DEACTIVATE_KEY,
                target=radius.access_key_id,
                region=None,
                reason="leaked",
            )
        ],
    ).to_proposed_plan()

    result = verify_plan(
        plan, radius, access_key_id=radius.access_key_id, repository=pick_nim_model.REPOSITORY
    )

    assert len(result.approved) == 1
    assert not result.rejected
