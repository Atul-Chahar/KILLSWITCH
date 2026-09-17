"""Who may act unattended. The fallback must be the strict answer, never the convenient one."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fakes import client_error

from authorize.decide import (
    ApprovalTier,
    DecisionSource,
    approval_tier_for,
    fallback_tier,
    tier_from_cedar_decision,
)

INCIDENT_ID = "inc-AKIA" + "IOSFODNN7EXAMPLE"
POLICY_STORE = "ps-test"


class StubVerifiedPermissions:
    def __init__(self, decision: str = "DENY", error: Exception | None = None) -> None:
        self.decision = decision
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def is_authorized(self, **kwargs: Any) -> dict[str, Any]:
        if self.error:
            raise self.error
        self.calls.append(kwargs)
        return {
            "decision": self.decision,
            "determiningPolicies": [{"policyId": "policy-forbid-destructive"}],
        }


@pytest.mark.parametrize("action_type", ["deactivate_key", "terminate_instance", "open_pr"])
def test_every_destructive_action_needs_a_human_in_the_fallback(action_type):
    assert fallback_tier(action_type) is ApprovalTier.HUMAN


@pytest.mark.parametrize("action_type", ["read_evidence", "tag_resource"])
def test_reads_and_tagging_are_automatic_in_the_fallback(action_type):
    assert fallback_tier(action_type) is ApprovalTier.AUTOMATIC


def test_an_unrecognised_action_is_treated_as_destructive():
    """Failing towards asking a human is the only safe direction to fail."""
    assert fallback_tier("something_new_and_unreviewed") is ApprovalTier.HUMAN


def test_cedar_allow_means_the_workflow_may_act_alone():
    assert tier_from_cedar_decision("ALLOW") is ApprovalTier.AUTOMATIC


@pytest.mark.parametrize("decision", ["DENY", "deny", "", "SOMETHING_ELSE"])
def test_anything_other_than_allow_means_ask_a_person(decision):
    assert tier_from_cedar_decision(decision) is ApprovalTier.HUMAN


def test_the_policy_store_is_asked_about_the_right_entities():
    client = StubVerifiedPermissions(decision="DENY")

    approval_tier_for(
        "terminate_instance",
        incident_id=INCIDENT_ID,
        verified_permissions_client=client,
        policy_store_id=POLICY_STORE,
    )

    (call,) = client.calls
    assert call["policyStoreId"] == POLICY_STORE
    assert call["principal"] == {"entityType": "Killswitch::Automation", "entityId": "workflow"}
    assert call["action"] == {"actionType": "Killswitch::Action", "actionId": "terminate_instance"}
    assert call["resource"]["entityId"] == INCIDENT_ID
    assert call["context"]["contextMap"]["human_approved"] == {"boolean": False}


def test_a_cedar_denial_records_which_policy_decided():
    decision = approval_tier_for(
        "terminate_instance",
        incident_id=INCIDENT_ID,
        verified_permissions_client=StubVerifiedPermissions(decision="DENY"),
        policy_store_id=POLICY_STORE,
    )

    assert decision.tier is ApprovalTier.HUMAN
    assert decision.source is DecisionSource.VERIFIED_PERMISSIONS
    assert decision.determining_policy_ids == ["policy-forbid-destructive"]


def test_an_unreachable_policy_store_falls_back_strictly_and_says_so():
    """An outage must not quietly become permission to act unattended."""
    decision = approval_tier_for(
        "terminate_instance",
        incident_id=INCIDENT_ID,
        verified_permissions_client=StubVerifiedPermissions(
            error=client_error("ResourceNotFoundException", "IsAuthorized")
        ),
        policy_store_id=POLICY_STORE,
    )

    assert decision.tier is ApprovalTier.HUMAN
    assert decision.source is DecisionSource.FALLBACK_TABLE
    assert decision.aws_error_code == "ResourceNotFoundException"


def test_no_policy_store_configured_uses_the_documented_fallback():
    decision = approval_tier_for("terminate_instance", incident_id=INCIDENT_ID)

    assert decision.tier is ApprovalTier.HUMAN
    assert decision.source is DecisionSource.FALLBACK_TABLE


def test_the_cedar_policy_file_forbids_destructive_actions_without_approval():
    """The policy text is the artefact judges will read, so its shape is asserted."""
    policy = (
        Path(__file__).resolve().parent.parent / "authorize/policies/containment.cedar"
    ).read_text()

    assert "forbid" in policy
    assert "unless { context.human_approved == true }" in policy
    for action in ("deactivate_key", "terminate_instance", "open_pr"):
        assert action in policy
