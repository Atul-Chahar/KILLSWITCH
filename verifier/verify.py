"""Deterministic verification of a proposed containment plan.

Pure functions. No AWS calls. No model calls. A test parses this file and fails if it
ever imports either, because this is the module the project's whole safety claim rests on.

The rule: an action survives only if CloudTrail shows the leaked key created the thing it
targets. Everything the model says about why is carried through for a human to read and is
never part of a decision.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field

from investigate.blast_radius import BlastRadius, CreatedResource
from verifier.plan import ProposedAction, ProposedPlan

# 8 or 17 hexadecimal characters, which are the only two forms AWS issues.
INSTANCE_ID_PATTERN = re.compile(r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
ACCESS_KEY_PATTERN = re.compile(r"^(?:AKIA|ASIA)[0-9A-Z]{16}$")
REPOSITORY_PATTERN = re.compile(r"^[\w.-]+/[\w.-]+$")


class ActionType(StrEnum):
    DEACTIVATE_KEY = "deactivate_key"
    TERMINATE_INSTANCE = "terminate_instance"
    OPEN_PR = "open_pr"


class RejectionReason(StrEnum):
    UNKNOWN_ACTION_TYPE = "unknown_action_type"
    MALFORMED_TARGET = "malformed_target"
    TARGET_NOT_IN_BLAST_RADIUS = "target_not_in_blast_radius"
    REGION_MISMATCH = "region_mismatch"
    KEY_MISMATCH = "key_mismatch"
    REPOSITORY_MISMATCH = "repository_mismatch"
    DUPLICATE_ACTION = "duplicate_action"


class VerifiedAction(BaseModel):
    action: ProposedAction
    # The CloudTrail record that justifies acting. None for actions whose subject is the
    # leaked key or the leaking repository, which are facts of the incident itself.
    evidence: CreatedResource | None = None


class RejectedAction(BaseModel):
    action: ProposedAction
    reason: RejectionReason


class VerificationResult(BaseModel):
    access_key_id: str
    approved: list[VerifiedAction] = Field(default_factory=list)
    rejected: list[RejectedAction] = Field(default_factory=list)
    evidence_incomplete: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.approved and not self.rejected


def _verify_terminate_instance(
    action: ProposedAction, radius: BlastRadius
) -> tuple[CreatedResource | None, RejectionReason | None]:
    if not INSTANCE_ID_PATTERN.match(action.target):
        return None, RejectionReason.MALFORMED_TARGET

    matches = [resource for resource in radius.resources if resource.resource_id == action.target]
    if not matches:
        return None, RejectionReason.TARGET_NOT_IN_BLAST_RADIUS

    # An instance id is only unique within a region, so the same id elsewhere is a
    # different machine and must not be terminated on this evidence.
    if action.region is not None:
        in_region = [resource for resource in matches if resource.region == action.region]
        if not in_region:
            return None, RejectionReason.REGION_MISMATCH
        return in_region[0], None

    return matches[0], None


def _verify_deactivate_key(
    action: ProposedAction, access_key_id: str
) -> tuple[CreatedResource | None, RejectionReason | None]:
    if not ACCESS_KEY_PATTERN.match(action.target):
        return None, RejectionReason.MALFORMED_TARGET
    if action.target != access_key_id:
        return None, RejectionReason.KEY_MISMATCH
    return None, None


def _verify_open_pr(
    action: ProposedAction, repository: str | None
) -> tuple[CreatedResource | None, RejectionReason | None]:
    if not REPOSITORY_PATTERN.match(action.target):
        return None, RejectionReason.MALFORMED_TARGET
    if repository is None or action.target != repository:
        return None, RejectionReason.REPOSITORY_MISMATCH
    return None, None


def verify_action(
    action: ProposedAction,
    radius: BlastRadius,
    *,
    access_key_id: str,
    repository: str | None,
) -> tuple[CreatedResource | None, RejectionReason | None]:
    """Judge one action. Returns (evidence, rejection reason); exactly one is meaningful."""
    if action.action_type == ActionType.TERMINATE_INSTANCE:
        return _verify_terminate_instance(action, radius)
    if action.action_type == ActionType.DEACTIVATE_KEY:
        return _verify_deactivate_key(action, access_key_id)
    if action.action_type == ActionType.OPEN_PR:
        return _verify_open_pr(action, repository)
    return None, RejectionReason.UNKNOWN_ACTION_TYPE


def verify_plan(
    plan: ProposedPlan,
    radius: BlastRadius,
    *,
    access_key_id: str,
    repository: str | None = None,
) -> VerificationResult:
    """Split a proposed plan into what may be acted on and what may not, with reasons."""
    result = VerificationResult(
        access_key_id=access_key_id, evidence_incomplete=not radius.is_complete
    )
    already_approved: set[tuple[str, str, str | None]] = set()

    for action in plan.actions:
        evidence, rejection = verify_action(
            action, radius, access_key_id=access_key_id, repository=repository
        )
        if rejection is not None:
            result.rejected.append(RejectedAction(action=action, reason=rejection))
            continue

        # Keyed on the evidence's region, not the proposed one: the same instance asked
        # for once with a region and once without is still one machine, not two.
        region = evidence.region if evidence is not None else action.region
        signature = (action.action_type, action.target, region)
        if signature in already_approved:
            result.rejected.append(
                RejectedAction(action=action, reason=RejectionReason.DUPLICATE_ACTION)
            )
            continue

        already_approved.add(signature)
        result.approved.append(VerifiedAction(action=action, evidence=evidence))

    return result
