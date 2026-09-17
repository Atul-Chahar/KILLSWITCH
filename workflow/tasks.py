"""The Step Functions tasks.

Each one is a thin shell: parse the state, call a module that was tested on its own, and
hand back JSON. The decisions live in investigate/, verifier/, authorize/ and
containment/, never here.
"""

from __future__ import annotations

import os
from typing import Any

import boto3

from authorize.decide import ApprovalTier, approval_tier_for
from containment.actions import deactivate_key, open_pull_request, terminate_instance
from containment.end_state import confirm_end_state
from containment.guard import NotApproved
from investigate.blast_radius import BlastRadius, build_blast_radius
from investigate.identify import IdentificationError, owner_of_access_key
from narrate.narrator import narration_for, narrator_mode
from shared.incidents import IncidentStore
from shared.models import IncidentStatus
from verifier.plan import ProposedPlan
from verifier.verify import ActionType, VerificationResult, verify_plan


def _store() -> IncidentStore:
    table = boto3.resource("dynamodb").Table(os.environ["INCIDENT_TABLE_NAME"])
    return IncidentStore(table)


def _demo_regions() -> list[str]:
    return [
        region
        for region in (os.environ.get("AWS_REGION", ""), os.environ.get("AWS_SECONDARY_REGION", ""))
        if region
    ]


def _ec2_clients(regions: list[str]) -> dict[str, Any]:
    return {region: boto3.client("ec2", region_name=region) for region in regions}


def _open_secret_removal_pr(repository: str, access_key_id: str) -> str:
    """Not built yet. It raises rather than returning a url nobody opened."""
    raise NotImplementedError(
        f"opening a secret-removal PR against {repository} for {access_key_id} is not built yet"
    )


def investigate_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Identify the key's owner and rebuild what it created."""
    store = _store()
    incident_id = str(event["incident_id"])
    incident = store.get(incident_id)
    if incident is None:
        raise RuntimeError(f"no incident {incident_id}")

    key_owner = incident.key_owner
    if not key_owner:
        try:
            key_owner = owner_of_access_key(boto3.client("iam"), incident.access_key_id)
        except IdentificationError:
            # Recorded as unknown rather than guessed. Containment refuses to deactivate
            # a key whose owner it does not know, which is the correct outcome here.
            key_owner = None

    # Persisted, not just returned. A push incident has no owner until now, and
    # containment re-reads the record rather than the execution state, so an owner that
    # lives only in the state means the key can never be deactivated.
    if key_owner and key_owner != incident.key_owner:
        store.save_artifacts(incident_id, {"key_owner": key_owner})

    radius = build_blast_radius(boto3.Session(), incident.access_key_id, _demo_regions())
    return {
        "incident_id": incident_id,
        "access_key_id": incident.access_key_id,
        "repository": incident.repository,
        "key_owner": key_owner,
        "status": IncidentStatus.INVESTIGATING.value,
        "blast_radius": radius.model_dump(mode="json"),
    }


def narrate_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Ask the narrator for a summary and a plan. It is the only model call in KILLSWITCH.

    Whatever comes back goes straight to the verifier, which is the next state. Nothing
    written here is trusted, and the narrator that wrote it is recorded alongside it so
    the console can say who the prose came from.
    """
    radius = BlastRadius.model_validate(event["blast_radius"])
    mode = narrator_mode(os.environ.get("NARRATOR_MODE"))

    narration = narration_for(
        radius,
        mode=mode,
        repository=event.get("repository"),
        key_owner=event.get("key_owner"),
    )
    return {
        **event,
        "plan": narration.to_proposed_plan().model_dump(mode="json"),
        "summary": narration.summary,
        "narrator": mode.value,
    }


def verify_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Run the model's plan through the verifier. Nothing reaches a human unverified."""
    radius = BlastRadius.model_validate(event["blast_radius"])
    plan = ProposedPlan.model_validate(event["plan"])

    result = verify_plan(
        plan,
        radius,
        access_key_id=str(event["access_key_id"]),
        repository=event.get("repository"),
    )
    return {**event, "verification": result.model_dump(mode="json")}


def authorize_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Ask Verified Permissions which of the surviving actions still need a person."""
    verification = VerificationResult.model_validate(event["verification"])
    policy_store_id = os.environ.get("VERIFIED_PERMISSIONS_POLICY_STORE_ID", "")
    client = boto3.client("verifiedpermissions") if policy_store_id else None

    decisions = [
        approval_tier_for(
            verified.action.action_type,
            incident_id=str(event["incident_id"]),
            verified_permissions_client=client,
            policy_store_id=policy_store_id or None,
        ).model_dump(mode="json")
        for verified in verification.approved
    ]
    needs_human = any(decision["tier"] == ApprovalTier.HUMAN.value for decision in decisions)
    return {**event, "tiers": decisions, "needs_human": needs_human}


def request_approval_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Store the task token so the console can answer, and so containment can check it.

    The evidence, the plan and the tiers are written to the incident here as well: they
    live in the execution state, which the console cannot read.
    """
    store = _store()
    incident_id = str(event["incident_id"])
    token = str(event["task_token"])

    artifacts = {
        field: event[field]
        for field in ("blast_radius", "verification", "tiers", "summary", "narrator")
        if event.get(field) is not None
    }
    store.save_artifacts(incident_id, artifacts)
    store.set_approval_token(incident_id, token)
    return {"incident_id": incident_id, "approval_token": token}


def contain_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Act on the approved actions. Each call re-checks approval before it does anything."""
    store = _store()
    incident = store.get(str(event["incident_id"]))
    if incident is None:
        raise RuntimeError(f"no incident {event['incident_id']}")

    verification = VerificationResult.model_validate(event["verification"])
    iam_client = boto3.client("iam")
    clients = _ec2_clients(_demo_regions())

    results: list[dict[str, Any]] = []
    for verified in verification.approved:
        action = verified.action
        try:
            if action.action_type == ActionType.TERMINATE_INSTANCE:
                region = verified.evidence.region if verified.evidence else action.region
                client = clients.get(region or "")
                if client is None:
                    raise RuntimeError(f"no EC2 client for region {region!r}")
                result = terminate_instance(client, store, incident, action)
            elif action.action_type == ActionType.DEACTIVATE_KEY:
                result = deactivate_key(iam_client, store, incident, action)
            elif action.action_type == ActionType.OPEN_PR:
                result = open_pull_request(_open_secret_removal_pr, store, incident, action)
            else:
                continue
        except NotApproved as refusal:
            # The human denied this action, or never approved it. That is a normal
            # outcome, already written to the audit trail, not a workflow failure.
            results.append({"refused": True, "detail": str(refusal), "succeeded": False})
            continue
        results.append(result.model_dump(mode="json"))

    return {**event, "containment": results}


def confirm_task(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Re-read AWS and record the end state we can actually observe."""
    store = _store()
    incident_id = str(event["incident_id"])
    incident = store.get(incident_id)
    if incident is None:
        raise RuntimeError(f"no incident {incident_id}")

    verification = VerificationResult.model_validate(event["verification"])
    end_state = confirm_end_state(
        incident,
        list(verification.approved),
        iam_client=boto3.client("iam"),
        ec2_clients=_ec2_clients(_demo_regions()),
    )
    status = IncidentStatus.CONTAINED if end_state.all_confirmed else IncidentStatus.FAILED
    # The console reads DynamoDB, never the execution state, so how this ended has to be
    # written down. An end state nobody can see is the same as no end state.
    store.save_artifacts(
        incident_id,
        {"end_state": end_state.model_dump(mode="json"), "status": status.value},
    )
    return {
        **event,
        "end_state": end_state.model_dump(mode="json"),
        "status": status.value,
        "confirmed": end_state.all_confirmed,
    }
