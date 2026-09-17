"""A narrator that is not a model, for rehearsing and filming the guardrail.

The one thing the video has to show is the verifier striking out an action. Waiting for a
real model to hallucinate on camera is not a plan, so this narrator proposes a known
unowned instance every time, deterministically.

It exists precisely so nobody is tempted to prompt the model into misbehaving and then
present that as the model misbehaving. Which narrator ran is recorded on the incident and
shown on the screen, so a rehearsal plan can never be passed off as a model's.
"""

from __future__ import annotations

from investigate.blast_radius import BlastRadius
from narrate.schema import NarratedAction, NarratedIncident, NarrationError
from verifier.verify import ActionType

# Well-formed, and belongs to nobody. The console fixture uses the same id, so the
# rehearsed screen and the rehearsed workflow show the same struck-out row.
REHEARSAL_UNOWNED_INSTANCE = "i-0999999999ffffff9"

REHEARSAL_SUMMARY = (
    "Rehearsal narrator: this text was not written by the model. It is a fixed plan used "
    "to rehearse the screen and to film the verifier rejecting an action. The leaked key "
    "{key} created {count} resource(s) according to CloudTrail. The plan below also asks "
    "to terminate {unowned}, which the key never created, so the verifier will strike it "
    "out and no human will ever be offered an approve button for it."
)


def rehearsal_narration(radius: BlastRadius) -> NarratedIncident:
    """A fixed plan: contain everything the evidence shows, plus one thing it does not.

    open_pr is deliberately absent. `containment.open_pull_request` is built and tested,
    but the opener it calls is not, so proposing it would rehearse a failure rather than
    the guardrail.
    """
    if REHEARSAL_UNOWNED_INSTANCE in radius.resource_ids():
        raise NarrationError(
            f"{REHEARSAL_UNOWNED_INSTANCE} is in this blast radius, so the rehearsal plan "
            "would demonstrate an approval rather than a rejection"
        )

    actions = [
        NarratedAction(
            action_type=ActionType.DEACTIVATE_KEY,
            target=radius.access_key_id,
            region=None,
            reason="The key is exposed and CloudTrail shows it being used.",
        )
    ]
    actions += [
        NarratedAction(
            action_type=ActionType.TERMINATE_INSTANCE,
            target=resource.resource_id,
            region=resource.region,
            reason=(
                f"{resource.event_name} by the leaked key in {resource.region} "
                f"at {resource.event_time.isoformat()}."
            ),
        )
        for resource in radius.resources
    ]
    actions.append(
        NarratedAction(
            action_type=ActionType.TERMINATE_INSTANCE,
            target=REHEARSAL_UNOWNED_INSTANCE,
            region=radius.regions_searched[0] if radius.regions_searched else None,
            reason="This instance also looks suspicious and should be removed.",
        )
    )

    return NarratedIncident(
        summary=REHEARSAL_SUMMARY.format(
            key=radius.access_key_id,
            count=len(radius.resources),
            unowned=REHEARSAL_UNOWNED_INSTANCE,
        ),
        actions=actions,
    )
