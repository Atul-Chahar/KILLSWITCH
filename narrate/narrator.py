"""Which narrator writes the plan, and the one place that decides.

The mode is recorded on the incident and rendered on the screen next to the prose, so a
rehearsal plan cannot be shown to a judge as something a model wrote.
"""

from __future__ import annotations

from enum import StrEnum

from investigate.blast_radius import BlastRadius
from narrate.rehearsal import rehearsal_narration
from narrate.schema import NarratedIncident, NarrationError


class NarratorMode(StrEnum):
    BEDROCK = "bedrock"
    REHEARSAL = "rehearsal"
    NIM = "nim"


def narrator_mode(value: str | None) -> NarratorMode:
    """Unset means the model. An unrecognised value is an error, never a quiet default."""
    if not value:
        return NarratorMode.BEDROCK
    try:
        return NarratorMode(value)
    except ValueError as error:
        raise NarrationError(
            f"{value!r} is not a narrator. Use one of: "
            f"{', '.join(mode.value for mode in NarratorMode)}"
        ) from error


def narration_for(
    radius: BlastRadius,
    *,
    mode: NarratorMode,
    repository: str | None,
    key_owner: str | None,
) -> NarratedIncident:
    if mode is NarratorMode.REHEARSAL:
        return rehearsal_narration(radius)

    if mode is NarratorMode.NIM:
        # Imported here and not at module scope: same reason as Bedrock below.
        from narrate.nim_agent import narrate_via_nim

        return narrate_via_nim(radius, repository=repository, key_owner=key_owner)

    # Imported here and not at module scope: the Strands SDK is a heavy import, and the
    # other five workflow tasks share this Lambda asset without ever needing it.
    from narrate.agent import narrate

    return narrate(radius, repository=repository, key_owner=key_owner)
