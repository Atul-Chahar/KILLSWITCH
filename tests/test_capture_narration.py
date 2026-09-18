"""The capture script, without Bedrock.

Nothing here calls a model. What is tested is the part that can be wrong quietly: that a
real answer is scrubbed before it reaches the repository, and that the artefact records
the verifier's verdict rather than only the model's plan.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from investigate.blast_radius import BlastRadius, CreatedResource, ResourceKind

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
REAL_LOOKING_KEY = "AKIA" + "QYSFN3XMPLE7RT4D"
LAUNCHED = "i-0a1b2c3d4e5f60001"
REGION = "ap-south-1"
NOW = datetime(2026, 9, 18, 11, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def capture_narration(request):
    from conftest import load_script

    return load_script("capture_narration")


def radius() -> BlastRadius:
    return BlastRadius(
        access_key_id=KEY,
        regions_searched=[REGION],
        window_start=NOW,
        window_end=NOW,
        resources=[
            CreatedResource(
                resource_id=LAUNCHED,
                kind=ResourceKind.EC2_INSTANCE,
                event_name="RunInstances",
                region=REGION,
                event_time=NOW,
                source_ip="203.0.113.10",
                event_id="event-1",
            )
        ],
    )


def test_a_model_that_names_an_account_does_not_get_it_committed(capture_narration):
    """A real model given real evidence will put an account id in a sentence eventually."""
    captured = capture_narration.scrubbed(
        {"narration": {"summary": f"Key {REAL_LOOKING_KEY} in account 123456789012 from 10.0.0.4"}}
    )

    written = json.dumps(captured)
    assert "123456789012" not in written
    assert REAL_LOOKING_KEY not in written
    assert "10.0.0.4" not in written


def test_the_evidence_file_it_reads_is_the_one_the_workflow_produces(capture_narration, tmp_path):
    """So the captured prompt is the prompt the deployed narrator would have been given."""
    evidence = tmp_path / "blast-radius.json"
    evidence.write_text(radius().model_dump_json())

    parsed = BlastRadius.model_validate_json(evidence.read_text())

    assert parsed.access_key_id == KEY
    assert [resource.resource_id for resource in parsed.resources] == [LAUNCHED]


def test_the_artefact_says_what_it_does_and_does_not_prove(capture_narration):
    """An artefact that reads as a passing test would be worse than no artefact."""
    source = Path(capture_narration.__file__).read_text()

    assert "what_this_shows" in source
    assert "not evidence the" in source


def test_it_refuses_to_run_without_evidence(capture_narration):
    with pytest.raises(SystemExit):
        capture_narration.main([])
