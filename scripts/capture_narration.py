#!/usr/bin/env python3
"""Ask the real model once, run the real verifier over its answer, and record both.

This exists to answer one question, which every reviewer of this project asks: was the
model ever actually called, or is the plan on screen something you wrote yourself?

The artefact it writes is the answer. It contains the model id, the prompt the model was
given, the plan it returned, and — the part that matters — what `verifier/verify.py` did
to that plan. Nothing here is a test and nothing runs in CI: it needs credentials and it
costs money, so a human runs it deliberately.

    python scripts/capture_narration.py --evidence tests/fixtures/blast-radius.json

The output is scrubbed with the same rules as `capture_fixture.py` before it is written,
because a real model given real evidence can put an account id in a sentence.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from investigate.blast_radius import BlastRadius  # noqa: E402
from narrate.prompt import evidence_prompt  # noqa: E402
from verifier.verify import verify_plan  # noqa: E402

DEFAULT_OUTPUT = Path("evidence/narration-from-the-model.json")


def scrubbed(value: Any) -> Any:
    """Reuse the capture script's rules rather than writing a second, weaker set."""
    from importlib.util import module_from_spec, spec_from_file_location

    path = Path(__file__).resolve().parent / "capture_fixture.py"
    spec = spec_from_file_location("killswitch_capture_fixture", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.scrub_value(value)


def capture(
    radius: BlastRadius, *, repository: str | None, key_owner: str | None
) -> dict[str, Any]:
    """One real Bedrock call, then the verifier's verdict on what came back."""
    # Imported here so --help and the tests do not need the Strands SDK or credentials.
    from narrate.agent import bedrock_model_id, narrate

    model_id = bedrock_model_id()
    narration = narrate(radius, repository=repository, key_owner=key_owner)
    plan = narration.to_proposed_plan()
    result = verify_plan(plan, radius, access_key_id=radius.access_key_id, repository=repository)

    return {
        "model_id": model_id,
        "region": os.environ.get("AWS_REGION", ""),
        "prompt": evidence_prompt(radius, repository=repository, key_owner=key_owner),
        "narration": narration.model_dump(mode="json"),
        "verification": result.model_dump(mode="json"),
        # Stated here so the artefact cannot be read as a passing test. The verifier
        # approving everything means this model behaved, not that the guard works; the
        # guard is exercised deliberately in tests/test_narrate_adversarial.py.
        "what_this_shows": (
            "One real call to the model named above, and what verifier/verify.py did to "
            "the plan it returned. It is evidence the model was called, not evidence the "
            "verifier is correct."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="a BlastRadius as JSON, from scripts/lookup.py or a fixture",
    )
    parser.add_argument("--repository", default=None, help="the repository that leaked, if any")
    parser.add_argument("--key-owner", default=None, help="the IAM user that owns the key")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    radius = BlastRadius.model_validate_json(args.evidence.read_text())
    captured = capture(radius, repository=args.repository, key_owner=args.key_owner)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(scrubbed(captured), indent=2) + "\n")

    approved = len(captured["verification"]["approved"])
    rejected = len(captured["verification"]["rejected"])
    print(f"model: {captured['model_id']}")
    print(f"the verifier kept {approved} action(s) and struck out {rejected}")
    print(f"written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
