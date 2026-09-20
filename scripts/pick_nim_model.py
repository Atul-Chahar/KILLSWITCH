#!/usr/bin/env python3
"""Find an NVIDIA NIM model that actually works as KILLSWITCH's narrator.

NVIDIA's catalogue is large, and most of it is useless to us. The narrator needs a
model that supports tool calling, because strands implements structured output as a
tool call — a model without it cannot return a plan at all. Some ids are also
deprecated, rate-limited, or slow enough to stall the demo.

Rather than guess, this asks each candidate to narrate a real (synthetic) incident
and reports what came back and how long it took. A model only passes if it produces
a plan the verifier accepts.

    export $(grep -v '^#' .env | xargs)
    python scripts/pick_nim_model.py              # test a shortlist
    python scripts/pick_nim_model.py --all        # test everything the key can reach
    python scripts/pick_nim_model.py --list       # just list ids, call nothing

Nothing here touches AWS. It calls NVIDIA with your key and nothing else.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from investigate.blast_radius import (  # noqa: E402
    BlastRadius,
    CreatedResource,
    ResourceKind,
)
from narrate.nim_agent import NIM_BASE_URL, build_nim_agent, narrate_via_nim  # noqa: E402
from verifier.verify import verify_plan  # noqa: E402

# AWS's own documented example key. Not a credential.
EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
REPOSITORY = "octo/private-demo-repo"
OWNED_INSTANCE = "i-0a1b2c3d4e5f60001"
TIMEOUT_SECONDS = 90

# Tried in order. Small-and-fast first: the narrator writes one short plan, so
# reasoning-heavy giants cost latency on camera and buy nothing.
SHORTLIST = (
    "meta/llama-3.1-8b-instruct",
    "meta/llama-3.1-70b-instruct",
    "meta/llama-3.3-70b-instruct",
    "mistralai/mistral-small-24b-instruct",
    "mistralai/mixtral-8x22b-instruct-v0.1",
    "microsoft/phi-4-mini-instruct",
    "qwen/qwen2.5-7b-instruct",
    "nvidia/llama-3.1-nemotron-70b-instruct",
)


def api_key() -> str:
    key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not key:
        sys.exit(
            "NVIDIA_API_KEY is not set.\n"
            "Get one at https://build.nvidia.com, put it in .env, then:\n"
            "    export $(grep -v '^#' .env | xargs)"
        )
    return key


def available_models(key: str) -> list[str]:
    """Every model id this key can reach, straight from the catalogue."""
    url = f"{NIM_BASE_URL}/models"
    # The base url is a module constant, but the check is cheap and keeps the key
    # from ever being attached to a non-https request if that constant changes.
    if not url.startswith("https://"):
        sys.exit(f"refusing to send the API key to a non-https url: {url}")

    request = urllib.request.Request(  # noqa: S310 - https enforced immediately above
        url, headers={"Authorization": f"Bearer {key}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        sys.exit(f"NVIDIA rejected the key listing models: HTTP {error.code} {error.reason}")
    except urllib.error.URLError as error:
        sys.exit(f"could not reach {NIM_BASE_URL}: {error.reason}")
    return sorted(str(item["id"]) for item in payload.get("data", []) if item.get("id"))


def sample_incident() -> BlastRadius:
    """One instance, one region. Small on purpose: we are testing the model, not the load."""
    now = datetime.now(UTC)
    return BlastRadius(
        access_key_id=EXAMPLE_KEY,
        regions_searched=["ap-south-1"],
        window_start=now,
        window_end=now,
        resources=[
            CreatedResource(
                resource_id=OWNED_INSTANCE,
                kind=ResourceKind.EC2_INSTANCE,
                event_name="RunInstances",
                region="ap-south-1",
                event_time=now,
                source_ip="203.0.113.10",
                event_id="event-sample-1",
            )
        ],
    )


def try_model(model_id: str, radius: BlastRadius) -> tuple[bool, float, str]:
    """Narrate one incident. Returns (passed, seconds, what happened)."""
    started = time.monotonic()
    try:
        agent = build_nim_agent(model_id=model_id)
        narration = narrate_via_nim(
            radius, repository=REPOSITORY, key_owner="demo-leaky-user", agent=agent
        )
    except Exception as error:  # noqa: BLE001 - every provider failure is a result, not a crash
        elapsed = time.monotonic() - started
        detail = str(error).strip().replace("\n", " ")
        return False, elapsed, detail[:110] or type(error).__name__

    elapsed = time.monotonic() - started
    result = verify_plan(
        narration.to_proposed_plan(),
        radius,
        access_key_id=EXAMPLE_KEY,
        repository=REPOSITORY,
    )
    if not result.approved:
        return (
            False,
            elapsed,
            f"plan had nothing the verifier could accept ({len(result.rejected)} rejected)",
        )
    return True, elapsed, f"{len(result.approved)} approved, {len(result.rejected)} rejected"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="test every model the key can reach")
    parser.add_argument("--list", action="store_true", help="list model ids and exit")
    parser.add_argument("--only", nargs="*", help="test just these ids")
    args = parser.parse_args()

    key = api_key()
    catalogue = available_models(key)
    print(f"{len(catalogue)} models reachable with this key\n")

    if args.list:
        for model_id in catalogue:
            print(f"  {model_id}")
        return 0

    if args.only:
        candidates = list(args.only)
    elif args.all:
        candidates = catalogue
    else:
        candidates = [m for m in SHORTLIST if m in catalogue]
        missing = [m for m in SHORTLIST if m not in catalogue]
        if missing:
            print(f"not in this catalogue, skipping: {', '.join(missing)}\n")
        if not candidates:
            print("None of the shortlist is available. Re-run with --all.\n")
            return 1

    radius = sample_incident()
    passed: list[tuple[str, float, str]] = []

    print(f"testing {len(candidates)} model(s), timeout {TIMEOUT_SECONDS}s each\n")
    for model_id in candidates:
        print(f"  {model_id:<52} ", end="", flush=True)
        ok, elapsed, detail = try_model(model_id, radius)
        print(f"{'PASS' if ok else 'fail'}  {elapsed:6.1f}s  {detail}")
        if ok:
            passed.append((model_id, elapsed, detail))

    print()
    if not passed:
        print("No model produced a usable plan.")
        print("Most likely cause: none of these support tool calling, which structured")
        print("output needs. Re-run with --all to widen the search.")
        return 1

    passed.sort(key=lambda row: row[1])
    print("Working models, fastest first:\n")
    for model_id, elapsed, detail in passed:
        print(f"  {elapsed:6.1f}s  {model_id}   ({detail})")

    best = passed[0][0]
    print(f"\nFastest working model: {best}")
    print(f"Put this in .env:\n    NIM_MODEL_ID={best}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
