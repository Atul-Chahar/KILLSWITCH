"""Trigger one: a push to the watched repository.

The push payload never carries file contents, so the diff is fetched per commit.
The fetcher is injected, which keeps this testable and keeps GitHub out of unit tests.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.request import Request, urlopen

from detect.patterns import find_access_key_ids
from detect.webhook import SIGNATURE_HEADER, SignatureError, verify_signature
from shared.incidents import IncidentStore
from shared.models import IncidentRecord, IncidentSource, incident_id_for

PatchFetcher = Callable[[str, str], str]

GITHUB_API = "https://api.github.com"
FETCH_TIMEOUT_SECONDS = 10


def fetch_commit_patch(repository: str, sha: str) -> str:
    """The unified diff for one commit, from the GitHub API."""
    token = os.environ.get("GITHUB_APP_TOKEN", "")
    request = Request(  # noqa: S310 - fixed https host, not caller controlled
        f"{GITHUB_API}/repos/{repository}/commits/{sha}",
        headers={
            "Accept": "application/vnd.github.v3.diff",
            "Authorization": f"Bearer {token}",
            "User-Agent": "killswitch",
        },
    )
    with urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        return str(response.read().decode("utf-8", errors="replace"))


def handle_push(
    payload: dict[str, Any],
    fetch_patch: PatchFetcher,
    store: IncidentStore,
    *,
    now: datetime | None = None,
) -> list[IncidentRecord]:
    """Scan every commit in the push, and open one incident per distinct leaked key."""
    detected_at = now or datetime.now(UTC)
    repository = str(payload.get("repository", {}).get("full_name", ""))

    incidents: list[IncidentRecord] = []
    seen: set[str] = set()
    for commit in payload.get("commits", []):
        sha = str(commit.get("id", ""))
        if not sha:
            continue
        for access_key_id in find_access_key_ids(fetch_patch(repository, sha)):
            if access_key_id in seen:
                continue
            seen.add(access_key_id)
            record, _created = store.create_if_absent(
                IncidentRecord(
                    incident_id=incident_id_for(access_key_id),
                    access_key_id=access_key_id,
                    source=IncidentSource.GITHUB_PUSH,
                    detected_at=detected_at,
                    repository=repository or None,
                    commit_sha=sha,
                )
            )
            incidents.append(record)
    return incidents


def _header(event: dict[str, Any], name: str) -> str | None:
    headers = event.get("headers") or {}
    lowered = {key.lower(): value for key, value in headers.items()}
    return lowered.get(name.lower())


def _default_store() -> IncidentStore:
    import boto3

    table = boto3.resource("dynamodb").Table(os.environ["INCIDENT_TABLE_NAME"])
    return IncidentStore(table)


def lambda_handler(
    event: dict[str, Any],
    _context: Any,
    *,
    store: IncidentStore | None = None,
    fetch_patch: PatchFetcher | None = None,
) -> dict[str, Any]:
    body = event.get("body") or ""
    raw = body.encode() if isinstance(body, str) else body

    try:
        verify_signature(
            os.environ.get("GITHUB_WEBHOOK_SECRET", ""), raw, _header(event, SIGNATURE_HEADER)
        )
    except SignatureError as error:
        return {"statusCode": 401, "body": json.dumps({"error": str(error)})}

    incidents = handle_push(
        json.loads(raw or b"{}"),
        fetch_patch or fetch_commit_patch,
        store or _default_store(),
    )
    return {"statusCode": 200, "body": json.dumps({"incidents": len(incidents)})}
