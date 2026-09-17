"""Finding AWS access key ids in text, without crying wolf over documentation."""

from __future__ import annotations

import re

ACCESS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# AWS uses these in its own documentation. They are not credentials, and an
# incident raised for one is a false positive in front of a judge.
EXAMPLE_KEY_SUFFIX = "EXAMPLE"


def is_example_key(access_key_id: str) -> bool:
    return access_key_id.endswith(EXAMPLE_KEY_SUFFIX)


def find_access_key_ids(text: str) -> list[str]:
    """Every distinct real-looking key in the text, in the order it first appears."""
    found: list[str] = []
    for match in ACCESS_KEY_PATTERN.finditer(text):
        key = match.group(0)
        if is_example_key(key) or key in found:
            continue
        found.append(key)
    return found
