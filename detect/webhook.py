"""GitHub webhook signature checking. Anything that fails here never becomes an incident."""

from __future__ import annotations

import hashlib
import hmac

SIGNATURE_HEADER = "X-Hub-Signature-256"
SUPPORTED_ALGORITHM = "sha256"


class SignatureError(Exception):
    """Raised when a webhook cannot be proven to have come from GitHub."""


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> None:
    if not secret:
        raise SignatureError("no webhook secret configured, refusing to trust the request")
    if not signature_header:
        raise SignatureError(f"missing {SIGNATURE_HEADER} header")

    algorithm, _, provided = signature_header.partition("=")
    if algorithm != SUPPORTED_ALGORITHM or not provided:
        raise SignatureError(f"unsupported signature format: {signature_header!r}")

    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise SignatureError("signature does not match the request body")
