"""Guards that keep demo tooling pointed at the throwaway account, and nowhere else."""

from __future__ import annotations

import os
from typing import Any


class WrongAccountError(RuntimeError):
    """Raised when credentials do not belong to the dedicated demo account."""


def mask_account_id(account_id: str) -> str:
    """Account ids are redacted in anything published, demo console output included."""
    if len(account_id) < 4:
        return "****"
    return f"****{account_id[-4:]}"


def demo_account_id_from_env(env: dict[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    value = source.get("DEMO_ACCOUNT_ID", "").strip()
    if not value:
        raise WrongAccountError(
            "DEMO_ACCOUNT_ID is not set. Refusing to touch any AWS account without it."
        )
    return value


def require_demo_account(sts_client: Any, expected_account_id: str) -> str:
    """Return the caller's account id, or refuse loudly if it is not the demo account.

    GetCallerIdentity is the right check here because AWS cannot deny it: even the
    quarantined, deny-everything demo user can still answer "which account am I in?",
    so this guard cannot be locked out by the very policy it runs under.
    """
    identity = sts_client.get_caller_identity()
    actual = identity["Account"]
    if actual != expected_account_id:
        raise WrongAccountError(
            f"Credentials belong to account {mask_account_id(actual)}, but "
            f"DEMO_ACCOUNT_ID is {mask_account_id(expected_account_id)}. Refusing to continue."
        )
    return actual
