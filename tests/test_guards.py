"""The demo-account guard is what stops this tooling touching a real account."""

from __future__ import annotations

import pytest

from shared.guards import (
    WrongAccountError,
    demo_account_id_from_env,
    mask_account_id,
    require_demo_account,
)

DEMO_ACCOUNT = "000000000000"
OTHER_ACCOUNT = "999999999999"


class StubSts:
    def __init__(self, account: str) -> None:
        self._account = account

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": self._account, "Arn": f"arn:aws:iam::{self._account}:user/demo"}


def test_mask_account_id_keeps_only_the_last_four_digits():
    assert mask_account_id("123456789012") == "****9012"


def test_mask_account_id_handles_a_short_value():
    assert mask_account_id("12") == "****"


def test_demo_account_id_from_env_requires_the_variable():
    with pytest.raises(WrongAccountError, match="DEMO_ACCOUNT_ID is not set"):
        demo_account_id_from_env({})


def test_demo_account_id_from_env_rejects_whitespace_only():
    with pytest.raises(WrongAccountError):
        demo_account_id_from_env({"DEMO_ACCOUNT_ID": "   "})


def test_require_demo_account_accepts_the_demo_account():
    assert require_demo_account(StubSts(DEMO_ACCOUNT), DEMO_ACCOUNT) == DEMO_ACCOUNT


def test_require_demo_account_refuses_any_other_account():
    with pytest.raises(WrongAccountError) as error:
        require_demo_account(StubSts(OTHER_ACCOUNT), DEMO_ACCOUNT)
    message = str(error.value)
    assert "Refusing to continue" in message
    assert OTHER_ACCOUNT not in message, "the guard must not print an unmasked account id"
