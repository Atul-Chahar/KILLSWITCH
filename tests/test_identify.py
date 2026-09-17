"""Mapping a key to its owner. Containment cannot deactivate a key without the user name."""

from __future__ import annotations

import pytest
from fakes import FakeIam

from investigate.identify import IdentificationError, active_access_key_ids, owner_of_access_key

KEY = "AKIA" + "TESTFAKEKEY00001"
SECOND_KEY = "AKIA" + "TESTFAKEKEY00002"
UNKNOWN_KEY = "AKIA" + "TESTFAKEKEY09999"

IAM = {
    "demo-leaky-user": [
        {"AccessKeyId": KEY, "Status": "Active"},
        {"AccessKeyId": SECOND_KEY, "Status": "Inactive"},
    ],
    "someone-else": [{"AccessKeyId": "AKIA" + "TESTFAKEKEY00003", "Status": "Active"}],
}


def test_a_key_resolves_to_the_user_that_owns_it():
    assert owner_of_access_key(FakeIam(IAM), KEY) == "demo-leaky-user"


def test_an_unknown_key_is_an_error_not_a_guess():
    with pytest.raises(IdentificationError):
        owner_of_access_key(FakeIam(IAM), UNKNOWN_KEY)


def test_a_user_resolves_to_their_active_keys():
    assert active_access_key_ids(FakeIam(IAM), "demo-leaky-user") == [KEY]


def test_inactive_keys_are_left_out():
    """An already-deactivated key needs no incident."""
    assert SECOND_KEY not in active_access_key_ids(FakeIam(IAM), "demo-leaky-user")


def test_an_unknown_user_is_an_error():
    with pytest.raises(IdentificationError):
        active_access_key_ids(FakeIam(IAM), "no-such-user")
