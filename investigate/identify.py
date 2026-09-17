"""Who owns this key, and which keys does this user have.

Both directions are needed. A push gives us a key id and containment needs the user
name to deactivate it; a quarantine event gives us a user name and no key id at all.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

ACTIVE = "Active"


class IdentificationError(RuntimeError):
    """Raised when a key or user cannot be resolved. Never answered with a guess."""


def owner_of_access_key(iam_client: Any, access_key_id: str) -> str:
    """The IAM user that owns this key.

    GetAccessKeyLastUsed is the only call that maps a bare key id to a user name;
    ListAccessKeys needs the user name you are trying to find.
    """
    try:
        response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
    except ClientError as error:
        raise IdentificationError(
            f"cannot resolve the owner of {access_key_id}: {error}"
        ) from error

    user_name = response.get("UserName")
    if not user_name:
        raise IdentificationError(f"{access_key_id} has no owning user (it may be a root key)")
    return str(user_name)


def active_access_key_ids(iam_client: Any, user_name: str) -> list[str]:
    """The user's active key ids. Inactive keys need no incident."""
    try:
        response = iam_client.list_access_keys(UserName=user_name)
    except ClientError as error:
        raise IdentificationError(f"cannot list keys for {user_name}: {error}") from error

    return [
        str(key["AccessKeyId"])
        for key in response.get("AccessKeyMetadata", [])
        if key.get("Status") == ACTIVE
    ]
