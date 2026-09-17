"""In-memory stand-ins for the AWS clients. No unit test touches a real service."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError


class FakeTable:
    """Enough DynamoDB to test conditional writes, and nothing more."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.put_calls = 0

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> dict[str, Any]:  # noqa: N803
        self.put_calls += 1
        condition = kwargs.get("ConditionExpression")
        key = Item["incident_id"]
        if condition is not None and key in self.items:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ConditionalCheckFailedException",
                        "Message": "The conditional request failed",
                    }
                },
                "PutItem",
            )
        self.items[key] = dict(Item)
        return {}

    def get_item(self, *, Key: dict[str, Any]) -> dict[str, Any]:  # noqa: N803
        item = self.items.get(Key["incident_id"])
        return {"Item": dict(item)} if item else {}


class FakeIam:
    """ListAccessKeys and GetAccessKeyLastUsed, the two calls that map keys to users."""

    def __init__(self, keys_by_user: dict[str, list[dict[str, str]]]) -> None:
        self.keys_by_user = keys_by_user

    def list_access_keys(self, *, UserName: str) -> dict[str, Any]:  # noqa: N803
        if UserName not in self.keys_by_user:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "user not found"}},
                "ListAccessKeys",
            )
        return {"AccessKeyMetadata": list(self.keys_by_user[UserName])}

    def get_access_key_last_used(self, *, AccessKeyId: str) -> dict[str, Any]:  # noqa: N803
        for user, keys in self.keys_by_user.items():
            for key in keys:
                if key["AccessKeyId"] == AccessKeyId:
                    return {"UserName": user, "AccessKeyLastUsed": {"ServiceName": "ec2"}}
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no such key"}},
            "GetAccessKeyLastUsed",
        )
