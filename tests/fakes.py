"""In-memory stand-ins for the AWS clients. No unit test touches a real service."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError


def client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class FakeTable:
    """Enough DynamoDB to test conditional writes and a sort-key query, and no more."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.put_calls = 0

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> dict[str, Any]:  # noqa: N803
        self.put_calls += 1
        key = (Item["incident_id"], Item.get("sk", "incident"))
        if kwargs.get("ConditionExpression") is not None and key in self.items:
            raise client_error("ConditionalCheckFailedException", "PutItem")
        self.items[key] = dict(Item)
        return {}

    def get_item(self, *, Key: dict[str, Any]) -> dict[str, Any]:  # noqa: N803
        item = self.items.get((Key["incident_id"], Key.get("sk", "incident")))
        return {"Item": dict(item)} if item else {}

    def update_item(
        self,
        *,
        Key: dict[str, Any],  # noqa: N803
        UpdateExpression: str,  # noqa: N803
        ExpressionAttributeValues: dict[str, Any],  # noqa: N803
        ExpressionAttributeNames: dict[str, str] | None = None,  # noqa: N803
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """Applies only the SET form the store uses; anything else is a test bug."""
        names = ExpressionAttributeNames or {}
        item = self.items.setdefault((Key["incident_id"], Key.get("sk", "incident")), dict(Key))
        assignments = UpdateExpression.removeprefix("SET").split(",")
        for assignment in assignments:
            field, _, placeholder = assignment.partition("=")
            field = field.strip()
            item[names.get(field, field)] = ExpressionAttributeValues[placeholder.strip()]
        return {}

    def query(self, *, KeyConditionExpression: Any, **_kwargs: Any) -> dict[str, Any]:  # noqa: N803
        """Serves the one query shape the store issues: partition plus sort-key prefix."""
        expression = KeyConditionExpression
        incident_id, prefix = _partition_and_prefix(expression)
        matching = [
            dict(item)
            for (item_incident, sort_key), item in sorted(self.items.items())
            if item_incident == incident_id and sort_key.startswith(prefix)
        ]
        return {"Items": matching}


def _partition_and_prefix(expression: Any) -> tuple[str, str]:
    """Pull the values back out of a boto3 Key condition without a real DynamoDB."""
    incident_id = ""
    prefix = ""
    for condition in getattr(expression, "_values", ()):
        name = getattr(getattr(condition, "_values", [None])[0], "name", None)
        values = getattr(condition, "_values", ())
        if name == "incident_id":
            incident_id = str(values[1])
        elif name == "sk":
            prefix = str(values[1])
    return incident_id, prefix


class FakeIam:
    """The IAM calls KILLSWITCH makes: identify a key's owner, list keys, deactivate one."""

    def __init__(self, keys_by_user: dict[str, list[dict[str, str]]]) -> None:
        self.keys_by_user = keys_by_user
        self.update_calls: list[dict[str, str]] = []

    def list_access_keys(self, *, UserName: str) -> dict[str, Any]:  # noqa: N803
        if UserName not in self.keys_by_user:
            raise client_error("NoSuchEntity", "ListAccessKeys")
        return {"AccessKeyMetadata": list(self.keys_by_user[UserName])}

    def get_access_key_last_used(self, *, AccessKeyId: str) -> dict[str, Any]:  # noqa: N803
        for user, keys in self.keys_by_user.items():
            for key in keys:
                if key["AccessKeyId"] == AccessKeyId:
                    return {"UserName": user, "AccessKeyLastUsed": {"ServiceName": "ec2"}}
        raise client_error("AccessDenied", "GetAccessKeyLastUsed")

    def update_access_key(self, *, UserName: str, AccessKeyId: str, Status: str) -> dict[str, Any]:  # noqa: N803
        self.update_calls.append(
            {"UserName": UserName, "AccessKeyId": AccessKeyId, "Status": Status}
        )
        for key in self.keys_by_user.get(UserName, []):
            if key["AccessKeyId"] == AccessKeyId:
                key["Status"] = Status
                return {}
        raise client_error("NoSuchEntity", "UpdateAccessKey")


class FakeEc2:
    """Instance state per region, and a record of every termination attempted."""

    def __init__(self, instances: dict[str, str] | None = None) -> None:
        self.instances = instances or {}
        self.terminate_calls: list[list[str]] = []

    def terminate_instances(self, *, InstanceIds: list[str]) -> dict[str, Any]:  # noqa: N803
        self.terminate_calls.append(list(InstanceIds))
        changed = []
        for instance_id in InstanceIds:
            if instance_id not in self.instances:
                raise client_error("InvalidInstanceID.NotFound", "TerminateInstances")
            previous = self.instances[instance_id]
            self.instances[instance_id] = "shutting-down"
            changed.append(
                {
                    "InstanceId": instance_id,
                    "PreviousState": {"Name": previous},
                    "CurrentState": {"Name": "shutting-down"},
                }
            )
        return {"TerminatingInstances": changed}

    def describe_instances(self, *, InstanceIds: list[str]) -> dict[str, Any]:  # noqa: N803
        instances = []
        for instance_id in InstanceIds:
            if instance_id not in self.instances:
                raise client_error("InvalidInstanceID.NotFound", "DescribeInstances")
            instances.append(
                {"InstanceId": instance_id, "State": {"Name": self.instances[instance_id]}}
            )
        return {"Reservations": [{"Instances": instances}]}
