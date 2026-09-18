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
        # What the table's stream would emit. Recorded here rather than hand-written in a
        # test, so the record that starts the workflow comes from the write that created
        # the incident and cannot drift away from it.
        self.stream: list[dict[str, Any]] = []

    def _emit(self, key: tuple[str, str], item: dict[str, Any], *, existed: bool) -> None:
        self.stream.append(
            {
                "eventName": "MODIFY" if existed else "INSERT",
                "dynamodb": {
                    "Keys": {"incident_id": {"S": key[0]}, "sk": {"S": key[1]}},
                    "NewImage": {
                        name: {"S": str(value)}
                        for name, value in item.items()
                        if isinstance(value, str)
                    },
                },
            }
        )

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> dict[str, Any]:  # noqa: N803
        self.put_calls += 1
        key = (Item["incident_id"], Item.get("sk", "incident"))
        existed = key in self.items
        if kwargs.get("ConditionExpression") is not None and existed:
            raise client_error("ConditionalCheckFailedException", "PutItem")
        self.items[key] = dict(Item)
        self._emit(key, self.items[key], existed=existed)
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
        self._emit((Key["incident_id"], Key.get("sk", "incident")), item, existed=True)
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
    """The IAM calls KILLSWITCH makes: identify a key's owner, list keys, deactivate one,
    and attach or read back the policy that revokes the sessions it already minted."""

    def __init__(
        self,
        keys_by_user: dict[str, list[dict[str, str]]],
        *,
        put_user_policy_error: ClientError | None = None,
    ) -> None:
        self.keys_by_user = keys_by_user
        self.update_calls: list[dict[str, str]] = []
        self.user_policies: dict[tuple[str, str], str] = {}
        self.put_user_policy_error = put_user_policy_error

    def put_user_policy(
        self,
        *,
        UserName: str,
        PolicyName: str,
        PolicyDocument: str,  # noqa: N803
    ) -> dict[str, Any]:
        if self.put_user_policy_error is not None:
            raise self.put_user_policy_error
        self.user_policies[(UserName, PolicyName)] = PolicyDocument
        return {}

    def get_user_policy(self, *, UserName: str, PolicyName: str) -> dict[str, Any]:  # noqa: N803
        document = self.user_policies.get((UserName, PolicyName))
        if document is None:
            raise client_error("NoSuchEntity", "GetUserPolicy")
        return {"UserName": UserName, "PolicyName": PolicyName, "PolicyDocument": document}

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


class FakeCloudTrail:
    """LookupEvents for one region. Records are handed in already shaped."""

    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self.records = records or []
        self.lookup_calls: list[dict[str, Any]] = []

    def lookup_events(self, **kwargs: Any) -> dict[str, Any]:
        self.lookup_calls.append(dict(kwargs))
        return {"Events": list(self.records)}
