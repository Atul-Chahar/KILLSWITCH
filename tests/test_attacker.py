"""The attack script must stay small, tagged, and incapable of hitting a real account."""

from __future__ import annotations

from typing import Any

AMI_ID = "ami-0test0000000000"


class StubEc2:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run_instances(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"Instances": [{"InstanceId": "i-0abc123def4567890"}]}


class StubSsm:
    def get_parameter(self, Name: str) -> dict[str, Any]:  # noqa: N803 - boto3 casing
        return {"Parameter": {"Name": Name, "Value": AMI_ID}}


class StubSession:
    """Fails loudly if the caller asks for a client the current mode should not need."""

    def __init__(self, *, allow_ec2: bool = True) -> None:
        self.ec2 = StubEc2()
        self._allow_ec2 = allow_ec2

    def client(self, service: str, region_name: str | None = None) -> Any:
        if service == "ssm":
            return StubSsm()
        if service == "ec2":
            if not self._allow_ec2:
                raise AssertionError("a dry run must not build an EC2 client")
            return self.ec2
        raise AssertionError(f"unexpected client {service}")


def test_launch_instance_requests_one_tagged_micro_instance(attacker):
    ec2 = StubEc2()
    instance_id = attacker.launch_instance(ec2, AMI_ID)

    assert instance_id == "i-0abc123def4567890"
    (call,) = ec2.calls
    assert call["ImageId"] == AMI_ID
    assert call["InstanceType"] == "t3.micro"
    assert call["MinCount"] == call["MaxCount"] == 1
    tags = call["TagSpecifications"][0]
    assert tags["ResourceType"] == "instance"
    assert tags["Tags"] == [{"Key": "demo", "Value": "killswitch-attack"}]


def test_resolve_ami_reads_the_public_amazon_linux_alias(attacker):
    assert attacker.resolve_ami(StubSsm()) == AMI_ID


def test_dry_run_launches_nothing(attacker):
    session = StubSession(allow_ec2=False)
    timeline = attacker.Timeline()

    instance_id = attacker.attack_region(session, "ap-south-1", timeline, dry_run=True)

    assert instance_id == "i-dryrun"


def test_a_real_run_launches_one_instance_in_the_region(attacker):
    session = StubSession()
    timeline = attacker.Timeline()

    instance_id = attacker.attack_region(session, "ap-south-1", timeline, dry_run=False)

    assert instance_id == "i-0abc123def4567890"
    assert len(session.ec2.calls) == 1


def test_regions_come_from_the_environment(attacker):
    env = {"AWS_REGION": "ap-south-1", "AWS_SECONDARY_REGION": "us-east-1"}
    assert attacker.regions_from_env(env) == ["ap-south-1", "us-east-1"]


def test_blank_regions_are_dropped_rather_than_passed_to_aws(attacker):
    assert attacker.regions_from_env({"AWS_REGION": "ap-south-1", "AWS_SECONDARY_REGION": ""}) == [
        "ap-south-1"
    ]


def test_refuses_to_run_without_two_regions(attacker, monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_SECONDARY_REGION", raising=False)
    assert attacker.main([]) == 2


def test_argument_parsing_accepts_the_documented_flags(attacker):
    args = attacker.parse_args(["--dry-run", "--regions", "ap-south-1", "us-east-1"])
    assert args.dry_run is True
    assert args.regions == ["ap-south-1", "us-east-1"]
