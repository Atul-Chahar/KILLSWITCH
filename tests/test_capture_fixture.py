"""The scrubber decides what reaches the repository, so it is tested like a safety control."""

from __future__ import annotations

import json
from datetime import UTC, datetime

REAL_ACCOUNT = "123456789012"
REAL_KEY = "AKIA" + "REALLOOKINGKEY01"
REAL_IP = "198.51.100.77"


def record_with_real_values() -> dict:
    detail = {
        "userIdentity": {
            "arn": f"arn:aws:iam::{REAL_ACCOUNT}:user/demo-leaky-user",
            "accountId": REAL_ACCOUNT,
            "accessKeyId": REAL_KEY,
        },
        "awsRegion": "ap-south-1",
        "sourceIPAddress": REAL_IP,
        "userAgent": "aws-cli/2.15.0 Python/3.11 Linux/6.1 exec-env/CloudShell",
        "recipientAccountId": REAL_ACCOUNT,
        "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0a1b2c3d4e5f60001"}]}},
    }
    return {
        "EventId": "abc",
        "EventName": "RunInstances",
        "EventTime": datetime(2026, 9, 18, 10, 12, 41, tzinfo=UTC),
        "AccessKeyId": REAL_KEY,
        "Resources": [
            {"ResourceType": "AWS::EC2::Instance", "ResourceName": "i-0a1b2c3d4e5f60001"}
        ],
        "CloudTrailEvent": json.dumps(detail),
    }


def scrubbed(capture) -> tuple[dict, str]:
    result = capture.scrub_record(record_with_real_values())
    return result, json.dumps(result)


def test_the_account_id_is_gone_from_the_outer_record(capture_fixture):
    _result, text = scrubbed(capture_fixture)
    assert REAL_ACCOUNT not in text


def test_the_account_id_is_gone_from_inside_the_nested_event(capture_fixture):
    """This is the field that would otherwise carry the account id into git."""
    result, _text = scrubbed(capture_fixture)
    detail = json.loads(result["CloudTrailEvent"])
    assert detail["userIdentity"]["accountId"] == "000000000000"
    assert detail["recipientAccountId"] == "000000000000"


def test_the_account_id_is_gone_from_arns(capture_fixture):
    result, _text = scrubbed(capture_fixture)
    arn = json.loads(result["CloudTrailEvent"])["userIdentity"]["arn"]
    assert arn == "arn:aws:iam::000000000000:user/demo-leaky-user"


def test_the_access_key_id_becomes_the_aws_example_key(capture_fixture):
    """A real-looking key id in a fixture would, correctly, fail check_secrets.sh."""
    result, text = scrubbed(capture_fixture)
    assert REAL_KEY not in text
    assert result["AccessKeyId"] == "AKIA" + "IOSFODNN7EXAMPLE"


def test_the_source_ip_becomes_a_documentation_address(capture_fixture):
    result, _text = scrubbed(capture_fixture)
    assert json.loads(result["CloudTrailEvent"])["sourceIPAddress"] == "203.0.113.10"


def test_the_user_agent_is_dropped(capture_fixture):
    result, _text = scrubbed(capture_fixture)
    assert json.loads(result["CloudTrailEvent"])["userAgent"] == "scrubbed"


def test_the_evidence_itself_survives_scrubbing(capture_fixture):
    """Scrubbing must not destroy what the fixture exists to prove."""
    result, _text = scrubbed(capture_fixture)
    detail = json.loads(result["CloudTrailEvent"])
    assert detail["responseElements"]["instancesSet"]["items"][0]["instanceId"] == (
        "i-0a1b2c3d4e5f60001"
    )
    assert result["EventName"] == "RunInstances"


def test_event_time_is_written_as_an_iso_string(capture_fixture):
    result, _text = scrubbed(capture_fixture)
    assert result["EventTime"] == "2026-09-18T10:12:41+00:00"
