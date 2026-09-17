"""What counts as a leaked key, and what is just documentation."""

from __future__ import annotations

from detect.patterns import find_access_key_ids, is_example_key

REAL_LOOKING_KEY = "AKIA" + "TESTFAKEKEY00001"
SECOND_KEY = "AKIA" + "TESTFAKEKEY00002"
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
DOCS_EXAMPLE_KEY = "AKIA" + "I44QH8DHBEXAMPLE"


def test_finds_a_key_in_an_added_diff_line():
    patch = f"@@ -0,0 +1 @@\n+AWS_ACCESS_KEY_ID={REAL_LOOKING_KEY}\n"
    assert find_access_key_ids(patch) == [REAL_LOOKING_KEY]


def test_ignores_the_aws_documented_example_key():
    patch = f"+AWS_ACCESS_KEY_ID={AWS_EXAMPLE_KEY}\n"
    assert find_access_key_ids(patch) == []


def test_ignores_other_keys_ending_in_example():
    assert find_access_key_ids(f"key = {DOCS_EXAMPLE_KEY}") == []
    assert is_example_key(DOCS_EXAMPLE_KEY) is True


def test_finds_a_real_key_sitting_next_to_an_example_key():
    patch = f"+EXAMPLE={AWS_EXAMPLE_KEY}\n+REAL={REAL_LOOKING_KEY}\n"
    assert find_access_key_ids(patch) == [REAL_LOOKING_KEY]


def test_reports_each_distinct_key_once_in_order():
    patch = f"{REAL_LOOKING_KEY} {SECOND_KEY} {REAL_LOOKING_KEY}"
    assert find_access_key_ids(patch) == [REAL_LOOKING_KEY, SECOND_KEY]


def test_empty_text_finds_nothing():
    assert find_access_key_ids("") == []


def test_a_string_that_merely_starts_with_akia_is_not_a_key():
    assert find_access_key_ids("AKIASHORT") == []


def test_lowercase_is_not_an_access_key_id():
    assert find_access_key_ids("akiatestfakekey00001") == []
