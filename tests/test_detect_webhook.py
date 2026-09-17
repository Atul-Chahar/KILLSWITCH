"""An unsigned or forged webhook must never be able to open an incident."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from detect.webhook import SignatureError, verify_signature

SECRET = "test-webhook-secret"
BODY = b'{"ref":"refs/heads/main"}'


def valid_header(secret: str = SECRET, body: bytes = BODY) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_a_correctly_signed_body_is_accepted():
    verify_signature(SECRET, BODY, valid_header())


def test_a_body_changed_after_signing_is_rejected():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, b'{"ref":"refs/heads/evil"}', valid_header())


def test_a_signature_from_the_wrong_secret_is_rejected():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, BODY, valid_header(secret="not-the-secret"))


def test_a_missing_signature_header_is_rejected():
    with pytest.raises(SignatureError, match="missing"):
        verify_signature(SECRET, BODY, None)


def test_an_unsupported_algorithm_is_rejected():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, BODY, "sha1=abcdef")


def test_a_malformed_header_is_rejected():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, BODY, "not-a-signature")


def test_an_empty_secret_is_refused_rather_than_trusted():
    with pytest.raises(SignatureError, match="secret"):
        verify_signature("", BODY, valid_header(secret=""))
