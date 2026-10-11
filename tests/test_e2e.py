"""End-to-end tests: fido2client against a real WebAuthn relying party.

The relying party is ``fido2.server.Fido2Server`` over HTTP on localhost. The
authenticator is a software CTAP2 device driven by the real ``fido2`` client
stack; only USB HID discovery is replaced. Signatures are real, so the
server's verification decides every outcome.
"""
from __future__ import annotations

import base64
import json
from collections.abc import Iterator

import cbor2
import pytest
from fido2.webauthn import UserVerificationRequirement

from fido2client import Fido2HttpClient
from fido2client.exceptions import FidoAuthenticationError

from .relying_party import BEGIN_PATH, COMPLETE_PATH, SESSION_COOKIE, RelyingParty
from .virtual_authenticator import VirtualAuthenticator

PIN = "1234"


@pytest.fixture()
def relying_party() -> Iterator[RelyingParty]:
    with RelyingParty() as rp:
        yield rp


def _register(authenticator: VirtualAuthenticator, rp: RelyingParty) -> bytes:
    credential = authenticator.create_credential(rp.rp_id)
    rp.credentials.append(credential)
    return credential.credential_id


def _authenticate(rp: RelyingParty, **kwargs) -> bool:
    with Fido2HttpClient() as client:
        return client.authenticate_to(rp.url, BEGIN_PATH, COMPLETE_PATH, **kwargs)


def test_server_verifies_assertion(authenticator, relying_party):
    credential_id = _register(authenticator, relying_party)
    prompts: list[str] = []

    with Fido2HttpClient() as client:
        result = client.authenticate_to(
            relying_party.url, BEGIN_PATH, COMPLETE_PATH, prompt_callback=prompts.append
        )

    assert result is True
    assert client.is_authenticated is True
    assert cbor2.loads(client.get_last_response().content) == {"status": "OK"}
    [complete] = relying_party.requests_to(COMPLETE_PATH)
    assert cbor2.loads(complete.body)["credentialId"] == credential_id
    assert prompts == ["Touch your authenticator device..."]


def test_client_authenticates_repeatedly(authenticator, relying_party):
    _register(authenticator, relying_party)

    with Fido2HttpClient() as client:
        first = client.authenticate_to(relying_party.url, BEGIN_PATH, COMPLETE_PATH)
        second = client.authenticate_to(relying_party.url, BEGIN_PATH, COMPLETE_PATH)

    assert (first, second) == (True, True)
    assert len(relying_party.requests_to(COMPLETE_PATH)) == 2


def test_server_rejects_signature_from_another_key(authenticator, relying_party):
    credential_id = _register(authenticator, relying_party)
    authenticator.replace_key(credential_id)

    with Fido2HttpClient() as client:
        result = client.authenticate_to(relying_party.url, BEGIN_PATH, COMPLETE_PATH)

    assert result is False
    assert client.is_authenticated is False
    assert cbor2.loads(client.get_last_response().content) == {
        "status": "FAILED",
        "message": "Invalid signature.",
    }


def test_authenticator_without_registered_credential_raises(authenticator, relying_party):
    relying_party.credentials.append(VirtualAuthenticator().create_credential("localhost"))

    with pytest.raises(FidoAuthenticationError):
        _authenticate(relying_party)

    assert relying_party.requests_to(COMPLETE_PATH) == []


def test_client_refuses_rp_id_foreign_to_server_origin(authenticator):
    with RelyingParty(rp_id="bank.example") as phishing_rp:
        _register(authenticator, phishing_rp)

        with pytest.raises(FidoAuthenticationError):
            _authenticate(phishing_rp)

        assert phishing_rp.requests_to(COMPLETE_PATH) == []
    assert authenticator.sign_count == 0


def test_headers_extra_data_and_session_cookie_reach_server(authenticator, relying_party):
    _register(authenticator, relying_party)

    result = _authenticate(
        relying_party,
        extra_headers={"X-Request-Id": "e2e-1"},
        extra_data={"session_id": "abc123"},
    )

    assert result is True
    [begin] = relying_party.requests_to(BEGIN_PATH)
    [complete] = relying_party.requests_to(COMPLETE_PATH)
    assert begin.headers["X-Request-Id"] == "e2e-1"
    assert complete.headers["X-Request-Id"] == "e2e-1"
    assert complete.headers["Content-Type"] == "application/cbor"
    assert f"{SESSION_COOKIE}=" in complete.headers["Cookie"]
    user_data = cbor2.loads(complete.body)["user_data"]
    assert json.loads(base64.b64decode(user_data)) == {"session_id": "abc123"}


@pytest.mark.parametrize("authenticator", [PIN], indirect=True)
def test_pin_satisfies_required_user_verification(authenticator):
    pin_requests: list[None] = []

    def pin_callback() -> str:
        pin_requests.append(None)
        return PIN

    with RelyingParty(user_verification=UserVerificationRequirement.REQUIRED) as rp:
        _register(authenticator, rp)
        result = _authenticate(rp, pin_callback=pin_callback)

    assert result is True
    assert len(pin_requests) == 1


@pytest.mark.parametrize("authenticator", [PIN], indirect=True)
@pytest.mark.parametrize("entered_pin", ["0000", ""], ids=["wrong-pin", "cancelled"])
def test_pin_not_accepted_raises(authenticator, relying_party, entered_pin):
    _register(authenticator, relying_party)

    with pytest.raises(FidoAuthenticationError):
        _authenticate(relying_party, pin_callback=lambda: entered_pin)

    assert relying_party.requests_to(COMPLETE_PATH) == []


def test_required_user_verification_without_pin_raises(authenticator):
    with RelyingParty(user_verification=UserVerificationRequirement.REQUIRED) as rp:
        _register(authenticator, rp)

        with pytest.raises(FidoAuthenticationError):
            _authenticate(rp)

        assert rp.requests_to(COMPLETE_PATH) == []
