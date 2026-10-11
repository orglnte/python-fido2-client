"""Tests for Fido2HttpClient with the HTTP layer mocked.

The FIDO2 side is real: ``fido2.client.Fido2Client`` drives the software
authenticator from ``tests/virtual_authenticator.py``, so a change in the
fido2 API surfaces here instead of being absorbed by a mock.
"""
from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import cbor2
import pytest
import requests
from fido2.utils import websafe_encode

from fido2client import Fido2HttpClient, WireFormat
from fido2client.client import logger as client_logger
from fido2client.exceptions import (
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)

from .virtual_authenticator import VirtualAuthenticator

MOCK_SERVER = "https://example.com"
MOCK_RP_ID = "example.com"
MOCK_CHALLENGE = b"\x01\x02\x03\x04" * 8
FOREIGN_CRED_ID = b"\x09\x0a\x0b\x0c"
OTHER_FOREIGN_CRED_ID = b"\x0d\x0e\x0f\x10"


def _begin_payload(*credential_ids: bytes, rp_id: str = MOCK_RP_ID) -> dict:
    return {
        "publicKey": {
            "rpId": rp_id,
            "challenge": MOCK_CHALLENGE,
            "allowCredentials": [{"id": cid, "type": "public-key"} for cid in credential_ids],
            "timeout": 30000,
            "userVerification": "preferred",
        }
    }


def _http_response(payload, status_code: int = 200) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.content = cbor2.dumps(payload)
    r.status_code = status_code
    r.raise_for_status = MagicMock()
    return r


def _json_response(payload) -> MagicMock:
    return _raw_response(json.dumps(payload).encode())


def _raw_response(content: bytes) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.content = content
    r.status_code = 200
    r.raise_for_status = MagicMock()
    return r


@pytest.fixture()
def credential_id(authenticator: VirtualAuthenticator) -> bytes:
    return authenticator.create_credential(MOCK_RP_ID).credential_id


@pytest.fixture()
def session():
    with patch("fido2client.client.requests.Session") as MockSession:
        yield MockSession.return_value


def _complete_body(session) -> dict:
    return cbor2.loads(session.post.call_args_list[1].kwargs["data"])


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------


def test_no_device_raises():
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([])):
        client = Fido2HttpClient()
        with pytest.raises(FidoDeviceNotFoundError):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


# ---------------------------------------------------------------------------
# Ceremony
# ---------------------------------------------------------------------------


def test_authenticate_success(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
    ]

    client = Fido2HttpClient()
    result = client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is True
    assert client.is_authenticated is True
    body = _complete_body(session)
    assert set(body) == {"credentialId", "authenticatorData", "clientDataJSON", "signature", "user_data"}
    assert body["credentialId"] == credential_id
    client_data = json.loads(body["clientDataJSON"])
    assert client_data["type"] == "webauthn.get"
    assert client_data["origin"] == MOCK_SERVER
    assert client_data["challenge"] == websafe_encode(MOCK_CHALLENGE)


def test_authenticate_failure(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "FAILED", "message": "invalid signature"}),
    ]

    client = Fido2HttpClient()
    result = client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is False
    assert client.is_authenticated is False


def test_client_error_status_on_complete_is_a_rejection(session, credential_id):
    unauthorized = _raw_response(b"<html>401 Unauthorized</html>")
    unauthorized.status_code = 401
    session.post.side_effect = [_http_response(_begin_payload(credential_id)), unauthorized]

    client = Fido2HttpClient()
    result = client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is False
    assert client.is_authenticated is False
    assert client.get_last_response() is unauthorized
    unauthorized.raise_for_status.assert_not_called()


def test_origin_is_scheme_and_host_of_server_url(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
    ]

    Fido2HttpClient().authenticate_to(f"{MOCK_SERVER}/app/", "/begin", "/complete")

    assert json.loads(_complete_body(session)["clientDataJSON"])["origin"] == MOCK_SERVER


def test_authenticator_picks_its_credential_from_allow_list(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(FOREIGN_CRED_ID, credential_id, OTHER_FOREIGN_CRED_ID)),
        _http_response({"status": "OK"}),
    ]

    result = Fido2HttpClient().authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is True
    assert _complete_body(session)["credentialId"] == credential_id


def test_rp_id_foreign_to_server_origin_raises(session, authenticator):
    foreign_cred = authenticator.create_credential("bank.example").credential_id
    session.post.side_effect = [_http_response(_begin_payload(foreign_cred, rp_id="bank.example"))]

    with pytest.raises(FidoAuthenticationError):
        Fido2HttpClient().authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert session.post.call_count == 1


def test_is_authenticated_resets_when_next_attempt_fails(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
        requests.exceptions.ConnectionError("refused"),
    ]

    client = Fido2HttpClient()
    assert client.authenticate_to(MOCK_SERVER, "/begin", "/complete") is True
    with pytest.raises(FidoServerError):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert client.is_authenticated is False


def test_begin_sends_no_body_without_begin_data(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
    ]

    Fido2HttpClient().authenticate_to(MOCK_SERVER, "/begin", "/complete")

    begin_call = session.post.call_args_list[0]
    assert begin_call.kwargs["data"] is None
    assert "content-type" not in begin_call.kwargs["headers"]


# ---------------------------------------------------------------------------
# JSON wire format
# ---------------------------------------------------------------------------


def _bare_json_options(*credential_ids: bytes) -> dict:
    return {
        "challenge": websafe_encode(MOCK_CHALLENGE),
        "rpId": MOCK_RP_ID,
        "allowCredentials": [{"id": websafe_encode(cid), "type": "public-key"} for cid in credential_ids],
        "userVerification": "preferred",
    }


def test_json_accepts_bare_options_and_sends_webauthn_json(session, credential_id):
    session.post.side_effect = [
        _json_response(_bare_json_options(credential_id)),
        _json_response({"status": "OK"}),
    ]

    result = Fido2HttpClient().authenticate_to(
        MOCK_SERVER, "/begin", "/complete",
        wire_format=WireFormat.JSON,
        begin_data={"username": "alice"},
        extra_data={"rawId": "spoofed", "device_name": "ci"},
    )

    assert result is True
    begin_call, complete_call = session.post.call_args_list
    assert json.loads(begin_call.kwargs["data"]) == {"username": "alice"}
    assert begin_call.kwargs["headers"]["content-type"] == "application/json"
    assert complete_call.kwargs["headers"]["content-type"] == "application/json"
    body = json.loads(complete_call.kwargs["data"])
    assert body["rawId"] == body["id"] == websafe_encode(credential_id)
    assert body["type"] == "public-key"
    assert set(body["response"]) >= {"clientDataJSON", "authenticatorData", "signature"}
    assert body["device_name"] == "ci"


def test_json_begin_undecodable(session, authenticator):
    session.post.return_value = _raw_response(b"<html>login</html>")

    with pytest.raises(FidoServerError, match="Could not decode JSON begin response"):
        Fido2HttpClient().authenticate_to(
            MOCK_SERVER, "/begin", "/complete", wire_format=WireFormat.JSON
        )


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------


def test_begin_network_error(session, authenticator):
    session.post.side_effect = requests.exceptions.ConnectionError("refused")

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Begin request failed"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_complete_network_error(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        requests.exceptions.ConnectionError("refused"),
    ]

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Complete request failed"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


# ---------------------------------------------------------------------------
# Malformed server responses
# ---------------------------------------------------------------------------


def test_begin_undecoded_cbor(session, authenticator):
    """Server returns bytes that CBOR cannot decode at all."""
    session.post.return_value = _raw_response(b"\xc0")

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Could not decode CBOR begin response"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_non_dict_cbor(session, authenticator):
    """Server returns valid CBOR but not a dict (e.g. a string)."""
    session.post.return_value = _http_response("not a dict")

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Unexpected CBOR begin response type"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_without_request_options(session, authenticator):
    session.post.return_value = _http_response({"somethingElse": {}})

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Missing required field 'rpId'"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_empty_allow_credentials(session, authenticator):
    session.post.return_value = _http_response(_begin_payload())

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="empty or missing 'allowCredentials'"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_missing_rp_id(session, credential_id):
    payload = _begin_payload(credential_id)
    del payload["publicKey"]["rpId"]
    session.post.return_value = _http_response(payload)

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Missing required field 'rpId'"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_complete_undecoded_cbor(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _raw_response(b"\xff\xfe\xfd"),
    ]

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="Could not decode CBOR complete response"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_complete_non_dict_cbor(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response(["OK"]),
    ]

    client = Fido2HttpClient()
    with pytest.raises(FidoServerError, match="unexpected type list"):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


# ---------------------------------------------------------------------------
# Session handling
# ---------------------------------------------------------------------------


def test_context_manager_closes_session(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
    ]

    with Fido2HttpClient() as client:
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    session.close.assert_called_once()


def test_external_session_reused(credential_id):
    external = MagicMock(spec=requests.Session)
    external.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
    ]

    with Fido2HttpClient() as client:
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete", session=external)

    assert client.session is external
    external.close.assert_not_called()
    assert external.post.call_count == 2


def test_get_last_response_is_none_before_auth():
    client = Fido2HttpClient()
    assert client.get_last_response() is None


def test_get_last_response_after_auth(session, credential_id):
    complete_resp = _http_response({"status": "OK"})
    session.post.side_effect = [_http_response(_begin_payload(credential_id)), complete_resp]

    client = Fido2HttpClient()
    client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert client.get_last_response() is complete_resp


def test_extra_headers_forwarded(session, credential_id):
    session.post.side_effect = [
        _http_response(_begin_payload(credential_id)),
        _http_response({"status": "OK"}),
    ]

    client = Fido2HttpClient()
    client.authenticate_to(
        MOCK_SERVER,
        "/begin",
        "/complete",
        extra_headers={"X-Custom": "value"},
    )

    assert session.post.call_count == 2
    for call in session.post.call_args_list:
        assert call.kwargs["headers"].get("X-Custom") == "value"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


@pytest.fixture()
def restore_client_logger():
    handlers, level = list(client_logger.handlers), client_logger.level
    yield
    client_logger.handlers[:] = handlers
    client_logger.setLevel(level)


def test_verbose_attaches_one_handler_for_many_clients(restore_client_logger):
    before = len(client_logger.handlers)

    Fido2HttpClient(verbose=True)
    Fido2HttpClient(verbose=True)

    assert len(client_logger.handlers) == before + 1
    assert client_logger.level == logging.DEBUG
