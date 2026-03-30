from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import cbor2
import pytest
import requests
from fido2.client import PinRequiredError

from fido2client import Fido2HttpClient
from fido2client.exceptions import (
    FidoDeviceNotFoundError,
    FidoServerError,
)

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

MOCK_SERVER = "https://example.com"
MOCK_RP_ID = "example.com"
MOCK_CHALLENGE = b"\x01\x02\x03\x04"
MOCK_CRED_ID = b"\x05\x06\x07\x08"
MOCK_CRED_ID_2 = b"\x09\x0a\x0b\x0c"
MOCK_CRED_ID_3 = b"\x0d\x0e\x0f\x10"

MOCK_BEGIN_PAYLOAD = {
    "publicKey": {
        "rpId": MOCK_RP_ID,
        "challenge": MOCK_CHALLENGE,
        "allowCredentials": [{"id": MOCK_CRED_ID, "type": "public-key"}],
        "timeout": 30000,
        "userVerification": "preferred",
    }
}


def _http_response(payload: dict, status_code: int = 200) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.content = cbor2.dumps(payload)
    r.status_code = status_code
    r.raise_for_status = MagicMock()
    return r


def _mock_assertion() -> MagicMock:
    a = MagicMock()
    a.credential = {"id": MOCK_CRED_ID, "type": "public-key"}
    a.auth_data = b"\xaa\xbb\xcc"
    a.signature = b"\xdd\xee\xff"
    return a


@pytest.fixture()
def mock_device():
    device = MagicMock()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([device])):
        yield device


@pytest.fixture()
def mock_no_device():
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([])):
        yield


@pytest.fixture()
def mock_fido2(mock_device):
    """Patches Fido2Client.get_assertion to return a successful assertion."""
    assertion = _mock_assertion()
    client_data = '{"type":"webauthn.get"}'
    with patch("fido2client.client.Fido2Client") as MockFido2Client:
        instance = MockFido2Client.return_value
        instance.get_assertion.return_value = ([assertion], client_data)
        yield instance


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------


def test_no_device_raises(mock_no_device):
    client = Fido2HttpClient()
    with pytest.raises(FidoDeviceNotFoundError):
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_authenticate_success(mock_fido2):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = [
            _http_response(MOCK_BEGIN_PAYLOAD),
            _http_response({"status": "OK"}),
        ]

        client = Fido2HttpClient()
        result = client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is True
    assert client.is_authenticated is True


def test_authenticate_failure(mock_fido2):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = [
            _http_response(MOCK_BEGIN_PAYLOAD),
            _http_response({"status": "FAILED", "message": "invalid signature"}),
        ]

        client = Fido2HttpClient()
        result = client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is False
    assert client.is_authenticated is False


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------


def test_begin_network_error(mock_device):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = requests.exceptions.ConnectionError("refused")

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="Begin request failed"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_complete_network_error(mock_fido2):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = [
            _http_response(MOCK_BEGIN_PAYLOAD),
            requests.exceptions.ConnectionError("refused"),
        ]

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="Complete request failed"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


# ---------------------------------------------------------------------------
# Malformed server responses
# ---------------------------------------------------------------------------


def test_begin_undecoded_cbor(mock_device):
    """Server returns bytes that CBOR cannot decode at all."""
    bad = MagicMock(spec=requests.Response)
    bad.content = b"\xc0"
    bad.raise_for_status = MagicMock()

    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.return_value = bad

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="Could not decode CBOR begin response"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_non_dict_cbor(mock_device):
    """Server returns valid CBOR but not a dict (e.g. a string)."""
    bad = MagicMock(spec=requests.Response)
    bad.content = cbor2.dumps("not a dict")
    bad.raise_for_status = MagicMock()

    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.return_value = bad

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="Unexpected CBOR begin response type"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_missing_public_key(mock_device):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.return_value = _http_response({"somethingElse": {}})

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="Missing 'publicKey'"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_empty_allow_credentials(mock_device):
    payload = {
        "publicKey": {
            "rpId": MOCK_RP_ID,
            "challenge": MOCK_CHALLENGE,
            "allowCredentials": [],
        }
    }
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.return_value = _http_response(payload)

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="empty or missing 'allowCredentials'"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


def test_begin_missing_rp_id(mock_device):
    payload = {
        "publicKey": {
            "challenge": MOCK_CHALLENGE,
            "allowCredentials": [{"id": MOCK_CRED_ID, "type": "public-key"}],
        }
    }
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.return_value = _http_response(payload)

        client = Fido2HttpClient()
        with pytest.raises(FidoServerError, match="Missing required field 'rpId'"):
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")


# ---------------------------------------------------------------------------
# PIN fallback
# ---------------------------------------------------------------------------


def test_pin_fallback(mock_device):
    assertion = _mock_assertion()
    client_data = '{"type":"webauthn.get"}'

    with patch("fido2client.client.Fido2Client") as MockFido2Client:
        instance = MockFido2Client.return_value
        instance.get_assertion.side_effect = [
            PinRequiredError(),
            ([assertion], client_data),
        ]

        with patch("fido2client.client.requests.Session") as MockSession:
            session = MockSession.return_value
            session.post.side_effect = [
                _http_response(MOCK_BEGIN_PAYLOAD),
                _http_response({"status": "OK"}),
            ]

            client = Fido2HttpClient()
            result = client.authenticate_to(
                MOCK_SERVER, "/begin", "/complete",
                pin_callback=lambda: "1234",
            )

    assert result is True


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


def test_context_manager_closes_session(mock_fido2):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = [
            _http_response(MOCK_BEGIN_PAYLOAD),
            _http_response({"status": "OK"}),
        ]

        with Fido2HttpClient() as client:
            client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

        session.close.assert_called_once()


# ---------------------------------------------------------------------------
# get_last_response
# ---------------------------------------------------------------------------


def test_get_last_response_is_none_before_auth():
    client = Fido2HttpClient()
    assert client.get_last_response() is None


def test_get_last_response_after_auth(mock_fido2):
    complete_resp = _http_response({"status": "OK"})

    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = [_http_response(MOCK_BEGIN_PAYLOAD), complete_resp]

        client = Fido2HttpClient()
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert client.get_last_response() is complete_resp


# ---------------------------------------------------------------------------
# Extra headers forwarded to both requests
# ---------------------------------------------------------------------------


def test_extra_headers_forwarded(mock_fido2):
    with patch("fido2client.client.requests.Session") as MockSession:
        session = MockSession.return_value
        session.post.side_effect = [
            _http_response(MOCK_BEGIN_PAYLOAD),
            _http_response({"status": "OK"}),
        ]

        client = Fido2HttpClient()
        client.authenticate_to(
            MOCK_SERVER,
            "/begin",
            "/complete",
            extra_headers={"X-Custom": "value"},
        )

    for call in session.post.call_args_list:
        assert call.kwargs["headers"].get("X-Custom") == "value"


# ---------------------------------------------------------------------------
# External session is reused
# ---------------------------------------------------------------------------


def test_external_session_reused(mock_fido2):
    external = MagicMock(spec=requests.Session)
    external.post.side_effect = [
        _http_response(MOCK_BEGIN_PAYLOAD),
        _http_response({"status": "OK"}),
    ]

    with Fido2HttpClient() as client:
        client.authenticate_to(MOCK_SERVER, "/begin", "/complete", session=external)

    assert client.session is external
    external.close.assert_not_called()
    assert external.post.call_count == 2


# ---------------------------------------------------------------------------
# Multiple credentials
# ---------------------------------------------------------------------------


def test_all_credentials_passed_to_authenticator(mock_device):
    """When the server returns multiple allowCredentials, all must reach the authenticator."""
    multi_cred_payload = {
        "publicKey": {
            "rpId": MOCK_RP_ID,
            "challenge": MOCK_CHALLENGE,
            "allowCredentials": [
                {"id": MOCK_CRED_ID, "type": "public-key"},
                {"id": MOCK_CRED_ID_2, "type": "public-key"},
                {"id": MOCK_CRED_ID_3, "type": "public-key"},
            ],
            "timeout": 30000,
            "userVerification": "preferred",
        }
    }

    assertion = _mock_assertion()
    client_data = '{"type":"webauthn.get"}'

    with patch("fido2client.client.Fido2Client") as MockFido2Client:
        instance = MockFido2Client.return_value
        instance.get_assertion.return_value = ([assertion], client_data)

        with patch("fido2client.client.requests.Session") as MockSession:
            session = MockSession.return_value
            session.post.side_effect = [
                _http_response(multi_cred_payload),
                _http_response({"status": "OK"}),
            ]

            client = Fido2HttpClient()
            result = client.authenticate_to(MOCK_SERVER, "/begin", "/complete")

    assert result is True
    allow_list = instance.get_assertion.call_args[0][2]
    assert len(allow_list) == 3
    assert allow_list[0]["id"] == MOCK_CRED_ID
    assert allow_list[1]["id"] == MOCK_CRED_ID_2
    assert allow_list[2]["id"] == MOCK_CRED_ID_3
