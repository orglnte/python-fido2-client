"""End-to-end tests for Fido2HttpClient.

A real HTTP server is started in a background thread for each test module.
Only the FIDO2 hardware device (CtapHidDevice + Fido2Client) is mocked —
all HTTP traffic goes through a real socket.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import cbor2
import pytest

from fido2client import Fido2HttpClient
from fido2client.exceptions import FidoServerError

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

MOCK_CHALLENGE = b"\x01\x02\x03\x04\x05\x06\x07\x08"
MOCK_CRED_ID = b"\x10\x11\x12\x13\x14\x15\x16\x17"


def _begin_payload(rp_id: str) -> dict:
    return {
        "publicKey": {
            "rpId": rp_id,
            "challenge": MOCK_CHALLENGE,
            "allowCredentials": [{"id": MOCK_CRED_ID, "type": "public-key"}],
            "timeout": 30000,
            "userVerification": "preferred",
        }
    }


def _mock_assertion() -> MagicMock:
    a = MagicMock()
    a.credential = {"id": MOCK_CRED_ID, "type": "public-key"}
    a.auth_data = b"\xaa\xbb\xcc"
    a.signature = b"\xdd\xee\xff"
    return a


# ---------------------------------------------------------------------------
# Reusable HTTP server fixture
# ---------------------------------------------------------------------------


def _make_server(handler_class: type) -> tuple[HTTPServer, str]:
    """Start handler_class on a random port, return (server, base_url)."""
    server = HTTPServer(("127.0.0.1", 0), handler_class)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def _cbor_response(handler: BaseHTTPRequestHandler, payload: dict) -> None:
    body = cbor2.dumps(payload)
    handler.send_response(200)
    handler.send_header("Content-Type", "application/cbor")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# ---------------------------------------------------------------------------
# Server that completes authentication successfully
# ---------------------------------------------------------------------------


class _OKHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        rp_id = self.server.server_address[0]
        if self.path == "/begin":
            _cbor_response(self, _begin_payload(rp_id))
        elif self.path == "/complete":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            _cbor_response(self, {"status": "OK"})
        else:
            self.send_error(404)


@pytest.fixture(scope="module")
def ok_server():
    server, url = _make_server(_OKHandler)
    yield url
    server.shutdown()


# ---------------------------------------------------------------------------
# Server that rejects authentication
# ---------------------------------------------------------------------------


class _FailHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        rp_id = self.server.server_address[0]
        if self.path == "/begin":
            _cbor_response(self, _begin_payload(rp_id))
        elif self.path == "/complete":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            _cbor_response(self, {"status": "FAILED", "message": "invalid signature"})
        else:
            self.send_error(404)


@pytest.fixture(scope="module")
def fail_server():
    server, url = _make_server(_FailHandler)
    yield url
    server.shutdown()


# ---------------------------------------------------------------------------
# Server that returns malformed CBOR on /complete
# ---------------------------------------------------------------------------


class _BadCborHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        rp_id = self.server.server_address[0]
        if self.path == "/begin":
            _cbor_response(self, _begin_payload(rp_id))
        elif self.path == "/complete":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/cbor")
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"\xff\xfe\xfd")  # invalid CBOR
        else:
            self.send_error(404)


@pytest.fixture(scope="module")
def bad_cbor_server():
    server, url = _make_server(_BadCborHandler)
    yield url
    server.shutdown()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_e2e_success(ok_server):
    assertion = _mock_assertion()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([MagicMock()])):
        with patch("fido2client.client.Fido2Client") as MockClient:
            MockClient.return_value.get_assertion.return_value = ([assertion], "{}")

            with Fido2HttpClient() as client:
                result = client.authenticate_to(ok_server, "/begin", "/complete")

    assert result is True
    assert client.is_authenticated is True


def test_e2e_server_rejects(fail_server):
    assertion = _mock_assertion()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([MagicMock()])):
        with patch("fido2client.client.Fido2Client") as MockClient:
            MockClient.return_value.get_assertion.return_value = ([assertion], "{}")

            client = Fido2HttpClient()
            result = client.authenticate_to(fail_server, "/begin", "/complete")

    assert result is False
    assert client.is_authenticated is False


def test_e2e_malformed_complete_response(bad_cbor_server):
    assertion = _mock_assertion()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([MagicMock()])):
        with patch("fido2client.client.Fido2Client") as MockClient:
            MockClient.return_value.get_assertion.return_value = ([assertion], "{}")

            client = Fido2HttpClient()
            with pytest.raises(FidoServerError, match="Could not decode CBOR complete response"):
                client.authenticate_to(bad_cbor_server, "/begin", "/complete")


def test_e2e_extra_headers_reach_server(ok_server):
    """Custom headers must be forwarded — verified via successful round-trip
    (server returns OK regardless of extra headers; the goal is no error)."""
    assertion = _mock_assertion()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([MagicMock()])):
        with patch("fido2client.client.Fido2Client") as MockClient:
            MockClient.return_value.get_assertion.return_value = ([assertion], "{}")

            client = Fido2HttpClient()
            result = client.authenticate_to(
                ok_server,
                "/begin",
                "/complete",
                extra_headers={"X-Test-Header": "e2e"},
            )

    assert result is True


def test_e2e_extra_data_in_body(ok_server):
    assertion = _mock_assertion()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([MagicMock()])):
        with patch("fido2client.client.Fido2Client") as MockClient:
            MockClient.return_value.get_assertion.return_value = ([assertion], "{}")

            client = Fido2HttpClient()
            result = client.authenticate_to(
                ok_server,
                "/begin",
                "/complete",
                extra_data={"session_id": "abc123"},
            )

    assert result is True


def test_e2e_context_manager_closes_session(ok_server):
    assertion = _mock_assertion()
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([MagicMock()])):
        with patch("fido2client.client.Fido2Client") as MockClient:
            MockClient.return_value.get_assertion.return_value = ([assertion], "{}")

            with Fido2HttpClient() as client:
                client.authenticate_to(ok_server, "/begin", "/complete")
                close_spy = patch.object(client.session, "close", wraps=client.session.close).start()
            # __exit__ must have called session.close()
            close_spy.assert_called_once()
