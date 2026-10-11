"""WebAuthn relying party for end-to-end tests.

Yubico's ``Fido2Server`` behind a begin/complete HTTP protocol on localhost,
in either wire format fido2client speaks: JSON, as the python-fido2 example
server since fido2 1.0, or CBOR, as the 0.9 example server. Ceremony state
travels in a session cookie, as in a real web app, and every request is
recorded so tests can assert on what actually reached the server.

Encoding is written out here rather than borrowed from ``fido2client.wire``,
so a bug in the client's codecs cannot cancel itself out.
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
from dataclasses import dataclass
from email.message import Message
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import cbor2
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

from fido2client import WireFormat

BEGIN_PATH = "/api/authenticate/begin"
COMPLETE_PATH = "/api/authenticate/complete"
SESSION_COOKIE = "session"

_ASSERTION_KEYS = {"id", "rawId", "response", "type", "authenticatorAttachment", "clientExtensionResults"}


@dataclass(frozen=True)
class ReceivedRequest:
    path: str
    headers: Message
    body: bytes


class RelyingParty:
    """Serves ``BEGIN_PATH`` and ``COMPLETE_PATH`` at ``url`` while used as a context manager.

    ``rp_id`` is the RP ID the server asks the client to sign for; leaving it
    at ``localhost`` matches the origin of ``url``. ``failure_status`` is the
    HTTP status of a failed completion.
    """

    def __init__(
        self,
        wire_format: WireFormat = WireFormat.JSON,
        rp_id: str = "localhost",
        user_verification: UserVerificationRequirement | None = None,
        failure_status: int = 200,
    ) -> None:
        self.wire_format = wire_format
        self.failure_status = failure_status
        self.rp_id = rp_id
        self.credentials: list[AttestedCredentialData] = []
        self.requests: list[ReceivedRequest] = []
        self._fido = Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name="fido2client tests"))
        self._user_verification = user_verification
        self._states: dict[str, Any] = {}
        self._httpd = HTTPServer(("127.0.0.1", 0), _handler_for(self))
        self.url = f"http://localhost:{self._httpd.server_address[1]}"

    def __enter__(self) -> RelyingParty:
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *args: Any) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def requests_to(self, path: str) -> list[ReceivedRequest]:
        return [r for r in self.requests if r.path == path]

    def payloads_to(self, path: str) -> list[Any]:
        return [self.decode(r.body) for r in self.requests_to(path)]

    def credential_id(self, complete_payload: dict[str, Any]) -> bytes:
        if self.wire_format is WireFormat.CBOR:
            return complete_payload["credentialId"]
        return websafe_decode(complete_payload["rawId"])

    def extra_data(self, complete_payload: dict[str, Any]) -> dict[str, Any]:
        if self.wire_format is WireFormat.CBOR:
            return json.loads(base64.b64decode(complete_payload["user_data"]))
        return {k: v for k, v in complete_payload.items() if k not in _ASSERTION_KEYS}

    def encode(self, payload: dict[str, Any]) -> bytes:
        if self.wire_format is WireFormat.CBOR:
            return cbor2.dumps(payload)
        return json.dumps(payload).encode()

    def decode(self, body: bytes) -> Any:
        if self.wire_format is WireFormat.CBOR:
            return cbor2.loads(body)
        return json.loads(body)

    @property
    def content_type(self) -> str:
        return f"application/{self.wire_format.value}"

    def begin(self) -> tuple[str, dict[str, Any]]:
        """Start a ceremony; returns the new session id and the response payload."""
        options, state = self._fido.authenticate_begin(
            self.credentials, user_verification=self._user_verification
        )
        session_id = secrets.token_urlsafe(16)
        self._states[session_id] = state
        if self.wire_format is WireFormat.CBOR:
            return session_id, {"publicKey": _cbor_request_options(options.public_key)}
        return session_id, dict(options)

    def complete(self, session_id: str | None, body: bytes) -> dict[str, Any]:
        state = self._states.pop(session_id, None) if session_id else None
        if state is None:
            return {"status": "FAILED", "message": "no ceremony in progress for this session"}
        data = self.decode(body)
        if self.wire_format is WireFormat.CBOR:
            response = {
                "rawId": data["credentialId"],
                "response": {
                    "clientDataJSON": data["clientDataJSON"],
                    "authenticatorData": data["authenticatorData"],
                    "signature": data["signature"],
                },
                "type": "public-key",
            }
        else:
            response = data
        try:
            self._fido.authenticate_complete(state, self.credentials, response)
        except ValueError as exc:
            return {"status": "FAILED", "message": str(exc)}
        return {"status": "OK"}


def _cbor_request_options(options: PublicKeyCredentialRequestOptions) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rpId": options.rp_id,
        "challenge": options.challenge,
        "allowCredentials": [
            {"type": "public-key", "id": descriptor.id}
            for descriptor in options.allow_credentials or []
        ],
    }
    if options.user_verification is not None:
        payload["userVerification"] = options.user_verification.value
    return payload


def _handler_for(rp: RelyingParty) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            rp.requests.append(ReceivedRequest(self.path, self.headers, body))
            if self.path == BEGIN_PATH:
                session_id, payload = rp.begin()
                self._send(payload, cookie=session_id)
            elif self.path == COMPLETE_PATH:
                result = rp.complete(self._session_id(), body)
                status = 200 if result["status"] == "OK" else rp.failure_status
                self._send(result, status=status)
            else:
                self.send_error(404)

        def _session_id(self) -> str | None:
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get(SESSION_COOKIE)
            return morsel.value if morsel else None

        def _send(self, payload: dict[str, Any], cookie: str | None = None, status: int = 200) -> None:
            body = rp.encode(payload)
            self.send_response(status)
            self.send_header("Content-Type", rp.content_type)
            self.send_header("Content-Length", str(len(body)))
            if cookie is not None:
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}={cookie}; Path=/")
            self.end_headers()
            self.wfile.write(body)

    return Handler
