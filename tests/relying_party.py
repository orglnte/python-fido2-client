"""WebAuthn relying party for end-to-end tests.

Yubico's ``Fido2Server`` behind the CBOR begin/complete protocol that
fido2client speaks, on a local HTTP server. Ceremony state travels in a
session cookie, as in a real web app, and every request is recorded so tests
can assert on what actually reached the server.
"""
from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from email.message import Message
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import cbor2
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)

BEGIN_PATH = "/api/authenticate/begin"
COMPLETE_PATH = "/api/authenticate/complete"
SESSION_COOKIE = "session"


@dataclass(frozen=True)
class ReceivedRequest:
    path: str
    headers: Message
    body: bytes


class RelyingParty:
    """Serves ``BEGIN_PATH`` and ``COMPLETE_PATH`` at ``url`` while used as a context manager.

    ``rp_id`` is the RP ID the server asks the client to sign for; leaving it
    at ``localhost`` matches the origin of ``url``.
    """

    def __init__(
        self,
        rp_id: str = "localhost",
        user_verification: UserVerificationRequirement | None = None,
    ) -> None:
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

    def begin(self) -> tuple[str, dict[str, Any]]:
        """Start a ceremony; returns the new session id and the CBOR-ready payload."""
        options, state = self._fido.authenticate_begin(
            self.credentials, user_verification=self._user_verification
        )
        session_id = secrets.token_urlsafe(16)
        self._states[session_id] = state
        return session_id, {"publicKey": _wire_request_options(options.public_key)}

    def complete(self, session_id: str | None, body: bytes) -> dict[str, Any]:
        state = self._states.pop(session_id, None) if session_id else None
        if state is None:
            return {"status": "FAILED", "message": "no ceremony in progress for this session"}
        data = cbor2.loads(body)
        response = {
            "rawId": data["credentialId"],
            "response": {
                "clientDataJSON": data["clientDataJSON"],
                "authenticatorData": data["authenticatorData"],
                "signature": data["signature"],
            },
            "type": "public-key",
        }
        try:
            self._fido.authenticate_complete(state, self.credentials, response)
        except ValueError as exc:
            return {"status": "FAILED", "message": str(exc)}
        return {"status": "OK"}


def _wire_request_options(options: PublicKeyCredentialRequestOptions) -> dict[str, Any]:
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
                self._send_cbor(payload, cookie=session_id)
            elif self.path == COMPLETE_PATH:
                self._send_cbor(rp.complete(self._session_id(), body))
            else:
                self.send_error(404)

        def _session_id(self) -> str | None:
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get(SESSION_COOKIE)
            return morsel.value if morsel else None

        def _send_cbor(self, payload: dict[str, Any], cookie: str | None = None) -> None:
            body = cbor2.dumps(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/cbor")
            self.send_header("Content-Length", str(len(body)))
            if cookie is not None:
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}={cookie}; Path=/")
            self.end_headers()
            self.wfile.write(body)

    return Handler
