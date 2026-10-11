"""How begin/complete messages travel between client and server."""
from __future__ import annotations

import base64
import json
from enum import Enum
from typing import Any, Protocol

import cbor2
from fido2.webauthn import AuthenticationResponse, PublicKeyCredentialRequestOptions

from .exceptions import FidoServerError


class WireFormat(str, Enum):
    """Encoding of the begin/complete messages.

    ``JSON`` is the WebAuthn JSON serialization used by most servers, including
    the python-fido2 example server since fido2 1.0. ``CBOR`` is the protocol
    of the python-fido2 0.9 example server.
    """

    CBOR = "cbor"
    JSON = "json"

    @property
    def codec(self) -> Codec:
        return _CODECS[self]


class Codec(Protocol):
    name: str
    content_type: str

    def dumps(self, payload: dict[str, Any]) -> bytes: ...

    def loads(self, content: bytes) -> Any: ...

    def assertion_payload(
        self, assertion: AuthenticationResponse, extra_data: dict[str, Any] | None
    ) -> dict[str, Any]: ...


class _CborCodec:
    name = "CBOR"
    content_type = "application/cbor"

    def dumps(self, payload: dict[str, Any]) -> bytes:
        return cbor2.dumps(payload)

    def loads(self, content: bytes) -> Any:
        return cbor2.loads(content)

    def assertion_payload(
        self, assertion: AuthenticationResponse, extra_data: dict[str, Any] | None
    ) -> dict[str, Any]:
        return {
            "credentialId": assertion.raw_id,
            "authenticatorData": bytes(assertion.response.authenticator_data),
            "clientDataJSON": bytes(assertion.response.client_data),
            "signature": assertion.response.signature,
            "user_data": base64.b64encode(json.dumps(extra_data or {}).encode("utf-8")),
        }


class _JsonCodec:
    name = "JSON"
    content_type = "application/json"

    def dumps(self, payload: dict[str, Any]) -> bytes:
        return json.dumps(payload).encode("utf-8")

    def loads(self, content: bytes) -> Any:
        return json.loads(content)

    def assertion_payload(
        self, assertion: AuthenticationResponse, extra_data: dict[str, Any] | None
    ) -> dict[str, Any]:
        return {**(extra_data or {}), **dict(assertion)}


_CODECS: dict[WireFormat, Codec] = {
    WireFormat.CBOR: _CborCodec(),
    WireFormat.JSON: _JsonCodec(),
}


def request_options(data: Any, codec: Codec) -> PublicKeyCredentialRequestOptions:
    """Validate a decoded begin response and return its request options.

    Accepts the options wrapped as ``{"publicKey": {...}}`` or bare.
    """
    if not isinstance(data, dict):
        raise FidoServerError(
            f"Unexpected {codec.name} begin response type: {type(data).__name__}"
        )
    options = data.get("publicKey", data)
    if not isinstance(options, dict):
        raise FidoServerError(f"Unexpected 'publicKey' type: {type(options).__name__}")
    for field in ("rpId", "challenge"):
        if field not in options:
            raise FidoServerError(f"Missing required field '{field}' in server response.")
    if not options.get("allowCredentials"):
        raise FidoServerError("Server returned empty or missing 'allowCredentials'.")
    _check_types(options)
    try:
        parsed = PublicKeyCredentialRequestOptions.from_dict(options)
    except (TypeError, ValueError, KeyError) as exc:
        raise FidoServerError(f"Malformed request options in server response: {exc}") from exc
    if not parsed.challenge:
        raise FidoServerError("Malformed request options in server response: empty challenge.")
    return parsed


def _check_types(options: dict[str, Any]) -> None:
    """Reject values fido2's parser would coerce silently, e.g. an int challenge into zero bytes."""
    problem = None
    if not isinstance(options["rpId"], str) or not options["rpId"]:
        problem = "'rpId' must be a non-empty string"
    elif not isinstance(options["challenge"], (bytes, str)):
        problem = "'challenge' must be bytes or a base64url string"
    elif not isinstance(options["allowCredentials"], list) or not all(
        isinstance(c, dict) and isinstance(c.get("id"), (bytes, str))
        for c in options["allowCredentials"]
    ):
        problem = "'allowCredentials' must be a list of credentials with an 'id'"
    if problem:
        raise FidoServerError(f"Malformed request options in server response: {problem}.")
