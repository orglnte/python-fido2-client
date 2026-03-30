from __future__ import annotations

import base64
import getpass
import json
import logging
import urllib.parse
from dataclasses import dataclass
from typing import Any

import cbor2 as cbor
import requests
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice

from .exceptions import (
    FidoDeviceNotFoundError,
    FidoServerError,
)

logger = logging.getLogger(__name__)


@dataclass
class _BeginResponse:
    """Typed representation of the publicKey payload in a WebAuthn begin response."""

    rp_id: str
    challenge: bytes
    allow_credentials: list[dict[str, Any]]

    @classmethod
    def from_cbor(cls, data: Any) -> _BeginResponse:
        if not isinstance(data, dict):
            raise FidoServerError(
                f"Unexpected CBOR begin response type: {type(data).__name__}"
            )
        pubkey = data.get("publicKey")
        if not pubkey:
            raise FidoServerError("Missing 'publicKey' in server response.")
        for field in ("rpId", "challenge"):
            if field not in pubkey:
                raise FidoServerError(f"Missing required field '{field}' in server response.")
        creds = pubkey.get("allowCredentials")
        if not creds:
            raise FidoServerError("Server returned empty or missing 'allowCredentials'.")
        return cls(
            rp_id=pubkey["rpId"],
            challenge=pubkey["challenge"],
            allow_credentials=creds,
        )


class Fido2HttpClient:
    """FIDO2 WebAuthn HTTP client.

    Orchestrates the FIDO2 authentication ceremony against a WebAuthn server:
    sends the begin request, retrieves an assertion from the connected
    authenticator device, then sends the completion request.

    Supports use as a context manager to ensure the HTTP session is closed:

        with Fido2HttpClient() as client:
            client.authenticate_to(server, begin_path, complete_path)
    """

    def __init__(
        self,
        ssl_verify: bool = True,
        verbose: bool = False,
        timeout: int = 30,
    ) -> None:
        """
        Args:
            ssl_verify: Verify TLS certificates. Always True in production;
                set False only for local development with self-signed certs.
            verbose: If True, attach a StreamHandler to the fido2client logger
                at DEBUG level. Equivalent to configuring logging externally.
            timeout: HTTP request timeout in seconds.
        """
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.is_authenticated: bool = False

        self.session: requests.Session | None = None
        self._owns_session: bool = False
        self._last_response: requests.Response | None = None

        if verbose:
            _handler = logging.StreamHandler()
            _handler.setLevel(logging.DEBUG)
            logger.addHandler(_handler)
            logger.setLevel(logging.DEBUG)

    def __enter__(self) -> Fido2HttpClient:
        return self

    def __exit__(self, *args: Any) -> None:
        if self._owns_session and self.session is not None:
            self.session.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authenticate_to(
        self,
        server: str,
        begin_endpoint: str,
        complete_endpoint: str,
        session: requests.Session | None = None,
        extra_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> bool:
        """Perform a FIDO2 authentication ceremony against a WebAuthn server.

        Args:
            server: Base URL of the authentication server
                (e.g. ``'https://example.com'``).
            begin_endpoint: Path to the begin endpoint
                (e.g. ``'/api/authenticate/begin'``).
            complete_endpoint: Path to the complete endpoint
                (e.g. ``'/api/authenticate/complete'``).
            session: Optional :class:`requests.Session` to reuse.
                A new session is created if omitted.
            extra_data: Optional dict merged into the completion request body.
            extra_headers: Optional HTTP headers added to every request.

        Returns:
            ``True`` if the server confirmed authentication, ``False`` otherwise.

        Raises:
            FidoDeviceNotFoundError: No FIDO2 device is connected.
            FidoServerError: The server returned an unreadable or unexpected response.
            requests.exceptions.RequestException: A network-level failure occurred.
        """
        if session is not None:
            self.session = session
            self._owns_session = False
        elif self.session is None:
            self.session = requests.Session()
            self._owns_session = True

        dev = self._find_device()

        begin_url = urllib.parse.urljoin(server, begin_endpoint)
        complete_url = urllib.parse.urljoin(server, complete_endpoint)

        begin_data = self._begin(begin_url, extra_headers=extra_headers)
        return self._complete(
            server, dev, begin_data, complete_url,
            extra_data=extra_data, extra_headers=extra_headers,
        )

    def get_last_response(self) -> requests.Response | None:
        """Return the raw HTTP response from the last completion request, or None."""
        return self._last_response

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_device(self) -> CtapHidDevice:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise FidoDeviceNotFoundError(
                "No FIDO2 device found. Connect your authenticator and try again."
            )
        return dev

    def _begin(
        self,
        begin_url: str,
        extra_headers: dict[str, str] | None = None,
    ) -> _BeginResponse:
        headers: dict[str, str] = dict(extra_headers) if extra_headers else {}
        try:
            r = self.session.post(
                begin_url, verify=self.ssl_verify, headers=headers, timeout=self.timeout
            )
            r.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FidoServerError(f"Begin request failed: {exc}") from exc

        try:
            raw = cbor.loads(r.content)
        except Exception as exc:
            raise FidoServerError(f"Could not decode CBOR begin response: {exc}") from exc

        begin_data = _BeginResponse.from_cbor(raw)
        logger.debug("BEGIN RESPONSE: %s", begin_data)
        return begin_data

    def _complete(
        self,
        server: str,
        dev: CtapHidDevice,
        begin_data: _BeginResponse,
        complete_url: str,
        extra_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> bool:
        fido2_client = Fido2Client(dev, server)
        challenge = base64.b64encode(begin_data.challenge).decode("utf-8")
        allow_list = [
            {"type": "public-key", "id": cred["id"]}
            for cred in begin_data.allow_credentials
        ]

        print("Touch your authenticator device...")
        try:
            assertions, client_data = fido2_client.get_assertion(
                begin_data.rp_id, challenge, allow_list
            )
        except ValueError:
            assertions, client_data = fido2_client.get_assertion(
                begin_data.rp_id,
                challenge,
                allow_list,
                pin=getpass.getpass("Please enter PIN: "),
            )

        assertion = assertions[0]
        logger.debug("ASSERTION: %s", assertion)
        logger.debug("CLIENT DATA: %s", client_data)

        user_data = base64.b64encode(json.dumps(extra_data or {}).encode("utf-8"))
        body = cbor.dumps(
            {
                "credentialId": assertion.credential["id"],
                "authenticatorData": assertion.auth_data,
                "clientDataJSON": client_data,
                "signature": assertion.signature,
                "user_data": user_data,
            }
        )

        headers: dict[str, str] = {"content-type": "application/cbor"}
        if extra_headers:
            headers.update(extra_headers)

        try:
            r = self.session.post(
                complete_url,
                verify=self.ssl_verify,
                headers=headers,
                data=body,
                timeout=self.timeout,
            )
            r.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FidoServerError(f"Complete request failed: {exc}") from exc

        self._last_response = r

        try:
            data = cbor.loads(r.content)
        except Exception as exc:
            raise FidoServerError(f"Could not decode CBOR complete response: {exc}") from exc

        if not isinstance(data, dict):
            raise FidoServerError(f"Could not decode CBOR complete response: unexpected type {type(data).__name__}")

        logger.debug("COMPLETE RESPONSE: %s", data)

        self.is_authenticated = data.get("status") == "OK"
        if self.is_authenticated:
            logger.info("Authentication succeeded.")
        else:
            logger.warning("Authentication failed. Server response: %s", data)

        return self.is_authenticated
