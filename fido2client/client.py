from __future__ import annotations

import base64
import getpass
import json
import logging
import urllib.parse
from collections.abc import Callable
from typing import Any

import cbor2 as cbor
import requests
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.webauthn import AuthenticationResponse, PublicKeyCredentialRequestOptions

from .exceptions import (
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)

logger = logging.getLogger(__name__)
_verbose_handler = logging.StreamHandler()
_verbose_handler.setLevel(logging.DEBUG)


def _request_options_from_cbor(data: Any) -> PublicKeyCredentialRequestOptions:
    """Validate a decoded begin response and return its publicKey request options."""
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
    if not pubkey.get("allowCredentials"):
        raise FidoServerError("Server returned empty or missing 'allowCredentials'.")
    try:
        return PublicKeyCredentialRequestOptions.from_dict(pubkey)
    except (TypeError, ValueError, KeyError) as exc:
        raise FidoServerError(f"Malformed 'publicKey' in server response: {exc}") from exc


def _origin(server: str) -> str:
    parts = urllib.parse.urlsplit(server)
    return f"{parts.scheme}://{parts.netloc}"


class _CallbackInteraction(UserInteraction):
    """Routes fido2's user-interaction requests to the caller's callbacks."""

    def __init__(
        self,
        prompt_callback: Callable[[str], None],
        pin_callback: Callable[[], str],
    ) -> None:
        self._prompt_callback = prompt_callback
        self._pin_callback = pin_callback

    def prompt_up(self) -> None:
        self._prompt_callback("Touch your authenticator device...")

    def request_pin(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> str | None:
        return self._pin_callback()


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
            logger.addHandler(_verbose_handler)
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
        prompt_callback: Callable[[str], None] = print,
        pin_callback: Callable[[], str] = lambda: getpass.getpass("Please enter PIN: "),
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
            extra_data: Optional dict sent to the server as the ``user_data``
                field of the completion request (JSON, then base64).
            extra_headers: Optional HTTP headers added to every request.
            prompt_callback: Called with a user-facing message when the
                authenticator waits for a touch. Defaults to :func:`print`.
            pin_callback: Called to obtain the authenticator PIN when required.
                Must return the PIN as a string. Defaults to
                :func:`getpass.getpass`.

        Returns:
            ``True`` if the server confirmed authentication, ``False`` otherwise.

        Raises:
            FidoDeviceNotFoundError: No FIDO2 device is connected.
            FidoServerError: A request failed at network or HTTP level (the
                :mod:`requests` exception is chained as ``__cause__``), or the
                server returned an unreadable or unexpected response.
            FidoAuthenticationError: The authenticator did not produce an
                assertion: no matching credential, wrong or missing PIN, user
                verification unavailable, RP ID not valid for the server's
                origin, or timeout.
        """
        if session is not None:
            if self._owns_session and self.session is not None:
                self.session.close()
            self.session = session
            self._owns_session = False
        elif self.session is None:
            self.session = requests.Session()
            self._owns_session = True

        self.is_authenticated = False
        dev = self._find_device()

        begin_url = urllib.parse.urljoin(server, begin_endpoint)
        complete_url = urllib.parse.urljoin(server, complete_endpoint)

        options = self._begin(begin_url, extra_headers=extra_headers)
        assertion = self._get_assertion(
            dev, _origin(server), options,
            _CallbackInteraction(prompt_callback, pin_callback),
        )
        return self._complete(
            complete_url, assertion,
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
    ) -> PublicKeyCredentialRequestOptions:
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

        options = _request_options_from_cbor(raw)
        logger.debug("BEGIN RESPONSE: %s", options)
        return options

    def _get_assertion(
        self,
        dev: CtapHidDevice,
        origin: str,
        options: PublicKeyCredentialRequestOptions,
        interaction: UserInteraction,
    ) -> AuthenticationResponse:
        fido2_client = Fido2Client(dev, DefaultClientDataCollector(origin), interaction)
        try:
            response = fido2_client.get_assertion(options).get_response(0)
        except ClientError as exc:
            raise FidoAuthenticationError(f"Authenticator did not produce an assertion: {exc}") from exc
        logger.debug("ASSERTION: %s", response)
        return response

    def _complete(
        self,
        complete_url: str,
        assertion: AuthenticationResponse,
        extra_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> bool:
        user_data = base64.b64encode(json.dumps(extra_data or {}).encode("utf-8"))
        body = cbor.dumps(
            {
                "credentialId": assertion.raw_id,
                "authenticatorData": bytes(assertion.response.authenticator_data),
                "clientDataJSON": bytes(assertion.response.client_data),
                "signature": assertion.response.signature,
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
