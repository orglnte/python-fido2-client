from __future__ import annotations

import getpass
import logging
import urllib.parse
from collections.abc import Callable
from typing import Any

import requests
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.webauthn import AuthenticationResponse, PublicKeyCredentialRequestOptions

from .exceptions import (
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)
from .wire import Codec, WireFormat, request_options

logger = logging.getLogger(__name__)
_verbose_handler = logging.StreamHandler()
_verbose_handler.setLevel(logging.DEBUG)


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
        wire_format: WireFormat = WireFormat.CBOR,
        begin_data: dict[str, Any] | None = None,
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
            extra_data: Optional dict sent with the completion request: merged
                into the top level of the body with ``WireFormat.JSON``, where
                keys of the assertion itself (``id``, ``rawId``, ``response``,
                ``type``, ...) take precedence; as the ``user_data`` field (JSON,
                then base64) with ``WireFormat.CBOR``.
            extra_headers: Optional HTTP headers added to every request.
            prompt_callback: Called with a user-facing message when the
                authenticator waits for a touch. Defaults to :func:`print`.
            pin_callback: Called to obtain the authenticator PIN when required.
                Must return the PIN as a string. Defaults to
                :func:`getpass.getpass`.
            wire_format: Encoding of the begin/complete messages. Defaults to
                ``WireFormat.CBOR`` for compatibility; most servers expect
                ``WireFormat.JSON``.
            begin_data: Optional dict sent as the body of the begin request,
                e.g. ``{"username": "alice"}``. No body is sent when omitted.

        Returns:
            ``True`` if the complete request answered ``{"status": "OK"}``;
            ``False`` if it answered another status or an HTTP 4xx.

        Raises:
            FidoDeviceNotFoundError: No FIDO2 device is connected.
            FidoServerError: A request failed at network or HTTP level (the
                :mod:`requests` exception is chained as ``__cause__``), or the
                server returned an unreadable or unexpected response.
            FidoAuthenticationError: The authenticator did not produce an
                assertion: no matching credential, wrong or missing PIN, user
                verification unavailable, RP ID not valid for the server's
                origin, timeout, or the device failed (e.g. unplugged).
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

        codec = WireFormat(wire_format).codec
        options = self._begin(begin_url, codec, begin_data=begin_data, extra_headers=extra_headers)
        assertion = self._get_assertion(
            dev, _origin(server), options,
            _CallbackInteraction(prompt_callback, pin_callback),
        )
        return self._complete(
            complete_url, codec, assertion,
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
        codec: Codec,
        begin_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> PublicKeyCredentialRequestOptions:
        body = codec.dumps(begin_data) if begin_data is not None else None
        r = self._post(begin_url, "Begin", codec, body, extra_headers)

        try:
            raw = codec.loads(r.content)
        except Exception as exc:
            raise FidoServerError(f"Could not decode {codec.name} begin response: {exc}") from exc

        options = request_options(raw, codec)
        logger.debug("BEGIN RESPONSE: %s", options)
        return options

    def _get_assertion(
        self,
        dev: CtapHidDevice,
        origin: str,
        options: PublicKeyCredentialRequestOptions,
        interaction: UserInteraction,
    ) -> AuthenticationResponse:
        try:
            fido2_client = Fido2Client(dev, DefaultClientDataCollector(origin), interaction)
            response = fido2_client.get_assertion(options).get_response(0)
        except (ClientError, CtapError, OSError) as exc:
            raise FidoAuthenticationError(f"Authenticator did not produce an assertion: {exc}") from exc
        logger.debug("ASSERTION: %s", response)
        return response

    def _complete(
        self,
        complete_url: str,
        codec: Codec,
        assertion: AuthenticationResponse,
        extra_data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> bool:
        body = codec.dumps(codec.assertion_payload(assertion, extra_data))
        r = self._post(complete_url, "Complete", codec, body, extra_headers, accept_client_error=True)
        self._last_response = r

        if r.status_code >= 400:
            logger.warning("Authentication rejected with HTTP %s: %s", r.status_code, r.text)
            return False

        try:
            data = codec.loads(r.content)
        except Exception as exc:
            raise FidoServerError(f"Could not decode {codec.name} complete response: {exc}") from exc

        if not isinstance(data, dict):
            raise FidoServerError(
                f"Could not decode {codec.name} complete response: unexpected type {type(data).__name__}"
            )

        logger.debug("COMPLETE RESPONSE: %s", data)

        self.is_authenticated = data.get("status") == "OK"
        if self.is_authenticated:
            logger.info("Authentication succeeded.")
        else:
            logger.warning("Authentication failed. Server response: %s", data)

        return self.is_authenticated

    def _post(
        self,
        url: str,
        step: str,
        codec: Codec,
        body: bytes | None,
        extra_headers: dict[str, str] | None,
        accept_client_error: bool = False,
    ) -> requests.Response:
        """POST ``body``; a 4xx status is returned instead of raised when ``accept_client_error``."""
        headers: dict[str, str] = {"content-type": codec.content_type} if body is not None else {}
        if extra_headers:
            headers.update(extra_headers)
        try:
            r = self.session.post(
                url, verify=self.ssl_verify, headers=headers, data=body, timeout=self.timeout
            )
            if not (accept_client_error and 400 <= r.status_code < 500):
                r.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FidoServerError(f"{step} request failed: {exc}") from exc
        return r
