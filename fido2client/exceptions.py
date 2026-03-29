from __future__ import annotations


class Fido2ClientError(Exception):
    """Base exception for all fido2client errors."""


class FidoDeviceNotFoundError(Fido2ClientError):
    """Raised when no FIDO2 HID device is connected."""


class FidoServerError(Fido2ClientError):
    """Raised when the server returns an unexpected or unreadable response."""


class FidoAuthenticationError(Fido2ClientError):
    """Raised when the FIDO2 authentication ceremony cannot proceed."""
