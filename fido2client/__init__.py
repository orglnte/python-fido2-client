from .client import Fido2HttpClient
from .exceptions import (
    Fido2ClientError,
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)

__version__ = "0.11.0"
__all__ = [
    "Fido2HttpClient",
    "Fido2ClientError",
    "FidoAuthenticationError",
    "FidoDeviceNotFoundError",
    "FidoServerError",
]

name = "fido2client"
