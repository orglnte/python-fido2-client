from importlib.metadata import version

from .client import Fido2HttpClient
from .exceptions import (
    Fido2ClientError,
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)

__version__ = version("fido2client")
__all__ = [
    "Fido2HttpClient",
    "Fido2ClientError",
    "FidoAuthenticationError",
    "FidoDeviceNotFoundError",
    "FidoServerError",
]
