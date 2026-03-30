from importlib.metadata import PackageNotFoundError, version

from .client import Fido2HttpClient
from .exceptions import (
    Fido2ClientError,
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)

try:
    __version__ = version("fido2client")
except PackageNotFoundError:
    __version__ = "0.0.0.dev"
__all__ = [
    "Fido2HttpClient",
    "Fido2ClientError",
    "FidoAuthenticationError",
    "FidoDeviceNotFoundError",
    "FidoServerError",
]
