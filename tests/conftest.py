from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

from .virtual_authenticator import VirtualAuthenticator


@pytest.fixture()
def authenticator(request: pytest.FixtureRequest) -> Iterator[VirtualAuthenticator]:
    """The only authenticator HID discovery finds.

    Parametrize indirectly with a PIN to get a device with clientPin configured.
    """
    device = VirtualAuthenticator(pin=getattr(request, "param", None))
    with patch(
        "fido2client.client.CtapHidDevice.list_devices",
        side_effect=lambda: iter([device]),
    ):
        yield device
