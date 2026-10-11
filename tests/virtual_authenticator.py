"""Software CTAP2 authenticator for tests.

A ``CtapDevice`` that keeps ES256 credentials in memory and answers the CTAP2
commands an assertion needs (GetInfo, GetAssertion, ClientPIN with PIN/UV
protocol 1), so the real ``fido2`` client stack runs without a USB key.
"""
from __future__ import annotations

import hmac
import os
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from threading import Event
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.ctap import STATUS, CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.hid import CAPABILITY, CTAPHID
from fido2.utils import bytes2int, int2bytes, sha256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

AAGUID = bytes.fromhex("f1d0f1d0f1d0f1d0f1d0f1d0f1d0f1d0")


@dataclass
class _Credential:
    rp_id_hash: bytes
    private_key: ec.EllipticCurvePrivateKey


class VirtualAuthenticator(CtapDevice):
    """In-memory CTAP2 authenticator. ``pin`` set means clientPin is configured."""

    def __init__(self, pin: str | None = None) -> None:
        self._credentials: dict[bytes, _Credential] = {}
        self._pin_hash = sha256(pin.encode())[:16] if pin is not None else None
        self._pin_protocol = PinProtocolV1()
        self._key_agreement = ec.generate_private_key(ec.SECP256R1())
        self._pin_token = os.urandom(32)
        self._unplugged = False
        self.sign_count = 0

    @property
    def capabilities(self) -> int:
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    @classmethod
    def list_devices(cls) -> Iterator[VirtualAuthenticator]:
        return iter(())

    def create_credential(self, rp_id: str) -> AttestedCredentialData:
        """Provision a credential for ``rp_id``; returns what an RP stores at registration."""
        credential_id = os.urandom(32)
        private_key = ec.generate_private_key(ec.SECP256R1())
        self._credentials[credential_id] = _Credential(sha256(rp_id.encode()), private_key)
        return AttestedCredentialData.create(
            AAGUID, credential_id, ES256.from_cryptography_key(private_key.public_key())
        )

    def replace_key(self, credential_id: bytes) -> None:
        """Swap the credential's private key, so its signatures stop matching the RP's copy."""
        self._credentials[credential_id].private_key = ec.generate_private_key(ec.SECP256R1())

    def unplug(self) -> None:
        """Fail every later command the way a removed USB device does."""
        self._unplugged = True

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        if self._unplugged:
            raise OSError("device disconnected")
        if cmd != CTAPHID.CBOR:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)
        command = data[0]
        params: Mapping[int, Any] = cbor.decode(data[1:]) if len(data) > 1 else {}
        handlers = {
            Ctap2.CMD.GET_INFO: self._get_info,
            Ctap2.CMD.GET_ASSERTION: self._get_assertion,
            Ctap2.CMD.CLIENT_PIN: self._client_pin,
        }
        handler = handlers.get(command)
        if handler is None:
            return bytes([CtapError.ERR.INVALID_COMMAND])
        try:
            response = handler(params, on_keepalive)
        except CtapError as exc:
            return bytes([exc.code])
        return b"\x00" + cbor.encode(response)

    def _get_info(self, params: Mapping[int, Any], on_keepalive: Any) -> dict[int, Any]:
        options = {"rk": False, "up": True, "plat": False}
        info: dict[int, Any] = {1: ["FIDO_2_0"], 3: AAGUID, 4: options}
        if self._pin_hash is not None:
            options["clientPin"] = True
            info[6] = [PinProtocolV1.VERSION]
        return info

    def _get_assertion(
        self,
        params: Mapping[int, Any],
        on_keepalive: Callable[[STATUS], None] | None,
    ) -> dict[int, Any]:
        rp_id_hash = sha256(params[1].encode())
        client_data_hash = params[2]
        flags = AuthenticatorData.FLAG(0)

        pin_uv_auth_param = params.get(6)
        if pin_uv_auth_param is not None:
            expected = self._pin_protocol.authenticate(self._pin_token, client_data_hash)
            if not hmac.compare_digest(pin_uv_auth_param, expected):
                raise CtapError(CtapError.ERR.PIN_AUTH_INVALID)
            flags |= AuthenticatorData.FLAG.UV

        credential_id, credential = self._find_credential(rp_id_hash, params.get(3) or [])

        if (params.get(5) or {}).get("up", True):
            if on_keepalive is not None:
                on_keepalive(STATUS.UPNEEDED)
            flags |= AuthenticatorData.FLAG.UP

        self.sign_count += 1
        auth_data = AuthenticatorData.create(rp_id_hash, flags, self.sign_count)
        signature = credential.private_key.sign(
            auth_data + client_data_hash, ec.ECDSA(hashes.SHA256())
        )
        return {1: {"type": "public-key", "id": credential_id}, 2: bytes(auth_data), 3: signature}

    def _find_credential(
        self, rp_id_hash: bytes, allow_list: list[Mapping[str, Any]]
    ) -> tuple[bytes, _Credential]:
        for descriptor in allow_list:
            credential = self._credentials.get(descriptor["id"])
            if credential is not None and credential.rp_id_hash == rp_id_hash:
                return descriptor["id"], credential
        raise CtapError(CtapError.ERR.NO_CREDENTIALS)

    def _client_pin(self, params: Mapping[int, Any], on_keepalive: Any) -> dict[int, Any]:
        if self._pin_hash is None:
            raise CtapError(CtapError.ERR.PIN_NOT_SET)
        sub_command = params[2]
        if sub_command == ClientPin.CMD.GET_KEY_AGREEMENT:
            numbers = self._key_agreement.public_key().public_numbers()
            cose_key = {1: 2, 3: -25, -1: 1, -2: int2bytes(numbers.x, 32), -3: int2bytes(numbers.y, 32)}
            return {ClientPin.RESULT.KEY_AGREEMENT: cose_key}
        if sub_command == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY:
            shared_secret = self._shared_secret(params[3])
            pin_hash = self._pin_protocol.decrypt(shared_secret, params[6])
            if not hmac.compare_digest(pin_hash, self._pin_hash):
                raise CtapError(CtapError.ERR.PIN_INVALID)
            token_enc = self._pin_protocol.encrypt(shared_secret, self._pin_token)
            return {ClientPin.RESULT.PIN_UV_TOKEN: token_enc}
        raise CtapError(CtapError.ERR.INVALID_SUBCOMMAND)

    def _shared_secret(self, platform_key: Mapping[int, Any]) -> bytes:
        peer = ec.EllipticCurvePublicNumbers(
            bytes2int(platform_key[-2]), bytes2int(platform_key[-3]), ec.SECP256R1()
        ).public_key()
        return self._pin_protocol.kdf(self._key_agreement.exchange(ec.ECDH(), peer))
