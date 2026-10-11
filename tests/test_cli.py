"""The fido2client command line against the test relying party and software authenticator."""
from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

from fido2client import WireFormat
from fido2client.cli import (
    EXIT_AUTHENTICATED,
    EXIT_ERROR,
    EXIT_INTERRUPTED,
    EXIT_REJECTED,
    main,
)

from .relying_party import BEGIN_PATH, SESSION_COOKIE, RelyingParty


@pytest.fixture(params=list(WireFormat), ids=lambda f: f.value)
def relying_party(request: pytest.FixtureRequest) -> Iterator[RelyingParty]:
    with RelyingParty(request.param) as rp:
        yield rp


def _login(rp: RelyingParty, *args: str) -> int:
    return main(["login", rp.url, "--format", rp.wire_format.value, *args])


def test_login_prints_session_cookie(authenticator, relying_party, capsys):
    relying_party.credentials.append(authenticator.create_credential(relying_party.rp_id))

    exit_code = _login(relying_party)

    out, err = capsys.readouterr()
    assert exit_code == EXIT_AUTHENTICATED
    assert out.startswith(f"{SESSION_COOKIE}=")
    assert "Touch your authenticator device..." in err
    assert "Authenticated." in err


def test_login_sends_begin_data_and_headers(authenticator, relying_party):
    relying_party.credentials.append(authenticator.create_credential(relying_party.rp_id))

    exit_code = _login(
        relying_party,
        "--begin-data", '{"username": "alice"}',
        "-H", "X-Request-Id: cli-1",
    )

    assert exit_code == EXIT_AUTHENTICATED
    [begin] = relying_party.requests_to(BEGIN_PATH)
    assert relying_party.decode(begin.body) == {"username": "alice"}
    assert begin.headers["X-Request-Id"] == "cli-1"


@pytest.mark.parametrize(
    ("failure_status", "expected_exit"),
    [(200, EXIT_REJECTED), (401, EXIT_REJECTED), (500, EXIT_ERROR)],
)
def test_login_rejected_by_server(authenticator, relying_party, capsys, failure_status, expected_exit):
    relying_party.failure_status = failure_status
    credential = authenticator.create_credential(relying_party.rp_id)
    relying_party.credentials.append(credential)
    authenticator.replace_key(credential.credential_id)

    exit_code = _login(relying_party)

    out, err = capsys.readouterr()
    assert exit_code == expected_exit
    assert out == ""
    if expected_exit == EXIT_REJECTED:
        assert f"Not authenticated (HTTP {failure_status})" in err
        assert "Invalid signature." in err


def test_login_without_server_cookies_prints_nothing(capsys):
    with patch("fido2client.cli.Fido2HttpClient") as Client:
        client = Client.return_value.__enter__.return_value
        client.authenticate_to.return_value = True
        client.session.cookies = []

        exit_code = main(["login", "http://localhost"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_AUTHENTICATED
    assert out == ""
    assert "Authenticated." in err


def test_login_interrupted(capsys):
    with patch("fido2client.cli.Fido2HttpClient") as Client:
        Client.return_value.__enter__.return_value.authenticate_to.side_effect = KeyboardInterrupt

        assert main(["login", "http://localhost"]) == EXIT_INTERRUPTED


def test_login_without_device(relying_party, capsys):
    with patch("fido2client.client.CtapHidDevice.list_devices", return_value=iter([])):
        exit_code = _login(relying_party)

    assert exit_code == EXIT_ERROR
    assert "error: No FIDO2 device found" in capsys.readouterr().err


@pytest.mark.parametrize(
    "bad_args",
    [["--begin-data", "[1, 2]"], ["--begin-data", "{nope"], ["-H", "no-colon"]],
    ids=["not-an-object", "not-json", "header-without-colon"],
)
def test_login_rejects_malformed_arguments(bad_args):
    with pytest.raises(SystemExit) as exc_info:
        main(["login", "http://localhost", *bad_args])
    assert exc_info.value.code == 2
