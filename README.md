# python-fido2-client

[![Tests](https://github.com/orglnte/python-fido2-client/actions/workflows/python-package.yml/badge.svg)](https://github.com/orglnte/python-fido2-client/actions/workflows/python-package.yml)
[![Publish](https://github.com/orglnte/python-fido2-client/actions/workflows/python-publish.yml/badge.svg?event=release)](https://github.com/orglnte/python-fido2-client/actions/workflows/python-publish.yml)
[![PyPI](https://img.shields.io/pypi/v/fido2client)](https://pypi.org/project/fido2client/)

Log in to a WebAuthn/FIDO2 server with a security key, from the console or from
your Python app.

`fido2client` calls the server's begin/complete endpoints over HTTP (JSON or CBOR),
gets the signed assertion from a USB key such as a YubiKey through Yubico's
[`fido2`](https://github.com/Yubico/python-fido2), and keeps the logged-in session.
Use it to test a WebAuthn server with a real key, or to add security-key login to
a client-side tool.

```bash
pip install fido2client
```

Requires Python 3.10+. On Linux, USB access to the key needs a
[udev rule](https://developers.yubico.com/python-fido2/) (or root). On
Windows 10 1903 and later, direct access to the key needs Administrator rights.

## From the console

```console
$ fido2client login https://example.com --begin-data '{"username": "alice"}'
Touch your authenticator device...
Authenticated.
session=eyJhbGciOi...
```

The session cookies go to stdout as one `Cookie` header value, everything else to
stderr, so the login drops into a script:

```bash
cookie=$(fido2client login https://example.com) && curl -H "Cookie: $cookie" https://example.com/api/me
```

Exit status: `0` authenticated, `1` rejected by the server, `2` error (no key,
network, HTTP 5xx, malformed response, wrong PIN). A PIN is asked for on the terminal when
the key has one and the server wants user verification.

| Option | Default | |
|---|---|---|
| `--begin PATH`, `--complete PATH` | `/api/authenticate/begin`, `/api/authenticate/complete` | endpoints |
| `--format json\|cbor` | `json` | message encoding |
| `--begin-data JSON` | | body of the begin request |
| `--extra-data JSON` | | extra fields for the complete request |
| `-H 'NAME: VALUE'` | | extra header, repeatable |
| `-k`, `--insecure` | | skip TLS verification, local development only |
| `--timeout SECONDS`, `-v` | `30` | HTTP timeout, debug logging |

`python -m fido2client` works the same way.

## From Python

```python
from fido2client import Fido2HttpClient, WireFormat

with Fido2HttpClient() as client:
    if client.authenticate_to(
        "https://example.com",
        "/api/authenticate/begin",
        "/api/authenticate/complete",
        wire_format=WireFormat.JSON,
        begin_data={"username": "alice"},
    ):
        me = client.session.get("https://example.com/api/me")
```

`authenticate_to` returns `True` when the server confirms the login and `False` when
it rejects it (see [What the server must speak](#what-the-server-must-speak)); `client.session`
is the `requests.Session` that now carries the server's cookies, and
`client.get_last_response()` is the raw completion response.

| `authenticate_to` argument | |
|---|---|
| `wire_format` | `WireFormat.JSON` for most servers; `WireFormat.CBOR` (the default, for compatibility) for the python-fido2 0.9 example protocol |
| `begin_data` | body of the begin request; none sent when omitted |
| `extra_data` | extra fields for the complete request: top level of the JSON body (the assertion's own keys, such as `id` or `response`, take precedence), or base64 JSON in `user_data` with CBOR |
| `extra_headers` | headers for both requests |
| `session` | your own `requests.Session` to log in with; it is not closed by the client |
| `prompt_callback`, `pin_callback` | how to ask for a touch (default `print`) and a PIN (default `getpass`); replace for GUI or headless apps |

`Fido2HttpClient(ssl_verify=True, timeout=30, verbose=False)` sets TLS verification,
the HTTP timeout in seconds, and DEBUG logging on the `fido2client` logger.

Errors, all subclasses of `fido2client.Fido2ClientError`:

| Exception | Raised when |
|---|---|
| `FidoDeviceNotFoundError` | no FIDO2 key is connected |
| `FidoServerError` | a request fails (network or HTTP status, chained as `__cause__`), or the server's response is unreadable or unexpected |
| `FidoAuthenticationError` | the key does not sign: no matching credential, wrong or missing PIN, user verification unavailable, RP ID not valid for the server's address, or timeout |

> **Security:** `ssl_verify=False` and `--insecure` turn off TLS certificate checks,
> which exposes the login to man-in-the-middle attacks. Use them only against a local
> server with a self-signed certificate.

## What the server must speak

1. **Begin** (`POST`, optional body `begin_data`) answers with WebAuthn request options,
   bare or wrapped as `{"publicKey": {...}}`, containing `rpId`, `challenge` and a
   non-empty `allowCredentials`.
2. **Complete** (`POST`) receives the assertion: the standard WebAuthn JSON
   (`id`, `rawId`, `response`, `type`) with `WireFormat.JSON`, or the fields
   `credentialId`, `authenticatorData`, `clientDataJSON`, `signature` with
   `WireFormat.CBOR`.
3. The login counts as successful when complete answers `{"status": "OK"}`; any
   other status, or an HTTP 4xx, counts as rejected; an HTTP 5xx is an error.
4. The `rpId` must be the server's host or a parent domain of it, over `https`
   (`http` only for `localhost`); the client refuses anything else.

The [python-fido2 example server](https://github.com/Yubico/python-fido2/tree/main/examples/server)
speaks this protocol in JSON; its
[0.9 version](https://github.com/Yubico/python-fido2/tree/0.9.3/examples/server) in CBOR.

## Development

```bash
pip install -e ".[dev]"
pytest
```

No key is needed: the tests run every login end to end, in both formats, against
`fido2.server.Fido2Server` on localhost (`tests/relying_party.py`) with a software
CTAP2 authenticator that signs with real ES256 keys and supports a PIN
(`tests/virtual_authenticator.py`). Only USB discovery is replaced.

## License

MIT
