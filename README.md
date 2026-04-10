# python-fido2-client

[![Tests](https://github.com/orglnte/python-fido2-client/actions/workflows/python-package.yml/badge.svg)](https://github.com/orglnte/python-fido2-client/actions/workflows/python-package.yml)
[![Publish](https://github.com/orglnte/python-fido2-client/actions/workflows/python-publish.yml/badge.svg?event=release)](https://github.com/orglnte/python-fido2-client/actions/workflows/python-publish.yml)
[![PyPI](https://img.shields.io/pypi/v/fido2client)](https://pypi.org/project/fido2client/)

WebAuthn API FIDO2 client implementation in Python.

A Python library for authenticating against WebAuthn/FIDO2 servers. Handles FIDO2 device discovery, assertion retrieval over CTAP HID, and server communication.

Tested against the [python-fido2 server example](https://github.com/Yubico/python-fido2/tree/master/examples/server).

## Requirements

- Python 3.10+
- A FIDO2-compatible USB authenticator (e.g. YubiKey)
- A WebAuthn server implementing the begin/complete authentication flow using CBOR encoding

## Installation

```bash
pip install fido2client
```

## Quick start

```python
import fido2client

with fido2client.Fido2HttpClient() as client:
    authenticated = client.authenticate_to(
        'https://your-server.com',
        '/api/authenticate/begin',
        '/api/authenticate/complete',
    )
    if authenticated:
        print('Authenticated!')
```

## Usage

### Basic authentication

```python
from fido2client import Fido2HttpClient

client = Fido2HttpClient()
result = client.authenticate_to(
    'https://example.com',
    '/api/authenticate/begin',
    '/api/authenticate/complete',
)
```

### With custom headers or extra data

```python
client = Fido2HttpClient()
result = client.authenticate_to(
    'https://example.com',
    '/api/authenticate/begin',
    '/api/authenticate/complete',
    extra_headers={'Authorization': 'Bearer <token>'},
    extra_data={'session_id': 'abc123'},
)
```

### Reusing an existing HTTP session

```python
import requests
from fido2client import Fido2HttpClient

session = requests.Session()
session.cookies.set('csrf_token', '...')

client = Fido2HttpClient()
result = client.authenticate_to(
    'https://example.com',
    '/api/authenticate/begin',
    '/api/authenticate/complete',
    session=session,
)
```

### Context manager (recommended)

The context manager ensures the HTTP session is closed when done:

```python
from fido2client import Fido2HttpClient

with Fido2HttpClient() as client:
    result = client.authenticate_to(
        'https://example.com',
        '/api/authenticate/begin',
        '/api/authenticate/complete',
    )
```

### Custom callbacks

By default, `authenticate_to` uses `print` for user prompts and `getpass.getpass`
for PIN entry. Override these for GUI apps or headless automation:

```python
from fido2client import Fido2HttpClient

with Fido2HttpClient() as client:
    result = client.authenticate_to(
        'https://example.com',
        '/api/authenticate/begin',
        '/api/authenticate/complete',
        prompt_callback=lambda msg: my_ui.show(msg),
        pin_callback=lambda: my_ui.ask_pin(),
    )
```

### Error handling

```python
from fido2client import Fido2HttpClient
from fido2client.exceptions import (
    FidoAuthenticationError,
    FidoDeviceNotFoundError,
    FidoServerError,
)
import requests

try:
    with Fido2HttpClient() as client:
        result = client.authenticate_to(
            'https://example.com',
            '/api/authenticate/begin',
            '/api/authenticate/complete',
        )
except FidoDeviceNotFoundError:
    print('No FIDO2 device found. Connect your authenticator and try again.')
except FidoAuthenticationError as e:
    print(f'Authentication ceremony failed: {e}')
except FidoServerError as e:
    print(f'Server communication failed: {e}')
except requests.exceptions.RequestException as e:
    print(f'Network error: {e}')
```

### Configuration options

```python
client = Fido2HttpClient(
    ssl_verify=True,  # Verify TLS certificates (default: True, always use in production)
    timeout=30,       # HTTP request timeout in seconds (default: 30)
    verbose=False,    # Shortcut to enable DEBUG logging (default: False)
)
```

> **Security note:** `ssl_verify=False` disables TLS certificate verification entirely.
> **Never use this in production** — it makes the connection vulnerable to man-in-the-middle attacks.
> It is only appropriate for local development environments using self-signed certificates.

### Enabling debug logging

Rather than using the `verbose` flag, you can configure the standard Python logging module:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('fido2client').setLevel(logging.DEBUG)
```

### Local development example

For local testing against a server using a self-signed certificate:

```python
import fido2client

# WARNING: ssl_verify=False is for local development only.
# Never use in production.
c = fido2client.Fido2HttpClient(ssl_verify=False, verbose=True)

c.authenticate_to(
    'https://localhost:5000',
    '/api/authenticate/begin',
    '/api/authenticate/complete',
)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Exception hierarchy

| Exception | Raised when |
|---|---|
| `Fido2ClientError` | Base class for all fido2client errors |
| `FidoDeviceNotFoundError` | No FIDO2 device is connected |
| `FidoServerError` | Server returns an unreadable or unexpected response |
| `FidoAuthenticationError` | The authentication ceremony cannot proceed |

## License

MIT
