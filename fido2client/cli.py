"""Command line: log in to a WebAuthn/FIDO2 server with a security key.

Messages for the user go to stderr; stdout carries only the session cookies,
as one ``Cookie`` header value, so a script can capture them.
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections.abc import Sequence
from typing import Any

from . import __version__
from .client import Fido2HttpClient
from .exceptions import Fido2ClientError
from .wire import WireFormat

EXIT_AUTHENTICATED = 0
EXIT_REJECTED = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _login(args)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception as exc:
        if args.verbose:
            traceback.print_exc()
        _tell(f"error: unexpected {type(exc).__name__}: {exc}")
        return EXIT_ERROR


def _login(args: argparse.Namespace) -> int:
    if args.insecure:
        _tell("warning: TLS certificate verification is disabled")
    wire_format = WireFormat(args.format)
    with Fido2HttpClient(
        ssl_verify=not args.insecure, verbose=args.verbose, timeout=args.timeout
    ) as client:
        try:
            authenticated = client.authenticate_to(
                args.server,
                args.begin,
                args.complete,
                extra_data=args.extra_data,
                extra_headers=dict(args.header) or None,
                prompt_callback=_tell,
                wire_format=wire_format,
                begin_data=args.begin_data,
            )
        except Fido2ClientError as exc:
            _tell(f"error: {exc}")
            return EXIT_ERROR

        if not authenticated:
            response = client.get_last_response()
            try:
                detail = wire_format.codec.loads(response.content)
            except Exception:
                detail = response.text
            _tell(f"Not authenticated (HTTP {response.status_code}). Server response: {detail}")
            return EXIT_REJECTED

        _tell("Authenticated.")
        cookies = "; ".join(f"{c.name}={c.value}" for c in client.session.cookies)
        if cookies:
            print(cookies)
        return EXIT_AUTHENTICATED


def _tell(message: str) -> None:
    print(message, file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fido2client",
        description="Log in to a WebAuthn/FIDO2 server with a security key.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    login = commands.add_parser(
        "login",
        help="authenticate, then print the session cookies",
        description=(
            "Run the begin/complete authentication ceremony against SERVER with the "
            "connected security key. Prints the session cookies as one Cookie header "
            "value on stdout. Exit status: 0 authenticated, 1 rejected by the server, "
            "2 error."
        ),
    )
    login.add_argument("server", help="base URL of the server, e.g. https://example.com")
    login.add_argument(
        "--begin", default="/api/authenticate/begin", metavar="PATH",
        help="begin endpoint (default: %(default)s)",
    )
    login.add_argument(
        "--complete", default="/api/authenticate/complete", metavar="PATH",
        help="complete endpoint (default: %(default)s)",
    )
    login.add_argument(
        "--format", choices=[f.value for f in WireFormat], default=WireFormat.JSON.value,
        help="message encoding (default: %(default)s)",
    )
    login.add_argument(
        "--begin-data", type=_json_object, metavar="JSON",
        help="body of the begin request, e.g. '{\"username\": \"alice\"}'",
    )
    login.add_argument(
        "--extra-data", type=_json_object, metavar="JSON",
        help="extra fields sent with the complete request",
    )
    login.add_argument(
        "-H", "--header", action="append", default=[], type=_header, metavar="'NAME: VALUE'",
        help="extra HTTP header for both requests; repeatable",
    )
    login.add_argument(
        "-k", "--insecure", action="store_true",
        help="skip TLS certificate verification (local development only)",
    )
    login.add_argument(
        "--timeout", type=int, default=30, metavar="SECONDS",
        help="HTTP timeout (default: %(default)s)",
    )
    login.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("must be a JSON object")
    return value


def _header(text: str) -> tuple[str, str]:
    name, separator, value = text.partition(":")
    if not separator or not name.strip():
        raise argparse.ArgumentTypeError("expected 'NAME: VALUE'")
    return name.strip(), value.strip()
