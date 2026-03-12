# opca/commands/csr/register.py

from __future__ import annotations

import argparse

from .actions import handle_csr_create, handle_csr_import, handle_csr_sign
from opca.constants import EXIT_OK
from opca.models import App


def _add_create_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `csr create`
    """

    parser = actions.add_parser("create",
        help="Generate a Certificate Signing Request (CSR) and private key")
    parser.add_argument("-t", "--csr-type",
        required=True,
        help="CSR type", choices=["appledev"])
    parser.add_argument("-n", "--cn",
        required=True,
        help="Common Name (CN) for the CSR subject")
    parser.add_argument("--email",
        required=True,
        help="Email address for the CSR subject")
    parser.add_argument("--country",
        required=False,
        help="Country code (e.g. AU). Defaults to CA config if available.")

    parser.set_defaults(handler=handle_csr_create)

    return parser


def _add_import_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `csr import`
    """

    parser = actions.add_parser("import",
        help="Import an externally signed certificate into an existing CSR entry")
    parser.add_argument("-n", "--cn",
        required=True,
        help="CN of the existing CSR entry in 1Password")
    parser.add_argument("-c", "--cert-file",
        required=True,
        help="Path to the signed certificate file (PEM or DER)")

    parser.set_defaults(handler=handle_csr_import)

    return parser


def _add_sign_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `csr sign`
    """

    parser = actions.add_parser("sign",
        help="Sign an external CSR with the local CA")
    parser.add_argument("-c", "--csr-file",
        required=False,
        help="Path to CSR file (PEM or DER)")
    parser.add_argument("--csr-pem",
        required=False,
        help="Inline CSR PEM string")
    parser.add_argument("-t", "--csr-type",
        required=False,
        default="webserver",
        choices=["appledev", "device", "vpnclient", "vpnserver", "webserver"],
        help="Certificate type (default: webserver)")
    parser.add_argument("-n", "--cn",
        required=False,
        help="CN override (defaults to CN from CSR subject)")

    parser.set_defaults(handler=handle_csr_sign)

    return parser


def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `csr` command and its actions.
    """
    parser = subparsers.add_parser(
        'csr',
        add_help=True,
        help='Generate Certificate Signing Requests',
    )

    actions = parser.add_subparsers(
        title='Actions',
        dest='action',
    )

    _add_create_subcommand(actions)
    _add_import_subcommand(actions)
    _add_sign_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)

def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
