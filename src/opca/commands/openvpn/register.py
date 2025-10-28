# opca/commands/openvpn/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_generate,
    handle_get,
    handle_import,
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_generate_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `openvpn generate`
    Allows: --dh, --ta-key, --profile (with its args), --server
    """

    parser = actions.add_parser('generate',
        help="Generate OpenVPN artifacts (e.g., DH params, TA key, profile, server object)",
    )
    parser.add_argument("--dh", action="store_true",
                        help="Generate Diffie-Hellman parameters")
    parser.add_argument("--ta-key", dest="ta_key", action="store_true",
                        help="Generate TLS Authentication static key")
    parser.add_argument("--profile", action="store_true",
                        help="Generate a VPN profile (requires --template and either --cn or --file)")
    parser.add_argument("--server", action="store_true",
                        help="Generate a sample OpenVPN server object")

    # Profile options (only used when --profile is set)
    parser.add_argument("-d", "--dest", required=False,
                        help="Destination vault to store the VPN profile")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-f", "--file",
                       help="Bulk certificate CN file (profile generation)")
    group.add_argument("-n", "--cn",
                       help="Certificate CN / 1Password title (profile generation)")
    parser.add_argument("-t", "--template", required=False,
                        help="OpenVPN template stored in 1Password (profile generation)")

    parser.set_defaults(handler=handle_generate)

    return parser

def _add_get_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `openvpn get`
    Allows: --dh, --ta-key (any combo)
    """
    parser = actions.add_parser(
        "get",
        help="Retrieve OpenVPN artifacts from 1Password",
    )
    parser.add_argument("--dh", action="store_true",
                        help="Retrieve Diffie-Hellman parameters")
    parser.add_argument("--ta-key", dest="ta_key", action="store_true",
                        help="Retrieve TLS Authentication static key")
    parser.add_argument("-t", "--template",
                        help="Retrieve an OpenVPN template by name/title")

    parser.set_defaults(handler=handle_get, _parser=parser)

    return parser

def _add_import_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `openvpn import`
    Allows: --dh [--file or --dh-file], --ta-key [--file or --ta-key-file]
    If importing both, prefer using --dh-file and --ta-key-file to avoid ambiguity.
    """
    parser = actions.add_parser(
        "import",
        help="Import OpenVPN artifacts from local files into 1Password",
    )
    parser.add_argument("--dh", action="store_true",
                        help="Import Diffie-Hellman parameters")
    parser.add_argument("--ta-key", dest="ta_key", action="store_true",
                        help="Import TLS Authentication static key")

    # File arguments
    parser.add_argument("-f", "--file",
                        help="Generic file (allowed only when importing exactly one artifact)")
    parser.add_argument("--dh-file",
                        help="DH parameters file (when using --dh)")
    parser.add_argument("--ta-key-file",
                        help="TLS Auth static key file (when using --ta-key)")

    parser.set_defaults(handler=handle_import, _parser=parser)

    return parser

def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `openvpn` command and its actions.
    """
    parser = subparsers.add_parser(
        'openvpn',
        add_help=True,
        help='Perform Certificate Revocation List actions',
    )

    actions = parser.add_subparsers(
        title='Actions',
        dest='action',
    )

    _add_generate_subcommand(actions)
    _add_get_subcommand(actions)
    _add_import_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)

def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
