# opca/commands/ca/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_ca_init,
    handle_ca_import,
    handle_ca_export,
    handle_ca_list,
    handle_ca_upload,
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_init_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `ca init`
    """

    parser = actions.add_parser('init',
        help='Initialise a 1Password Certificate Authority'
    )
    parser.add_argument('-e', '--email',
        required=False,
        help='The email address to use in the certificate subject'
    )
    parser.add_argument('-o', '--org',
        required=True,
        help='The organisation to use in the certificate subject'
    )
    parser.add_argument('--city',
        required=False,
        help='The city to use in the certificate subject'
    )
    parser.add_argument('--state',
        required=False,
        help='The state to use in the certificate subject'
    )
    parser.add_argument('--country',
        required=False,
        help='The country to use in the certificate subject'
    )
    parser.add_argument('--ca-days',
        required=True,
        type=int,
        help='The number of days this CA certificate should be valid for'
    )
    parser.add_argument('--crl-days',
        required=True,
        type=int,
        help='The number of days a CRL should be valid for'
    )
    parser.add_argument('--days',
        required=True,
        type=int,
        help='The number of days the certificate signed by this CA should be valid for'
    )
    parser.add_argument('-n', '--cn',
        required=True,
        help='x509 Common Name attribute for the 1Password Certificate Authority'
    )
    parser.add_argument('--ou',
        required=False,
        help='x509 Organisational Unit attribute for the 1Password Certificate Authority'
    )
    parser.add_argument('--ca-url',
        required=False,
        help='The URL where we can find the CA certificate'
    )
    parser.add_argument('--crl-url',
        required=False,
        help='The URL where we can find the Certificate Revocation List'
    )
    parser.set_defaults(handler=handle_ca_init, subcommand="init_ca")

    return parser

def _add_import_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `ca import`
    """

    parser= actions.add_parser('import',
        help='Import a 1Password Certificate Authority from file'
    )
    parser.add_argument('-c', '--cert-file',
        required=True,
        help='Certificate file'
    )
    parser.add_argument('-k', '--key-file',
        required=True,
        help='Private Key file'
    )
    parser.add_argument('--days',
        required=True,
        type=int,
        help='The number of days the certificate should be valid for'
    )
    parser.add_argument('--crl-days',
        required=True,
        type=int,
        help='The number of days a CRL should be valid for'
    )
    parser.add_argument('--serial',
        required=False,
        type=int,
        help='CA next serial number'
    )
    parser.add_argument('--crl-serial',
        required=False,
        type=int,
        help='Certificate Authority next CRL serial number'
    )
    parser.add_argument('--ca-url',
        required=False,
        help='The URL where we can find the CA certificate'
    )
    parser.add_argument('--crl-url',
        required=False,
        help='The URL where we can find the Certificate Revocation List'
    )
    parser.set_defaults(handler=handle_ca_import, subcommand="import_ca")

    return parser

def _add_export_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `ca export`
    """

    parser = actions.add_parser('export',
        help='Export the object CA Certificate and optionally the CA key'
    )
    parser.set_defaults(handler=handle_ca_export, subcommand="export")

    parser.add_argument("--with-key",
        action="store_true",
        help="Include the CA private key in the export"
    )
    parser.add_argument("--cert-only",
        action="store_true",
        help="Export certificate only (default)"
    )
    parser.add_argument("--to-stdout",
        action="store_true",
        help="Write output to stdout"
    )
    parser.add_argument("--cert-out",
        metavar="FILE",
        help="Write certificate PEM to this file"
    )
    parser.add_argument("--key-out",
        metavar="FILE",
        help="Write private key PEM to this file (requires --with-key)"
    )

    return parser

def _add_list_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `ca list`
    """
    parser = actions.add_parser("list",
        help="List certificates signed by the CA.")
    mode = parser.add_mutually_exclusive_group(
        required=False
    )
    mode.add_argument("-a", "--all",
        dest="list_mode",
        action="store_const",
        const="all",
        help="List all certificates (default)"
    )
    mode.add_argument("-e", "--expired",
        dest="list_mode",
        action="store_const",
        const="expired",
        help="List expired certificates"
    )
    mode.add_argument("-r", "--revoked",
        dest="list_mode",
        action="store_const",
        const="revoked",
        help="List revoked certificates"
    )
    mode.add_argument("-x", "--expiring",
        dest="list_mode",
        action="store_const",
        const="expiring",
        help="List certificates expiring soon"
    )
    mode.add_argument("-v", "--valid",
        dest="list_mode",
        action="store_const",
        const="valid",
        help="List all valid certificates"
    )

    mode.add_argument("-n", "--cn",
        help="List certificate with this cn"
    )
    mode.add_argument("-s", "--serial",
        type=int,
        help="List certificate with this serial number"
    )

    parser.set_defaults(handler=handle_ca_list, list_mode="all")

    return parser

def _add_upload_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `ca upload`
    """

    parser = actions.add_parser('upload',
        help='Upload the CA Certificate to the public store'
    )
    parser.add_argument('--store',
        action='append',
        required=False,
        help='Manually set the store location. Example: s3://bucket/key'
    )
    parser.set_defaults(handler=handle_ca_upload, subcommand="upload_ca_cert")

    return parser

def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `ca` command and its actions.
    """
    parser = subparsers.add_parser(
        'ca',
        add_help=True,
        help='Perform Certificate Authority actions',
    )

    actions = parser.add_subparsers(
        title='Actions',
        dest='action',
    )

    _add_init_subcommand(actions)
    _add_import_subcommand(actions)
    _add_export_subcommand(actions)
    _add_list_subcommand(actions)
    _add_upload_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)

def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
