# opca/commands/cert/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_cert_create,
    handle_cert_export,
    handle_cert_info,
    handle_cert_import,
    handle_cert_renew,
    handle_cert_revoke
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_create_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `cert create`
    """

    parser = actions.add_parser("create",
        help="Create a new x509 CertificateBundle object")
    subparser_group_create_cert = parser.add_mutually_exclusive_group(
        required=True)
    subparser_group_create_cert.add_argument("-n", "--cn",
        help="CN attribute. Regular certificates use this for the 1Password title.")
    subparser_group_create_cert.add_argument("-f", "--file",
        help="Bulk host file")
    parser.add_argument("-t", "--cert-type",
        required=True,
        help="x509 Certificate type", choices=["device", "vpnserver", "vpnclient", "webserver"])
    parser.add_argument("-s", "--serial",
        required=False,
        type=int,
        help="Certificate serial number or CA Certificate next serial number")
    parser.add_argument("--alt",
        action="append",
        required=False,
        help="Alternate CN.")

    parser.set_defaults(handler=handle_cert_create)

    return parser

def _add_export_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `cert export`
    """
    parser = actions.add_parser("export",
        help="Export a x509 CertificateBundle"
    )
    id_group = parser.add_mutually_exclusive_group(
        required=True
    )
    id_group.add_argument("-n", "--cn",
        help="x509 CN attribute of the certificate to export"
    )
    id_group.add_argument("-s", "--serial",
        type=int,
        help="Serial number of the certificate to export"
    )
    parser.add_argument("-f", "--format",
        default="pem",
        choices=["pem", "pkcs12"],
        help="Export format (default: pem)"
    )

    # PEM knobs
    parser.add_argument('--with-key', action='store_true', help='Include private key (PEM only)')
    parser.add_argument('--cert-only', action='store_true', help='Export certificate only (PEM only; default)')
    parser.add_argument('--to-stdout', action='store_true', help='Write PEM to stdout')
    parser.add_argument('--cert-out', metavar='FILE', help='Write certificate PEM to this file')
    parser.add_argument('--key-out', metavar='FILE', help='Write private key PEM to this file (requires --with-key)')

    # PKCS#12 knobs
    parser.add_argument('-o', '--outfile',
        metavar='FILE',
        help='Output PKCS#12 file (required for pkcs12)'
    )
    parser.add_argument('--p12-password',
        metavar='PASS',
        help='Ask for a export password (pkcs12)'
    )

    parser.set_defaults(handler=handle_cert_export)

    return parser

def _add_info_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `cert info`
    """
    parser = actions.add_parser('info',
        help='Show information of a x509 CertificateBundle object')
    parser_group_info_cert = parser.add_mutually_exclusive_group(
        required=True)
    parser_group_info_cert.add_argument('-n', '--cn',
        help='x509 CN attribute of the certificate to show')
    parser_group_info_cert.add_argument('-s', '--serial',
        type=int,
        help='Serial number of the certificate to show')

    parser.set_defaults(handler=handle_cert_info)

    return parser

def _add_import_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `cert import`
    """
    parser = actions.add_parser('import',
        help='Import a x509 CertificateBundle object from files')
    parser.add_argument('-c', '--cert-file',
        required=True,
        help='Certificate file')
    parser.add_argument('-k', '--key-file',
        required=False,
        help='Private Key file')
    parser.add_argument('-n', '--cn',
        required=False,
        help='x509 CN attribute for the 1Password Certificate Authority')

    parser.set_defaults(handler=handle_cert_import)

    return parser

def _add_renew_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `cert renew`
    """
    parser = actions.add_parser('renew',
        help='Renew a x509 certificate, retaining the private key')
    parser_group_renew_cert = parser.add_mutually_exclusive_group(
        required=True)
    parser_group_renew_cert.add_argument('-n', '--cn',
        help='x509 CN of the certificate to renew')
    parser_group_renew_cert.add_argument('-s', '--serial',
        type=int,
        help='Serial number of the certificate to renew')

    parser.set_defaults(handler=handle_cert_renew)

    return parser

def _add_revoke_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `cert revoke`
    """
    parser = actions.add_parser('revoke',
        help='Create a new x509 CertificateBundle object')
    parser_group_revoke_cert = parser.add_mutually_exclusive_group(
        required=True)
    parser_group_revoke_cert.add_argument('-f', '--file',
        help='Bulk host file')
    parser_group_revoke_cert.add_argument('-n', '--cn',
        help='x509 CN of the certificate to revoke')
    parser_group_revoke_cert.add_argument('-s', '--serial',
        type=int,
        help='Serial number of the certificate to revoke')

    parser.set_defaults(handler=handle_cert_revoke)

    return parser

def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `cert` command and its actions.
    """
    parser = subparsers.add_parser(
        'cert',
        add_help=True,
        help='Perform Certificate actions',
    )

    actions = parser.add_subparsers(
        title='Actions',
        dest='action',
    )

    _add_create_subcommand(actions)
    _add_export_subcommand(actions)
    _add_info_subcommand(actions)
    _add_import_subcommand(actions)
    _add_renew_subcommand(actions)
    _add_revoke_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)

def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
