# opca/commands/database/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_database_config_get,
    handle_database_config_set,
    handle_database_export,
    handle_database_rebuild,
    handle_database_upload,
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_config_get_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `database config get`
    """

    parser = actions.add_parser('config-get',
        help='Get the current CA Database configuration')

    parser.set_defaults(handler=handle_database_config_get)

    return parser

def _add_config_set_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `database config set`
    """

    parser = actions.add_parser('config-set',
        help='Modify the CA Database configuration')
    parser.add_argument('--conf',
        action='append',
        required=True,
        help='Configuration attributes to modify. Example: --conf city=Canberra --conf days=30')

    parser.set_defaults(handler=handle_database_config_set)

    return parser

def _add_export_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `database export`
    """

    parser = actions.add_parser('export',
        help='Export the entire CA SQLite database')

    parser.set_defaults(handler=handle_database_export)

    return parser

def _add_rebuild_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `database rebuild`
    """

    parser = actions.add_parser('rebuild',
        help='Generate a Certificate Database for the 1Password CA')
    parser.add_argument('--days',
        required=True,
        type=int,
        help='The number of days the certificate should be valid for')
    parser.add_argument('--crl-days',
        required=True,
        type=int,
        help='The number of days a CRL should be valid for')
    parser.add_argument('--serial',
        required=False,
        type=int,
        help='Certificate Authority next serial number')
    parser.add_argument('--crl-serial',
        required=False,
        type=int,
        help='Certificate Authority next CRL serial number')
    parser.add_argument('--ca-url',
        required=False,
        help='The URL where we can find the CA certificate')
    parser.add_argument('--crl-url',
        required=False,
        help='The URL where we can find the Certificate Revocation List')
    parser.set_defaults(handler=handle_database_rebuild)

    return parser

def _add_upload_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `database upload`
    """

    parser = actions.add_parser('upload',
        help='Upload the CA Database to the private store')
    parser.add_argument('--store', action='append', required=False,
        help='Manually set the store location. Example: s3://bucket/key')

    parser.set_defaults(handler=handle_database_upload)

    return parser

def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `database` command and its actions.
    """
    parser = subparsers.add_parser(
        'database',
        add_help=True,
        help='Perform Database actions',
    )

    actions = parser.add_subparsers(
        title='Actions',
        dest='action',
    )

    _add_config_get_subcommand(actions)
    _add_config_set_subcommand(actions)
    _add_export_subcommand(actions)
    _add_rebuild_subcommand(actions)
    _add_upload_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)

def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
