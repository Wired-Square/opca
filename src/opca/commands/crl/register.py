# opca/commands/crl/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_crl_create,
    handle_crl_export,
    handle_crl_info,
    handle_crl_upload,
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_create_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `crl create`
    """
    parser = actions.add_parser('create',
        help='Generate a Certificate Revocation List for the 1Password CA'
    )

    parser.set_defaults(handler=handle_crl_create)

    return parser

def _add_export_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `crl export`
    """
    parser = actions.add_parser(
        'export',
        help='Export the Certificate Revocation List (CRL) from 1Password'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['pem', 'der'],
        default='pem',
        help='Export format (default: pem)'
    )

    dest = parser.add_mutually_exclusive_group()
    dest.add_argument(
        '--to-stdout',
        action='store_true',
        help='Write CRL to stdout'
    )
    dest.add_argument(
        '-o', '--outfile',
        metavar='FILE',
        help='Write CRL to this file'
    )

    parser.set_defaults(handler=handle_crl_export)

    return parser

def _add_info_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `crl info`
    """
    parser = actions.add_parser(
        'info',
        help='Show information about the Certificate Revocation List from 1Password'
    )

    parser.set_defaults(handler=handle_crl_info)

    return parser

def _add_upload_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `crl upload`
    """
    parser = actions.add_parser(
        'upload',
        help='Upload the CRL Database to the public store')

    parser.add_argument(
        '--generate', '--gen',
        action='store_true',
        required=False,
        help='Generate the CRL before storing'
    )

    parser.add_argument(
        '--store',
        action='append',
        required=False,
        help='Manually set the store location. Example: s3://bucket/key'
    )

    parser.set_defaults(handler=handle_crl_upload)

    return parser


def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `crl` command and its actions.
    """
    parser = subparsers.add_parser(
        'crl',
        add_help=True,
        help='Perform Certificate Revocation List actions',
    )

    actions = parser.add_subparsers(
        title='Actions',
        dest='action',
    )

    _add_create_subcommand(actions)
    _add_export_subcommand(actions)
    _add_info_subcommand(actions)
    _add_upload_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)

def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
