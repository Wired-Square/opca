# opca/commands/vault/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_vault_backup,
    handle_vault_restore,
    handle_vault_info,
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_backup_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register ``vault backup``."""
    parser = actions.add_parser(
        "backup",
        help="Create an encrypted backup of the entire vault",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file path (default: <vault>-<date>.opca)",
    )
    parser.add_argument(
        "--password",
        help="Encryption password (if omitted, you will be prompted interactively)",
    )
    parser.set_defaults(handler=handle_vault_backup, subcommand="backup")
    return parser


def _add_restore_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register ``vault restore``."""
    parser = actions.add_parser(
        "restore",
        help="Restore a vault from an encrypted backup file",
    )
    parser.add_argument(
        "-i", "--input",
        metavar="FILE",
        required=True,
        dest="input_file",
        help="Backup file to restore from",
    )
    parser.add_argument(
        "--password",
        help="Decryption password (if omitted, you will be prompted interactively)",
    )
    parser.set_defaults(handler=handle_vault_restore, subcommand="restore")
    return parser


def _add_info_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register ``vault info``."""
    parser = actions.add_parser(
        "info",
        help="Display metadata from an encrypted backup file",
    )
    parser.add_argument(
        "-i", "--input",
        metavar="FILE",
        required=True,
        dest="input_file",
        help="Backup file to inspect",
    )
    parser.add_argument(
        "--password",
        help="Decryption password (if omitted, you will be prompted interactively)",
    )
    parser.set_defaults(handler=handle_vault_info, subcommand="info")
    return parser


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``vault`` command and its actions."""
    parser = subparsers.add_parser(
        "vault",
        add_help=True,
        help="Vault backup and restore operations",
    )

    actions = parser.add_subparsers(
        title="Actions",
        dest="action",
    )

    _add_backup_subcommand(actions)
    _add_restore_subcommand(actions)
    _add_info_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)


def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
