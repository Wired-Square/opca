# opca/commands/dkim/register.py

from __future__ import annotations

import argparse

from .actions import (
    handle_dkim_create,
    handle_dkim_deploy,
    handle_dkim_info,
    handle_dkim_list,
    handle_dkim_verify,
)
from opca.constants import EXIT_OK
from opca.models import App


def _add_create_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `dkim create`
    """
    parser = actions.add_parser(
        "create",
        help="Generate a new DKIM key pair and store in 1Password",
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domain name for the DKIM key (e.g., example.com)",
    )

    parser.add_argument(
        "-s", "--selector",
        required=True,
        help="DKIM selector (e.g., mail, default, 2024)",
    )

    parser.add_argument(
        "-k", "--key-size",
        type=int,
        default=2048,
        choices=[1024, 2048, 4096],
        help="RSA key size in bits (default: 2048)",
    )

    parser.add_argument(
        "--deploy-route53",
        action="store_true",
        help="Deploy the DKIM record to AWS Route53",
    )

    parser.add_argument(
        "--zone-id",
        help="Route53 hosted zone ID (required if multiple zones match domain)",
    )

    parser.set_defaults(handler=handle_dkim_create)

    return parser


def _add_info_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `dkim info`
    """
    parser = actions.add_parser(
        "info",
        help="Show DKIM key information from 1Password",
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domain name",
    )

    parser.add_argument(
        "-s", "--selector",
        required=True,
        help="DKIM selector",
    )

    parser.set_defaults(handler=handle_dkim_info)

    return parser


def _add_deploy_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `dkim deploy`
    """
    parser = actions.add_parser(
        "deploy",
        help="Deploy existing DKIM key from 1Password to Route53",
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domain name",
    )

    parser.add_argument(
        "-s", "--selector",
        required=True,
        help="DKIM selector",
    )

    parser.add_argument(
        "--zone-id",
        help="Route53 hosted zone ID (required if multiple zones match domain)",
    )

    parser.set_defaults(handler=handle_dkim_deploy)

    return parser


def _add_list_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `dkim list`
    """
    parser = actions.add_parser(
        "list",
        help="List all DKIM keys stored in 1Password",
    )

    parser.add_argument(
        "-d", "--domain",
        help="Filter by domain name",
    )

    parser.set_defaults(handler=handle_dkim_list)

    return parser


def _add_verify_subcommand(actions: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """
    Register `dkim verify`
    """
    parser = actions.add_parser(
        "verify",
        help="Verify DKIM DNS record is published correctly",
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Domain name",
    )

    parser.add_argument(
        "-s", "--selector",
        required=True,
        help="DKIM selector",
    )

    parser.set_defaults(handler=handle_dkim_verify)

    return parser


def register(subparsers: argparse._SubParsersAction) -> None:
    """
    Register the `dkim` command and its actions.
    """
    parser = subparsers.add_parser(
        "dkim",
        add_help=True,
        help="Manage DKIM keys for email authentication",
    )

    actions = parser.add_subparsers(
        title="Actions",
        dest="action",
    )

    _add_create_subcommand(actions)
    _add_deploy_subcommand(actions)
    _add_info_subcommand(actions)
    _add_list_subcommand(actions)
    _add_verify_subcommand(actions)

    parser.set_defaults(handler=_show_help, _parser=parser)


def _show_help(app: App):
    app.args._parser.print_help()
    return EXIT_OK
