# opca/commands/tui/__init__.py

from __future__ import annotations

import argparse

from .actions import handle_tui


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `tui` command."""
    parser = subparsers.add_parser(
        "tui",
        add_help=True,
        help="Launch the interactive Terminal UI",
    )
    parser.set_defaults(handler=handle_tui, command="tui", subcommand="")
