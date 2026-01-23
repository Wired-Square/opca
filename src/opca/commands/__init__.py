# opca/commands/__init__.py

from __future__ import annotations

import argparse

from . import ca, cert, crl, database, dkim, openvpn

def register_all(subparsers: argparse._SubParsersAction) -> None:
    """
    Register all subcommands here
    """
    ca.register(subparsers)
    cert.register(subparsers)
    crl.register(subparsers)
    database.register(subparsers)
    dkim.register(subparsers)
    openvpn.register(subparsers)