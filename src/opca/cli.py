#!/usr/bin/env python3
"""
#
# opca.py - 1Password Certificate Authority
#

A Python certificate authority implementation to generate keys, sign certificates,
and then store them in 1Password.

Requirements:
  - Python 3.7+
  - Cryptography (pyca/cryptography) - https://cryptography.io

Optional Requirements:
  - Boto3 - S3 library for uploading CA fragments

"""
from __future__ import annotations

import argparse
import logging
from typing import Optional, Callable

from opca import __version__, __title__, __short_title__
from .constants import EXIT_FATAL
from .commands import register_all
from .models.app import App
from .utils.formatting import title, error

from .services.op_errors import OPError
from .services.ca_errors import CAError


def build_parser(prog_desc: str) -> argparse.ArgumentParser:
    """ Build the command line argument parser """

    parser = argparse.ArgumentParser(
        description=prog_desc,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("-a", "--account",
        required=False,
        help="1Password Account. Example: company.1password.com"
    )

    parser.add_argument("-v", "--vault",
        required=True,
        help="CA Vault"
    )

    parser.add_argument("--log-level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="Set logging verbosity",
    )

    parser.add_argument("--version",
        action="version",
        version=f"{__title__} {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    register_all(subparsers)

    return parser

# ---------------------
# Entry point
# ---------------------

def main(argv: Optional[list[str]] = None) -> int:

    description: str = f'{__title__} - {__short_title__} v{__version__}'

    parser: argparse.ArgumentParser = build_parser(description)
    args: argparse.Namespace = parser.parse_args(argv)
    handler: Optional[Callable[[App], int]] = getattr(args, "handler", None)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    title(description, 1)

    if handler is None:
        logging.error("Unknown command: %s", getattr(args, "command", None))
        return EXIT_FATAL

    try:
        app: App = App.from_args(args=args)

        return handler(app)

    except OPError as e:
        # 1Password-related problems (vault not found, auth, permissions, conflicts, CLI)
        error(str(e))
        return EXIT_FATAL
    except CAError as e:
        # Your CA/domain-layer problems
        error(str(e))
        return EXIT_FATAL
    except SystemExit:
        raise
    except Exception:
        logging.exception("Unexpected error")
        return EXIT_FATAL

if __name__ == "__main__":
    raise SystemExit(main())
