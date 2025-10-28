# opca/reports/ca_list.py

from __future__ import annotations

from datetime import datetime
import logging

from opca.constants import (
    EXIT_OK,
    EXIT_FATAL,
    COLOUR,
    COLOUR_BRIGHT,
    COLOUR_RESET,
)
from opca.utils.datetime import format_datetime
from opca.utils.formatting import title

log = logging.getLogger(__name__)


# Row shape we expect from the action:
# {
#   "serial": int,
#   "cn": str,
#   "title": str,
#   "status": "Valid"|"Revoked"|"Expired",
#   "expiry_date": "YYYYmmddHHMMSSZ",
#   "revocation_date": Optional["YYYYmmddHHMMSSZ"]
# }

def ca_list(rows: list[dict], *, report_title: str) -> int:
    """
    Render a CA certificate list from pre-collected rows.
    No dependency on `App`.
    """
    title(report_title, level=2)

    headers = ["serial", "cn", "title", "status", "expiry_date", "revocation_date"]
    row_format = "{:<8} {:<35} {:<40} {:<10} {:<20} {:<20}"

    print(row_format.format(*headers))
    print("-" * 140)

    status_colours = {
        "Valid":    [COLOUR["green"],  COLOUR["bold_green"]],
        "Revoked":  [COLOUR["red"],    COLOUR["bold_red"]],
        "Expired":  [COLOUR["white"],  COLOUR["bright_white"]],
        "Expiring": [COLOUR["yellow"], COLOUR["bold_yellow"]],
    }

    for index, cert in enumerate(rows):
        if len(cert["cn"]) <= 35:
            cn = cert["cn"]
        else:
            cn = cert["cn"][:32] + "..."

        expiry_str = format_datetime(
            date=datetime.strptime(
                cert["expiry_date"],
                "%Y%m%d%H%M%SZ"
            ),
            output_format="compact",
        )

        if cert.get("revocation_date"):
            revocation_str = format_datetime(
                date=datetime.strptime(cert["revocation_date"], "%Y%m%d%H%M%SZ"),
                output_format="compact"
            )
        else:
            revocation_str = ""

        colours = status_colours.get(cert['status'], [COLOUR['white'], COLOUR['bold_white']])
        colour = colours[index % 2]

        print(
            colour + row_format.format(
                cert['serial'],
                cn,
                cert['title'],
                cert['status'],
                expiry_str,
                revocation_str
            )
            + COLOUR_RESET
        )

    return EXIT_OK
