# opca/commands/crl/actions.py

from __future__ import annotations

import logging
import sys

from opca.models import App
from opca.constants import (
    EXIT_OK,
    EXIT_FATAL,
    COLOUR_BRIGHT,
    COLOUR_RESET,
)
from opca.services.ca_errors import CAStorageError, CANotFoundError, CAError
from opca.utils.formatting import error, warning, print_result, title
from opca.utils.files import write_bytes

log = logging.getLogger(__name__)


def handle_crl_create(app: App) -> int:
    title("Create Certificate Revocation List", level=2)

    crl = app.ca.generate_crl()

    title(f'Checking generated [ { COLOUR_BRIGHT }CRL Validity{ COLOUR_RESET } ]', 9)
    print_result(app.ca.is_crl_valid(crl.encode('utf-8')))

    print(crl)

    return EXIT_OK

def handle_crl_export(app: App) -> int:
    """
    Export CRL to stdout or file in PEM/DER formats.
    """
    title("Export Certificate Revocation List", level=2)

    fmt = getattr(app.args, "format", "pem")
    outfile = getattr(app.args, "outfile", None)

    out_bytes = app.ca.get_crl_bytes(fmt)

    if outfile:
        write_bytes(outfile, out_bytes, overwrite=False, atomic=True, mode=0o644)
        title(f'Wrote CRL ({fmt.upper()}) → {outfile}')
        return EXIT_OK

    sys.stdout.buffer.write(out_bytes)

    if fmt == "pem" and sys.stdout.isatty():
        sys.stdout.write("\n")

    return EXIT_OK

def handle_crl_info(app: App) -> int:
    title("Certificate Revocation List Info", level=2)

    crl_info = app.ca.get_crl_info()

    title(f"Checking { COLOUR_BRIGHT }CRL Validity{ COLOUR_RESET} [ { COLOUR_BRIGHT }{crl_info['crl_number']}{ COLOUR_RESET } ]", 9)
    print_result(crl_info["valid"])

    print(f"Issuer: {crl_info['issuer']}")
    print(f"Last Update: {crl_info['last_update']}")
    print(f"Next Update: {crl_info['next_update']}")

    if crl_info["expired"]:
        warning("This CRL is expired. A new one should be issued.")

    if crl_info["revoked"]:
        print(f"{ COLOUR_BRIGHT }Revoked Certificates:{ COLOUR_RESET}")
        for cert in crl_info["revoked"]:
            print(f"  Serial: {cert.serial_number}, Revocation Date: {cert.revocation_date_utc}")
    else:
        print(f"{ COLOUR_BRIGHT }No Revoked Certificates:{ COLOUR_RESET}")

    return EXIT_OK

def handle_crl_upload(app: App) -> int:
    title("Upload x509 Certificate Revocation List", level=2)

    try:
        # Get or (optionally) generate a fresh CRL
        crl = app.ca.generate_crl() if getattr(app.args, "generate", False) else app.ca.get_crl()

        # Optional: still show a quick validity check result for the user
        title(f'Checking retrieved [ {COLOUR_BRIGHT}CRL Validity{COLOUR_RESET} ]', 9)
        print_result(app.ca.is_crl_valid(crl.encode('utf-8')))

        # Upload to default public store or to supplied URIs
        if not getattr(app.args, "store", None):
            title(f'Uploading CRL to [ {COLOUR_BRIGHT}Public Store{COLOUR_RESET} ]', 9)
            print_result(app.ca.upload_crl())
        else:
            for store_uri in app.args.store:
                title(f'Uploading CRL to [ {COLOUR_BRIGHT}{store_uri}{COLOUR_RESET} ]', 9)
                print_result(app.ca.upload_crl(store_uri))

        return EXIT_OK

    except (CAStorageError, CANotFoundError) as e:
        # Config/runtime issues we expect (e.g., no ca_public_store, missing CRL)
        error(str(e))
        return EXIT_FATAL
    except CAError as e:
        # Other CA-domain errors
        error(str(e))
        return EXIT_FATAL
    except Exception:
        # Anything unexpected
        log.exception("Failed to upload CRL")
        return EXIT_FATAL
