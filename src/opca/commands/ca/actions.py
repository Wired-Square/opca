# opca/commands/ca/actions.py

from __future__ import annotations

import logging

from opca.constants import (
    COLOUR_BRIGHT,
    COLOUR_RESET,
    DEFAULT_KEY_SIZE,
    DEFAULT_OP_CONF,
    EXIT_OK,
    EXIT_FATAL
)
from opca.models import App
from opca.reports.ca_list import ca_list
from opca.services.ca import CertificateAuthority
from opca.services.ca_errors import CAAlreadyExistsError, CAError, CANotFoundError, CAStorageError
from opca.utils.crypto import load_certificate_pem
from opca.utils.files import read_bytes, write_bytes
from opca.utils.formatting import error, warning, print_result, title

log = logging.getLogger(__name__)

CA_CONFIG_ATTRS: tuple[str, ...] = (
    'org',
    'ou',
    'email',
    'city',
    'state',
    'country',
    'ca_url',
    'crl_url',
    'days',
    'crl_days'
)

def handle_ca_init(app: App) -> int:
    title('Initialising the Certificate Authority', 3)

    ca_config = {
        'command': 'init',
        'cn': app.args.cn,
        'ca_days': app.args.ca_days,
        'next_serial': 1,
        'next_crl_serial': 1,
        'key_size': DEFAULT_KEY_SIZE['ca']
    }

    for attr in CA_CONFIG_ATTRS:
        arg_value = getattr(app.args, attr, None)
        if arg_value:
            ca_config[attr] = arg_value

    try:
        cert_authority = CertificateAuthority(
            one_password=app.op,
            config=ca_config,
            op_config=DEFAULT_OP_CONF,
        )
        title(f'Created [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ]', 9)
        print_result(cert_authority.is_valid())
        return EXIT_OK

    except CAAlreadyExistsError as e:
        log.error(str(e))
        return EXIT_FATAL
    except CAError:
        log.exception("Failed to initialize CA")
        return EXIT_FATAL

def handle_ca_import(app: App) -> int:
    title('Importing a Certificate Authority from file', 3)

    title(f'Private Key [ {COLOUR_BRIGHT}{app.args.key_file}{COLOUR_RESET} ]', 9)
    imported_private_key = read_bytes(app.args.key_file)
    print_result(imported_private_key)

    title(f'Certificate [ {COLOUR_BRIGHT}{app.args.cert_file}{COLOUR_RESET} ]', 9)
    imported_certificate = read_bytes(app.args.cert_file)
    print_result(imported_certificate)

    if not imported_private_key or not imported_certificate:
        return EXIT_FATAL

    cert_obj = load_certificate_pem(imported_certificate)
    next_serial = app.args.serial if getattr(app.args, "serial", None) else cert_obj.serial_number + 1
    next_crl_serial = app.args.crl_serial if getattr(app.args, "crl_serial", None) else 1

    title('The next available serial number is ' + \
        f'[ {COLOUR_BRIGHT}{next_serial}{COLOUR_RESET} ]', 7)

    ca_config = {
        'command': 'import',
        'private_key': imported_private_key,
        'certificate': imported_certificate,
        'next_serial': next_serial,
        'next_crl_serial': next_crl_serial
    }

    for attr in CA_CONFIG_ATTRS:
        val = getattr(app.args, attr, None)
        if val is not None:
            ca_config[attr] = val

    try:
        ca = CertificateAuthority(
            one_password=app.op,
            config=ca_config,
            op_config=DEFAULT_OP_CONF,
        )
    except CAAlreadyExistsError as e:
        log.error(str(e))
        return EXIT_FATAL
    except CAError:
        log.exception("Failed to import CA")
        return EXIT_FATAL

    title(f'Checking [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
    print_result(app.op.item_exists(DEFAULT_OP_CONF["ca_title"]))

    title(f'Validating [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
    print_result(ca.is_valid())

    return EXIT_OK

def handle_ca_export(app: App) -> int:
    """
    Export the CA certificate (PEM) to stdout or file.
    """

    title("Certificate Authority", extra="export", level=2)

    args = app.args
    cert_out = getattr(args, "cert_out", None)
    key_out  = getattr(args, "key_out", None)
    to_stdout = bool(getattr(args, "to_stdout", False))
    with_key  = bool(getattr(args, "with_key", False))
    cert_only = bool(getattr(args, "cert_only", False) or not with_key)

    try:
        cert_pem = app.ca.get_certificate()     # str
    except CANotFoundError as e:
        error(str(e)); return EXIT_FATAL

    key_pem = None
    if with_key:
        try:
            key_pem = app.ca.get_private_key()  # str
        except CANotFoundError as e:
            error(str(e)); return EXIT_FATAL

    # Safety checks
    if with_key and not (to_stdout or key_out):
        error("Refusing to export private key without explicit destination. Use --key-out FILE or --to-stdout.")
        return EXIT_FATAL
    if key_out and not with_key:
        error("--key-out requires --with-key.")
        return EXIT_FATAL

    # Stdout path
    if to_stdout or (not cert_out and not key_out):
        if with_key and key_pem:
            print(cert_pem.rstrip())
            print(key_pem.rstrip())
            print()
        else:
            print(cert_pem, end="" if cert_pem.endswith("\n") else "\n")
        return EXIT_OK

    # Files: use atomic, permissioned writer
    if cert_out:
        ok = True
        title(f"Writing certificate to [ {cert_out} ]", 9)
        try:
            write_bytes(cert_out, cert_pem.encode("utf-8"),
                        overwrite=False, create_dirs=True, atomic=True, mode=0o644)
        except SystemExit:
            ok = False

        print_result(ok)

    if with_key and key_out and key_pem:
        ok = True
        title(f"Writing private key to [ {key_out} ]", 9)
        try:
            write_bytes(key_out, key_pem.encode("utf-8"),
                        overwrite=False, create_dirs=True, atomic=True, mode=0o600)
        except SystemExit:
            ok = False

        print_result(ok)

    return EXIT_OK if ok else EXIT_FATAL

def handle_ca_list(app: App) -> int:

    db = app.ca.ca_database

    # Update in-memory DB state and warn if it changed
    if db.process_ca_database():
        warning('The CA database was changed in memory, but not saved. Maybe you should generate a CRL more often?')


    # Select which serials to show
    rows_serials: list[int]
    report_title: str

    if getattr(app.args, "cn", None):
        try:
            rows_serials = [app.ca.get_cert_serial_from_cn(app.args.cn)]
            report_title = f"Certificate Matching CN: {app.args.cn}"
        except Exception:
            error(f"CN not found: {app.args.cn}")
            return EXIT_FATAL

    elif getattr(app.args, "serial", None) is not None:
        rows_serials = [int(app.args.serial)]
        report_title = f"Certificate Serial: {app.args.serial}"

    else:
        mode = getattr(app.args, "list_mode", "all")
        if mode == "all":
            report_title = "All CA Certificates Signed"
            rows_serials = sorted(
                db.certs_expired | db.certs_revoked | db.certs_expires_soon | db.certs_valid,
                key=int
            )
        elif mode == "expired":
            report_title = "Expired CA Certificates Signed"
            rows_serials = sorted(db.certs_expired, key=int)
        elif mode == "revoked":
            report_title = "Revoked CA Certificates Signed"
            rows_serials = sorted(db.certs_revoked, key=int)
        elif mode == "expiring":
            report_title = "Expiring CA Certificates Signed"
            rows_serials = sorted(db.certs_expires_soon, key=int)
        elif mode == "valid":
            report_title = "Valid CA Certificates Signed"
            rows_serials = sorted(db.certs_valid, key=int)
        else:
            error(f"Unknown list mode: {mode}")
            return EXIT_FATAL

    expiring_set = set(map(int, db.certs_expires_soon))
    rows: list[dict] = []

    for serial in rows_serials:
        cert = db.query_cert(cert_info={'serial': int(serial)})
        if not cert:
            continue

        status = cert["status"]
        if status == "Valid" and int(cert["serial"]) in expiring_set:
            status = "Expiring"

        rows.append({
            "serial": int(cert["serial"]),
            "cn": cert["cn"],
            "title": cert["title"],
            "status": status,                      # "Valid"|"Revoked"|"Expired"|"Expiring"
            "expiry_date": cert["expiry_date"],    # "YYYYmmddHHMMSSZ"
            "revocation_date": cert.get("revocation_date"),
        })

    return ca_list(rows, report_title=report_title)

def handle_ca_upload(app: App) -> int:

    try:
        if app.args.store is None:
            title(f'Uploading CA Certificate to [ {COLOUR_BRIGHT}Public Store{COLOUR_RESET} ]', 9)
            print_result(app.ca.upload_ca_cert())
        else:
            for store_uri in app.args.store:
                title(f'Uploading CA Certificate to [ {COLOUR_BRIGHT}{store_uri}{COLOUR_RESET} ]', 9)
                print_result(app.ca.upload_ca_cert(store_uri))
        return EXIT_OK
    except (CAStorageError, CANotFoundError) as e:
        error(str(e))
        return EXIT_FATAL
    except Exception:
        log.exception("Failed to upload CA certificate")
        return EXIT_FATAL
