# opca/commands/cert/actions.py

from __future__ import annotations

import logging
from typing import Dict, Iterable, List

from opca.models import App
from opca.constants import (
    DEFAULT_KEY_SIZE,
    EXIT_OK,
    EXIT_FATAL,
    COLOUR_BRIGHT,
    COLOUR_OK,
    COLOUR_ERROR,
    COLOUR_RESET,
)
from opca.utils.cli_ui import get_confirmed_password
from opca.utils.formatting import error, print_result, title
from opca.utils.files import read_bytes, write_bytes, parse_bulk_file

log = logging.getLogger(__name__)


def handle_cert_create(app: App) -> int:
    title("Create x509 Certificate", level=2)

    # Base config from the CA, then override per-cert
    base_config = app.ca.ca_certbundle.get_config().copy() # type: ignore
    base_config["key_size"] = DEFAULT_KEY_SIZE[app.args.cert_type]

    certs_to_create: List[Dict[str, object]] = []

    if getattr(app.args, "file", None):
        # Bulk mode
        for cfg in parse_bulk_file(app.args.file):
            merged = base_config.copy()
            merged.update(cfg)
            certs_to_create.append(merged)
    elif getattr(app.args, "cn", None):
        # Single CN mode
        cfg = base_config.copy()
        cfg["cn"] = app.args.cn
        if getattr(app.args, "alt", None):
            cfg["alt_dns_names"] = app.args.alt
        certs_to_create.append(cfg)
    else:
        error("You must provide either --cn or --file.", 1)

    # Create each cert (skip duplicates safely)
    for cert_info in certs_to_create:
        cn = cert_info["cn"]  # type: ignore[index]
        if app.op.item_exists(cn):
            error(f"CN {cn} already exists. Skipping.", 0)
            continue

        title(f'Generating a certificate bundle for {COLOUR_BRIGHT}{cn}{COLOUR_RESET}', 9)

        bundle = app.ca.generate_certificate_bundle( # type: ignore
            cert_type=app.args.cert_type,
            item_title=str(cn),
            config=cert_info,
        )
        print_result(bundle.is_valid())

    return EXIT_OK

def handle_cert_export(app: App) -> int:
    title("Export x509 Certificate", level=2)

    if getattr(app.args, "cn", None):
        cert_cn = app.args.cn
    elif getattr(app.args, "serial", None):
        cert_cn = app.ca.get_cert_cn_from_serial(app.args.serial)
    else:
        error(f"Must provide either --cn or --serial. Got: {app.args}", 1)

    cert_bundle = app.ca.retrieve_certbundle(cert_cn)

    if cert_bundle is None:
        error(f"Certificate bundle '{cert_cn}' not found in 1Password.", 1)

    fmt = getattr(app.args, "format", "pem").lower()

    if fmt == "pem":
        with_key   = bool(getattr(app.args, "with_key", False))
        cert_only  = bool(getattr(app.args, "cert_only", False) or not with_key)
        to_stdout  = bool(getattr(app.args, "to_stdout", False))
        cert_out   = getattr(app.args, "cert_out", None)
        key_out    = getattr(app.args, "key_out", None)

        cert_pem = cert_bundle.get_certificate(pem_format=True)
        key_pem  = cert_bundle.get_private_key() if with_key else None

        # Safety checks (avoid accidental key dump)
        if with_key and not to_stdout and not key_out and not cert_out:
            error("Refusing to print private key without explicit destination. "
                  "Use --key-out FILE or --to-stdout.", 1)
        if key_out and not with_key:
            error("--key-out requires --with-key.", 1)

        # Default to stdout when no files provided
        if to_stdout or (not cert_out and not key_out):
            if with_key and not cert_only and key_pem:
                print(cert_pem.rstrip())
                print(key_pem.rstrip())
                print()
            else:
                print(cert_pem)
            return EXIT_OK

        ok = True
        if cert_out:
            title(f"Writing certificate to [ {COLOUR_BRIGHT}{cert_out}{COLOUR_RESET} ]", 9)
            ok = ok and bool(write_bytes(cert_out, cert_pem.encode("utf-8"),
                                         overwrite=False, create_dirs=False,
                                         atomic=True, mode=0o644))
        if key_out and key_pem:
            title(f"Writing private key to [ {COLOUR_BRIGHT}{key_out}{COLOUR_RESET} ]", 9)
            ok = ok and bool(write_bytes(key_out, key_pem.encode("utf-8"),
                                         overwrite=False, create_dirs=False,
                                         atomic=True, mode=0o600))
        print_result(ok)
        return EXIT_OK if ok else EXIT_FATAL

    elif fmt == "pkcs12":
        password = None

        if app.args.p12_password:
            password = get_confirmed_password()

        try:
            p12_bytes = cert_bundle.export_pkcs12(
                password=password,
                name=cert_cn,
                include_chain=None,  # supply CA chain if/when available
            )
            out_path = write_bytes(
                app.args.outfile,
                p12_bytes,
                overwrite=False,
                create_dirs=False,
                atomic=True,
                mode=0o600,
            )
            print(
                f"Certificate and key exported as PKCS12 to "
                f"{COLOUR_BRIGHT}{out_path}{COLOUR_RESET}"
            )
        except ValueError as e:
            error(str(e), 1)
        return EXIT_OK

    # Unknown format
    error(f"Invalid export format {COLOUR_BRIGHT}{app.args.format}{COLOUR_RESET}", 99)
    return EXIT_FATAL

def handle_cert_info(app: App) -> int:
    if getattr(app.args, "cn", None):
        cert_cn = app.args.cn
        cert_serial = app.ca.get_cert_serial_from_cn(cert_cn)

    elif getattr(app.args, "serial", None):
        cert_serial = app.args.serial
        cert_cn = app.ca.get_cert_cn_from_serial(cert_serial, valid_only=False)

    else:
        error(f"Must provide either --cn or --serial. Got: {app.args}", 1)

    print(f'CA Database Entry: [ {COLOUR_BRIGHT}{cert_serial}{COLOUR_RESET} ] {cert_cn}')

    cert_bundle = app.ca.retrieve_certbundle(cert_cn)

    # Pull status & dates from the CA database so revocation is respected.
    db_row = app.ca.ca_database.query_cert(
        {"serial": cert_serial} if cert_serial else {"cn": cert_cn}
    )
    # Fallbacks in case DB row is missing fields
    db_status = (db_row or {}).get("status", "Unknown")
    db_revocation_date = (db_row or {}).get("revocation_date")
    cert_type = cert_bundle.get_type()
    cert_issuer = cert_bundle.get_certificate_attrib("issuer")
    cert_subject = cert_bundle.get_certificate_attrib("subject")
    cert_san_obj = cert_bundle.get_certificate_attrib("subject_alt_name")
    cert_expiry_date = cert_bundle.get_certificate_attrib("not_after")
    key_size = cert_bundle.get_public_key_size()
    key_type = cert_bundle.get_public_key_type()

    if db_status == "Valid":
        cert_status = f"[ {COLOUR_OK}Valid{COLOUR_RESET} ]"
    elif db_status == "Revoked":
        cert_status = f"[ {COLOUR_ERROR}Revoked{COLOUR_RESET} ]"
    elif db_status == "Expired":
        cert_status = f"[ {COLOUR_ERROR}Expired{COLOUR_RESET} ]"
    else:
        cert_status = f"[ {COLOUR_ERROR}{db_status}{COLOUR_RESET} ]"

    if cert_san_obj:
        cert_san = str(cert_san_obj)
    else:
        cert_san = "-"

    print(f'Certificate Type: {cert_type} [ {COLOUR_OK}{key_type} {key_size}-bit key{COLOUR_RESET} ]')
    print(f'Subject: {cert_subject}')
    print(f'Issuer: {cert_issuer}')
    print(f'Status: {cert_status}')
    print(f'Expiry Date: {cert_expiry_date}')
    print(f'SAN: {cert_san}')
    print(cert_bundle.get_certificate(pem_format=True))

    return EXIT_OK

def handle_cert_import(app: App) -> int:
    object_config: Dict[str, object] = {"type": "imported"}

    title("Importing a Certificate Bundle from file", 3)

    if getattr(app.args, "key_file", None):
        title(f"Private Key {COLOUR_BRIGHT}{app.args.key_file}{COLOUR_RESET}", 9)
        imported_private_key = read_bytes(app.args.key_file)  # bytes
        print_result(bool(imported_private_key))
        if imported_private_key:
            object_config["private_key"] = imported_private_key
    else:
        title("Importing without Private Key", 8)

    title(f"Certificate {COLOUR_BRIGHT}{app.args.cert_file}{COLOUR_RESET}", 9)
    imported_certificate = read_bytes(app.args.cert_file)  # bytes
    print_result(bool(imported_certificate))
    if imported_certificate:
        object_config["certificate"] = imported_certificate

    item_title = getattr(app.args, "cn", None) or None

    cert_bundle = app.ca.import_certificate_bundle(
        cert_type="imported",
        config=object_config,
        item_title=item_title,
    )

    if not item_title:
        item_title = cert_bundle.get_certificate_attrib("cn")

    item_serial = cert_bundle.get_certificate_attrib("serial")

    if app.ca.is_cert_valid(cert_bundle.certificate):
        prior_serial = app.ca.ca_database.increment_serial(
            serial_type="cert",
            serial_number=item_serial,
        )

        if prior_serial < item_serial:
            title(
                "The next available serial number is "
                f"[ {COLOUR_BRIGHT}{item_serial + 1}{COLOUR_RESET} ]",
                8,
            )

        title(
            "Storing certificate bundle for "
            f"{COLOUR_BRIGHT}{item_title}{COLOUR_RESET} in 1Password",
            9,
        )
        result = app.ca.store_certbundle(cert_bundle)
        print_result(result.returncode == 0)
    else:
        error("Certificate is not signed by this Certificate Authority", 1)

    return EXIT_OK

def handle_cert_renew(app: App) -> int:
    certs_to_renew: List[Dict[str, str]] = []

    if getattr(app.args, "cn", None):
        certs_to_renew.append({"cn": app.args.cn})
    elif getattr(app.args, "serial", None):
        certs_to_renew.append({"serial": app.args.serial})
    else:
        error(f"Must provide either --cn or --serial. Got: {app.args}", 1)

    for cert_info in certs_to_renew:
        if "cn" in cert_info:
            desc = cert_info["cn"]
        else:
            desc = f"Serial: {cert_info['serial']}"

        title(f"Renewing the certificate [ {COLOUR_BRIGHT}{desc}{COLOUR_RESET} ]:", 6)
        ok = bool(app.ca.renew_certificate_bundle(cert_info=cert_info))
        print_result(success=ok)

        if ok:
            try:
                _ = app.ca.ca_database.process_ca_database()
                app.ca.store_ca_database()
            except Exception:
                pass

    return EXIT_OK

def handle_cert_revoke(app: App) -> int:
    certs_to_revoke: List[Dict[str, str]] = []

    if getattr(app.args, "serial", None):
        certs_to_revoke.append({"serial": app.args.serial})

    if getattr(app.args, "cn", None):
        certs_to_revoke.append({"cn": app.args.cn})

    if getattr(app.args, "file", None):
        for line in read_bytes(app.args.file).decode("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            certs_to_revoke.append({"cn": line.split("--alt")[0].strip()})

    if not certs_to_revoke:
        error(f"Must provide at least one of --serial, --cn, or --file. Got: {app.args}", 1)

    any_revoked = False

    for cert_info in certs_to_revoke:
        if "cn" in cert_info:
            desc = cert_info["cn"]
        elif "serial" in cert_info:
            desc = f"Serial: {cert_info['serial']}"
        else:
            error("Certificate requires either a CN or a serial.", 1)

        title(f"Revoking the certificate [ {COLOUR_BRIGHT}{desc}{COLOUR_RESET} ]", 9)

        success = app.ca.revoke_certificate(cert_info=cert_info)
        print_result(success=bool(success))
        any_revoked = any_revoked or bool(success)

    if any_revoked:
        print(app.ca.generate_crl())

    return EXIT_OK
