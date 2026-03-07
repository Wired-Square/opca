# opca/commands/csr/actions.py

from __future__ import annotations

import logging

from opca.models import App
from opca.constants import (
    DEFAULT_KEY_SIZE,
    DEFAULT_OP_CONF,
    EXIT_OK,
)
from opca.services.cert import CertificateBundle
from opca.utils.formatting import error, title, print_result
from opca.utils.files import read_bytes

log = logging.getLogger(__name__)


def handle_csr_create(app: App) -> int:
    title("Create Certificate Signing Request", level=2)

    csr_type = app.args.csr_type
    cn = app.args.cn
    email = app.args.email

    config: dict = {
        'cn': cn,
        'email': email,
        'key_size': DEFAULT_KEY_SIZE[csr_type],
    }

    # Pull country from CLI arg or CA config if available
    if getattr(app.args, 'country', None):
        config['country'] = app.args.country
    elif app.ca and app.ca.ca_certbundle:
        ca_country = app.ca.ca_certbundle.get_config('country')
        if ca_country:
            config['country'] = ca_country

    if app.op.item_exists(cn):
        log.error("Item '%s' already exists in 1Password.", cn)
        print_result(False)
        return EXIT_OK

    cert_bundle = CertificateBundle(
        cert_type=csr_type,
        item_title=cn,
        import_certbundle=False,
        config=config,
    )

    # Store private key + CSR in 1Password (no certificate)
    attributes = [
        f'{DEFAULT_OP_CONF["cert_type_item"]}={csr_type}',
        f'{DEFAULT_OP_CONF["cn_item"]}={cn}',
        f'{DEFAULT_OP_CONF["key_item"]}={cert_bundle.get_private_key()}',
        f'{DEFAULT_OP_CONF["csr_item"]}={cert_bundle.get_csr()}',
    ]

    result = app.op.store_item(
        action='create',
        item_title=cn,
        attributes=attributes,
    )
    print_result(result.returncode == 0)

    # Print CSR to stdout
    print(cert_bundle.get_csr())

    return EXIT_OK


def handle_csr_import(app: App) -> int:
    title("Import Externally Signed Certificate", level=2)

    cn = app.args.cn
    cert_file = app.args.cert_file

    if not app.op.item_exists(cn):
        error(f"No existing entry '{cn}' found in 1Password.", 1)

    cert_data = read_bytes(cert_file)
    if not cert_data:
        error(f"Could not read certificate file '{cert_file}'.", 1)

    # Try PEM first, fall back to DER
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding

    try:
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception:
        try:
            certificate = x509.load_der_x509_certificate(cert_data, default_backend())
        except Exception:
            error(f"Unable to parse '{cert_file}' as PEM or DER certificate.", 1)

    cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')

    attributes = [
        f'{DEFAULT_OP_CONF["cert_item"]}={cert_pem}',
    ]

    result = app.op.store_item(
        action='edit',
        item_title=cn,
        attributes=attributes,
    )
    print_result(result.returncode == 0)

    return EXIT_OK
