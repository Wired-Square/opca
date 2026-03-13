# opca/commands/csr/actions.py

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

from opca.models import App
from opca.constants import (
    DEFAULT_KEY_SIZE,
    DEFAULT_OP_CONF,
    EXIT_FATAL,
    EXIT_OK,
    EXIT_VALIDATION_ERROR,
)
from opca.services.cert import CertificateBundle
from opca.utils.datetime import now_utc_str
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

    op_title = f"CSR_{cn}"

    if app.op.item_exists(op_title):
        log.error("Item '%s' already exists in 1Password.", op_title)
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
        item_title=op_title,
        attributes=attributes,
    )
    print_result(result.returncode == 0)

    # Record CSR in the CA database
    if result.returncode == 0 and app.ca and app.ca.ca_database:
        subject = cert_bundle.csr.subject.rfc4514_string() if cert_bundle.csr else ''
        app.ca.ca_database.add_csr({
            'cn': cn,
            'title': op_title,
            'csr_type': csr_type,
            'email': email or '',
            'subject': subject,
            'status': 'Pending',
            'created_date': now_utc_str(),
        })
        app.ca.store_ca_database()

    # Print CSR to stdout
    print(cert_bundle.get_csr())

    return EXIT_OK


def handle_csr_import(app: App) -> int:
    title("Import Externally Signed Certificate", level=2)

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    cert_file = getattr(app.args, "cert_file", None)
    logger.debug("cert_file=%s", cert_file)

    # --- Parse the imported certificate ---
    cert_file_data = getattr(app.args, "cert_file_data", None)
    logger.debug("cert_file_data present: %s (%d bytes)",
                 cert_file_data is not None,
                 len(cert_file_data) if cert_file_data else 0)
    if cert_file_data:
        title("Reading certificate (inline data)", 9)
        cert_data = cert_file_data
    else:
        title("Reading certificate file", 9)
        cert_data = read_bytes(cert_file)
    if not cert_data:
        error(f"Could not read certificate from '{cert_file}'.", 1)

    try:
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        logger.debug("Parsed certificate as PEM")
    except Exception as pem_exc:
        logger.debug("PEM parse failed: %s", pem_exc)
        try:
            certificate = x509.load_der_x509_certificate(cert_data, default_backend())
            logger.debug("Parsed certificate as DER")
        except Exception as der_exc:
            logger.debug("DER parse failed: %s", der_exc)
            error(f"Unable to parse '{cert_file}' as PEM or DER certificate.", 1)
    print_result(True)

    # --- Determine CN from certificate or --cn override ---
    cn_override = getattr(app.args, "cn", None)
    if cn_override:
        cn = cn_override
        logger.debug("Using CN override: %s", cn)
    else:
        cn_attrs = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs:
            error("No Common Name found in certificate subject. Use --cn to specify.", 1)
        cn = cn_attrs[0].value
        logger.debug("Extracted CN from certificate: %s", cn)

    op_title = f"CSR_{cn}"
    logger.debug("Looking up 1Password item: %s", op_title)

    # --- Retrieve existing CSR item from 1Password ---
    title("Retrieving CSR from 1Password", 9)
    if not app.op.item_exists(op_title):
        error(f"No existing entry '{op_title}' found in 1Password.", 1)

    item_result = app.op.get_item(op_title)
    if item_result.returncode != 0:
        error(f"Failed to retrieve '{cn}' from 1Password.", 1)

    item_fields = {}
    loaded_object = json.loads(item_result.stdout)
    for field in loaded_object['fields']:
        label = field.get('label', '')
        value = field.get('value', '')
        if label in ('private_key', 'certificate_signing_request', 'type', 'cn'):
            item_fields[label] = value
    print_result(True)

    if 'private_key' not in item_fields:
        error(f"No private key found in '{cn}'. Cannot validate certificate.", 1)

    if 'certificate_signing_request' not in item_fields:
        error(f"No CSR found in '{cn}'. Is this a CSR item?", 1)

    csr_type = item_fields.get('type', 'external')

    # --- Validate certificate against private key ---
    title("Validating certificate against private key", 9)
    private_key_pem = item_fields['private_key'].encode('utf-8')
    csr_pem = item_fields['certificate_signing_request'].encode('utf-8')
    cert_pem = certificate.public_bytes(Encoding.PEM)

    cert_bundle = CertificateBundle(
        cert_type=csr_type,
        item_title=cn,
        import_certbundle=True,
        config={
            'private_key': private_key_pem,
            'certificate': cert_pem,
            'csr': csr_pem,
        },
    )

    # Check that the certificate's public key matches the private key
    if cert_bundle.private_key and cert_bundle.certificate:
        cert_pub = cert_bundle.certificate.public_key()
        key_pub = cert_bundle.private_key.public_key()
        if cert_pub != key_pub:
            print_result(False)
            error("Certificate public key does not match the private key from the CSR.", 1)
            return EXIT_VALIDATION_ERROR
    print_result(True)

    # --- Delete the old CSR-only item before storing the full bundle ---
    title("Removing CSR-only item from 1Password", 9)
    app.op.delete_item(item_title=op_title, archive=True)
    print_result(True)

    # --- Store as external certificate via CA service ---
    issuer_attrs = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = issuer_attrs[0].value if issuer_attrs else "Unknown"
    issuer_subject = certificate.issuer.rfc4514_string()

    title(f"Storing certificate bundle for '{cn}' as external certificate", 9)
    result = app.ca.store_certbundle(cert_bundle, issuer=issuer, issuer_subject=issuer_subject)
    print_result(result.returncode == 0)

    # --- Update CSR status in the CA database ---
    if result.returncode == 0 and app.ca.ca_database:
        app.ca.ca_database.update_csr({'cn': cn, 'status': 'Complete'})
        app.ca.store_ca_database()

    return EXIT_OK


def handle_csr_sign(app: App) -> int:
    """Sign an external CSR with the local CA and store the certificate (no private key)."""
    title("Sign Certificate Signing Request", level=2)

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding

    csr_type = getattr(app.args, 'csr_type', 'webserver')
    cn_override = getattr(app.args, 'cn', None)

    # --- Read the CSR from file or inline PEM ---
    csr_file = getattr(app.args, 'csr_file', None)
    csr_pem_str = getattr(app.args, 'csr_pem', None)

    if csr_file:
        title("Reading CSR file", 9)
        csr_data = read_bytes(csr_file)
        if not csr_data:
            error(f"Could not read CSR file '{csr_file}'.", EXIT_FATAL)
            return EXIT_FATAL
        print_result(True)
    elif csr_pem_str:
        csr_data = csr_pem_str.encode('utf-8')
    else:
        error("No CSR provided. Supply --csr-file or --csr-pem.", EXIT_VALIDATION_ERROR)
        return EXIT_VALIDATION_ERROR

    # --- Parse the CSR (PEM, fallback to DER) ---
    title("Parsing CSR", 9)
    try:
        csr = x509.load_pem_x509_csr(csr_data, default_backend())
    except Exception:
        try:
            csr = x509.load_der_x509_csr(csr_data, default_backend())
        except Exception:
            error("Unable to parse CSR as PEM or DER.", EXIT_VALIDATION_ERROR)
            return EXIT_VALIDATION_ERROR
    print_result(True)

    # --- Extract CN from the CSR subject ---
    from cryptography.x509.oid import NameOID
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    csr_cn = cn_attrs[0].value if cn_attrs else None

    cn = cn_override or csr_cn
    if not cn:
        error("CSR has no CN and no --cn override was provided.", EXIT_VALIDATION_ERROR)
        return EXIT_VALIDATION_ERROR

    # --- Sign the CSR with the CA ---
    title(f"Signing CSR for '{cn}' as {csr_type}", 9)
    signed_certificate = app.ca.sign_certificate(csr=csr, target=csr_type)
    print_result(True)

    cert_pem = signed_certificate.public_bytes(Encoding.PEM)
    csr_pem_bytes = csr.public_bytes(Encoding.PEM)

    # --- Build a CertificateBundle without a private key ---
    cert_bundle = CertificateBundle(
        cert_type=csr_type,
        item_title=cn,
        import_certbundle=True,
        config={
            'certificate': cert_pem,
            'csr': csr_pem_bytes,
        },
    )

    # --- Store the certificate in 1Password + CA database ---
    title(f"Storing signed certificate for '{cn}'", 9)
    result = app.ca.store_certbundle(cert_bundle)
    print_result(result.returncode == 0)

    if result.returncode != 0:
        error("Failed to store signed certificate.", EXIT_FATAL)
        return EXIT_FATAL

    # Print the signed certificate PEM
    print(cert_pem.decode('utf-8'))

    return EXIT_OK
