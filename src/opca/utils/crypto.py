# opca/services/crypto.py

from __future__ import annotations

import secrets
from typing import Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from opca.constants import DEFAULT_KEY_SIZE
from opca.services.ca_errors import InvalidCertificateError

#from cryptography.x509 import UniformResourceIdentifier
#from cryptography.x509.extensions import ExtensionOID, ExtensionNotFound
#from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID
#from cryptography.hazmat.primitives import hashes, serialization
#from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa, padding
#from cryptography.hazmat.primitives.serialization import Encoding, load_pem_parameters, pkcs12
#from cryptography.exceptions import InvalidSignature


def generate_dh_params(key_size=DEFAULT_KEY_SIZE['dh']):
    """
    Generate PEM formatted Diffie–Hellman parameters.
    Returns a UTF-8 PEM string.
    """
    parameters = dh.generate_parameters(
        generator=2,
        key_size=key_size,
        backend=default_backend()
    )

    dh_parameters_pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3).decode('utf-8')

    return dh_parameters_pem

def generate_ta_key(key_size=DEFAULT_KEY_SIZE['ta']):
    """
    Generate PEM formatted TLS Authentication Key parameters

    Args:
        key_size (int): Target DH Key size

    Returns:
        str

    Raises:
        None
    """
    line_length = 32

    hex_key = secrets.token_bytes(key_size // 8).hex()

    key_chunks = [hex_key[i:i + line_length] for i in range(0, len(hex_key), line_length)]

    formatted_key = "\n".join(key_chunks)

    formatted_key = f"""\
-----BEGIN OpenVPN Static key V1-----
{formatted_key}
-----END OpenVPN Static key V1-----
"""

    return formatted_key

def load_certificate_pem(pem: Union[str, bytes]) -> x509.Certificate:
    """
    Load a PEM-encoded certificate into a cryptography.x509.Certificate.

    Args:
        pem: Certificate bytes or UTF-8 string containing a PEM block.

    Returns:
        x509.Certificate

    Raises:
        InvalidCertificateError: If the data is missing, not PEM, or cannot be parsed.
    """
    if pem is None:
        raise InvalidCertificateError("No certificate data provided.")

    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    data = data.strip()

    header = b"-----BEGIN CERTIFICATE-----"
    footer = b"-----END CERTIFICATE-----"
    if header not in data or footer not in data:
        raise InvalidCertificateError("Certificate must be PEM with BEGIN/END CERTIFICATE markers.")

    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except Exception as exc:
        raise InvalidCertificateError("Failed to parse PEM certificate.") from exc

def verify_dh_params(dh_params_pem):
    """
    Verify PEM formatted Diffie-Hellman parameters

    Args:
        dh_params_pem (str): The Diffie-Hellman parameters

    Returns:
        int: Diffie-Hellman key size

    Raises:
        None
    """

    dh_params = load_pem_parameters(dh_params_pem, backend=default_backend())

    return dh_params.parameter_numbers().p.bit_length()

def verify_ta_key(ta_key_pem):
    """
    Verify PEM formatted TLS Authentication Key

    Args:
        ta_key_pem (str): The TLS Authentication Key

    Returns:
        int: TLS Authentication key size

    Raises:
        None
    """

    content = ta_key_pem.decode('utf-8').split("-----BEGIN OpenVPN Static key V1-----")[1]
    content = content.split("-----END OpenVPN Static key V1-----")[0]

    hex_string = content.replace("\n", "").strip()

    return len(hex_string) * 4



