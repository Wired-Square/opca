"""
#
# opca_lib/crypto.py
#

Cryptography helper functions

"""

import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

DEFAULT_KEY_SIZE = {
    'ca': 4096,
    'dh': 2048,
    'ta': 2048,
    'vpnclient': 2048,
    'vpnserver': 2048,
    'webserver': 2048
}


def generate_dh_params(key_size=DEFAULT_KEY_SIZE['dh']):
    """
    Generate PEM formatted Diffie-Hellman parameters

    Args:
        key_size (int): Target DH Key size
    
    Returns:
        str

    Raises:
        None
    """
    parameters = dh.generate_parameters(generator=2,
                                        key_size=key_size,
                                        backend=default_backend())

    dh_parameters_pem = parameters.parameter_bytes(encoding=serialization.Encoding.PEM,
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
