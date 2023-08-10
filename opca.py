#!/usr/bin/env python3
"""
#
# opca.py - 1Password Certificate Authority
#

A Python certificate authority implementation that uses pyca/cryptography (https://cryptography.io)
to generate keys and sign certificates, and then store them in 1Password.

The design contraints are
  - Keep this program as a single file (So we can store it easily in 1Password)

  - Limit the dependendies.
    - 1Password CLI
    - Python 3
    - Python Cryptography Library

  - Store no sensitive data on disk. Ever. 

This version of 1Password Certificate Authority represents a minimum viable product, but there are other features
that need to be implemented to be properly useful

- CA certificate and key renewal
- Regular certificate and key renewal
- Generate a CRL
- Store the default certificate config in 1Password
- Implement private key passphrases
"""

import argparse
import datetime
import re
import os
import shutil
import secrets
import subprocess
import sys
from cryptography import x509
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

# Configuration
quiet_output = False
OPCA_DEBUG = False
OP_BIN = 'op'

# ANSI color codes for formatting text
COLOUR = {
'black': '\033[0;30m',
'red': '\033[0;31m',
'green': '\033[0;32m',
'yellow': '\033[0;33m',
'blue': '\033[0;34m',
'magenta': '\033[0;35m',
'cyan': '\033[0;36m',
'white': '\033[0;37m',
'bold_black': '\033[1;30m',
'bold_red': '\033[1;31m',
'bold_green': '\033[1;32m',
'bold_yellow': '\033[1;33m',
'bold_blue': '\033[1;34m',
'bold_magenta': '\033[1;35m',
'bold_cyan': '\033[1;36m',
'bold_white': '\033[1;37m',
'underline_black': '\033[4;30m',
'underline_red': '\033[4;31m',
'underline_green': '\033[4;32m',
'underline_yellow': '\033[4;33m',
'underline_blue': '\033[4;34m',
'underline_magenta': '\033[4;35m',
'underline_cyan': '\033[4;36m',
'underline_white': '\033[4;37m',
'reset': '\033[0m'
}

BG_COLOUR = {
'black': '\033[40m',
'red': '\033[41m',
'green': '\033[42m',
'yellow': '\033[43m',
'blue': '\033[44m',
'magenta': '\033[45m',
'cyan': '\033[46m',
'white': '\033[47m',
'reset': '\033[0m'
}

# Constants
OPCA_VERSION       = "0.8"
OPCA_TITLE         = "1Password Certificate Authority"
OPCA_SHORT_TITLE   = "OPCA"
OPCA_AUTHOR        = "Alex Ferrara <alex@wiredsquare.com>"
OPCA_LICENSE       = "mit"
OPCA_STATUS_COLUMN = 90
OPCA_COLOUR_H      = [
    COLOUR['bold_yellow'],
    COLOUR['bold_yellow'],
    COLOUR['bold_white'],
    COLOUR['underline_white']
]
OPCA_COLOUR_ERROR  = COLOUR['bold_red']
OPCA_COLOUR_OK     = COLOUR['green']
OPCA_COLOUR_BRIGHT = COLOUR['bold_white']

# TODO: This should be stored in 1Password so it can be vault specific
DEFAULT_CERT_CONF = {
    'org': 'Example Organisation',
    'email': 'admin@organisation.com.au',
    'city': 'Canberra',
    'state': 'ACT',
    'country': 'AU',
    'days': 365
}
DEFAULT_OP_CONF = {
    'category': 'Secure Note',
    'ca_title': 'CA',
    'cn_item': 'cn[text]',
    'key_item': 'private_key',
    'key_size_item': 'key_size[text]',
    'cert_item': 'certificate',
    'cert_type_item': 'type[text]',
    'ca_cert_item': 'ca_certificate',
    'csr_item': 'certificate_signing_request',
    'start_date_item': 'not_before[text]',
    'expiry_date_item': 'not_after[text]',
    'serial_item': 'serial[text]',
    'next_serial_item': 'next_serial[text]',
    'dh_item': 'diffie-hellman.dh_parameters',
    'dh_key_size_item': 'diffie-hellman.key_size[text]',
    'ta_item': 'tls_authentication.static_key',
    'ta_key_size_item': 'tls_authentication.key_size[text]',
    'openvpn_item': 'OpenVPN'
}
DEFAULT_KEY_SIZE = {
    'ca': 4096,
    'dh': 2048,
    'ta': 2048,
    'client': 2048,
    'server': 2048,
    'vpnclient': 2048,
    'vpnserver': 2048,
    'webserver': 2048
}


def error(error_msg, exit_code):
    """
    Prints an error message with custom formatting.

    Args:
        error_msg (str): The error message to be displayed.
        exit_code (str): The exist code to give

    Returns:
        None
    
    Raises:
        None
    """

    error_colour = OPCA_COLOUR_ERROR
    reset = COLOUR['reset']

    print(f'{error_colour}Error:{reset} {error_msg}')
    sys.exit(exit_code)

def find_executable(file):
    """
    Searches the path for an executable.

    Args:
        file (str): Filename of the executable

    Returns:
        str: The full path to the executable if it is found

    Raises:
        None
    """
    return shutil.which(file)

def format_openvpn_static_key(hex_key, line_length=32):
    """
    Formats a TLS Authentication Static Key to the same format as OpenVPN

    Args:
        hex_key(str): The actual key consisting of random numbers
        line_length(str): The maximum line length

    Returns:
        None
    
    Raises:
        None
    """

    key_chunks = [hex_key[i:i + line_length] for i in range(0, len(hex_key), line_length)]

    formatted_key = "\n".join(key_chunks)

    formatted_key = f"""\
-----BEGIN OpenVPN Static key V1-----
{formatted_key}
-----END OpenVPN Static key V1-----
"""

    return formatted_key

def handle_ca_action(action, args):
    """
    Handle CA Actions called from the selection

    Args:
        action (stf): Desired action
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title(f'Certificate Authority', extra=action, level=2)

    op = Op(bin=OP_BIN, account=args.account, vault=args.vault)

    if action == 'init-ca':
        handle_ca_init_ca(op, args)

    elif action == 'import-ca':
        handle_ca_import_ca(op, args)

    elif action == 'get-ca-cert':
        handle_ca_get_ca_cert(op, args)

    elif action == 'create-cert':
        handle_ca_create_cert(op, args)

    elif action == 'get-csr':
        handle_ca_get_csr()

    else:
        error('This feature is not yet written', 99)

def handle_ca_create_cert(op, args):
    """
    Create a new CertificateBundle object with a generated key
    and self-signed certificate

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    if op.item_exists(args.cn):
        error(f'CN {args.cn} already exists. Aborting', 1)

    config = DEFAULT_CERT_CONF
    config['cn'] = args.cn

    ca = import_certificate_bundle_from_op(op, item_title=DEFAULT_OP_CONF["ca_title"], ca=True)

    title(f'Generating a certificate bundle for {OPCA_COLOUR_BRIGHT}{args.cn}{COLOUR["reset"]}', 9)
    new_certificate_bundle = CertificateBundle(type=args.cert_type, title=args.cn, bundle_import=False, config=DEFAULT_CERT_CONF)

    pem_csr = new_certificate_bundle.get_csr().encode('utf-8')
    csr = x509.load_pem_x509_csr(pem_csr, default_backend())

    signed_certificate = ca.sign_certificate(csr=csr, target=args.cert_type)

    new_certificate_bundle.update_certificate(signed_certificate)
    print_result(new_certificate_bundle.is_valid())

    if new_certificate_bundle.is_valid():
        title(f'Storing certificate bundle for {OPCA_COLOUR_BRIGHT}{args.cn}{COLOUR["reset"]} in 1Password', 9)
        result = op.store_cert_bundle(new_certificate_bundle)
        print_cmd_result(result.returncode)
    else:
        error('Private key and Certificate do not match', 1)
    
    title(f'Storing CA next serial number in 1Password', 9)
    result = op.store_item(title=DEFAULT_OP_CONF["ca_title"], action='edit',
                    attributes=[f'{DEFAULT_OP_CONF["next_serial_item"]}={ca.get_next_serial()}'])
    print_cmd_result(result.returncode)

def handle_ca_get_ca_cert(op, args):
    """
    Retreive the CA certificate and print it to the console

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """
    ca = import_certificate_bundle_from_op(op, DEFAULT_OP_CONF["ca_title"], ca=True)

    print(ca.get_certificate())

def handle_ca_get_csr(op, args):
    error('This feature is scheduled, but not written yet', 99)

def handle_ca_init_ca(op, args):
    """
    Initialise the Certificate Authority object in 1Password
    through generating the contents

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    if op.ca_exists:
        error('Certificate Authority already exists. Aborting.', 1)

    title('Initialising the Certificate Authority', 3)

    next_serial = 1

    title(f'Next serial number is {OPCA_COLOUR_BRIGHT}{next_serial}{COLOUR["reset"]}', 8)

    object_config = DEFAULT_CERT_CONF
    object_config['cn'] = args.cn
    object_config['next_serial'] = next_serial

    ca = CertificateBundle(type='ca', title=DEFAULT_OP_CONF['ca_title'], bundle_import=False, config=object_config)

    title('Storing the Certificate Bundle in 1Password', 9)
    result = op.store_cert_bundle(ca)
    print_cmd_result(result.returncode)

def handle_ca_import_ca(op, args):
    """
    Initialise the Certificate Authority object in 1Password
    by importing a PEM encoded private key and x509 certificate.

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """
    if op.ca_exists:
        error('Certificate Authority already exists. Aborting.', 1)

    title('Importing a Certificate Authority from file', 3)

    title(f'Private Key {OPCA_COLOUR_BRIGHT}{args.key_file}{COLOUR["reset"]}', 9)
    imported_private_key = read_file(args.key_file)
    print_result(not is_empty(imported_private_key))

    title(f'Certificate {OPCA_COLOUR_BRIGHT}{args.cert_file}{COLOUR["reset"]}', 9)
    imported_certificate = read_file(args.cert_file)
    print_result(not is_empty(imported_certificate))

    if args.serial:
        next_serial = args.serial
    else:
        next_serial = 1

    ca = import_certificate_bundle(private_key=imported_private_key,
                                    certificate=imported_certificate,
                                    next_serial=next_serial, ca=True)

    if ca.is_valid():
        title(f'Storing certificate bundle for {OPCA_COLOUR_BRIGHT}CA{COLOUR["reset"]} in 1Password', 9)
        result = op.store_cert_bundle(ca)
        print_cmd_result(result.returncode)
    else:
        error('Private key and Certificate do not match', 1)

def handle_openvpn_action(action, args):
    """
    Handle OpenVPN Actions called from the selection

    Args:
        action (stf): Desired action
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title(f'OpenVPN', extra=action, level=2)

    op = Op(bin=OP_BIN, account=args.account, vault=args.vault)

    if action == 'gen-dh':
        handle_openvpn_gen_dh(op, args)

    elif action == 'get-dh':
        handle_openvpn_get_dh(op, args)

    elif action == 'gen-ta-key':
        handle_openvpn_gen_ta_key(op, args)

    elif action == 'gen-vpn-profile':
        handle_openvpn_gen_vpn_profile(op, args)

    elif action == 'gen-sample-vpn-server':
        handle_openvpn_gen_sample_vpn_server(op, args)

    else:
        error('This feature is not yet written', 99)

def handle_openvpn_gen_dh(op, args):
    """
    Create the Diffie-Hellman parameters and store them in 1Password

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('Generate the DH Parameters', 3)

    parameters = dh.generate_parameters(generator=2, key_size=DEFAULT_KEY_SIZE["dh"], backend=default_backend())

    dh_parameters_pem = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3).decode('utf-8')

    title('Storing the DH parameters in 1Password', 9)
    attributes = [f'{DEFAULT_OP_CONF["dh_item"]}={dh_parameters_pem}',
                f'{DEFAULT_OP_CONF["dh_key_size_item"]}={DEFAULT_KEY_SIZE["dh"]}'
                ]

    result = op.edit_or_create(title=DEFAULT_OP_CONF["openvpn_item"],
                        attributes=attributes)

    print_cmd_result(result.returncode)

def handle_openvpn_get_dh(op, args):
    """
    TITLE

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """
    
    url = f'op://{args.vault}/{DEFAULT_OP_CONF["openvpn_item"]}/{DEFAULT_OP_CONF["dh_item"].replace(".", "/")}' 

    title(f'Reading the [ {OPCA_COLOUR_BRIGHT}{url}{COLOUR["reset"]} ] from 1Password', 9)

    result = op.read_item(url)
    print_cmd_result(result.returncode)

    if result.returncode == 0:
        print(result.stdout)

def handle_openvpn_gen_ta_key(op, args):
    """
    Generate the TLS Authentication Static Key

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('Generate the OpenVPN TLS Authentication Key', 3)

    parameters = dh.generate_parameters(generator=2, key_size=DEFAULT_KEY_SIZE["dh"], backend=default_backend())

    dh_parameters_pem = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3).decode('utf-8')

    ta_key = secrets.token_bytes(DEFAULT_KEY_SIZE["ta"] // 8).hex()

    formatted_ta_key = format_openvpn_static_key(ta_key)

    title('Storing the TLS Authentication Key in 1Password', 9)
    attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={formatted_ta_key}',
                f'{DEFAULT_OP_CONF["ta_key_size_item"]}={DEFAULT_KEY_SIZE["ta"]}'
                ]

    result = op.edit_or_create(title=DEFAULT_OP_CONF["openvpn_item"],
                        attributes=attributes)

    print_cmd_result(result.returncode)

def handle_openvpn_gen_vpn_profile(op, args):
    """
    Generate a OpenVPN profile from a template stored in 1Password,
    then save the profile to 1Password as a document

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    env_vars = os.environ.copy()
    env_vars['USER'] = args.cn

    title(f'Reading VPN profile [ {OPCA_COLOUR_BRIGHT}{args.template}{COLOUR["reset"]} ] from 1Password', 9)
    result = op.read_item(f'op://{args.vault}/{DEFAULT_OP_CONF["openvpn_item"]}/template/{args.template}')
    print_cmd_result(result.returncode)

    if result.returncode == 0:
        ovpn_template = result.stdout
    else:
        error(result.stderr, result.returncode)

    title(f'Generating VPN profile for [ {OPCA_COLOUR_BRIGHT}{args.cn}{COLOUR["reset"]} ]', 9)
    result = op.inject_item(env_vars=env_vars, template=ovpn_template)
    print_cmd_result(result.returncode)

    if result.returncode != 0:
        error(result.stderr, result.returncode)

    title(f'Storing VPN profile in 1Password', 9)
    op.store_document(action='create', title=f'VPN_{args.cn}', filename=f'{args.cn}-{args.template}.ovpn', str_in=result.stdout)
    print_cmd_result(result.returncode)

def handle_openvpn_gen_sample_vpn_server(op, args):
    """
    Generate the boilerplate sample OpenVPN server object in 1Password

    Args:
        op (OpObject): An initialised 1Password object
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title(f'Storing the sample OpenVPN configuration template', 9)

    attributes = [f'server.hostname[text]=vpn.domain.com.au',
                f'server.port[text]=1194',
                f'server.ta_key=',
                f'''template.sample[text]=#
# Client - {{{{ op://{args.vault}/$USER/cn }}}}
#

# Brought to you by Wired Square - www.wiredsquare.com

client
dev tun
proto udp
remote {{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_item"]}/server/hostname }}}} {{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_item"]}/server/port }}}}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-256-gcm
auth sha256
verb 3
key-direction 1
mssfix 1300
<ca>
{{{{ op://{args.vault}/{DEFAULT_OP_CONF["ca_title"]}/{DEFAULT_OP_CONF["cert_item"]} }}}}
</ca>
<cert>
{{{{ op://{args.vault}/$USER/{DEFAULT_OP_CONF["cert_item"]} }}}}
</cert>
<key>
{{{{ op://{args.vault}/$USER/{DEFAULT_OP_CONF["key_item"]} }}}}
</key>
<tls-auth>
{{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_item"]}/{DEFAULT_OP_CONF["ta_item"].replace(".", "/")} }}}}
</tls-auth>
''']

    result = op.store_item(title=DEFAULT_OP_CONF["openvpn_item"], action='create', attributes=attributes)

    print_cmd_result(result.returncode)

def handle_manage_action(action, args):
    """
    Handle Management Actions called from the selection

    Args:
        action (stf): Desired action
        args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title(f'Management', extra=action, level=2)

    op = Op(bin=OP_BIN, account=args.account, vault=None)

    if action == 'test':
        title('Test the system dependencies', level=3)

        print(f'1Password CLI - {OPCA_COLOUR_BRIGHT}{OP_BIN}{COLOUR["reset"]}', end='')
        result = is_file_executable(OP_BIN)
        print_result(result)

        bin_file = find_executable(OP_BIN)
        print(f'1Password CLI in path - {OPCA_COLOUR_BRIGHT}{bin_file}{COLOUR["reset"]}', end='')
        result = is_file_executable(bin_file)
        print_result(result)

    elif action == 'whoami':

        title('Get the current user', 9)
        result = op.whoami()
        print_cmd_result(result.returncode)

        print(result.stdout)

        title('Retrieve the current user details', 9)
        result = op.get_current_user_details()
        print_cmd_result(result.returncode)

        print(result.stdout)
    else:
        error('This feature is not yet written', 99)

def import_certificate_bundle(private_key, certificate, next_serial=None, ca=False):
    """
    Imports a certificate bundle from variables

    Args:
        private_key (str): Private Key
        certificate (str): x509 certificate
        next_serial (str): x509 certificate serial number
        ca (bool): Is the certificate bundle a CA?

    Returns:
        None

    Raises:
        None
    """

    object_config = DEFAULT_CERT_CONF
    object_config['private_key'] = private_key
    object_config['certificate'] = certificate

    if ca:
        object_config['next_serial'] = next_serial

        title(f'The next available serial number is [ {OPCA_COLOUR_BRIGHT}{next_serial}{COLOUR["reset"]} ]', 7)

    obj = CertificateBundle(type='ca', title=DEFAULT_OP_CONF['ca_title'], bundle_import=True)

    title(f'Checking certificate bundle', 9)
    print_result(obj.is_valid())

    return obj

def import_certificate_bundle_from_op(op, item_title, ca=False):
    """
    Imports a certificate bundle from 1Password

    Args:
        op (OpObject): An initialised 1Password object
        op_url (str): The 1Password secrets URL of the item
        ca (bool): Is the certificate bundle a CA?

    Returns:
        None

    Raises:
        None
    """

    loaded_next_serial = None

    if not op.ca_exists:
        error(f'CA does not exist. Have you considered using {OPCA_COLOUR_BRIGHT}init-ca or import-ca{COLOUR["reset"]}', 1)

    if ca:
        object_desc = 'Certificate Authority'
    else:
        object_desc = 'Regular Certificate'
    
    title(f'Importing a {object_desc}', 3)

    item_url = op.mk_url(item_title=item_title, value_key=DEFAULT_OP_CONF["key_item"])

    title(f'Loading {OPCA_COLOUR_BRIGHT}{item_url}{COLOUR["reset"]} from 1Password', 9)
    result = op.read_item(item_url)
    loaded_private_key = result.stdout.encode('utf-8')
    print_cmd_result(result.returncode)

    item_url = op.mk_url(item_title=item_title, value_key=DEFAULT_OP_CONF["cert_item"])

    title(f'Loading {OPCA_COLOUR_BRIGHT}{item_url}{COLOUR["reset"]} from 1Password', 9)
    result = op.read_item(item_url)
    loaded_certificate = result.stdout.encode('utf-8')
    print_cmd_result(result.returncode)
    
    if ca:
        item_url = op.mk_url(item_title=item_title, value_key=strip_op_type(DEFAULT_OP_CONF["next_serial_item"]))

        title(f'Loading {OPCA_COLOUR_BRIGHT}{item_url}{COLOUR["reset"]} from 1Password', 9)
        result = op.read_item(item_url)
        loaded_next_serial = result.stdout.replace('\n', '')
        print_cmd_result(result.returncode)

    return import_certificate_bundle(private_key=loaded_private_key,
                                     certificate=loaded_certificate,
                                     next_serial=loaded_next_serial,
                                     ca=ca)

def is_empty(var):
    """
    Checks if the variable is empty

    Args:
        var (str): The variable to check

    Returns:
        bool: True if the variable is empty

    Raises:
        None
    """

    if not var:
        return True
    else:
        return False

def is_file_executable(file_path):
    """
    Checks if the file at the specified path is executable.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file is executable, False otherwise.

    Raises:
        None
    """
    return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

def parse_arguments(description):
    """
    Parses the arguments given at the command line

    Args:
        description (str): Progam description

    Returns:
        argparse.Namespace: Description of the return value.

    Raises:
        None
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-a', '--account', required=True, help='1Password Account. Example: company.1password.com')

    subparsers = parser.add_subparsers(title='Commands', dest='selection', required=True)

    subparser_ca = subparsers.add_parser('ca', help='Perform Certificate Authority actions')
    subparser_ca.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_ca_actions = subparser_ca.add_subparsers(title='Actions', dest='action', required=True)

    subparser_action_init_ca = subparser_ca_actions.add_parser('init-ca', help='Initialise a 1Password Certificate Authority')
    subparser_action_init_ca.add_argument('-n', '--cn', required=True,
            help='x509 CN attribute for the 1Password Certificate Authority.')

    subparser_action_import_ca = subparser_ca_actions.add_parser('import-ca', help='Import a 1Password Certificate Authority from file')
    subparser_action_import_ca.add_argument('-c', '--cert-file', required=True, help='Certificate file')
    subparser_action_import_ca.add_argument('-k', '--key-file', required=True, help='Private Key file')
    subparser_action_import_ca.add_argument('-s', '--serial', required=False, help='Certificate serial number. If we are importing a CA, it is the next serial number')

    subparser_action_import_ca = subparser_ca_actions.add_parser('get-ca-cert', help='Get the object CA Certificate')

    subparser_action_get_csr = subparser_ca_actions.add_parser('get-csr', help='Get the CertificateBundle object Certificate Signing Request')

    #subparser_action_gen_crl = subparser_ca_actions.add_parser('gen-crl', help='Generate a Certificate Revokation List for the 1Password CA')
    #subparser_action_get_crl = subparser_ca_actions.add_parser('gen-crl', help='Generate a Certificate Revokation List for the 1Password CA')

    subparser_action_create_cert = subparser_ca_actions.add_parser('create-cert', help='Create a new x509 CertificateBundle object')
    subparser_action_create_cert.add_argument('-t', '--cert-type', required=True,
            help='x509 Certificate type', choices=['vpnserver', 'vpnclient', 'webserver'])
    subparser_action_create_cert.add_argument('-s', '--serial', required=False,
            help='Certificate serial number. If we are importing a CA, it is the next serial number')
    subparser_action_create_cert.add_argument('-n', '--cn', required=False,
            help='CN attribute. Regular certificates use this for the 1Password title.')
    subparser_action_create_cert.add_argument('-a', '--alt', nargs='+', required=False,
            help='Alternate CN.')

    #action_import_ca = subparser_ca_actions.add_parser('renew-cert', help='Renew a x509 certificate')

    subparser_openvpn = subparsers.add_parser('openvpn', help='Perform OpenVPN actions')
    subparser_openvpn.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_openvpn_actions = subparser_openvpn.add_subparsers(title='Actions', dest='action', required=True)

    subparser_action_gen_dh = subparser_openvpn_actions.add_parser('gen-dh', help='Generate Diffie-Hellman parameters')

    subparser_action_get_dh = subparser_openvpn_actions.add_parser('get-dh', help='Retrieve Diffie-Hellman parameters from 1Password')

    subparser_action_gen_ta_key = subparser_openvpn_actions.add_parser('gen-ta-key', help='Generate TLS Authentication Static Key')

    subparser_action_gen_vpn_profile = subparser_openvpn_actions.add_parser('gen-vpn-profile', help='Generate VPN profile from template')
    subparser_action_gen_vpn_profile.add_argument('-n', '--cn', required=True, help='The certificate CN. This is also the 1Password title.')
    subparser_action_gen_vpn_profile.add_argument('-t', '--template', required=True, help='OpenVPN template stored in 1Password')

    subparser_action_gen_sample_vpn_server = subparser_openvpn_actions.add_parser('gen-sample-vpn-server', help='Generate a sample OpenVPN object in 1Password')

    subparser_manage = subparsers.add_parser('manage', help='Perform management actions')
    subparser_manage_actions = subparser_manage.add_subparsers(title='Actions', dest='action', required=True)

    subparser_action_whoami = subparser_manage_actions.add_parser('test', help='Run pre-flight checks')
    subparser_action_whoami = subparser_manage_actions.add_parser('whoami', help='Find out about the current 1Password user')

    return parser.parse_args()

def print_cmd_result(returncode, ok_msg='  OK  ', failed_msg='FAILED'):
    """
    Prints a ANSI success or failure message in a RedHat theme

    Args:
        returncode (int): Return code from subprocess. 0 = success
        ok_msg (str): OK message text
        failed_msg (str): Failed message text
    
    Returns:
        None

    Raises:
        None
    """

    if returncode == 0:
        success = True
    else:
        success = False

    if not quiet_output:
        print_result(success, ok_msg, failed_msg)

def print_result(success, ok_msg='  OK  ', failed_msg='FAILED'):
    """
    Prints a ANSI success or failure message in a RedHat theme

    Args:
        success (bool): Success test condition
        ok_msg (str): OK message text
        failed_msg (str): Failed message text
    
    Returns:
        None

    Raises:
        None
    """

    column = f'\033[{OPCA_STATUS_COLUMN}G'

    if success:
        msg = ok_msg
        msg_colour = OPCA_COLOUR_OK
    else:
        msg = failed_msg
        msg_colour = OPCA_COLOUR_ERROR

    if not quiet_output:
        print(f'{column}[ {msg_colour}{msg}{COLOUR["reset"]} ]')

def read_file(file_path):
    """
    Read the contents of a file

    Args:
        file_path (str): The file to be read

    Returns:
        bytes: The contents of the file

    Raises:
        None
    """

    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        error(f"File '{file_path}' not found.", 1)
    except PermissionError:
        error(f"Permission denied for file '{file_path}'.", 1)
    except IOError as e:
        error(f"I/O error occurred while reading file '{file_path}': {e}", 1)
    except Exception as e:
        error(f"An unexpected error occurred: {e}", 1)

def run_command(command, text=True, shell=False, stdin=None, str_in=None, env_vars=None):
    """
    Run a command and capture the output

    Args:
        command (list of strings): The command to execute
        text (bool): Subprocess text variable passed directly
        shell (bool): Subprocess shell variable passed directly
        stdin () Subprocess stdin variable passed directly
        str_in (str): Subprocess input variable passed directly
        env_vars ():Subprocess env_vars variable passed directly

    Returns:
        subprocess.CompletedProcess: The captured output
    
    Raises:
        None
    """

    try:
        result = subprocess.run(command, env=env_vars, stdin=stdin, input=str_in, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text, shell=shell)

        return result

    except FileNotFoundError:
        error(f'Command not found. Does { command[0] }it exist?', 1)
        sys.exit(1)

def strip_op_type(text):
    """
    Strips the 1Password item types encapsulated by square brackets

    Args:
        text (str): The 1Password value key to strip

    Returns:
        str: A 1Password value key stripped of type

    Raises:
        None
    """

    pattern = r"\[.*?\]"
    result = re.sub(pattern, "", text)
    return result

def title(text, level=1, extra=None):
    """
    Prints a title in a consistant format

    Args:
        text (str): The text to be displayed
        level (int):  The level of heading (optional)
    
    Returns:
        None

    Raises:
        None
    """
    
    if 1 <= level <= 3:
        title_colour = OPCA_COLOUR_H[level-1]
    else:
        title_colour = COLOUR['cyan']

    highlight_colour = OPCA_COLOUR_BRIGHT
    reset = COLOUR['reset']

    if not quiet_output:
        if level == 1:
            if extra is None:
                extra = '---===oooO'
            print(f'{extra} {title_colour}{text}{reset} {extra[::-1]}\n')
        elif level == 2:
            if extra is not None:
                print(f'{title_colour}{text}{reset} [ {highlight_colour}{extra}{reset} ]\n')
            else:
                print(f'{title_colour}{text}{reset}\n')
        elif level == 3:
            print(f'{title_colour}{text}{reset}\n')
        elif level == 7:
            print(f'{text}')
        elif level == 8:
            print(f'{text}...')
        elif level == 9:
            print(f'{text}...', end='')
        else:
            print(f'{title_colour}{text}{reset}\n')


class CertificateBundle:
    def __init__(self, type, title, bundle_import, key_size=DEFAULT_KEY_SIZE, config=DEFAULT_CERT_CONF):
        """
        CertificateBundle - A class for dealing with x509 certificate items

        Args:
            type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            title (str): The name to object will be stored as in 1Password
            ca_cert (str): PEM formatted x509 certificate of the signing CA to import
            cert (str): PEM formatted x509 certificate of this object to import
            private_key (str): PEM formatted private key to import
            key_size (dict): A dictionary of private key sizes keyed to the certificate type
            config (dict): A dictionary of certificate configuration items
        """

        self.type = type
        self.title = title
        self.key_size = key_size[self.type]
        self.config = config

        self.ca_certificate = None
        self.certificate = None
        self.csr = None
        self.private_key = None
        self.private_key_passphrase = None # TODO: Implement private key passphrase

        self.initialised = False

        if self.type == 'ca':
            self.next_serial = int(self.config['next_serial'])

        if bundle_import:
            # Import
            self.import_private_key(self.config['private_key'], self.private_key_passphrase)
            self.import_certificate(self.config['certificate'])

        else:
            # Generate
            self.private_key = self.generate_private_key()
            self.csr = self.generate_csr(private_key=self.private_key, cn=self.config['cn'])
            self.certificate = self.sign_certificate(self.csr, self.private_key, self.csr)

        self.initialised = True

    def format_datetime(self, date, timezone='UTC'):
        """
        Format a datetime to match OpenSSL text

        Args:
            date (datetime): The datetime object we are working with
            timezone (str):  The timezone we are working with
        
        Returns:
            str

        Raises:
            None
        """
        format_string = f'%b %d %H:%M:%S %Y {timezone}'

        return date.strftime(format_string)
                        
    def generate_csr(self, cn, private_key):
        """
        Generate a certificate signing request for the current Certificate Bundle

        Args:
            cn (str): The CN to use for the CSR
            private_key (str):  The private key to use in creating a CSR
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest

        Raises:
            None
        """

        x509_attributes = [x509.NameAttribute(x509.NameOID.COMMON_NAME, cn),
                        x509.NameAttribute(NameOID.COUNTRY_NAME, self.config['country']),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config['state']),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, self.config['city']),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config['org'])
        ]

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(x509_attributes
        )).sign(private_key, hashes.SHA256(), default_backend())

        return csr

    def generate_private_key(self):
        """
        Generate and returns the RSA private key for the certificate bundle

        Args:
            None
        
        Returns:
            cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey

        Raises:
            None
        """
        public_exponent = 65537
        backend = default_backend()

        private_key = rsa.generate_private_key(
            public_exponent = public_exponent,
            key_size = self.key_size,
            backend = backend
        )

        return private_key

    def get_ca_cert(self):
        """
        Returns a PEM encoded CA certificate for the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def get_csr(self):
        """
        Returns a PEM encoded certificate signing request for the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def get_certificate(self):
        """
        Returns the PEM encoded certificate of the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def get_certificate_cn(self):
        """
        Returns the common name of the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        attribute = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

        return attribute[0].value

    def get_certificate_start(self):
        """
        Returns the validity start datetime for the certificate bundle certificate

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.format_datetime(self.certificate.not_valid_before)

    def get_certificate_expiry(self):
        """
        Returns the validity expiry datetime for the certificate bundle certificate

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.format_datetime(self.certificate.not_valid_after)

    def get_certificate_issuer(self):
        """
        Returns the issuer of the certificate bundle certificate

        Args:
            None
        
        Returns:
            None

        Raises:
            None
        """
        return self.certificate.issuer

    def get_certificate_serial(self):
        """
        Returns the serial number of the certificate bundle certificate

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.certificate.serial_number

    def get_certificate_subject(self):
        """
        Returns the subject of the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.certificate.subject.rfc4514_string()

    def get_certificate_version(self):
        """
        Returns the version of the certificate bundle

        Args:
            None
        
        Returns:
            int

        Raises:
            None
        """
        return self.certificate.version

    def get_next_serial(self):
        """
        This is used in a CA to identify certificates that have been signed by the CA. In OPCA
        a CA object stores the next available certificate number for signing.

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        if self.is_ca_certificate():
            return self.next_serial
        else:
            return None

    def get_private_key(self):
        """
        Returns a PEM encoded private key for the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.private_key.private_bytes(
            Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        ).decode('utf-8')

    def get_title(self):
        """
        Returns the title of the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.title          

    def get_type(self):
        """
        Returns the certificate bundle type

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.type

    def get_certificate_basic_constraints(self):
        """
        Returns the basic constrints of the certificate bundle

        Args:
            None
        
        Returns:
            cryptography.x509.extensions.Extension

        Raises:
            None
        """
        return self.certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)

    def import_certificate(self, certificate):
        """
        Imports a PEM encoded x509 certificate into the certificate bundle

        Args:
            certificate (str): PEM encoded x509 certificate
        
        Returns:
            None

        Raises:
            None
        """
        self.certificate = x509.load_pem_x509_certificate(certificate, default_backend())

    def import_private_key(self, private_key, passphrase=None):
        """
        Imports a PEM encoded RSA private key into the certificate bundle

        Args:
            private_key (str): PEM encoded RSA private key
        
        Returns:
            None

        Raises:
            None
        """
        self.private_key = serialization.load_pem_private_key(private_key, passphrase)

    def is_ca_certificate(self):
        """
        Returns True if the x509 certificate of the certificate bundle is a CA

        Args:
            None
        
        Returns:
            bool

        Raises:
            None
        """
        return self.get_certificate_basic_constraints().value.ca

    def is_valid(self):
        """
        Returns true if the certificate budle private key and certificate are consistent

        Args:
            None
        
        Returns:
            bool

        Raises:
            None
        """
        valid = False

        # Does the private key match the certificate?
        if self.private_key.public_key() == self.certificate.public_key():
            # CA Status
            if (self.type == 'ca' and self.is_ca_certificate()) or (self.type != 'ca' and not self.is_ca_certificate()):
                valid = True

        return valid

    def sign_certificate(self, csr, ca_private_key=None, ca_certificate=None, target=None):
        """
        Sign a csr to create a x509 certificate.

        Args:
            csr (cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest): Certificate Signing Request
            ca_private_key (cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey): CA Private Key
            ca_certificate (cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest): CA x509 Certificate
            target ():
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.Certificate

        Raises:
            None
        """

        if not ca_private_key:
            ca_private_key = self.private_key

        if not ca_certificate:
            ca_certificate = self.certificate

        if not self.initialised:
            target=self.type

        if self.type == 'ca' and self.initialised:
                certificate_serial = self.next_serial
                self.next_serial += 1
        else:
            certificate_serial = x509.random_serial_number() 

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(ca_certificate.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=self.config['days']))
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key())), critical=False)

        if target == 'ca':
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

            builder = builder.add_extension(x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    key_agreement=False,
                    data_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False), critical=True,
                    )
        else:
            builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)

            if target == 'vpnclient':
                builder = builder.add_extension(x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=False,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False), critical=True,
                        )
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        ]), critical=True)

            elif target == 'vpnserver':
                builder = builder.add_extension(x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False), critical=True,
                        )
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        ]), critical=True)

            elif target == 'webserver':
                builder = builder.add_extension(x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False), critical=True,
                        )
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        ]), critical=False)

                dns_names = [x509.DNSName(args.cn)]

                if args.alt:
                    dns_names.extend([x509.DNSName(hostname) for hostname in args.alt])

                    builder = builder.add_extension(x509.SubjectAlternativeName(dns_names), critical=False,)
                
                #
                # TODO: This needs to be dynamic and this is only an example.
                crl_distribution_points = [
                    x509.DistributionPoint(
                        full_name=[UniformResourceIdentifier("http://crl.example.com/crl.pem")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None
                    )
                ]

                aia_access_descriptions = [
                    x509.AccessDescription(
                        access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                        access_location=x509.UniformResourceIdentifier("http://ca.example.com/ca.pem")
                    )
                ]

                builder = builder.add_extension(x509.CRLDistributionPoints(crl_distribution_points),
                    critical=False)
                
                builder = builder.add_extension(x509.AuthorityInformationAccess(aia_access_descriptions),
                    critical=False)
            else:
                error('Unknown certificate type. Aborting.', 1)

        certificate = builder.sign(
            private_key=ca_private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate

    def update_certificate(self, certificate):
        """
        Replace the x509 certificate for the certificate bundle with the certificate provided

        Args:
            certificate (cryptography.hazmat.bindings._rust.x509.Certificate): The new x509 certificate
        
        Returns:
            None

        Raises:
            None
        """
        self.certificate = certificate

class Op:
    def __init__(self, account, bin=OP_BIN, vault=None, config=DEFAULT_OP_CONF):
        self.account = account
        self.vault = vault
        self.bin = bin
        self.ca_exists = False
        self.config = config

        if not os.path.isfile(self.bin) and os.access(bin, os.X_OK):
            print("Error: No 1Password-CLI executable. Is it installed?")

        result = run_command([self.bin, 'signin', '--account', self.account])

        if result.returncode != 0:
            error(result.stderr, result.returncode)
            sys.exit(result.returncode)
        
        if self.item_exists(self.config['ca_title']):
            self.ca_exists = True

    def ca_exists(self):
        """
        Test to see if a Certificate Authority object exists in 1Password

        Args:
            None

        Returns:
            bool: Existance of a 1Password CA

        Raises:
            None
        """

        return self.ca_exists
    
    def store_cert_bundle(self, obj):
        """
        Store a certificate bundle into 1Password

        Args:
            obj (CertificateBundle): A certificate bundle object

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if obj.is_valid():
            title = obj.get_title()

            attributes = [f'{self.config["cert_type_item"]}={obj.get_type()}',
                        f'{self.config["cn_item"]}={obj.get_certificate_cn()}',
                        f'{self.config["key_item"]}={obj.get_private_key()}',
                        f'{self.config["cert_item"]}={obj.get_certificate()}',
                        f'{self.config["start_date_item"]}={obj.get_certificate_start()}',
                        f'{self.config["expiry_date_item"]}={obj.get_certificate_expiry()}',
                        f'{self.config["serial_item"]}={obj.get_certificate_serial()}'
            ]

            if obj.get_type() == 'ca':
                attributes.append(f'{self.config["next_serial_item"]}={obj.get_next_serial()}')
            else:
                attributes.append(f'{self.config["csr_item"]}={obj.get_csr()}')

            result = self.store_item(action='create',
                                     title=title,
                                     attributes=attributes)
        else:
            error('Certificate Object is invalid. Unable to store in 1Password', 1)

        return result

    def mk_url(self, item_title, value_key=None):
        """
        Make a 1Password secret url from an item title and optional value

        Args:
            item_title (str): The 1Password item title
            item_key (str): The 1Password item key

        Returns:
            None

        Raises:
            None
        """

        if value_key is None:
            url = f'op://{self.vault}/{item_title}'
        else:
            url = f'op://{self.vault}/{item_title}/{value_key}'
        
        return url

    def edit_or_create(self, title, attributes):
        """
        CRUD helper. Store an item by either editing or creating

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        result = self.store_item(action='edit',
                            title=title,
                            attributes=attributes)

        if result.returncode != 0:
            result = self.store_item(action='create',
                                title=title,
                                attributes=attributes)
        
        return result

    def get_current_user_details(self):
        """
        Return the current 1Password CLI user details

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op user get --me

        Raises:
            None
        """

        result = run_command([self.bin, 'user', 'get', '--me'])

        return result

    def get_vault(self):
        """
        Return the current 1Password vault details

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """
        result = run_command([self.bin, 'vault', 'get', self.vault])

        return result

    def inject_item(self, template, env_vars):
        """
        Fill out a template from data in 1Password

        Args:
            template (str): A 1Password template
            env_vars (dict): A dict of environment variables for the execution environment

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """

        result = run_command([self.bin, 'inject'], env_vars=env_vars, str_in=template)
        
        return result

    def item_exists(self, item):
        """
        Checks to see if an item exists in 1Password

        Args:
            item (str): The item to check for

        Returns:
            bool: Existence of the item in 1Password

        Raises:
            None
        """
        result = self.read_item(self.mk_url(item_title=item, value_key='Title'))

        if result.returncode == 0:
            return True
        else:
            return False 

    def read_item(self, url):
        """
        Retrieve the contents of an item at a given 1Password secrets url

        Args:
            url (str): 1Password secrets url

        Returns:
            str: Contents of the item

        Raises:
            None
        """

        result = run_command([self.bin, 'read', url])

        return result

    def store_document(self, title, filename, str_in, action='create'):
        """
        Store a document in 1Password

        Args:
            title (str): 1Password item title
            filename (str): The filename to store as metadata in 1Password
            str_in (str): The contents of a file to store as a document
            action (str): CRUD action

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if action == 'create':
            cmd = [self.bin, 'document', action, f'--title={title}', f'--vault={self.vault}', f'--file-name={filename}']
        else:
            error(f'Unknown storage command {action}', 1)

        result=run_command(cmd, str_in=str_in)

        return result

    def store_item(self, title, attributes, action='create'):
        """
        Store an item in 1Password

        Args:
            title (str): 1Password item title
            attributes (list): A list of strings containing the item attributes
            action (str): CRUD action

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if action == 'create':
            if not self.item_exists(title):
                cmd = [self.bin, 'item', action, f'--category={self.config["category"]}', f'--title={title}', f'--vault={self.vault}']
            else:
                error(f'Item {title} already exists. Aborting', 1)
        elif action == 'edit':
            cmd = [self.bin, 'item', action, f'{title}', f'--vault={self.vault}']
        else:
            error(f'Unknown storage command {action}', 1)

        cmd.extend(attributes)

        result=run_command(cmd)

        return result

    def whoami(self):
        """
        Return the current 1Password CLI user

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op whoami

        Raises:
            None
        """
        result = run_command([self.bin, 'whoami'])
        return result


if __name__ == "__main__":

    description = f'{OPCA_TITLE} - {OPCA_SHORT_TITLE} v{OPCA_VERSION}'

    args = parse_arguments(description)

    selection = args.selection
    action = args.action

    title(description, 1)

    if selection == 'ca':
        handle_ca_action(action, args)

    elif selection == 'openvpn':
        handle_openvpn_action(action, args)

    elif selection == 'manage':
        handle_manage_action(action, args)