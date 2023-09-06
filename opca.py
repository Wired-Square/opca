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

This version of 1Password Certificate Authority represents a minimum viable product, but there are
other features that need to be implemented to be properly useful

- CA certificate and key renewal
- Regular certificate and key renewal
- Implement private key passphrases
"""

import argparse
import base64
import json
import os
import shutil
import secrets
import subprocess
import sys
from datetime import datetime, timedelta
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
OPCA_VERSION        = "0.11"
OPCA_TITLE          = "1Password Certificate Authority"
OPCA_SHORT_TITLE    = "OPCA"
OPCA_AUTHOR         = "Alex Ferrara <alex@wiredsquare.com>"
OPCA_LICENSE        = "mit"
OPCA_STATUS_COLUMN  = 90
OPCA_COLOUR_H       = [
    COLOUR['bold_yellow'],
    COLOUR['bold_yellow'],
    COLOUR['bold_white'],
    COLOUR['underline_white']
]
OPCA_COLOUR_ERROR   = COLOUR['bold_red']
OPCA_COLOUR_OK      = COLOUR['green']
OPCA_COLOUR_BRIGHT  = COLOUR['bold_white']
OPCA_COLOUR_WARNING = COLOUR['bold_yellow']

DEFAULT_OP_CONF = {
    'category': 'Secure Note',
    'ca_title': 'CA',
    'cn_item': 'cn[text]',
    'subject_item': 'subject[text]',
    'key_item': 'private_key',
    'key_size_item': 'key_size[text]',
    'cert_item': 'certificate',
    'cert_type_item': 'type[text]',
    'ca_cert_item': 'ca_certificate',
    'csr_item': 'certificate_signing_request',
    'start_date_item': 'not_before[text]',
    'expiry_date_item': 'not_after[text]',
    'serial_item': 'serial[text]',
    'openvpn_title': 'OpenVPN',
    'dh_item': 'diffie-hellman.dh_parameters',
    'dh_key_size_item': 'diffie-hellman.key_size[text]',
    'ta_item': 'tls_authentication.static_key',
    'ta_key_size_item': 'tls_authentication.key_size[text]',
    'ca_database_title': 'CA_Database',
    'next_serial_item': 'config.next_serial[text]',
    'org_item': 'config.org[text]',
    'email_item': 'config.email[text]',
    'city_item': 'config.city[text]',
    'state_item': 'config.state[text]',
    'country_item': 'config.country[text]',
    'ca_url_item': 'config.ca_url[text]',
    'crl_url_item': 'config.crl_url[text]',
    'days_item': 'config.days[text]',
    'crl_days_item': 'config.crl_days[text]'
}

DEFAULT_KEY_SIZE = {
    'ca': 4096,
    'dh': 2048,
    'ta': 2048,
    'vpnclient': 2048,
    'vpnserver': 2048,
    'webserver': 2048
}


def dh_key_size_estimate(dh_params):
    """
    Determines an estimate size of the Diffie-Hellman parameters

    Args:
        dh_params (str): The Diffie-Hellman parameters
    
    Returns:
        int

    Raises:
        None
    """
    content = dh_params.split("-----BEGIN DH PARAMETERS-----")[1]
    content = content.split("-----END DH PARAMETERS-----")[0]

    decoded_data = base64.b64decode(content.strip())

    number_of_bits = len(decoded_data) * 8

    return number_of_bits

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

    title('Certificate Authority', extra=action, level=2)

    one_password = Op(binary=OP_BIN, account=args.account, vault=args.vault)

    if action == 'init-ca':
        next_serial = 1

        title('Initialising the Certificate Authority', 3)

        ca_config = {
            'command': 'init',
            'cn': args.cn,
            'next_serial': next_serial,
            'ca_days': args.ca_days,
            'days': args.days,
            'key_size': DEFAULT_KEY_SIZE['ca']
        }

        attributes = [
            'org',
            'email',
            'city',
            'state',
            'country',
            'ca_url',
            'crl_url',
            'days',
            'crl_days'
        ]

        for attr in attributes:
            arg_value = getattr(args, attr, None)
            if arg_value:
                ca_config[attr] = arg_value

        ca = CertificateAuthority(one_password=one_password,
                                config=ca_config,
                                op_config=DEFAULT_OP_CONF)

        title(f'Checking [ {OPCA_COLOUR_BRIGHT}CA Certificate Bundle{COLOUR["reset"]} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_title']))

        title(f'Validating [ {OPCA_COLOUR_BRIGHT}CA Certificate Bundle{COLOUR["reset"]} ] in 1Password', 9)
        print_result(ca.is_valid())

        title(f'Checking [ {OPCA_COLOUR_BRIGHT}Certificate Database{COLOUR["reset"]} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_database_title']))

    elif action == 'import-ca':

        title('Importing a Certificate Authority from file', 3)

        title(f'Private Key [ {OPCA_COLOUR_BRIGHT}{args.key_file}{COLOUR["reset"]} ]', 9)
        imported_private_key = read_file(args.key_file)
        print_result(not is_empty(imported_private_key))

        title(f'Certificate [ {OPCA_COLOUR_BRIGHT}{args.cert_file}{COLOUR["reset"]} ]', 9)
        imported_certificate = read_file(args.cert_file)
        print_result(not is_empty(imported_certificate))

        if args.serial:
            next_serial = args.serial
        else:
            next_serial = x509.load_pem_x509_certificate(imported_certificate,
                                                      default_backend).serial_number

        title('The next available serial number is ' + \
            f'[ {OPCA_COLOUR_BRIGHT}{next_serial}{COLOUR["reset"]} ]', 7)

        ca_config = {
            'command': 'import',
            'private_key': imported_private_key,
            'certificate': imported_certificate,
            'next_serial': next_serial
        }

        attributes = [
            'org',
            'email',
            'city',
            'state',
            'country',
            'ca_url',
            'crl_url',
            'days',
            'crl_days'
        ]

        for attr in attributes:
            arg_value = getattr(args, attr, None)
            if arg_value:
                ca_config[attr] = arg_value

        ca = CertificateAuthority(one_password=one_password,
                                  config=ca_config,
                                  op_config=DEFAULT_OP_CONF)

        title(f'Checking [ {OPCA_COLOUR_BRIGHT}CA Certificate Bundle{COLOUR["reset"]} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_title']))

        title(f'Validating [ {OPCA_COLOUR_BRIGHT}CA Certificate Bundle{COLOUR["reset"]} ] in 1Password', 9)
        print_result(ca.is_valid())

    elif action == 'get-ca-db':
        ca = prepare_certificate_authority(one_password)

        print(ca.ca_database)

    elif action == 'get-ca-cert':
        ca = prepare_certificate_authority(one_password)

        print(ca.get_certificate())

    elif action == 'get-csr':
        url = one_password.mk_url(args.cn, DEFAULT_OP_CONF['csr_item'])

        result = one_password.read_item(url)

        if result.returncode != 0:
            error(result.stderr, 1)

        print(result.stdout)

    elif action == 'gen-ca-db':
        ca_config = {
            'command': 'rebuild-ca-database',
            'next_serial': args.serial,
            'crl_days': args.crl_days,
            'days': args.days,
            'ca_url': args.ca_url,
            'crl_url': args.crl_url
        }

        ca = CertificateAuthority(one_password=one_password,
                                config=ca_config,
                                op_config=DEFAULT_OP_CONF)

    elif action == 'gen-crl':
        ca = prepare_certificate_authority(one_password)

        if ca.process_ca_database():
            title(f'Storing {OPCA_COLOUR_BRIGHT}Certificate Database{COLOUR["reset"]} into 1Password', 9)
            result = one_password.store_ca_database(ca)
            print_cmd_result(result.returncode)

        print(ca.generate_crl())

    elif action == 'create-cert':
        ca = prepare_certificate_authority(one_password)

        if one_password.item_exists(args.cn):
            error(f'CN {args.cn} already exists. Aborting', 1)

        cert_config = ca.ca_certbundle.get_config()
        cert_config['cn'] = args.cn
        cert_config['key_size'] = DEFAULT_KEY_SIZE[args.cert_type]

        title(f'Generating a certificate bundle for {OPCA_COLOUR_BRIGHT}{args.cn}{COLOUR["reset"]}', 9)

        new_certificate_bundle = ca.generate_certificate_bundle(cert_type=args.cert_type,
                                              item_title=args.cn,
                                              config=cert_config)

        print_result(new_certificate_bundle.is_valid())

    elif action == 'import-cert':
        ca = prepare_certificate_authority(one_password)
        object_config = {
            'type': 'imported'
        }

        title('Importing a Certificate Bundle from file', 3)

        if args.key_file:
            title(f'Private Key {OPCA_COLOUR_BRIGHT}{args.key_file}{COLOUR["reset"]}', 9)
            imported_private_key = read_file(args.key_file)
            print_result(not is_empty(imported_private_key))

            if not is_empty(imported_private_key):
                object_config['private_key'] = imported_private_key
        else:
            title('Importing without Private Key', 8)

        title(f'Certificate {OPCA_COLOUR_BRIGHT}{args.cert_file}{COLOUR["reset"]}', 9)
        imported_certificate = read_file(args.cert_file)
        print_result(not is_empty(imported_certificate))

        if not is_empty(imported_certificate):
            object_config['certificate'] = imported_certificate

        if args.cn:
            item_title = args.cn
        else:
            item_title = None

        cert_bundle = ca.import_certificate_bundle(cert_type='imported',
                                                  config=object_config,
                                                  item_title=item_title)

        if not item_title:
            item_title = cert_bundle.get_certificate_attrib('cn')

        title('Storing certificate bundle for ' + \
            f'{OPCA_COLOUR_BRIGHT}{item_title}{COLOUR["reset"]} in 1Password', 9)
        result = ca.store_certbundle(cert_bundle)
        print_cmd_result(result.returncode)

    else:
        error('This feature is not yet written', 99)

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

    title('OpenVPN', extra=action, level=2)

    one_password = Op(binary=OP_BIN, account=args.account, vault=args.vault)

    if action == 'gen-dh':
        title('Generate the DH Parameters', 3)

        parameters = dh.generate_parameters(generator=2,
                                            key_size=DEFAULT_KEY_SIZE["dh"],
                                            backend=default_backend())

        dh_parameters_pem = parameters.parameter_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.ParameterFormat.PKCS3).decode('utf-8')

        title('Storing the DH parameters in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["dh_item"]}={dh_parameters_pem}',
                    f'{DEFAULT_OP_CONF["dh_key_size_item"]}={DEFAULT_KEY_SIZE["dh"]}'
                    ]

        result = one_password.edit_or_create(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_cmd_result(result.returncode)

    elif action == 'get-dh':
        url = one_password.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        value_key=DEFAULT_OP_CONF["dh_item"].replace(".", "/"))

        title(f'Reading the [ {OPCA_COLOUR_BRIGHT}{url}{COLOUR["reset"]} ] from 1Password', 9)

        result = one_password.read_item(url)
        print_cmd_result(result.returncode)

        if result.returncode == 0:
            print(result.stdout)

    elif action == 'import-dh':
        title('Importing a Diffie-Hellmnan parameters from file', 3)

        title(f'DH Parameters {OPCA_COLOUR_BRIGHT}{args.file}{COLOUR["reset"]}', 9)
        imported_ta_key = read_file(args.file).decode('UTF-8')
        print_result(not is_empty(imported_ta_key))

        key_size = dh_key_size_estimate(imported_ta_key)

        title(f'DH Key size is estimated at {OPCA_COLOUR_BRIGHT}{key_size}{COLOUR["reset"]} bits', 8)

        title('Storing the DH Parameters in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["dh_item"]}={imported_ta_key}',
                    f'{DEFAULT_OP_CONF["dh_key_size_item"]}={key_size}'
                    ]

        result = one_password.edit_or_create(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_cmd_result(result.returncode)

    elif action == 'gen-ta-key':
        line_length = 32

        title('Generate the OpenVPN TLS Authentication Key', 3)

        hex_key = secrets.token_bytes(DEFAULT_KEY_SIZE["ta"] // 8).hex()

        key_chunks = [hex_key[i:i + line_length] for i in range(0, len(hex_key), line_length)]

        formatted_key = "\n".join(key_chunks)

        formatted_key = f"""\
-----BEGIN OpenVPN Static key V1-----
{formatted_key}
-----END OpenVPN Static key V1-----
"""

        title('Storing the TLS Authentication Key in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={formatted_key}',
                    f'{DEFAULT_OP_CONF["ta_key_size_item"]}={DEFAULT_KEY_SIZE["ta"]}'
                    ]

        result = one_password.edit_or_create(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_cmd_result(result.returncode)

    elif action == 'import-ta-key':
        title('Importing a TLS Authentication static key from file', 3)

        title(f'TA Key {OPCA_COLOUR_BRIGHT}{args.file}{COLOUR["reset"]}', 9)
        imported_ta_key = read_file(args.file).decode('UTF-8')
        print_result(not is_empty(imported_ta_key))

        key_size = ta_key_size(imported_ta_key)

        title(f'TA Key size is {OPCA_COLOUR_BRIGHT}{key_size}{COLOUR["reset"]} bits', 8)

        title('Storing the TLS Authentication Key in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={imported_ta_key}',
                    f'{DEFAULT_OP_CONF["ta_key_size_item"]}={key_size}'
                    ]

        result = one_password.edit_or_create(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_cmd_result(result.returncode)

    elif action == 'gen-vpn-profile':
        env_vars = os.environ.copy()
        env_vars['USER'] = args.cn

        title('Reading VPN profile ' + \
            f'[ {OPCA_COLOUR_BRIGHT}{args.template}{COLOUR["reset"]} ] from 1Password', 9)

        result = one_password.read_item(url = one_password.mk_url(
                            item_title=DEFAULT_OP_CONF["openvpn_title"],
                            value_key=f'template/{args.template}'))
        print_cmd_result(result.returncode)

        if result.returncode == 0:
            ovpn_template = result.stdout
        else:
            error(result.stderr, result.returncode)

        title(f'Generating VPN profile for [ {OPCA_COLOUR_BRIGHT}{args.cn}{COLOUR["reset"]} ]', 9)
        result = one_password.inject_item(env_vars=env_vars, template=ovpn_template)
        print_cmd_result(result.returncode)

        if result.returncode != 0:
            error(result.stderr, result.returncode)

        title('Storing VPN profile in 1Password', 9)
        one_password.store_document(action='create', item_title=f'VPN_{args.cn}',
                        filename=f'{args.cn}-{args.template}.ovpn', str_in=result.stdout)
        print_cmd_result(result.returncode)

    elif action == 'gen-sample-vpn-server':
        title('Storing the sample OpenVPN configuration template', 9)

        attributes = ['server.hostname[text]=vpn.domain.com.au',
                    'server.port[text]=1194',
                    'server.cipher[text]=aes-256-gcm',
                    'server.auth[text]=sha256',
                    f'''template.sample[text]=#
# Client - {{{{ op://{args.vault}/$USER/cn }}}}
#

# Brought to you by Wired Square - www.wiredsquare.com

client
dev tun
proto udp
remote {{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_title"]}/server/hostname }}}} {{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_title"]}/server/port }}}}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher {{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_title"]}/server/cipher }}}}
auth {{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_title"]}/server/auth }}}}
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
{{{{ op://{args.vault}/{DEFAULT_OP_CONF["openvpn_title"]}/{DEFAULT_OP_CONF["ta_item"].replace(".", "/")} }}}}
</tls-auth>
''']

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"], action='create',
                                attributes=attributes)

        print_cmd_result(result.returncode)

    else:
        error('This feature is not yet written', 99)

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

    title('Management', extra=action, level=2)

    one_password = Op(binary=OP_BIN, account=args.account, vault=None)

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
        result = one_password.whoami()
        print_cmd_result(result.returncode)

        print(result.stdout)

        title('Retrieve the current user details', 9)
        result = one_password.get_current_user_details()
        print_cmd_result(result.returncode)

        print(result.stdout)
    else:
        error('This feature is not yet written', 99)

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

    return not bool(var)

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

    subparsers = parser.add_subparsers(title='Commands', dest='selection',
                                                        required=True)

    #
    # CA
    parser_ca = subparsers.add_parser('ca', help='Perform Certificate Authority actions')
    parser_ca_actions = parser_ca.add_subparsers(title='Actions', dest='action',
                                                        required=True)

    subparser_action_init_ca = parser_ca_actions.add_parser('init-ca',
            help='Initialise a 1Password Certificate Authority')
    subparser_action_init_ca.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_init_ca.add_argument('-e', '--email', required=False,
            help='The email address to use in the certificate subject')
    subparser_action_init_ca.add_argument('-o', '--org', required=True,
            help='The organisation to use in the certificate subject')
    subparser_action_init_ca.add_argument('-v', '--vault', required=True,
            help='CA Vault')
    subparser_action_init_ca.add_argument('--city', required=False,
            help='The city to use in the certificate subject')
    subparser_action_init_ca.add_argument('--state', required=False,
            help='The state to use in the certificate subject')
    subparser_action_init_ca.add_argument('--country', required=False,
            help='The country to use in the certificate subject')
    subparser_action_init_ca.add_argument('--ca-days', required=True, type=int,
            help='The number of days this CA certificate should be valid for')
    subparser_action_init_ca.add_argument('--crl-days', required=True, type=int,
            help='The number of days a CRL should be valid for')
    subparser_action_init_ca.add_argument('--days', required=True, type=int,
            help='The number of days the certificate signed by this CA should be valid for')
    subparser_action_init_ca.add_argument('-n', '--cn', required=True,
            help='x509 CN attribute for the 1Password Certificate Authority')
    subparser_action_init_ca.add_argument('--ca-url', required=False,
            help='The URL where we can find the CA certificate')
    subparser_action_init_ca.add_argument('--crl-url', required=False,
            help='The URL where we can find the Certificate Revocation List')

    subparser_action_import_ca = parser_ca_actions.add_parser('import-ca',
            help='Import a 1Password Certificate Authority from file')
    subparser_action_import_ca.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_import_ca.add_argument('-c', '--cert-file', required=True,
            help='Certificate file')
    subparser_action_import_ca.add_argument('-k', '--key-file', required=True,
            help='Private Key file')
    subparser_action_import_ca.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_action_import_ca.add_argument('--days', required=True, type=int,
            help='The number of days the certificate should be valid for')
    subparser_action_import_ca.add_argument('--crl-days', required=True, type=int,
            help='The number of days a CRL should be valid for')
    subparser_action_import_ca.add_argument('--serial', required=False,
            help='Certificate serial number or CA next serial number')
    subparser_action_import_ca.add_argument('--ca-url', required=False,
            help='The URL where we can find the CA certificate')
    subparser_action_import_ca.add_argument('--crl-url', required=False,
            help='The URL where we can find the Certificate Revocation List')

    subparser_action_get_ca_db = parser_ca_actions.add_parser('get-ca-db',
            help='Generate a Certificate Database for the 1Password CA')
    subparser_action_get_ca_db.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_get_ca_db.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_get_ca_cert = parser_ca_actions.add_parser('get-ca-cert',
            help='Get the object CA Certificate')
    subparser_action_get_ca_cert.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_get_ca_cert.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_get_csr = parser_ca_actions.add_parser('get-csr',
            help='Get the CertificateBundle object Certificate Signing Request')
    subparser_action_get_csr.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_get_csr.add_argument('-n', '--cn', required=True,
            help='x509 CN attribute for the 1Password Certificate Authority')
    subparser_action_get_csr.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_gen_ca_db = parser_ca_actions.add_parser('gen-ca-db',
            help='Generate a Certificate Database for the 1Password CA')
    subparser_action_gen_ca_db.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_gen_ca_db.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_action_gen_ca_db.add_argument('--days', required=True, type=int,
            help='The number of days the certificate should be valid for')
    subparser_action_gen_ca_db.add_argument('--crl-days', required=True, type=int,
            help='The number of days a CRL should be valid for')
    subparser_action_gen_ca_db.add_argument('--serial', required=False,
            help='Certificate Authority next serial number')
    subparser_action_gen_ca_db.add_argument('--ca-url', required=False,
            help='The URL where we can find the CA certificate')
    subparser_action_gen_ca_db.add_argument('--crl-url', required=False,
            help='The URL where we can find the Certificate Revocation List')

    subparser_action_gen_crl = parser_ca_actions.add_parser('gen-crl',
            help='Generate a Certificate Revokation List for the 1Password CA')
    subparser_action_gen_crl.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_gen_crl.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_create_cert = parser_ca_actions.add_parser('create-cert',
            help='Create a new x509 CertificateBundle object')
    subparser_action_create_cert.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_create_cert.add_argument('-n', '--cn', required=True,
            help='CN attribute. Regular certificates use this for the 1Password title.')
    subparser_action_create_cert.add_argument('-t', '--cert-type', required=True,
            help='x509 Certificate type', choices=['vpnserver', 'vpnclient', 'webserver'])
    subparser_action_create_cert.add_argument('-s', '--serial', required=False,
            help='Certificate serial number or CA Certificate next serial number')
    subparser_action_create_cert.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_action_create_cert.add_argument('--alt', nargs='+', required=False,
            help='Alternate CN.')

    subparser_action_import_cert = parser_ca_actions.add_parser('import-cert',
            help='Create a new x509 CertificateBundle object')
    subparser_action_import_cert.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_import_cert.add_argument('-c', '--cert-file', required=True,
            help='Certificate file')
    subparser_action_import_cert.add_argument('-k', '--key-file', required=False,
            help='Private Key file')
    subparser_action_import_cert.add_argument('-n', '--cn', required=False,
            help='x509 CN attribute for the 1Password Certificate Authority')
    subparser_action_import_cert.add_argument('-v', '--vault', required=True, help='CA Vault')

    """
    action_import_ca = parser_ca_actions.add_parser('renew-cert',
            help='Renew a x509 certificate')
    """

    #
    # OpenVPN
    parser_openvpn = subparsers.add_parser('openvpn', help='Perform OpenVPN actions')
    parser_openvpn_actions = parser_openvpn.add_subparsers(title='Actions', dest='action',
                                                                  required=True)

    subparser_action_gen_dh = parser_openvpn_actions.add_parser('gen-dh',
            help='Generate Diffie-Hellman parameters')
    subparser_action_gen_dh.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_gen_dh.add_argument('-v', '--vault', required=True,
            help='CA Vault')

    subparser_action_import_dh = parser_openvpn_actions.add_parser('import-dh',
            help='Importa Diffie-Hellman parameters from file')
    subparser_action_import_dh.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_import_dh.add_argument('-f', '--file', required=True,
            help='Diffie-Hellman parameters file')
    subparser_action_import_dh.add_argument('-v', '--vault', required=True,
            help='CA Vault')

    subparser_action_get_dh = parser_openvpn_actions.add_parser('get-dh',
            help='Retrieve Diffie-Hellman parameters from 1Password')
    subparser_action_get_dh.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_get_dh.add_argument('-v', '--vault', required=True,
            help='CA Vault')

    subparser_action_gen_ta_key = parser_openvpn_actions.add_parser('gen-ta-key',
            help='Generate a TLS Authentication Static Key')
    subparser_action_gen_ta_key.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_gen_ta_key.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_import_ta_key = parser_openvpn_actions.add_parser('import-ta-key',
            help='Importa a TLS Authentication Static Key from file')
    subparser_action_import_ta_key.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_import_ta_key.add_argument('-f', '--file', required=True,
            help='TLS Authentication static key file')
    subparser_action_import_ta_key.add_argument('-v', '--vault', required=True,
            help='CA Vault')

    subparser_action_gen_vpn_profile = parser_openvpn_actions.add_parser('gen-vpn-profile',
            help='Generate VPN profile from template')
    subparser_action_gen_vpn_profile.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_gen_vpn_profile.add_argument('-n', '--cn', required=True,
            help='The certificate CN. This is also the 1Password title.')
    subparser_action_gen_vpn_profile.add_argument('-t', '--template', required=True,
            help='OpenVPN template stored in 1Password')
    subparser_action_gen_vpn_profile.add_argument('-v', '--vault', required=True,
            help='CA Vault')

    subparser_action_gen_sample_vpn_server = parser_openvpn_actions.add_parser(
            'gen-sample-vpn-server',
            help='Generate a sample OpenVPN object in 1Password')
    subparser_action_gen_sample_vpn_server.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_gen_sample_vpn_server.add_argument('-v', '--vault', required=True,
            help='CA Vault')

    #
    # Manage
    parser_manage = subparsers.add_parser('manage', help='Perform management actions')
    parser_manage_actions = parser_manage.add_subparsers(title='Actions', dest='action',
                                                                required=True)

    subparser_action_test = parser_manage_actions.add_parser('test', help='Run pre-flight checks')
    subparser_action_test.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_whoami = parser_manage_actions.add_parser('whoami',
            help='Find out about the current 1Password user')
    subparser_action_whoami.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')

    return parser.parse_args()

def prepare_certificate_authority(one_password):
    """
    Prepares the certificate authority object for later consumption

    Args:
        command (str): The way we will construct the certificate authority
        config (dict): CA Configuration

    Returns:
        CertificateAuthority

    Raises:
        None
    """

    ca_config = {
        'command': 'retrieve'
    }

    ca = CertificateAuthority(one_password=one_password,
                            config=ca_config,
                            op_config=DEFAULT_OP_CONF)

    return ca

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

    success = bool(returncode == 0)

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
    content = None

    try:
        with open(file_path, 'rb') as file:
            content = file.read()
    except FileNotFoundError:
        error(f"File '{file_path}' not found.", 1)
    except PermissionError:
        error(f"Permission denied for file '{file_path}'.", 1)
    except IOError as err:
        error(f"I/O error occurred while reading file '{file_path}': {err}", 1)
    except Exception as err:
        error(f"An unexpected error occurred: {err}", 1)

    return content

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
        result = subprocess.run(command, env=env_vars, stdin=stdin, input=str_in,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=text, shell=shell)

        return result

    except FileNotFoundError:
        error(f'Command not found. Does { command[0] }it exist?', 1)
        sys.exit(1)

def ta_key_size(ta_key):
    """
    Determines the key size of a OpenVPN TLS Authentication Static Key

    Args:
        ta_key (str): The TLS Authentication Static Key
    
    Returns:
        int

    Raises:
        None
    """
    content = ta_key.split("-----BEGIN OpenVPN Static key V1-----")[1]
    content = content.split("-----END OpenVPN Static key V1-----")[0]

    hex_string = content.replace("\n", "").strip()

    number_of_bits = len(hex_string) * 4

    return number_of_bits

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

def warning(warning_msg):
    """
    Prints a warning message with custom formatting.

    Args:
        warning_msg (str): The error message to be displayed.

    Returns:
        None
    
    Raises:
        None
    """

    error_colour = OPCA_COLOUR_WARNING
    reset = COLOUR['reset']

    print(f'{error_colour}Warning:{reset} {warning_msg}')


class CertificateBundle:
    """ Class to contain x509 Certificates, Private Keys and Signing Requests """
    def __init__(self, cert_type, item_title, import_certbundle, config):
        """
        CertificateBundle - A class for dealing with x509 certificate items

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            import_certbundle (bool): Are we importing?
            config (dict): A dictionary of certificate configuration items
        """
        self.type = cert_type
        self.title = item_title
        self.config = config
        self.csr = None
        self.private_key = None
        self.private_key_passphrase = None # TODO: Implement private key passphrase
        self.certificate = None
        self.config_attrs = (
            'org',
            'city',
            'state',
            'country',
            'email'
        )

        if import_certbundle:
            # Import
            if 'private_key' in self.config:
                self.import_private_key(self.config['private_key'], self.private_key_passphrase)
            self.import_certificate(self.config['certificate'])

            if not self.title:
                self.title = self.get_certificate_attrib('cn')

            # If we haven't been given these details, extract them from the certificate
            for attr in self.config_attrs:
                if attr not in self.config:
                    value = self.get_certificate_attrib(attr)
                    if value is not None:
                        self.config[attr] = value

        else:
            # Generate
            self.private_key = self.generate_private_key(key_size=config['key_size'])
            self.csr = self.generate_csr(private_key=self.private_key, cert_cn=self.config['cn'])
            self.certificate = self.sign_certificate(self.csr)

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

    def get_certificate_attrib(self, attrib):
        """
        Returns an attribute of the stored certificate

        Args:
            attrib (str): The attribute to return
        
        Returns:
            str

        Raises:
            None
        """

        attr_value = None

        if attrib == 'cn':
            attribute = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'not_before':
            attr_value = self.format_datetime(self.certificate.not_valid_before)
        elif attrib == 'not_after':
            attr_value = self.format_datetime(self.certificate.not_valid_after)
        elif attrib == 'issuer':
            attr_value = self.certificate.issuer
        elif attrib == 'subject':
            attr_value = self.certificate.subject.rfc4514_string()
        elif attrib == 'serial':
            attr_value = self.certificate.serial_number
        elif attrib == 'version':
            attr_value = self.certificate.version
        elif attrib == 'org':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.ORGANIZATION_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'email':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.EMAIL_ADDRESS)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'city':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.LOCALITY_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'state':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.STATE_OR_PROVINCE_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'country':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.COUNTRY_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'basic_constraints':
            attr_value = self.certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS)

        return attr_value

    def get_config(self, attr='all'):
        """
        Return the contents of a Certificate Bundle config item

        Args:
            attr (str): The attribute to return
        
        Returns:
            str or dict

        Raises:
            None
        """
        config = None

        if attr in self.config_attrs and attr in self.config:
            config = self.config[attr]

        if attr == 'all':
            config = {attr: self.config[attr] for attr in self.config_attrs if attr in self.config}

        return config

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
        csr = None

        if self.csr:
            csr = self.csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        return csr

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
        if self.private_key:
            return self.private_key.private_bytes(
                Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode('utf-8')

        return ""

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

    def generate_csr(self, cert_cn, private_key):
        """
        Generate a certificate signing request for the current Certificate Bundle

        Args:
            cert_cn (str): The CN to use for the CSR
            private_key (str):  The private key to use in creating a CSR
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest

        Raises:
            None
        """

        x509_attributes = [x509.NameAttribute(x509.NameOID.COMMON_NAME, cert_cn)]

        if 'country' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.COUNTRY_NAME, self.config['country']))

        if 'state' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, self.config['state']))

        if 'city' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.LOCALITY_NAME, self.config['city']))

        if 'org' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, self.config['org']))

        if 'email' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.EMAIL_ADDRESS, self.config['email']))


        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(x509_attributes
        )).sign(private_key, hashes.SHA256(), default_backend())

        return csr

    def generate_private_key(self, key_size):
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
            key_size = key_size,
            backend = backend
        )

        return private_key

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
        return self.get_certificate_attrib("basic_constraints").value.ca

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
        current_time = datetime.now()

        if not self.private_key:
            # No private key, we only care about validity
            return self.certificate.not_valid_before <= current_time <= self.certificate.not_valid_after

        if self.private_key.public_key() != self.certificate.public_key():
            # The private key does not match the certificate
            return False

        if self.type != 'ca' and self.is_ca_certificate():
            return False

        if self.type == 'ca' and not self.is_ca_certificate():
            return False

        return self.certificate.not_valid_before <= current_time <= self.certificate.not_valid_after

    def sign_certificate(self, csr):
        """
        Sign a csr to create a x509 certificate.

        Args:
            csr (cryptography x509.CertificateSigningRequest): Certificate Signing Request
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.Certificate

        Raises:
            None
        """

        if self.type == 'ca':
            certificate_serial = self.config['next_serial']
            delta = timedelta(int(self.config['ca_days']))
        else:
            certificate_serial = x509.random_serial_number()
            delta = timedelta(int(30))

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(csr.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + delta)
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key()),
                critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key())),
                critical=False)

        if self.type == 'ca':
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True)

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
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=False)

            if self.type == 'vpnclient':
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

            elif self.type == 'vpnserver':
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

            elif self.type == 'webserver':
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

                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(dns_names), critical=False,)

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in self.config:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(self.config["crl_url"])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in self.config:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(self.config["ca_url"])
                        )
                    ]

                    builder = builder.add_extension(
                        x509.AuthorityInformationAccess(aia_access_descriptions),
                        critical=False)
            else:
                error('Unknown certificate type. Aborting.', 1)

        certificate = builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate

    def update_certificate(self, certificate):
        """
        Replace the x509 certificate for the certificate bundle with the certificate provided

        Args:
            certificate (cryptography Certificate): x509 certificate
        
        Returns:
            None

        Raises:
            None
        """

        # Does the private key match the certificate?
        if self.private_key.public_key() == certificate.public_key():
            self.certificate = certificate
        else:
            error('Signed certificate does not match the private key', 1)


class CertificateAuthority:
    """ Class to act as a Certificate Authority """
    def __init__(self, one_password, config, op_config):
        """
        Construct a certificate authority object.

        Args:
            one_password (OpObject): An initialised 1Password object
            command (str): How we should acquire a certificate authority key and certificate
            config (dict): Configuration items
        """
        self.ca_certbundle = None
        self.ca_config = None
        self.ca_database = None      # The equivalent of index.txt. Dict keyed by serial
        self.ca_database_cn = None   # Dict keyed by cn. Essentially an index to ca_database
        self.certs_revoked = None
        self.certs_expires_soon = None
        self.certs_valid = None
        self.next_serial = None
        self.one_password = one_password
        self.op_config = op_config
        self.config_attrs = (
            'org',
            'email',
            'city',
            'state',
            'country',
            'ca_url',
            'crl_url',
            'days',
            'crl_days'
        )

        if config['command'] == 'init':
            self.ca_database = []
            self.ca_database_cn = {}
            self.ca_config = config
            self.next_serial = int(self.ca_config['next_serial'])

            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 1)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=False,
                                      config=self.ca_config)

            self.next_serial += 1

            self.ca_database.append(self.format_db_item(self.ca_certbundle.certificate))

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'import':
            self.ca_database = []
            self.ca_database_cn = {}
            self.ca_config = config
            self.next_serial = int(self.ca_config['next_serial'])

            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 1)


            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=True,
                                      config=self.ca_config)

            self.ca_database.append(self.format_db_item(self.ca_certbundle.certificate))

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'retrieve':
            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 1)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            self.retrieve_ca_database()
            if self.process_ca_database():
                self.store_ca_database()

        elif config['command'] == 'rebuild-ca-database':
            self.ca_database = []
            self.ca_database_cn = {}
            self.ca_config = config
            self.next_serial = self.ca_config.get('next_serial')

            # If present, it needs to be cast to an int
            if self.next_serial is not None:
                self.next_serial = int(self.next_serial)

            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 1)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            if self.one_password.item_exists(self.op_config['ca_database_title']):
                error('CA database exists. Aborting', 1)

            self.ca_database.append(self.format_db_item(self.ca_certbundle.certificate))

            self.rebuild_ca_database()

        else:
            error('Unknown CA command', 1)

    def add_ca_database_item(self, certificate):
        """
        Add an item to the CA database, process and store.

        Args:
            certificate (Certfqwfwe): The certificate to add to the database
        
        Returns:
            Bool

        Raises:
            None
        """

        certificate_cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        certificate_serial = certificate.serial_number

        if certificate_serial in self.ca_database:
            return False

        self.process_ca_database()

        self.ca_database.append(self.format_db_item(certificate))
        self.store_ca_database()

        self.ca_database_cn[certificate_cn] = certificate_serial

        return True

    def format_datetime(self, date):
        """
        Format a datetime to match OpenSSL text

        Args:
            date (datetime): The datetime object we are working with
        
        Returns:
            str

        Raises:
            None
        """
        format_string = '%Y%m%d%H%M%SZ'

        return date.strftime(format_string)

    def format_db_item(self, certificate):
        """
        Format a certificate db item from a certificate

        Args:
            certificate: cryptography.hazmat.bindings._rust.x509.Certificate

        Returns:
            list

        Raises:
            None
        """

        expired = datetime.utcnow() > certificate.not_valid_after

        if expired:
            status = 'Expired'
        else:
            status = 'Valid'

        cert_db_item = {
            'serial': certificate.serial_number,
            'cn': certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'status': status,
            'expiry_date': self.format_datetime(certificate.not_valid_after),
            'revocation_date': '',
            'subject': certificate.subject.rfc4514_string()
        }

        return cert_db_item

    def get_certificate(self):
        """
        Returns the CA certificate in various formats

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.ca_certbundle.get_certificate()

    def generate_crl(self):
        """
        Generate a certificate revocation list in PEM format for the Certificate Authority

        Args:
            None

        Returns:
            string

        Raises:
            None
        """

        builder = x509.CertificateRevocationListBuilder()

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.ca_certbundle.get_certificate_attrib('cn')),
        ]))

        builder = builder.last_update(datetime.today())
        builder = builder.next_update(datetime.today() + timedelta(int(self.ca_config["crl_days"])))

        for cert in self.certs_revoked:
            serial_number = cert['serial']
            revocation_date = datetime.strptime(cert['revocation_date'], '%Y%m%d%H%M%SZ')

            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                serial_number).revocation_date(revocation_date).build(default_backend())
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_certbundle.private_key, hashes.SHA256(), default_backend())

        return crl.public_bytes(serialization.Encoding.PEM).decode('UTF-8')

    def generate_certificate_bundle(self, cert_type, item_title, config):
        """
        Creates a certificate bundle from configuration

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            config (dict): A dictionary of certificate configuration items

        Returns:
            CertificateBundle

        Raises:
            None
        """
        cert_bundle = CertificateBundle(cert_type=cert_type,
                                        item_title=item_title,
                                        import_certbundle=False,
                                        config=config)

        pem_csr = cert_bundle.get_csr().encode('utf-8')
        csr = x509.load_pem_x509_csr(pem_csr, default_backend())

        signed_certificate = self.sign_certificate(csr=csr, target=args.cert_type)

        cert_bundle.update_certificate(signed_certificate)

        if cert_bundle.is_valid():
            self.store_certbundle(cert_bundle)

        return cert_bundle

    def import_certificate_bundle(self, cert_type, item_title, config):
        """
        Imports a certificate bundle from variables

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            config (dict): A dictionary of certificate configuration items

        Returns:
            CertificateBundle

        Raises:
            None
        """

        obj = CertificateBundle(cert_type=cert_type,
                                item_title=item_title,
                                import_certbundle=True,
                                config=config)

        if item_title is None:
            item_title = obj.get_certificate_attrib('cn')

        title(f'Checking [ { OPCA_COLOUR_BRIGHT }{ item_title }{ COLOUR["reset"] } ] certificate bundle', 9)

        if obj.private_key:
            print_result(obj.is_valid())
        else:
            print_result(False, failed_msg='NOPRIV')

        return obj

    def is_valid(self):
        """
        Is the certifiate authority object valid

        Args:
            None

        Returns:
            bool

        Raises:
            None
        """

        return self.ca_certbundle.is_valid()

    def process_ca_database(self):
        """
        Process the CA database.
         - The status of certifiates might change due to time
         - Gather a list of
           - Certificates revoked
           - Certificates expiring soon
           - Certificates valid

        Args:
            None

        Returns:
            bool: Did the database chnage post-processing

        Raises:
            None
        """
        changed = False
        db_error = False
        tmp_ca_db = []
        self.certs_revoked = []
        self.certs_expires_soon = []
        self.certs_valid = []

        if self.ca_database is None:
            db_error = True

        else:

            for cert in self.ca_database:
                skip = False

                try:
                    expiry_date = datetime.strptime(cert['expiry_date'], '%Y%m%d%H%M%SZ')

                    expired = datetime.utcnow() > expiry_date

                    expires_soon = datetime.utcnow() + timedelta(30) > expiry_date
                    revoked = bool(cert['revocation_date']) or (cert['status'] == 'Revoked')

                except KeyError:
                    warning(f"'expiry_date' key not found for certificate { cert['serial'] }.")
                    skip = True
                    db_error = True
                except ValueError:
                    warning(f"Unable to parse 'expiry_date' for certificate { cert['serial'] }.")
                    skip = True
                    db_error = True



                if not skip:
                    if expired:
                        if cert['status'] != 'Expired':
                            changed = True
                            cert['status'] = 'Expired'
                    elif revoked:
                        if cert['status'] != 'Revoked':
                            cert['status'] = 'Revoked'
                            changed = True

                        self.certs_revoked.append(cert)

                    elif expires_soon:
                        self.certs_expires_soon.append(cert)

                    else:
                        self.certs_valid.append(cert)

                    tmp_ca_db.append(cert)

        if changed and not db_error:
            self.ca_database = tmp_ca_db
            self.store_ca_database()

        return changed

    def rebuild_ca_database(self):
        """
        Rebuild the CA certificate database from 1Password

        Args:
            None

        Returns:
            dict: The CA database as rebuilt

        Raises:
            None
        """
        result_dict = {}
        max_serial = 0

        result = self.one_password.item_list(categories=self.op_config['category'])

        if result.returncode != 0:
            error(error_msg=result.stderr, exit_code=result.returncode)

        op_items = json.loads(result.stdout)

        for op_item in op_items:
            item_title = op_item['title']

            cert_bundle = self.retrieve_certbundle(item_title)

            if cert_bundle is None:
                warning(f'{ item_title } is not a certificate. Ignoring.')
            else:
                # Actual certificate
                cert_serial = cert_bundle.get_certificate_attrib('serial')
                result_dict[cert_serial] = cert_bundle.certificate

        for serial, certificate in sorted(result_dict.items()):
            self.add_ca_database_item(certificate=certificate)

            if serial > max_serial:
                max_serial = serial + 1

        if self.next_serial:
            if max_serial >= self.next_serial:
                warning(f'The next serial is { self.next_serial } but the largest serial number seen is { max_serial }')

        else:
            self.next_serial = max_serial + 1

        title(f'Next serial is [ { OPCA_COLOUR_BRIGHT }{ self.next_serial }{ COLOUR["reset"] } ]', 8)
        self.store_ca_database()

    def retrieve_ca_database(self):
        """
        Retrieve the CA certificate database from 1Password

        Args:
            None

        Returns:
            dict: The CA database as retrieved

        Raises:
            None
        """
        self.ca_config = {}
        self.ca_database_cn = {}
        result_dict = {}
        result = self.one_password.get_item(self.op_config['ca_database_title'])

        if result.returncode == 0:
            loaded_ca_db = json.loads(result.stdout)

            for field in loaded_ca_db['fields']:
                if 'section' in field:
                    section_label = field['section']['label']
                    field_label = field['label']
                    field_value = field.get('value', '')

                    if section_label == 'config':
                        if field_label == 'next_serial':
                            self.next_serial = int(field_value)
                        elif field_label in self.config_attrs:
                            self.ca_config[field_label] = field_value
                    elif section_label not in result_dict:
                        result_dict[section_label] = {'serial': int(section_label)}

                    if section_label != 'config':
                        if field_label in ('status', 'cn', 'subject', 'expiry_date', 'revocation_date'):
                            result_dict[section_label][field_label] = field_value

                    # Build the index
                    if field_label == 'cn' and field_value not in self.ca_database_cn:
                        self.ca_database_cn[field_value] = section_label

            self.ca_database = list(result_dict.values())

        return self.ca_database

    def retrieve_certbundle(self, item_title):
        """
        Imports a certificate bundle from 1Password

        Args:
            item_title (str): The 1Password object that contains a certificate bundle
            ca (bool): Is the certificate bundle our CA?

        Returns:
            CertificateBundle if the retrieved object is a certificate bundle, otherwise None

        Raises:
            None
        """
        cert_config = {}
        cert_type = None

        result = self.one_password.get_item(item_title)

        if result.returncode != 0:
            error('Something went wrong retrieving the certificate bundle', 1)

        loaded_object = json.loads(result.stdout)

        for field in loaded_object['fields']:
            if field['label'] == 'certificate':
                cert_config['certificate'] = field['value'].encode('utf-8')
            elif field['label'] == 'private_key':
                cert_config['private_key'] = field['value'].encode('utf-8')
            elif field['label'] == 'type':
                cert_config['cert_type'] = field['value']
                cert_type = field['value']

        if 'certificate' not in cert_config:
            return None

        return self.import_certificate_bundle(cert_type=cert_type,
                                              item_title=item_title,
                                              config=cert_config)

    def sign_certificate(self, csr, target=None):
        """
        Sign a csr to create a x509 certificate.

        Args:
            csr (cryptography x509.CertificateSigningRequest): Certificate Signing Request
            target (): The type of x509 certificate to create
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.Certificate

        Raises:
            None
        """

        certificate_serial = self.next_serial
        delta = timedelta(int(self.ca_config['days']))

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_certbundle.certificate.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + delta)
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_certbundle.private_key.public_key()),
                critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_certbundle.private_key.public_key())),
                critical=False)

        if target == 'ca':
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True)

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
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=False)

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

                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(dns_names), critical=False,)

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in self.ca_config:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(self.ca_config["crl_url"])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in self.ca_config:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(self.ca_config["ca_url"])
                        )
                    ]

                    builder = builder.add_extension(
                        x509.AuthorityInformationAccess(aia_access_descriptions),
                        critical=False)
            else:
                error('Unknown certificate type. Aborting.', 1)

        certificate = builder.sign(
            private_key=self.ca_certbundle.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        self.next_serial += 1

        return certificate

    def store_certbundle(self, certbundle):
        """
        Store a certificate bundle into 1Password

        Args:
            certbundle (CertificateBundle): The certificate to store

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        item_title = certbundle.get_title()

        if certbundle.is_valid() and item_title not in self.ca_database_cn:
            self.add_ca_database_item(certbundle.certificate)

            attributes = [f'{self.op_config["cert_type_item"]}=' + \
                                f'{certbundle.get_type()}',
                          f'{self.op_config["cn_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("cn")}',
                          f'{self.op_config["subject_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("subject")}',
                          f'{self.op_config["key_item"]}=' + \
                                f'{certbundle.get_private_key()}',
                          f'{self.op_config["cert_item"]}=' + \
                                f'{certbundle.get_certificate()}',
                          f'{self.op_config["start_date_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("not_before")}',
                          f'{self.op_config["expiry_date_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("not_after")}',
                          f'{self.op_config["serial_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("serial")}',
                          f'{self.op_config["csr_item"]}=' + \
                                f'{certbundle.get_csr() or ""}'
            ]

            result = self.one_password.store_item(action='create',
                                     item_title=item_title,
                                     attributes=attributes)
        else:
            error('Certificate Object is invalid or already exists. Unable to store in 1Password', 1)

        return result

    def store_ca_database(self):
        """
        Store a CA certificate database into 1Password

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        attributes = [
            f'{DEFAULT_OP_CONF["next_serial_item"]}={self.next_serial}',
            f'{DEFAULT_OP_CONF["org_item"]}={self.ca_config.get("org", "")}',
            f'{DEFAULT_OP_CONF["email_item"]}={self.ca_config.get("email", "")}',
            f'{DEFAULT_OP_CONF["city_item"]}={self.ca_config.get("city", "")}',
            f'{DEFAULT_OP_CONF["state_item"]}={self.ca_config.get("state", "")}',
            f'{DEFAULT_OP_CONF["country_item"]}={self.ca_config.get("country", "")}',
            f'{DEFAULT_OP_CONF["ca_url_item"]}={self.ca_config.get("ca_url", "")}',
            f'{DEFAULT_OP_CONF["crl_url_item"]}={self.ca_config.get("crl_url", "")}',
            f'{DEFAULT_OP_CONF["days_item"]}={self.ca_config.get("days", "")}',
            f'{DEFAULT_OP_CONF["crl_days_item"]}={self.ca_config.get("crl_days", "")}',
        ]

        for cert in self.ca_database:
            attributes.append(f'{cert["serial"]}.cn[text]={cert["cn"]}')
            attributes.append(f'{cert["serial"]}.status[text]={cert["status"]}')
            attributes.append(f'{cert["serial"]}.expiry_date[text]={cert["expiry_date"]}')
            attributes.append(f'{cert["serial"]}.revocation_date[text]={cert["revocation_date"]}')
            attributes.append(f'{cert["serial"]}.subject[text]={cert["subject"]}')

        result = self.one_password.edit_or_create(item_title=self.op_config['ca_database_title'],
                                attributes=attributes)

        return result


class Op:
    """ Class to act on 1Password CLI """
    def __init__(self, account=None, binary=OP_BIN, vault=None):
        self.account = account
        self.vault = vault
        self.bin = binary

        if not os.path.isfile(self.bin) and os.access(self.bin, os.X_OK):
            error('Error: No 1Password-CLI executable. Is it installed?', 1)

        signin_command = [self.bin, 'signin']

        if self.account:
            signin_command.extend(['--account', self.account])

        result = run_command(signin_command)

        if result.returncode != 0:
            error(result.stderr, result.returncode)
            sys.exit(result.returncode)

    def edit_or_create(self, item_title, attributes):
        """
        CRUD helper. Store an item by either editing or creating

        Args:
            item_title (str): The title of the 1Password object
            attributes (dict): The object attributes to write to 1Password

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        result = self.store_item(action='edit',
                            item_title=item_title,
                            attributes=attributes)

        if result.returncode != 0:
            result = self.store_item(action='create',
                                item_title=item_title,
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

    def get_item(self, item_title, output_format='json'):
        """
        Retrieve the contents of an item at a given 1Password secrets url

        Args:
            item_title (str): The title of the 1Password object
            output_format (str): The format 1Password CLI should give

        Returns:
            subprocess.CompletedProcess

        Raises:
            None
        """

        result = run_command([self.bin, 'item', 'get', item_title, f'--vault={self.vault}',
                                                              f'--format={output_format}'])

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

        return bool(result.returncode == 0)

    def item_list(self, categories, output_format='json'):
        """
        List all items in the current vault

        Args:
            categories (str): A comma seperated list of 1Password categories 

        Returns:
            subprocess.CompletedProcess

        Raises:
            None
        """
        result = run_command([self.bin, 'item', 'list', f'--vault={self.vault}',
                                                        f'--categories={categories}',
                                                        f'--format={output_format}'])

        return result

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

    def mk_url(self, item_title, value_key=None):
        """
        Make a 1Password secret url from an item title and optional value

        Args:
            item_title (str): The 1Password item title
            value_key (str): The 1Password item key

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

    def store_document(self, item_title, filename, str_in, action='create'):
        """
        Store a document in 1Password

        Args:
            item_title (str): 1Password item title
            filename (str): The filename to store as metadata in 1Password
            str_in (str): The contents of a file to store as a document
            action (str): CRUD action

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if action == 'create':
            cmd = [self.bin, 'document', action, f'--title={item_title}',
                                                 f'--vault={self.vault}',
                                                 f'--file-name={filename}']
        else:
            error(f'Unknown storage command {action}', 1)

        result=run_command(cmd, str_in=str_in)

        return result

    def store_item(self, item_title, attributes, action='create', category='Secure Note'):
        """
        Store an item in 1Password

        Args:
            item_title (str): 1Password item title
            attributes (list): A list of strings containing the item attributes
            action (str): CRUD action
            category (str): The 1Password category to use. Secure Note is the default.

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if action == 'create':
            if not self.item_exists(item_title):
                cmd = [self.bin, 'item', action, f'--category={category}',
                                                 f'--title={item_title}',
                                                 f'--vault={self.vault}']
            else:
                error(f'Item {item_title} already exists. Aborting', 1)
        elif action == 'edit':
            cmd = [self.bin, 'item', action, f'{item_title}', f'--vault={self.vault}']
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
