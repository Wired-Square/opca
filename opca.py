#!/usr/bin/env python3
"""
#
# opca.py - 1Password Certificate Authority
#

A Python certificate authority implementation that uses pyca/cryptography (https://cryptography.io)
to generate keys and sign certificates, and then store them in 1Password.

The design contraints are
  - Keep this program as a single file (So we can store it easily in 1Password). This will likely be
    done with a tool like pyinstaller

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
- Implement a seperate CA Database class
- Increment the CRL serial number on generation
"""

import argparse
import base64
import os
import shutil
import secrets
from opca_lib.ca import CertificateAuthority
from opca_lib.op import Op
from opca_lib.op import DEFAULT_OP_CONF
from opca_lib.alerts import error, title, warning, print_result, print_cmd_result
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

# Configuration
OP_BIN = 'op'

# Constants
OPCA_VERSION        = "0.13.1"
OPCA_TITLE          = "1Password Certificate Authority"
OPCA_SHORT_TITLE    = "OPCA"
OPCA_AUTHOR         = "Alex Ferrara <alex@wiredsquare.com>"
OPCA_LICENSE        = "mit"

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

        title(f'Checking [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_title']))

        title(f'Validating [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(ca.is_valid())

        title(f'Checking [ {COLOUR_BRIGHT}Certificate Database{COLOUR_RESET} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_database_title']))

    elif action == 'import-ca':

        title('Importing a Certificate Authority from file', 3)

        title(f'Private Key [ {COLOUR_BRIGHT}{args.key_file}{COLOUR_RESET} ]', 9)
        imported_private_key = read_file(args.key_file)
        print_result(not is_empty(imported_private_key))

        title(f'Certificate [ {COLOUR_BRIGHT}{args.cert_file}{COLOUR_RESET} ]', 9)
        imported_certificate = read_file(args.cert_file)
        print_result(not is_empty(imported_certificate))

        if args.serial:
            next_serial = args.serial
        else:
            next_serial = x509.load_pem_x509_certificate(imported_certificate,
                                                      default_backend).serial_number

        title('The next available serial number is ' + \
            f'[ {COLOUR_BRIGHT}{next_serial}{COLOUR_RESET} ]', 7)

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

        title(f'Checking [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_title']))

        title(f'Validating [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
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
            title(f'Storing {COLOUR_BRIGHT}Certificate Database{COLOUR_RESET} into 1Password', 9)
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
        
        if 'alt' in args:
            cert_config['alt_dns_names'] = args.alt

        title(f'Generating a certificate bundle for {COLOUR_BRIGHT}{args.cn}{COLOUR_RESET}', 9)

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
            title(f'Private Key {COLOUR_BRIGHT}{args.key_file}{COLOUR_RESET}', 9)
            imported_private_key = read_file(args.key_file)
            print_result(not is_empty(imported_private_key))

            if not is_empty(imported_private_key):
                object_config['private_key'] = imported_private_key
        else:
            title('Importing without Private Key', 8)

        title(f'Certificate {COLOUR_BRIGHT}{args.cert_file}{COLOUR_RESET}', 9)
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
            f'{COLOUR_BRIGHT}{item_title}{COLOUR_RESET} in 1Password', 9)
        result = ca.store_certbundle(cert_bundle)
        print_cmd_result(result.returncode)

    elif action == 'revoke-cert':
        ca = prepare_certificate_authority(one_password)
        cert_info = {}

        if args.serial:
            cert_info['serial'] = args.serial
            desc = f'Serial: {args.serial}'
        else:
            cert_info['cn'] = args.cn
            desc = args.cn

        title(f'Revoking the certificate [ { COLOUR_BRIGHT }{ desc }{ COLOUR_RESET } ]', 8)

        if ca.revoke_certificate(cert_info=cert_info):
            print(ca.generate_crl())

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

        title(f'Reading the [ {COLOUR_BRIGHT}{url}{COLOUR_RESET} ] from 1Password', 9)

        result = one_password.read_item(url)
        print_cmd_result(result.returncode)

        if result.returncode == 0:
            print(result.stdout)

    elif action == 'import-dh':
        title('Importing a Diffie-Hellmnan parameters from file', 3)

        title(f'DH Parameters {COLOUR_BRIGHT}{args.file}{COLOUR_RESET}', 9)
        imported_ta_key = read_file(args.file).decode('UTF-8')
        print_result(not is_empty(imported_ta_key))

        key_size = dh_key_size_estimate(imported_ta_key)

        title(f'DH Key size is estimated at {COLOUR_BRIGHT}{key_size}{COLOUR_RESET} bits', 8)

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

        title(f'TA Key {COLOUR_BRIGHT}{args.file}{COLOUR_RESET}', 9)
        imported_ta_key = read_file(args.file).decode('UTF-8')
        print_result(not is_empty(imported_ta_key))

        key_size = ta_key_size(imported_ta_key)

        title(f'TA Key size is {COLOUR_BRIGHT}{key_size}{COLOUR_RESET} bits', 8)

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
            f'[ {COLOUR_BRIGHT}{args.template}{COLOUR_RESET} ] from 1Password', 9)

        result = one_password.read_item(url = one_password.mk_url(
                            item_title=DEFAULT_OP_CONF["openvpn_title"],
                            value_key=f'template/{args.template}'))
        print_cmd_result(result.returncode)

        if result.returncode == 0:
            ovpn_template = result.stdout
        else:
            error(result.stderr, result.returncode)

        title(f'Generating VPN profile for [ {COLOUR_BRIGHT}{args.cn}{COLOUR_RESET} ]', 9)
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

        print(f'1Password CLI - {COLOUR_BRIGHT}{OP_BIN}{COLOUR_RESET}', end='')
        result = is_file_executable(OP_BIN)
        print_result(result)

        bin_file = find_executable(OP_BIN)
        print(f'1Password CLI in path - {COLOUR_BRIGHT}{bin_file}{COLOUR_RESET}', end='')
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
    subparser_action_create_cert.add_argument('--alt', action='append', required=False,
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

    subparser_action_revoke_cert = parser_ca_actions.add_parser('revoke-cert',
            help='Create a new x509 CertificateBundle object')
    subparser_action_revoke_cert.add_argument('-a', '--account', required=False,
            help='1Password Account. Example: company.1password.com')
    subparser_action_revoke_cert.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_group_revoke_cert = subparser_action_revoke_cert.add_mutually_exclusive_group(required=True)
    subparser_group_revoke_cert.add_argument('-n', '--cn',
            help='x509 CN of the certificate to revoke')
    subparser_group_revoke_cert.add_argument('-s', '--serial',
            help='Serial number of the certificate to revoke')

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
