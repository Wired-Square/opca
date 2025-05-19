#!/usr/bin/env python3
"""
#
# opca.py - 1Password Certificate Authority
#

A Python certificate authority implementation that uses pyca/cryptography (https://cryptography.io)
to generate keys and sign certificates, and then store them in 1Password.

"""

import argparse
import json
import io
import os
import secrets
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_parameters
from cryptography.exceptions import InvalidSignature


# Constants
OPCA_VERSION        = '0.16.4'
OPCA_TITLE          = '1Password Certificate Authority'
OPCA_SHORT_TITLE    = 'OPCA'
OPCA_AUTHOR         = 'Alex Ferrara <alex@wiredsquare.com>'
OPCA_LICENSE        = 'mit'

COLOUR = {
'black': '\033[30m',
'red': '\033[31m',
'green': '\033[32m',
'yellow': '\033[33m',
'blue': '\033[34m',
'magenta': '\033[35m',
'cyan': '\033[36m',
'white': '\033[37m',
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
'bright_white': '\033[97m',
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

COLOUR_ERROR   = COLOUR['bold_red']
COLOUR_OK      = COLOUR['green']
COLOUR_BRIGHT  = COLOUR['bold_white']
COLOUR_WARNING = COLOUR['bold_yellow']
COLOUR_RESET   = COLOUR['reset']

DEFAULT_KEY_SIZE = {
    'ca': 4096,
    'dh': 2048,
    'ta': 2048,
    'vpnclient': 2048,
    'vpnserver': 2048,
    'webserver': 2048
}

DEFAULT_OP_CONF = {
    'category': 'Secure Note',
    'ca_title': 'CA',
    'ca_database_title': 'CA_Database',
    'ca_database_filename': 'ca-db-export.sql',
    'crl_title': 'CRL',
    'crl_filename': 'crl.pem',
    'openvpn_title': 'OpenVPN',
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
    'dh_item': 'diffie-hellman.dh_parameters',
    'dh_key_size_item': 'diffie-hellman.key_size[text]',
    'ta_item': 'tls_authentication.static_key',
    'ta_key_size_item': 'tls_authentication.key_size[text]'
}

OP_BIN = 'op'

STATUS_COLUMN  = 90

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

    error_colour = COLOUR_ERROR
    reset = COLOUR['reset']

    print(f'{error_colour}Error:{reset} {error_msg}')

    if exit_code != 0:
        sys.exit(exit_code)

def format_datetime(date, output_format='openssl'):
    """
    Format a datetime

    Args:
        date (datetime): The datetime object we are working with
        output_format (string, optional): The output format (openssl)

    Returns:
        str

    Raises:
        None
    """
    if output_format == 'openssl':
        format_string = '%Y%m%d%H%M%SZ'
    elif output_format == 'text':
        format_string = '%b %d %H:%M:%S %Y UTC'
    elif output_format == 'compact':
        format_string = '%H:%M %d %b %Y'
    else:
        error('Invalid date format', 1)

    return date.strftime(format_string)

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

def handle_ca_action(ca_action, cli_args):
    """
    Handle CA Actions called from the selection

    Args:
        ca_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('Certificate Authority', extra=ca_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=cli_args.vault)

    ca_config_attributes = [
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
    ]

    if ca_action == 'init':
        title('Initialising the Certificate Authority', 3)

        ca_config = {
            'command': 'init',
            'cn': cli_args.cn,
            'ca_days': cli_args.ca_days,
            'next_serial': 1,
            'next_crl_serial': 1,
            'key_size': DEFAULT_KEY_SIZE['ca']
        }

        for attr in ca_config_attributes:
            arg_value = getattr(cli_args, attr, None)
            if arg_value:
                ca_config[attr] = arg_value

        cert_authority = CertificateAuthority(one_password=one_password,
                                config=ca_config,
                                op_config=DEFAULT_OP_CONF)

        title(f'Checking [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_title']))

        title(f'Validating [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(cert_authority.is_valid())

        title(f'Checking [ {COLOUR_BRIGHT}Certificate Database{COLOUR_RESET} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_database_title']))

    elif ca_action == 'import':

        title('Importing a Certificate Authority from file', 3)

        title(f'Private Key [ {COLOUR_BRIGHT}{cli_args.key_file}{COLOUR_RESET} ]', 9)
        imported_private_key = read_file(cli_args.key_file)
        print_result(imported_private_key)

        title(f'Certificate [ {COLOUR_BRIGHT}{cli_args.cert_file}{COLOUR_RESET} ]', 9)
        imported_certificate = read_file(cli_args.cert_file)
        print_result(imported_certificate)

        if cli_args.serial:
            next_serial = cli_args.serial
        else:
            next_serial = x509.load_pem_x509_certificate(imported_certificate,
                                                      default_backend).serial_number + 1

        if cli_args.crl_serial:
            next_crl_serial = cli_args.crl_serial
        else:
            next_crl_serial = 1

        title('The next available serial number is ' + \
            f'[ {COLOUR_BRIGHT}{next_serial}{COLOUR_RESET} ]', 7)

        ca_config = {
            'command': 'import',
            'private_key': imported_private_key,
            'certificate': imported_certificate,
            'next_serial': next_serial,
            'next_crl_serial': next_crl_serial
        }

        for attr in ca_config_attributes:
            arg_value = getattr(cli_args, attr, None)
            if arg_value:
                ca_config[attr] = arg_value

        cert_authority = CertificateAuthority(one_password=one_password,
                                  config=ca_config,
                                  op_config=DEFAULT_OP_CONF)

        title(f'Checking [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(one_password.item_exists(DEFAULT_OP_CONF['ca_title']))

        title(f'Validating [ {COLOUR_BRIGHT}CA Certificate Bundle{COLOUR_RESET} ] in 1Password', 9)
        print_result(cert_authority.is_valid())

    elif ca_action == 'get-cert':
        cert_authority = prepare_cert_authority(one_password)

        print(cert_authority.get_certificate())

    elif ca_action == 'get-csr':
        url = one_password.mk_url(cli_args.cn, DEFAULT_OP_CONF['csr_item'])

        result = one_password.read_item(url)

        if result.returncode != 0:
            error(result.stderr, 1)

        print(result.stdout)

    else:
        error('This feature is not yet written', 99)

def handle_cert_action(cert_action, cli_args):
    """
    Handle x509 Certificate Actions called from the selection

    Args:
        cert_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """
    title('x509 Certificate', extra=cert_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=cli_args.vault)
    cert_authority = prepare_cert_authority(one_password)

    if cert_action == 'create':
        certs_to_create = []

        # TODO: This test should happen for each cert. If a file is provided, then this is bypassed
        if one_password.item_exists(cli_args.cn):
            error(f'CN {cli_args.cn} already exists. Aborting', 1)

        cert_config = cert_authority.ca_certbundle.get_config()
        cert_config['key_size'] = DEFAULT_KEY_SIZE[cli_args.cert_type]

        if cli_args.cn:
            cert_config['cn'] = cli_args.cn

            if cli_args.alt is not None:
                cert_config['alt_dns_names'] = cli_args.alt

            certs_to_create.append(cert_config)

        elif cli_args.file:
            for line in read_file(file_path=cli_args.file, file_mode='r').split('\n'):
                line = line.strip()

                if not line:
                    continue

                if line.startswith('#'):
                    continue

                tmp_config = cert_config.copy()

                hostnames = line.split('--alt')

                tmp_config['cn'] = hostnames[0].strip()

                if len(hostnames) > 1:
                    tmp_config['alt_dns_names'] = [alt.strip() for alt in hostnames[1:]]

                certs_to_create.append(tmp_config)

        else:
            error(f'Subcommand has not been written:  { cli_args }', 1)

        for cert_info in certs_to_create:
            title(f'Generating a certificate bundle for {COLOUR_BRIGHT}{cert_info["cn"]}{COLOUR_RESET}', 9)

            new_certificate_bundle = cert_authority.generate_certificate_bundle(
                cert_type=cli_args.cert_type,
                item_title=cert_info['cn'],
                config=cert_info)

            print_result(new_certificate_bundle.is_valid())

    elif cert_action == 'import':
        object_config = {
            'type': 'imported'
        }

        title('Importing a Certificate Bundle from file', 3)

        if cli_args.key_file:
            title(f'Private Key {COLOUR_BRIGHT}{cli_args.key_file}{COLOUR_RESET}', 9)
            imported_private_key = read_file(cli_args.key_file)
            print_result(imported_private_key)

            if imported_private_key:
                object_config['private_key'] = imported_private_key
        else:
            title('Importing without Private Key', 8)

        title(f'Certificate {COLOUR_BRIGHT}{cli_args.cert_file}{COLOUR_RESET}', 9)
        imported_certificate = read_file(cli_args.cert_file)
        print_result(imported_certificate)

        if imported_certificate:
            object_config['certificate'] = imported_certificate

        if cli_args.cn:
            item_title = cli_args.cn
        else:
            item_title = None

        cert_bundle = cert_authority.import_certificate_bundle(cert_type='imported',
                                                  config=object_config,
                                                  item_title=item_title)

        if not item_title:
            item_title = cert_bundle.get_certificate_attrib('cn')

        item_serial = cert_bundle.get_certificate_attrib('serial')

        if cert_authority.is_cert_valid(cert_bundle.certificate):
            prior_serial = cert_authority.ca_database.increment_serial(serial_type='cert',
                                                                       serial_number=item_serial)

            if prior_serial < item_serial:
                title('The next available serial number is ' + \
                      f'[ {COLOUR_BRIGHT}{item_serial + 1}{COLOUR_RESET} ]', 8)

            title('Storing certificate bundle for ' + \
                f'{COLOUR_BRIGHT}{item_title}{COLOUR_RESET} in 1Password', 9)
            result = cert_authority.store_certbundle(cert_bundle)
            print_result(result.returncode == 0)

        else:
            error('Certificate is not signed by this Certificate Authority', 1)

    elif cert_action == 'info':
        if cli_args.cn:
            cert_cn = cli_args.cn
            cert_serial = cert_authority.get_cert_serial_from_cn(cli_args.cn)

        elif cli_args.serial:
            cert_cn = cert_authority.get_cert_cn_from_serial(cli_args.serial)
            cert_serial = cli_args.serial

        else:
            error(f'Subcommand has not been written:  { cli_args }', 1)

        print(f'CA Database Entry: [ {COLOUR_BRIGHT}{cert_serial}{COLOUR_RESET} ] {cert_cn}')

        cert_bundle = cert_authority.retrieve_certbundle(cert_cn)

        certificate = cert_bundle.get_certificate()
        cert_type = cert_bundle.get_type()
        cert_issuer = cert_bundle.get_certificate_attrib('issuer')
        cert_subject = cert_bundle.get_certificate_attrib('subject')
        cert_subject_alt_name = cert_bundle.get_certificate_attrib('subject_alt_name')
        cert_expiry_date = cert_bundle.get_certificate_attrib('not_after')
        key_size = cert_bundle.get_public_key_size()
        key_type = cert_bundle.get_public_key_type()

        if cert_bundle.is_valid():
            cert_status = f'[ {COLOUR_OK}Valid{COLOUR_RESET} ]'

        print(f'Certificate Type: {cert_type} [ {COLOUR_OK}{key_type} {key_size}-bit key{COLOUR_RESET} ]')
        print(f'Subject: {cert_subject}')
        print(f'Issuer: {cert_issuer}')
        print(f'Status: {cert_status}')
        print(f'Expiry Date: {cert_expiry_date}')
        print(f'SAN: {cert_subject_alt_name}')
        print(certificate)

    elif cert_action == 'renew':
        certs_to_renew = []

        if cli_args.cn:
            certs_to_renew.append({'title': cli_args.cn})

        elif cli_args.serial:
            certs_to_renew.append({'serial': cli_args.serial})

        else:
            error(f'Subcommand has not been written:  { cli_args }', 1)

        for cert_info in certs_to_renew:
            title(f'Renewing the certificate [ { COLOUR_BRIGHT }{ cert_info['title'] }{ COLOUR_RESET } ]:', 6)

            print_result(success=cert_authority.renew_certificate_bundle(cert_info=cert_info))

    elif cert_action == 'revoke':
        certs_to_revoke = []

        if cli_args.serial:
            cert_info = {
                'serial': cli_args.serial,
            }

            certs_to_revoke.append(cert_info)

        elif cli_args.cn:
            cert_info = {
                'cn': cli_args.cn,
            }

            certs_to_revoke.append(cert_info)

        elif cli_args.file:
            for line in read_file(file_path=cli_args.file, file_mode='r').split('\n'):
                line = line.strip()

                if not line:
                    continue

                if line.startswith('#'):
                    continue

                cert_info = {
                    'cn': line.split('--alt')[0].strip(),
                }

                certs_to_revoke.append(cert_info)

        else:
            error(f'Subcommand has not been written:  { cli_args }', 1)

        for cert_info in certs_to_revoke:

            generate_crl = False

            if 'cn' in cert_info:
                desc = cert_info['cn']
            elif 'serial' in cert_info:
                desc = f'Serial: { cert_info["serial"] }'
            else:
                error('Certificate requires either a cn or serial', 1)

            title(f'Revoking the certificate [ { COLOUR_BRIGHT }{ desc }{ COLOUR_RESET } ]', 9)

            if cert_authority.revoke_certificate(cert_info=cert_info):
                print_result(success=True)
                generate_crl = True

            else:
                print_result(success=False)

        if generate_crl:
            print(cert_authority.generate_crl())

    else:
        error('This feature is not yet written', 99)

def handle_crl_action(crl_action, cli_args):
    """
    Handle CRL Actions called from the selection

    Args:
        crl_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('Certificate Revocation List', extra=crl_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=cli_args.vault)

    if crl_action == 'create':
        cert_authority = prepare_cert_authority(one_password)

        crl = cert_authority.generate_crl()

        title(f'Checking generated [ { COLOUR_BRIGHT }CRL Validity{ COLOUR_RESET } ]', 9)
        print_result(cert_authority.is_crl_valid(crl.encode('utf-8')))

        print(crl)

    elif crl_action == 'get':
        cert_authority = prepare_cert_authority(one_password)

        crl = cert_authority.get_crl()

        title(f'Checking retrieved [ { COLOUR_BRIGHT }CRL Validity{ COLOUR_RESET } ]', 9)
        print_result(cert_authority.is_crl_valid(crl.encode('utf-8')))

        print(crl)

    elif crl_action == 'import':
        cert_authority = prepare_cert_authority(one_password)

        title(f'Certificate Revocation List [ {COLOUR_BRIGHT}{cli_args.file}{COLOUR_RESET} ]', 9)
        imported_crl = read_file(cli_args.file)
        print_result(imported_crl)

        title(f'Checking retrieved [ { COLOUR_BRIGHT }CRL Validity{ COLOUR_RESET } ]', 9)
        print_result(cert_authority.import_crl(imported_crl))

        print("import da file")

    else:
        error('This feature is not yet written', 99)

def handle_database_action(db_action, cli_args):
    """
    Handle CA Database Actions called from the selection

    Args:
        db_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('CA Database', extra=db_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=cli_args.vault)
    certs_to_list = []

    if db_action == 'export':
        cert_authority = prepare_cert_authority(one_password)

        print(cert_authority.ca_database.export_database().decode('utf-8'))

    elif db_action == 'list':
        cert_authority = prepare_cert_authority(one_password)

        if cert_authority.ca_database.process_ca_database():
            warning('The CA database was changed in memory, but not saved. Maybe you should generate a CRL more often?')

        if cli_args.all:
            certs_to_list = sorted(
                cert_authority.ca_database.certs_expired |
                cert_authority.ca_database.certs_revoked |
                cert_authority.ca_database.certs_expires_soon |
                cert_authority.ca_database.certs_valid,
                key=int
            )

        elif cli_args.expired:
            certs_to_list = sorted(cert_authority.ca_database.certs_expired, key=int)

        elif cli_args.revoked:
            certs_to_list = sorted(cert_authority.ca_database.certs_revoked, key=int)

        elif cli_args.expiring:
            certs_to_list = sorted(cert_authority.ca_database.certs_expires_soon, key=int)

        elif cli_args.valid:
            certs_to_list = sorted(cert_authority.ca_database.certs_valid, key=int)

        elif cli_args.cn:
            certs_to_list = [cert_authority.get_cert_serial_from_cn(cli_args.cn)]

        elif cli_args.serial:
            certs_to_list = [cli_args.serial]

        else:
            error('This feature is not yet written', 99)

        headers = ["serial", "cn", "title", "status", "expiry_date", "revocation_date"]
        row_format = "{:<8} {:<35} {:<40} {:<10} {:<20} {:<20}"

        print(row_format.format(*headers))
        print("-" * 140)

        for line, cert_serial in enumerate(certs_to_list):
            cert = cert_authority.ca_database.query_cert(cert_info={'serial': cert_serial})

            if len(cert['cn']) > 35:
                cn = cert['cn'][:32] + "..."
            else:
                cn = cert['cn']

            expiry_str = format_datetime(
                date=datetime.strptime(cert['expiry_date'], "%Y%m%d%H%M%SZ"),
                output_format='compact'
            )

            if cert.get('revocation_date'):
                revocation_str = format_datetime(
                    date=datetime.strptime(cert['revocation_date'], "%Y%m%d%H%M%SZ"),
                    output_format='compact'
                )
            else:
                revocation_str = ''

            status_colours = {
                'Valid':   [COLOUR['green'], COLOUR['bold_green']],
                'Revoked': [COLOUR['red'], COLOUR['bold_red']],
                'Expired': [COLOUR['white'], COLOUR['bright_white']],
                'Expiring': [COLOUR['yellow'], COLOUR['bold_yellow']],
            }

            # Change the colour of 'Expiring' certificates
            if cert['status'] == 'Valid' and cert['serial'] in cert_authority.ca_database.certs_expires_soon:
                colours = status_colours.get('Expiring', [COLOUR['magenta'], COLOUR['bold_magenta']])
            else:
                colours = status_colours.get(cert['status'], [COLOUR['white'], COLOUR['bold_white']])

            colour = colours[line % 2]
            print(colour + row_format.format(cert['serial'],
                                    cn,
                                    cert['title'],
                                    cert['status'],
                                    expiry_str,
                                    revocation_str) + COLOUR_RESET)

    elif db_action == 'get-config':
        cert_authority = prepare_cert_authority(one_password)

        print(cert_authority.ca_database.get_config_attributes())

    elif db_action == 'rebuild':
        ca_config = {
            'command': 'rebuild-ca-database',
            'next_serial': cli_args.serial,
            'next_crl_serial': cli_args.crl_serial,
            'crl_days': cli_args.crl_days,
            'days': cli_args.days,
            'ca_url': cli_args.ca_url,
            'crl_url': cli_args.crl_url
        }

        cert_authority = CertificateAuthority(one_password=one_password,
                                config=ca_config,
                                op_config=DEFAULT_OP_CONF)

    elif db_action == 'set-config':
        cert_authority = prepare_cert_authority(one_password)

        config = {item.split('=')[0]: item.split('=')[1] for item in cli_args.conf}

        cert_authority.ca_database.update_config(config)

        cert_authority.store_ca_database()

        print(cert_authority.ca_database.get_config_attributes())

    else:
        error('This feature is not yet written', 99)

def handle_openvpn_action(openvpn_action, cli_args):
    """
    Handle OpenVPN Actions called from the selection

    Args:
        openvpn_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('OpenVPN', extra=openvpn_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=cli_args.vault)

    if openvpn_action == 'gen-dh':
        title('Generating DH parameters', 9)
        dh_parameters_pem = generate_dh_params()
        print_result(dh_parameters_pem)

        title('Verifying DH parameters', 9)
        dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
        print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

        title('Storing the DH parameters in 1Password', 9)
        attributes = [f'{ DEFAULT_OP_CONF["dh_item"] }={ dh_parameters_pem }',
                      f'{ DEFAULT_OP_CONF["dh_key_size_item"] }={ dh_keysize}'
                    ]

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                         attributes=attributes)

        print_result(result.returncode == 0)

        print(dh_parameters_pem)

    elif openvpn_action == 'gen-ta-key':
        title('Generate the OpenVPN TLS Authentication Key', 9)
        ta_key_pem = generate_ta_key()
        print_result(ta_key_pem)

        title('Verifying the TLS Authentication Key', 9)
        ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))

        if ta_keysize >= DEFAULT_KEY_SIZE['ta']:
            print_result(True)
        else:
            print_result(False)
            error('TLS Authentication Key is not suitable', 1)

        title('Storing the TLS Authentication Key in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={ ta_key_pem }',
                      f'{DEFAULT_OP_CONF["ta_key_size_item"]}={ ta_keysize }'
                      ]

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                         attributes=attributes)

        print_result(result.returncode == 0)

        print(ta_key_pem)

    elif openvpn_action == 'gen-vpn-profile':
        profiles_to_generate = []
        ovpn_templates = {}
 
        if cli_args.cn:
            profile_config = {
                'template': cli_args.template,
                'cn': cli_args.cn
            }

            profiles_to_generate.append(profile_config)
        elif cli_args.file:
            for line in read_file(file_path=cli_args.file, file_mode='r').split('\n'):
                line = line.strip()

                if not line:
                    continue

                if line.startswith('#'):
                    continue

                profile_config = {
                    'template': cli_args.template,
                    'cn': line
                }

                profiles_to_generate.append(profile_config)
        else:
            error(f'Subcommand has not been written:  { cli_args }', 1)

        for profile in profiles_to_generate:
            profile_template = profile.get('template')
            profile_cn = profile.get('cn')

            env_vars = os.environ.copy()
            env_vars['OPCA_USER'] = profile_cn

            if profile_template not in ovpn_templates:
                title('Reading VPN profile ' + \
                    f'[ {COLOUR_BRIGHT}{profile_template}{COLOUR_RESET} ] from 1Password', 9)

                result = one_password.read_item(url = one_password.mk_url(
                                    item_title=DEFAULT_OP_CONF["openvpn_title"],
                                    value_key=f'template/{profile_template}'))

                print_result(result.returncode == 0)

                if result.returncode == 0:
                    ovpn_templates[profile_template] = result.stdout
                else:
                    error(result.stderr, result.returncode)

            title(f'Generating VPN profile for [ {COLOUR_BRIGHT}{profile_cn}{COLOUR_RESET} ] with template [ {COLOUR_BRIGHT}{profile_template}{COLOUR_RESET} ]', 9)
            result = one_password.inject_item(env_vars=env_vars, template=ovpn_templates[profile_template])
            print_result(result.returncode == 0)

            if result.returncode != 0:
                error(result.stderr, result.returncode)

            if cli_args.dest:
                title(f'Storing VPN profile in 1Password vault [ {COLOUR_BRIGHT}{cli_args.dest}{COLOUR_RESET} ]', 9)
                result = one_password.store_document(op_action='create', item_title=f'VPN_{profile_cn}',
                            filename=f'{profile_cn}-{profile_template}.ovpn', str_in=result.stdout, vault=cli_args.dest)
            else:
                title('Storing VPN profile in 1Password', 9)
                result = one_password.store_document(op_action='create', item_title=f'VPN_{profile_cn}',
                            filename=f'{profile_cn}-{profile_template}.ovpn', str_in=result.stdout)

            print_result(result.returncode == 0)

            if result.returncode != 0:
                error(result.stderr, result.returncode)

    elif openvpn_action == 'get-dh':
        title('Reading the DH parameters from 1Password', 9)

        url = one_password.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        value_key=DEFAULT_OP_CONF["dh_item"].replace(".", "/"))

        result = one_password.read_item(url)
        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(f'Unable to read the dh parameters from { url }', 1)

        title('Verifying DH parameters', 9)
        dh_parameters_pem = result.stdout
        dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
        print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

        print(dh_parameters_pem)

    elif openvpn_action == 'get-ta-key':
        title('Reading the TLS Authentication Key from 1Password', 9)

        url = one_password.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        value_key=DEFAULT_OP_CONF["ta_item"].replace(".", "/"))

        result = one_password.read_item(url)
        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(f'Unable to read the TLS Authentication Key from { url }', 1)

        title('Verifying TLS Authentication Key', 9)
        ta_key_pem = result.stdout
        ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))
        print_result(ta_keysize >= DEFAULT_KEY_SIZE['ta'])

        print(ta_key_pem)

    elif openvpn_action == 'import-dh':
        file = cli_args.file

        title('Reading the DH Parameters from file', 9)
        dh_parameters_pem = read_file(file).decode('utf-8')
        print_result(dh_parameters_pem)

        if not dh_parameters_pem:
            error(f'Unable to read the dh parameters from { file }', 1)

        title('Verifying DH parameters', 9)
        dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
        print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

        title('Storing the DH Parameters in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["dh_item"]}={ dh_parameters_pem }',
                    f'{DEFAULT_OP_CONF["dh_key_size_item"]}={ dh_keysize }'
                    ]

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_result(result.returncode == 0)

        print(dh_parameters_pem)

    elif openvpn_action == 'import-ta-key':
        file = cli_args.file

        title('Reading the TLS Authentication Key from file', 9)
        ta_key_pem = read_file(file).decode('utf-8')
        print_result(ta_key_pem)

        if not ta_key_pem:
            error(f'Unable to read the dh parameters from { file }', 1)

        title('Verifying TLS Authentication Key', 9)
        ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))
        print_result(ta_keysize >= DEFAULT_KEY_SIZE['dh'])

        print(f'The TLS Authentication Key is { ta_keysize } bits')

        title('Storing the TLS Authentication Key in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={ ta_key_pem }',
                    f'{DEFAULT_OP_CONF["ta_key_size_item"]}={ ta_keysize }'
                    ]

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_result(result.returncode == 0)

    elif openvpn_action == 'gen-sample-vpn-server':
        title('Storing the sample OpenVPN configuration template', 9)

        base_url = f'op://{cli_args.vault}/{{}}'
        openvpn_title = f'{ DEFAULT_OP_CONF["openvpn_title"] }'

        client_url = base_url.format('$OPCA_USER/cn')
        hostname_url = base_url.format(f'{openvpn_title}/server/hostname')
        port_url = base_url.format(f'{openvpn_title}/server/port')
        cipher_url = base_url.format(f'{openvpn_title}/server/cipher')
        auth_url = base_url.format(f'{openvpn_title}/server/auth')
        ca_cert_url = base_url.format((f'{DEFAULT_OP_CONF["ca_title"]}/'
                                       f'{DEFAULT_OP_CONF["cert_item"]}'))
        cert_url = base_url.format(f'$OPCA_USER/{DEFAULT_OP_CONF["cert_item"]}')
        private_key_url = base_url.format(f'$OPCA_USER/{DEFAULT_OP_CONF["key_item"]}')
        tls_auth_url = base_url.format((f'{openvpn_title}/'
                                        f'{DEFAULT_OP_CONF["ta_item"].replace(".", "/")}'))

        attributes = ['server.hostname[text]=vpn.domain.com.au',
                    'server.port[text]=1194',
                    'server.cipher[text]=aes-256-gcm',
                    'server.auth[text]=sha256',
                    f'''template.sample[text]=#
# Client - {{{{ { client_url } }}}}
#

# Brought to you by Wired Square - www.wiredsquare.com

client
dev tun
proto udp
remote {{{{ { hostname_url } }}}} {{{{ { port_url } }}}}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher {{{{ { cipher_url } }}}}
auth {{{{ { auth_url } }}}}
verb 3
key-direction 1
mssfix 1300
<ca>
{{{{ { ca_cert_url } }}}}
</ca>
<cert>
{{{{ { cert_url } }}}}
</cert>
<key>
{{{{ { private_key_url } }}}}
</key>
<tls-auth>
{{{{ { tls_auth_url } }}}}
</tls-auth>
''']

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                          op_action='create', attributes=attributes)

        print_result(result.returncode == 0)

    else:
        error('This feature is not yet written', 99)

def parse_arguments(prog_desc):
    """
    Parses the arguments given at the command line

    Args:
        prog_desc (str): Progam description

    Returns:
        argparse.Namespace: Description of the return value.

    Raises:
        None
    """
    parser = argparse.ArgumentParser(description=prog_desc)

    parser.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    parser.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparsers = parser.add_subparsers(title='Commands', dest='selection',
                                                        required=True)

    setup_ca_subparser(subparsers)
    setup_cert_subparser(subparsers)
    setup_crl_subparser(subparsers)
    setup_database_subparser(subparsers)
    setup_openvpn_subparser(subparsers)

    return parser.parse_args()

def prepare_cert_authority(one_password):
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

    cert_authority = CertificateAuthority(one_password=one_password,
                            config=ca_config,
                            op_config=DEFAULT_OP_CONF)

    return cert_authority

def print_result(success, ok_msg='  OK  ', failed_msg='FAILED'):
    """
    Prints a ANSI success or failure message in a RedHat theme

    Args:
        success (bool): Success test condition
        ok_msg (str): OK message text
        failed_msg (str): Failed message text

    Returns:
        success (bool): A passthrough of the success

    Raises:
        None
    """

    column = f'\033[{STATUS_COLUMN}G'

    if success:
        msg = ok_msg
        msg_colour = COLOUR_OK
    else:
        msg = failed_msg
        msg_colour = COLOUR_ERROR

    print(f'{column}[ {msg_colour}{msg}{COLOUR_RESET} ]')

    return success

def read_file(file_path, file_mode='rb'):
    """
    Read the contents of a file

    Args:
        file_path (str): The file to be read
        file_mode (str): The method to open the file. Default is to Read as Bytes

    Returns:
        bytes: The contents of the file

    Raises:
        None
    """
    content = None

    try:
        with open(file_path, file_mode) as file:
            content = file.read()
    except FileNotFoundError:
        error(f"File '{file_path}' not found.", 1)
    except PermissionError:
        error(f"Permission denied for file '{file_path}'.", 1)
    except IOError as err:
        error(f"I/O error occurred while reading file '{file_path}': {err}", 1)

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
                                text=text, shell=shell, check=False)

        return result

    except FileNotFoundError:
        error(f'Command not found. Does { command[0] }it exist?', 1)
        sys.exit(1)

def setup_ca_subparser(subparsers):
    """
    Set up the subparser for Certificate Authority (CA) related commands.

    Args:
        subparsers (argparse._SubParsersAction): The subparsers object from the main parser.

    Returns:
        None

    Raises:
        None
    """

    parser_ca = subparsers.add_parser('ca', help='Perform Certificate Authority actions')
    parser_ca_actions = parser_ca.add_subparsers(title='Actions', dest='action',
                                                        required=True)

    subparser_action_init_ca = parser_ca_actions.add_parser('init',
        help='Initialise a 1Password Certificate Authority')
    subparser_action_init_ca.add_argument('-e', '--email', required=False,
        help='The email address to use in the certificate subject')
    subparser_action_init_ca.add_argument('-o', '--org', required=True,
        help='The organisation to use in the certificate subject')
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
        help='x509 Common Name attribute for the 1Password Certificate Authority')
    subparser_action_init_ca.add_argument('--ou', required=False,
        help='x509 Organisational Unit attribute for the 1Password Certificate Authority')
    subparser_action_init_ca.add_argument('--ca-url', required=False,
        help='The URL where we can find the CA certificate')
    subparser_action_init_ca.add_argument('--crl-url', required=False,
        help='The URL where we can find the Certificate Revocation List')

    subparser_action_import_ca = parser_ca_actions.add_parser('import',
        help='Import a 1Password Certificate Authority from file')
    subparser_action_import_ca.add_argument('-c', '--cert-file', required=True,
        help='Certificate file')
    subparser_action_import_ca.add_argument('-k', '--key-file', required=True,
        help='Private Key file')
    subparser_action_import_ca.add_argument('--days', required=True, type=int,
        help='The number of days the certificate should be valid for')
    subparser_action_import_ca.add_argument('--crl-days', required=True, type=int,
        help='The number of days a CRL should be valid for')
    subparser_action_import_ca.add_argument('--serial', required=False, type=int,
        help='CA next serial number')
    subparser_action_import_ca.add_argument('--crl-serial', required=False, type=int,
        help='Certificate Authority next CRL serial number')

    subparser_action_import_ca.add_argument('--ca-url', required=False,
        help='The URL where we can find the CA certificate')
    subparser_action_import_ca.add_argument('--crl-url', required=False,
        help='The URL where we can find the Certificate Revocation List')

    parser_ca_actions.add_parser('get-cert',
        help='Get the object CA Certificate')

    subparser_action_get_csr = parser_ca_actions.add_parser('get-csr',
        help='Get the Certificate Signing Request for a 1Password Certificate Bundle')
    subparser_action_get_csr.add_argument('-n', '--cn', required=True,
        help='x509 CN attribute for the 1Password Certificate Authority')

def setup_cert_subparser(subparsers):
    """
    Configure the x509 Certificate related subparser.

    Args:
        subparsers (argparse._SubParsersAction): The subparsers object from the main parser.

    Returns:
        None
    """
    parser_cert = subparsers.add_parser('cert', help='Perform x509 Certificate actions')
    parser_cert_actions = parser_cert.add_subparsers(title='Actions', dest='action',
                                                        required=True)

    subparser_action_create_cert = parser_cert_actions.add_parser('create',
        help='Create a new x509 CertificateBundle object')
    subparser_group_create_cert = subparser_action_create_cert.add_mutually_exclusive_group(
        required=True)
    subparser_group_create_cert.add_argument('-n', '--cn',
        help='CN attribute. Regular certificates use this for the 1Password title.')
    subparser_group_create_cert.add_argument('-f', '--file',
        help='Bulk host file')
    subparser_action_create_cert.add_argument('-t', '--cert-type', required=True,
        help='x509 Certificate type', choices=['vpnserver', 'vpnclient', 'webserver'])
    subparser_action_create_cert.add_argument('-s', '--serial', required=False, type=int,
        help='Certificate serial number or CA Certificate next serial number')
    subparser_action_create_cert.add_argument('--alt', action='append', required=False,
        help='Alternate CN.')

    subparser_action_import_cert = parser_cert_actions.add_parser('import',
        help='Create a new x509 CertificateBundle object')
    subparser_action_import_cert.add_argument('-c', '--cert-file', required=True,
        help='Certificate file')
    subparser_action_import_cert.add_argument('-k', '--key-file', required=False,
        help='Private Key file')
    subparser_action_import_cert.add_argument('-n', '--cn', required=False,
        help='x509 CN attribute for the 1Password Certificate Authority')

    subparser_action_info_cert = parser_cert_actions.add_parser('info',
        help='Show information of a x509 CertificateBundle object')
    subparser_group_info_cert = subparser_action_info_cert.add_mutually_exclusive_group(
        required=True)
    subparser_group_info_cert.add_argument('-n', '--cn',
        help='x509 CN attribute of the certificate to show')
    subparser_group_info_cert.add_argument('-s', '--serial', type=int,
        help='Serial number of the certificate to show')

    subparser_action_renew_cert = parser_cert_actions.add_parser('renew',
        help='Renew a x509 certificate, retaining the private key')
    subparser_group_renew_cert = subparser_action_renew_cert.add_mutually_exclusive_group(
        required=True)
    subparser_group_renew_cert.add_argument('-n', '--cn',
        help='x509 CN of the certificate to renew')
    subparser_group_renew_cert.add_argument('-s', '--serial', type=int,
        help='Serial number of the certificate to renew')

    subparser_action_revoke_cert = parser_cert_actions.add_parser('revoke',
        help='Create a new x509 CertificateBundle object')
    subparser_group_revoke_cert = subparser_action_revoke_cert.add_mutually_exclusive_group(
        required=True)
    subparser_group_revoke_cert.add_argument('-f', '--file',
        help='Bulk host file')
    subparser_group_revoke_cert.add_argument('-n', '--cn',
        help='x509 CN of the certificate to revoke')
    subparser_group_revoke_cert.add_argument('-s', '--serial', type=int,
        help='Serial number of the certificate to revoke')

def setup_crl_subparser(subparsers):
    """
    Configure the CRL-related subparser.

    Args:
        subparsers (argparse._SubParsersAction): The subparsers object from the main parser.

    Returns:
        None
    """
    parser_crl = subparsers.add_parser('crl', help='Perform CRL actions')
    parser_crl_actions = parser_crl.add_subparsers(title='Actions', dest='action',
                                                        required=True)

    parser_crl_actions.add_parser('create',
        help='Generate a Certificate Revokation List for the 1Password CA')

    parser_crl_actions.add_parser('get',
        help='Get the Certificate Revocation List from 1Password')

    subparser_action_import_crl = parser_crl_actions.add_parser('import',
        help='Import a previously generated Certificate Revocation List')
    subparser_action_import_crl.add_argument('-f', '--file', required=True,
        help='PEM formatted CRL file')

def setup_database_subparser(subparsers):
    """
    Set up the subparser for database related commands.

    Args:
        subparsers (argparse._SubParsersAction): The subparsers object from the main parser.

    Returns:
        None
    """

    parser_db = subparsers.add_parser('database',
        help='Perform Certificate Authority Database actions')
    parser_db_actions = parser_db.add_subparsers(title='Actions', dest='action',
                                                        required=True)

    parser_db_actions.add_parser('export',
        help='Export the entire CA SQLite database')

    parser_db_actions.add_parser('get-config',
        help='Get the current CA Database configuration')

    subparser_action_list_db = parser_db_actions.add_parser('list',
        help='List the certificates in the CA database.')
    subparser_group_create_cert = subparser_action_list_db.add_mutually_exclusive_group(
        required=True)
    subparser_group_create_cert.add_argument('-a', '--all', action='store_true',
        help='List all certificates')
    subparser_group_create_cert.add_argument('-e', '--expired', action='store_true',
        help='List all expired certificates')
    subparser_group_create_cert.add_argument('-r', '--revoked', action='store_true',
        help='List all revoked certificates')
    subparser_group_create_cert.add_argument('-x', '--expiring', action='store_true',
        help='List certificates expiring soon')
    subparser_group_create_cert.add_argument('-v', '--valid', action='store_true',
        help='List all valid certificates')
    subparser_group_create_cert.add_argument('-n', '--cn',
        help='List certificate with this cn')
    subparser_group_create_cert.add_argument('-s', '--serial',
        help='List certificate with this serial number')

    subparser_action_rebuild_db = parser_db_actions.add_parser('rebuild',
        help='Generate a Certificate Database for the 1Password CA')
    subparser_action_rebuild_db.add_argument('--days', required=True, type=int,
        help='The number of days the certificate should be valid for')
    subparser_action_rebuild_db.add_argument('--crl-days', required=True, type=int,
        help='The number of days a CRL should be valid for')
    subparser_action_rebuild_db.add_argument('--serial', required=False, type=int,
        help='Certificate Authority next serial number')
    subparser_action_rebuild_db.add_argument('--crl-serial', required=False, type=int,
        help='Certificate Authority next CRL serial number')
    subparser_action_rebuild_db.add_argument('--ca-url', required=False,
        help='The URL where we can find the CA certificate')
    subparser_action_rebuild_db.add_argument('--crl-url', required=False,
        help='The URL where we can find the Certificate Revocation List')

    subparser_action_set_config = parser_db_actions.add_parser('set-config',
        help='Modify the CA Database configuration')
    subparser_action_set_config.add_argument('--conf', action='append', required=True,
        help='Configuration attributes to modify. Example: --conf city=Canberra --conf days=30')

def setup_openvpn_subparser(subparsers):
    """
    Set up the subparser for OpenVPN related commands.

    Args:
        subparsers (argparse._SubParsersAction): The subparsers object from the main parser.

    Returns:
        None
    """

    parser_openvpn = subparsers.add_parser('openvpn', help='Perform OpenVPN actions')
    parser_openvpn_actions = parser_openvpn.add_subparsers(title='Actions', dest='action',
                                                                  required=True)

    parser_openvpn_actions.add_parser('gen-dh',
        help='Generate Diffie-Hellman parameters')

    subparser_action_import_dh = parser_openvpn_actions.add_parser('import-dh',
        help='Importa Diffie-Hellman parameters from file')
    subparser_action_import_dh.add_argument('-f', '--file', required=True,
        help='Diffie-Hellman parameters file')

    parser_openvpn_actions.add_parser('get-dh',
        help='Retrieve Diffie-Hellman parameters from 1Password')

    parser_openvpn_actions.add_parser('get-ta-key',
        help='Retrieve Diffie-Hellman parameters from 1Password')

    parser_openvpn_actions.add_parser('gen-ta-key',
        help='Generate a TLS Authentication Static Key')

    subparser_action_import_ta_key = parser_openvpn_actions.add_parser('import-ta-key',
        help='Importa a TLS Authentication Static Key from file')
    subparser_action_import_ta_key.add_argument('-f', '--file', required=True,
        help='TLS Authentication static key file')

    subparser_action_gen_vpn_profile = parser_openvpn_actions.add_parser('gen-vpn-profile',
        help='Generate VPN profile from template')
    subparser_action_gen_vpn_profile.add_argument('-d', '--dest', required=False,
        help='The destination vault to store the VPN profile')

    subparser_group_gen_vpn_profile = subparser_action_gen_vpn_profile.add_mutually_exclusive_group(
        required=True)
    subparser_group_gen_vpn_profile.add_argument('-f', '--file',
        help='Bulk certificate CN file')
    subparser_group_gen_vpn_profile.add_argument('-n', '--cn',
        help='The certificate CN. This is also the 1Password title')
    subparser_action_gen_vpn_profile.add_argument('-t', '--template', required=True,
        help='OpenVPN template stored in 1Password')

    parser_openvpn_actions.add_parser(
        'gen-sample-vpn-server',
        help='Generate a sample OpenVPN object in 1Password')

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

    title_colour = COLOUR['cyan']

    highlight_colour = COLOUR_BRIGHT
    reset = COLOUR_RESET

    if level == 1:
        title_colour = COLOUR['bold_yellow']

        if extra is None:
            extra = '---===oooO'

        print(f'{extra} {title_colour}{text}{reset} {extra[::-1]}\n')

    elif level == 2:
        title_colour = COLOUR['bold_yellow']

        if extra is not None:
            print(f'{title_colour}{text}{reset} [ {highlight_colour}{extra}{reset} ]\n')
        else:
            print(f'{title_colour}{text}{reset}\n')

    elif level == 3:
        title_colour = COLOUR['bold_white']

        print(f'{title_colour}{text}{reset}\n')

    elif level == 4:
        title_colour = COLOUR['underline_white']

        print(f'{title_colour}{text}{reset}\n')

    elif level == 6:
        print(f'{text}\n')

    elif level == 7:
        print(f'{text}')

    elif level == 8:
        print(f'{text}...')

    elif level == 9:
        print(f'{text}...', end='')

    else:
        print(f'{title_colour}{text}{reset}\n')

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

    error_colour = COLOUR_WARNING
    reset = COLOUR['reset']

    print(f'{error_colour}Warning:{reset} {warning_msg}')


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
        self.one_password = one_password
        self.op_config = op_config
        self.crl = None

        if config['command'] == 'init':
            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 1)

            self.ca_database = CertificateAuthorityDB(config)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=False,
                                      config=config)

            self.ca_database.increment_serial('cert')

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'import':
            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 0)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=True,
                                      config=config)

            self.ca_database = CertificateAuthorityDB(self.ca_certbundle.config)

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'retrieve':
            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 0)

            result = self.one_password.get_document(self.op_config['ca_database_title'])

            if result.returncode == 0:
                ca_database_sql = result.stdout

            self.ca_database = CertificateAuthorityDB(data=ca_database_sql)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

        elif config['command'] == 'rebuild-ca-database':
            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 1)

            if self.one_password.item_exists(self.op_config['ca_database_title']):
                error('CA database exists. Aborting', 1)

            self.ca_database = CertificateAuthorityDB(config)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            self.ca_database.update_config(self.ca_certbundle.get_config())

            self.rebuild_ca_database()

        else:
            error('Unknown CA command', 0)

    def delete_certbundle(self, item_title, archive=True):
        """
        Delete a certificate bundle in 1Password

        Args:
            item_title (str): The 1Password object that contains a certificate bundle
            archive (bool): Archive the item in 1Password. Defaults to True

        Returns:
            bool: True if the update succeeded, False otherwise.

        Raises:
            None
        """
        db_item = self.ca_database.query_cert(cert_info={'title': item_title},
                                              valid_only=False)

        if self.ca_database.update_cert(db_item):
            return self.one_password.delete_item(item_title=item_title, archive=archive)

        return False

    def format_db_item(self, certificate, item_title=None):
        """
        Format a certificate db item from a certificate

        Args:
            certificate: cryptography.hazmat.bindings._rust.x509.Certificate
            item_title (str): The storage title of the certificate bundle

        Returns:
            list

        Raises:
            None
        """

        expired = datetime.now(timezone.utc) > certificate.not_valid_after_utc

        if expired:
            status = 'Expired'
        else:
            status = 'Valid'

        cert_db_item = {
            'serial': certificate.serial_number,
            'cn': certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'title': item_title,
            'status': status,
            'expiry_date': format_datetime(certificate.not_valid_after_utc),
            'subject': certificate.subject.rfc4514_string()
        }

        return cert_db_item

    def get_certificate(self):
        """
        Returns the CA certificate in PEM format

        Args:
            None

        Returns:
            str

        Raises:
            None
        """
        return self.ca_certbundle.get_certificate()

    def get_cert_cn_from_serial(self, serial):
        """
        Searches for a certificate by serial number and returns the certificate name

        Args:
            cert_serial (int)

        Returns:
            cert_cn (str)

        Raises:
            None
        """

        cert_info = {'serial': serial}

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            error(f'Certificate with { cert_info } not found. Aborting', 0)
            return False

        return cert['cn']

    def get_cert_serial_from_cn(self, cn):
        """
        Searches for a certificate by certificate name and returns the serial number

        Args:
            cert_cn (str)

        Returns:
            cert_serial (int)

        Raises:
            None
        """

        cert_info = {'cn': cn}

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            error(f'Certificate with { cert_info } not found. Aborting', 0)
            return False

        return cert['serial']

    def get_crl(self):
        """
        Returns the Certificate Signing Request stored in 1Password in PEM format

        Args:
            None

        Returns:
            str

        Raises:
            None
        """

        if self.crl is None:
            result = self.one_password.get_document(self.op_config['crl_title'])

            if result.returncode == 0:
                self.crl = result.stdout

        return self.crl

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

        self.ca_database.process_ca_database()

        crl_days = self.ca_database.get_config_attributes()['crl_days']

        builder = x509.CertificateRevocationListBuilder()

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                self.ca_certbundle.get_certificate_attrib('cn')),
        ]))

        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(crl_days))

        crl_serial = self.ca_database.increment_serial('crl')
        builder = builder.add_extension(x509.CRLNumber(crl_serial), critical=False)

        for cert_serial in self.ca_database.certs_revoked:
            cert_info = {
                'serial': cert_serial
            }

            cert_db_record = self.ca_database.query_cert(cert_info=cert_info, valid_only=False)

            serial_number = int(cert_serial)
            revocation_date = datetime.strptime(cert_db_record['revocation_date'], '%Y%m%d%H%M%SZ')

            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                serial_number).revocation_date(revocation_date).build(default_backend())
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_certbundle.private_key, hashes.SHA256(), default_backend())

        self.crl = crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        result = self.one_password.store_document(op_action='auto',
                        item_title=self.op_config['crl_title'],
                        filename=self.op_config['crl_filename'],
                        str_in=self.crl)

        if result.returncode != 0:
            error(result.stderr, 1)

        result = self.store_ca_database()

        if result.returncode != 0:
            error(result.stderr, 1)

        return self.crl

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

        signed_certificate = self.sign_certificate(csr=csr, target=cert_type)

        cert_bundle.update_certificate(signed_certificate)

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

        title(f'Checking [ { COLOUR_BRIGHT }{ item_title }{ COLOUR_RESET } ] certificate bundle', 9)

        cert_valid = obj.is_valid()

        if obj.private_key:
            print_result(cert_valid)

            if obj.get_certificate_attrib('serial') in self.ca_database.certs_expires_soon:
                warning(f'Certificate { item_title } is expiring soon')
        else:
            print_result(False, failed_msg='NOPRIV')

        if item_title == DEFAULT_OP_CONF['ca_title'] and not cert_valid:
            error('CA Certificate is not valid. This is quite serious.', 1)

        return obj

    def import_crl(self, crl_pem):
        """
        Imports a certificate revocation list from a variable

        Args:
            crl_pem (bytes): The PEM encoded CRL.

        Returns:
            CertificateBundle

        Raises:
            None
        """
        print(crl_pem)

    def is_cert_valid(self, certificate):
        """
        Check if a certificate is valid and was signed by the CA certificate.

        Args:
            certificate (x509.Certificate): The certificate to check.

        Returns:
            bool: True if the certificate is valid and was signed by the CA, False otherwise.
        """
        ca_cert = self.ca_certbundle.certificate

        # 1. Signature Verification
        try:
            ca_cert.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )
        except InvalidSignature:
            return False

        # 2. Date Validity
        current_date = datetime.now(timezone.utc)
        if certificate.not_valid_before <= current_date <= certificate.not_valid_after:
            return True

        return False

    def is_crl_valid(self, crl_pem):
        """
        Check if a CRL is valid.

        Args:
            crl_pem (bytes): The PEM encoded CRL.

        Returns:
            bool: True if the CRL is valid, False otherwise.
        """
        crl = x509.load_pem_x509_crl(crl_pem, default_backend())
        ca_cert = self.ca_certbundle.certificate

        # 1. Signature Verification
        try:
            ca_cert.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm
            )
        except InvalidSignature:
            return False

        # 2. Date Validity
        current_date = datetime.now(timezone.utc)
        if crl.last_update_utc <= current_date <= crl.next_update_utc:
            return True

        return False

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

                if cert_serial in result_dict:
                    warning(f'Duplicate serial number [ '
                            f'{ COLOUR_BRIGHT }{ cert_serial }{ COLOUR_RESET } ] in CA Database')

                result_dict[cert_serial] = {'cert': cert_bundle.certificate,
                                            'title': item_title}

        for serial, attrs in sorted(result_dict.items()):
            self.ca_database.add_cert(self.format_db_item(certificate=attrs['cert'],
                                                          item_title=attrs['title']))

            if serial > max_serial:
                max_serial = serial + 0

        next_serial = self.ca_database.get_config_attributes()['next_serial']

        if next_serial:
            if max_serial >= next_serial:
                warning(f'The next serial is { next_serial } '
                        f'but the largest serial number seen is { max_serial }')

        else:
            next_serial = max_serial + 1
            self.ca_database.update_config({'next_serial': next_serial})

        title(f'Next serial is [ { COLOUR_BRIGHT }{ next_serial }{ COLOUR_RESET } ]', 7)
        title(f'Total certificates in database is [ '
              f'{ COLOUR_BRIGHT }{ self.ca_database.count_certs() }{ COLOUR_RESET } ]', 7)

        self.store_ca_database()

    def rename_certbundle(self, src_item_title, dst_item_title):
        """
        Renames a certificate bundle in 1Password

        Args:
            src_item_title (str): The 1Password object that contains a certificate bundle
            dst_item_title (str): The new 1Password object that contains a certificate bundle

        Returns:
            bool: True if the update succeeded, False otherwise.

        Raises:
            None
        """
        db_item = self.ca_database.query_cert(cert_info={'title': src_item_title},
                                              valid_only=False)

        db_item['title'] = dst_item_title

        result = self.one_password.rename_item(src_item_title=src_item_title,
                                               dst_item_title=dst_item_title)

        if result.returncode != 0:
            error(f'Unable to rename the item {src_item_title} to {dst_item_title}', 1)
            return False

        if self.ca_database.update_cert(db_item) and self.store_ca_database().returncode == 0:
            return True

        return False

    def renew_certificate_bundle(self, cert_info):
        """
        Renew a previously signed certificate from the stored CSR

        Args:
            cert_info (dict): key - The certificate attribute (cn or serial)
                            value - The attribute data

        Returns:
            bool

        Raises:
            None
        """

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            error(f'Certificate with { cert_info } not found. Aborting', 0)
            return False

        item_serial = cert['serial']
        item_title = cert['title']

        if item_title == item_serial:
            error(f'You cannot renew a certificate that has already been acted on', 1)

        cert_bundle = self.retrieve_certbundle(item_title=item_title)

        pem_csr = cert_bundle.get_csr().encode('utf-8')
        cert_type = cert_bundle.get_type()

        csr = x509.load_pem_x509_csr(pem_csr, default_backend())

        signed_cert = self.sign_certificate(csr=csr, target=cert_type)

        if cert_bundle.update_certificate(signed_cert):
            print_result(success=True)

        print(cert_bundle.get_certificate())

        if item_title != str(item_serial):
            if self.rename_certbundle(src_item_title=item_title,
                                    dst_item_title=str(item_serial)):
                pass
            else:
                error(f'Unable to rename the certificate bundle', 1)
        else:
            error(f'Item title and serial are the same. This should never happen.', 1)

        if self.store_certbundle(certbundle=cert_bundle).returncode == 0:
            if self.store_ca_database().returncode == 0:
                pass
            else:
                error(f'Unable to store the CA Database', 1)

        else:
            error(f'Unable to store the new certificate bundle', 1)

        return True

    def retrieve_certbundle(self, item_title):
        """
        Imports a certificate bundle from 1Password

        Args:
            item_title (str): The 1Password object that contains a certificate bundle

        Returns:
            CertificateBundle if the retrieved object is a certificate bundle, otherwise None

        Raises:
            None
        """
        cert_config = {}
        cert_type = None

        result = self.one_password.get_item(item_title)

        if result.returncode != 0:
            error('Something went wrong retrieving the certificate bundle', 0)

        loaded_object = json.loads(result.stdout)

        for field in loaded_object['fields']:
            if field['label'] == 'certificate':
                cert_config['certificate'] = field['value'].encode('utf-8')
            elif field['label'] == 'private_key' and 'value' in field:
                cert_config['private_key'] = field['value'].encode('utf-8')
            elif field['label'] == 'certificate_signing_request' and 'value' in field:
                cert_config['csr'] = field['value'].encode('utf-8')
            elif field['label'] == 'type':
                cert_config['cert_type'] = field['value']
                cert_type = field['value']
            elif field['label'] == 'revocation_date' and 'value' in field:
                cert_config['revocation_date'] = field['value']

        if 'certificate' not in cert_config:
            return None

        return self.import_certificate_bundle(cert_type=cert_type,
                                              item_title=item_title,
                                              config=cert_config)

    def revoke_certificate(self, cert_info):
        """
        Revokes a previously signed certificate

        Args:
            cert_info (dict): key - The certificate attribute (cn or serial)
                            value - The attribute data

        Returns:
            bool

        Raises:
            None
        """

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            error(f'Certificate with { cert_info } not found. Aborting', 0)
            return False

        item_serial = cert['serial']
        item_title = cert['title']

        if self.ca_database.process_ca_database(revoke_serial=item_serial):

            self.store_ca_database()

            if item_title != str(item_serial):
                result = self.rename_certbundle(src_item_title=item_title,
                                                dst_item_title=str(item_serial))

                if not result:
                    error(f'Unable to rename the certificate bundle { item_title } '
                          f'[ { item_serial } ]', 1)

                return result

            return True

        return False

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

        ca_config = self.ca_database.get_config_attributes()
        ca_public_key = self.ca_certbundle.private_key.public_key()
        certificate_serial = self.ca_database.increment_serial('cert')
        delta = timedelta(ca_config['days'])

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_certbundle.certificate.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc) + delta)
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_public_key),
                critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(ca_public_key)),
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

                common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                dns_names = [x509.DNSName(common_name)]

                try:
                    san = csr.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                    dns_names.extend([name for name in san if isinstance(name, x509.DNSName)])

                    combined_san = x509.SubjectAlternativeName(dns_names)

                    builder = builder.add_extension(combined_san, critical=False)

                except x509.ExtensionNotFound:
                    builder = builder.add_extension(x509.SubjectAlternativeName(dns_names),
                                                     critical=False)

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in ca_config and ca_config['crl_url']:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(ca_config['crl_url'])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in ca_config and ca_config['ca_url']:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(ca_config['ca_url'])
                        )
                    ]

                    builder = builder.add_extension(
                        x509.AuthorityInformationAccess(aia_access_descriptions),
                        critical=False)
            else:
                error('Unknown certificate type. Aborting.', 0)

        certificate = builder.sign(
            private_key=self.ca_certbundle.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate

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

        result = self.one_password.store_document(op_action='auto',
                        item_title=self.op_config['ca_database_title'],
                        filename=self.op_config['ca_database_filename'],
                        str_in=self.ca_database.export_database().decode('utf-8'))

        return result

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
        item_serial = certbundle.certificate.serial_number

        if not certbundle.is_valid():
            error('Certificate Bundle is not valid', 1)

        if self.ca_database.query_cert(cert_info={'title': item_title},
                                        valid_only=True) is not None:
            # Certificate 'title' must be unique.
            # Certificate 'cn' does not need to be unique
            error('Certificate with a duplicate name exists', 0)
            return False

        if self.ca_database.query_cert(cert_info={'serial': item_serial},
                                        valid_only=True) is not None:
            # Certificate 'serial' must be unique.
            error('Certificate with a duplicate serial number exists', 0)
            return False

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
                            f'{ item_serial }',
                        f'{self.op_config["csr_item"]}=' + \
                            f'{certbundle.get_csr() or ""}'
        ]

        result = self.one_password.store_item(op_action='create',
                                    item_title=item_title,
                                    attributes=attributes)

        if self.ca_database.add_cert(self.format_db_item(certificate=certbundle.certificate,
                                                         item_title=item_title)):
            self.store_ca_database()

        return result


class CertificateAuthorityDB:
    """ Class to manage a database for the CA in SQLite """

    _default_schema_version = 2

    @property
    def default_schema_version(self):
        """ Return the schema version """
        return self._default_schema_version

    def __init__(self, config=None, data=None):
        """
        Construct a certificate authority db object.

        Args:
            data (dict): The ca_config dict that may contain a previous database backup

        Returns:
            None
        """
        self.certs_expired = set()
        self.certs_expires_soon = set()
        self.certs_revoked = set()
        self.certs_valid = set()
        self.conn = sqlite3.connect(':memory:')
        self.config_attrs = (
            'next_serial',
            'next_crl_serial',
            'org',
            'ou',
            'email',
            'city',
            'state',
            'country',
            'ca_url',
            'crl_url',
            'days',
            'crl_days',
            'schema_version'
        )

        if data:
            self.import_database(data)

        else:
            # Build a shiny new DB from config
            self.create_config_table(config)
            self.create_ca_table()

    def add_cert(self, cert_db_item):
        """
        Add a certificate record to the database

        Args:
            cert_db_item (dict): A structure of the certificate record to add

        Returns:
            bool:  True if the insert succeeded, False otherwise
        """
        cert_db_item['serial'] = str(cert_db_item['serial'])
        cursor = self.conn.cursor()

        columns = ', '.join(cert_db_item.keys())
        placeholders = ', '.join(['?'] * len(cert_db_item))
        sql = f"INSERT INTO certificate_authority ({columns}) VALUES ({placeholders})"

        try:
            cursor.execute(sql, tuple(cert_db_item.values()))
            self.conn.commit()
            return True

        except sqlite3.Error as sqlite_error:
            error(f'SQLite error: {sqlite_error}', 1)
            return False

    def create_ca_table(self):
        """ Create a table to track certificates """
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_authority (
                serial TEXT PRIMARY KEY,
                cn TEXT,
                title TEXT,
                status TEXT,
                expiry_date TEXT,
                revocation_date TEXT,
                subject TEXT
            )
        ''')
        self.conn.commit()
        cursor.close()

    def create_config_table(self, config):
        """
        Create and populate the CA configuration table

        Args:
            config (dict): The config data to insert

        Returns:
            bool
        
        Raises:
            None
        """

        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                next_serial TEXT,
                next_crl_serial TEXT,
                org TEXT,
                ou TEXT,
                email TEXT,
                city TEXT,
                state TEXT,
                country TEXT,
                ca_url TEXT,
                crl_url TEXT,
                days INTEGER,
                crl_days INTEGER,
                schema_version INTEGER
            )
        ''')
        self.conn.commit()

        for key in self.config_attrs:
            if key in config and config[key] is None:
                config[key] = ''

        if 'next_serial' in config:
            config['next_serial'] = str(config['next_serial'])
        if 'next_crl_serial' in config:
            config['next_crl_serial'] = str(config['next_crl_serial'])

        if config['command'] == 'rebuild-ca-database':
            if config['next_crl_serial']:
                config['next_crl_serial'] = 1

        filtered_dict = {k: config[k] for k in self.config_attrs if k in config}

        filtered_dict['id'] = 1
        filtered_dict['schema_version'] = self.default_schema_version

        columns = ', '.join(filtered_dict.keys())
        placeholders = ', '.join(['?'] * len(filtered_dict))
        sql = f"INSERT INTO config ({columns}) VALUES ({placeholders})"

        cursor.execute(sql, tuple(filtered_dict.values()))
        self.conn.commit()

        cursor.close()

    def count_certs(self):
        """
        Count the number of certificates in the database.

        Returns:
            int: The number of certificates.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM certificate_authority")
        count = cursor.fetchone()[0]
        return count

    def export_database(self):
        """ Export the entire database to a io.BytesIO object """

        memory_file = io.BytesIO()

        for line in self.conn.iterdump():
            memory_file.write(line.encode('utf-8'))

        return memory_file.getvalue()

    def get_config_attributes(self, attrs=None):
        """
        Retrieve config attributes from the database.

        Args:
            attrs (tuple): The config attributes to retrieve

        Returns:
            dict: Attribute names as keys and their values from the database as values.
        """
        try:
            cursor = self.conn.cursor()

            if attrs is None:
                attrs = self.config_attrs

            columns = ', '.join(attrs)
            sql = f'SELECT {columns} FROM config LIMIT 1'

            cursor.execute(sql)
            row = cursor.fetchone()

            if row:
                result = dict(zip(attrs, row))

                if 'next_serial' in attrs:
                    try:
                        result['next_serial'] = int(result['next_serial'])

                    except ValueError:
                        result['next_serial'] = None

                if 'next_crl_serial' in attrs:
                    try:
                        result['next_crl_serial'] = int(result['next_crl_serial'])

                    except ValueError:
                        result['next_crl_serial'] = None

                return result

            return None

        except sqlite3.OperationalError:
            print('Error retrieving config attributes')
            return None

        finally:
            cursor.close()

    def import_database(self, data):
        """
        Imports the database from a previous export, and update the schema if required

        Args:
            data (bytes): The SQLite database backup to import

        Returns:
            None
        
        Raises:
            ValueError
        """

        self.conn.executescript(data)

        schema_version = self.get_config_attributes(attrs=('schema_version',))['schema_version']

        if schema_version < self.default_schema_version:
            title('Updating database schema from ' + \
                  f'[ {COLOUR_BRIGHT}{schema_version}{COLOUR_RESET} ] to ' + \
                  f'[ {COLOUR_BRIGHT}{self.default_schema_version}{COLOUR_RESET} ]', 8)

            cursor = self.conn.cursor()

            if schema_version == 1:
                title('Updating schema to version 2', 9)

                try:
                    cursor.execute('ALTER TABLE config ADD COLUMN ou TEXT;')
                    cursor.execute('UPDATE config SET schema_version=2 WHERE id=1;')
                    self.conn.commit()

                    schema_version = 2
                    print_result(True)

                except sqlite3.OperationalError:
                    print_result(False)

    def increment_serial(self, serial_type, serial_number=None):
        """
        Returns the next available serial number, and increments it in the database

        Args:
            serial_type (str): The type of serial to act on. Either 'cert' or 'crl'

        Returns:
            (int) The current next serial number value
        
        Raises:
            ValueError
        """
        cursor = self.conn.cursor()

        if serial_type == 'cert':
            column_name = 'next_serial'

        elif serial_type == 'crl':
            column_name = 'next_crl_serial'

        else:
            raise ValueError("Invalid serial type. Expected 'cert' or 'crl'.")

        cursor.execute(f"SELECT { column_name } FROM config LIMIT 1")
        current_value = int(cursor.fetchone()[0])

        if serial_number and current_value < serial_number:
            next_serial = serial_number + 1
        else:
            next_serial = current_value + 1

        cursor.execute(f"UPDATE config SET { column_name } = { next_serial }")

        self.conn.commit()
        cursor.close()

        return current_value

    def process_ca_database(self, revoke_serial=None):
        """
        Process the CA database.
         - The status of certifiates might change due to time
         - Gather a list of
           - Expired Certificates
           - Revoked Certificates
           - Certificates expiring soon
           - Valid Certificates

        Args:
            revoke_serial (int, optional): Serial number of the certificate to revoke.

        Returns:
            bool: Did the database change post-processing

        Raises:
            None
        """
        db_changed = False
        self.certs_expired = set()
        self.certs_expires_soon = set()
        self.certs_revoked = set()
        self.certs_valid = set()
        expiry_warning_days = 30

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM certificate_authority")
        all_certs = cursor.fetchall()

        columns = [desc[0] for desc in cursor.description]
        all_cert_dicts = [dict(zip(columns, cert)) for cert in all_certs]

        for cert in all_cert_dicts:
            cert_changed = False

            expiry_date = datetime.strptime(cert['expiry_date'], '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)

            expired = datetime.now(timezone.utc) > expiry_date

            expires_soon = datetime.now(timezone.utc) + timedelta(expiry_warning_days) > expiry_date
            revoked = bool(cert['revocation_date']) or (cert['status'] == 'Revoked')

            if revoke_serial is not None:
                if not expired and not revoked and revoke_serial == cert['serial']:
                    revoked = True
                    cert_changed = True
                    db_changed = True
                    cert['revocation_date'] = format_datetime(datetime.now(timezone.utc))

            if expired:
                if cert['status'] != 'Expired':
                    cert_changed = True
                    db_changed = True
                    cert['status'] = 'Expired'

                self.certs_expired.add(cert['serial'])

            elif revoked:
                if cert['status'] != 'Revoked':
                    cert_changed = True
                    db_changed = True
                    cert['status'] = 'Revoked'

                self.certs_revoked.add(cert['serial'])

            elif expires_soon:
                self.certs_expires_soon.add(cert['serial'])

            else:
                self.certs_valid.add(cert['serial'])

            if cert_changed:
                self.update_cert(cert_db_item=cert)

        return db_changed

    def query_cert(self, cert_info, valid_only=False):
        """
        Search for a certificate by serial or CN and return the record if it exists

        Args:
            cert_info (dict): key - The certificate attribute (cn, title or serial)
                            value - The attribute data
            valid_only (bool): Only show valid results by default

        Returns:
            dict or None
        
        Raises:
            ValueError is key is unknown
        """
        cursor = self.conn.cursor()

        where_conditions = []
        values = []

        if 'serial' in cert_info:
            where_conditions.append("serial=?")
            values.append(cert_info['serial'])

        elif 'title' in cert_info:
            where_conditions.append("title=?")
            values.append(cert_info['title'])

        elif 'cn' in cert_info:
            where_conditions.append("cn=?")
            values.append(cert_info['cn'])

        else:
            raise ValueError("Either serial, title or cn must be provided.")

        if valid_only:
            where_conditions.append('status="Valid"')

        where_clause = " AND ".join(where_conditions)
        sql = f"SELECT * FROM certificate_authority WHERE { where_clause }"

        cursor.execute(sql, tuple(values))
        row = cursor.fetchone()

        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

        return None

    def close(self):
        """ Close the database connection """
        self.conn.close()

    def update_config(self, config):
        """
        Update the config table with the provided data.

        Args:
            config (dict): Dictionary containing the configuration data to update.

        Returns:
            bool: True if the update succeeded, False otherwise.
        """
        cursor = self.conn.cursor()

        if 'next_serial' in config:
            config['next_serial'] = str(config['next_serial'])
        if 'next_crl_serial' in config:
            config['next_crl_serial'] = str(config['next_crl_serial'])

        valid_data = {k: v for k, v in config.items() if k in self.config_attrs}

        update_clauses = [f"{key} = ?" for key in valid_data.keys()]
        sql = f"UPDATE config SET {', '.join(update_clauses)} WHERE id = 1"

        try:
            cursor.execute(sql, tuple(valid_data.values()))
            self.conn.commit()
            cursor.close()
            return True

        except sqlite3.Error as sqlite_error:
            print(f"Error updating config: {sqlite_error}")
            return False

    def update_cert(self, cert_db_item):
        """
        Update an existing certificate record in the database.

        Args:
            cert_db_item (dict): A structure of the certificate record to update. 
                                Must include 'serial' to identify the record.

        Returns:
            bool: True if the update succeeded, False otherwise.
        """
        cursor = self.conn.cursor()

        if 'serial' not in cert_db_item:
            error("The 'serial' key must be provided in cert_db_item to update a certificate.", 1)
            return False

        serial_number = cert_db_item.pop('serial')

        columns = ', '.join([f"{key} = ?" for key in cert_db_item.keys()])
        sql = f"UPDATE certificate_authority SET {columns} WHERE serial = ?"

        try:
            cursor.execute(sql, tuple(cert_db_item.values()) + (serial_number,))
            self.conn.commit()

            if cursor.rowcount == 0:
                error(f"No certificate found with serial number {serial_number}.", 1)
                return False

            cursor.close()
            return True

        except sqlite3.Error as sqlite_error:
            error(f'SQLite error: {sqlite_error}', 1)
            return False


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
            'ou',
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

            if 'csr' in self.config:
                self.csr = x509.load_pem_x509_csr(self.config['csr'], default_backend())

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

        def get_attribute_for_oid(oid):
            attribute = self.certificate.subject.get_attributes_for_oid(oid)
            return attribute[0].value if attribute else None

        def get_subject_alt_name():
            try:
                return self.certificate.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
            except ExtensionNotFound:
                return None

        attrib_map = {
            'cn': lambda: get_attribute_for_oid(NameOID.COMMON_NAME),
            'not_before': lambda: format_datetime(self.certificate.not_valid_before_utc,
                                                  output_format='text'),
            'not_after': lambda: format_datetime(self.certificate.not_valid_after_utc,
                                                  output_format='text'),
            'issuer': self.certificate.issuer.rfc4514_string(),
            'subject': self.certificate.subject.rfc4514_string(),
            'serial': self.certificate.serial_number,
            'version': self.certificate.version,
            'org': lambda: get_attribute_for_oid(NameOID.ORGANIZATION_NAME),
            'ou': lambda: get_attribute_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME),
            'email': lambda: get_attribute_for_oid(NameOID.EMAIL_ADDRESS),
            'city': lambda: get_attribute_for_oid(NameOID.LOCALITY_NAME),
            'state': lambda: get_attribute_for_oid(NameOID.STATE_OR_PROVINCE_NAME),
            'country': lambda: get_attribute_for_oid(NameOID.COUNTRY_NAME),
            'basic_constraints': lambda: self.certificate.extensions.
                    get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS),
            'subject_alt_name': lambda: get_subject_alt_name()
        }

        func = attrib_map.get(attrib)

        return func() if callable(func) else func

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

    def get_public_key(self):
        """
        Returns the public key

        Args:
            None

        Returns:
            cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey

        Raises:
            None
        """

        return self.certificate.public_key()

    def get_public_key_size(self):
        """
        Returns the key length of the private key

        Args:
            None

        Returns:
            int

        Raises:
            None
        """

        public_key = self.get_public_key()

        return public_key.key_size

    def get_public_key_type(self):
        """
        Returns the private key type

        Args:
            None

        Returns:
            str

        Raises:
            None
        """

        public_key = self.get_public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return "EC"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        else:
            return "Unknown"

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

        if 'ou' in self.config:
            x509_attributes.append(x509.NameAttribute(
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.config['ou']))

        if 'email' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.EMAIL_ADDRESS, self.config['email']))

        csr_builder = (x509.CertificateSigningRequestBuilder()
                       .subject_name(x509.Name(x509_attributes)))

        if 'alt_dns_names' in self.config:
            san_list = [x509.DNSName(name) for name in self.config['alt_dns_names']]

            san_extension = x509.SubjectAlternativeName(san_list)

            csr_builder = csr_builder.add_extension(san_extension, critical=False)

        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

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
        Returns true if the certificate bundle private key and certificate are consistent

        Args:
            None

        Returns:
            bool

        Raises:
            None
        """
        current_time = datetime.now(timezone.utc)
        not_valid_before = self.certificate.not_valid_before_utc.replace(tzinfo=timezone.utc)
        not_valid_after = self.certificate.not_valid_after_utc.replace(tzinfo=timezone.utc)

        if not self.private_key:
            # No private key, we only care about validity
            is_valid_from = self.certificate.not_valid_before <= current_time
            is_valid_to = current_time <= self.certificate.not_valid_after

            return is_valid_from and is_valid_to

        if self.private_key.public_key() != self.certificate.public_key():
            # The private key does not match the certificate
            return False

        if self.type != 'ca' and self.is_ca_certificate():
            return False

        if self.type == 'ca' and not self.is_ca_certificate():
            return False

        return not_valid_before <= current_time <= not_valid_after

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
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc) + delta)
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

                dns_names = [x509.DNSName(self.config['cn'])]

                if 'alt_dns_names' in self.config:
                    dns_names.extend(
                        [x509.DNSName(hostname) for hostname in self.config['alt_dns_names']])

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
            bool: Success of updating the certificate bundle certificate

        Raises:
            None
        """

        # Does the private key match the certificate?
        if self.private_key.public_key() == certificate.public_key():
            self.certificate = certificate

            return True
        else:
            error('Signed certificate does not match the private key', 1)

        return False


class Op:
    """ Class to act on 1Password CLI """
    def __init__(self, binary, account=None, vault=None):
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

    def delete_item(self, item_title, archive=True):
        """
        Deletes an item from 1Password

        Args:
            item_title (str): The item to delete

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """

        cmd = [self.bin, 'item', 'delete', item_title, '--vault', self.vault]

        if archive:
            cmd.append('--archive')

        result = run_command(cmd)

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

    def get_document(self, item_title):
        """
        Retrieve the contents of a document in 1Password

        Args:
            item_title (str): The title of the 1Password object

        Returns:
            subprocess.CompletedProcess

        Raises:
            None
        """

        result = run_command([self.bin, 'document', 'get', item_title, f'--vault={self.vault}'])

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

    def item_exists(self, item_title):
        """
        Checks to see if an item exists in 1Password

        Args:
            item_title (str): The item to check for

        Returns:
            bool: Existence of the item in 1Password

        Raises:
            None
        """
        result = self.read_item(self.mk_url(item_title=item_title, value_key='Title'))

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

    def rename_item(self, src_item_title, dst_item_title):
        """
        Rename an item in 1Password

        Args:
            src_item_title (str): The item to rename
            dst_item_title (str): The name to item should be renamed to

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """

        cmd = [self.bin, 'item', 'edit', src_item_title, '--title', dst_item_title, '--vault', self.vault]

        result = run_command(cmd)

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

    def store_document(self, item_title, filename, str_in, op_action='create', vault=None):
        """
        Store a document in 1Password

        Args:
            item_title (str): 1Password item title
            filename (str): The filename to store as metadata in 1Password
            str_in (str): The contents of a file to store as a document
            op_action (str): CRUD action
            vault (str): The destination vault for 'create' items

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if vault == None:
            vault = self.vault

        if op_action not in ['auto', 'create', 'edit']:
            error(f'Unknown storage command {op_action}', 1)

        if op_action == 'auto':
            if self.item_exists(item_title):
                op_action = 'edit'
            else:
                op_action = 'create'

        if op_action == 'create':
            item_title = f'--title={item_title}'

        cmd = [self.bin, 'document', op_action, item_title,
                f'--vault={vault}', f'--file-name={filename}']

        result = run_command(cmd, str_in=str_in)

        return result

    def store_item(self, item_title, attributes=None, op_action='auto',
                   category='Secure Note', str_in=None):
        """
        Store an item in 1Password

        Args:
            item_title (str): 1Password item title
            attributes (list): A list of strings containing the item attributes
            op_action (str): CRUD action
            category (str): The 1Password category to use. Secure Note is the default.
            std_in (str): A value to pass in via stdin instead of dealing with attributes

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if op_action not in ['auto', 'create', 'edit']:
            error(f'Unknown storage command {op_action}', 1)

        if op_action == 'auto':
            if self.item_exists(item_title):
                op_action = 'edit'
            else:
                op_action = 'create'

        if op_action == 'create':
            item_title = f'--title={item_title}'

        cmd = [self.bin, 'item', op_action, item_title, f'--vault={self.vault}']

        if category is not None and op_action == 'create':
            cmd.append(f'--category={ category }')

        if attributes is not None:
            cmd.extend(attributes)

        result=run_command(cmd, str_in=str_in)

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

    elif selection == 'cert':
        handle_cert_action(action, args)

    elif selection == 'crl':
        handle_crl_action(action, args)

    elif selection == 'database':
        handle_database_action(action, args)

    elif selection == 'openvpn':
        handle_openvpn_action(action, args)
