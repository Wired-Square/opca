#!/usr/bin/env python3
"""
#
# opca.py - 1Password Certificate Authority
#

A Python certificate authority implementation that uses pyca/cryptography (https://cryptography.io)
to generate keys and sign certificates, and then store them in 1Password.

"""

import argparse
from opca_lib.alerts import title
from opca_lib.command_openvpn import handle_openvpn_action
from opca_lib.command_ca import handle_ca_action
from opca_lib.command_crl import handle_crl_action
from opca_lib.command_database import handle_database_action
from opca_lib.command_manage import handle_manage_action

# Constants
OPCA_VERSION        = "0.13.2"
OPCA_TITLE          = "1Password Certificate Authority"
OPCA_SHORT_TITLE    = "OPCA"
OPCA_AUTHOR         = "Alex Ferrara <alex@wiredsquare.com>"
OPCA_LICENSE        = "mit"


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

    subparsers = parser.add_subparsers(title='Commands', dest='selection',
                                                        required=True)

    setup_ca_subparser(subparsers)
    setup_crl_subparser(subparsers)
    setup_database_subparser(subparsers)
    setup_openvpn_subparser(subparsers)
    setup_manage_subparser(subparsers)

    return parser.parse_args()

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
    subparser_action_import_ca.add_argument('--serial', required=False, type=int,
        help='CA next serial number')
    subparser_action_import_ca.add_argument('--crl-serial', required=False, type=int,
        help='Certificate Authority next CRL serial number')

    subparser_action_import_ca.add_argument('--ca-url', required=False,
        help='The URL where we can find the CA certificate')
    subparser_action_import_ca.add_argument('--crl-url', required=False,
        help='The URL where we can find the Certificate Revocation List')

    subparser_action_get_ca_cert = parser_ca_actions.add_parser('get-ca-cert',
        help='Get the object CA Certificate')
    subparser_action_get_ca_cert.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_get_ca_cert.add_argument('-v', '--vault', required=True,
        help='CA Vault')

    subparser_action_get_csr = parser_ca_actions.add_parser('get-csr',
        help='Get the Certificate Signing Request for a 1Password Certificate Bundle')
    subparser_action_get_csr.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_get_csr.add_argument('-n', '--cn', required=True,
        help='x509 CN attribute for the 1Password Certificate Authority')
    subparser_action_get_csr.add_argument('-v', '--vault', required=True,
        help='CA Vault')

    subparser_action_create_cert = parser_ca_actions.add_parser('create-cert',
        help='Create a new x509 CertificateBundle object')
    subparser_action_create_cert.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_create_cert.add_argument('-n', '--cn', required=True,
        help='CN attribute. Regular certificates use this for the 1Password title.')
    subparser_action_create_cert.add_argument('-t', '--cert-type', required=True,
        help='x509 Certificate type', choices=['vpnserver', 'vpnclient', 'webserver'])
    subparser_action_create_cert.add_argument('-s', '--serial', required=False, type=int,
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

    subparser_action_renew_cert = parser_ca_actions.add_parser('renew-cert',
        help='Renew a x509 certificate, retaining the private key')
    subparser_action_renew_cert.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_renew_cert.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_group_renew_cert = subparser_action_renew_cert.add_mutually_exclusive_group(
        required=True)
    subparser_group_renew_cert.add_argument('-n', '--cn',
        help='x509 CN of the certificate to revoke')
    subparser_group_renew_cert.add_argument('-s', '--serial', type=int,
        help='Serial number of the certificate to revoke')

    subparser_action_revoke_cert = parser_ca_actions.add_parser('revoke-cert',
        help='Create a new x509 CertificateBundle object')
    subparser_action_revoke_cert.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_revoke_cert.add_argument('-v', '--vault', required=True, help='CA Vault')
    subparser_group_revoke_cert = subparser_action_revoke_cert.add_mutually_exclusive_group(
        required=True)
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

    subparser_action_get_crl = parser_crl_actions.add_parser('get',
        help='Get the Certificate Revocation List from 1Password')
    subparser_action_get_crl.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_get_crl.add_argument('-v', '--vault', required=True,
        help='CA Vault')

    subparser_action_gen_crl = parser_crl_actions.add_parser('create',
        help='Generate a Certificate Revokation List for the 1Password CA')
    subparser_action_gen_crl.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_gen_crl.add_argument('-v', '--vault', required=True, help='CA Vault')

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

    subparser_action_export_db = parser_db_actions.add_parser('export',
        help='Export the entire CA SQLite database')
    subparser_action_export_db.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company when your url is company.1password.com')
    subparser_action_export_db.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_get_config = parser_db_actions.add_parser('get-config',
        help='Get the current CA Database configuration')
    subparser_action_get_config.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company when your url is company.1password.com')
    subparser_action_get_config.add_argument('-v', '--vault', required=True, help='CA Vault')

    subparser_action_rebuild_db = parser_db_actions.add_parser('rebuild',
        help='Generate a Certificate Database for the 1Password CA')
    subparser_action_rebuild_db.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_rebuild_db.add_argument('-v', '--vault', required=True, help='CA Vault')
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
    subparser_action_set_config.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company when your url is company.1password.com')
    subparser_action_set_config.add_argument('-v', '--vault', required=True, help='CA Vault')
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

    subparser_action_get_ta = parser_openvpn_actions.add_parser('get-ta-key',
        help='Retrieve Diffie-Hellman parameters from 1Password')
    subparser_action_get_ta.add_argument('-a', '--account', required=False,
        help='1Password Account. Example: company.1password.com')
    subparser_action_get_ta.add_argument('-v', '--vault', required=True,
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
    subparser_action_gen_vpn_profile.add_argument('-d', '--dest', required=False,
        help='The destination vault to store the VPN profile')
    subparser_action_gen_vpn_profile.add_argument('-n', '--cn', required=True,
        help='The certificate CN. This is also the 1Password title')
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

def setup_manage_subparser(subparsers):
    """
    Set up the subparser for management related commands.

    Args:
        subparsers (argparse._SubParsersAction): The subparsers object from the main parser.

    Returns:
        None
    """

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

if __name__ == "__main__":

    description = f'{OPCA_TITLE} - {OPCA_SHORT_TITLE} v{OPCA_VERSION}'

    args = parse_arguments(description)

    selection = args.selection
    action = args.action

    title(description, 1)

    if selection == 'ca':
        handle_ca_action(action, args)

    if selection == 'crl':
        handle_crl_action(action, args)

    elif selection == 'database':
        handle_database_action(action, args)

    elif selection == 'openvpn':
        handle_openvpn_action(action, args)

    elif selection == 'manage':
        handle_manage_action(action, args)
