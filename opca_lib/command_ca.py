"""
#
# opca_lib/command_ca.py
#

Handle the various certificate authority commands

"""


from cryptography import x509
from cryptography.hazmat.backends import default_backend
from opca_lib.alerts import error, title, print_result
from opca_lib.ca import CertificateAuthority, prepare_cert_authority
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from opca_lib.crypto import DEFAULT_KEY_SIZE
from opca_lib.fs_io import read_file
from opca_lib.op import Op, OP_BIN, DEFAULT_OP_CONF


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

    if ca_action == 'init-ca':
        title('Initialising the Certificate Authority', 3)

        ca_config = {
            'command': 'init',
            'cn': cli_args.cn,
            'ca_days': cli_args.ca_days,
            'days': cli_args.days,
            'next_serial': 1,
            'next_crl_serial': 1,
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

    elif ca_action == 'import-ca':

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
                                                      default_backend).serial_number

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

    elif ca_action == 'get-ca-cert':
        cert_authority = prepare_cert_authority(one_password)

        print(cert_authority.get_certificate())

    elif ca_action == 'get-csr':
        url = one_password.mk_url(cli_args.cn, DEFAULT_OP_CONF['csr_item'])

        result = one_password.read_item(url)

        if result.returncode != 0:
            error(result.stderr, 1)

        print(result.stdout)

    elif ca_action == 'create-cert':
        cert_authority = prepare_cert_authority(one_password)

        if one_password.item_exists(cli_args.cn):
            error(f'CN {cli_args.cn} already exists. Aborting', 1)

        cert_config = cert_authority.ca_certbundle.get_config()
        cert_config['cn'] = cli_args.cn
        cert_config['key_size'] = DEFAULT_KEY_SIZE[cli_args.cert_type]

        if cli_args.alt is not None:
            cert_config['alt_dns_names'] = cli_args.alt

        title(f'Generating a certificate bundle for {COLOUR_BRIGHT}{cli_args.cn}{COLOUR_RESET}', 9)

        new_certificate_bundle = cert_authority.generate_certificate_bundle(
            cert_type=cli_args.cert_type,
            item_title=cli_args.cn,
            config=cert_config)

        print_result(new_certificate_bundle.is_valid())

    elif ca_action == 'import-cert':
        cert_authority = prepare_cert_authority(one_password)
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

        if cert_authority.is_cert_valid(cert_bundle.certificate):
            title('Storing certificate bundle for ' + \
                f'{COLOUR_BRIGHT}{item_title}{COLOUR_RESET} in 1Password', 9)
            result = cert_authority.store_certbundle(cert_bundle)
            print_result(result.returncode == 0)

        else:
            error('Certificate is not signed by this Certificate Authority', 1)

    elif ca_action == 'renew-cert':
        title('This is a work-in-progress.', 8)

    elif ca_action == 'revoke-cert':
        cert_authority = prepare_cert_authority(one_password)
        cert_info = {}

        if cli_args.serial:
            cert_info['serial'] = cli_args.serial
            desc = f'Serial: {cli_args.serial}'
        else:
            cert_info['cn'] = cli_args.cn
            desc = cli_args.cn

        title(f'Revoking the certificate [ { COLOUR_BRIGHT }{ desc }{ COLOUR_RESET } ]', 8)

        if cert_authority.revoke_certificate(cert_info=cert_info):
            print(cert_authority.generate_crl())

    else:
        error('This feature is not yet written', 99)
