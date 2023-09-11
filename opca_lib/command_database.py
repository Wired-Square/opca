"""
#
# opca_lib/command_database.py
#

Handle the various certificate authority database commands

"""

from opca_lib.alerts import error, title
from opca_lib.ca import CertificateAuthority, prepare_cert_authority
from opca_lib.op import Op, OP_BIN, DEFAULT_OP_CONF


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

    if db_action == 'export':
        cert_authority = prepare_cert_authority(one_password)

        print(cert_authority.ca_database.export_database().decode('utf-8'))

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
