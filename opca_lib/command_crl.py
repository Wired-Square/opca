"""
#
# opca_lib/command_ca.py
#

Handle the various certificate authority commands

"""

from opca_lib.ca import prepare_cert_authority
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from opca_lib.alerts import error, title, print_result
from opca_lib.op import Op, OP_BIN

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

    title('Certificate Authority', extra=crl_action, level=2)

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

    else:
        error('This feature is not yet written', 99)
