"""
#
# opca_lib/command_manage.py
#

Handle the various manage commands

"""

import os
import shutil
from opca_lib.alerts import error, title, print_result
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from opca_lib.fs_io import is_file_executable
from opca_lib.op import Op, OP_BIN


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

def handle_manage_action(manage_action, cli_args):
    """
    Handle Management Actions called from the selection

    Args:
        manage_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('Management', extra=manage_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=None)

    if manage_action == 'test':
        title('Test the system dependencies', level=3)

        print(f'1Password CLI - {COLOUR_BRIGHT}{OP_BIN}{COLOUR_RESET}', end='')
        result = is_file_executable(OP_BIN)
        print_result(result)

        bin_file = find_executable(OP_BIN)
        print(f'1Password CLI in path - {COLOUR_BRIGHT}{bin_file}{COLOUR_RESET}', end='')
        result = is_file_executable(bin_file)
        print_result(result)

    elif manage_action == 'whoami':

        title('Get the current user', 9)
        result = one_password.whoami()
        print_result(result.returncode == 0)

        print(result.stdout)

        title('Retrieve the current user details', 9)
        result = one_password.get_current_user_details()
        print_result(result.returncode == 0)

        print(result.stdout)
    else:
        error('This feature is not yet written', 99)

