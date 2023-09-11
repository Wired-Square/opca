"""
#
# opca_lib/alerts.py
#

A library to display coloured alerts to the screen

"""

import sys
from opca_lib.colour import COLOUR
from opca_lib.colour import COLOUR_BRIGHT
from opca_lib.colour import COLOUR_ERROR
from opca_lib.colour import COLOUR_OK
from opca_lib.colour import COLOUR_RESET
from opca_lib.colour import COLOUR_WARNING

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
    sys.exit(exit_code)

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

    column = f'\033[{STATUS_COLUMN}G'

    if success:
        msg = ok_msg
        msg_colour = COLOUR_OK
    else:
        msg = failed_msg
        msg_colour = COLOUR_ERROR

    print(f'{column}[ {msg_colour}{msg}{COLOUR_RESET} ]')

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

    error_colour = COLOUR_WARNING
    reset = COLOUR['reset']

    print(f'{error_colour}Warning:{reset} {warning_msg}')
