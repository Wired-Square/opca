# opca/utils/formatting.py

from __future__ import annotations

import sys
from opca.constants import COLOUR, COLOUR_BRIGHT, COLOUR_RESET
from opca.constants import COLOUR_ERROR, COLOUR_OK, COLOUR_WARNING
from opca.constants import STATUS_COLUMN

def title(text: str, level: int=1, extra=None) -> None:
    """
    Prints a title in a consistant format

    Args:
        text (str): The text to be displayed
        level (int):  The level of heading (optional)
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

def print_result(success, *, ok_msg='  OK  ', failed_msg='FAILED') -> int:
    """
    Prints a ANSI success or failure message in a RedHat theme

    Args:
        success (bool): Success test condition
        ok_msg (str): OK message text
        failed_msg (str): Failed message text
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

def error(text: str, exit_code: int=0) -> None:
    """
    Prints an error message with custom formatting.

    Args:
        text (str): The error message to be displayed.
        exit_code (str): The exist code to give
    """

    error_colour = COLOUR_ERROR
    reset = COLOUR['reset']

    print(f'{error_colour}Error:{reset} {text}')

    if exit_code != 0:
        sys.exit(exit_code)

def warning(text: str) -> None:
    """
    Prints a warning message with custom formatting.

    Args:
        warning_msg (str): The error message to be displayed.
    """

    error_colour = COLOUR_WARNING
    reset = COLOUR['reset']

    print(f'⚠️ {error_colour}Warning:{reset} {text}')
