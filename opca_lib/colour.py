#!/usr/bin/env python3
"""
#
# opca_lib/colour.py
#

Variables containing ANSI colour codes

"""

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

COLOUR_ERROR   = COLOUR['bold_red']
COLOUR_OK      = COLOUR['green']
COLOUR_BRIGHT  = COLOUR['bold_white']
COLOUR_WARNING = COLOUR['bold_yellow']
COLOUR_RESET   = COLOUR['reset']
