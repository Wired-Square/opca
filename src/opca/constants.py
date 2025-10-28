# opca/constants.py

from __future__ import annotations

"""
Standardised exit codes for candor CLI commands.

0 = success
1 = validation errors (semantic or structural checks failed)
2 = fatal errors (load/IO problems, unsupported args, unhandled exceptions)
"""
EXIT_OK: int = 0
EXIT_VALIDATION_ERROR: int = 1
EXIT_FATAL: int = 2

# ---- ANSI Colour Codes ----
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

# Convenience shortcuts
COLOUR_ERROR = COLOUR['bold_red']
COLOUR_OK = COLOUR['green']
COLOUR_BRIGHT = COLOUR['bold_white']
COLOUR_WARNING = COLOUR['bold_yellow']
COLOUR_RESET = COLOUR['reset']

# ---- Cryptographic defaults ----
DEFAULT_KEY_SIZE = {
    'ca': 4096,
    'dh': 2048,
    'ta': 2048,
    'device'   : 2048,
    'vpnclient': 2048,
    'vpnserver': 2048,
    'webserver': 2048,
}

# ---- 1Password defaults ----
OP_BIN = 'op'

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

# ---- Storage defaults ----
DEFAULT_STORAGE_CONF = {
    'ca_cert_file': 'ca.crt',
    'crl_file': 'crl.pem'
}

# ---- View defaults ----
STATUS_COLUMN  = 90
