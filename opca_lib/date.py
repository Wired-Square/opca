"""
#
# opca_lib/date.py
#

Some handy date functions

"""

from opca_lib.alerts import error

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
    else:
        error('Invalid date format', 1)

    return date.strftime(format_string)
