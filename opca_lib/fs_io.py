"""
#
# opca_lib/fs_io.py
#

Filesystem and IO helper functions

"""

import os
from opca_lib.alerts import error


def is_file_executable(file_path):
    """
    Checks if the file at the specified path is executable.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file is executable, False otherwise.

    Raises:
        None
    """
    return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

def read_file(file_path):
    """
    Read the contents of a file

    Args:
        file_path (str): The file to be read

    Returns:
        bytes: The contents of the file

    Raises:
        None
    """
    content = None

    try:
        with open(file_path, 'rb') as file:
            content = file.read()
    except FileNotFoundError:
        error(f"File '{file_path}' not found.", 1)
    except PermissionError:
        error(f"Permission denied for file '{file_path}'.", 1)
    except IOError as err:
        error(f"I/O error occurred while reading file '{file_path}': {err}", 1)

    return content
