"""
#
# opca_lib/op.py
#

A class to interact with 1Password CLI

"""

import os
import subprocess
import sys
from opca_lib.alerts import error

# Configuration
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

def run_command(command, text=True, shell=False, stdin=None, str_in=None, env_vars=None):
    """
    Run a command and capture the output

    Args:
        command (list of strings): The command to execute
        text (bool): Subprocess text variable passed directly
        shell (bool): Subprocess shell variable passed directly
        stdin () Subprocess stdin variable passed directly
        str_in (str): Subprocess input variable passed directly
        env_vars ():Subprocess env_vars variable passed directly

    Returns:
        subprocess.CompletedProcess: The captured output
    
    Raises:
        None
    """

    try:
        result = subprocess.run(command, env=env_vars, stdin=stdin, input=str_in,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=text, shell=shell, check=False)

        return result

    except FileNotFoundError:
        error(f'Command not found. Does { command[0] }it exist?', 1)
        sys.exit(1)


class Op:
    """ Class to act on 1Password CLI """
    def __init__(self, binary, account=None, vault=None):
        self.account = account
        self.vault = vault
        self.bin = binary

        if not os.path.isfile(self.bin) and os.access(self.bin, os.X_OK):
            error('Error: No 1Password-CLI executable. Is it installed?', 1)

        signin_command = [self.bin, 'signin']

        if self.account:
            signin_command.extend(['--account', self.account])

        result = run_command(signin_command)

        if result.returncode != 0:
            error(result.stderr, result.returncode)
            sys.exit(result.returncode)

    def delete_item(self, item_title, archive=True):
        """
        Deletes an item from 1Password

        Args:
            item_title (str): The item to delete

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """

        cmd = [self.bin, 'item', 'delete', item_title]

        if archive:
            cmd.append('--archive')

        result = run_command(cmd)

        return result

    def get_current_user_details(self):
        """
        Return the current 1Password CLI user details

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op user get --me

        Raises:
            None
        """

        result = run_command([self.bin, 'user', 'get', '--me'])

        return result

    def get_document(self, item_title):
        """
        Retrieve the contents of a document in 1Password

        Args:
            item_title (str): The title of the 1Password object

        Returns:
            subprocess.CompletedProcess

        Raises:
            None
        """

        result = run_command([self.bin, 'document', 'get', item_title, f'--vault={self.vault}'])

        return result

    def get_item(self, item_title, output_format='json'):
        """
        Retrieve the contents of an item at a given 1Password secrets url

        Args:
            item_title (str): The title of the 1Password object
            output_format (str): The format 1Password CLI should give

        Returns:
            subprocess.CompletedProcess

        Raises:
            None
        """

        result = run_command([self.bin, 'item', 'get', item_title, f'--vault={self.vault}',
                                                              f'--format={output_format}'])

        return result

    def get_vault(self):
        """
        Return the current 1Password vault details

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """
        result = run_command([self.bin, 'vault', 'get', self.vault])

        return result

    def inject_item(self, template, env_vars):
        """
        Fill out a template from data in 1Password

        Args:
            template (str): A 1Password template
            env_vars (dict): A dict of environment variables for the execution environment

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op vault get [ vault ]

        Raises:
            None
        """

        result = run_command([self.bin, 'inject'], env_vars=env_vars, str_in=template)

        return result

    def item_exists(self, item_title):
        """
        Checks to see if an item exists in 1Password

        Args:
            item_title (str): The item to check for

        Returns:
            bool: Existence of the item in 1Password

        Raises:
            None
        """
        result = self.read_item(self.mk_url(item_title=item_title, value_key='Title'))

        return bool(result.returncode == 0)

    def item_list(self, categories, output_format='json'):
        """
        List all items in the current vault

        Args:
            categories (str): A comma seperated list of 1Password categories 

        Returns:
            subprocess.CompletedProcess

        Raises:
            None
        """
        result = run_command([self.bin, 'item', 'list', f'--vault={self.vault}',
                                                        f'--categories={categories}',
                                                        f'--format={output_format}'])

        return result

    def read_item(self, url):
        """
        Retrieve the contents of an item at a given 1Password secrets url

        Args:
            url (str): 1Password secrets url

        Returns:
            str: Contents of the item

        Raises:
            None
        """

        result = run_command([self.bin, 'read', url])

        return result

    def mk_url(self, item_title, value_key=None):
        """
        Make a 1Password secret url from an item title and optional value

        Args:
            item_title (str): The 1Password item title
            value_key (str): The 1Password item key

        Returns:
            None

        Raises:
            None
        """

        if value_key is None:
            url = f'op://{self.vault}/{item_title}'
        else:
            url = f'op://{self.vault}/{item_title}/{value_key}'

        return url

    def store_document(self, item_title, filename, str_in, action='create'):
        """
        Store a document in 1Password

        Args:
            item_title (str): 1Password item title
            filename (str): The filename to store as metadata in 1Password
            str_in (str): The contents of a file to store as a document
            action (str): CRUD action

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if action not in ['auto', 'create', 'edit']:
            error(f'Unknown storage command {action}', 1)

        if action == 'auto':
            if self.item_exists(item_title):
                action = 'edit'
            else:
                action = 'create'

        if action == 'create':
            item_title = f'--title={item_title}'

        cmd = [self.bin, 'document', action, item_title,
                f'--vault={self.vault}', f'--file-name={filename}']

        result = run_command(cmd, str_in=str_in)

        return result

    def store_item(self, item_title, attributes=None, action='auto',
                   category='Secure Note', str_in=None):
        """
        Store an item in 1Password

        Args:
            item_title (str): 1Password item title
            attributes (list): A list of strings containing the item attributes
            action (str): CRUD action
            category (str): The 1Password category to use. Secure Note is the default.
            std_in (str): A value to pass in via stdin instead of dealing with attributes

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        if action not in ['auto', 'create', 'edit']:
            error(f'Unknown storage command {action}', 1)

        if action == 'auto':
            if self.item_exists(item_title):
                action = 'edit'
            else:
                action = 'create'

        if action == 'create':
            item_title = f'--title={item_title}'

        cmd = [self.bin, 'item', action, item_title, f'--vault={self.vault}']

        if category is not None and action == 'create':
            cmd.append(f'--category={ category }')

        if attributes is not None:
            cmd.extend(attributes)

        result=run_command(cmd, str_in=str_in)

        return result

    def whoami(self):
        """
        Return the current 1Password CLI user

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI > op whoami

        Raises:
            None
        """
        result = run_command([self.bin, 'whoami'])
        return result
