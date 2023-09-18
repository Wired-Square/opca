"""
#
# opca_lib/database.py
#

A class to interact with SQLite

"""

import io
import sqlite3
from datetime import datetime, timedelta
from opca_lib.alerts import error
from opca_lib.date import format_datetime

class CertificateAuthorityDB:
    """ Class to manage a database for the CA in SQLite """
    def __init__(self, config=None, data=None):
        """
        Construct a certificate authority db object.

        Args:
            data (dict): The ca_config dict that may contain a previous database backup

        Returns:
            None
        """
        self.certs_expires_soon = []
        self.certs_revoked = []
        self.certs_valid = []
        self.conn = sqlite3.connect(':memory:')
        self.config_attrs = (
            'next_serial',
            'next_crl_serial',
            'org',
            'email',
            'city',
            'state',
            'country',
            'ca_url',
            'crl_url',
            'days',
            'crl_days'
        )
        self.schema_version = 1

        if data:
            # Restore the DB from data
            self.conn.executescript(data)

        else:
            # Build a shiny new DB from config
            self.create_config_table()
            self.insert_config(config)
            self.create_ca_table()

    def add_cert(self, cert_db_item):
        """
        Add a certificate record to the database

        Args:
            cert_db_item (dict): A structure of the certificate record to add

        Returns:
            bool:  True if the insert succeeded, False otherwise
        """
        cert_db_item['serial'] = str(cert_db_item['serial'])
        cursor = self.conn.cursor()

        columns = ', '.join(cert_db_item.keys())
        placeholders = ', '.join(['?'] * len(cert_db_item))
        sql = f"INSERT INTO certificate_authority ({columns}) VALUES ({placeholders})"

        try:
            cursor.execute(sql, tuple(cert_db_item.values()))
            self.conn.commit()
            return True

        except sqlite3.Error as sqlite_error:
            error(f'SQLite error: {sqlite_error}', 1)
            return False

    def create_ca_table(self):
        """ Create a table to track certificates """
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_authority (
                serial TEXT PRIMARY KEY,
                cn TEXT,
                title TEXT,
                status TEXT,
                expiry_date TEXT,
                revocation_date TEXT,
                subject TEXT
            )
        ''')
        self.conn.commit()

    def create_config_table(self):
        """ Create a config table """
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                next_serial TEXT,
                next_crl_serial TEXT,
                org TEXT,
                email TEXT,
                city TEXT,
                state TEXT,
                country TEXT,
                ca_url TEXT,
                crl_url TEXT,
                days INTEGER,
                crl_days INTEGER,
                schema_version INTEGER
            )
        ''')
        self.conn.commit()

    def count_certs(self):
        """
        Count the number of certificates in the database.

        Returns:
            int: The number of certificates.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM certificate_authority")
        count = cursor.fetchone()[0]
        return count

    def export_database(self):
        """ Export the entire database to a io.BytesIO object """

        memory_file = io.BytesIO()

        for line in self.conn.iterdump():
            memory_file.write(line.encode('utf-8'))

        return memory_file.getvalue()

    def get_config_attributes(self):
        """
        Retrieve all valid config attributes from the database.

        Returns:
            dict: Attribute names as keys and their values from the database as values.
        """
        cursor = self.conn.cursor()

        columns = ', '.join(self.config_attrs)
        sql = f"SELECT {columns} FROM config LIMIT 1"

        cursor.execute(sql)
        row = cursor.fetchone()

        if row:
            result = dict(zip(self.config_attrs, row))

            result['next_serial'] = int(result['next_serial'])

            try:
                result['next_crl_serial'] = int(result['next_crl_serial'])

            except ValueError:
                pass

            return result

        return None

    def increment_serial(self, serial_type):
        """
        Returns the next available serial number, and increments it in the database

        Args:
            serial_type (str): The type of serial to act on. Either 'cert' or 'crl'

        Returns:
            int
        
        Raises:
            ValueError
        """
        cursor = self.conn.cursor()

        if serial_type == 'cert':
            column_name = 'next_serial'

        elif serial_type == 'crl':
            column_name = 'next_crl_serial'

        else:
            raise ValueError("Invalid serial type. Expected 'cert' or 'crl'.")

        cursor.execute(f"SELECT { column_name } FROM config LIMIT 1")
        current_value = int(cursor.fetchone()[0])

        cursor.execute(f"UPDATE config SET { column_name } = { current_value + 1 }")

        self.conn.commit()

        return current_value

    def insert_config(self, config):
        """
        Insert the CA configuration into the config table

        Args:
            config (dict): The config data to insert

        Returns:
            bool
        
        Raises:
            None
        """
        cursor = self.conn.cursor()

        if 'next_serial' in config:
            config['next_serial'] = str(config['next_serial'])
        if 'next_crl_serial' in config:
            config['next_crl_serial'] = str(config['next_crl_serial'])

        if config['command'] == 'rebuild-ca-database':
            if config['next_crl_serial'] is None:
                config['next_crl_serial'] = 1

        filtered_dict = {k: config[k] for k in self.config_attrs if k in config}

        filtered_dict['id'] = 1
        filtered_dict['schema_version'] = self.schema_version

        columns = ', '.join(filtered_dict.keys())
        placeholders = ', '.join(['?'] * len(filtered_dict))
        sql = f"INSERT INTO config ({columns}) VALUES ({placeholders})"

        cursor.execute(sql, tuple(filtered_dict.values()))
        self.conn.commit()

    def process_ca_database(self, revoke_serial=None):
        """
        Process the CA database.
         - The status of certifiates might change due to time
         - Gather a list of
           - Certificates revoked
           - Certificates expiring soon
           - Certificates valid

        Args:
            revoke_serial (int, optional): Serial number of the certificate to revoke.

        Returns:
            bool: Did the database change post-processing

        Raises:
            None
        """
        db_changed = False
        self.certs_revoked = []
        self.certs_expires_soon = []
        self.certs_valid = []
        expiry_warning_days = 30

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM certificate_authority")
        all_certs = cursor.fetchall()

        columns = [desc[0] for desc in cursor.description]
        all_cert_dicts = [dict(zip(columns, cert)) for cert in all_certs]

        for cert in all_cert_dicts:
            cert_changed = False

            expiry_date = datetime.strptime(cert['expiry_date'], '%Y%m%d%H%M%SZ')

            expired = datetime.utcnow() > expiry_date

            expires_soon = datetime.utcnow() + timedelta(expiry_warning_days) > expiry_date
            revoked = bool(cert['revocation_date']) or (cert['status'] == 'Revoked')

            if revoke_serial is not None:
                if not expired and not revoked and revoke_serial == cert['serial']:
                    revoked = True
                    cert_changed = True
                    db_changed = True
                    cert['revocation_date'] = format_datetime(datetime.utcnow())

            if expired:
                if cert['status'] != 'Expired':
                    cert_changed = True
                    db_changed = True
                    cert['status'] = 'Expired'
            elif revoked:
                if cert['status'] != 'Revoked':
                    cert_changed = True
                    db_changed = True
                    cert['status'] = 'Revoked'

                self.certs_revoked.append(cert)

            elif expires_soon:
                self.certs_expires_soon.append(cert)

            else:
                self.certs_valid.append(cert)

            if cert_changed:
                self.update_cert(cert_db_item=cert)

        return db_changed

    def query_cert(self, cert_info, valid_only=False):
        """
        Search for a certificate by serial or CN and return the record if it exists

        Args:
            cert_info (dict): key - The certificate attribute (cn, title or serial)
                            value - The attribute data

        Returns:
            dict or None
        
        Raises:
            ValueError is key is unknown
        """
        cursor = self.conn.cursor()

        where_conditions = []
        values = []

        if 'serial' in cert_info:
            where_conditions.append("serial=?")
            values.append(cert_info['serial'])

        elif 'title' in cert_info:
            where_conditions.append("title=?")
            values.append(cert_info['title'])

        elif 'cn' in cert_info:
            where_conditions.append("cn=?")
            values.append(cert_info['cn'])

        else:
            raise ValueError("Either serial, title or cn must be provided.")

        if valid_only:
            where_conditions.append('status="Valid"')

        where_clause = " AND ".join(where_conditions)
        sql = f"SELECT * FROM certificate_authority WHERE { where_clause }"

        cursor.execute(sql, tuple(values))
        row = cursor.fetchone()

        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

        return None

    def close(self):
        """ Close the database connection """
        self.conn.close()

    def update_config(self, config):
        """
        Update the config table with the provided data.

        Args:
            config (dict): Dictionary containing the configuration data to update.

        Returns:
            bool: True if the update succeeded, False otherwise.
        """
        cursor = self.conn.cursor()

        if 'next_serial' in config:
            config['next_serial'] = str(config['next_serial'])
        if 'next_crl_serial' in config:
            config['next_crl_serial'] = str(config['next_crl_serial'])

        valid_data = {k: v for k, v in config.items() if k in self.config_attrs}

        update_clauses = [f"{key} = ?" for key in valid_data.keys()]
        sql = f"UPDATE config SET {', '.join(update_clauses)} WHERE id = 1"

        try:
            cursor.execute(sql, tuple(valid_data.values()))
            self.conn.commit()
            return True

        except sqlite3.Error as sqlite_error:
            print(f"Error updating config: {sqlite_error}")
            return False

    def update_cert(self, cert_db_item):
        """
        Update an existing certificate record in the database.

        Args:
            cert_db_item (dict): A structure of the certificate record to update. 
                                Must include 'serial' to identify the record.

        Returns:
            bool: True if the update succeeded, False otherwise.
        """
        cursor = self.conn.cursor()

        if 'serial' not in cert_db_item:
            error("The 'serial' key must be provided in cert_db_item to update a certificate.", 1)
            return False

        serial_number = cert_db_item.pop('serial')

        columns = ', '.join([f"{key} = ?" for key in cert_db_item.keys()])
        sql = f"UPDATE certificate_authority SET {columns} WHERE serial = ?"

        try:
            cursor.execute(sql, tuple(cert_db_item.values()) + (serial_number,))
            self.conn.commit()

            if cursor.rowcount == 0:
                error(f"No certificate found with serial number {serial_number}.", 1)
                return False

            return True

        except sqlite3.Error as sqlite_error:
            error(f'SQLite error: {sqlite_error}', 1)
            return False
