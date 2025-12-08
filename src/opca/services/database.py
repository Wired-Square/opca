# opca/services/database.py

from __future__ import annotations

import io
import sqlite3
import tempfile

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from opca.utils.datetime import now_utc, now_utc_plus, now_utc_str, parse_datetime
from opca.services.ca_errors import CADatabaseError


class CertificateAuthorityDB:
    """
    SQLite database manager for Certificate Authority operations.

    Maintains an in-memory SQLite database tracking:
    - All issued certificates with serial numbers, CNs, expiry dates, and status
    - CA configuration (serial counters, validity periods, URLs, storage locations)
    - Certificate lifecycle state (valid, expired, revoked, expiring soon)

    The database uses schema versioning with automatic migrations for upgrades.
    It can be exported as SQL text or binary SQLite format for storage in 1Password
    or remote backends.

    Schema versions:
    - v1: Initial schema with config and certificate_authority tables
    - v2: Added 'ou' (organizational unit) field
    - v3: Added storage location fields (ca_public_store, ca_private_store, ca_backup_store)
    """

    _default_schema_version: int = 3

    @property
    def default_schema_version(self):
        """ Return the schema version """
        return self._default_schema_version

    def __init__(self, config: Optional[Dict[str, Any]] = None, data: Optional[str] = None) -> None:
        """
        Construct a certificate authority db object.

        Args:
            data (dict): The ca_config dict that may contain a previous database backup
        """
        self.certs_expired: Set[str] = set()
        self.certs_expires_soon: Set[str] = set()
        self.certs_revoked: Set[str] = set()
        self.certs_valid: Set[str] = set()
        self.conn = sqlite3.connect(':memory:')
        self.config_attrs: Tuple[str, ...] = (
            "next_serial",
            "next_crl_serial",
            "org",
            "ou",
            "email",
            "city",
            "state",
            "country",
            "ca_url",
            "crl_url",
            "days",
            "crl_days",
            "schema_version",
            "ca_public_store",
            "ca_private_store",
            "ca_backup_store",
        )

        if data:
            self.import_database(data)

        else:
            # Build a shiny new DB from config
            self.create_config_table(config or {})
            self.create_ca_table()

        self.create_database_index()


    # --------------------------
    # Schema / setup
    # --------------------------

    def create_ca_table(self) -> None:
        """ Create a table to track certificates """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS certificate_authority (
                serial TEXT PRIMARY KEY,
                cn TEXT,
                title TEXT,
                status TEXT,
                expiry_date TEXT,
                revocation_date TEXT,
                subject TEXT
            )
            """
        )
        self.conn.commit()
        cursor.close()

    def create_config_table(self, config: Dict[str, Any]) -> None:
        """
        Create and populate the CA configuration table

        Args:
            config (dict): The config data to insert
        """

        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                next_serial TEXT,
                next_crl_serial TEXT,
                org TEXT,
                ou TEXT,
                email TEXT,
                city TEXT,
                state TEXT,
                country TEXT,
                ca_url TEXT,
                crl_url TEXT,
                days INTEGER,
                crl_days INTEGER,
                schema_version INTEGER,
                ca_public_store TEXT,
                ca_private_store TEXT,
                ca_backup_store TEXT
            )
            """
        )
        self.conn.commit()

        # Normalize None → '' for string fields so inserts don't fail.
        for key in self.config_attrs:
            if key in config and config[key] is None:
                config[key] = ""

        # Cast serials to string if present
        if "next_serial" in config:
            config["next_serial"] = str(config["next_serial"])
        if "next_crl_serial" in config:
            config["next_crl_serial"] = str(config["next_crl_serial"])

        if config.get("command") == "rebuild-ca-database":
            if not config.get("next_crl_serial"):
                config["next_crl_serial"] = "1"

        filtered_dict = {k: config[k] for k in self.config_attrs if k in config}

        filtered_dict["id"] = 1
        filtered_dict["schema_version"] = self.default_schema_version

        columns = ", ".join(filtered_dict.keys())
        placeholders = ", ".join(["?"] * len(filtered_dict))
        sql = f"INSERT INTO config ({columns}) VALUES ({placeholders})"

        cursor.execute(sql, tuple(filtered_dict.values()))
        self.conn.commit()

        cursor.close()

    def create_database_index(self) -> None:
        """ Create database indexes """

        cursor = self.conn.cursor()

        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ca_cn ON certificate_authority (cn)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ca_title ON certificate_authority (title)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ca_status ON certificate_authority (status)")
            self.conn.commit()
        finally:
            cursor.close()

    def import_database(self, data: str) -> Dict[str, Any]:
        """
        Imports the database from a previous export, and update the schema if required

        Args:
            data (str): The SQLite database backup to import
        """

        self.conn.executescript(data)

        schema_version = self.get_config_attributes(attrs=("schema_version",))["schema_version"]

        info: Dict[str, Any] = {"migrated": False, "from": schema_version, "to": self.default_schema_version, "steps": []}
        if schema_version >= self.default_schema_version:
            return info

        cursor = self.conn.cursor()
        try:
            if schema_version == 1:
                step = {"to": 2, "ok": False}
                cursor.execute('ALTER TABLE config ADD COLUMN ou TEXT;')
                cursor.execute('UPDATE config SET schema_version=2 WHERE id=1;')
                self.conn.commit()
                schema_version = 2
                step["ok"] = True
                info["steps"].append(step)

            if schema_version == 2:
                step = {"to": 3, "ok": False}
                cursor.execute('ALTER TABLE config ADD COLUMN ca_public_store TEXT;')
                cursor.execute('ALTER TABLE config ADD COLUMN ca_private_store TEXT;')
                cursor.execute('ALTER TABLE config ADD COLUMN ca_backup_store TEXT;')
                cursor.execute('UPDATE config SET schema_version=3 WHERE id=1;')
                self.conn.commit()
                schema_version = 3
                step["ok"] = True
                info["steps"].append(step)

            info["migrated"] = True
            return info
        except sqlite3.Error as e:
            raise CADatabaseError(f"Failed to migrate schema: {e}") from e
        finally:
            cursor.close()


    # --------------------------
    # CRUD helpers
    # --------------------------

    def add_cert(self, cert_db_item: Dict[str, Any]) -> bool:
        """
        Add a certificate record to the database

        Args:
            cert_db_item (dict): A structure of the certificate record to add
        """
        cert_db_item["serial"] = str(cert_db_item["serial"])
        cursor = self.conn.cursor()

        columns = ", ".join(cert_db_item.keys())
        placeholders = ", ".join(["?"] * len(cert_db_item))
        sql = f"INSERT INTO certificate_authority ({columns}) VALUES ({placeholders})"

        try:
            cursor.execute(sql, tuple(cert_db_item.values()))
            self.conn.commit()
            return True

        except sqlite3.Error as sqlite_error:
            raise CADatabaseError(f"SQLite insert error: {sqlite_error}") from sqlite_error
        finally:
            cursor.close()

    def update_cert(self, cert_db_item: Dict[str, Any]) -> bool:
        """
        Update an existing certificate record in the database.

        Args:
            cert_db_item (dict): A structure of the certificate record to update. 
                                Must include 'serial' to identify the record.
        """

        if "serial" not in cert_db_item:
            raise ValueError("The 'serial' key must be provided in cert_db_item to update a certificate.")

        item = dict(cert_db_item)
        cursor = self.conn.cursor()
        serial_number = item.pop('serial')

        columns = ', '.join([f"{key} = ?" for key in item.keys()])
        sql = f"UPDATE certificate_authority SET {columns} WHERE serial = ?"

        try:
            cursor.execute(sql, tuple(item.values()) + (serial_number,))
            self.conn.commit()

            if cursor.rowcount == 0:
                raise CADatabaseError(f"No certificate found with serial number {serial_number}.")

            return True

        except sqlite3.Error as sqlite_error:
            raise CADatabaseError(f"SQLite update error: {sqlite_error}") from sqlite_error
        finally:
            cursor.close()

    def update_config(self, config: Dict[str, Any]) -> bool:
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
            raise CADatabaseError(f"Error updating config: {sqlite_error}") from sqlite_error
        finally:
            cursor.close()

    # --------------------------
    # Queries / utilities
    # --------------------------

    def count_certs(self) -> int:
        """
        Count the number of certificates in the database.

        Returns:
            int: The number of certificates.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM certificate_authority")
        count = cursor.fetchone()[0]
        cursor.close()
        return count

    def export_database(self) -> bytes:
        """ Export the entire database to a io.BytesIO object """

        memory_file = io.BytesIO()

        for line in self.conn.iterdump():
            memory_file.write(line.encode('utf-8'))

        return memory_file.getvalue()

    def export_database_binary(self) -> bytes:
        """
        Export the in-memory database as a binary SQLite file.

        Creates a temporary file, backs up the in-memory database to it,
        and returns the raw binary content. This format is suitable for
        uploading to remote storage or archiving.

        Returns:
            bytes: The complete SQLite database in binary format

        Note:
            This is more efficient than export_database() for large databases
            and preserves the exact SQLite structure including indexes.
        """
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=True) as tmp_file:

            disk_conn = sqlite3.connect(tmp_file.name)

            self.conn.backup(disk_conn)
            disk_conn.close()

            tmp_file.seek(0)
            return tmp_file.read()

    def get_config_attributes(self, attrs: Optional[Sequence[str]] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve config attributes from the database.

        Args:
            attrs (tuple): The config attributes to retrieve
        """
        try:
            cursor = self.conn.cursor()

            if attrs is None:
                attrs = self.config_attrs

            columns = ', '.join(attrs)
            sql = f'SELECT {columns} FROM config LIMIT 1'

            cursor.execute(sql)
            row = cursor.fetchone()

            if row:
                result: Dict[str, Any] = dict(zip(attrs, row))

                if 'next_serial' in attrs:
                    try:
                        result['next_serial'] = int(result['next_serial'])

                    except ValueError:
                        result['next_serial'] = None

                if 'next_crl_serial' in attrs:
                    try:
                        result['next_crl_serial'] = int(result['next_crl_serial'])

                    except ValueError:
                        result['next_crl_serial'] = None

                return result

            return None

        except sqlite3.Error as e:
            raise CADatabaseError(f"Error retrieving config attributes: {e}") from e
        finally:
            cursor.close()

    def query_cert(self, cert_info: Dict[str, str], valid_only: bool = False) -> Optional[Dict[str, Any]]:
        """
        Search for a certificate by serial or CN and return the record if it exists

        Args:
            cert_info (dict): key - The certificate attribute (cn, title or serial)
                            value - The attribute data
            valid_only (bool): Only show valid results by default
        """
        cursor = self.conn.cursor()

        where_conditions: List[str] = []
        values: List[str] = []

        if 'serial' in cert_info:
            where_conditions.append("serial=?")
            values.append(cert_info["serial"])

        elif 'title' in cert_info:
            where_conditions.append("title=?")
            values.append(cert_info["title"])

        elif 'cn' in cert_info:
            where_conditions.append("cn=?")
            values.append(cert_info["cn"])

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
            result = dict(zip(columns, row))
            cursor.close()
            return result

        cursor.close()

        return None

    def increment_serial(self, serial_type: str, serial_number: Optional[int] = None) -> int:
        """
        Get the current serial number and increment the counter for next use.

        Serial numbers are used for certificates ('cert') and CRLs ('crl').
        The counter is automatically incremented after returning the current value.

        Args:
            serial_type: The type of serial to act on - either 'cert' or 'crl'
            serial_number: Optional explicit serial to ensure counter is at least this value

        Returns:
            int: The current serial number (before increment)

        Raises:
            ValueError: If serial_type is not 'cert' or 'crl'

        Note:
            If serial_number is provided and is greater than the current counter,
            the counter will jump to that value before incrementing.
        """
        cursor = self.conn.cursor()

        if serial_type == 'cert':
            column_name = 'next_serial'

        elif serial_type == 'crl':
            column_name = 'next_crl_serial'

        else:
            raise ValueError("Invalid serial type. Expected 'cert' or 'crl'.")

        cursor.execute(f"SELECT { column_name } FROM config LIMIT 1")
        row = cursor.fetchone()
        raw = row[0] if row else None

        try:
            current_value = int(raw) if (raw is not None and str(raw).strip() != "") else 0
        except (TypeError, ValueError):
            current_value = 0

        # If caller supplies an explicit serial (cert path), bump forward if needed
        if serial_number is not None:
            try:
                sn = int(serial_number)
                if sn > current_value:
                    current_value = sn
            except (TypeError, ValueError):
                pass

        next_serial = current_value + 1
        cursor.execute(f"UPDATE config SET {column_name} = ?", (str(next_serial),))

        self.conn.commit()
        cursor.close()

        return current_value

    def process_ca_database(self, revoke_serial: Optional[Union[int, str]] = None) -> bool:
        """
        Process the certificate database to update certificate states.

        Scans all certificates and:
        1. Updates status based on expiry dates (Valid -> Expired)
        2. Optionally revokes a certificate by serial number
        3. Categorizes certificates into sets:
           - certs_expired: Certificates past their not_after date
           - certs_revoked: Certificates marked as revoked
           - certs_expires_soon: Valid certificates expiring within 30 days
           - certs_valid: All other valid certificates

        The status field in the database is automatically updated for expired
        or newly revoked certificates.

        Args:
            revoke_serial: Optional serial number of certificate to revoke during processing

        Returns:
            bool: True if any database records were modified, False otherwise

        Side effects:
            Updates the following instance attributes with certificate serial sets:
            - self.certs_expired
            - self.certs_revoked
            - self.certs_expires_soon
            - self.certs_valid
        """
        db_changed = False
        self.certs_expired = set()
        self.certs_expires_soon = set()
        self.certs_revoked = set()
        self.certs_valid = set()
        expiry_warning_days = 30
        try:
            cfg = self.get_config_attributes(attrs=("crl_days",))
            if cfg and isinstance(cfg.get("crl_days"), int) and cfg["crl_days"] > 0:
                # leave as 30 unless you want to tie to crl_days; otherwise skip this block
                pass
        except CADatabaseError:
            pass

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM certificate_authority")
        all_certs = cursor.fetchall()

        columns = [desc[0] for desc in cursor.description]
        cursor.close()
        all_cert_dicts = [dict(zip(columns, cert)) for cert in all_certs]

        for cert in all_cert_dicts:
            cert_changed = False

            expiry_date = parse_datetime(cert["expiry_date"], "openssl")
            expired = now_utc() > expiry_date
            expires_soon = now_utc_plus(days=expiry_warning_days) > expiry_date
            revoked = bool(cert["revocation_date"]) or (cert["status"] == "Revoked")

            if revoke_serial is not None:
                if not expired and not revoked and str(revoke_serial) == str(cert["serial"]):
                    revoked = True
                    cert_changed = True
                    db_changed = True
                    cert["revocation_date"] = now_utc_str("openssl")

            if expired:
                if cert["status"] != "Expired":
                    cert_changed = True
                    db_changed = True
                    cert["status"] = "Expired"

                self.certs_expired.add(cert["serial"])

            elif revoked:
                if cert["status"] != "Revoked":
                    cert_changed = True
                    db_changed = True
                    cert["status"] = "Revoked"

                self.certs_revoked.add(cert["serial"])

            elif expires_soon:
                self.certs_expires_soon.add(cert["serial"])

            else:
                self.certs_valid.add(cert["serial"])

            if cert_changed:
                self.update_cert(cert_db_item=cert)

        return db_changed

    def close(self) -> None:
        """ Close the database connection """
        self.conn.close()
