"""Unit tests for opca.services.database module."""

import sqlite3
from datetime import datetime, timezone, timedelta
import pytest

from opca.services.database import CertificateAuthorityDB
from opca.services.ca_errors import CADatabaseError


class TestDatabaseInitialization:
    """Tests for CertificateAuthorityDB initialization."""

    def test_init_creates_empty_database(self):
        """Should create an in-memory database with default schema."""
        config = {
            "next_serial": 1,
            "next_crl_serial": 1,
            "days": 365,
            "crl_days": 30,
            "org": "Test Org",
            "country": "US",
        }

        db = CertificateAuthorityDB(config)

        assert db.conn is not None
        assert db.default_schema_version == 6

    def test_init_creates_config_table(self):
        """Should create and populate config table."""
        config = {
            "next_serial": 100,
            "next_crl_serial": 10,
            "days": 365,
            "crl_days": 30,
        }

        db = CertificateAuthorityDB(config)
        result = db.get_config_attributes(attrs=("next_serial", "next_crl_serial"))

        assert result["next_serial"] == 100
        assert result["next_crl_serial"] == 10

    def test_init_creates_certificate_table(self):
        """Should create certificate_authority table."""
        db = CertificateAuthorityDB({})

        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificate_authority'")
        result = cursor.fetchone()

        assert result is not None

    def test_init_creates_external_cert_table(self):
        """Should create external_certificate table."""
        db = CertificateAuthorityDB({})

        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='external_certificate'")
        result = cursor.fetchone()

        assert result is not None

    def test_init_creates_indexes(self):
        """Should create database indexes."""
        db = CertificateAuthorityDB({})

        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = [row[0] for row in cursor.fetchall()]

        assert "idx_ca_cn" in indexes
        assert "idx_ca_title" in indexes
        assert "idx_ca_status" in indexes
        assert "idx_ext_cn" in indexes
        assert "idx_ext_status" in indexes

    def test_init_sets_schema_version(self):
        """Should set schema version to current default."""
        db = CertificateAuthorityDB({})
        config = db.get_config_attributes(attrs=("schema_version",))

        assert config["schema_version"] == 6


class TestConfigOperations:
    """Tests for configuration management."""

    def test_get_config_attributes_all(self):
        """Should retrieve all config attributes."""
        config = {
            "next_serial": 1,
            "next_crl_serial": 1,  # Need to set this too
            "days": 365,
            "org": "Test Org",
            "country": "US",
        }

        db = CertificateAuthorityDB(config)
        result = db.get_config_attributes()

        # Should return all config attrs (not just the ones we set)
        assert result is not None
        assert "next_serial" in result
        assert "days" in result
        assert "org" in result
        assert "country" in result
        # Verify values
        assert result["next_serial"] == 1
        assert result["days"] == 365
        assert result["org"] == "Test Org"
        assert result["country"] == "US"

    def test_get_config_attributes_specific(self):
        """Should retrieve specific config attributes."""
        config = {
            "next_serial": 1,
            "days": 365,
            "org": "Test Org",
        }

        db = CertificateAuthorityDB(config)
        result = db.get_config_attributes(attrs=("days", "org"))

        assert result == {"days": 365, "org": "Test Org"}

    def test_update_config(self):
        """Should update config values."""
        db = CertificateAuthorityDB({"next_serial": 1})

        success = db.update_config({"next_serial": 100})

        assert success is True
        result = db.get_config_attributes(attrs=("next_serial",))
        assert result["next_serial"] == 100

    def test_update_config_multiple_fields(self):
        """Should update multiple config fields."""
        db = CertificateAuthorityDB({"next_serial": 1, "days": 365})

        db.update_config({"next_serial": 50, "days": 730})

        result = db.get_config_attributes(attrs=("next_serial", "days"))
        assert result["next_serial"] == 50
        assert result["days"] == 730

    def test_config_handles_none_values(self):
        """Should handle None values in config."""
        config = {
            "next_serial": 1,
            "org": None,
            "country": None,
        }

        db = CertificateAuthorityDB(config)
        result = db.get_config_attributes(attrs=("org", "country"))

        # None should be converted to empty string
        assert result["org"] == ""
        assert result["country"] == ""


class TestSerialNumberManagement:
    """Tests for serial number incrementing."""

    def test_increment_cert_serial(self):
        """Should increment certificate serial number."""
        db = CertificateAuthorityDB({"next_serial": "10"})

        current = db.increment_serial("cert")

        assert current == 10
        result = db.get_config_attributes(attrs=("next_serial",))
        assert result["next_serial"] == 11

    def test_increment_crl_serial(self):
        """Should increment CRL serial number."""
        db = CertificateAuthorityDB({"next_crl_serial": "5"})

        current = db.increment_serial("crl")

        assert current == 5
        result = db.get_config_attributes(attrs=("next_crl_serial",))
        assert result["next_crl_serial"] == 6

    def test_increment_serial_invalid_type(self):
        """Should raise ValueError for invalid serial type."""
        db = CertificateAuthorityDB({})

        with pytest.raises(ValueError, match="Invalid serial type"):
            db.increment_serial("invalid")

    def test_increment_serial_with_explicit_number(self):
        """Should jump to explicit serial if higher."""
        db = CertificateAuthorityDB({"next_serial": "10"})

        current = db.increment_serial("cert", serial_number=50)

        assert current == 50
        result = db.get_config_attributes(attrs=("next_serial",))
        assert result["next_serial"] == 51

    def test_increment_serial_explicit_lower_ignored(self):
        """Should ignore explicit serial if lower than current."""
        db = CertificateAuthorityDB({"next_serial": "100"})

        current = db.increment_serial("cert", serial_number=50)

        # Should use current (100) not explicit (50)
        assert current == 100
        result = db.get_config_attributes(attrs=("next_serial",))
        assert result["next_serial"] == 101

    def test_increment_serial_from_zero(self):
        """Should handle missing/zero serial."""
        db = CertificateAuthorityDB({})

        current = db.increment_serial("cert")

        # Should start from 0 and increment to 1
        assert current == 0
        result = db.get_config_attributes(attrs=("next_serial",))
        assert result["next_serial"] == 1


class TestCertificateOperations:
    """Tests for certificate CRUD operations."""

    def test_add_cert(self):
        """Should add certificate to database."""
        db = CertificateAuthorityDB({})

        cert_item = {
            "serial": "100",
            "cn": "server.example.com",
            "title": "Test Server",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=server.example.com,O=Test",
        }

        success = db.add_cert(cert_item)

        assert success is True

    def test_add_cert_stores_as_string_serial(self):
        """Should store serial as string."""
        db = CertificateAuthorityDB({})

        cert_item = {
            "serial": 100,  # Integer
            "cn": "test.com",
            "title": "Test",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=test.com",
        }

        db.add_cert(cert_item)
        result = db.query_cert({"serial": "100"}, valid_only=False)

        assert result["serial"] == "100"

    def test_query_cert_by_serial(self):
        """Should query certificate by serial number."""
        db = CertificateAuthorityDB({})

        cert_item = {
            "serial": "100",
            "cn": "server.example.com",
            "title": "Test Server",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=server.example.com",
        }
        db.add_cert(cert_item)

        result = db.query_cert({"serial": "100"}, valid_only=False)

        assert result["cn"] == "server.example.com"
        assert result["serial"] == "100"

    def test_query_cert_by_cn(self):
        """Should query certificate by CN."""
        db = CertificateAuthorityDB({})

        cert_item = {
            "serial": "100",
            "cn": "server.example.com",
            "title": "Test Server",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=server.example.com",
        }
        db.add_cert(cert_item)

        result = db.query_cert({"cn": "server.example.com"}, valid_only=False)

        assert result["serial"] == "100"

    def test_query_cert_by_title(self):
        """Should query certificate by title."""
        db = CertificateAuthorityDB({})

        cert_item = {
            "serial": "100",
            "cn": "server.example.com",
            "title": "Test Server",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=server.example.com",
        }
        db.add_cert(cert_item)

        result = db.query_cert({"title": "Test Server"}, valid_only=False)

        assert result["serial"] == "100"

    def test_query_cert_valid_only(self):
        """Should filter by valid status."""
        db = CertificateAuthorityDB({})

        # Add expired cert
        db.add_cert({
            "serial": "100",
            "cn": "expired.example.com",
            "title": "Expired",
            "status": "Expired",
            "expiry_date": "20200101000000Z",
            "subject": "CN=expired.example.com",
        })

        result = db.query_cert({"serial": "100"}, valid_only=True)

        # Should not find expired cert when valid_only=True
        assert result is None

    def test_query_cert_not_found(self):
        """Should return None for non-existent certificate."""
        db = CertificateAuthorityDB({})

        result = db.query_cert({"serial": "999"}, valid_only=False)

        assert result is None

    def test_update_cert(self):
        """Should update existing certificate."""
        db = CertificateAuthorityDB({})

        # Add cert
        db.add_cert({
            "serial": "100",
            "cn": "test.com",
            "title": "Original",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=test.com",
        })

        # Update title
        updated_cert = {
            "serial": "100",
            "title": "Updated",
        }
        success = db.update_cert(updated_cert)

        assert success is True
        result = db.query_cert({"serial": "100"}, valid_only=False)
        assert result["title"] == "Updated"

    def test_update_cert_requires_serial(self):
        """Should raise ValueError if serial is missing."""
        db = CertificateAuthorityDB({})

        with pytest.raises(ValueError, match="serial"):
            db.update_cert({"cn": "test.com"})

    def test_update_nonexistent_cert_raises_error(self):
        """Should raise CADatabaseError for non-existent certificate."""
        db = CertificateAuthorityDB({})

        with pytest.raises(CADatabaseError, match="No certificate found"):
            db.update_cert({"serial": "999", "title": "New"})

    def test_count_certs(self):
        """Should count certificates in database."""
        db = CertificateAuthorityDB({})

        # Initially 0
        assert db.count_certs() == 0

        # Add certs
        db.add_cert({
            "serial": "1",
            "cn": "test1.com",
            "title": "Test1",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=test1.com",
        })
        db.add_cert({
            "serial": "2",
            "cn": "test2.com",
            "title": "Test2",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=test2.com",
        })

        assert db.count_certs() == 2


class TestDatabaseProcessing:
    """Tests for process_ca_database functionality."""

    def test_process_categorizes_valid_certs(self):
        """Should categorize certificates by status."""
        db = CertificateAuthorityDB({})

        # Add valid cert
        future_date = (datetime.now(timezone.utc) + timedelta(days=100)).strftime("%Y%m%d%H%M%SZ")
        db.add_cert({
            "serial": "1",
            "cn": "valid.com",
            "title": "Valid",
            "status": "Valid",
            "expiry_date": future_date,
            "subject": "CN=valid.com",
        })

        db.process_ca_database()

        assert "1" in db.certs_valid
        assert "1" not in db.certs_expired
        assert "1" not in db.certs_revoked

    def test_process_categorizes_expiring_soon(self):
        """Should identify certificates expiring within 30 days."""
        db = CertificateAuthorityDB({})

        # Add cert expiring in 15 days
        expiry_date = (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y%m%d%H%M%SZ")
        db.add_cert({
            "serial": "1",
            "cn": "expiring.com",
            "title": "Expiring",
            "status": "Valid",
            "expiry_date": expiry_date,
            "subject": "CN=expiring.com",
        })

        db.process_ca_database()

        assert "1" in db.certs_expires_soon
        assert "1" not in db.certs_valid
        assert "1" not in db.certs_expired

    def test_process_categorizes_expired_certs(self):
        """Should identify expired certificates."""
        db = CertificateAuthorityDB({})

        # Add expired cert
        db.add_cert({
            "serial": "1",
            "cn": "expired.com",
            "title": "Expired",
            "status": "Valid",  # Status will be updated
            "expiry_date": "20200101000000Z",
            "subject": "CN=expired.com",
        })

        db.process_ca_database()

        assert "1" in db.certs_expired
        assert "1" not in db.certs_valid

        # Status should be updated
        cert = db.query_cert({"serial": "1"}, valid_only=False)
        assert cert["status"] == "Expired"

    def test_process_revokes_certificate(self):
        """Should revoke certificate when revoke_serial is provided."""
        db = CertificateAuthorityDB({})

        future_date = (datetime.now(timezone.utc) + timedelta(days=100)).strftime("%Y%m%d%H%M%SZ")
        db.add_cert({
            "serial": "1",
            "cn": "test.com",
            "title": "Test",
            "status": "Valid",
            "expiry_date": future_date,
            "subject": "CN=test.com",
        })

        db.process_ca_database(revoke_serial="1")

        assert "1" in db.certs_revoked
        cert = db.query_cert({"serial": "1"}, valid_only=False)
        assert cert["status"] == "Revoked"
        assert cert["revocation_date"] is not None

    def test_process_returns_true_when_changes_made(self):
        """Should return True when database changes are made."""
        db = CertificateAuthorityDB({})

        # Add expired cert that will be updated
        db.add_cert({
            "serial": "1",
            "cn": "expired.com",
            "title": "Expired",
            "status": "Valid",
            "expiry_date": "20200101000000Z",
            "subject": "CN=expired.com",
        })

        result = db.process_ca_database()

        assert result is True

    def test_process_returns_false_when_no_changes(self):
        """Should return False when no changes are made."""
        db = CertificateAuthorityDB({})

        # Add already-expired cert
        db.add_cert({
            "serial": "1",
            "cn": "expired.com",
            "title": "Expired",
            "status": "Expired",
            "expiry_date": "20200101000000Z",
            "subject": "CN=expired.com",
        })

        result = db.process_ca_database()

        assert result is False


class TestDatabaseExport:
    """Tests for database export operations."""

    def test_export_database(self):
        """Should export database as SQL text."""
        db = CertificateAuthorityDB({"next_serial": 1})

        exported = db.export_database()

        assert isinstance(exported, bytes)
        # Should contain SQL statements
        assert b"CREATE TABLE" in exported or b"INSERT INTO" in exported

    def test_export_database_binary(self):
        """Should export database as binary SQLite."""
        db = CertificateAuthorityDB({"next_serial": 1})

        exported = db.export_database_binary()

        assert isinstance(exported, bytes)
        # SQLite files start with "SQLite format 3"
        assert exported.startswith(b"SQLite format 3")

    def test_import_database(self):
        """Should import database from SQL export."""
        # Create and export database
        db1 = CertificateAuthorityDB({"next_serial": 100, "days": 365})
        db1.add_cert({
            "serial": "1",
            "cn": "test.com",
            "title": "Test",
            "status": "Valid",
            "expiry_date": "20251231235959Z",
            "subject": "CN=test.com",
        })
        exported = db1.export_database().decode("utf-8")

        # Import into new database
        db2 = CertificateAuthorityDB(data=exported)

        # Verify config
        config = db2.get_config_attributes(attrs=("next_serial", "days"))
        assert config["next_serial"] == 100
        assert config["days"] == 365

        # Verify cert
        cert = db2.query_cert({"serial": "1"}, valid_only=False)
        assert cert["cn"] == "test.com"


class TestSchemaMigration:
    """Tests for schema version migrations."""

    def test_schema_migration_path_exists(self):
        """Should have migration path defined in code."""
        # This test verifies that the schema migration code exists
        # We can't easily test actual v1->v2 migration without creating a real v1 database
        # from scratch, so we just verify the migration code path is present

        db = CertificateAuthorityDB({})

        # Verify current schema is v3
        config = db.get_config_attributes(attrs=("schema_version",))
        assert config["schema_version"] == 6

        # Verify import_database method exists and handles schema versions
        import inspect
        source = inspect.getsource(db.import_database)

        # Should have migration logic for v1 and v2
        assert "schema_version == 1" in source
        assert "schema_version == 2" in source
        assert "ADD COLUMN ou" in source
        assert "ADD COLUMN ca_public_store" in source

    def test_current_schema_no_migration(self):
        """Should not migrate if already at current schema."""
        db = CertificateAuthorityDB({"next_serial": 1})

        exported = db.export_database().decode("utf-8")
        db2 = CertificateAuthorityDB(data=exported)

        config = db2.get_config_attributes(attrs=("schema_version",))
        assert config["schema_version"] == 6


class TestExternalCertificateOperations:
    """Tests for external certificate CRUD operations."""

    def _make_ext_cert(self, serial="500", cn="ext.example.com", **overrides):
        item = {
            "serial": serial,
            "cn": cn,
            "title": f"EXT_{cn}",
            "status": "Valid",
            "expiry_date": "20261231235959Z",
            "subject": f"CN={cn}",
            "issuer": "Let's Encrypt",
            "issuer_subject": "CN=R3,O=Let's Encrypt,C=US",
            "import_date": "20260101120000Z",
        }
        item.update(overrides)
        return item

    def test_add_external_cert(self):
        """Should add external certificate to database."""
        db = CertificateAuthorityDB({})
        success = db.add_external_cert(self._make_ext_cert())
        assert success is True

    def test_add_external_cert_stores_string_serial(self):
        """Should store serial as string."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert(serial=500))
        result = db.query_external_cert({"serial": "500"}, valid_only=False)
        assert result["serial"] == "500"

    def test_query_external_cert_by_serial(self):
        """Should query external certificate by serial."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert())
        result = db.query_external_cert({"serial": "500"}, valid_only=False)
        assert result["cn"] == "ext.example.com"
        assert result["issuer"] == "Let's Encrypt"
        assert result["issuer_subject"] == "CN=R3,O=Let's Encrypt,C=US"
        assert result["import_date"] == "20260101120000Z"

    def test_query_external_cert_by_cn(self):
        """Should query external certificate by CN."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert())
        result = db.query_external_cert({"cn": "ext.example.com"}, valid_only=False)
        assert result["serial"] == "500"

    def test_query_external_cert_by_title(self):
        """Should query external certificate by title."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert())
        result = db.query_external_cert({"title": "EXT_ext.example.com"}, valid_only=False)
        assert result["serial"] == "500"

    def test_query_external_cert_valid_only(self):
        """Should filter by valid status."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert(status="Expired"))
        result = db.query_external_cert({"serial": "500"}, valid_only=True)
        assert result is None

    def test_query_external_cert_not_found(self):
        """Should return None for non-existent external certificate."""
        db = CertificateAuthorityDB({})
        result = db.query_external_cert({"serial": "999"}, valid_only=False)
        assert result is None

    def test_update_external_cert(self):
        """Should update existing external certificate."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert())

        success = db.update_external_cert({"serial": "500", "status": "Expired"})
        assert success is True

        result = db.query_external_cert({"serial": "500"}, valid_only=False)
        assert result["status"] == "Expired"

    def test_update_external_cert_requires_serial(self):
        """Should raise ValueError if serial is missing."""
        db = CertificateAuthorityDB({})
        with pytest.raises(ValueError, match="serial"):
            db.update_external_cert({"cn": "test.com"})

    def test_update_nonexistent_external_cert_raises_error(self):
        """Should raise CADatabaseError for non-existent external certificate."""
        db = CertificateAuthorityDB({})
        with pytest.raises(CADatabaseError, match="No external certificate found"):
            db.update_external_cert({"serial": "999", "status": "Expired"})

    def test_query_all_external_certs(self):
        """Should return all external certificates."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert(serial="1", cn="a.com"))
        db.add_external_cert(self._make_ext_cert(serial="2", cn="b.com"))

        results = db.query_all_external_certs()
        assert len(results) == 2

    def test_query_all_external_certs_filtered(self):
        """Should filter external certificates by status."""
        db = CertificateAuthorityDB({})
        db.add_external_cert(self._make_ext_cert(serial="1", cn="a.com", status="Valid"))
        db.add_external_cert(self._make_ext_cert(serial="2", cn="b.com", status="Expired"))

        results = db.query_all_external_certs(status="Valid")
        assert len(results) == 1
        assert results[0]["cn"] == "a.com"

    def test_count_external_certs(self):
        """Should count external certificates."""
        db = CertificateAuthorityDB({})
        assert db.count_external_certs() == 0

        db.add_external_cert(self._make_ext_cert(serial="1", cn="a.com"))
        db.add_external_cert(self._make_ext_cert(serial="2", cn="b.com"))
        assert db.count_external_certs() == 2


class TestExternalCertProcessing:
    """Tests for process_ca_database with external certificates."""

    def test_process_categorises_valid_external_certs(self):
        """Should categorise valid external certificates."""
        db = CertificateAuthorityDB({})
        future_date = (datetime.now(timezone.utc) + timedelta(days=100)).strftime("%Y%m%d%H%M%SZ")

        db.add_external_cert({
            "serial": "500",
            "cn": "ext.com",
            "title": "EXT_ext.com",
            "status": "Valid",
            "expiry_date": future_date,
            "subject": "CN=ext.com",
            "issuer": "External CA",
            "issuer_subject": "CN=External CA",
            "import_date": "20260101120000Z",
        })

        db.process_ca_database()

        assert "500" in db.ext_certs_valid
        assert "500" not in db.ext_certs_expired
        assert "500" not in db.ext_certs_expires_soon

    def test_process_categorises_expired_external_certs(self):
        """Should identify expired external certificates."""
        db = CertificateAuthorityDB({})

        db.add_external_cert({
            "serial": "500",
            "cn": "ext.com",
            "title": "EXT_ext.com",
            "status": "Valid",
            "expiry_date": "20200101000000Z",
            "subject": "CN=ext.com",
            "issuer": "External CA",
            "issuer_subject": "CN=External CA",
            "import_date": "20260101120000Z",
        })

        db.process_ca_database()

        assert "500" in db.ext_certs_expired
        assert "500" not in db.ext_certs_valid

    def test_process_categorises_expiring_external_certs(self):
        """Should identify external certificates expiring soon."""
        db = CertificateAuthorityDB({})
        expiry_date = (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y%m%d%H%M%SZ")

        db.add_external_cert({
            "serial": "500",
            "cn": "ext.com",
            "title": "EXT_ext.com",
            "status": "Valid",
            "expiry_date": expiry_date,
            "subject": "CN=ext.com",
            "issuer": "External CA",
            "issuer_subject": "CN=External CA",
            "import_date": "20260101120000Z",
        })

        db.process_ca_database()

        assert "500" in db.ext_certs_expires_soon
        assert "500" not in db.ext_certs_valid
        assert "500" not in db.ext_certs_expired

    def test_external_certs_separate_from_local(self):
        """External certs should not appear in local cert sets."""
        db = CertificateAuthorityDB({})
        future_date = (datetime.now(timezone.utc) + timedelta(days=100)).strftime("%Y%m%d%H%M%SZ")

        db.add_cert({
            "serial": "1",
            "cn": "local.com",
            "title": "Local",
            "status": "Valid",
            "expiry_date": future_date,
            "subject": "CN=local.com",
        })
        db.add_external_cert({
            "serial": "500",
            "cn": "ext.com",
            "title": "EXT_ext.com",
            "status": "Valid",
            "expiry_date": future_date,
            "subject": "CN=ext.com",
            "issuer": "External CA",
            "issuer_subject": "CN=External CA",
            "import_date": "20260101120000Z",
        })

        db.process_ca_database()

        assert "1" in db.certs_valid
        assert "500" not in db.certs_valid
        assert "500" in db.ext_certs_valid
        assert "1" not in db.ext_certs_valid


class TestSchemaMigrationV5ToV6:
    """Tests for v5 to v6 schema migration."""

    def _create_v5_database(self) -> str:
        """Create a v5-schema database and return its SQL export."""
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()

        # Create v5 schema tables (config is a single-row table with columns)
        cursor.execute("""
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
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificate_authority (
                serial TEXT PRIMARY KEY,
                cn TEXT,
                title TEXT,
                status TEXT,
                expiry_date TEXT,
                subject TEXT,
                revocation_date TEXT,
                issuer TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS csr (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cn TEXT,
                title TEXT,
                csr_type TEXT,
                email TEXT,
                subject TEXT,
                status TEXT,
                created_date TEXT
            )
        """)

        # Config (single row)
        cursor.execute(
            "INSERT INTO config (id, next_serial, next_crl_serial, days, crl_days, schema_version) "
            "VALUES (1, '10', '1', 365, 30, 5)"
        )

        # Local cert
        cursor.execute(
            "INSERT INTO certificate_authority VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("1", "local.com", "local.com", "Valid", "20271231235959Z", "CN=local.com", None, None),
        )
        # External cert (has issuer)
        cursor.execute(
            "INSERT INTO certificate_authority VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("500", "ext.com", "ext.com", "Valid", "20271231235959Z", "CN=ext.com", None, "Let's Encrypt"),
        )

        conn.commit()

        # Export as SQL
        lines = []
        for line in conn.iterdump():
            lines.append(line)
        conn.close()
        return "\n".join(lines)

    def test_migration_creates_external_cert_table(self):
        """Migration should create external_certificate table."""
        sql = self._create_v5_database()
        db = CertificateAuthorityDB(data=sql)

        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='external_certificate'")
        assert cursor.fetchone() is not None

    def test_migration_moves_external_certs(self):
        """Migration should move external certs to new table."""
        sql = self._create_v5_database()
        db = CertificateAuthorityDB(data=sql)

        # External cert should be in new table
        ext = db.query_external_cert({"serial": "500"}, valid_only=False)
        assert ext is not None
        assert ext["cn"] == "ext.com"
        assert ext["issuer"] == "Let's Encrypt"

        # External cert should be removed from certificate_authority
        local_ext = db.query_cert({"serial": "500"}, valid_only=False)
        assert local_ext is None

    def test_migration_preserves_local_certs(self):
        """Migration should keep local certs in certificate_authority."""
        sql = self._create_v5_database()
        db = CertificateAuthorityDB(data=sql)

        local = db.query_cert({"serial": "1"}, valid_only=False)
        assert local is not None
        assert local["cn"] == "local.com"

    def test_migration_prefixes_external_title(self):
        """Migration should prefix external cert titles with EXT_."""
        sql = self._create_v5_database()
        db = CertificateAuthorityDB(data=sql)

        ext = db.query_external_cert({"serial": "500"}, valid_only=False)
        assert ext["title"] == "EXT_ext.com"

    def test_migration_updates_schema_version(self):
        """Migration should update schema version to 6."""
        sql = self._create_v5_database()
        db = CertificateAuthorityDB(data=sql)

        config = db.get_config_attributes(attrs=("schema_version",))
        assert config["schema_version"] == 6


class TestDatabaseClose:
    """Tests for database cleanup."""

    def test_close_database(self):
        """Should close database connection."""
        db = CertificateAuthorityDB({})

        db.close()

        # Connection should be closed
        # Attempting to use it should raise an error
        with pytest.raises(sqlite3.ProgrammingError):
            db.conn.cursor()
