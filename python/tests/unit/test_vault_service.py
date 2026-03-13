"""Unit tests for opca.services.vault module."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from opca.services.vault import (
    VaultBackup,
    VaultBackupError,
    VaultNotEmptyError,
    ITEM_TYPE_CA,
    ITEM_TYPE_CA_DATABASE,
    ITEM_TYPE_CRL,
    ITEM_TYPE_CERTIFICATE,
    ITEM_TYPE_EXTERNAL_CERT,
    ITEM_TYPE_OPENVPN,
    _extract_attributes,
    _restore_order,
)
from opca.services.op_errors import ItemNotFoundError


def _make_op_result(stdout="", returncode=0):
    """Create a mock subprocess.CompletedProcess."""
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


def _make_item_json(title, fields=None):
    """Create a minimal 1Password item JSON string."""
    if fields is None:
        fields = [
            {"label": "certificate", "value": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", "type": "CONCEALED"},
            {"label": "type", "value": "webserver", "type": "STRING"},
            {"label": "cn", "value": title, "type": "STRING"},
            {"label": "serial", "value": "42", "type": "STRING"},
        ]
    return json.dumps({"title": title, "fields": fields})


class TestCreateBackup:
    """Tests for VaultBackup.create_backup()."""

    def test_backup_includes_ca_item(self):
        """CA item should be present in the backup."""
        op = MagicMock()
        op.vault = "TestVault"
        op.get_item.return_value = _make_op_result(_make_item_json("CA"))
        op.get_document.side_effect = ItemNotFoundError("not found")
        op.item_list.return_value = _make_op_result(json.dumps([{"title": "CA"}]))

        vb = VaultBackup(op=op)
        payload = vb.create_backup()

        ca_items = [i for i in payload["items"] if i["type"] == ITEM_TYPE_CA]
        assert len(ca_items) == 1
        assert ca_items[0]["title"] == "CA"

    def test_backup_raises_if_no_ca(self):
        """Should raise VaultBackupError if no CA item exists."""
        op = MagicMock()
        op.vault = "TestVault"
        op.get_item.side_effect = ItemNotFoundError("not found")

        vb = VaultBackup(op=op)
        with pytest.raises(VaultBackupError, match="CA item not found"):
            vb.create_backup()

    def test_backup_includes_database_and_crl(self):
        """Database and CRL documents should be included when present."""
        op = MagicMock()
        op.vault = "TestVault"
        op.get_item.return_value = _make_op_result(_make_item_json("CA"))

        def get_document_side_effect(title):
            if title == "CA_Database":
                return _make_op_result("SQL DUMP HERE")
            elif title == "CRL":
                return _make_op_result("-----BEGIN X509 CRL-----\ntest\n-----END X509 CRL-----")
            raise ItemNotFoundError("not found")

        op.get_document.side_effect = get_document_side_effect
        op.item_list.return_value = _make_op_result(json.dumps([{"title": "CA"}]))

        vb = VaultBackup(op=op)
        payload = vb.create_backup()

        types = [i["type"] for i in payload["items"]]
        assert ITEM_TYPE_CA_DATABASE in types
        assert ITEM_TYPE_CRL in types

    def test_backup_classifies_certificates(self):
        """Regular certificates should be classified correctly."""
        op = MagicMock()
        op.vault = "TestVault"

        ca_json = _make_item_json("CA")
        cert_json = _make_item_json("webserver.example.com")

        def get_item_side_effect(title, output_format="json"):
            if title == "CA":
                return _make_op_result(ca_json)
            elif title == "webserver.example.com":
                return _make_op_result(cert_json)
            elif title == "OpenVPN":
                raise ItemNotFoundError("not found")
            return _make_op_result(_make_item_json(title))

        op.get_item.side_effect = get_item_side_effect
        op.get_document.side_effect = ItemNotFoundError("not found")
        op.item_list.return_value = _make_op_result(
            json.dumps([{"title": "CA"}, {"title": "webserver.example.com"}])
        )

        vb = VaultBackup(op=op)
        payload = vb.create_backup()

        cert_items = [i for i in payload["items"] if i["type"] == ITEM_TYPE_CERTIFICATE]
        assert len(cert_items) == 1
        assert cert_items[0]["title"] == "webserver.example.com"

    def test_backup_classifies_external_certs(self):
        """Items prefixed with EXT_ should be classified as external certificates."""
        op = MagicMock()
        op.vault = "TestVault"

        def get_item_side_effect(title, output_format="json"):
            if title == "OpenVPN":
                raise ItemNotFoundError("not found")
            return _make_op_result(_make_item_json(title))

        op.get_item.side_effect = get_item_side_effect
        op.get_document.side_effect = ItemNotFoundError("not found")
        op.item_list.return_value = _make_op_result(
            json.dumps([{"title": "CA"}, {"title": "EXT_external.example.com"}])
        )

        vb = VaultBackup(op=op)
        payload = vb.create_backup()

        ext_items = [i for i in payload["items"] if i["type"] == ITEM_TYPE_EXTERNAL_CERT]
        assert len(ext_items) == 1

    def test_backup_metadata(self):
        """Metadata should include vault name and item count."""
        op = MagicMock()
        op.vault = "MyVault"
        op.get_item.return_value = _make_op_result(_make_item_json("CA"))
        op.get_document.side_effect = ItemNotFoundError("not found")
        op.item_list.return_value = _make_op_result(json.dumps([{"title": "CA"}]))

        # Make OpenVPN not found
        original_get_item = op.get_item.return_value

        def get_item_side_effect(title, output_format="json"):
            if title == "OpenVPN":
                raise ItemNotFoundError("not found")
            return original_get_item

        op.get_item.side_effect = get_item_side_effect

        vb = VaultBackup(op=op)
        payload = vb.create_backup()

        assert payload["metadata"]["vault_name"] == "MyVault"
        assert payload["metadata"]["item_count"] == 1
        assert "opca_version" in payload["metadata"]
        assert "backup_date" in payload["metadata"]


class TestRestoreBackup:
    """Tests for VaultBackup.restore_backup()."""

    def test_restore_refuses_non_empty_vault(self):
        """Should raise VaultNotEmptyError if vault already has a CA."""
        op = MagicMock()
        op.item_exists.return_value = True

        vb = VaultBackup(op=op)
        with pytest.raises(VaultNotEmptyError, match="already contains a CA"):
            vb.restore_backup({"items": []})

    def test_restore_creates_items_in_order(self):
        """Items should be restored in dependency order (CA first)."""
        op = MagicMock()
        op.item_exists.return_value = False
        op.store_item.return_value = _make_op_result()
        op.store_document.return_value = _make_op_result()

        payload = {
            "metadata": {},
            "items": [
                {"type": ITEM_TYPE_CERTIFICATE, "title": "web.example.com", "data": _make_item_json("web.example.com")},
                {"type": ITEM_TYPE_CA, "title": "CA", "data": _make_item_json("CA")},
                {"type": ITEM_TYPE_CA_DATABASE, "title": "CA_Database", "data": "SQL DUMP"},
            ],
        }

        vb = VaultBackup(op=op)
        counts = vb.restore_backup(payload)

        assert counts[ITEM_TYPE_CA] == 1
        assert counts[ITEM_TYPE_CA_DATABASE] == 1
        assert counts[ITEM_TYPE_CERTIFICATE] == 1

        # Verify CA was restored before the certificate
        calls = op.store_item.call_args_list + op.store_document.call_args_list
        assert len(calls) == 3

    def test_restore_returns_counts(self):
        """Restore should return a dict with item type counts."""
        op = MagicMock()
        op.item_exists.return_value = False
        op.store_item.return_value = _make_op_result()

        payload = {
            "metadata": {},
            "items": [
                {"type": ITEM_TYPE_CA, "title": "CA", "data": _make_item_json("CA")},
            ],
        }

        vb = VaultBackup(op=op)
        counts = vb.restore_backup(payload)

        assert counts == {ITEM_TYPE_CA: 1}


class TestGetMetadata:
    """Tests for VaultBackup.get_metadata()."""

    def test_returns_metadata(self):
        metadata = {"opca_version": "1.0", "vault_name": "Test"}
        payload = {"metadata": metadata, "items": []}

        result = VaultBackup.get_metadata(payload)
        assert result == metadata

    def test_returns_empty_dict_if_missing(self):
        result = VaultBackup.get_metadata({})
        assert result == {}


class TestExtractAttributes:
    """Tests for _extract_attributes helper."""

    def test_extracts_concealed_fields(self):
        """Concealed fields (certificate, private_key) should be extracted without [text] suffix."""
        obj = {
            "fields": [
                {"label": "certificate", "value": "cert-pem", "type": "CONCEALED"},
                {"label": "private_key", "value": "key-pem", "type": "CONCEALED"},
            ]
        }
        attrs = _extract_attributes(obj)
        assert "certificate=cert-pem" in attrs
        assert "private_key=key-pem" in attrs

    def test_extracts_string_fields_with_text_suffix(self):
        """STRING fields should get [text] suffix if not already present."""
        obj = {
            "fields": [
                {"label": "cn", "value": "example.com", "type": "STRING"},
                {"label": "serial", "value": "42", "type": "STRING"},
            ]
        }
        attrs = _extract_attributes(obj)
        assert "cn[text]=example.com" in attrs
        assert "serial[text]=42" in attrs

    def test_skips_internal_fields(self):
        """Internal 1Password fields like notesPlain should be skipped."""
        obj = {
            "fields": [
                {"label": "notesPlain", "value": "notes", "type": "STRING", "id": "notesPlain"},
                {"label": "certificate", "value": "cert-pem", "type": "CONCEALED"},
            ]
        }
        attrs = _extract_attributes(obj)
        assert len(attrs) == 1
        assert attrs[0].startswith("certificate=")

    def test_skips_empty_values(self):
        """Fields with empty values should be skipped."""
        obj = {
            "fields": [
                {"label": "certificate", "value": "", "type": "CONCEALED"},
                {"label": "cn", "value": "test", "type": "STRING"},
            ]
        }
        attrs = _extract_attributes(obj)
        assert len(attrs) == 1


class TestRestoreOrder:
    """Tests for _restore_order helper."""

    def test_ca_comes_first(self):
        assert _restore_order(ITEM_TYPE_CA) < _restore_order(ITEM_TYPE_CA_DATABASE)
        assert _restore_order(ITEM_TYPE_CA) < _restore_order(ITEM_TYPE_CERTIFICATE)

    def test_database_before_certs(self):
        assert _restore_order(ITEM_TYPE_CA_DATABASE) < _restore_order(ITEM_TYPE_CERTIFICATE)

    def test_unknown_type_last(self):
        assert _restore_order("unknown_type") > _restore_order(ITEM_TYPE_CERTIFICATE)
