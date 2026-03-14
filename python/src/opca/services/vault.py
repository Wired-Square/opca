# opca/services/vault.py

"""
Vault-level backup and restore operations.

Enumerates every item in a 1Password vault (CA, certificates, CRL,
database, OpenVPN, CSRs, external certs) and serialises them into a
JSON payload suitable for encryption by :mod:`opca.services.backup`.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Optional

from opca import __version__
from opca.constants import DEFAULT_OP_CONF
from opca.services.ca_errors import CAError, CAStorageError
from opca.services.one_password import Op
from opca.services.op_errors import ItemNotFoundError

log = logging.getLogger(__name__)


# --- exceptions --------------------------------------------------------------

class VaultBackupError(CAError):
    """Raised when a vault backup or restore operation fails."""


class VaultNotEmptyError(CAError):
    """Raised when restoring into a vault that already contains a CA."""


# --- item type tags ----------------------------------------------------------

ITEM_TYPE_CA = "ca"
ITEM_TYPE_CA_DATABASE = "ca_database"
ITEM_TYPE_CRL = "crl"
ITEM_TYPE_CERTIFICATE = "certificate"
ITEM_TYPE_EXTERNAL_CERT = "external_certificate"
ITEM_TYPE_CSR = "csr"
ITEM_TYPE_OPENVPN = "openvpn"


# --- public API --------------------------------------------------------------

class VaultBackup:
    """Create and restore encrypted vault backups."""

    def __init__(self, op: Op, op_config: dict | None = None) -> None:
        self.op = op
        self.op_config = op_config or DEFAULT_OP_CONF

    # --------------------------------------------------------------------- #
    #  Backup                                                                 #
    # --------------------------------------------------------------------- #

    def create_backup(self) -> dict:
        """Enumerate every item in the vault and return the backup payload dict."""
        items: list[dict] = []

        # 1. CA item (Secure Note)
        ca_title = self.op_config["ca_title"]
        ca_json = self._get_item_json(ca_title)
        if ca_json is not None:
            items.append({"type": ITEM_TYPE_CA, "title": ca_title, "data": ca_json})
        else:
            raise VaultBackupError("CA item not found — nothing to back up.")

        # 2. CA Database (Document)
        db_title = self.op_config["ca_database_title"]
        db_content = self._get_document_content(db_title)
        if db_content is not None:
            items.append({"type": ITEM_TYPE_CA_DATABASE, "title": db_title, "data": db_content})

        # 3. CRL (Document)
        crl_title = self.op_config["crl_title"]
        crl_content = self._get_document_content(crl_title)
        if crl_content is not None:
            items.append({"type": ITEM_TYPE_CRL, "title": crl_title, "data": crl_content})

        # 4. OpenVPN (Secure Note — optional)
        ovpn_title = self.op_config["openvpn_title"]
        ovpn_json = self._get_item_json(ovpn_title)
        if ovpn_json is not None:
            items.append({"type": ITEM_TYPE_OPENVPN, "title": ovpn_title, "data": ovpn_json})

        # 5. All remaining Secure Notes (certificates, CSRs, external certs)
        known_titles = {ca_title, ovpn_title}
        all_notes = self._list_secure_notes()

        for note_title in all_notes:
            if note_title in known_titles:
                continue

            item_json = self._get_item_json(note_title)
            if item_json is None:
                continue

            item_type = self._classify_item(note_title, item_json)
            items.append({"type": item_type, "title": note_title, "data": item_json})

        metadata = {
            "opca_version": __version__,
            "backup_date": datetime.now(timezone.utc).isoformat(),
            "vault_name": self.op.vault,
            "item_count": len(items),
        }

        return {"metadata": metadata, "items": items}

    # --------------------------------------------------------------------- #
    #  Restore                                                                #
    # --------------------------------------------------------------------- #

    def restore_backup(
        self,
        payload: dict,
        on_progress: Callable[[str, str], None] | None = None,
    ) -> dict:
        """Restore items from a backup *payload* into the current vault.

        The vault must be empty (no existing CA item).

        Parameters
        ----------
        on_progress:
            Optional callback ``(item_type, title)`` invoked before each item
            is restored.

        Returns a summary dict with item counts.
        """
        if self.op.item_exists(self.op_config["ca_title"]):
            raise VaultNotEmptyError(
                "Target vault already contains a CA. "
                "Restore requires an empty vault."
            )

        items = payload.get("items", [])
        counts: dict[str, int] = {}

        # Restore in dependency order: CA → database → CRL → certs/CSRs/OpenVPN
        ordered = sorted(items, key=lambda i: _restore_order(i["type"]))

        for item in ordered:
            item_type = item["type"]
            title = item["title"]
            data = item["data"]

            log.debug("Restoring %s: %s", item_type, title)
            if on_progress is not None:
                on_progress(item_type, title)

            if item_type in (ITEM_TYPE_CA_DATABASE, ITEM_TYPE_CRL):
                self._restore_document(title, data)
            else:
                self._restore_secure_note(title, data)

            counts[item_type] = counts.get(item_type, 0) + 1

        return counts

    # --------------------------------------------------------------------- #
    #  Metadata                                                               #
    # --------------------------------------------------------------------- #

    @staticmethod
    def get_metadata(payload: dict) -> dict:
        """Return only the metadata section from a backup payload."""
        return payload.get("metadata", {})

    # --------------------------------------------------------------------- #
    #  Internals — read helpers                                               #
    # --------------------------------------------------------------------- #

    def _get_item_json(self, title: str) -> Optional[str]:
        """Return the raw JSON string from ``op item get``, or None."""
        try:
            result = self.op.get_item(title)
            return result.stdout
        except ItemNotFoundError:
            return None

    def _get_document_content(self, title: str) -> Optional[str]:
        """Return document text from ``op document get``, or None."""
        try:
            result = self.op.get_document(title)
            return result.stdout
        except ItemNotFoundError:
            return None

    def _list_secure_notes(self) -> list[str]:
        """Return titles of all Secure Note items in the vault."""
        result = self.op.item_list(categories=self.op_config["category"])
        notes = json.loads(result.stdout)
        return [n["title"] for n in notes if n.get("title")]

    def _classify_item(self, title: str, item_json: str) -> str:
        """Determine the item type from its title and field content."""
        if title.startswith("EXT_"):
            return ITEM_TYPE_EXTERNAL_CERT

        # Check fields for certificate vs CSR
        try:
            obj = json.loads(item_json)
        except (json.JSONDecodeError, TypeError):
            return ITEM_TYPE_CERTIFICATE

        labels = {f.get("label") for f in obj.get("fields", [])}

        if "certificate" in labels:
            return ITEM_TYPE_CERTIFICATE

        if "certificate_signing_request" in labels:
            return ITEM_TYPE_CSR

        # Fallback — treat as certificate
        return ITEM_TYPE_CERTIFICATE

    # --------------------------------------------------------------------- #
    #  Internals — restore helpers                                            #
    # --------------------------------------------------------------------- #

    def _restore_document(self, title: str, content: str) -> None:
        """Re-create a Document item in the vault."""
        # Determine filename from title
        if title == self.op_config["ca_database_title"]:
            filename = self.op_config["ca_database_filename"]
        elif title == self.op_config["crl_title"]:
            filename = self.op_config["crl_filename"]
        else:
            filename = f"{title}.txt"

        result = self.op.store_document(
            item_title=title,
            filename=filename,
            str_in=content,
            action="create",
        )
        if result.returncode != 0:
            raise CAStorageError(f"Failed to restore document {title!r}.")

    def _restore_secure_note(self, title: str, item_json: str) -> None:
        """Re-create a Secure Note item from its saved JSON."""
        try:
            obj = json.loads(item_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise VaultBackupError(f"Invalid JSON for item {title!r}.") from exc

        attributes = _extract_attributes(obj)

        result = self.op.store_item(
            item_title=title,
            attributes=attributes,
            action="create",
            category=self.op_config["category"],
        )
        if result.returncode != 0:
            raise CAStorageError(f"Failed to restore item {title!r}.")


# --- helpers -----------------------------------------------------------------

def _restore_order(item_type: str) -> int:
    """Return a sort key so items are restored in dependency order."""
    order = {
        ITEM_TYPE_CA: 0,
        ITEM_TYPE_CA_DATABASE: 1,
        ITEM_TYPE_CRL: 2,
        ITEM_TYPE_OPENVPN: 3,
        ITEM_TYPE_CERTIFICATE: 4,
        ITEM_TYPE_EXTERNAL_CERT: 5,
        ITEM_TYPE_CSR: 6,
    }
    return order.get(item_type, 99)


def _extract_attributes(item_obj: dict) -> list[str]:
    """Build ``label=value`` attribute list from an ``op item get`` JSON object.

    Only includes fields that have a non-empty value and a user-visible label
    (skips internal 1Password fields like ``notesPlain``).
    """
    attrs: list[str] = []

    # 1Password JSON has a "fields" array and sometimes a "sections" structure.
    # We care about the top-level fields that OPCA uses.
    skip_labels = {"notesPlain", "password", "username"}

    for field in item_obj.get("fields", []):
        label = field.get("label", "")
        value = field.get("value", "")

        if not label or label in skip_labels:
            continue

        # 1Password internal fields have an "id" starting with a known prefix
        field_id = field.get("id", "")
        if field_id in ("notesPlain", "password", "username"):
            continue

        # Only include fields that have a value
        if value:
            # Section-qualified labels (e.g. "diffie-hellman.dh_parameters")
            section = field.get("section", {})
            section_label = section.get("label", "") if isinstance(section, dict) else ""
            if section_label:
                qualified = f"{section_label}.{label}"
            else:
                qualified = label

            # Determine if this is a text field (needs [text] suffix)
            field_type = field.get("type", "")
            if field_type == "STRING" and "[text]" not in qualified:
                qualified = f"{qualified}[text]"

            attrs.append(f"{qualified}={value}")

    return attrs
