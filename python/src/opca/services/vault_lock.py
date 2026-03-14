# opca/services/vault_lock.py

from __future__ import annotations

import json
import logging
import platform
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from opca.constants import DEFAULT_OP_CONF
from opca.services.one_password import Op
from opca.services.op_errors import (
    ItemConflictError,
    ItemNotFoundError,
    VaultLockedError,
)

logger = logging.getLogger(__name__)

# Field labels written onto the CA_Lock Secure Note.
_FIELD_HOLDER_EMAIL = "holder_email"
_FIELD_HOLDER_NAME = "holder_name"
_FIELD_ACQUIRED_AT = "acquired_at"
_FIELD_OPERATION = "operation"
_FIELD_HOSTNAME = "hostname"
_FIELD_TTL = "ttl_seconds"


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp (with or without trailing Z)."""
    ts = ts.rstrip("Z")
    return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)


def _extract_fields(item_json: Dict[str, Any]) -> Dict[str, str]:
    """Pull label→value pairs from a 1Password item JSON blob."""
    fields: Dict[str, str] = {}
    for f in item_json.get("fields", []):
        label = f.get("label", "")
        value = f.get("value", "")
        if label:
            fields[label] = value
    return fields


class VaultLock:
    """
    Advisory lock backed by a 1Password Secure Note.

    Uses ``op item create`` as an atomic compare-and-swap: if two users
    race to create the same ``CA_Lock`` item, only one succeeds.

    Usage::

        lock = VaultLock(op)
        with lock("cert_issue"):
            # … mutating operations …
    """

    DEFAULT_TTL = 300  # seconds

    def __init__(self, op: Op, *, lock_title: Optional[str] = None):
        self.op = op
        self.lock_title = lock_title or DEFAULT_OP_CONF["lock_title"]
        self._held = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def acquire(self, operation: str, ttl: int = DEFAULT_TTL) -> None:
        """
        Attempt to acquire the vault lock.

        Args:
            operation: Human-readable description of the operation.
            ttl: Maximum seconds the lock may be held before it is
                 considered stale and eligible for automatic breaking.

        Raises:
            VaultLockedError: Another user holds a non-stale lock.
        """
        holder_email, holder_name = self._current_user()
        hostname = platform.node()
        acquired_at = _now_utc_iso()

        attributes = [
            f"{_FIELD_HOLDER_EMAIL}[text]={holder_email}",
            f"{_FIELD_HOLDER_NAME}[text]={holder_name}",
            f"{_FIELD_ACQUIRED_AT}[text]={acquired_at}",
            f"{_FIELD_OPERATION}[text]={operation}",
            f"{_FIELD_HOSTNAME}[text]={hostname}",
            f"{_FIELD_TTL}[text]={ttl}",
        ]

        try:
            self.op.store_item(
                item_title=self.lock_title,
                attributes=attributes,
                action="create",
            )
            self._held = True
            logger.info("Vault lock acquired for %s", operation)
            return
        except ItemConflictError:
            pass  # someone else holds the lock — inspect it

        # Lock exists.  Read it to decide whether it is stale.
        lock_info = self._read_lock()

        if self._is_stale(lock_info):
            logger.warning(
                "Breaking stale vault lock held by %s since %s",
                lock_info.get(_FIELD_HOLDER_EMAIL, "unknown"),
                lock_info.get(_FIELD_ACQUIRED_AT, "unknown"),
            )
            self._break_stale()
            # Retry once.
            try:
                self.op.store_item(
                    item_title=self.lock_title,
                    attributes=attributes,
                    action="create",
                )
                self._held = True
                logger.info("Vault lock acquired (after breaking stale lock) for %s", operation)
                return
            except ItemConflictError:
                # Another user beat us to re-acquire after the stale break.
                lock_info = self._read_lock()

        raise VaultLockedError(
            holder_email=lock_info.get(_FIELD_HOLDER_EMAIL, ""),
            holder_name=lock_info.get(_FIELD_HOLDER_NAME, ""),
            acquired_at=lock_info.get(_FIELD_ACQUIRED_AT, ""),
            operation=lock_info.get(_FIELD_OPERATION, ""),
            hostname=lock_info.get(_FIELD_HOSTNAME, ""),
        )

    def release(self) -> None:
        """Release the vault lock (permanent delete so the title is reusable)."""
        if not self._held:
            return
        try:
            self.op.delete_item(item_title=self.lock_title, archive=False)
            logger.info("Vault lock released")
        except ItemNotFoundError:
            logger.debug("Lock item already removed")
        finally:
            self._held = False

    @property
    def held(self) -> bool:
        return self._held

    # ------------------------------------------------------------------
    # Context manager — use as ``with lock("operation"): …``
    # ------------------------------------------------------------------

    def __call__(self, operation: str, ttl: int = DEFAULT_TTL) -> VaultLock:
        """Allow ``with lock("op"):`` syntax."""
        self._pending_operation = operation
        self._pending_ttl = ttl
        return self

    def __enter__(self) -> VaultLock:
        self.acquire(self._pending_operation, self._pending_ttl)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _current_user(self) -> tuple[str, str]:
        """Return (email, name) of the currently authenticated user."""
        result = self.op.get_current_user_details()
        try:
            data = json.loads(result.stdout)
            return data.get("email", ""), data.get("name", "")
        except (json.JSONDecodeError, AttributeError):
            return ("unknown", "unknown")

    def _read_lock(self) -> Dict[str, str]:
        """Read the existing lock item and return its fields."""
        try:
            result = self.op.get_item(self.lock_title)
            data = json.loads(result.stdout)
            return _extract_fields(data)
        except (ItemNotFoundError, json.JSONDecodeError):
            return {}

    def _is_stale(self, lock_info: Dict[str, str]) -> bool:
        """Check whether a lock has exceeded its TTL."""
        acquired_str = lock_info.get(_FIELD_ACQUIRED_AT, "")
        ttl_str = lock_info.get(_FIELD_TTL, str(self.DEFAULT_TTL))

        if not acquired_str:
            return True  # corrupt lock — treat as stale

        try:
            acquired = _parse_iso(acquired_str)
            ttl = int(ttl_str)
        except (ValueError, TypeError):
            return True  # unparseable — treat as stale

        elapsed = (datetime.now(timezone.utc) - acquired).total_seconds()
        return elapsed > ttl

    def _break_stale(self) -> None:
        """Delete a stale lock item so a new one can be created."""
        try:
            self.op.delete_item(item_title=self.lock_title, archive=False)
        except ItemNotFoundError:
            pass  # already gone
