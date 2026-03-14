"""Unit tests for opca.services.vault_lock module."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from opca.services.vault_lock import VaultLock, _extract_fields, _parse_iso
from opca.services.op_errors import (
    ItemConflictError,
    ItemNotFoundError,
    VaultLockedError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_op(
    *,
    create_side_effect=None,
    get_item_return=None,
    delete_side_effect=None,
    user_email="alice@example.com",
    user_name="Alice Smith",
):
    """Build a mock Op with configurable responses."""
    op = MagicMock()

    # get_current_user_details → JSON with email + name
    user_result = MagicMock()
    user_result.stdout = json.dumps({"email": user_email, "name": user_name})
    op.get_current_user_details.return_value = user_result

    # store_item — success or raise
    if create_side_effect is not None:
        op.store_item.side_effect = create_side_effect
    else:
        op.store_item.return_value = MagicMock(returncode=0)

    # get_item — return JSON item
    if get_item_return is not None:
        item_result = MagicMock()
        item_result.stdout = json.dumps(get_item_return)
        op.get_item.return_value = item_result

    # delete_item
    if delete_side_effect is not None:
        op.delete_item.side_effect = delete_side_effect
    else:
        op.delete_item.return_value = MagicMock(returncode=0)

    return op


def _lock_item_json(
    email="bob@example.com",
    name="Bob Jones",
    acquired_at=None,
    operation="cert_create",
    hostname="bobs-mac",
    ttl=300,
):
    """Return a 1Password item JSON dict representing a lock."""
    if acquired_at is None:
        acquired_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "fields": [
            {"label": "holder_email", "value": email},
            {"label": "holder_name", "value": name},
            {"label": "acquired_at", "value": acquired_at},
            {"label": "operation", "value": operation},
            {"label": "hostname", "value": hostname},
            {"label": "ttl_seconds", "value": str(ttl)},
        ]
    }


# ---------------------------------------------------------------------------
# Tests: _extract_fields helper
# ---------------------------------------------------------------------------


class TestExtractFields:
    def test_extracts_label_value_pairs(self):
        item = {
            "fields": [
                {"label": "holder_email", "value": "a@b.com"},
                {"label": "operation", "value": "cert_create"},
            ]
        }
        result = _extract_fields(item)
        assert result == {"holder_email": "a@b.com", "operation": "cert_create"}

    def test_empty_fields(self):
        assert _extract_fields({"fields": []}) == {}

    def test_missing_fields_key(self):
        assert _extract_fields({}) == {}


class TestParseIso:
    def test_parses_with_z(self):
        dt = _parse_iso("2026-03-14T10:30:00Z")
        assert dt.year == 2026
        assert dt.tzinfo == timezone.utc

    def test_parses_without_z(self):
        dt = _parse_iso("2026-03-14T10:30:00")
        assert dt.year == 2026


# ---------------------------------------------------------------------------
# Tests: VaultLock.acquire — happy path
# ---------------------------------------------------------------------------


class TestAcquireHappyPath:
    def test_acquire_succeeds(self):
        op = _make_op()
        lock = VaultLock(op)
        lock.acquire("cert_create")

        assert lock.held is True
        op.store_item.assert_called_once()
        # Verify attributes contain expected fields
        call_kwargs = op.store_item.call_args
        attrs = call_kwargs.kwargs.get("attributes") or call_kwargs[1].get("attributes", [])
        labels = [a.split("=")[0] for a in attrs]
        assert "holder_email[text]" in labels
        assert "operation[text]" in labels

    def test_release_deletes_without_archive(self):
        op = _make_op()
        lock = VaultLock(op)
        lock.acquire("cert_create")
        lock.release()

        assert lock.held is False
        op.delete_item.assert_called_once_with(
            item_title="CA_Lock", archive=False
        )

    def test_release_idempotent(self):
        op = _make_op()
        lock = VaultLock(op)
        lock.acquire("cert_create")
        lock.release()
        lock.release()  # second call is a no-op

        op.delete_item.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: VaultLock.acquire — contention
# ---------------------------------------------------------------------------


class TestAcquireContention:
    def test_raises_vault_locked_when_held(self):
        """Should raise VaultLockedError with holder details."""
        lock_json = _lock_item_json(
            email="bob@example.com",
            name="Bob Jones",
            operation="cert_revoke",
        )
        op = _make_op(
            create_side_effect=ItemConflictError("already exists"),
            get_item_return=lock_json,
        )
        lock = VaultLock(op)

        with pytest.raises(VaultLockedError) as exc_info:
            lock.acquire("cert_create")

        err = exc_info.value
        assert err.holder_email == "bob@example.com"
        assert err.holder_name == "Bob Jones"
        assert err.operation == "cert_revoke"
        assert lock.held is False


# ---------------------------------------------------------------------------
# Tests: VaultLock.acquire — stale lock
# ---------------------------------------------------------------------------


class TestStaleLockBreaking:
    def test_breaks_stale_lock_and_reacquires(self):
        """Should auto-break an expired lock and acquire successfully."""
        stale_time = (
            datetime.now(timezone.utc) - timedelta(seconds=600)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        lock_json = _lock_item_json(acquired_at=stale_time, ttl=300)

        # First store_item → conflict, second → success
        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ItemConflictError("already exists")
            return MagicMock(returncode=0)

        op = _make_op(
            create_side_effect=side_effect,
            get_item_return=lock_json,
        )

        lock = VaultLock(op)
        lock.acquire("cert_create")

        assert lock.held is True
        # Should have deleted the stale lock
        op.delete_item.assert_called_once_with(
            item_title="CA_Lock", archive=False
        )

    def test_corrupt_lock_treated_as_stale(self):
        """A lock with unparseable acquired_at should be treated as stale."""
        lock_json = _lock_item_json(acquired_at="not-a-date", ttl=300)

        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ItemConflictError("already exists")
            return MagicMock(returncode=0)

        op = _make_op(
            create_side_effect=side_effect,
            get_item_return=lock_json,
        )

        lock = VaultLock(op)
        lock.acquire("test_op")

        assert lock.held is True


# ---------------------------------------------------------------------------
# Tests: Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_context_manager_acquires_and_releases(self):
        op = _make_op()
        lock = VaultLock(op)

        with lock("cert_create"):
            assert lock.held is True

        assert lock.held is False
        op.delete_item.assert_called_once()

    def test_context_manager_releases_on_exception(self):
        op = _make_op()
        lock = VaultLock(op)

        with pytest.raises(ValueError):
            with lock("cert_create"):
                assert lock.held is True
                raise ValueError("boom")

        assert lock.held is False
        op.delete_item.assert_called_once()

    def test_context_manager_does_not_release_when_acquire_fails(self):
        lock_json = _lock_item_json()
        op = _make_op(
            create_side_effect=ItemConflictError("already exists"),
            get_item_return=lock_json,
        )
        lock = VaultLock(op)

        with pytest.raises(VaultLockedError):
            with lock("cert_create"):
                pass  # pragma: no cover

        assert lock.held is False
        op.delete_item.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: Staleness detection
# ---------------------------------------------------------------------------


class TestIsStale:
    def test_not_stale_within_ttl(self):
        lock = VaultLock(_make_op())
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert lock._is_stale({"acquired_at": now, "ttl_seconds": "300"}) is False

    def test_stale_beyond_ttl(self):
        lock = VaultLock(_make_op())
        old = (
            datetime.now(timezone.utc) - timedelta(seconds=600)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert lock._is_stale({"acquired_at": old, "ttl_seconds": "300"}) is True

    def test_missing_acquired_at_is_stale(self):
        lock = VaultLock(_make_op())
        assert lock._is_stale({}) is True

    def test_unparseable_ttl_is_stale(self):
        lock = VaultLock(_make_op())
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert lock._is_stale({"acquired_at": now, "ttl_seconds": "abc"}) is True


# ---------------------------------------------------------------------------
# Tests: Release edge cases
# ---------------------------------------------------------------------------


class TestReleaseEdgeCases:
    def test_release_ignores_item_not_found(self):
        """If the lock item was already removed, release should not raise."""
        op = _make_op(delete_side_effect=ItemNotFoundError("gone"))
        lock = VaultLock(op)
        lock._held = True

        lock.release()  # should not raise

        assert lock.held is False
