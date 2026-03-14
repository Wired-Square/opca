# opca/services/command_queue.py

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from opca.services.one_password import Op

logger = logging.getLogger(__name__)


@dataclass
class QueuedCommand:
    """A single queued write operation for 1Password."""
    operation: str       # store_item, store_document, rename_item, delete_item
    target_type: str     # certbundle, crl, database, openvpn_profile
    target_id: str       # 1Password item title
    payload: Dict[str, Any] = field(default_factory=dict)
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CommandQueue:
    """
    In-memory command queue for batching 1Password write operations.

    Write operations are queued in memory and flushed after each logical
    operation completes. Multiple store_database commands are collapsed
    into a single flush (only the final state matters).

    This queue is intentionally NOT persisted to the database because
    payloads may contain secret material (private keys, cert PEM data)
    and the database gets uploaded to S3 via ca_private_store.
    """

    def __init__(self) -> None:
        self._queue: List[QueuedCommand] = []
        self._lock = threading.Lock()
        self._flush_timer: Optional[threading.Timer] = None
        self._debounce_seconds: float = 2.0

    @property
    def pending_count(self) -> int:
        """Number of commands waiting to be flushed."""
        with self._lock:
            return len(self._queue)

    def enqueue(self, command: QueuedCommand) -> None:
        """Add a command to the queue."""
        with self._lock:
            self._queue.append(command)
        logger.debug("Queued %s for %s (%s)", command.operation, command.target_id, command.target_type)

    def enqueue_store_item(self, target_id: str, attributes: List[str],
                           target_type: str = "certbundle", action: str = "create") -> None:
        """Convenience: queue a store_item operation."""
        self.enqueue(QueuedCommand(
            operation="store_item",
            target_type=target_type,
            target_id=target_id,
            payload={"action": action, "attributes": attributes},
        ))

    def enqueue_store_document(self, target_id: str, filename: str, content: str,
                               target_type: str = "database", action: str = "auto") -> None:
        """Convenience: queue a store_document operation."""
        self.enqueue(QueuedCommand(
            operation="store_document",
            target_type=target_type,
            target_id=target_id,
            payload={"action": action, "filename": filename, "content": content},
        ))

    def enqueue_rename_item(self, src_title: str, dst_title: str) -> None:
        """Convenience: queue a rename_item operation."""
        self.enqueue(QueuedCommand(
            operation="rename_item",
            target_type="certbundle",
            target_id=src_title,
            payload={"src_title": src_title, "dst_title": dst_title},
        ))

    def enqueue_delete_item(self, target_id: str, archive: bool = True) -> None:
        """Convenience: queue a delete_item operation."""
        self.enqueue(QueuedCommand(
            operation="delete_item",
            target_type="certbundle",
            target_id=target_id,
            payload={"archive": archive},
        ))

    def _collapse_queue(self) -> List[QueuedCommand]:
        """
        Collapse redundant commands before flushing.

        Multiple store_document commands for the same target_id (e.g., CA_Database)
        are collapsed into the last one, since only the final state matters.
        """
        collapsed: List[QueuedCommand] = []
        # Track last store_document per target_id
        last_store_doc: Dict[str, int] = {}

        for i, cmd in enumerate(self._queue):
            if cmd.operation == "store_document":
                last_store_doc[cmd.target_id] = i

        for i, cmd in enumerate(self._queue):
            if cmd.operation == "store_document" and i != last_store_doc.get(cmd.target_id):
                logger.debug("Collapsed duplicate store_document for %s", cmd.target_id)
                continue
            collapsed.append(cmd)

        return collapsed

    def flush(self, op: Op) -> List[Dict[str, Any]]:
        """
        Execute all queued commands against the 1Password CLI.

        Args:
            op: The Op instance to execute commands through.

        Returns:
            List of result dicts with keys: operation, target_id, success, error
        """
        with self._lock:
            if self._flush_timer is not None:
                self._flush_timer.cancel()
                self._flush_timer = None

            if not self._queue:
                return []

            commands = self._collapse_queue()
            self._queue.clear()

        results: List[Dict[str, Any]] = []

        for cmd in commands:
            result: Dict[str, Any] = {
                "operation": cmd.operation,
                "target_id": cmd.target_id,
                "success": False,
                "error": None,
            }

            try:
                if cmd.operation == "store_item":
                    op.store_item(
                        action=cmd.payload.get("action", "create"),
                        item_title=cmd.target_id,
                        attributes=cmd.payload.get("attributes", []),
                    )
                elif cmd.operation == "store_document":
                    op.store_document(
                        action=cmd.payload.get("action", "auto"),
                        item_title=cmd.target_id,
                        filename=cmd.payload.get("filename", ""),
                        str_in=cmd.payload.get("content", ""),
                    )
                elif cmd.operation == "rename_item":
                    op.rename_item(
                        src_title=cmd.payload["src_title"],
                        dst_title=cmd.payload["dst_title"],
                    )
                elif cmd.operation == "delete_item":
                    op.delete_item(
                        item_title=cmd.target_id,
                        archive=cmd.payload.get("archive", True),
                    )
                else:
                    result["error"] = f"Unknown operation: {cmd.operation}"
                    results.append(result)
                    continue

                result["success"] = True

            except Exception as e:
                result["error"] = str(e)
                logger.error("Command queue flush failed for %s %s: %s",
                             cmd.operation, cmd.target_id, e)

            results.append(result)

        return results

    def flush_debounced(self, op: Op, callback=None) -> None:
        """
        Schedule a flush after the debounce window.

        If called again before the timer fires, the previous timer is
        cancelled and a new one starts (debounce behaviour).

        Args:
            op: The Op instance to execute commands through.
            callback: Optional callback invoked with flush results.
        """
        with self._lock:
            if self._flush_timer is not None:
                self._flush_timer.cancel()

            def _do_flush():
                results = self.flush(op)
                if callback:
                    callback(results)

            self._flush_timer = threading.Timer(self._debounce_seconds, _do_flush)
            self._flush_timer.daemon = True
            self._flush_timer.start()

    def clear(self) -> None:
        """Discard all pending commands without executing them."""
        with self._lock:
            if self._flush_timer is not None:
                self._flush_timer.cancel()
                self._flush_timer = None
            self._queue.clear()
