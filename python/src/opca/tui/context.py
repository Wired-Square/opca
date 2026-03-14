# opca/tui/context.py

from __future__ import annotations

import contextlib
import logging
from argparse import Namespace
from dataclasses import dataclass, field
from typing import Generator, Optional

from opca.models.app import App
from opca.services.ca import CertificateAuthority, prepare_cert_authority
from opca.services.ca_errors import CANotFoundError, CADatabaseError
from opca.services.one_password import Op
from opca.services.vault_lock import VaultLock

log = logging.getLogger(__name__)


@dataclass
class TuiContext:
    """
    Bridges the TUI to existing OPCA services.
    Manages 1Password connection and CA lifecycle without argparse coupling.
    """
    account: Optional[str] = None
    vault: str = ""
    op: Optional[Op] = field(default=None, repr=False)
    ca: Optional[CertificateAuthority] = field(default=None, repr=False)

    @property
    def connected(self) -> bool:
        return self.op is not None

    @property
    def has_ca(self) -> bool:
        return self.ca is not None

    def connect(self) -> None:
        """Initialize 1Password connection and attempt to load CA."""
        self.op = Op(account=self.account, vault=self.vault)
        try:
            self.ca = prepare_cert_authority(self.op)
            self._enable_cross_thread_db()
        except (CANotFoundError, CADatabaseError):
            self.ca = None

    def disconnect(self) -> None:
        """Tear down the 1Password connection and clear CA state."""
        if self.ca is not None:
            try:
                self.ca.ca_database.conn.close()
            except Exception:
                pass
            self.ca = None
        self.op = None

    def reload_ca(self) -> None:
        """Reload CA from 1Password (e.g. after init/import)."""
        if self.op is None:
            raise RuntimeError("Not connected to 1Password")
        try:
            self.ca = prepare_cert_authority(self.op)
            self._enable_cross_thread_db()
        except (CANotFoundError, CADatabaseError):
            self.ca = None

    def _enable_cross_thread_db(self) -> None:
        """
        Re-create the in-memory SQLite connection with check_same_thread=False.

        The CA database is created in a worker thread but accessed from both
        the main thread and other worker threads. This is safe because the TUI
        serialises all DB operations via exclusive worker groups.
        """
        if self.ca is None:
            return
        import sqlite3
        db = self.ca.ca_database
        # Dump and restore into a new connection that allows cross-thread access
        sql_dump = "\n".join(db.conn.iterdump())
        new_conn = sqlite3.connect(":memory:", check_same_thread=False)
        new_conn.executescript(sql_dump)
        db.conn.close()
        db.conn = new_conn

    @contextlib.contextmanager
    def locked_mutation(self, operation: str) -> Generator[None, None, None]:
        """
        Context manager that acquires the vault lock and refreshes the
        in-memory CA database before yielding.

        Usage inside a ``@work(thread=True)`` method::

            with ctx.locked_mutation("cert_create"):
                ctx.ca.generate_certificate_bundle(...)

        On exit the lock is released automatically (even on error).
        """
        if self.op is None:
            raise RuntimeError("Not connected to 1Password")

        lock = VaultLock(self.op)
        with lock(operation):
            # Re-download the database under lock so the TUI always
            # works with the freshest state.
            self.reload_ca()
            yield

    def make_app(self, **kwargs: object) -> App:
        """
        Build an App instance with a synthetic Namespace.
        Pass handler-specific args as keyword arguments.
        """
        if self.op is None:
            raise RuntimeError("Not connected to 1Password")
        ns = Namespace(account=self.account, vault=self.vault, **kwargs)
        return App(args=ns, op=self.op, ca=self.ca)
