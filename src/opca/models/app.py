# opca/models/app.py

import logging
from argparse import Namespace
from dataclasses import dataclass
from typing import Optional

from opca.services.ca import CertificateAuthority, prepare_cert_authority
from opca.services.ca_errors import CANotFoundError, CADatabaseError
from opca.services.one_password import Op

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class App:
    """
    Lightweight application context passed to all handlers.
    Holds long-lived service singletons and shared runtime config.
    """
    args: Namespace
    op: Op
    ca: Optional[CertificateAuthority]

    @classmethod
    def from_args(cls, args: Namespace) -> "App":
        op = Op(account=args.account, vault=args.vault)
        ca: Optional[CertificateAuthority] = None

        cmd = getattr(args, "command", "")
        sub = getattr(args, "subcommand", "")

        # initlike: commands allowed to run without an existing CA DB (they can create it)
        initlike = (
            (cmd == "ca" and sub in {"init", "import"})
            or (cmd == "database" and sub == "rebuild")
        )

        if initlike:
            log.debug("Skipping eager CA load for init-like command: %s %s", cmd, sub)
        else:
            try:
                ca = prepare_cert_authority(op)  # retrieve existing CA
            except (CANotFoundError, CADatabaseError):
                ca = None  # handlers can decide what to do

        return cls(args=args, op=op, ca=ca)

    @property
    def account(self) -> Optional[str]:
        return self.args.account

    @property
    def vault(self) -> str:
        return self.args.vault
