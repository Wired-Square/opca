# opca/services/op_errors.py

class OPError(Exception):
    """Base class for errors raised by the 1Password (Op) integration."""


class VaultNotFoundError(OPError):
    """Configured 1Password vault does not exist or is inaccessible."""


class AuthenticationError(OPError):
    """Not signed in / session expired / account mismatch."""


class PermissionDeniedError(OPError):
    """Insufficient permissions for the operation."""


class ItemConflictError(OPError):
    """Duplicate title (including archived), or conflicting state."""


class ItemNotFoundError(OPError):
    """Requested item/document was not found (only raise when the caller expects existence)."""


class CLIError(OPError):
    """Generic Op CLI failure when no specific mapping applies."""


class VaultLockedError(OPError):
    """The vault is locked by another user or session."""

    def __init__(
        self,
        holder_email: str = "",
        holder_name: str = "",
        acquired_at: str = "",
        operation: str = "",
        hostname: str = "",
    ):
        self.holder_email = holder_email
        self.holder_name = holder_name
        self.acquired_at = acquired_at
        self.operation = operation
        self.hostname = hostname
        holder = holder_name or holder_email or "unknown"
        super().__init__(
            f"Vault is locked by {holder} since {acquired_at} "
            f"for {operation} (on {hostname})."
        )


class StaleDatabaseError(OPError):
    """The vault database has been modified externally since it was downloaded."""