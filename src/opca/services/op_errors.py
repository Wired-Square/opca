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