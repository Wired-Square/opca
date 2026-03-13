# opca/services/errors.py

class CAError(Exception):
    """Base class for Certificate Authority errors."""


class CAAlreadyExistsError(CAError):
    """Raised when attempting to create/import a CA that already exists."""


class CANotFoundError(CAError):
    """Raised when the CA (or related records) cannot be found."""


class CADatabaseError(CAError):
    """Raised when the CA database cannot be read/written/processed."""


class CAStorageError(CAError):
    """Raised when upload/store via 1Password or remote storage fails."""


class InvalidCertificateError(CAError):
    """Raised when a CertificateBundle or certificate is invalid."""


class DuplicateCertificateError(CAError):
    """Raised when a duplicate title/serial is found."""


class UnknownCommandError(CAError):
    """Raised for unsupported CA commands."""

