# opca/services/backup.py

"""
Encrypted backup file format for OPCA vault exports.

File layout:
    Bytes 0-3:    Magic (b"OPCA")
    Byte  4:      Format version (0x01)
    Bytes 5-20:   PBKDF2 salt (16 bytes)
    Bytes 21-32:  AES-GCM nonce (12 bytes)
    Bytes 33-48:  GCM authentication tag (16 bytes)
    Bytes 49-N:   AES-256-GCM ciphertext

Encryption uses AES-256-GCM with a key derived from a user
password via PBKDF2-HMAC-SHA256 (600 000 iterations).
Data never touches disk unencrypted.
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from opca.services.ca_errors import CAError

# --- constants ---------------------------------------------------------------

BACKUP_MAGIC = b"OPCA"
BACKUP_VERSION = 1
SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16
PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32  # AES-256

HEADER_LENGTH = len(BACKUP_MAGIC) + 1 + SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH  # 49


# --- exceptions --------------------------------------------------------------

class BackupFormatError(CAError):
    """Raised when the backup file header is invalid or unsupported."""


class BackupDecryptionError(CAError):
    """Raised when decryption fails (wrong password or corrupted data)."""


# --- public API --------------------------------------------------------------

def encrypt_payload(plaintext: bytes, password: str) -> bytes:
    """Encrypt *plaintext* with *password* and return the full backup blob.

    The returned bytes include the OPCA header followed by the ciphertext.
    """
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns nonce‖ciphertext‖tag but we manage nonce/tag
    # ourselves so we can place them in fixed header positions.
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # GCM appends the 16-byte tag to the ciphertext
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]

    header = BACKUP_MAGIC + struct.pack("B", BACKUP_VERSION) + salt + nonce + tag
    return header + ciphertext


def decrypt_payload(data: bytes, password: str) -> bytes:
    """Decrypt a backup blob produced by :func:`encrypt_payload`.

    Raises:
        BackupFormatError: If magic bytes or version are wrong.
        BackupDecryptionError: If the password is wrong or data is corrupted.
    """
    if len(data) < HEADER_LENGTH:
        raise BackupFormatError("File is too small to be a valid OPCA backup.")

    magic = data[:4]
    if magic != BACKUP_MAGIC:
        raise BackupFormatError(
            f"Invalid file: expected magic {BACKUP_MAGIC!r}, got {magic!r}."
        )

    version = data[4]
    if version != BACKUP_VERSION:
        raise BackupFormatError(
            f"Unsupported backup version {version}; this tool supports version {BACKUP_VERSION}."
        )

    salt = data[5:21]
    nonce = data[21:33]
    tag = data[33:49]
    ciphertext = data[49:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:
        raise BackupDecryptionError(
            "Decryption failed — wrong password or corrupted backup file."
        ) from exc

    return plaintext


# --- internals ---------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from *password* and *salt* using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))
