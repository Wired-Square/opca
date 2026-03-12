"""Unit tests for opca.services.backup module."""

import os

import pytest

from opca.services.backup import (
    BACKUP_MAGIC,
    BACKUP_VERSION,
    HEADER_LENGTH,
    encrypt_payload,
    decrypt_payload,
    BackupFormatError,
    BackupDecryptionError,
)


class TestEncryptDecrypt:
    """Round-trip encryption/decryption tests."""

    def test_round_trip_small(self):
        """Encrypting then decrypting returns the original data."""
        data = b"Hello, vault backup!"
        password = "test-password-123"

        encrypted = encrypt_payload(data, password)
        decrypted = decrypt_payload(encrypted, password)

        assert decrypted == data

    def test_round_trip_large(self):
        """Round-trip works with larger payloads."""
        data = os.urandom(1024 * 100)  # 100 KB
        password = "strong-password"

        encrypted = encrypt_payload(data, password)
        decrypted = decrypt_payload(encrypted, password)

        assert decrypted == data

    def test_round_trip_unicode_password(self):
        """Unicode passwords work correctly."""
        data = b"test data"
        password = "p\u00e4ssw\u00f6rd-\U0001f512"

        encrypted = encrypt_payload(data, password)
        decrypted = decrypt_payload(encrypted, password)

        assert decrypted == data

    def test_round_trip_empty_payload(self):
        """Empty payloads are handled correctly."""
        data = b""
        password = "password"

        encrypted = encrypt_payload(data, password)
        decrypted = decrypt_payload(encrypted, password)

        assert decrypted == data

    def test_encrypted_output_has_correct_header(self):
        """Output starts with correct magic bytes and version."""
        encrypted = encrypt_payload(b"test", "password")

        assert encrypted[:4] == BACKUP_MAGIC
        assert encrypted[4] == BACKUP_VERSION
        assert len(encrypted) >= HEADER_LENGTH

    def test_encrypted_output_differs_from_plaintext(self):
        """Ciphertext is not the same as plaintext."""
        data = b"sensitive data"
        encrypted = encrypt_payload(data, "password")

        assert data not in encrypted

    def test_different_passwords_produce_different_output(self):
        """Same data encrypted with different passwords produces different ciphertext."""
        data = b"test data"
        enc1 = encrypt_payload(data, "password1")
        enc2 = encrypt_payload(data, "password2")

        # The ciphertext portions should differ (after the header)
        assert enc1[HEADER_LENGTH:] != enc2[HEADER_LENGTH:]

    def test_each_encryption_uses_unique_salt_and_nonce(self):
        """Same data and password should produce different output each time."""
        data = b"test data"
        password = "password"

        enc1 = encrypt_payload(data, password)
        enc2 = encrypt_payload(data, password)

        # Salt (bytes 5-20) and nonce (bytes 21-32) should differ
        assert enc1[5:21] != enc2[5:21] or enc1[21:33] != enc2[21:33]


class TestDecryptionErrors:
    """Tests for decryption failure modes."""

    def test_wrong_password_raises_error(self):
        """Decrypting with the wrong password raises BackupDecryptionError."""
        encrypted = encrypt_payload(b"secret", "correct-password")

        with pytest.raises(BackupDecryptionError):
            decrypt_payload(encrypted, "wrong-password")

    def test_corrupted_magic_raises_format_error(self):
        """Invalid magic bytes raise BackupFormatError."""
        encrypted = encrypt_payload(b"test", "password")
        corrupted = b"NOPE" + encrypted[4:]

        with pytest.raises(BackupFormatError, match="Invalid file"):
            decrypt_payload(corrupted, "password")

    def test_unsupported_version_raises_format_error(self):
        """An unsupported version byte raises BackupFormatError."""
        encrypted = encrypt_payload(b"test", "password")
        corrupted = encrypted[:4] + bytes([99]) + encrypted[5:]

        with pytest.raises(BackupFormatError, match="Unsupported backup version"):
            decrypt_payload(corrupted, "password")

    def test_truncated_file_raises_format_error(self):
        """A file shorter than the header raises BackupFormatError."""
        with pytest.raises(BackupFormatError, match="too small"):
            decrypt_payload(b"OPC", "password")

    def test_corrupted_ciphertext_raises_decryption_error(self):
        """Corrupted ciphertext raises BackupDecryptionError."""
        encrypted = encrypt_payload(b"test data", "password")
        # Flip some bytes in the ciphertext area
        corrupted = bytearray(encrypted)
        if len(corrupted) > HEADER_LENGTH + 5:
            corrupted[HEADER_LENGTH + 3] ^= 0xFF
            corrupted[HEADER_LENGTH + 4] ^= 0xFF

        with pytest.raises(BackupDecryptionError):
            decrypt_payload(bytes(corrupted), "password")

    def test_corrupted_tag_raises_decryption_error(self):
        """Corrupted GCM auth tag raises BackupDecryptionError."""
        encrypted = encrypt_payload(b"test data", "password")
        corrupted = bytearray(encrypted)
        # Tag is at bytes 33-48
        corrupted[35] ^= 0xFF

        with pytest.raises(BackupDecryptionError):
            decrypt_payload(bytes(corrupted), "password")
