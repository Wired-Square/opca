"""Unit tests for opca.commands.dkim module."""

import base64
import pytest

from opca.commands.dkim.actions import (
    _make_dkim_item_title,
    _generate_dkim_keypair,
    _format_dkim_dns_record,
)
from opca.services.route53 import split_txt_value


class TestMakeDkimItemTitle:
    """Tests for _make_dkim_item_title function."""

    def test_basic_title(self):
        """Should generate correct item title format."""
        result = _make_dkim_item_title("example.com", "mail")
        assert result == "DKIM_example.com_mail"

    def test_subdomain(self):
        """Should handle subdomains correctly."""
        result = _make_dkim_item_title("sub.example.com", "default")
        assert result == "DKIM_sub.example.com_default"

    def test_numeric_selector(self):
        """Should handle numeric selectors."""
        result = _make_dkim_item_title("example.com", "2024")
        assert result == "DKIM_example.com_2024"

    def test_complex_selector(self):
        """Should handle selectors with various characters."""
        result = _make_dkim_item_title("example.com", "selector-v1")
        assert result == "DKIM_example.com_selector-v1"


class TestGenerateDkimKeypair:
    """Tests for _generate_dkim_keypair function."""

    def test_generates_2048_bit_key(self):
        """Should generate a 2048-bit RSA key pair."""
        private_key, private_pem, public_pem = _generate_dkim_keypair(2048)

        assert private_key.key_size == 2048
        assert b"-----BEGIN RSA PRIVATE KEY-----" in private_pem
        assert b"-----END RSA PRIVATE KEY-----" in private_pem
        assert b"-----BEGIN PUBLIC KEY-----" in public_pem
        assert b"-----END PUBLIC KEY-----" in public_pem

    def test_generates_4096_bit_key(self):
        """Should generate a 4096-bit RSA key pair."""
        private_key, private_pem, public_pem = _generate_dkim_keypair(4096)

        assert private_key.key_size == 4096

    def test_generates_1024_bit_key(self):
        """Should generate a 1024-bit RSA key pair."""
        private_key, private_pem, public_pem = _generate_dkim_keypair(1024)

        assert private_key.key_size == 1024

    def test_private_key_is_valid_pem(self):
        """Should generate valid PEM-encoded private key."""
        _, private_pem, _ = _generate_dkim_keypair(2048)

        # Should be decodable as UTF-8
        pem_str = private_pem.decode("utf-8")
        lines = pem_str.strip().split("\n")

        # First and last lines should be PEM markers
        assert lines[0] == "-----BEGIN RSA PRIVATE KEY-----"
        assert lines[-1] == "-----END RSA PRIVATE KEY-----"

        # Middle lines should be valid base64
        base64_content = "".join(lines[1:-1])
        decoded = base64.b64decode(base64_content)
        assert len(decoded) > 0

    def test_public_key_is_valid_pem(self):
        """Should generate valid PEM-encoded public key."""
        _, _, public_pem = _generate_dkim_keypair(2048)

        pem_str = public_pem.decode("utf-8")
        lines = pem_str.strip().split("\n")

        assert lines[0] == "-----BEGIN PUBLIC KEY-----"
        assert lines[-1] == "-----END PUBLIC KEY-----"

        base64_content = "".join(lines[1:-1])
        decoded = base64.b64decode(base64_content)
        assert len(decoded) > 0

    def test_generates_unique_keys(self):
        """Should generate different keys each time."""
        _, private_pem1, _ = _generate_dkim_keypair(2048)
        _, private_pem2, _ = _generate_dkim_keypair(2048)

        assert private_pem1 != private_pem2


class TestFormatDkimDnsRecord:
    """Tests for _format_dkim_dns_record function."""

    def test_dns_record_format(self):
        """Should format DNS record with correct prefix."""
        _, _, public_pem = _generate_dkim_keypair(2048)

        dns_record = _format_dkim_dns_record(public_pem)

        assert dns_record.startswith("v=DKIM1; k=rsa; p=")

    def test_dns_record_no_pem_markers(self):
        """Should not contain PEM markers in DNS record."""
        _, _, public_pem = _generate_dkim_keypair(2048)

        dns_record = _format_dkim_dns_record(public_pem)

        assert "-----BEGIN" not in dns_record
        assert "-----END" not in dns_record

    def test_dns_record_no_newlines(self):
        """Should not contain newlines in DNS record."""
        _, _, public_pem = _generate_dkim_keypair(2048)

        dns_record = _format_dkim_dns_record(public_pem)

        assert "\n" not in dns_record
        assert "\r" not in dns_record

    def test_dns_record_valid_base64(self):
        """Should contain valid base64 public key."""
        _, _, public_pem = _generate_dkim_keypair(2048)

        dns_record = _format_dkim_dns_record(public_pem)

        # Extract the base64 portion after p=
        pubkey_b64 = dns_record.split("p=")[1]

        # Should be valid base64
        decoded = base64.b64decode(pubkey_b64)
        assert len(decoded) > 0

    def test_dns_record_2048_key_length(self):
        """2048-bit key should produce expected base64 length."""
        _, _, public_pem = _generate_dkim_keypair(2048)

        dns_record = _format_dkim_dns_record(public_pem)
        pubkey_b64 = dns_record.split("p=")[1]

        # 2048-bit RSA public key in SubjectPublicKeyInfo format is ~294 bytes
        # Base64 encoding increases size by ~33%
        decoded = base64.b64decode(pubkey_b64)
        assert 290 <= len(decoded) <= 300

    def test_dns_record_4096_key_length(self):
        """4096-bit key should produce longer base64."""
        _, _, public_pem = _generate_dkim_keypair(4096)

        dns_record = _format_dkim_dns_record(public_pem)
        pubkey_b64 = dns_record.split("p=")[1]

        # 4096-bit key should be roughly twice as long
        decoded = base64.b64decode(pubkey_b64)
        assert 540 <= len(decoded) <= 560


class TestSplitTxtValue:
    """Tests for split_txt_value function."""

    def test_short_value_no_split(self):
        """Short values should not be split."""
        value = "v=DKIM1; k=rsa; p=short"
        result = split_txt_value(value)

        assert result == [value]
        assert len(result) == 1

    def test_exact_255_chars_no_split(self):
        """Value exactly 255 chars should not be split."""
        value = "x" * 255
        result = split_txt_value(value)

        assert result == [value]
        assert len(result) == 1

    def test_256_chars_splits_into_two(self):
        """Value of 256 chars should split into two chunks."""
        value = "x" * 256
        result = split_txt_value(value)

        assert len(result) == 2
        assert result[0] == "x" * 255
        assert result[1] == "x"

    def test_split_preserves_content(self):
        """Split should preserve all content when rejoined."""
        value = "a" * 300 + "b" * 200
        result = split_txt_value(value)

        rejoined = "".join(result)
        assert rejoined == value

    def test_split_4096_dkim_key(self):
        """4096-bit DKIM key should split into multiple chunks."""
        # Generate a real 4096-bit key to test with realistic data
        _, _, public_pem = _generate_dkim_keypair(4096)
        dns_record = _format_dkim_dns_record(public_pem)

        result = split_txt_value(dns_record)

        # 4096-bit key produces ~740 char record, should be 3 chunks
        assert len(result) >= 3
        # Each chunk should be <= 255 chars
        for chunk in result:
            assert len(chunk) <= 255
        # Content should be preserved
        assert "".join(result) == dns_record

    def test_split_2048_dkim_key(self):
        """2048-bit DKIM key should split into two chunks."""
        _, _, public_pem = _generate_dkim_keypair(2048)
        dns_record = _format_dkim_dns_record(public_pem)

        result = split_txt_value(dns_record)

        # 2048-bit key produces ~400 char record, should be 2 chunks
        assert len(result) == 2
        # Content should be preserved
        assert "".join(result) == dns_record

    def test_custom_max_length(self):
        """Should respect custom max_len parameter."""
        value = "abcdefghij"  # 10 chars
        result = split_txt_value(value, max_len=3)

        assert len(result) == 4
        assert result == ["abc", "def", "ghi", "j"]

    def test_empty_string(self):
        """Empty string should return single empty chunk."""
        result = split_txt_value("")

        assert result == [""]
