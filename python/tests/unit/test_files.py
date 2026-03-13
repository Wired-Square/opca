"""Unit tests for opca.utils.files module."""

import os
import tempfile
from pathlib import Path
import pytest

from opca.utils.files import read_bytes, write_bytes, parse_bulk_file


class TestReadBytes:
    """Tests for read_bytes function."""

    def test_read_existing_file(self, tmp_path):
        """Should read bytes from an existing file."""
        test_file = tmp_path / "test.txt"
        test_content = b"Hello, World!"
        test_file.write_bytes(test_content)

        result = read_bytes(test_file)
        assert result == test_content

    def test_read_empty_file(self, tmp_path):
        """Should read empty file successfully."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        result = read_bytes(test_file)
        assert result == b""

    def test_read_binary_file(self, tmp_path):
        """Should read binary data correctly."""
        test_file = tmp_path / "binary.dat"
        test_content = bytes([0x00, 0x01, 0xFF, 0xFE, 0x42])
        test_file.write_bytes(test_content)

        result = read_bytes(test_file)
        assert result == test_content

    def test_read_with_path_object(self, tmp_path):
        """Should accept Path objects."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"content")

        result = read_bytes(test_file)
        assert result == b"content"

    def test_read_with_string_path(self, tmp_path):
        """Should accept string paths."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"content")

        result = read_bytes(str(test_file))
        assert result == b"content"

    def test_read_nonexistent_file_exits(self, tmp_path):
        """Should exit when file doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            read_bytes(tmp_path / "nonexistent.txt")
        assert exc_info.value.code == 1


class TestWriteBytes:
    """Tests for write_bytes function."""

    def test_write_to_new_file(self, tmp_path):
        """Should create and write to a new file."""
        test_file = tmp_path / "test.txt"
        test_content = b"Hello, World!"

        result = write_bytes(test_file, test_content)

        assert result == test_file
        assert test_file.read_bytes() == test_content

    def test_write_sets_permissions(self, tmp_path):
        """Should set file permissions to 0o600 by default."""
        test_file = tmp_path / "test.txt"

        write_bytes(test_file, b"content")

        # Check file permissions
        stat_result = os.stat(test_file)
        mode = stat_result.st_mode & 0o777
        assert mode == 0o600

    def test_write_with_custom_permissions(self, tmp_path):
        """Should respect custom permission mode."""
        test_file = tmp_path / "test.txt"

        write_bytes(test_file, b"content", mode=0o644)

        stat_result = os.stat(test_file)
        mode = stat_result.st_mode & 0o777
        assert mode == 0o644

    def test_write_without_overwrite_fails(self, tmp_path):
        """Should exit when file exists and overwrite=False."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"original")

        with pytest.raises(SystemExit) as exc_info:
            write_bytes(test_file, b"new content", overwrite=False)
        assert exc_info.value.code == 1

        # File should remain unchanged
        assert test_file.read_bytes() == b"original"

    def test_write_with_overwrite(self, tmp_path):
        """Should overwrite existing file when overwrite=True."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"original")

        write_bytes(test_file, b"new content", overwrite=True)

        assert test_file.read_bytes() == b"new content"

    def test_write_creates_parent_dirs(self, tmp_path):
        """Should create parent directories when create_dirs=True."""
        test_file = tmp_path / "subdir1" / "subdir2" / "test.txt"

        write_bytes(test_file, b"content", create_dirs=True)

        assert test_file.exists()
        assert test_file.read_bytes() == b"content"

    def test_write_without_create_dirs_fails(self, tmp_path):
        """Should exit when parent directory doesn't exist and create_dirs=False."""
        test_file = tmp_path / "nonexistent" / "test.txt"

        with pytest.raises(SystemExit) as exc_info:
            write_bytes(test_file, b"content", create_dirs=False)
        assert exc_info.value.code == 1

    def test_write_atomic_default(self, tmp_path):
        """Should use atomic write by default."""
        test_file = tmp_path / "test.txt"

        write_bytes(test_file, b"content")

        # Atomic write should succeed and file should exist
        assert test_file.exists()
        assert test_file.read_bytes() == b"content"

    def test_write_non_atomic(self, tmp_path):
        """Should write directly when atomic=False."""
        test_file = tmp_path / "test.txt"

        write_bytes(test_file, b"content", atomic=False)

        assert test_file.read_bytes() == b"content"

    def test_write_large_file(self, tmp_path):
        """Should handle large files."""
        test_file = tmp_path / "large.dat"
        # 1MB of data
        large_content = b"x" * (1024 * 1024)

        write_bytes(test_file, large_content)

        assert test_file.read_bytes() == large_content

    def test_write_binary_data(self, tmp_path):
        """Should write binary data correctly."""
        test_file = tmp_path / "binary.dat"
        binary_content = bytes([0x00, 0x01, 0xFF, 0xFE, 0x42])

        write_bytes(test_file, binary_content)

        assert test_file.read_bytes() == binary_content

    def test_write_returns_path(self, tmp_path):
        """Should return the Path object."""
        test_file = tmp_path / "test.txt"

        result = write_bytes(test_file, b"content")

        assert isinstance(result, Path)
        assert result == test_file

    def test_write_with_string_path(self, tmp_path):
        """Should accept string paths."""
        test_file = str(tmp_path / "test.txt")

        result = write_bytes(test_file, b"content")

        assert Path(test_file).exists()
        assert isinstance(result, Path)


class TestParseBulkFile:
    """Tests for parse_bulk_file function."""

    def test_parse_simple_cn(self, tmp_path):
        """Should parse file with simple CN entries."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"server1.example.com\nserver2.example.com\n")

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 2
        assert result[0] == {"cn": "server1.example.com"}
        assert result[1] == {"cn": "server2.example.com"}

    def test_parse_cn_with_single_san(self, tmp_path):
        """Should parse CN with single SAN."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"server.example.com --alt www.example.com\n")

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 1
        assert result[0] == {
            "cn": "server.example.com",
            "alt_dns_names": ["www.example.com"]
        }

    def test_parse_cn_with_multiple_sans(self, tmp_path):
        """Should parse CN with multiple SANs."""
        test_file = tmp_path / "bulk.txt"
        content = b"server.example.com --alt www.example.com --alt api.example.com --alt cdn.example.com\n"
        test_file.write_bytes(content)

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 1
        assert result[0] == {
            "cn": "server.example.com",
            "alt_dns_names": ["www.example.com", "api.example.com", "cdn.example.com"]
        }

    def test_parse_ignores_empty_lines(self, tmp_path):
        """Should ignore empty lines."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"server1.example.com\n\n\nserver2.example.com\n\n")

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 2
        assert result[0] == {"cn": "server1.example.com"}
        assert result[1] == {"cn": "server2.example.com"}

    def test_parse_ignores_comments(self, tmp_path):
        """Should ignore lines starting with #."""
        test_file = tmp_path / "bulk.txt"
        content = b"# This is a comment\nserver1.example.com\n# Another comment\nserver2.example.com\n"
        test_file.write_bytes(content)

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 2
        assert result[0] == {"cn": "server1.example.com"}
        assert result[1] == {"cn": "server2.example.com"}

    def test_parse_strips_whitespace(self, tmp_path):
        """Should strip leading/trailing whitespace."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"  server1.example.com  \n\t server2.example.com \t\n")

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 2
        assert result[0] == {"cn": "server1.example.com"}
        assert result[1] == {"cn": "server2.example.com"}

    def test_parse_strips_alt_whitespace(self, tmp_path):
        """Should strip whitespace from alt names."""
        test_file = tmp_path / "bulk.txt"
        content = b"server.example.com --alt  www.example.com  --alt   api.example.com   \n"
        test_file.write_bytes(content)

        result = list(parse_bulk_file(str(test_file)))

        assert result[0]["alt_dns_names"] == ["www.example.com", "api.example.com"]

    def test_parse_ignores_empty_alt_entries(self, tmp_path):
        """Should ignore empty alt entries."""
        test_file = tmp_path / "bulk.txt"
        content = b"server.example.com --alt www.example.com --alt  --alt api.example.com\n"
        test_file.write_bytes(content)

        result = list(parse_bulk_file(str(test_file)))

        # Empty alt should be filtered out
        assert result[0]["alt_dns_names"] == ["www.example.com", "api.example.com"]

    def test_parse_mixed_format(self, tmp_path):
        """Should parse file with mixed entries."""
        test_file = tmp_path / "bulk.txt"
        content = b"""# Certificate list
server1.example.com
server2.example.com --alt www2.example.com

# More servers
server3.example.com --alt www3.example.com --alt api3.example.com
"""
        test_file.write_bytes(content)

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 3
        assert result[0] == {"cn": "server1.example.com"}
        assert result[1] == {"cn": "server2.example.com", "alt_dns_names": ["www2.example.com"]}
        assert result[2] == {
            "cn": "server3.example.com",
            "alt_dns_names": ["www3.example.com", "api3.example.com"]
        }

    def test_parse_empty_file(self, tmp_path):
        """Should return empty list for empty file."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"")

        result = list(parse_bulk_file(str(test_file)))

        assert result == []

    def test_parse_only_comments_and_whitespace(self, tmp_path):
        """Should return empty list for file with only comments and whitespace."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"# Comment 1\n\n# Comment 2\n\n")

        result = list(parse_bulk_file(str(test_file)))

        assert result == []

    def test_parse_unicode_content(self, tmp_path):
        """Should handle Unicode characters in CNs."""
        test_file = tmp_path / "bulk.txt"
        # Some servers allow IDNs (Internationalized Domain Names)
        test_file.write_bytes("münchen.example.com\n".encode("utf-8"))

        result = list(parse_bulk_file(str(test_file)))

        assert len(result) == 1
        assert result[0] == {"cn": "münchen.example.com"}

    def test_parse_returns_generator(self, tmp_path):
        """Should return an iterable/generator."""
        test_file = tmp_path / "bulk.txt"
        test_file.write_bytes(b"server1.example.com\nserver2.example.com\n")

        result = parse_bulk_file(str(test_file))

        # Should be iterable
        from collections.abc import Iterable
        assert isinstance(result, Iterable)

        # Should be able to iterate
        items = list(result)
        assert len(items) == 2


class TestReadWriteRoundtrip:
    """Tests for read/write roundtrip operations."""

    def test_roundtrip_preserves_content(self, tmp_path):
        """Writing and reading should preserve content."""
        test_file = tmp_path / "test.dat"
        original_content = b"Test content with \x00 null bytes and \xFF high bytes"

        write_bytes(test_file, original_content)
        read_content = read_bytes(test_file)

        assert read_content == original_content

    def test_roundtrip_with_overwrite(self, tmp_path):
        """Should handle overwrite correctly."""
        test_file = tmp_path / "test.txt"

        write_bytes(test_file, b"first")
        assert read_bytes(test_file) == b"first"

        write_bytes(test_file, b"second", overwrite=True)
        assert read_bytes(test_file) == b"second"
