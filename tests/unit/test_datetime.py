"""Unit tests for opca.utils.datetime module."""

from datetime import datetime, timezone, timedelta
import pytest

from opca.utils.datetime import (
    format_datetime,
    now_utc,
    now_utc_plus,
    now_utc_str,
    parse_datetime,
)


class TestFormatDatetime:
    """Tests for format_datetime function."""

    def test_format_openssl_naive_datetime(self):
        """Naive datetime should be treated as UTC and formatted correctly."""
        dt = datetime(2024, 1, 15, 14, 30, 45)
        result = format_datetime(dt, "openssl")
        assert result == "20240115143045Z"

    def test_format_openssl_utc_datetime(self):
        """UTC datetime should be formatted correctly."""
        dt = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = format_datetime(dt, "openssl")
        assert result == "20240115143045Z"

    def test_format_openssl_with_other_timezone(self):
        """Datetime with non-UTC timezone should be converted to UTC."""
        # Create a datetime with +2 hours offset
        tz_plus_2 = timezone(timedelta(hours=2))
        dt = datetime(2024, 1, 15, 16, 30, 45, tzinfo=tz_plus_2)  # 16:30 +02:00
        result = format_datetime(dt, "openssl")
        # Should convert to 14:30 UTC
        assert result == "20240115143045Z"

    def test_format_text(self):
        """Text format should produce human-readable output."""
        dt = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = format_datetime(dt, "text")
        assert result == "Jan 15 14:30:45 2024 UTC"

    def test_format_compact(self):
        """Compact format should produce abbreviated output."""
        dt = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = format_datetime(dt, "compact")
        assert result == "14:30 15 Jan 2024"

    def test_format_default_is_openssl(self):
        """Default format should be openssl."""
        dt = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = format_datetime(dt)
        assert result == "20240115143045Z"

    def test_format_midnight(self):
        """Midnight should format correctly with zeros."""
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = format_datetime(dt, "openssl")
        assert result == "20240101000000Z"

    def test_format_end_of_year(self):
        """End of year date should format correctly."""
        dt = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        result = format_datetime(dt, "openssl")
        assert result == "20241231235959Z"


class TestParseDatetime:
    """Tests for parse_datetime function."""

    def test_parse_openssl_format(self):
        """Should parse openssl format correctly."""
        result = parse_datetime("20240115143045Z", "openssl")
        expected = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_text_format(self):
        """Should parse text format correctly."""
        result = parse_datetime("Jan 15 14:30:45 2024 UTC", "text")
        expected = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_compact_format(self):
        """Should parse compact format correctly."""
        result = parse_datetime("14:30 15 Jan 2024", "compact")
        expected = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_default_is_openssl(self):
        """Default format should be openssl."""
        result = parse_datetime("20240115143045Z")
        expected = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_returns_utc_aware_datetime(self):
        """Parsed datetime should always have UTC timezone."""
        result = parse_datetime("20240115143045Z", "openssl")
        assert result.tzinfo == timezone.utc

    def test_parse_midnight(self):
        """Should parse midnight correctly."""
        result = parse_datetime("20240101000000Z", "openssl")
        expected = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert result == expected


class TestFormatParseRoundtrip:
    """Tests for format/parse roundtrip consistency."""

    def test_openssl_roundtrip(self):
        """Format and parse should be inverse operations for openssl format."""
        original = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        formatted = format_datetime(original, "openssl")
        parsed = parse_datetime(formatted, "openssl")
        assert parsed == original

    def test_text_roundtrip(self):
        """Format and parse should be inverse operations for text format."""
        original = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        formatted = format_datetime(original, "text")
        parsed = parse_datetime(formatted, "text")
        assert parsed == original

    def test_compact_roundtrip(self):
        """Format and parse should be inverse operations for compact format."""
        # Note: compact format doesn't include seconds, so they'll be lost
        original = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)
        formatted = format_datetime(original, "compact")
        parsed = parse_datetime(formatted, "compact")
        assert parsed == original


class TestNowUtc:
    """Tests for now_utc function."""

    def test_now_utc_returns_utc_datetime(self):
        """Should return a UTC-aware datetime."""
        result = now_utc()
        assert result.tzinfo == timezone.utc

    def test_now_utc_is_recent(self):
        """Should return current time (within 1 second)."""
        before = datetime.now(timezone.utc)
        result = now_utc()
        after = datetime.now(timezone.utc)

        assert before <= result <= after
        # Should be within 1 second
        assert (result - before).total_seconds() < 1


class TestNowUtcPlus:
    """Tests for now_utc_plus function."""

    def test_now_utc_plus_days(self):
        """Should add days correctly."""
        result = now_utc_plus(days=5)
        expected_delta = timedelta(days=5)

        # Compare with current time
        now = now_utc()
        actual_delta = result - now

        # Should be within 1 second of expected
        assert abs(actual_delta.total_seconds() - expected_delta.total_seconds()) < 1

    def test_now_utc_plus_hours(self):
        """Should add hours correctly."""
        result = now_utc_plus(hours=3)
        now = now_utc()
        delta = result - now

        # Should be approximately 3 hours (within 1 second)
        assert abs(delta.total_seconds() - 10800) < 1  # 3 hours = 10800 seconds

    def test_now_utc_plus_minutes(self):
        """Should add minutes correctly."""
        result = now_utc_plus(minutes=30)
        now = now_utc()
        delta = result - now

        # Should be approximately 30 minutes (within 1 second)
        assert abs(delta.total_seconds() - 1800) < 1  # 30 minutes = 1800 seconds

    def test_now_utc_plus_seconds(self):
        """Should add seconds correctly."""
        result = now_utc_plus(seconds=90)
        now = now_utc()
        delta = result - now

        # Should be approximately 90 seconds (within 1 second)
        assert abs(delta.total_seconds() - 90) < 1

    def test_now_utc_plus_combined(self):
        """Should handle multiple time units."""
        result = now_utc_plus(days=1, hours=2, minutes=30, seconds=45)
        now = now_utc()
        delta = result - now

        expected_seconds = (1 * 86400) + (2 * 3600) + (30 * 60) + 45  # 95445 seconds
        assert abs(delta.total_seconds() - expected_seconds) < 1

    def test_now_utc_plus_negative_offset(self):
        """Should handle negative offsets (past time)."""
        result = now_utc_plus(days=-5)
        now = now_utc()

        assert result < now
        delta = now - result
        assert abs(delta.total_seconds() - (5 * 86400)) < 1

    def test_now_utc_plus_returns_utc(self):
        """Should return UTC-aware datetime."""
        result = now_utc_plus(hours=1)
        assert result.tzinfo == timezone.utc


class TestNowUtcStr:
    """Tests for now_utc_str function."""

    def test_now_utc_str_openssl(self):
        """Should return current time in openssl format."""
        result = now_utc_str("openssl")

        # Should match pattern YYYYMMDDHHMMSSZ
        assert len(result) == 15
        assert result.endswith("Z")
        assert result[:-1].isdigit()

    def test_now_utc_str_text(self):
        """Should return current time in text format."""
        result = now_utc_str("text")

        # Should contain "UTC" at the end
        assert result.endswith("UTC")

    def test_now_utc_str_compact(self):
        """Should return current time in compact format."""
        result = now_utc_str("compact")

        # Should contain time and date
        assert ":" in result  # Time separator
        assert " " in result  # Space between components

    def test_now_utc_str_default_is_openssl(self):
        """Default format should be openssl."""
        result = now_utc_str()

        # Should match openssl pattern
        assert len(result) == 15
        assert result.endswith("Z")


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_leap_year_february_29(self):
        """Should handle leap year dates correctly."""
        dt = datetime(2024, 2, 29, 12, 0, 0, tzinfo=timezone.utc)
        formatted = format_datetime(dt, "openssl")
        parsed = parse_datetime(formatted, "openssl")
        assert parsed == dt

    def test_year_2000_boundary(self):
        """Should handle Y2K era dates."""
        dt = datetime(2000, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        formatted = format_datetime(dt, "openssl")
        assert formatted == "20000101000000Z"

    def test_far_future_date(self):
        """Should handle dates far in the future."""
        dt = datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        formatted = format_datetime(dt, "openssl")
        parsed = parse_datetime(formatted, "openssl")
        assert parsed == dt

    def test_extreme_timezone_offset(self):
        """Should handle extreme timezone offsets."""
        # UTC+14 (Line Islands)
        tz_plus_14 = timezone(timedelta(hours=14))
        dt = datetime(2024, 1, 15, 14, 0, 0, tzinfo=tz_plus_14)
        formatted = format_datetime(dt, "openssl")

        # Should convert to UTC (subtract 14 hours = 00:00)
        assert formatted == "20240115000000Z"
