# opca/utils/datetime.py

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

from opca.utils.formatting import error

OutputFormat = Literal["openssl", "text", "compact"]


def _ensure_utc(dt: datetime) -> datetime:
    """
    Return a timezone-aware datetime in UTC.
    If `dt` is naive, treat it as UTC (to match current behavior).
    """
    if dt.tzinfo is None:
        # Assume UTC when naive to avoid surprises elsewhere.
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def format_datetime(date: datetime, output_format: OutputFormat = "openssl") -> str:
    """
    Format a datetime in UTC using one of OPCA's canonical styles.

    Args:
        date: The datetime to format (naive treated as UTC).
        output_format: One of:
            - "openssl" → '%Y%m%d%H%M%SZ' (X.509/CRL friendly)
            - "text"    → '%b %d %H:%M:%S %Y UTC'
            - "compact" → '%H:%M %d %b %Y'

    Returns:
        The formatted datetime string.
    """
    dt = _ensure_utc(date)

    if output_format == "openssl":
        fmt = "%Y%m%d%H%M%SZ"
    elif output_format == "text":
        fmt = "%b %d %H:%M:%S %Y UTC"
    elif output_format == "compact":
        fmt = "%H:%M %d %b %Y"
    else:
        error(f"Invalid date format: {output_format!r}", 1)  # exits

    return dt.strftime(fmt)


def now_utc_str(output_format: OutputFormat = "openssl") -> str:
    """
    Convenience: current UTC time formatted with `format_datetime`.
    """
    return format_datetime(datetime.now(timezone.utc), output_format)

def now_utc() -> datetime:
    """Return current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)

def now_utc_plus(*, days: int = 0, hours: int = 0, minutes: int = 0, seconds: int = 0) -> datetime:
    """Return current UTC time plus the given offset."""
    return now_utc() + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

def parse_datetime(value: str, input_format: OutputFormat = "openssl") -> datetime:
    """
    Parse a datetime string (e.g., from DB) into a UTC-aware datetime.
    """
    if input_format == "openssl":
        fmt = "%Y%m%d%H%M%SZ"
    elif input_format == "text":
        fmt = "%b %d %H:%M:%S %Y UTC"
    elif input_format == "compact":
        fmt = "%H:%M %d %b %Y"
    else:
        from opca.utils.formatting import error
        error(f"Invalid date format: {input_format!r}", 1)

    # parsed strings are UTC; attach tzinfo
    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
