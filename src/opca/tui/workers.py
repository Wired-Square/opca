# opca/tui/workers.py

from __future__ import annotations

import contextlib
import io
import re
from typing import Callable, Any

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub('', text)


def capture_handler(handler: Callable[..., int], *args: Any, **kwargs: Any) -> tuple[int, str]:
    """
    Run an existing CLI handler, capturing its stdout output.
    Returns (exit_code, captured_output_without_ansi).
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            exit_code = handler(*args, **kwargs)
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 1
    output = buf.getvalue()
    buf.close()
    return exit_code, strip_ansi(output)
