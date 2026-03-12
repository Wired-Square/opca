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


def set_loading(screen: Any, loading: bool) -> None:
    """Set loading overlay on the screen's first Vertical container."""
    try:
        from textual.containers import Vertical
        container = screen.query_one(Vertical)
        container.loading = loading
    except Exception:
        pass


def capture_handler(handler: Callable[..., int], *args: Any, **kwargs: Any) -> tuple[int, str]:
    """
    Run an existing CLI handler, capturing its stdout output.
    Returns (exit_code, captured_output_without_ansi).
    """
    with io.StringIO() as buf, contextlib.redirect_stdout(buf):
        exit_code = handler(*args, **kwargs)
        output = buf.getvalue()
    return exit_code, strip_ansi(output)
