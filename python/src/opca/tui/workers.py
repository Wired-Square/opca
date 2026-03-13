# opca/tui/workers.py

from __future__ import annotations

import contextlib
import io
import re
from contextlib import contextmanager
from typing import Any, Callable, Generator

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub('', text)


@contextmanager
def op_status_context(screen: Any, message: str, status_id: str = "#op-status") -> Generator[None, None, None]:
    """Show an OpStatus spinner for the duration of a worker block.

    Usage inside a ``@work(thread=True)`` method::

        with op_status_context(self, "Working..."):
            ...  # OpStatus is hidden automatically on exit
    """
    from opca.tui.widgets.op_status import OpStatus

    op_status = screen.query_one(status_id, OpStatus)
    screen.app.call_from_thread(op_status.show, message)
    try:
        yield
    finally:
        screen.app.call_from_thread(op_status.hide)


# Re-export from canonical location for backwards compatibility.
from opca.utils.crypto import extract_certificate_cn  # noqa: F401


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
