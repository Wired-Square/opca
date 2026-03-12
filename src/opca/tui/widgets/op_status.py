# opca/tui/widgets/op_status.py

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import LoadingIndicator, Static


class OpStatus(Horizontal):
    """Inline status bar with a spinner and message text."""

    def compose(self) -> ComposeResult:
        yield LoadingIndicator(id="op-spinner")
        yield Static("", id="op-status-text")

    def on_mount(self) -> None:
        self.query_one("#op-spinner", LoadingIndicator).display = False

    def show(self, message: str) -> None:
        self.query_one("#op-spinner", LoadingIndicator).display = True
        self.query_one("#op-status-text", Static).update(message)

    def hide(self) -> None:
        self.query_one("#op-spinner", LoadingIndicator).display = False
        self.query_one("#op-status-text", Static).update("")
