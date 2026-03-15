# opca/tui/widgets/screen_header.py

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from opca import __version__


class ScreenHeader(Static):
    """Branded header bar: ``opca v0.x  ──  Page Name  vault · account``."""

    def __init__(self, page_name: str, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._page_name = page_name

    def compose(self) -> ComposeResult:
        with Horizontal(id="screen-header-row"):
            yield Static("opca", id="screen-header-brand")
            yield Static(f"v{__version__}", id="screen-header-version")
            yield Static("\u2500\u2500", id="screen-header-sep")
            yield Static(self._page_name, id="screen-header-page")
            yield Static("", id="screen-header-badge")
            yield Static("", id="screen-header-context")

    def on_mount(self) -> None:
        """Populate vault and account from the TUI context."""
        self._refresh_context()

    def _refresh_context(self) -> None:
        ctx = self.app.tui_context
        parts: list[str] = []
        if ctx.vault:
            parts.append(ctx.vault)
        if ctx.account:
            parts.append(ctx.account)
        self.query_one("#screen-header-context", Static).update(
            " \u00b7 ".join(parts)
        )
        badge = self.query_one("#screen-header-badge", Static)
        if ctx.connected and not ctx.has_ca:
            badge.update("empty vault")
            badge.display = True
        else:
            badge.update("")
            badge.display = False
