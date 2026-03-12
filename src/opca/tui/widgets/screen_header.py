# opca/tui/widgets/screen_header.py

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from opca import __version__


class ScreenHeader(Static):
    """Branded header bar: ``opca v0.x  ──  Page Name``."""

    def __init__(self, page_name: str, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._page_name = page_name

    def compose(self) -> ComposeResult:
        with Horizontal(id="screen-header-row"):
            yield Static("opca", id="screen-header-brand")
            yield Static(f"v{__version__}", id="screen-header-version")
            yield Static("\u2500\u2500", id="screen-header-sep")
            yield Static(self._page_name, id="screen-header-page")
