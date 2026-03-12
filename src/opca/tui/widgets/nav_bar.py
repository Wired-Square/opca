# opca/tui/widgets/nav_bar.py

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Button


class NavBar(Horizontal):
    """Horizontal button bar with selectable tabs.

    Yields buttons from a list of (label, id) tuples.  One button is
    highlighted at a time via the ``nav-selected`` CSS class.  Clicking
    a button posts a :class:`NavBar.Selected` message and updates the
    highlight.

    A special ``home`` id triggers :class:`NavBar.Home` instead.
    """

    class Selected(Message):
        """Posted when a nav button is clicked."""

        def __init__(self, view_id: str) -> None:
            self.view_id = view_id
            super().__init__()

    class Home(Message):
        """Posted when the Home button is clicked."""

    def __init__(
        self,
        items: list[tuple[str, str]],
        *,
        default: str | None = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._items = items
        self._default = default or (items[0][1] if items else None)

    def compose(self) -> ComposeResult:
        for label, btn_id in self._items:
            classes = "nav-selected" if btn_id == self._default else ""
            yield Button(label, id=f"nav-{btn_id}", classes=classes)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = (event.button.id or "").removeprefix("nav-")
        if btn_id == "home":
            event.stop()
            self.post_message(self.Home())
        else:
            event.stop()
            self.select(btn_id)
            self.post_message(self.Selected(btn_id))

    def select(self, view_id: str) -> None:
        """Highlight the given nav button."""
        for btn in self.query("Button"):
            btn.remove_class("nav-selected")
        try:
            self.query_one(f"#nav-{view_id}", Button).add_class("nav-selected")
        except Exception:
            pass
