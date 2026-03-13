# opca/tui/mixins.py

from __future__ import annotations

from opca.tui.widgets.nav_bar import NavBar


class TabbedViewMixin:
    """Mixin for screens that use NavBar with toggled view containers.

    Subclasses must define a ``VIEWS`` class variable listing the view IDs
    (e.g. ``VIEWS = ["list", "create", "import"]``).  Each view ID must
    correspond to a widget with ``id="view-{view_id}"`` in the screen's
    compose tree.
    """

    VIEWS: list[str]

    def _switch_view(self, view: str) -> None:
        """Show the container for *view* and hide all others."""
        for v in self.VIEWS:
            self.query_one(f"#view-{v}").display = v == view  # type: ignore[attr-defined]

    def on_nav_bar_selected(self, event: NavBar.Selected) -> None:
        self._switch_view(event.view_id)

    def on_nav_bar_home(self, event: NavBar.Home) -> None:
        self.app.pop_screen()  # type: ignore[attr-defined]
