# opca/tui/screens/dashboard.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, ListView, ListItem, Label, Static

from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.screen_header import ScreenHeader


# Sidebar menu items mapped to screen IDs
MENU_ITEMS = [
    ("CA", "ca"),
    ("Certificates", "cert_list"),
    ("CRL", "crl"),
    ("CSR", "csr"),
    ("DKIM", "dkim"),
    ("OpenVPN", "openvpn"),
    ("Database", "database"),
    ("Vault", "vault_backup"),
]


class Dashboard(Screen):
    """Main dashboard with sidebar navigation and content area."""

    BINDINGS = [
        ("q", "app.quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("1", "nav(0)", "CA"),
        ("2", "nav(1)", "Certs"),
        ("3", "nav(2)", "CRL"),
        ("4", "nav(3)", "CSR"),
        ("5", "nav(4)", "DKIM"),
        ("6", "nav(5)", "OpenVPN"),
        ("7", "nav(6)", "Database"),
        ("8", "nav(7)", "Vault"),
    ]

    def compose(self) -> ComposeResult:
        ctx = self.app.tui_context

        with Vertical(id="sidebar"):
            yield Static("OPCA", id="sidebar-title")
            yield ListView(
                *[ListItem(Label(name), id=f"menu-{sid}") for name, sid in MENU_ITEMS],
                id="menu",
            )

        with VerticalScroll(id="content"):
            yield ScreenHeader("Dashboard")
            yield Static("", id="content-body")
            yield LogPanel(id="output-log")

        yield Footer()

    def on_mount(self) -> None:
        self._show_welcome()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        screen_id = item_id.replace("menu-", "")
        self._navigate_to(screen_id)

    def action_nav(self, index: int) -> None:
        if 0 <= index < len(MENU_ITEMS):
            _, screen_id = MENU_ITEMS[index]
            self._navigate_to(screen_id)

    def action_refresh(self) -> None:
        screen_id = getattr(self, "_current_screen_id", None)
        if screen_id:
            self._navigate_to(screen_id)

    def _navigate_to(self, screen_id: str) -> None:
        self._current_screen_id = screen_id
        self.app.navigate_to(screen_id)

    def on_screen_resume(self) -> None:
        self._show_welcome()

    @work(thread=True, exclusive=True, group="op")
    def _show_welcome(self) -> None:
        self.app.call_from_thread(
            self._set_content_loading, True,
        )
        try:
            ctx = self.app.tui_context

            if ctx.has_ca:
                db = ctx.ca.ca_database
                db.process_ca_database()
                cert_count = db.count_certs()
                valid = len(db.certs_valid)
                expired = len(db.certs_expired)
                revoked = len(db.certs_revoked)
                expiring = len(db.certs_expires_soon)

                text = (
                    f"Vault: [bold]{ctx.vault}[/bold]\n"
                    f"Certificates: {cert_count} total "
                    f"([green]{valid} valid[/green], "
                    f"[yellow]{expiring} expiring[/yellow], "
                    f"[dim]{expired} expired[/dim], "
                    f"[red]{revoked} revoked[/red])\n\n"
                    "Use the sidebar or press 1-8 to navigate."
                )
            else:
                text = (
                    f"Vault: [bold]{ctx.vault}[/bold]\n\n"
                    "No Certificate Authority found in this vault.\n"
                    "Press [bold]1[/bold] to open CA management and initialise or import a CA.\n"
                    "Press [bold]8[/bold] to open Vault and restore from a backup."
                )

            self.app.call_from_thread(
                self.query_one("#content-body", Static).update,
                text,
            )
        finally:
            self.app.call_from_thread(
                self._set_content_loading, False,
            )

    def _set_content_loading(self, loading: bool) -> None:
        try:
            self.query_one("#content", VerticalScroll).loading = loading
        except Exception:
            pass
