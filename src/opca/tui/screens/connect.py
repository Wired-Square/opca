# opca/tui/screens/connect.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Static, LoadingIndicator


class ConnectScreen(Screen):
    """Initial screen for entering vault/account and connecting to 1Password."""

    BINDINGS = [("escape", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        with Vertical(id="connect-form"):
            yield Static(
                "[bold #ffffff]opca[/bold #ffffff]\n[bold]The 1Password Certificate Authority[/bold]\n[dim]by Wired Square[/dim]",
                id="connect-title",
            )
            yield Static("Vault (required):", classes="form-label")
            yield Input(
                placeholder="e.g. CA-Production",
                id="vault-input",
                value=self.app.tui_context.vault,
            )
            yield Static("Account (optional):", classes="form-label")
            yield Input(
                placeholder="e.g. company.1password.com",
                id="account-input",
                value=self.app.tui_context.account or "",
            )
            yield Button("Connect", variant="primary", id="connect-btn")
            yield Static("", id="connect-status")
            yield LoadingIndicator(id="connect-spinner")

    def on_mount(self) -> None:
        self.query_one("#connect-spinner").display = False
        # If vault was provided via CLI, auto-connect
        if self.app.tui_context.vault:
            self._do_connect()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "connect-btn":
            self._do_connect()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._do_connect()

    def _do_connect(self) -> None:
        vault = self.query_one("#vault-input", Input).value.strip()
        account = self.query_one("#account-input", Input).value.strip()

        if not vault:
            self.query_one("#connect-status", Static).update("[red]Vault is required[/red]")
            return

        self.app.tui_context.vault = vault
        self.app.tui_context.account = account or None
        self._connect_worker()

    @work(thread=True, exclusive=True)
    def _connect_worker(self) -> None:
        self.app.call_from_thread(self._show_connecting)
        try:
            self.app.tui_context.connect()
            self.app.call_from_thread(self._on_connected)
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._show_error, str(e))

    def _show_connecting(self) -> None:
        self.query_one("#connect-spinner").display = True
        self.query_one("#connect-btn", Button).disabled = True
        self.query_one("#connect-status", Static).update("Connecting to 1Password...")

    def _on_connected(self) -> None:
        self.query_one("#connect-spinner").display = False
        ca_status = "CA loaded" if self.app.tui_context.has_ca else "No CA found (you can initialize one)"
        self.query_one("#connect-status", Static).update(f"[green]Connected![/green] {ca_status}")
        self.app.switch_to_dashboard()

    def _show_error(self, msg: str) -> None:
        self.query_one("#connect-spinner").display = False
        self.query_one("#connect-btn", Button).disabled = False
        self.query_one("#connect-status", Static).update(f"[red]Error: {msg}[/red]")
