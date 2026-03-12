# opca/tui/widgets/status_bar.py

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static
from textual.containers import Horizontal


class StatusBar(Static):
    """Footer status bar showing vault, account, and connection info."""

    def __init__(
        self,
        vault: str = "",
        account: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._vault = vault
        self._account = account
        self._status = "Disconnected"

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Static(f" vault: {self._vault}", classes="status-item", id="status-vault")
            yield Static(f"account: {self._account or 'default'}", classes="status-item", id="status-account")
            yield Static(self._status, classes="status-item", id="status-state")

    def update_status(self, status: str) -> None:
        self._status = status
        state_widget = self.query_one("#status-state", Static)
        state_widget.update(status)

    def update_vault(self, vault: str) -> None:
        self._vault = vault
        self.query_one("#status-vault", Static).update(f" vault: {vault}")

    def update_account(self, account: str) -> None:
        self._account = account
        self.query_one("#status-account", Static).update(f"account: {account or 'default'}")
