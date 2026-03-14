# opca/tui/app.py

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from textual.app import App
from textual.events import Key
from textual.widgets import Button

from opca import __version__
from opca.tui.context import TuiContext

log = logging.getLogger(__name__)

CSS_PATH = Path(__file__).parent / "css" / "app.tcss"


class OpcaTuiApp(App):
    """OPCA Terminal User Interface."""

    TITLE = f"OPCA v{__version__}"
    CSS_PATH = CSS_PATH

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("question_mark", "help", "Help"),
    ]

    def __init__(
        self,
        account: Optional[str] = None,
        vault: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self.tui_context = TuiContext(account=account, vault=vault)
        # Redirect Python logging away from stderr so it does not corrupt the
        # Textual display.  Any StreamHandlers that point at the real terminal
        # must be removed before Textual takes ownership of the TTY.
        self._saved_handlers: list[logging.Handler] = []
        root = logging.getLogger()
        for handler in root.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                root.removeHandler(handler)
                self._saved_handlers.append(handler)

    def _on_exit_app(self) -> None:
        """Restore logging handlers on exit."""
        root = logging.getLogger()
        for handler in self._saved_handlers:
            root.addHandler(handler)
        self._saved_handlers.clear()
        super()._on_exit_app()

    def on_key(self, event: Key) -> None:
        """Allow left/right arrow keys to navigate between buttons."""
        if event.key in ("left", "right") and isinstance(self.focused, Button):
            if event.key == "right":
                self.screen.focus_next()
            else:
                self.screen.focus_previous()
            event.prevent_default()

    def action_help(self) -> None:
        """Show help modal."""
        from opca.tui.screens.help import HelpModal
        self.push_screen(HelpModal())

    def on_mount(self) -> None:
        """Show connect screen or dashboard depending on state."""
        from opca.tui.screens.connect import ConnectScreen
        self.push_screen(ConnectScreen())

    def action_logout(self) -> None:
        """Disconnect and return to the connect screen."""
        from opca.tui.screens.connect import ConnectScreen
        self.tui_context.disconnect()
        self.switch_screen(ConnectScreen(auto_connect=False))

    def switch_to_dashboard(self) -> None:
        """Switch from connect screen to dashboard."""
        from opca.tui.screens.dashboard import Dashboard
        self.switch_screen(Dashboard())

    def navigate_to(self, screen_id: str) -> None:
        """Navigate to a content screen by ID. Pushes screen on top of dashboard."""
        screen = self._make_screen(screen_id)
        if screen is not None:
            self.push_screen(screen)

    def _make_screen(self, screen_id: str):
        """Lazily import and create the screen for the given ID."""
        if screen_id == "ca":
            from opca.tui.screens.ca import CAScreen
            return CAScreen()
        elif screen_id == "cert_list":
            from opca.tui.screens.cert_list import CertListScreen
            return CertListScreen()
        elif screen_id == "cert_create":
            from opca.tui.screens.cert_create import CertCreateScreen
            return CertCreateScreen()
        elif screen_id == "cert_info":
            # Needs a serial or CN, handled by caller
            return None
        elif screen_id == "cert_export":
            return None
        elif screen_id == "crl":
            from opca.tui.screens.crl import CRLScreen
            return CRLScreen()
        elif screen_id == "csr":
            from opca.tui.screens.csr import CSRScreen
            return CSRScreen()
        elif screen_id == "dkim":
            from opca.tui.screens.dkim import DKIMScreen
            return DKIMScreen()
        elif screen_id == "openvpn":
            from opca.tui.screens.openvpn import OpenVPNScreen
            return OpenVPNScreen()
        elif screen_id == "database":
            from opca.tui.screens.database import DatabaseScreen
            return DatabaseScreen()
        elif screen_id == "vault_backup":
            from opca.tui.screens.vault_backup import VaultBackupScreen
            return VaultBackupScreen()
        else:
            log.warning("Unknown screen: %s", screen_id)
            return None
