# opca/tui/screens/help.py

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from opca import __version__

HELP_TEXT = f"""\
[bold]opca[/bold] v{__version__} — The 1Password Certificate Authority

[bold]Global[/bold]
  [bold]q[/bold]       Quit
  [bold]?[/bold]       Show this help

[bold]Dashboard[/bold]
  [bold]1-7[/bold]     Navigate to section
  [bold]r[/bold]       Refresh

[bold]Certificates[/bold]
  [bold]c[/bold]       Create certificate
  [bold]r[/bold]       Refresh list
  [bold]i[/bold]       Info on selected cert
  [bold]w[/bold]       Renew selected cert
  [bold]x[/bold]       Revoke selected cert
  [bold]e[/bold]       Export selected cert
  [bold]esc[/bold]     Back

[bold]All Sub-screens[/bold]
  [bold]esc[/bold]     Back to previous screen

Press [bold]esc[/bold] or [bold]?[/bold] to close this help.
"""


class HelpModal(ModalScreen[None]):
    """Modal help screen."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("question_mark", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Static(HELP_TEXT, id="help-text")
