# opca/commands/tui/actions.py

from __future__ import annotations

from opca.constants import EXIT_OK, EXIT_FATAL
from opca.models import App


def handle_tui(app: App) -> int:
    try:
        from opca.tui.app import OpcaTuiApp
    except ImportError:
        print(
            "Error: The TUI requires the 'textual' package.\n"
            "Install it with: pip install opca[tui]"
        )
        return EXIT_FATAL

    tui = OpcaTuiApp(account=app.account, vault=app.vault)
    tui.run()
    return EXIT_OK
