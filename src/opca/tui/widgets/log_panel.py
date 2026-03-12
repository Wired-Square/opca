# opca/tui/widgets/log_panel.py

from __future__ import annotations

from textual.widgets import RichLog


class LogPanel(RichLog):
    """Scrollable log/output panel for operation results."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(highlight=True, markup=True, wrap=True, **kwargs)

    def log_success(self, message: str) -> None:
        self.write(f"[green]✓[/green] {message}")

    def log_error(self, message: str) -> None:
        self.write(f"[red]✗[/red] {message}")

    def log_info(self, message: str) -> None:
        self.write(f"[blue]ℹ[/blue] {message}")

    def log_warning(self, message: str) -> None:
        self.write(f"[yellow]⚠[/yellow] {message}")
