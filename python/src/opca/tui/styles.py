# opca/tui/styles.py

from __future__ import annotations

_STATUS_MARKUP: dict[str, str] = {
    "Valid": "[green]Valid[/green]",
    "Revoked": "[red]Revoked[/red]",
    "Expired": "[dim]Expired[/dim]",
    "Expiring": "[yellow]Expiring[/yellow]",
    "Pending": "[yellow]Pending[/yellow]",
    "Complete": "[green]Complete[/green]",
}


def style_status(status: str) -> str:
    """Return Rich-markup styled text for a certificate or CSR status."""
    return _STATUS_MARKUP.get(status, f"[red]{status}[/red]")
