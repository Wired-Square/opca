# opca/tui/widgets/vault_picker.py

from __future__ import annotations

import json

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Static

from opca.tui.widgets.op_status import OpStatus


class VaultPicker(ModalScreen[str | None]):
    """Modal dialog that lists available 1Password vaults for selection."""

    def __init__(self, tui_context: object, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._tui_context = tui_context

    def compose(self) -> ComposeResult:
        with Vertical(id="vault-picker-dialog"):
            yield Static("Select Vault", id="vault-picker-title")
            yield DataTable(id="vault-picker-table")
            yield OpStatus(id="vault-picker-status")
            with Horizontal(classes="button-row"):
                yield Button("Select", variant="primary", id="vault-picker-select")
                yield Button("Cancel", variant="default", id="vault-picker-cancel")

    def on_mount(self) -> None:
        table = self.query_one("#vault-picker-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name")
        self._load_vaults()

    @work(thread=True, exclusive=True)
    def _load_vaults(self) -> None:
        """Fetch available vaults from 1Password."""
        op_status = self.query_one("#vault-picker-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading vaults...")
        try:
            result = self._tui_context.op.vault_list()
            vaults = json.loads(result.stdout)
            rows = []
            for vault in vaults:
                name = vault.get("name", "")
                if name:
                    rows.append(name)
            rows.sort()
            self.app.call_from_thread(self._populate_table, rows)
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._show_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _populate_table(self, names: list[str]) -> None:
        table = self.query_one("#vault-picker-table", DataTable)
        table.clear()
        for name in names:
            table.add_row(name)

    def _show_error(self, msg: str) -> None:
        table = self.query_one("#vault-picker-table", DataTable)
        table.clear()
        table.add_row(f"[red]Error: {msg}[/red]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "vault-picker-cancel":
            self.dismiss(None)
        elif event.button.id == "vault-picker-select":
            self._try_select()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Allow double-click / enter on a row to select."""
        self._try_select()

    def _try_select(self) -> None:
        table = self.query_one("#vault-picker-table", DataTable)
        if table.row_count == 0:
            return
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            row = table.get_row(row_key)
            self.dismiss(str(row[0]))
        except Exception:
            pass

    def key_escape(self) -> None:
        self.dismiss(None)
