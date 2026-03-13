# opca/tui/screens/file_picker.py

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Static


class FilePickerScreen(ModalScreen[str | None]):
    """Modal file picker using DirectoryTree.

    Dismisses with the selected file path (str) or None on cancel.
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self,
        start_path: str | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._start_path = start_path or str(Path.home())
        self._selected_path: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="file-picker-dialog"):
            yield Static("Select File", id="file-picker-title")
            yield DirectoryTree(self._start_path, id="file-picker-tree")
            yield Static("", id="file-picker-selected")
            with Horizontal(classes="button-row"):
                yield Button("Select", variant="primary", id="btn-fp-select")
                yield Button("Cancel", variant="default", id="btn-fp-cancel")

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self._selected_path = str(event.path)
        self.query_one("#file-picker-selected", Static).update(
            f"[dim]{self._selected_path}[/dim]"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-fp-select":
            self.dismiss(self._selected_path)
        elif event.button.id == "btn-fp-cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
