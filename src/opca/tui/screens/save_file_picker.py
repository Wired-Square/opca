# opca/tui/screens/save_file_picker.py

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Footer, Input, Static


class SaveFilePickerScreen(ModalScreen[str | None]):
    """Modal file picker for choosing a save destination.

    Lets the user browse directories and type a filename.
    Dismisses with the full path (str) or None on cancel.
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    SaveFilePickerScreen {
        align: center middle;
    }
    #save-picker-dialog {
        width: 70;
        height: 80%;
        border: solid $accent;
        padding: 1 2;
    }
    #save-picker-title {
        text-style: bold;
        padding-bottom: 1;
    }
    #save-picker-tree {
        height: 1fr;
    }
    #save-picker-dir {
        height: 1;
        padding: 0 1;
        color: $accent;
    }
    """

    def __init__(
        self,
        start_path: str | None = None,
        default_filename: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._start_path = start_path or str(Path.home())
        self._default_filename = default_filename
        self._selected_dir = self._start_path

    def compose(self) -> ComposeResult:
        with Vertical(id="save-picker-dialog"):
            yield Static("Save File", id="save-picker-title")
            yield DirectoryTree(self._start_path, id="save-picker-tree")
            yield Static(f"[dim]{self._selected_dir}/[/dim]", id="save-picker-dir")
            yield Static("Filename:", classes="form-label")
            yield Input(
                placeholder="e.g. ca-cert.pem",
                value=self._default_filename,
                id="save-picker-filename",
            )
            with Horizontal(classes="button-row"):
                yield Button("Save", variant="primary", id="btn-sp-save")
                yield Button("Cancel", variant="default", id="btn-sp-cancel")

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        self._selected_dir = str(event.path)
        self.query_one("#save-picker-dir", Static).update(
            f"[dim]{self._selected_dir}/[/dim]"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-sp-save":
            self._try_save()
        elif event.button.id == "btn-sp-cancel":
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._try_save()

    def _try_save(self) -> None:
        filename = self.query_one("#save-picker-filename", Input).value.strip()
        if not filename:
            return
        full_path = str(Path(self._selected_dir) / filename)
        self.dismiss(full_path)

    def action_cancel(self) -> None:
        self.dismiss(None)
