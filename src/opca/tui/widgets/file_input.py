# opca/tui/widgets/file_input.py

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Static, TextArea
from textual.widget import Widget

from opca.utils.files import read_bytes


class FileInput(Widget):
    """Reusable file input: accepts a file path or pasted PEM content.

    Compose with a label, text area, and Browse button.
    The field accepts either:
      - A filesystem path (single line — read at retrieval time)
      - Pasted PEM content (multi-line, detected by '-----BEGIN' prefix)
    """

    def __init__(
        self,
        label: str = "File:",
        placeholder: str = "File path or paste PEM content",
        input_id: str = "file-input",
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._label = label
        self._placeholder = placeholder
        self._input_id = input_id

    def compose(self) -> ComposeResult:
        yield Static(self._label, classes="form-label")
        with Horizontal(classes="file-input-row"):
            yield TextArea(id=self._input_id)
            yield Button("Browse", variant="default", id=f"{self._input_id}-browse")
            yield Button("Clear", variant="default", id=f"{self._input_id}-clear")

    @property
    def value(self) -> str:
        """Return the raw text in the field."""
        return self.query_one(f"#{self._input_id}", TextArea).text.strip()

    @value.setter
    def value(self, text: str) -> None:
        ta = self.query_one(f"#{self._input_id}", TextArea)
        ta.clear()
        ta.insert(text)

    def is_pem_content(self) -> bool:
        """Check whether the input looks like pasted PEM data."""
        return self.value.startswith("-----BEGIN")

    def get_content(self) -> bytes | None:
        """Return the content as bytes.

        - If the input starts with '-----BEGIN', treat it as pasted PEM and encode.
        - Otherwise treat it as a file path and read the file.
        - Returns None if the field is empty or the file cannot be read.
        """
        text = self.value
        if not text:
            return None

        if self.is_pem_content():
            return text.encode("utf-8")

        return read_bytes(Path(text).expanduser())

    def get_path(self) -> str | None:
        """Return the file path if the input is a path (not pasted PEM), else None."""
        text = self.value
        if not text or self.is_pem_content():
            return None
        return str(Path(text).expanduser())

    def as_kwarg(self, name: str) -> dict[str, object]:
        """Return kwargs for make_app(): ``{name: path}`` or ``{name + '_data': bytes}``.

        When the user provided a file path the original path is returned so
        the CLI handler can read it normally.  When PEM content was pasted the
        raw bytes are returned under a ``_data`` suffixed key so the handler
        can use them directly — no temporary file needed.
        """
        path = self.get_path()
        if path is not None:
            return {name: path}
        content = self.get_content()
        if content is not None:
            return {f"{name}_data": content}
        return {}

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == f"{self._input_id}-browse":
            event.stop()
            from opca.tui.screens.file_picker import FilePickerScreen
            self.app.push_screen(
                FilePickerScreen(),
                callback=self._on_file_selected,
            )
        elif event.button.id == f"{self._input_id}-clear":
            event.stop()
            self.query_one(f"#{self._input_id}", TextArea).clear()

    def _on_file_selected(self, path: str | None) -> None:
        if path:
            ta = self.query_one(f"#{self._input_id}", TextArea)
            ta.clear()
            ta.insert(path)
