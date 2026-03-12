# opca/tui/screens/password.py

from __future__ import annotations

import secrets
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Static

from opca.tui.widgets.vault_picker import VaultPicker


@dataclass
class PasswordResult:
    """Value returned by :class:`PasswordModal` on success."""
    password: str
    store_in_op: bool = False
    store_vault: str = ""
    store_title: str = ""


class PasswordModal(ModalScreen[PasswordResult | None]):
    """Password input modal with optional generation and 1Password storage.

    Parameters
    ----------
    title:
        Dialog heading.
    default_store_title:
        Pre-filled item name when *Store in 1Password* is ticked.
    confirm:
        When ``True`` (default) show a confirmation field and Generate button.
        Set to ``False`` for restore/decrypt flows (single password entry).
    """

    def __init__(
        self,
        title: str = "Enter Password",
        default_store_title: str = "",
        confirm: bool = True,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._title = title
        self._default_store_title = default_store_title
        self._confirm = confirm
        self._selected_vault: str = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="password-dialog"):
            yield Static(self._title, id="confirm-title")

            # Password row with optional Generate button
            yield Static("Password:", classes="form-label")
            with Horizontal(classes="form-row"):
                yield Input(password=True, id="password-input")
                if self._confirm:
                    yield Button("Generate", variant="default", id="password-generate")

            # Confirmation field (only in confirm mode)
            if self._confirm:
                yield Static("Confirm password:", classes="form-label")
                yield Input(password=True, id="password-confirm")

            # Store in 1Password section
            if self._confirm:
                yield Checkbox("Store in 1Password", id="store-in-op-check")

                with Vertical(id="store-op-section"):
                    yield Static("Vault:", classes="form-label")
                    with Horizontal(classes="form-row"):
                        yield Input(
                            id="store-vault-input",
                            placeholder="Select a vault...",
                        )
                        yield Button("Browse", variant="default", id="store-vault-browse")

                    yield Static("Item title:", classes="form-label")
                    yield Input(
                        value=self._default_store_title,
                        id="store-title-input",
                        placeholder="e.g. Vault Backup Password",
                    )

            yield Static("", id="password-error")
            with Horizontal(classes="button-row"):
                yield Button("OK", variant="primary", id="password-ok")
                yield Button("Cancel", variant="default", id="password-cancel")

    def on_mount(self) -> None:
        if self._confirm:
            self._update_store_section_visibility()
            # Pre-fill vault with the current vault if available
            try:
                current_vault = self.app.tui_context.op.vault
                if current_vault:
                    self._selected_vault = current_vault
                    self.query_one("#store-vault-input", Input).value = current_vault
            except (AttributeError, Exception):
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "password-cancel":
            self.dismiss(None)
        elif event.button.id == "password-ok":
            self._validate()
        elif event.button.id == "password-generate":
            self._generate_password()
        elif event.button.id == "store-vault-browse":
            self._browse_vault()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "store-in-op-check":
            self._update_store_section_visibility()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "password-input":
            if self._confirm:
                self.query_one("#password-confirm", Input).focus()
            else:
                self._validate()
        elif event.input.id == "password-confirm":
            self._validate()

    def _validate(self) -> None:
        pw1 = self.query_one("#password-input", Input).value
        error_widget = self.query_one("#password-error", Static)

        if not pw1:
            error_widget.update("[red]Password cannot be empty[/red]")
            return

        if self._confirm:
            pw2 = self.query_one("#password-confirm", Input).value
            if pw1 != pw2:
                error_widget.update("[red]Passwords do not match[/red]")
                return

        store_in_op = False
        store_vault = ""
        store_title = ""

        if self._confirm:
            store_in_op = self.query_one("#store-in-op-check", Checkbox).value
            if store_in_op:
                store_vault = self.query_one("#store-vault-input", Input).value.strip()
                store_title = self.query_one("#store-title-input", Input).value.strip()
                if not store_vault:
                    error_widget.update("[red]Please select a vault to store the password[/red]")
                    return
                if not store_title:
                    error_widget.update("[red]Please enter a title for the password item[/red]")
                    return

        self.dismiss(PasswordResult(
            password=pw1,
            store_in_op=store_in_op,
            store_vault=store_vault,
            store_title=store_title,
        ))

    def _generate_password(self) -> None:
        """Fill both password fields with a strong random password.

        Auto-enables *Store in 1Password* because a generated password
        is unrecoverable unless it is saved somewhere.
        """
        generated = secrets.token_urlsafe(32)
        self.query_one("#password-input", Input).value = generated
        if self._confirm:
            self.query_one("#password-confirm", Input).value = generated
            self.query_one("#store-in-op-check", Checkbox).value = True
            self._update_store_section_visibility()

    def _browse_vault(self) -> None:
        """Open the VaultPicker modal to select a target vault."""
        try:
            ctx = self.app.tui_context
        except AttributeError:
            return
        self.app.push_screen(
            VaultPicker(tui_context=ctx),
            callback=self._on_vault_selected,
        )

    def _on_vault_selected(self, vault_name: str | None) -> None:
        if vault_name:
            self._selected_vault = vault_name
            self.query_one("#store-vault-input", Input).value = vault_name

    def _update_store_section_visibility(self) -> None:
        """Show/hide the 1Password storage fields based on checkbox state."""
        checked = self.query_one("#store-in-op-check", Checkbox).value
        self.query_one("#store-op-section", Vertical).display = checked

    def key_escape(self) -> None:
        self.dismiss(None)
