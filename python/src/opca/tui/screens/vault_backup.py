# opca/tui/screens/vault_backup.py

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Static

from opca.services.backup import (
    encrypt_payload,
    decrypt_payload,
    BackupDecryptionError,
    BackupFormatError,
)
from opca.services.one_password import Op
from opca.services.vault import VaultBackup, VaultNotEmptyError
from opca.tui.screens.password import PasswordModal, PasswordResult
from opca.tui.screens.save_file_picker import SaveFilePickerScreen
from opca.tui.mixins import TabbedViewMixin
from opca.tui.screens.file_picker import FilePickerScreen
from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import op_status_context
from opca.utils.files import read_bytes, write_bytes


class VaultBackupScreen(TabbedViewMixin, Screen):
    """Vault backup, restore, and info operations."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    VIEWS = ["backup", "restore", "info"]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("Vault Backup")

            yield NavBar(
                [("Home", "home"), ("Backup", "backup"), ("Restore", "restore"), ("Info", "info")],
                default="backup",
            )

            # --- Backup view ---
            with Vertical(id="view-backup"):
                yield Static("Output file:", classes="form-label")
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="e.g. /tmp/my-vault.opca", id="backup-output")
                    yield Button("Browse", variant="default", id="btn-backup-browse")
                with Horizontal(classes="button-row"):
                    yield Button("Backup", variant="primary", id="btn-backup")

            # --- Restore view ---
            with Vertical(id="view-restore"):
                yield Static("Backup file:", classes="form-label")
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="e.g. /tmp/my-vault.opca", id="restore-input")
                    yield Button("Browse", variant="default", id="btn-restore-browse")
                with Horizontal(classes="button-row"):
                    yield Button("Restore", variant="warning", id="btn-restore")

            # --- Info view ---
            with Vertical(id="view-info"):
                yield Static("Backup file:", classes="form-label")
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="e.g. /tmp/my-vault.opca", id="info-input")
                    yield Button("Browse", variant="default", id="btn-info-browse")
                with Horizontal(classes="button-row"):
                    yield Button("Show Info", variant="primary", id="btn-info")

            yield OpStatus(id="op-status")
            yield LogPanel(id="vault-log")
        yield Footer()

    def on_mount(self) -> None:
        ctx = self.app.tui_context

        if ctx.has_ca:
            self._switch_view("backup")
            # Pre-fill default backup filename with full path under home directory
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            vault_name = ctx.op.vault if ctx.connected else "vault"
            default_path = Path.home() / f"{vault_name}-{timestamp}.opca"
            self.query_one("#backup-output", Input).value = str(default_path)
        else:
            self._switch_view("restore")
            # Disable the Backup tab when the vault is empty
            self.query_one("#nav-backup", Button).disabled = True

    # --- Navigation ---



    # --- Button handlers ---

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-backup":
            self._start_backup()
        elif bid == "btn-restore":
            self._start_restore()
        elif bid == "btn-info":
            self._start_info()
        elif bid == "btn-backup-browse":
            self._browse_save("backup-output")
        elif bid == "btn-restore-browse":
            self._browse_open("restore-input")
        elif bid == "btn-info-browse":
            self._browse_open("info-input")

    # --- File pickers ---

    def _browse_save(self, input_id: str) -> None:
        self.app.push_screen(
            SaveFilePickerScreen(),
            callback=lambda path: self._set_path(input_id, path),
        )

    def _browse_open(self, input_id: str) -> None:
        self.app.push_screen(
            FilePickerScreen(),
            callback=lambda path: self._set_path(input_id, path),
        )

    def _set_path(self, input_id: str, path: str | None) -> None:
        if path:
            if input_id == "backup-output":
                path = self._ensure_opca_ext(path)
            self.query_one(f"#{input_id}", Input).value = path

    # --- Backup flow ---

    def _start_backup(self) -> None:
        output = self.query_one("#backup-output", Input).value.strip()
        if not output:
            self._log_error("Please specify an output file.")
            return

        output = self._ensure_opca_ext(output)
        self.query_one("#backup-output", Input).value = output

        ctx = self.app.tui_context
        vault_name = ctx.op.vault if ctx.connected else "vault"
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        self.app.push_screen(
            PasswordModal(
                title="Backup Password",
                default_store_title=f"Vault Backup: {vault_name} {date_str}",
            ),
            callback=lambda result: self._on_backup_password(result, output),
        )

    def _on_backup_password(self, result: PasswordResult | None, output: str) -> None:
        if result is None:
            return
        self._do_backup(result, output)

    @work(thread=True, exclusive=True, group="op")
    def _do_backup(self, result: PasswordResult, output: str) -> None:
        log_panel = self.query_one("#vault-log", LogPanel)
        ctx = self.app.tui_context

        with op_status_context(self, "Creating backup..."):
            try:
                self.app.call_from_thread(log_panel.log_info, "Enumerating vault items...")
                vb = VaultBackup(op=ctx.op)
                payload = vb.create_backup()

                metadata = payload["metadata"]
                self.app.call_from_thread(
                    log_panel.log_info,
                    f"Found {metadata['item_count']} items in vault '{metadata['vault_name']}'",
                )

                self.app.call_from_thread(log_panel.log_info, "Encrypting...")
                plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                encrypted = encrypt_payload(plaintext, result.password)

                self.app.call_from_thread(log_panel.log_info, f"Writing {output}...")
                write_bytes(output, encrypted, overwrite=True, mode=0o600)

                self.app.call_from_thread(log_panel.log_success, f"Backup saved to {output}")

                # Store password in 1Password if requested
                if result.store_in_op:
                    self.app.call_from_thread(log_panel.log_info, "Storing password in 1Password...")
                    try:
                        op = Op(account=getattr(ctx.op, "account", None), vault=result.store_vault)
                        op.store_item(
                            item_title=result.store_title,
                            attributes=[f"password={result.password}"],
                            category="Password",
                            action="create",
                        )
                        self.app.call_from_thread(
                            log_panel.log_success,
                            f"Password stored as '{result.store_title}' in vault '{result.store_vault}'",
                        )
                    except (Exception, SystemExit) as e:
                        self.app.call_from_thread(log_panel.log_warning, f"Could not store password: {e}")

            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log_panel.log_error, str(e))

    # --- Restore flow ---

    def _start_restore(self) -> None:
        input_file = self.query_one("#restore-input", Input).value.strip()
        if not input_file:
            self._log_error("Please specify a backup file.")
            return

        self.app.push_screen(
            PasswordModal(title="Restore Password", confirm=False),
            callback=lambda result: self._on_restore_password(result, input_file),
        )

    def _on_restore_password(self, result: PasswordResult | None, input_file: str) -> None:
        if result is None:
            return
        self._do_restore(result.password, input_file)

    @work(thread=True, exclusive=True, group="op")
    def _do_restore(self, password: str, input_file: str) -> None:
        log_panel = self.query_one("#vault-log", LogPanel)
        ctx = self.app.tui_context

        with op_status_context(self, "Restoring from backup..."):
            try:
                self.app.call_from_thread(log_panel.log_info, f"Reading {input_file}...")
                data = read_bytes(input_file)
                if not data:
                    self.app.call_from_thread(log_panel.log_error, f"Cannot read {input_file}")
                    return

                self.app.call_from_thread(log_panel.log_info, "Decrypting...")
                plaintext = decrypt_payload(data, password)
                payload = json.loads(plaintext.decode("utf-8"))

                metadata = VaultBackup.get_metadata(payload)
                self.app.call_from_thread(
                    log_panel.log_info,
                    f"Backup from '{metadata.get('vault_name', '?')}' "
                    f"({metadata.get('backup_date', '?')}), "
                    f"{metadata.get('item_count', '?')} items",
                )

                self.app.call_from_thread(log_panel.log_info, "Restoring items...")
                vb = VaultBackup(op=ctx.op)

                def _on_progress(item_type: str, title: str) -> None:
                    self.app.call_from_thread(log_panel.log_info, f"  {item_type}: {title}")

                counts = vb.restore_backup(payload, on_progress=_on_progress)

                self.app.call_from_thread(log_panel.log_info, "Summary:")
                for item_type, count in sorted(counts.items()):
                    self.app.call_from_thread(log_panel.log_info, f"  {item_type}: {count}")

                self.app.call_from_thread(log_panel.log_success, "Restore complete")

            except BackupDecryptionError as e:
                self.app.call_from_thread(log_panel.log_error, str(e))
            except BackupFormatError as e:
                self.app.call_from_thread(log_panel.log_error, str(e))
            except VaultNotEmptyError as e:
                self.app.call_from_thread(log_panel.log_error, str(e))
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log_panel.log_error, str(e))

    # --- Info flow ---

    def _start_info(self) -> None:
        input_file = self.query_one("#info-input", Input).value.strip()
        if not input_file:
            self._log_error("Please specify a backup file.")
            return

        self.app.push_screen(
            PasswordModal(title="Backup Password", confirm=False),
            callback=lambda result: self._on_info_password(result, input_file),
        )

    def _on_info_password(self, result: PasswordResult | None, input_file: str) -> None:
        if result is None:
            return
        self._do_info(result.password, input_file)

    @work(thread=True, exclusive=True, group="op")
    def _do_info(self, password: str, input_file: str) -> None:
        log_panel = self.query_one("#vault-log", LogPanel)

        with op_status_context(self, "Reading backup info..."):
            try:
                data = read_bytes(input_file)
                if not data:
                    self.app.call_from_thread(log_panel.log_error, f"Cannot read {input_file}")
                    return

                plaintext = decrypt_payload(data, password)
                payload = json.loads(plaintext.decode("utf-8"))
                metadata = VaultBackup.get_metadata(payload)

                self.app.call_from_thread(log_panel.log_info, f"OPCA version: {metadata.get('opca_version', '?')}")
                self.app.call_from_thread(log_panel.log_info, f"Vault name:   {metadata.get('vault_name', '?')}")
                self.app.call_from_thread(log_panel.log_info, f"Backup date:  {metadata.get('backup_date', '?')}")
                self.app.call_from_thread(log_panel.log_info, f"Item count:   {metadata.get('item_count', '?')}")

                items = payload.get("items", [])
                type_counts: dict[str, int] = {}
                for item in items:
                    t = item.get("type", "unknown")
                    type_counts[t] = type_counts.get(t, 0) + 1

                if type_counts:
                    self.app.call_from_thread(log_panel.log_info, "")
                    self.app.call_from_thread(log_panel.log_info, "Item breakdown:")
                    for t, c in sorted(type_counts.items()):
                        self.app.call_from_thread(log_panel.log_info, f"  {t}: {c}")

                self.app.call_from_thread(log_panel.log_success, "Info complete")

            except (BackupDecryptionError, BackupFormatError) as e:
                self.app.call_from_thread(log_panel.log_error, str(e))
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log_panel.log_error, str(e))

    # --- Helpers ---

    @staticmethod
    def _ensure_opca_ext(path: str) -> str:
        """Append ``.opca`` extension if the path has no extension."""
        if not Path(path).suffix:
            return path + ".opca"
        return path

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Auto-add .opca extension when the user presses Enter on the backup output field."""
        if event.input.id == "backup-output":
            val = event.input.value.strip()
            if val:
                event.input.value = self._ensure_opca_ext(val)

    def _log_error(self, msg: str) -> None:
        self.query_one("#vault-log", LogPanel).log_error(msg)
