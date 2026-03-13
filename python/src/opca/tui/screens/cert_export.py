# opca/tui/screens/cert_export.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Select, Static, Checkbox

from opca.tui.clipboard import copy_to_clipboard
from opca.tui.screens.password import PasswordModal, PasswordResult
from opca.services.one_password import Op
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import op_status_context
from opca.utils.files import write_bytes


EXPORT_FORMATS = [
    ("PEM", "pem"),
    ("PKCS#12", "pkcs12"),
]


class CertExportScreen(Screen):
    """Export a certificate in PEM or PKCS#12 format."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, cn: str, serial: str | int, title: str = "", **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._cn = cn
        self._serial = serial
        self._title = title or cn
        self._cert_pem: str | None = None
        self._key_pem: str | None = None
        self._p12_bytes: bytes | None = None
        self._bundle = None

    def _get_bundle(self, ctx):
        """Return cached bundle, or fetch from 1Password once."""
        if self._bundle is None:
            self._bundle = ctx.ca.retrieve_certbundle(self._title)
        return self._bundle

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield ScreenHeader(f"Export: {self._cn}")

            yield Static("Format:", classes="form-label")
            yield Select(EXPORT_FORMATS, value="pem", id="format-select", allow_blank=False)

            yield Checkbox("Include private key", id="with-key-check")

            yield Static("Output file (leave blank for stdout display):", classes="form-label")
            yield Input(placeholder="e.g. /tmp/cert.pem", id="outfile-input")

            with Horizontal(classes="button-row"):
                yield Button("Export", variant="primary", id="btn-export")
                yield Button("Copy Certificate", variant="default", id="btn-copy-cert")
                yield Button("Copy Private Key", variant="default", id="btn-copy-key")
                yield Button("Copy PKCS#12", variant="default", id="btn-copy-p12")
                yield Button("Home", variant="default", id="btn-home")

            yield OpStatus(id="op-status")
            yield Static("", id="export-status")
            yield Static("", id="export-output")
        yield Footer()

    def on_mount(self) -> None:
        self._update_copy_buttons()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "format-select":
            self._update_copy_buttons()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "with-key-check":
            self._update_copy_buttons()

    def _update_copy_buttons(self) -> None:
        fmt = str(self.query_one("#format-select", Select).value)
        with_key = self.query_one("#with-key-check", Checkbox).value
        is_pem = fmt == "pem"

        self.query_one("#btn-copy-cert", Button).display = is_pem
        self.query_one("#btn-copy-key", Button).display = is_pem and with_key
        self.query_one("#btn-copy-p12", Button).display = not is_pem
        self.query_one("#with-key-check", Checkbox).display = is_pem

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-home":
            self.app.pop_screen()
        elif event.button.id == "btn-export":
            self._submit()
        elif event.button.id == "btn-copy-cert":
            self._do_copy("cert")
        elif event.button.id == "btn-copy-key":
            self._do_copy("key")
        elif event.button.id == "btn-copy-p12":
            self._submit_copy_p12()

    def _submit(self) -> None:
        fmt = str(self.query_one("#format-select", Select).value)
        if fmt == "pkcs12":
            self.app.push_screen(
                PasswordModal(
                    title="PKCS#12 Password",
                    default_store_title=f"PKCS#12: {self._cn}",
                ),
                callback=self._export_pkcs12,
            )
        else:
            self._export_pem()

    def _submit_copy_p12(self) -> None:
        self.app.push_screen(
            PasswordModal(
                title="PKCS#12 Password",
                default_store_title=f"PKCS#12: {self._cn}",
            ),
            callback=self._copy_pkcs12,
        )

    @work(thread=True, exclusive=True, group="op")
    def _export_pem(self) -> None:
        with_key = self.query_one("#with-key-check", Checkbox).value
        outfile = self.query_one("#outfile-input", Input).value.strip() or None

        with op_status_context(self, "Exporting PEM..."):
            ctx = self.app.tui_context
            try:
                bundle = self._get_bundle(ctx)
                if bundle is None:
                    self.app.call_from_thread(self._show_error, "Certificate not found")
                    return

                cert_pem = bundle.get_certificate(pem_format=True)
                key_pem = bundle.get_private_key() if with_key else None

                self._cert_pem = cert_pem
                self._key_pem = key_pem

                if outfile:
                    write_bytes(outfile, cert_pem.encode("utf-8"),
                                overwrite=False, create_dirs=False, atomic=True, mode=0o644)
                    if key_pem:
                        key_file = outfile.replace(".pem", ".key").replace(".crt", ".key")
                        if key_file == outfile:
                            key_file = outfile + ".key"
                        write_bytes(key_file, key_pem.encode("utf-8"),
                                    overwrite=False, create_dirs=False, atomic=True, mode=0o600)
                    self.app.call_from_thread(self._show_success, f"Written to {outfile}")
                else:
                    output = cert_pem
                    if key_pem:
                        output += "\n" + key_pem
                    self.app.call_from_thread(self._show_output, output)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(self._show_error, str(e))

    def _export_pkcs12(self, result: PasswordResult | None) -> None:
        if result is None:
            return
        self._do_export_pkcs12(result)

    @work(thread=True, exclusive=True, group="op")
    def _do_export_pkcs12(self, result: PasswordResult) -> None:
        outfile = self.query_one("#outfile-input", Input).value.strip() or None

        with op_status_context(self, "Exporting PKCS#12..."):
            ctx = self.app.tui_context
            try:
                bundle = self._get_bundle(ctx)
                if bundle is None:
                    self.app.call_from_thread(self._show_error, "Certificate not found")
                    return

                p12_bytes = bundle.export_pkcs12(password=result.password, name=self._cn)
                self._p12_bytes = p12_bytes

                if outfile:
                    write_bytes(outfile, p12_bytes,
                                overwrite=False, create_dirs=False, atomic=True, mode=0o600)
                    self.app.call_from_thread(self._show_success, f"PKCS#12 written to {outfile}")
                else:
                    import base64
                    b64 = base64.b64encode(p12_bytes).decode("ascii")
                    self.app.call_from_thread(self._show_output, f"Base64 PKCS#12:\n{b64}")

                stored, msg = _store_password_if_requested(result, ctx)
                if msg:
                    severity = "information" if stored else "warning"
                    self.app.call_from_thread(self.notify, msg, severity=severity)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(self._show_error, str(e))

    @work(thread=True, exclusive=True, group="op")
    def _do_copy(self, what: str) -> None:
        with op_status_context(self, f"Copying {what}..."):
            ctx = self.app.tui_context
            try:
                # Fetch if not already cached
                if self._cert_pem is None:
                    bundle = self._get_bundle(ctx)
                    if bundle is None:
                        self.app.call_from_thread(self._show_error, "Certificate not found")
                        return
                    self._cert_pem = bundle.get_certificate(pem_format=True)
                    self._key_pem = bundle.get_private_key()

                if what == "cert":
                    copy_to_clipboard(self._cert_pem.encode("utf-8"))
                    self.app.call_from_thread(self.notify, "Certificate PEM copied to clipboard", severity="information")
                elif what == "key":
                    if not self._key_pem:
                        self.app.call_from_thread(self._show_error, "No private key available")
                        return
                    copy_to_clipboard(self._key_pem.encode("utf-8"))
                    self.app.call_from_thread(self.notify, "Private key copied to clipboard", severity="information")
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(self.notify, f"Copy failed: {e}", severity="error")

    def _copy_pkcs12(self, result: PasswordResult | None) -> None:
        if result is None:
            return
        self._do_copy_pkcs12(result)

    @work(thread=True, exclusive=True, group="op")
    def _do_copy_pkcs12(self, result: PasswordResult) -> None:
        with op_status_context(self, "Copying PKCS#12..."):
            ctx = self.app.tui_context
            try:
                if self._p12_bytes is None:
                    bundle = self._get_bundle(ctx)
                    if bundle is None:
                        self.app.call_from_thread(self._show_error, "Certificate not found")
                        return
                    self._p12_bytes = bundle.export_pkcs12(password=result.password, name=self._cn)

                import base64
                copy_to_clipboard(base64.b64encode(self._p12_bytes))
                self.app.call_from_thread(
                    self.notify, "PKCS#12 (base64) copied to clipboard", severity="information"
                )

                stored, msg = _store_password_if_requested(result, ctx)
                if msg:
                    severity = "information" if stored else "warning"
                    self.app.call_from_thread(self.notify, msg, severity=severity)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(self.notify, f"Copy failed: {e}", severity="error")

    def _show_success(self, msg: str) -> None:
        self.query_one("#export-status", Static).update(f"[green]{msg}[/green]")
        self.notify(msg, severity="information")

    def _show_output(self, output: str) -> None:
        self.query_one("#export-status", Static).update("[green]Export complete[/green]")
        self.query_one("#export-output", Static).update(output)

    def _show_error(self, msg: str) -> None:
        self.query_one("#export-status", Static).update(f"[red]Error: {msg}[/red]")


def _store_password_if_requested(result: PasswordResult, ctx: object) -> tuple[bool, str]:
    """Store the password in 1Password if the user ticked the checkbox.

    Returns (success, message) — ``(False, "")`` when storage was not requested.
    """
    if not result.store_in_op:
        return False, ""
    try:
        op = Op(account=getattr(ctx.op, "account", None), vault=result.store_vault)
        op.store_item(
            item_title=result.store_title,
            attributes=[f"password={result.password}"],
            category="Password",
            action="create",
        )
        return True, f"Password stored as '{result.store_title}' in vault '{result.store_vault}'"
    except (Exception, SystemExit) as e:
        return False, f"Could not store password: {e}"
