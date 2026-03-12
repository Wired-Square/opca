# opca/tui/screens/cert_import.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Select, Static

from opca.tui.widgets.file_input import FileInput
from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import capture_handler


class CertImportScreen(Screen):
    """Import a certificate with its private key, or match against an existing CSR."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield ScreenHeader("Import Certificate")

            yield FileInput(
                label="Certificate (required):",
                placeholder="File path or paste PEM certificate",
                input_id="cert-input",
                id="fi-cert",
            )

            yield Static(
                "[dim]Provide either a private key OR a CSR CN (not both):[/dim]",
                classes="form-label",
            )

            yield FileInput(
                label="Private Key (optional):",
                placeholder="File path or paste PEM private key",
                input_id="key-input",
                id="fi-key",
            )

            yield Static("CSR Common Name (optional):", classes="form-label")
            yield Select(
                [],
                prompt="Select a pending CSR",
                allow_blank=True,
                id="csr-cn-select",
            )

            with Horizontal(classes="button-row"):
                yield Button("Import", variant="primary", id="btn-import")
                yield Button("Back", variant="default", id="btn-home")

            yield OpStatus(id="op-status")
            yield Static("", id="import-status")
            yield LogPanel(id="import-log")
        yield Footer()

    def on_mount(self) -> None:
        self._load_pending_csrs()

    @work(thread=True, exclusive=True, group="csr-load")
    def _load_pending_csrs(self) -> None:
        try:
            ctx = self.app.tui_context
            if not ctx.has_ca:
                return
            csrs = ctx.ca.ca_database.query_all_csrs(status="Pending")
            options = [(csr["cn"], csr["cn"]) for csr in csrs]
            self.app.call_from_thread(self._set_csr_options, options)
        except (Exception, SystemExit):
            pass

    def _set_csr_options(self, options: list) -> None:
        select = self.query_one("#csr-cn-select", Select)
        select.set_options(options)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-home":
            self.app.pop_screen()
        elif event.button.id == "btn-import":
            self._submit()

    def _submit(self) -> None:
        fi_cert = self.query_one("#fi-cert", FileInput)
        fi_key = self.query_one("#fi-key", FileInput)
        csr_select = self.query_one("#csr-cn-select", Select)
        csr_value = csr_select.value
        csr_cn = "" if csr_value is Select.BLANK or csr_value is Select.NULL else str(csr_value)

        has_key = bool(fi_key.value)
        has_csr = bool(csr_cn)

        if not fi_cert.value:
            self._show_error("Certificate is required.")
            return

        if has_key and has_csr:
            self._show_error("Provide either a private key or a CSR CN, not both.")
            return

        if not has_key and not has_csr:
            self._show_error("Provide either a private key or a CSR CN.")
            return

        if has_csr:
            self._do_import_csr(csr_cn)
        else:
            self._do_import_with_key()

    @work(thread=True, exclusive=True, group="op")
    def _do_import_with_key(self) -> None:
        """Import certificate + private key. Auto-detects local vs external."""
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Importing certificate...")

        try:
            fi_cert = self.query_one("#fi-cert", FileInput)
            fi_key = self.query_one("#fi-key", FileInput)

            cert_data = fi_cert.get_content()
            key_data = fi_key.get_content()

            if not cert_data:
                self.app.call_from_thread(self._show_error, "Could not read certificate.")
                return
            if not key_data:
                self.app.call_from_thread(self._show_error, "Could not read private key.")
                return

            # Determine if signed by our CA
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            try:
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            except Exception:
                try:
                    certificate = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    self.app.call_from_thread(
                        self._show_error, "Unable to parse certificate as PEM or DER."
                    )
                    return

            ctx = self.app.tui_context
            is_external = not ctx.ca.is_cert_valid(certificate)

            from opca.commands.cert.actions import handle_cert_import

            app = ctx.make_app(
                command="cert",
                subcommand="import",
                **fi_cert.as_kwarg("cert_file"),
                **fi_key.as_kwarg("key_file"),
                external=is_external,
                cn=None,
            )
            code, output = capture_handler(handle_cert_import, app)

            log = self.query_one("#import-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")

            if code == 0:
                label = "external" if is_external else "local"
                self.app.call_from_thread(
                    self.notify,
                    f"Certificate imported as {label}.",
                    severity="information",
                )
                self.app.call_from_thread(self.app.pop_screen)
            else:
                self.app.call_from_thread(self._show_error, "Import failed. See log.")

        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._show_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_import_csr(self, csr_cn: str) -> None:
        """Import a certificate that matches an existing CSR."""
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Importing certificate for CSR '{csr_cn}'...")

        try:
            fi_cert = self.query_one("#fi-cert", FileInput)
            cert_data = fi_cert.get_content()

            if not cert_data:
                self.app.call_from_thread(self._show_error, "Could not read certificate.")
                return

            from opca.commands.csr.actions import handle_csr_import

            ctx = self.app.tui_context
            app = ctx.make_app(
                command="csr",
                subcommand="import",
                cn=csr_cn,
                **fi_cert.as_kwarg("cert_file"),
            )
            code, output = capture_handler(handle_csr_import, app)

            log = self.query_one("#import-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")

            if code == 0:
                self.app.call_from_thread(
                    self.notify,
                    f"Certificate imported for CSR '{csr_cn}'.",
                    severity="information",
                )
                self.app.call_from_thread(self.app.pop_screen)
            else:
                self.app.call_from_thread(self._show_error, "Import failed. See log.")

        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._show_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _show_error(self, msg: str) -> None:
        self.query_one("#import-status", Static).update(f"[red]{msg}[/red]")
