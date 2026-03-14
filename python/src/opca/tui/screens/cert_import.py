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
from opca.tui.workers import op_status_context


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

            yield FileInput(
                label="Private Key (optional):",
                placeholder="File path or paste PEM private key",
                input_id="key-input",
                id="fi-key",
            )

            yield Static("Passphrase (for encrypted private keys):", classes="form-label")
            yield Input(
                placeholder="Leave blank if key is not encrypted",
                password=True,
                id="passphrase-input",
            )

            yield FileInput(
                label="Certificate Chain (optional):",
                placeholder="File path or paste PEM intermediate certificates",
                input_id="chain-input",
                id="fi-chain",
            )

            yield Static("CSR Common Name (optional):", classes="form-label")
            with Horizontal(classes="form-row"):
                yield Select(
                    [],
                    prompt="Select a pending CSR",
                    allow_blank=True,
                    id="csr-cn-select",
                )
                yield Button("Detect", variant="default", id="btn-detect-csr")

            yield Static(
                "[dim]Provide either a private key OR a CSR CN (not both).[/dim]",
                classes="form-label",
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
        self._pending_csr_cns = [val for _, val in options]
        select = self.query_one("#csr-cn-select", Select)
        select.set_options(options)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-home":
            self.app.pop_screen()
        elif event.button.id == "btn-detect-csr":
            self._detect_csr()
        elif event.button.id == "btn-import":
            self._submit()

    @work(thread=True, exclusive=True, group="op")
    def _detect_csr(self) -> None:
        """Extract CN from the certificate and select the matching pending CSR."""
        from opca.tui.workers import extract_certificate_cn

        fi_cert = self.query_one("#fi-cert", FileInput)
        cert_content = fi_cert.get_content()
        if not cert_content:
            self.app.call_from_thread(self._show_error, "Provide a certificate first.")
            return

        cn = extract_certificate_cn(cert_content)
        if cn is None:
            self.app.call_from_thread(self._show_error, "Unable to parse certificate or no CN found.")
            return

        select = self.query_one("#csr-cn-select", Select)
        pending = getattr(self, "_pending_csr_cns", [])
        if cn in pending:
            self.app.call_from_thread(setattr, select, "value", cn)
            self.app.call_from_thread(
                self.query_one("#import-status", Static).update,
                f"[green]Matched pending CSR: {cn}[/green]",
            )
        else:
            self.app.call_from_thread(
                self.query_one("#import-status", Static).update,
                f"[yellow]No pending CSR found for '{cn}'[/yellow]",
            )

    def _submit(self) -> None:
        fi_cert = self.query_one("#fi-cert", FileInput)
        fi_key = self.query_one("#fi-key", FileInput)
        csr_select = self.query_one("#csr-cn-select", Select)
        csr_value = csr_select.value
        csr_cn = str(csr_value) if isinstance(csr_value, str) else ""

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
        """Import certificate + private key (+ optional chain). Auto-detects local vs external."""
        with op_status_context(self, "Importing certificate..."):
            try:
                fi_cert = self.query_one("#fi-cert", FileInput)
                fi_key = self.query_one("#fi-key", FileInput)
                fi_chain = self.query_one("#fi-chain", FileInput)
                passphrase_input = self.query_one("#passphrase-input", Input)

                cert_data = fi_cert.get_content()
                key_data = fi_key.get_content()
                chain_data = fi_chain.get_content()
                passphrase_text = passphrase_input.value.strip()

                if not cert_data:
                    self.app.call_from_thread(self._show_error, "Could not read certificate.")
                    return
                if not key_data:
                    self.app.call_from_thread(self._show_error, "Could not read private key.")
                    return

                # Try to detect encrypted private key and apply passphrase
                passphrase: bytes | None = None
                if passphrase_text:
                    passphrase = passphrase_text.encode("utf-8")
                elif b"ENCRYPTED" in key_data:
                    self.app.call_from_thread(
                        self._show_error,
                        "Private key appears to be encrypted. Please provide the passphrase.",
                    )
                    return

                # Validate the private key can be loaded
                from cryptography.hazmat.primitives.serialization import load_pem_private_key

                try:
                    load_pem_private_key(key_data, passphrase)
                except (ValueError, TypeError) as e:
                    if "password" in str(e).lower() or "decrypt" in str(e).lower():
                        self.app.call_from_thread(
                            self._show_error,
                            "Failed to decrypt private key. Check passphrase.",
                        )
                    else:
                        self.app.call_from_thread(self._show_error, f"Invalid private key: {e}")
                    return

                # If passphrase was provided, re-export key as unencrypted PEM for storage
                if passphrase:
                    from cryptography.hazmat.primitives.serialization import (
                        Encoding,
                        NoEncryption,
                        PrivateFormat,
                    )

                    decrypted_key = load_pem_private_key(key_data, passphrase)
                    key_data = decrypted_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption(),
                    )

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
                cert_type = "external" if is_external else "imported"

                cn = None
                for attr in certificate.subject:
                    if attr.oid == x509.oid.NameOID.COMMON_NAME:
                        cn = attr.value
                        break

                config: dict = {
                    "type": cert_type,
                    "certificate": cert_data,
                    "private_key": key_data,
                }

                with ctx.locked_mutation("cert_import"):
                    cert_bundle = ctx.ca.import_certificate_bundle(
                        cert_type=cert_type,
                        config=config,
                        item_title=cn,
                    )

                    if is_external:
                        from cryptography.x509.oid import NameOID

                        issuer_attrs = certificate.issuer.get_attributes_for_oid(
                            NameOID.COMMON_NAME
                        )
                        issuer = issuer_attrs[0].value if issuer_attrs else "Unknown"
                        issuer_subject = certificate.issuer.rfc4514_string()
                    else:
                        issuer = None
                        issuer_subject = None

                        # Advance serial counter for locally signed imports
                        cert_serial = certificate.serial_number
                        ctx.ca.ca_database.increment_serial(
                            serial_type="cert",
                            serial_number=cert_serial,
                        )

                    # Attach certificate chain to bundle if provided
                    if chain_data:
                        cert_bundle.certificate_chain = chain_data

                    result = ctx.ca.store_certbundle(
                        cert_bundle,
                        issuer=issuer,
                        issuer_subject=issuer_subject,
                    )

                log = self.query_one("#import-log", LogPanel)
                label = "external" if is_external else "local"

                if result.returncode == 0:
                    self.app.call_from_thread(
                        self.notify,
                        f"Certificate imported as {label}.",
                        severity="information",
                    )
                    self.app.call_from_thread(self.app.pop_screen)
                else:
                    self.app.call_from_thread(
                        log.write,
                        result.stderr.decode("utf-8", errors="replace") if result.stderr else "Import failed.",
                    )
                    self.app.call_from_thread(self._show_error, "Import failed. See log.")

            except (Exception, SystemExit) as e:
                self.app.call_from_thread(self._show_error, str(e))

    @work(thread=True, exclusive=True, group="op")
    def _do_import_csr(self, csr_cn: str) -> None:
        """Import a certificate that matches an existing CSR."""
        with op_status_context(self, f"Importing certificate for CSR '{csr_cn}'..."):
            try:
                fi_cert = self.query_one("#fi-cert", FileInput)
                cert_data = fi_cert.get_content()

                if not cert_data:
                    self.app.call_from_thread(self._show_error, "Could not read certificate.")
                    return

                from opca.commands.csr.actions import handle_csr_import
                from opca.tui.workers import capture_handler

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

    def _show_error(self, msg: str) -> None:
        self.query_one("#import-status", Static).update(f"[red]{msg}[/red]")
