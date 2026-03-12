# opca/tui/screens/csr.py

from __future__ import annotations

import json

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Input, Select, Static

from opca.tui.clipboard import copy_to_clipboard
from opca.tui.widgets.file_input import FileInput
from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import capture_handler
from opca.utils.files import write_bytes


CSR_TYPES = [
    ("Apple Development", "appledev"),
    ("Web Server", "webserver"),
    ("Device", "device"),
]

SIGN_CERT_TYPES = [
    ("Web Server", "webserver"),
    ("Apple Development", "appledev"),
    ("Device", "device"),
    ("VPN Client", "vpnclient"),
    ("VPN Server", "vpnserver"),
]

STATUS_STYLES = {
    "Pending": "[yellow]Pending[/yellow]",
    "Complete": "[green]Complete[/green]",
}


class CSRScreen(Screen):
    """CSR management: list, create, import, and sign."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    VIEWS = ["list", "create", "import", "sign"]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("Certificate Signing Requests")

            yield NavBar(
                [("Home", "home"), ("CSR", "list"), ("Create CSR", "create"),
                 ("Import CSR", "import"), ("Sign CSR", "sign")],
                default="list",
            )

            with VerticalScroll(id="view-list"):
                yield DataTable(id="csr-table")
                yield Static("Export file:", classes="form-label")
                with Horizontal(classes="form-row"):
                    yield Input(
                        placeholder="Leave blank for output window",
                        id="export-outfile",
                    )
                    yield Button("Browse", variant="default", id="btn-browse-export")
                with Horizontal(classes="button-row"):
                    yield Button("Export", variant="primary", id="btn-export-csr")
                    yield Button("Copy", variant="default", id="btn-copy-csr")
                    yield Button("Refresh", variant="default", id="btn-refresh")

            with VerticalScroll(id="view-create"):
                yield Static("Common Name:", classes="form-label")
                yield Input(placeholder="e.g. John Smith", id="cn-input")
                yield Static("Email:", classes="form-label")
                yield Input(placeholder="e.g. john@example.com", id="email-input")
                yield Static("Type:", classes="form-label")
                yield Select(CSR_TYPES, value="appledev", id="type-select", allow_blank=False)
                with Horizontal(classes="button-row"):
                    yield Button("Create CSR", variant="primary", id="btn-create")

            with VerticalScroll(id="view-import"):
                yield Static("CN:", classes="form-label")
                yield Input(placeholder="e.g. John Smith", id="import-cn")
                yield FileInput(
                    label="Certificate (file path or paste PEM):",
                    placeholder="File path or paste PEM content",
                    input_id="import-cert-input",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Import", variant="primary", id="btn-import")

            with VerticalScroll(id="view-sign"):
                yield FileInput(
                    label="CSR (file path or paste PEM):",
                    placeholder="File path or paste PEM content",
                    input_id="sign-csr-input",
                )
                yield Static("Certificate type:", classes="form-label")
                yield Select(SIGN_CERT_TYPES, value="webserver", id="sign-type-select", allow_blank=False)
                with Horizontal(classes="button-row"):
                    yield Button("Sign", variant="primary", id="btn-sign")

            yield OpStatus(id="op-status")
            yield Static("", id="csr-status")
            yield LogPanel(id="csr-log")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#csr-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("CN", "Type", "Email", "Status", "Created")
        self._switch_view("list")
        self._load_csrs()

    def on_screen_resume(self) -> None:
        self._load_csrs()

    def _switch_view(self, view: str) -> None:
        for v in self.VIEWS:
            self.query_one(f"#view-{v}").display = v == view

    def on_nav_bar_selected(self, event: NavBar.Selected) -> None:
        self._switch_view(event.view_id)
        if event.view_id == "list":
            self._load_csrs()

    def on_nav_bar_home(self, event: NavBar.Home) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create":
            self._do_create()
        elif event.button.id == "btn-import":
            self._do_import()
        elif event.button.id == "btn-refresh":
            self._load_csrs()
        elif event.button.id == "btn-export-csr":
            self._do_export_csr()
        elif event.button.id == "btn-copy-csr":
            self._do_copy_csr()
        elif event.button.id == "btn-sign":
            self._do_sign()
        elif event.button.id == "btn-browse-export":
            self._browse_export()

    def _browse_export(self) -> None:
        from opca.tui.screens.save_file_picker import SaveFilePickerScreen
        self.app.push_screen(
            SaveFilePickerScreen(default_filename="request.pem"),
            callback=self._on_export_path_selected,
        )

    def _on_export_path_selected(self, path: str | None) -> None:
        if path:
            self.query_one("#export-outfile", Input).value = path

    @work(thread=True, exclusive=True, group="op")
    def _load_csrs(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading CSRs...")
        try:
            ctx = self.app.tui_context
            if not ctx.has_ca:
                self.app.call_from_thread(self._update_csr_table, [])
                return

            rows = ctx.ca.ca_database.query_all_csrs()
            self.app.call_from_thread(self._update_csr_table, rows)
        except (Exception, SystemExit) as e:
            log = self.query_one("#csr-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _update_csr_table(self, rows: list) -> None:
        table = self.query_one("#csr-table", DataTable)
        table.clear()
        for csr in rows:
            styled_status = STATUS_STYLES.get(csr["status"], csr["status"])
            # Display the raw CN (strip CSR_ prefix from title if present)
            display_cn = csr.get("cn", "")
            table.add_row(
                display_cn,
                csr.get("csr_type", ""),
                csr.get("email", ""),
                styled_status,
                csr.get("created_date", ""),
            )

    @work(thread=True, exclusive=True, group="op")
    def _do_create(self) -> None:
        cn = self.query_one("#cn-input", Input).value.strip()
        email = self.query_one("#email-input", Input).value.strip()
        csr_type = str(self.query_one("#type-select", Select).value)

        if not cn:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                "[red]CN is required[/red]",
            )
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Creating CSR for {cn}...")

        try:
            from opca.commands.csr.actions import handle_csr_create
            ctx = self.app.tui_context
            app = ctx.make_app(
                command="csr", subcommand="create",
                cn=cn, email=email or None, csr_type=csr_type,
                country=None, outdir=None,
            )
            code, output = capture_handler(handle_csr_create, app)
            log = self.query_one("#csr-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
            if code == 0:
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    f"[green]CSR created for {cn}[/green]",
                )
            else:
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    "[red]CSR creation failed[/red]",
                )
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                f"[red]Error: {e}[/red]",
            )
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_import(self) -> None:
        cn = self.query_one("#import-cn", Input).value.strip()
        file_input = self.query_one("#view-import").query_one(FileInput)
        cert_content = file_input.get_content()

        if not cn or not cert_content:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                "[red]CN and certificate are required for import[/red]",
            )
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Importing certificate for {cn}...")
        try:
            from opca.commands.csr.actions import handle_csr_import
            ctx = self.app.tui_context
            app = ctx.make_app(
                command="csr", subcommand="import",
                cn=cn, **file_input.as_kwarg("cert_file"),
            )
            code, output = capture_handler(handle_csr_import, app)
            log = self.query_one("#csr-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
        except (Exception, SystemExit) as e:
            log = self.query_one("#csr-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _get_selected_cn(self) -> str | None:
        table = self.query_one("#csr-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            row = table.get_row(row_key)
            return str(row[0]).strip() if row else None
        except Exception:
            return None

    def _fetch_csr_pem(self, cn: str) -> str | None:
        ctx = self.app.tui_context
        op_title = f"CSR_{cn}"
        result = ctx.op.get_item(op_title)
        if result.returncode != 0:
            return None
        loaded_object = json.loads(result.stdout)
        for field in loaded_object['fields']:
            if field.get('label') == 'certificate_signing_request' and 'value' in field:
                return field['value']
        return None

    @work(thread=True, exclusive=True, group="op")
    def _do_export_csr(self) -> None:
        cn = self._get_selected_cn()
        if not cn:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                "[red]Select a CSR from the table first[/red]",
            )
            return

        outfile = self.query_one("#export-outfile", Input).value.strip() or None
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Exporting CSR for {cn}...")

        try:
            csr_pem = self._fetch_csr_pem(cn)
            if not csr_pem:
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    f"[red]CSR not found for {cn}[/red]",
                )
                return

            log = self.query_one("#csr-log", LogPanel)
            if outfile:
                write_bytes(outfile, csr_pem.encode("utf-8"),
                            overwrite=False, create_dirs=False, atomic=True, mode=0o644)
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    f"[green]CSR written to {outfile}[/green]",
                )
                self.app.call_from_thread(self.notify, f"CSR written to {outfile}", severity="information")
            else:
                self.app.call_from_thread(log.write, csr_pem)
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    "[green]CSR exported[/green]",
                )
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                f"[red]Export failed: {e}[/red]",
            )
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_copy_csr(self) -> None:
        cn = self._get_selected_cn()
        if not cn:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                "[red]Select a CSR from the table first[/red]",
            )
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Copying CSR for {cn}...")

        try:
            csr_pem = self._fetch_csr_pem(cn)
            if not csr_pem:
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    f"[red]CSR not found for {cn}[/red]",
                )
                return

            copy_to_clipboard(csr_pem.encode("utf-8"))
            self.app.call_from_thread(self.notify, "CSR PEM copied to clipboard", severity="information")
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self.notify, f"Copy failed: {e}", severity="error")
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_sign(self) -> None:
        file_input = self.query_one(FileInput)
        csr_content = file_input.get_content()
        csr_type = str(self.query_one("#sign-type-select", Select).value)

        if not csr_content:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                "[red]Provide a CSR file path or paste PEM content[/red]",
            )
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Signing CSR...")

        try:
            from opca.commands.csr.actions import handle_csr_sign
            ctx = self.app.tui_context

            # Pass CSR as inline PEM since we already have the bytes
            app = ctx.make_app(
                command="csr", subcommand="sign",
                csr_file=None, csr_pem=csr_content.decode("utf-8"),
                csr_type=csr_type, cn=None,
            )
            code, output = capture_handler(handle_csr_sign, app)
            log = self.query_one("#csr-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
            if code == 0:
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    "[green]CSR signed successfully[/green]",
                )
            else:
                self.app.call_from_thread(
                    self.query_one("#csr-status", Static).update,
                    "[red]CSR signing failed[/red]",
                )
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(
                self.query_one("#csr-status", Static).update,
                f"[red]Error: {e}[/red]",
            )
        finally:
            self.app.call_from_thread(op_status.hide)
