# opca/tui/screens/cert_list.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Static, Select

from opca.tui.screens.confirm import ConfirmModal
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.utils.datetime import format_datetime, parse_datetime


STATUS_STYLES = {
    "Valid": "[green]Valid[/green]",
    "Revoked": "[red]Revoked[/red]",
    "Expired": "[dim]Expired[/dim]",
    "Expiring": "[yellow]Expiring[/yellow]",
}

FILTER_MODES = [
    ("All", "all"),
    ("Valid", "valid"),
    ("Expiring", "expiring"),
    ("Expired", "expired"),
    ("Revoked", "revoked"),
]

LOCAL_COLUMNS = ("Serial", "CN", "Title", "Status", "Expiry", "Revoked")
EXTERNAL_COLUMNS = ("Serial", "CN", "Issuer", "Status", "Expiry", "Imported")


class CertListScreen(Screen):
    """Certificate list with DataTable, filters, and action buttons."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("c", "create", "Create"),
        ("m", "import_cert", "Import"),
        ("r", "refresh_list", "Refresh"),
        ("i", "info", "Info"),
        ("w", "renew", "Renew"),
        ("x", "revoke", "Revoke"),
        ("e", "export", "Export"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("Certificates")
            yield NavBar(
                [("Home", "home"), ("Local", "local"), ("External", "external")],
                default="local",
            )
            with Horizontal(classes="button-row"):
                yield Select(
                    FILTER_MODES,
                    value="all",
                    id="filter-select",
                    allow_blank=False,
                )
                yield Button("Create", variant="primary", id="btn-create")
                yield Button("Import", variant="primary", id="btn-import")
                yield Button("Refresh", variant="default", id="btn-refresh")
            yield DataTable(id="cert-table")
            with Horizontal(classes="button-row"):
                yield Button("Info", variant="default", id="btn-info")
                yield Button("Renew", variant="warning", id="btn-renew")
                yield Button("Revoke", variant="error", id="btn-revoke")
                yield Button("Export", variant="default", id="btn-export")
            yield OpStatus(id="op-status")
        yield Footer()

    def on_screen_resume(self) -> None:
        if not self._op_pending:
            self.action_refresh_list()

    def on_mount(self) -> None:
        self._op_pending = False
        self._active_tab = "local"
        table = self.query_one("#cert-table", DataTable)
        table.cursor_type = "row"
        table.add_columns(*LOCAL_COLUMNS)
        self._load_certs("all")

    def on_nav_bar_home(self, event: NavBar.Home) -> None:
        self.app.pop_screen()

    def on_nav_bar_selected(self, event: NavBar.Selected) -> None:
        self._active_tab = event.view_id
        is_external = event.view_id == "external"
        self.query_one("#btn-create", Button).display = not is_external
        self.query_one("#btn-renew", Button).display = not is_external
        self.query_one("#btn-revoke", Button).display = not is_external
        self._rebuild_columns()
        self.action_refresh_list()

    def _rebuild_columns(self) -> None:
        """Rebuild DataTable columns to match the active tab."""
        table = self.query_one("#cert-table", DataTable)
        table.clear(columns=True)
        cols = EXTERNAL_COLUMNS if self._active_tab == "external" else LOCAL_COLUMNS
        table.add_columns(*cols)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "filter-select":
            self._load_certs(str(event.value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create":
            self.action_create()
        elif event.button.id == "btn-import":
            self.action_import_cert()
        elif event.button.id == "btn-refresh":
            self.action_refresh_list()
        elif event.button.id == "btn-info":
            self._action_on_selected("info")
        elif event.button.id == "btn-renew":
            self._action_on_selected("renew")
        elif event.button.id == "btn-revoke":
            self._action_on_selected("revoke")
        elif event.button.id == "btn-export":
            self._action_on_selected("export")

    def action_create(self) -> None:
        from opca.tui.screens.cert_create import CertCreateScreen
        self.app.push_screen(CertCreateScreen())

    def action_import_cert(self) -> None:
        from opca.tui.screens.cert_import import CertImportScreen
        self.app.push_screen(CertImportScreen())

    def action_info(self) -> None:
        self._action_on_selected("info")

    def action_renew(self) -> None:
        self._action_on_selected("renew")

    def action_revoke(self) -> None:
        self._action_on_selected("revoke")

    def action_export(self) -> None:
        self._action_on_selected("export")

    def action_refresh_list(self) -> None:
        select = self.query_one("#filter-select", Select)
        self._load_certs(str(select.value))

    def _action_on_selected(self, action: str) -> None:
        table = self.query_one("#cert-table", DataTable)
        if table.cursor_row is None or table.row_count == 0:
            return

        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        row_data = table.get_row(row_key)
        serial = str(row_data[0])
        cn = str(row_data[1])
        title = str(row_data[2])

        if action == "info":
            from opca.tui.screens.cert_info import CertInfoScreen
            self.app.push_screen(CertInfoScreen(cn=cn, serial=serial, title=title))
        elif action == "renew":
            self.app.push_screen(
                ConfirmModal(
                    title="Renew Certificate",
                    message=f"Renew certificate '{cn}' (serial {serial})?",
                ),
                callback=lambda confirmed: self._start_renew(serial, cn) if confirmed else None,
            )
        elif action == "revoke":
            self.app.push_screen(
                ConfirmModal(
                    title="Revoke Certificate",
                    message=f"Revoke certificate '{cn}' (serial {serial})?\nThis cannot be undone.",
                ),
                callback=lambda confirmed: self._start_revoke(serial, cn) if confirmed else None,
            )
        elif action == "export":
            from opca.tui.screens.cert_export import CertExportScreen
            self.app.push_screen(CertExportScreen(cn=cn, serial=serial, title=title))

    @work(thread=True, exclusive=True, group="op")
    def _load_certs(self, mode: str) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading certificates...")
        try:
            self._load_certs_inner(mode)
        finally:
            self.app.call_from_thread(op_status.hide)

    def _load_certs_inner(self, mode: str) -> None:
        ctx = self.app.tui_context
        if not ctx.has_ca:
            self.app.call_from_thread(self._show_no_ca)
            return

        db = ctx.ca.ca_database
        db.process_ca_database()

        if self._active_tab == "external":
            self._load_external_certs(db, mode)
        else:
            self._load_local_certs(db, mode)

    def _load_local_certs(self, db, mode: str) -> None:
        if mode == "valid":
            serials = sorted(db.certs_valid, key=int)
        elif mode == "expired":
            serials = sorted(db.certs_expired, key=int)
        elif mode == "revoked":
            serials = sorted(db.certs_revoked, key=int)
        elif mode == "expiring":
            serials = sorted(db.certs_expires_soon, key=int)
        else:
            serials = sorted(
                db.certs_valid | db.certs_expired | db.certs_revoked | db.certs_expires_soon,
                key=int,
            )

        expiring_set = db.certs_expires_soon
        rows = []
        for serial in serials:
            cert = db.query_cert(cert_info={"serial": serial})
            if not cert:
                continue

            status = cert["status"]
            if status == "Valid" and cert["serial"] in expiring_set:
                status = "Expiring"

            expiry = format_datetime(parse_datetime(cert["expiry_date"]), output_format="compact") if cert.get("expiry_date") else "-"
            revocation = format_datetime(parse_datetime(cert["revocation_date"]), output_format="compact") if cert.get("revocation_date") else "-"
            rows.append((
                cert["serial"],
                cert["cn"],
                cert["title"],
                status,
                expiry,
                revocation,
            ))

        self.app.call_from_thread(self._update_table, rows)

    def _load_external_certs(self, db, mode: str) -> None:
        if mode == "valid":
            serials = sorted(db.ext_certs_valid)
        elif mode == "expired":
            serials = sorted(db.ext_certs_expired)
        elif mode == "expiring":
            serials = sorted(db.ext_certs_expires_soon)
        elif mode == "revoked":
            # External certs have no revocation
            serials = []
        else:
            serials = sorted(
                db.ext_certs_valid | db.ext_certs_expired | db.ext_certs_expires_soon,
            )

        expiring_set = db.ext_certs_expires_soon
        rows = []
        for serial in serials:
            cert = db.query_external_cert(cert_info={"serial": serial})
            if not cert:
                continue

            status = cert["status"]
            if status == "Valid" and cert["serial"] in expiring_set:
                status = "Expiring"

            expiry = format_datetime(parse_datetime(cert["expiry_date"]), output_format="compact") if cert.get("expiry_date") else "-"
            imported = format_datetime(parse_datetime(cert["import_date"]), output_format="compact") if cert.get("import_date") else "-"
            rows.append((
                cert["serial"],
                cert["cn"],
                cert.get("issuer", "-"),
                status,
                expiry,
                imported,
            ))

        self.app.call_from_thread(self._update_table, rows)

    def _update_table(self, rows: list) -> None:
        table = self.query_one("#cert-table", DataTable)
        prev_row = table.cursor_row if table.row_count > 0 else 0
        table.clear()
        for row in rows:
            styled_row = list(row)
            styled_row[3] = STATUS_STYLES.get(str(row[3]), str(row[3]))
            table.add_row(*[str(v) for v in styled_row])
        if rows and prev_row is not None:
            table.move_cursor(row=min(prev_row, len(rows) - 1))

    def _show_no_ca(self) -> None:
        table = self.query_one("#cert-table", DataTable)
        table.clear()

    def _start_renew(self, serial: str, cn: str) -> None:
        """Set the pending flag and launch the renew worker."""
        self._op_pending = True
        self._do_renew(serial, cn)

    def _start_revoke(self, serial: str, cn: str) -> None:
        """Set the pending flag and launch the revoke worker."""
        self._op_pending = True
        self._do_revoke(serial, cn)

    @work(thread=True, exclusive=True, group="op")
    def _do_renew(self, serial: str, cn: str) -> None:
        self.app.call_from_thread(self.query_one("#op-status", OpStatus).show, f"Renewing {cn}...")
        ok = False
        try:
            ctx = self.app.tui_context
            ok = bool(ctx.ca.renew_certificate_bundle(cert_info={"serial": serial}))
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._notify_error, "Renew", str(e))
        finally:
            self.app.call_from_thread(self.query_one("#op-status", OpStatus).hide)
            self._op_pending = False
        if ok:
            self.app.call_from_thread(
                self.notify, f"Renew succeeded: {cn}", severity="information"
            )
        else:
            self.app.call_from_thread(
                self.notify, f"Renew failed: {cn}", severity="error"
            )
        select = self.query_one("#filter-select", Select)
        self._load_certs_inner(str(select.value))

    @work(thread=True, exclusive=True, group="op")
    def _do_revoke(self, serial: str, cn: str) -> None:
        self.app.call_from_thread(self.query_one("#op-status", OpStatus).show, f"Revoking {cn}...")
        ok = False
        try:
            ctx = self.app.tui_context
            ok = bool(ctx.ca.revoke_certificate(cert_info={"serial": serial}))
            if ok:
                ctx.ca.generate_crl()
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._notify_error, "Revoke", str(e))
        finally:
            self.app.call_from_thread(self.query_one("#op-status", OpStatus).hide)
            self._op_pending = False
        if ok:
            self.app.call_from_thread(
                self.notify, f"Revoke succeeded: {cn}", severity="information"
            )
        else:
            self.app.call_from_thread(
                self.notify, f"Revoke failed: {cn}", severity="error"
            )
        select = self.query_one("#filter-select", Select)
        self._load_certs_inner(str(select.value))

    def _notify_error(self, action: str, msg: str) -> None:
        self.notify(f"{action} error: {msg}", severity="error")
