# opca/tui/screens/database.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Static

from opca.tui.screens.confirm import ConfirmModal
from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import capture_handler


class DatabaseScreen(Screen):
    """CA database management: config, export, rebuild, upload."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    VIEWS = ["info", "config", "upload", "maintenance"]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("CA Database")

            yield NavBar(
                [("Home", "home"), ("Info", "info"), ("Config", "config"), ("Upload", "upload"), ("Maintenance", "maintenance")],
                default="info",
            )

            with Vertical(id="view-info"):
                yield Static("", id="db-config")
                with Horizontal(classes="button-row"):
                    yield Button("Refresh", variant="default", id="btn-refresh")

            with Vertical(id="view-config"):
                yield Static("Key:", classes="form-label")
                yield Input(placeholder="e.g. days, crl_days, ca_url", id="config-key")
                yield Static("Value:", classes="form-label")
                yield Input(placeholder="e.g. 398", id="config-value")
                with Horizontal(classes="button-row"):
                    yield Button("Set", variant="primary", id="btn-config-set")

            with Vertical(id="view-upload"):
                with Horizontal(classes="button-row"):
                    yield Button("Export SQL", variant="default", id="btn-export")
                    yield Button("Upload", variant="primary", id="btn-upload")

            with Vertical(id="view-maintenance"):

                yield Static("[bold]Rebuild Database[/bold]")
                yield Static("Starting serial (optional):", classes="form-label")
                yield Input(placeholder="1", id="rebuild-serial")
                yield Static("Starting CRL serial (optional):", classes="form-label")
                yield Input(placeholder="1", id="rebuild-crl-serial")
                with Horizontal(classes="button-row"):
                    yield Button("Rebuild", variant="error", id="btn-rebuild")

            yield OpStatus(id="op-status")
            yield LogPanel(id="db-log")
        yield Footer()

    def on_mount(self) -> None:
        self._switch_view("info")
        self._load_config()

    def _switch_view(self, view: str) -> None:
        for v in self.VIEWS:
            self.query_one(f"#view-{v}").display = v == view

    def on_nav_bar_selected(self, event: NavBar.Selected) -> None:
        self._switch_view(event.view_id)
        if event.view_id == "info":
            self._load_config()

    def on_nav_bar_home(self, event: NavBar.Home) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh":
            self._load_config()
        elif event.button.id == "btn-config-set":
            self._do_config_set()
        elif event.button.id == "btn-export":
            self._do_export()
        elif event.button.id == "btn-upload":
            self._do_upload()
        elif event.button.id == "btn-rebuild":
            self.app.push_screen(
                ConfirmModal(
                    title="Rebuild Database",
                    message="Rebuild the entire CA database?\nThis cannot be undone.",
                ),
                callback=lambda confirmed: self._do_rebuild() if confirmed else None,
            )

    @work(thread=True, exclusive=True, group="op")
    def _load_config(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading config...")
        ctx = self.app.tui_context
        if not ctx.has_ca:
            self.app.call_from_thread(
                self.query_one("#db-config", Static).update,
                "[yellow]No CA found[/yellow]",
            )
            self.app.call_from_thread(op_status.hide)
            return

        try:
            config = ctx.ca.ca_database.get_config_attributes()
            lines = []
            for key, value in sorted(config.items()):
                lines.append(f"[bold]{key}:[/bold] {value}")
            self.app.call_from_thread(
                self.query_one("#db-config", Static).update,
                "\n".join(lines),
            )
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(
                self.query_one("#db-config", Static).update,
                f"[red]Error: {e}[/red]",
            )
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_config_set(self) -> None:
        key = self.query_one("#config-key", Input).value.strip()
        value = self.query_one("#config-value", Input).value.strip()
        log = self.query_one("#db-log", LogPanel)

        if not key or not value:
            self.app.call_from_thread(log.log_error, "Key and value are required")
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Setting {key}...")
        ctx = self.app.tui_context
        try:
            ctx.ca.ca_database.update_config({key: value})
            ctx.ca.store_ca_database()
            self.app.call_from_thread(log.log_success, f"Set {key} = {value}")
            self.app.call_from_thread(self._load_config)
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_export(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Exporting database...")
        ctx = self.app.tui_context
        log = self.query_one("#db-log", LogPanel)
        try:
            sql = ctx.ca.ca_database.export_database()
            self.app.call_from_thread(log.write, sql.decode("utf-8", errors="replace"))
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_upload(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Uploading database...")
        ctx = self.app.tui_context
        log = self.query_one("#db-log", LogPanel)
        try:
            ok = ctx.ca.upload_ca_database()
            if ok:
                self.app.call_from_thread(log.log_success, "Database uploaded")
            else:
                self.app.call_from_thread(log.log_error, "Upload failed")
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_rebuild(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Rebuilding database...")
        serial_str = self.query_one("#rebuild-serial", Input).value.strip()
        crl_serial_str = self.query_one("#rebuild-crl-serial", Input).value.strip()
        log = self.query_one("#db-log", LogPanel)

        ctx = self.app.tui_context
        try:
            from opca.commands.database.actions import handle_database_rebuild
            app = ctx.make_app(
                command="database", subcommand="rebuild",
                serial=int(serial_str) if serial_str else None,
                crl_serial=int(crl_serial_str) if crl_serial_str else None,
                days=None,
                crl_days=None,
            )
            code, output = capture_handler(handle_database_rebuild, app)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
            if code == 0:
                ctx.reload_ca()
                self.app.call_from_thread(log.log_success, "Database rebuilt")
                self.app.call_from_thread(self._load_config)
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)
