# opca/tui/screens/dkim.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Checkbox, DataTable, Footer, Input, Static

from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import capture_handler


class DKIMScreen(Screen):
    """DKIM key management: create, deploy, info, list, verify."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    VIEWS = ["keys", "create"]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("DKIM Key Management")

            yield NavBar(
                [
                    ("Home", "home"),
                    ("Keys", "keys"),
                    ("Create", "create"),
                ],
                default="keys",
            )

            with VerticalScroll(id="view-keys"):
                yield DataTable(id="dkim-table")
                with Horizontal(classes="button-row"):
                    yield Button("Refresh", variant="default", id="btn-refresh")
                    yield Button("Info", variant="default", id="btn-info")
                    yield Button("Deploy", variant="primary", id="btn-deploy")
                    yield Button("Verify", variant="default", id="btn-verify")

            with VerticalScroll(id="view-create"):
                yield Static("Domain:", classes="form-label")
                yield Input(placeholder="e.g. example.com", id="domain-input")
                yield Static("Selector:", classes="form-label")
                yield Input(placeholder="e.g. mail", id="selector-input")
                yield Checkbox("Deploy to Route53", id="deploy-r53-check")
                yield Static("", id="dkim-status")
                with Horizontal(classes="button-row"):
                    yield Button("Create", variant="primary", id="btn-create")

            yield OpStatus(id="op-status")
            yield LogPanel(id="dkim-log")
        yield Footer()

    def on_screen_resume(self) -> None:
        self._load_list()

    def on_mount(self) -> None:
        table = self.query_one("#dkim-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Domain", "Selector", "Created")
        self._switch_view("keys")

    def _switch_view(self, view: str) -> None:
        for v in self.VIEWS:
            self.query_one(f"#view-{v}").display = v == view
        if view == "keys":
            self._load_list()

    def on_nav_bar_home(self, event: NavBar.Home) -> None:
        self.app.pop_screen()

    def on_nav_bar_selected(self, event: NavBar.Selected) -> None:
        self._switch_view(event.view_id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh":
            self._load_list()
        elif event.button.id == "btn-create":
            self._do_create()
        elif event.button.id == "btn-info":
            self._do_info()
        elif event.button.id == "btn-deploy":
            self._do_deploy()
        elif event.button.id == "btn-verify":
            self._do_verify()

    def _get_selected_row(self) -> tuple[str, str] | None:
        """Get domain and selector from the selected table row."""
        table = self.query_one("#dkim-table", DataTable)
        if table.row_count == 0:
            log = self.query_one("#dkim-log", LogPanel)
            log.log_warning("No DKIM keys loaded")
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            row = table.get_row(row_key)
            domain, selector = row[0], row[1]
            return str(domain), str(selector)
        except Exception:
            log = self.query_one("#dkim-log", LogPanel)
            log.log_warning("Select a DKIM key from the table first")
            return None

    @work(thread=True, exclusive=True, group="op")
    def _load_list(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading DKIM keys...")
        try:
            from opca.commands.dkim.actions import handle_dkim_list
            ctx = self.app.tui_context
            app = ctx.make_app(command="dkim", subcommand="list")
            code, output = capture_handler(handle_dkim_list, app)
            log = self.query_one("#dkim-log", LogPanel)
            if output.strip():
                self.app.call_from_thread(log.write, output)
        except (Exception, SystemExit) as e:
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_create(self) -> None:
        domain = self.query_one("#domain-input", Input).value.strip()
        selector = self.query_one("#selector-input", Input).value.strip()
        deploy_r53 = self.query_one("#deploy-r53-check", Checkbox).value

        if not domain or not selector:
            self.app.call_from_thread(
                self.query_one("#dkim-status", Static).update,
                "[red]Domain and selector are required[/red]",
            )
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Creating DKIM key for {selector}._domainkey.{domain}...")

        try:
            from opca.commands.dkim.actions import handle_dkim_create
            ctx = self.app.tui_context
            app = ctx.make_app(
                command="dkim", subcommand="create",
                domain=domain, selector=selector,
                key_size=2048, deploy_route53=deploy_r53,
            )
            code, output = capture_handler(handle_dkim_create, app)
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
            if code == 0:
                self.app.call_from_thread(
                    self.query_one("#dkim-status", Static).update,
                    "[green]DKIM key created[/green]",
                )
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(
                self.query_one("#dkim-status", Static).update,
                f"[red]Error: {e}[/red]",
            )
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_info(self) -> None:
        selected = self._get_selected_row()
        if not selected:
            return
        domain, selector = selected
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading DKIM info...")
        try:
            from opca.commands.dkim.actions import handle_dkim_info
            ctx = self.app.tui_context
            app = ctx.make_app(command="dkim", subcommand="info", domain=domain, selector=selector)
            code, output = capture_handler(handle_dkim_info, app)
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
        except (Exception, SystemExit) as e:
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_deploy(self) -> None:
        selected = self._get_selected_row()
        if not selected:
            return
        domain, selector = selected
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Deploying DKIM key...")
        try:
            from opca.commands.dkim.actions import handle_dkim_deploy
            ctx = self.app.tui_context
            app = ctx.make_app(command="dkim", subcommand="deploy", domain=domain, selector=selector)
            code, output = capture_handler(handle_dkim_deploy, app)
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
        except (Exception, SystemExit) as e:
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_verify(self) -> None:
        selected = self._get_selected_row()
        if not selected:
            return
        domain, selector = selected
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Verifying DKIM key...")
        try:
            from opca.commands.dkim.actions import handle_dkim_verify
            ctx = self.app.tui_context
            app = ctx.make_app(command="dkim", subcommand="verify", domain=domain, selector=selector)
            code, output = capture_handler(handle_dkim_verify, app)
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
        except (Exception, SystemExit) as e:
            log = self.query_one("#dkim-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)
