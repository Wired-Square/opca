# opca/tui/screens/openvpn.py

from __future__ import annotations

import json

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Input, Select, Static, TextArea

from opca.tui.mixins import TabbedViewMixin
from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.vault_picker import VaultPicker
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import capture_handler


class NewTemplateModal(Screen):
    """Modal to prompt for a new template name."""

    BINDINGS = [("escape", "app.pop_screen", "Cancel")]

    def __init__(self, existing: list[str]) -> None:
        super().__init__()
        self._existing = existing

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static("New template name", id="confirm-title")
            yield Input(placeholder="e.g. sample", id="new-template-name")
            yield Static("", id="new-template-error")
            with Horizontal(classes="button-row"):
                yield Button("Create", variant="primary", id="btn-create-template")
                yield Button("Cancel", variant="default", id="btn-cancel-template")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-template":
            self.dismiss(None)
        elif event.button.id == "btn-create-template":
            self._try_create()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._try_create()

    def _try_create(self) -> None:
        name = self.query_one("#new-template-name", Input).value.strip()
        error = self.query_one("#new-template-error", Static)
        if not name:
            error.update("[red]Name is required[/red]")
            return
        if name in self._existing:
            error.update(f"[red]Template '{name}' already exists[/red]")
            return
        self.dismiss(name)


class OpenVPNScreen(TabbedViewMixin, Screen):
    """OpenVPN artifact management: generate, get, import."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    VIEWS = ["client", "server", "profiles"]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("OpenVPN")

            yield NavBar(
                [("Home", "home"), ("Client", "client"), ("Server", "server"), ("Profiles", "profiles")],
                default="client",
            )

            with Vertical(id="view-client", classes="openvpn-view"):
                yield Static("Template:", classes="form-label")
                yield Select(
                    [], id="client-template-select",
                    allow_blank=True, prompt="Select template",
                )
                yield Static("Client CN:", classes="form-label")
                yield Select(
                    [], id="client-cn-select",
                    allow_blank=True, prompt="Select VPN client",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Generate Profile", variant="primary", id="btn-gen-profile")

            with Vertical(id="view-server", classes="openvpn-view"):
                with Horizontal(classes="form-row"):
                    with Vertical():
                        yield Static("Template name:", classes="form-label")
                        yield Select(
                            [], id="server-template-select",
                            allow_blank=True, prompt="Select template",
                        )
                    yield Button("New", id="btn-new-template")
                yield Static("Template:", classes="form-label")
                yield TextArea(id="server-template-editor")
                with Horizontal(classes="button-row"):
                    yield Button("Generate Template", variant="primary", id="btn-gen-server")
                    yield Button("Save Template", variant="default", id="btn-save-template")
                    yield Button("Generate DH", variant="default", id="btn-gen-dh", disabled=True)
                    yield Button("Generate TA Key", variant="default", id="btn-gen-ta", disabled=True)

            with Vertical(id="view-profiles", classes="openvpn-view"):
                yield DataTable(id="profile-table")
                with Horizontal(classes="form-row"):
                    with Vertical():
                        yield Static("Destination vault:", classes="form-label")
                        yield Input(placeholder="e.g. client-vault", id="dest-vault-input")
                    yield Button("Browse", id="btn-browse-vault")
                with Horizontal(classes="button-row"):
                    yield Button("Refresh", variant="default", id="btn-refresh-profiles")
                    yield Button("Send to Vault", variant="primary", id="btn-send-profile")

            yield OpStatus(id="op-status")
            yield LogPanel(id="openvpn-log")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#profile-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("CN", "Created")
        self._switch_view("client")

    def _switch_view(self, view: str) -> None:
        for v in self.VIEWS:
            self.query_one(f"#view-{v}").display = v == view
        if view == "server":
            self._load_template_list()
        elif view == "client":
            self._load_client_data()
        elif view == "profiles":
            self._load_profiles()

    @property
    def _selected_template(self) -> str:
        """Return the currently selected template name, or empty string."""
        select = self.query_one("#server-template-select", Select)
        if select.value is Select.BLANK or select.value is Select.NULL:
            return ""
        return str(select.value)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "server-template-select":
            return
        if event.value is Select.BLANK or event.value is Select.NULL:
            self._set_editor_content("")
            return
        self._load_template_content(str(event.value))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        handlers = {
            "btn-gen-dh": self._gen_dh,
            "btn-gen-ta": self._gen_ta,
            "btn-gen-profile": self._gen_profile,
            "btn-gen-server": self._gen_server,
            "btn-save-template": self._save_template,
            "btn-new-template": self._new_template,
            "btn-browse-vault": self._browse_vault,
            "btn-refresh-profiles": self._load_profiles,
            "btn-send-profile": self._send_to_vault,
        }
        handler = handlers.get(event.button.id)
        if handler:
            handler()

    # -----------------------------------------
    # New template modal
    # -----------------------------------------
    def _new_template(self) -> None:
        """Prompt for a new template name and create it."""
        select = self.query_one("#server-template-select", Select)
        existing = [str(label) for label, _ in select._options] if select._options else []
        self.app.push_screen(NewTemplateModal(existing), callback=self._on_new_template)

    def _on_new_template(self, name: str | None) -> None:
        if not name:
            return
        self._create_and_edit_template(name)

    @work(thread=True, exclusive=True, group="op")
    def _create_and_edit_template(self, name: str) -> None:
        """Create a new template via handle_server_setup and load it for editing."""
        self._run_handler(
            "openvpn.actions", "handle_server_setup",
            subcommand="generate",
            template=name, setup=True,
        )
        self._post_gen_load(name)

    # -----------------------------------------
    # Server tab operations
    # -----------------------------------------
    @work(thread=True, exclusive=True, group="op")
    def _load_template_list(self) -> None:
        """Fetch the OpenVPN item, populate the template Select, and update button state."""
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading templates...")
        try:
            loaded = self._fetch_openvpn_item()
            templates = self._extract_template_names(loaded)
            options = [(name, name) for name in templates]
            self.app.call_from_thread(self._update_template_select, options)

            labels = self._extract_field_labels(loaded)
            has_dh = 'dh_parameters' in labels
            has_ta = 'static_key' in labels
            self.app.call_from_thread(self._update_gen_buttons, has_dh, has_ta)
        except (Exception, SystemExit) as e:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _update_template_select(self, options: list[tuple[str, str]]) -> None:
        select = self.query_one("#server-template-select", Select)
        select.set_options(options)

    def _select_template(self, name: str) -> None:
        """Programmatically select a template in the dropdown."""
        select = self.query_one("#server-template-select", Select)
        select.value = name

    def _update_gen_buttons(self, has_dh: bool, has_ta: bool) -> None:
        self.query_one("#btn-gen-dh", Button).disabled = has_dh
        self.query_one("#btn-gen-ta", Button).disabled = has_ta

    def _fetch_openvpn_item(self) -> dict:
        """Read the OpenVPN 1Password item and return the parsed JSON (or empty dict)."""
        from opca.constants import DEFAULT_OP_CONF
        ctx = self.app.tui_context
        if not ctx.op.item_exists(DEFAULT_OP_CONF["openvpn_title"]):
            return {}
        result = ctx.op.get_item(DEFAULT_OP_CONF["openvpn_title"])
        return json.loads(result.stdout)

    def _extract_template_names(self, loaded: dict) -> list[str]:
        """Extract template field names from a parsed OpenVPN item."""
        templates = []
        for field in loaded.get('fields', []):
            label = field.get('label', '')
            section = field.get('section', {})
            section_label = section.get('label', '') if isinstance(section, dict) else ''
            if section_label == 'template' and label:
                templates.append(label)
        return templates

    def _extract_field_labels(self, loaded: dict) -> set[str]:
        """Extract all field labels from a parsed OpenVPN item."""
        return {field.get('label', '') for field in loaded.get('fields', []) if field.get('label')}

    @work(thread=True, exclusive=True, group="op")
    def _load_template_content(self, template_name: str) -> None:
        """Fetch a specific template's content and populate the editor."""
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Loading template '{template_name}'...")
        try:
            from opca.constants import DEFAULT_OP_CONF
            ctx = self.app.tui_context
            url = ctx.op.mk_url(
                item_title=DEFAULT_OP_CONF["openvpn_title"],
                value_key=f"template/{template_name}",
            )
            result = ctx.op.read_item(url)
            if result.returncode == 0:
                self.app.call_from_thread(self._set_editor_content, result.stdout)
            else:
                log_panel = self.query_one("#openvpn-log", LogPanel)
                self.app.call_from_thread(log_panel.log_error, f"Template '{template_name}' not found")
        except (Exception, SystemExit) as e:
            log_panel = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log_panel.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _set_editor_content(self, content: str) -> None:
        editor = self.query_one("#server-template-editor", TextArea)
        editor.clear()
        editor.insert(content)

    @work(thread=True, exclusive=True, group="op")
    def _gen_server(self) -> None:
        template = self._selected_template
        if not template:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, "Select a template first, or create one with 'New'")
            return
        self._run_handler(
            "openvpn.actions", "handle_server_setup",
            subcommand="generate",
            template=template, setup=True,
        )
        self._post_gen_load(template)

    def _post_gen_load(self, template_name: str) -> None:
        """Load template list, content, and button state after generation."""
        try:
            loaded = self._fetch_openvpn_item()
            templates = self._extract_template_names(loaded)
            options = [(name, name) for name in templates]
            self.app.call_from_thread(self._update_template_select, options)
            self.app.call_from_thread(self._select_template, template_name)

            labels = self._extract_field_labels(loaded)
            has_dh = 'dh_parameters' in labels
            has_ta = 'static_key' in labels
            self.app.call_from_thread(self._update_gen_buttons, has_dh, has_ta)

            from opca.constants import DEFAULT_OP_CONF
            ctx = self.app.tui_context
            url = ctx.op.mk_url(
                item_title=DEFAULT_OP_CONF["openvpn_title"],
                value_key=f"template/{template_name}",
            )
            result = ctx.op.read_item(url)
            if result.returncode == 0:
                self.app.call_from_thread(self._set_editor_content, result.stdout)
        except (Exception, SystemExit):
            pass  # Best effort — generation output already shown in log

    @work(thread=True, exclusive=True, group="op")
    def _save_template(self) -> None:
        template = self._selected_template
        editor = self.query_one("#server-template-editor", TextArea)
        content = editor.text.strip()
        if not template:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, "Select a template first")
            return
        if not content:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, "Template content is empty")
            return
        self._run_handler(
            "openvpn.actions", "handle_template_save",
            subcommand="generate",
            template=template, template_content=content,
        )

    # -----------------------------------------
    # Client tab operations
    # -----------------------------------------
    @work(thread=True, exclusive=True, group="op")
    def _load_client_data(self) -> None:
        """Populate the Client tab dropdowns: templates and VPN client certs."""
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading client data...")
        try:
            # Load templates
            loaded = self._fetch_openvpn_item()
            templates = self._extract_template_names(loaded)
            options = [(name, name) for name in templates]
            self.app.call_from_thread(self._update_client_templates, options)

            # Load VPN client certificates
            ctx = self.app.tui_context
            if ctx.has_ca:
                db = ctx.ca.ca_database
                db.process_ca_database()
                vpn_clients = []
                for serial in sorted(db.certs_valid, key=int):
                    cert = db.query_cert(cert_info={"serial": int(serial)})
                    if not cert:
                        continue
                    title = cert.get("title", cert.get("cn", ""))
                    try:
                        bundle = ctx.ca.retrieve_certbundle(title)
                        if bundle.get_type() == "vpnclient":
                            cn = cert.get("cn", title)
                            vpn_clients.append((cn, cn))
                    except (Exception, SystemExit):
                        continue
                self.app.call_from_thread(self._update_client_cn, vpn_clients)
        except (Exception, SystemExit) as e:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _update_client_templates(self, options: list[tuple[str, str]]) -> None:
        select = self.query_one("#client-template-select", Select)
        select.set_options(options)

    def _update_client_cn(self, options: list[tuple[str, str]]) -> None:
        select = self.query_one("#client-cn-select", Select)
        select.set_options(options)

    @work(thread=True, exclusive=True, group="op")
    def _gen_profile(self) -> None:
        template_select = self.query_one("#client-template-select", Select)
        cn_select = self.query_one("#client-cn-select", Select)
        if template_select.value is Select.BLANK or template_select.value is Select.NULL:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, "Select a template")
            return
        if cn_select.value is Select.BLANK or cn_select.value is Select.NULL:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, "Select a VPN client")
            return
        template = str(template_select.value)
        cn = str(cn_select.value)
        self._run_handler(
            "openvpn.actions", "handle_profile_gen",
            subcommand="generate",
            template=template, cn=cn, profile=True,
            dest=None, file=None,
        )

    # -----------------------------------------
    # Vault picker
    # -----------------------------------------
    def _browse_vault(self) -> None:
        """Open the vault picker modal."""
        self.app.push_screen(
            VaultPicker(self.app.tui_context),
            callback=self._on_vault_selected,
        )

    def _on_vault_selected(self, vault: str | None) -> None:
        """Populate the destination vault input from the picker."""
        if vault:
            self.query_one("#dest-vault-input", Input).value = vault

    # -----------------------------------------
    # Profiles tab operations
    # -----------------------------------------
    @work(thread=True, exclusive=True, group="op")
    def _load_profiles(self) -> None:
        """List VPN_ documents from 1Password (single API call)."""
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading profiles...")
        try:
            ctx = self.app.tui_context
            result = ctx.op.item_list(categories="Document")
            items = json.loads(result.stdout)
            rows = []
            for item in items:
                title = item.get("title", "")
                if not title.startswith("VPN_"):
                    continue
                cn = title[4:]  # strip VPN_ prefix
                created = item.get("created_at", "")[:10]
                rows.append((cn, created))
            rows.sort(key=lambda r: r[0])
            self.app.call_from_thread(self._update_profile_table, rows)
        except (Exception, SystemExit) as e:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _update_profile_table(self, rows: list[tuple[str, str]]) -> None:
        table = self.query_one("#profile-table", DataTable)
        table.clear()
        for row in rows:
            table.add_row(*row)

    def _get_selected_profile(self) -> str | None:
        """Return the CN of the selected profile row, or None."""
        table = self.query_one("#profile-table", DataTable)
        if table.row_count == 0:
            log = self.query_one("#openvpn-log", LogPanel)
            log.log_warning("No profiles loaded")
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            row = table.get_row(row_key)
            return str(row[0])
        except Exception:
            log = self.query_one("#openvpn-log", LogPanel)
            log.log_warning("Select a profile from the table first")
            return None

    @work(thread=True, exclusive=True, group="op")
    def _send_to_vault(self) -> None:
        """Send the selected profile document to another vault."""
        cn = self._get_selected_profile()
        if not cn:
            return
        dest_vault = self.query_one("#dest-vault-input", Input).value.strip()
        if not dest_vault:
            log = self.query_one("#openvpn-log", LogPanel)
            self.app.call_from_thread(log.log_error, "Enter a destination vault")
            return

        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Sending VPN_{cn} to {dest_vault}...")
        log = self.query_one("#openvpn-log", LogPanel)
        try:
            ctx = self.app.tui_context
            item_title = f"VPN_{cn}"
            result = ctx.op.get_document(item_title)
            content = result.stdout
            ctx.op.store_document(
                item_title=item_title,
                filename=f"{cn}.ovpn",
                str_in=content,
                vault=dest_vault,
            )
            self.app.call_from_thread(log.log_success, f"Sent {item_title} to vault '{dest_vault}'")
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    # -----------------------------------------
    # Server tab: DH / TA generation
    # -----------------------------------------
    @work(thread=True, exclusive=True, group="op")
    def _gen_dh(self) -> None:
        self._run_handler("openvpn.actions", "handle_dh_gen", subcommand="generate")
        self._refresh_gen_buttons()

    @work(thread=True, exclusive=True, group="op")
    def _gen_ta(self) -> None:
        self._run_handler("openvpn.actions", "handle_ta_key_gen", subcommand="generate")
        self._refresh_gen_buttons()

    def _refresh_gen_buttons(self) -> None:
        """Re-check DH/TA existence and update button disabled state."""
        try:
            loaded = self._fetch_openvpn_item()
            labels = self._extract_field_labels(loaded)
            has_dh = 'dh_parameters' in labels
            has_ta = 'static_key' in labels
            self.app.call_from_thread(self._update_gen_buttons, has_dh, has_ta)
        except (Exception, SystemExit):
            pass

    # -----------------------------------------
    # Common handler runner
    # -----------------------------------------
    def _run_handler(self, module_path: str, handler_name: str, subcommand: str = "", **extra_args: object) -> None:
        import importlib
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Running {handler_name}...")
        log = self.query_one("#openvpn-log", LogPanel)
        try:
            mod = importlib.import_module(f"opca.commands.{module_path}")
            handler = getattr(mod, handler_name)
            ctx = self.app.tui_context
            app = ctx.make_app(command="openvpn", subcommand=subcommand, **extra_args)
            code, output = capture_handler(handler, app)
            self.app.call_from_thread(log.write, output or f"Exit code: {code}")
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)
