# opca/tui/screens/ca.py

from __future__ import annotations

import subprocess
import sys

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Static

from opca.constants import DEFAULT_KEY_SIZE, DEFAULT_OP_CONF
from opca.tui.mixins import TabbedViewMixin
from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import op_status_context


class CAScreen(TabbedViewMixin, Screen):
    """CA management: view info, init, import, export, upload."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    VIEWS = ["cert", "config", "stores", "init"]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("Certificate Authority")

            yield NavBar(
                [
                    ("Home", "home"),
                    ("Certificate", "cert"),
                    ("Config", "config"),
                    ("Stores", "stores"),
                    ("Init", "init"),
                ],
                default="cert",
            )

            with VerticalScroll(id="view-cert"):
                yield Static("Export file:", classes="form-label")
                with Horizontal(classes="form-row"):
                    yield Input(
                        placeholder="Leave blank for output window",
                        id="export-path",
                    )
                    yield Button("Browse", variant="default", id="btn-browse-export")
                with Horizontal(classes="button-row"):
                    yield Button("Export", variant="primary", id="btn-export")
                    yield Button("Copy", variant="default", id="btn-copy")
                    yield Button("Upload", variant="default", id="btn-upload")
                    yield Button("Refresh", variant="default", id="btn-refresh")

            with VerticalScroll(id="view-config"):
                yield Static("CA URL:", classes="form-label")
                yield Input(placeholder="e.g. https://example.com/ca.pem", id="cfg-ca-url")
                yield Static("Cert validity (days):", classes="form-label")
                yield Input(placeholder="e.g. 398", id="cfg-days")
                yield Static("CRL validity (days):", classes="form-label")
                yield Input(placeholder="e.g. 47", id="cfg-crl-days")
                yield Static("CRL URL:", classes="form-label")
                yield Input(placeholder="e.g. https://example.com/ca.crl", id="cfg-crl-url")
                with Horizontal(classes="button-row"):
                    yield Button("Save", variant="primary", id="btn-save-config")
                    yield Button("Refresh", variant="default", id="btn-refresh-config")

            with VerticalScroll(id="view-stores"):
                yield Static("Public store:", classes="form-label")
                yield Input(placeholder="e.g. s3://bucket/public/", id="cfg-ca-public-store")
                yield Static("Private store:", classes="form-label")
                yield Input(placeholder="e.g. s3://bucket/private/", id="cfg-ca-private-store")
                yield Static("Backup store:", classes="form-label")
                yield Input(placeholder="e.g. rsync://host/backup/", id="cfg-ca-backup-store")
                with Horizontal(classes="button-row"):
                    yield Button("Save", variant="primary", id="btn-save-stores")
                    yield Button("Refresh", variant="default", id="btn-refresh-stores")

            with VerticalScroll(id="view-init"):
                yield Static("[bold]Initialise New CA[/bold]")
                yield Static("Organisation:", classes="form-label")
                yield Input(placeholder="e.g. My Organisation", id="org-input")
                yield Static("Common Name:", classes="form-label")
                yield Input(placeholder="e.g. My Org CA", id="cn-input")
                with Horizontal(classes="form-row"):
                    with Vertical():
                        yield Static("CA validity (days):", classes="form-label")
                        yield Input(placeholder="3650", value="3650", id="ca-days-input")
                    with Vertical():
                        yield Static("Cert validity (days):", classes="form-label")
                        yield Input(placeholder="398", value="398", id="days-input")
                    with Vertical():
                        yield Static("CRL validity (days):", classes="form-label")
                        yield Input(placeholder="47", value="47", id="crl-days-input")
                yield Static("", id="init-status")
                with Horizontal(classes="button-row"):
                    yield Button("Create CA", variant="primary", id="btn-do-init")

            yield OpStatus(id="op-status")
            yield LogPanel(id="ca-log")
        yield Footer()

    def on_mount(self) -> None:
        self._switch_view("cert")

    def _switch_view(self, view: str) -> None:
        for v in self.VIEWS:
            self.query_one(f"#view-{v}").display = v == view
        if view == "cert":
            self._load_ca_info()
        elif view == "config":
            self._load_config()
        elif view == "stores":
            self._load_stores()
        elif view == "init":
            self._update_button_states()

    def _update_button_states(self) -> None:
        """Enable/disable buttons based on whether a CA exists."""
        has_ca = self.app.tui_context.has_ca
        self.query_one("#btn-do-init", Button).disabled = has_ca
        self.query_one("#nav-init", Button).disabled = has_ca

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-do-init":
            self._do_init()
        elif event.button.id == "btn-export":
            self._do_export()
        elif event.button.id == "btn-copy":
            self._do_copy_cert()
        elif event.button.id == "btn-upload":
            self._do_upload()
        elif event.button.id == "btn-refresh":
            self._load_ca_info()
        elif event.button.id == "btn-save-config":
            self._save_config()
        elif event.button.id == "btn-refresh-config":
            self._load_config()
        elif event.button.id == "btn-save-stores":
            self._save_stores()
        elif event.button.id == "btn-refresh-stores":
            self._load_stores()
        elif event.button.id == "btn-browse-export":
            self._browse_export()

    @work(thread=True, exclusive=True, group="op")
    def _load_ca_info(self) -> None:
        log = self.query_one("#ca-log", LogPanel)
        self.app.call_from_thread(log.clear)
        with op_status_context(self, "Loading CA info..."):
            try:
                ctx = self.app.tui_context
                if not ctx.has_ca:
                    self.app.call_from_thread(
                        log.log_warning,
                        "No CA found in this vault. Use the 'Init' tab to create one.",
                    )
                    return

                ca = ctx.ca
                config = ca.ca_database.get_config_attributes()

                subject = ca.ca_certbundle.get_certificate_attrib("subject")
                not_after = ca.ca_certbundle.get_certificate_attrib("not_after")
                not_before = ca.ca_certbundle.get_certificate_attrib("not_before")
                key_size = ca.ca_certbundle.get_public_key_size()
                key_type = ca.ca_certbundle.get_public_key_type()

                db = ca.ca_database
                db.process_ca_database()

                info = (
                    f"[bold]Subject:[/bold]       {subject}\n"
                    f"[bold]Key:[/bold]           {key_type} {key_size}-bit\n"
                    f"[bold]Valid From:[/bold]    {not_before}\n"
                    f"[bold]Valid Until:[/bold]   {not_after}\n"
                    f"[bold]Next Serial:[/bold]   {config.get('next_serial', '?')}\n"
                    f"[bold]Certificates:[/bold]  {db.count_certs()} total "
                    f"([green]{len(db.certs_valid)}[/green] valid, "
                    f"[yellow]{len(db.certs_expires_soon)}[/yellow] expiring, "
                    f"[dim]{len(db.certs_expired)}[/dim] expired, "
                    f"[red]{len(db.certs_revoked)}[/red] revoked)\n"
                    f"[bold]Organisation:[/bold] {config.get('org', '-')}\n"
                    f"[bold]CA URL:[/bold]        {config.get('ca_url', '-')}\n"
                    f"[bold]CRL URL:[/bold]       {config.get('crl_url', '-')}\n"
                )
                self.app.call_from_thread(log.write, info)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log.log_error, f"Error loading CA info: {e}")
            finally:
                self.app.call_from_thread(self._update_button_states)

    CONFIG_FIELDS = {
        "ca_url": "#cfg-ca-url",
        "days": "#cfg-days",
        "crl_days": "#cfg-crl-days",
        "crl_url": "#cfg-crl-url",
    }

    STORE_FIELDS = {
        "ca_public_store": "#cfg-ca-public-store",
        "ca_private_store": "#cfg-ca-private-store",
        "ca_backup_store": "#cfg-ca-backup-store",
    }

    def _load_fields(self, fields: dict[str, str], label: str) -> None:
        """Load config values into Input widgets (runs in worker thread)."""
        log = self.query_one("#ca-log", LogPanel)
        self.app.call_from_thread(log.clear)
        with op_status_context(self, f"Loading {label}..."):
            try:
                ctx = self.app.tui_context
                if not ctx.has_ca:
                    self.app.call_from_thread(
                        log.log_warning,
                        "No CA found. Use the 'Init' tab to create one.",
                    )
                    return

                config = ctx.ca.ca_database.get_config_attributes()
                for key, widget_id in fields.items():
                    value = str(config.get(key, "") or "")
                    self.app.call_from_thread(
                        setattr, self.query_one(widget_id, Input), "value", value
                    )
                self.app.call_from_thread(log.log_info, f"{label} loaded")
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log.log_error, f"Error loading {label}: {e}")

    def _save_fields(self, fields: dict[str, str], label: str) -> None:
        """Save Input widget values to config (runs in worker thread)."""
        log = self.query_one("#ca-log", LogPanel)
        with op_status_context(self, f"Saving {label}..."):
            try:
                ctx = self.app.tui_context
                if not ctx.has_ca:
                    self.app.call_from_thread(
                        log.log_warning,
                        "No CA found. Use the 'Init' tab to create one.",
                    )
                    return

                updates = {}
                for key, widget_id in fields.items():
                    updates[key] = self.query_one(widget_id, Input).value.strip()

                with ctx.locked_mutation(f"save_{label.lower()}"):
                    ctx.ca.ca_database.update_config(updates)
                    ctx.ca.store_ca_database()
                self.app.call_from_thread(log.log_success, f"{label} saved")
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log.log_error, f"Error saving {label}: {e}")

    @work(thread=True, exclusive=True, group="op")
    def _load_config(self) -> None:
        self._load_fields(self.CONFIG_FIELDS, "Config")

    @work(thread=True, exclusive=True, group="op")
    def _save_config(self) -> None:
        self._save_fields(self.CONFIG_FIELDS, "Config")

    @work(thread=True, exclusive=True, group="op")
    def _load_stores(self) -> None:
        self._load_fields(self.STORE_FIELDS, "Stores")

    @work(thread=True, exclusive=True, group="op")
    def _save_stores(self) -> None:
        self._save_fields(self.STORE_FIELDS, "Stores")

    @work(thread=True, exclusive=True, group="op")
    def _do_init(self) -> None:
        org = self.query_one("#org-input", Input).value.strip()
        cn = self.query_one("#cn-input", Input).value.strip()
        ca_days = self.query_one("#ca-days-input", Input).value.strip()
        days = self.query_one("#days-input", Input).value.strip()
        crl_days = self.query_one("#crl-days-input", Input).value.strip()

        if not org or not cn:
            self.app.call_from_thread(
                self.query_one("#init-status", Static).update,
                "[red]Organisation and CN are required[/red]",
            )
            return

        self.app.call_from_thread(
            self.query_one("#init-status", Static).update,
            "Initialising CA...",
        )

        ctx = self.app.tui_context
        with op_status_context(self, "Initialising CA..."):
            try:
                from opca.services.ca import CertificateAuthority
                from opca.services.vault_lock import VaultLock

                ca_config = {
                    "command": "init",
                    "cn": cn,
                    "org": org,
                    "ca_days": int(ca_days),
                    "days": int(days),
                    "crl_days": int(crl_days),
                    "next_serial": 1,
                    "next_crl_serial": 1,
                    "key_size": DEFAULT_KEY_SIZE["ca"],
                }

                lock = VaultLock(ctx.op)
                with lock("ca_init"):
                    CertificateAuthority(
                        one_password=ctx.op,
                        config=ca_config,
                        op_config=DEFAULT_OP_CONF,
                    )

                ctx.reload_ca()
                self.app.call_from_thread(self._on_init_done)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(
                    self.query_one("#init-status", Static).update,
                    f"[red]Error: {e}[/red]",
                )

    def _on_init_done(self) -> None:
        self.query_one("#init-status", Static).update("")
        self.notify("CA initialised successfully", severity="information")
        self.query_one(NavBar).select("cert")
        self._switch_view("cert")

    def _browse_export(self) -> None:
        from opca.tui.screens.save_file_picker import SaveFilePickerScreen
        self.app.push_screen(
            SaveFilePickerScreen(default_filename="ca-cert.pem"),
            callback=self._on_export_path_selected,
        )

    def _on_export_path_selected(self, path: str | None) -> None:
        if path:
            self.query_one("#export-path", Input).value = path

    @work(thread=True, exclusive=True, group="op")
    def _do_export(self) -> None:
        ctx = self.app.tui_context
        if not ctx.has_ca:
            return
        export_path = self.query_one("#export-path", Input).value.strip()
        log = self.query_one("#ca-log", LogPanel)
        with op_status_context(self, "Exporting certificate..."):
            try:
                cert_pem = ctx.ca.get_certificate()
                if export_path:
                    from pathlib import Path
                    Path(export_path).expanduser().write_text(cert_pem)
                    self.app.call_from_thread(
                        log.log_success, f"Certificate exported to {export_path}"
                    )
                else:
                    self.app.call_from_thread(log.write, cert_pem)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log.log_error, str(e))

    @work(thread=True, exclusive=True, group="op")
    def _do_copy_cert(self) -> None:
        ctx = self.app.tui_context
        if not ctx.has_ca:
            return
        with op_status_context(self, "Copying certificate..."):
            try:
                cert_pem = ctx.ca.get_certificate()
                cmd = ["pbcopy"] if sys.platform == "darwin" else ["xclip", "-selection", "clipboard"]
                subprocess.run(cmd, input=cert_pem.encode(), check=True)
                self.app.call_from_thread(
                    self.notify, "CA certificate copied to clipboard", severity="information"
                )
            except (Exception, SystemExit) as e:
                log = self.query_one("#ca-log", LogPanel)
                self.app.call_from_thread(log.log_error, str(e))

    @work(thread=True, exclusive=True, group="op")
    def _do_upload(self) -> None:
        ctx = self.app.tui_context
        if not ctx.has_ca:
            return
        log = self.query_one("#ca-log", LogPanel)
        with op_status_context(self, "Uploading CA certificate..."):
            try:
                ok = ctx.ca.upload_ca_cert()
                if ok:
                    self.app.call_from_thread(log.log_success, "CA certificate uploaded")
                else:
                    self.app.call_from_thread(log.log_error, "Upload failed")
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(log.log_error, str(e))
