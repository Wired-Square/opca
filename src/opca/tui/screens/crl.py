# opca/tui/screens/crl.py

from __future__ import annotations

import subprocess
import sys

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Select, Static

from opca.tui.widgets.log_panel import LogPanel
from opca.tui.widgets.nav_bar import NavBar
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader


class CRLScreen(Screen):
    """CRL management: create, view info, export, upload."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("Certificate Revocation List")

            yield NavBar(
                [("Home", "home"), ("CRL", "crl")],
                default="crl",
            )

            with VerticalScroll(id="view-crl"):
                yield Static("Export format:", classes="form-label")
                yield Select(
                    [("PEM", "pem"), ("DER", "der")],
                    value="pem", id="fmt-select", allow_blank=False,
                )
                yield Static("Export file:", classes="form-label")
                with Horizontal(classes="form-row"):
                    yield Input(
                        placeholder="Leave blank for output window",
                        id="export-file",
                    )
                    yield Button("Browse", variant="default", id="btn-browse-export")
                with Horizontal(classes="button-row"):
                    yield Button("Generate", variant="primary", id="btn-create")
                    yield Button("Export", variant="default", id="btn-export")
                    yield Button("Copy PEM", variant="default", id="btn-copy")
                    yield Button("Upload", variant="default", id="btn-upload")
                    yield Button("Refresh", variant="default", id="btn-refresh")

            yield OpStatus(id="op-status")
            yield LogPanel(id="crl-log")
        yield Footer()

    def on_mount(self) -> None:
        self._load_info()

    def on_nav_bar_home(self, event: NavBar.Home) -> None:
        self.app.pop_screen()

    def on_nav_bar_selected(self, event: NavBar.Selected) -> None:
        if event.view_id == "crl":
            self._load_info()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "fmt-select":
            fmt = str(event.value).upper()
            self.query_one("#btn-copy", Button).label = f"Copy {fmt}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create":
            self._do_create()
        elif event.button.id == "btn-copy":
            self._do_copy()
        elif event.button.id == "btn-export":
            self._do_export()
        elif event.button.id == "btn-upload":
            self._do_upload()
        elif event.button.id == "btn-refresh":
            self._load_info()
        elif event.button.id == "btn-browse-export":
            self._browse_export()

    def _browse_export(self) -> None:
        from opca.tui.screens.save_file_picker import SaveFilePickerScreen
        self.app.push_screen(
            SaveFilePickerScreen(default_filename="ca.crl"),
            callback=self._on_export_path_selected,
        )

    def _on_export_path_selected(self, path: str | None) -> None:
        if path:
            self.query_one("#export-file", Input).value = path

    @work(thread=True, exclusive=True, group="op")
    def _load_info(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        log = self.query_one("#crl-log", LogPanel)
        self.app.call_from_thread(op_status.show, "Loading CRL info...")
        self.app.call_from_thread(log.clear)

        ctx = self.app.tui_context
        if not ctx.has_ca:
            self.app.call_from_thread(
                log.log_warning, "No CA found",
            )
            self.app.call_from_thread(op_status.hide)
            return

        try:
            crl_info = ctx.ca.get_crl_info()
            if not crl_info:
                self.app.call_from_thread(
                    log.log_warning,
                    "No CRL found. Click 'Generate' to create one.",
                )
                return

            self.app.call_from_thread(log.write, self._format_crl_info(crl_info))
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, f"Error: {e}")
        finally:
            self.app.call_from_thread(op_status.hide)

    @staticmethod
    def _format_crl_info(crl_info: dict) -> str:
        """Format CRL info dict into Rich-markup text."""
        revoked_list = crl_info.get("revoked", [])
        info = (
            f"[bold]Issuer:[/bold]        {crl_info.get('issuer', '-')}\n"
            f"[bold]Last Update:[/bold]   {crl_info.get('last_update', '-')}\n"
            f"[bold]Next Update:[/bold]   {crl_info.get('next_update', '-')}\n"
            f"[bold]CRL Number:[/bold]    {crl_info.get('crl_number', '-')}\n"
            f"[bold]Expired:[/bold]       {'Yes' if crl_info.get('expired') else 'No'}\n"
            f"[bold]Revoked Certs:[/bold] {len(revoked_list)}\n"
        )
        if revoked_list:
            info += "\n[bold]Revoked Serials:[/bold]\n"
            for entry in revoked_list:
                info += f"  Serial {entry.get('serial', '?')} - {entry.get('date', '?')}\n"
        return info

    @work(thread=True, exclusive=True, group="op")
    def _do_copy(self) -> None:
        fmt = str(self.query_one("#fmt-select", Select).value)
        fmt_label = fmt.upper()
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, f"Copying CRL {fmt_label} to clipboard...")
        ctx = self.app.tui_context
        try:
            crl_bytes = ctx.ca.get_crl_bytes(fmt=fmt)
            if fmt == "pem":
                clip_data = crl_bytes
            else:
                import base64
                clip_data = base64.b64encode(crl_bytes)
            cmd = ["pbcopy"] if sys.platform == "darwin" else ["xclip", "-selection", "clipboard"]
            subprocess.run(cmd, input=clip_data, check=True)
            note = " (base64-encoded)" if fmt != "pem" else ""
            self.app.call_from_thread(
                self.notify, f"CRL {fmt_label}{note} copied to clipboard", severity="information"
            )
        except (Exception, SystemExit) as e:
            log = self.query_one("#crl-log", LogPanel)
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_create(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Generating CRL...")
        log = self.query_one("#crl-log", LogPanel)
        ctx = self.app.tui_context
        try:
            ctx.ca.generate_crl()
            self.app.call_from_thread(log.log_success, "CRL generated")
            self._load_info_inner()
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _load_info_inner(self) -> None:
        """Reload CRL info into LogPanel (called from worker thread)."""
        log = self.query_one("#crl-log", LogPanel)
        ctx = self.app.tui_context
        try:
            crl_info = ctx.ca.get_crl_info()
            if not crl_info:
                return
            self.app.call_from_thread(log.clear)
            self.app.call_from_thread(log.write, self._format_crl_info(crl_info))
        except (Exception, SystemExit):
            pass

    @work(thread=True, exclusive=True, group="op")
    def _do_export(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Exporting CRL...")
        log = self.query_one("#crl-log", LogPanel)
        fmt = str(self.query_one("#fmt-select", Select).value)
        outfile = self.query_one("#export-file", Input).value.strip() or None
        ctx = self.app.tui_context

        try:
            crl_bytes = ctx.ca.get_crl_bytes(fmt=fmt)
            if outfile:
                from opca.utils.files import write_bytes
                write_bytes(outfile, crl_bytes, overwrite=False, create_dirs=False, atomic=True, mode=0o644)
                self.app.call_from_thread(log.log_success, f"CRL exported to {outfile}")
            else:
                if fmt == "pem":
                    self.app.call_from_thread(log.write, crl_bytes.decode("utf-8", errors="replace"))
                else:
                    self.app.call_from_thread(
                        log.log_info,
                        f"DER CRL ({len(crl_bytes)} bytes) — specify a file to export",
                    )
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    @work(thread=True, exclusive=True, group="op")
    def _do_upload(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Uploading CRL...")
        log = self.query_one("#crl-log", LogPanel)
        ctx = self.app.tui_context
        try:
            ok = ctx.ca.upload_crl()
            if ok:
                self.app.call_from_thread(log.log_success, "CRL uploaded")
            else:
                self.app.call_from_thread(log.log_error, "CRL upload failed")
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(log.log_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)
