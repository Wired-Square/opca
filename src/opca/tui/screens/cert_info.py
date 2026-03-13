# opca/tui/screens/cert_info.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Static

from opca.tui.styles import style_status
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader


class CertInfoScreen(Screen):
    """Display detailed certificate information."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, cn: str, serial: str | int, title: str = "", **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._cn = cn
        self._serial = serial
        self._title = title or cn

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield ScreenHeader(f"Certificate: {self._cn}")
            with Horizontal(classes="button-row"):
                yield Button("Home", variant="default", id="btn-home")
            yield OpStatus(id="op-status")
            yield Static("Loading...", id="cert-details")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-home":
            self.app.pop_screen()

    def on_mount(self) -> None:
        self._load_info()

    @work(thread=True, exclusive=True, group="op")
    def _load_info(self) -> None:
        op_status = self.query_one("#op-status", OpStatus)
        self.app.call_from_thread(op_status.show, "Loading certificate info...")
        try:
            ctx = self.app.tui_context
            db_row = ctx.ca.ca_database.query_cert({"serial": self._serial})
            cert_bundle = ctx.ca.retrieve_certbundle(self._title)
            if cert_bundle is None:
                self.app.call_from_thread(self._show_error, "Certificate bundle not found in 1Password")
                return
            db_status = (db_row or {}).get("status", "Unknown")
            db_revocation_date = (db_row or {}).get("revocation_date")

            cert_type = cert_bundle.get_type()
            issuer = cert_bundle.get_certificate_attrib("issuer")
            subject = cert_bundle.get_certificate_attrib("subject")
            san_obj = cert_bundle.get_certificate_attrib("subject_alt_name")
            expiry = cert_bundle.get_certificate_attrib("not_after")
            not_before = cert_bundle.get_certificate_attrib("not_before")
            key_size = cert_bundle.get_public_key_size()
            key_type = cert_bundle.get_public_key_type()
            cert_pem = cert_bundle.get_certificate(pem_format=True)

            san = str(san_obj) if san_obj else "-"

            styled_status = style_status(db_status)

            info = (
                f"[bold]Serial:[/bold]       {self._serial}\n"
                f"[bold]Type:[/bold]         {cert_type}\n"
                f"[bold]Key:[/bold]          {key_type} {key_size}-bit\n"
                f"[bold]Subject:[/bold]      {subject}\n"
                f"[bold]Issuer:[/bold]       {issuer}\n"
                f"[bold]Status:[/bold]       {styled_status}\n"
                f"[bold]Not Before:[/bold]   {not_before}\n"
                f"[bold]Not After:[/bold]    {expiry}\n"
                f"[bold]SAN:[/bold]          {san}\n"
            )
            if db_revocation_date:
                info += f"[bold]Revoked:[/bold]      {db_revocation_date}\n"
            info += f"\n{cert_pem}"

            self.app.call_from_thread(self._show_info, info)
        except (Exception, SystemExit) as e:
            self.app.call_from_thread(self._show_error, str(e))
        finally:
            self.app.call_from_thread(op_status.hide)

    def _show_info(self, info: str) -> None:
        self.query_one("#cert-details", Static).update(info)

    def _show_error(self, msg: str) -> None:
        self.query_one("#cert-details", Static).update(f"[red]Error: {msg}[/red]")
