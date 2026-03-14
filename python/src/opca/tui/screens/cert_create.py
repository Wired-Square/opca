# opca/tui/screens/cert_create.py

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Select, Static

from opca.constants import DEFAULT_KEY_SIZE
from opca.tui.widgets.op_status import OpStatus
from opca.tui.widgets.screen_header import ScreenHeader
from opca.tui.workers import op_status_context


CERT_TYPES = [
    ("Web Server", "webserver"),
    ("Device", "device"),
    ("VPN Client", "vpnclient"),
    ("VPN Server", "vpnserver"),
]


class CertCreateScreen(Screen):
    """Form for creating a new certificate."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield ScreenHeader("Create Certificate")

            yield Static("Common Name (CN):", classes="form-label")
            yield Input(placeholder="e.g. www.example.com", id="cn-input")

            yield Static("Certificate Type:", classes="form-label")
            yield Select(CERT_TYPES, value="webserver", id="type-select", allow_blank=False)

            yield Static("Subject Alternative Names (comma-separated):", classes="form-label")
            yield Input(placeholder="e.g. test.example.com, api.example.com", id="alt-input")

            with Horizontal(classes="button-row"):
                yield Button("Create", variant="primary", id="btn-create")
                yield Button("Home", variant="default", id="btn-home")

            yield OpStatus(id="op-status")
            yield Static("", id="create-status")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-home":
            self.app.pop_screen()
        elif event.button.id == "btn-create":
            self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        cn = self.query_one("#cn-input", Input).value.strip()
        cert_type = str(self.query_one("#type-select", Select).value)
        alt_text = self.query_one("#alt-input", Input).value.strip()
        alt_names = [s.strip() for s in alt_text.split(",") if s.strip()] if alt_text else None

        if not cn:
            self.query_one("#create-status", Static).update("[red]CN is required[/red]")
            return

        self._do_create(cn, cert_type, alt_names)

    @work(thread=True, exclusive=True, group="op")
    def _do_create(self, cn: str, cert_type: str, alt_names: list[str] | None) -> None:
        with op_status_context(self, f"Creating certificate for {cn}..."):
            ctx = self.app.tui_context
            try:
                with ctx.locked_mutation("cert_create"):
                    if ctx.op.item_exists(cn):
                        self.app.call_from_thread(
                            self.query_one("#create-status", Static).update,
                            f"[red]'{cn}' already exists in 1Password[/red]",
                        )
                        return

                    base_config = ctx.ca.ca_certbundle.get_config().copy()
                    base_config["key_size"] = DEFAULT_KEY_SIZE[cert_type]
                    base_config["cn"] = cn
                    if alt_names:
                        base_config["alt_dns_names"] = alt_names

                    bundle = ctx.ca.generate_certificate_bundle(
                        cert_type=cert_type,
                        item_title=cn,
                        config=base_config,
                    )
                    valid = bundle.is_valid()
                self.app.call_from_thread(self._on_created, cn, valid)
            except (Exception, SystemExit) as e:
                self.app.call_from_thread(
                    self.query_one("#create-status", Static).update,
                    f"[red]Error: {e}[/red]",
                )

    def _on_created(self, cn: str, valid: bool) -> None:
        if valid:
            self.notify(f"Certificate created: {cn}", severity="information")
            self.app.pop_screen()
        else:
            self.query_one("#create-status", Static).update(
                f"[yellow]Certificate created for {cn} but validation failed[/yellow]"
            )
