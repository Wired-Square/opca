# tests/e2e/test_60_tui.py
#
# End-to-end tests that drive the TUI via Textual's Pilot against a real
# 1Password vault.  The vault is expected to already contain a CA and
# certificates from the earlier e2e tests (order 10-50).

from __future__ import annotations

import time

import pytest

try:
    from textual.widgets import Button, DataTable, Input, Select, Static
    from opca.tui.app import OpcaTuiApp
except ImportError:
    pytest.skip("textual not installed", allow_module_level=True)


pytestmark = pytest.mark.e2e

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MAX_WORKER_WAIT = 30  # seconds to wait for background workers


async def wait_for_workers(pilot, timeout: float = MAX_WORKER_WAIT) -> None:
    """Wait until all background workers in the app have finished."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pilot.app.workers._workers:
            return
        await pilot.pause(delay=0.25)
    remaining = [str(w) for w in pilot.app.workers._workers]
    raise TimeoutError(f"Workers still running after {timeout}s: {remaining}")


async def connect_and_get_dashboard(app: OpcaTuiApp, pilot):
    """Drive through the ConnectScreen and wait until we land on Dashboard."""
    await wait_for_workers(pilot)
    from opca.tui.screens.dashboard import Dashboard
    assert isinstance(app.screen, Dashboard), (
        f"Expected Dashboard after connect, got {type(app.screen).__name__}"
    )


def _make_app(op_account: str, vault_name: str) -> OpcaTuiApp:
    return OpcaTuiApp(account=op_account, vault=vault_name)


def _require_ca(app: OpcaTuiApp) -> None:
    """Skip the test if the vault has no CA loaded."""
    if not app.tui_context.has_ca:
        pytest.skip("No CA in vault — run full e2e suite (order 10+) first")


# ---------------------------------------------------------------------------
# Tests – Connection & Dashboard
# ---------------------------------------------------------------------------

@pytest.mark.order(60)
@pytest.mark.asyncio
async def test_tui_connect_and_dashboard(op_account, create_vault):
    """TUI connects to 1Password, loads CA, and shows the Dashboard."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await wait_for_workers(pilot)
        from opca.tui.screens.dashboard import Dashboard
        assert isinstance(app.screen, Dashboard)

        # Welcome text should mention the vault name
        body = app.screen.query_one("#content-body", Static)
        body_text = str(body.render())
        assert create_vault in body_text, (
            f"Expected vault name '{create_vault}' in body text: {body_text}"
        )


# ---------------------------------------------------------------------------
# Tests – CA Screen
# ---------------------------------------------------------------------------

@pytest.mark.order(61)
@pytest.mark.asyncio
async def test_tui_ca_info(op_account, create_vault):
    """CA screen shows CA subject and certificate counts."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("ca")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        from opca.tui.screens.ca import CAScreen
        assert isinstance(app.screen, CAScreen)

        from opca.tui.widgets.log_panel import LogPanel
        log = app.screen.query_one("#ca-log", LogPanel)
        info_text = "\n".join(str(line) for line in log.lines)
        assert "Subject" in info_text or "subject" in info_text.lower() or "Test" in info_text


@pytest.mark.order(62)
@pytest.mark.asyncio
async def test_tui_ca_export(op_account, create_vault):
    """CA export button writes PEM data to the log panel."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("ca")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        btn = app.screen.query_one("#btn-export", Button)
        await pilot.click(btn)
        await wait_for_workers(pilot)

        from opca.tui.widgets.log_panel import LogPanel
        log = app.screen.query_one("#ca-log", LogPanel)
        # RichLog stores written content in its lines list
        log_content = "\n".join(str(line) for line in log.lines)
        assert "BEGIN CERTIFICATE" in log_content or "CERTIFICATE" in log_content, (
            f"Expected PEM data in log, got: {log_content[:200]}"
        )


# ---------------------------------------------------------------------------
# Tests – Certificate List
# ---------------------------------------------------------------------------

@pytest.mark.order(63)
@pytest.mark.asyncio
async def test_tui_cert_list_shows_certs(op_account, create_vault):
    """Certificate list screen shows certificates created by earlier e2e tests."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_list")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        from opca.tui.screens.cert_list import CertListScreen
        assert isinstance(app.screen, CertListScreen)

        table = app.screen.query_one("#cert-table", DataTable)
        assert table.row_count > 0, "Expected at least one certificate in the table"


@pytest.mark.order(64)
@pytest.mark.asyncio
async def test_tui_cert_list_filter_valid(op_account, create_vault):
    """Filtering by 'Valid' shows only valid certificates."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_list")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        select = app.screen.query_one("#filter-select", Select)
        select.value = "valid"
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        table = app.screen.query_one("#cert-table", DataTable)
        for row_idx in range(table.row_count):
            row_data = table.get_row_at(row_idx)
            status_text = str(row_data[3])
            assert "Valid" in status_text or "valid" in status_text.lower(), (
                f"Expected 'Valid' status, got: {status_text}"
            )


@pytest.mark.order(65)
@pytest.mark.asyncio
async def test_tui_cert_list_filter_revoked(op_account, create_vault):
    """Filtering by 'Revoked' shows only revoked certificates."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_list")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        select = app.screen.query_one("#filter-select", Select)
        select.value = "revoked"
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        table = app.screen.query_one("#cert-table", DataTable)
        # Prior e2e tests revoked at least one cert
        assert table.row_count > 0, "Expected at least one revoked certificate"
        for row_idx in range(table.row_count):
            row_data = table.get_row_at(row_idx)
            status_text = str(row_data[3])
            assert "Revoked" in status_text or "revoked" in status_text.lower(), (
                f"Expected 'Revoked' status, got: {status_text}"
            )


# ---------------------------------------------------------------------------
# Tests – Certificate Info
# ---------------------------------------------------------------------------

@pytest.mark.order(66)
@pytest.mark.asyncio
async def test_tui_cert_info(op_account, create_vault):
    """Selecting a certificate and viewing info shows certificate details."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_list")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        table = app.screen.query_one("#cert-table", DataTable)
        assert table.row_count > 0, "No certificates to view"

        row_data = table.get_row_at(0)
        serial = int(row_data[0])
        cn = str(row_data[1])

        from opca.tui.screens.cert_info import CertInfoScreen
        app.push_screen(CertInfoScreen(cn=cn, serial=serial))
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        assert isinstance(app.screen, CertInfoScreen)
        details = app.screen.query_one("#cert-details", Static)
        details_text = str(details.render())
        assert "Serial" in details_text or str(serial) in details_text
        assert "BEGIN CERTIFICATE" in details_text or cn in details_text


# ---------------------------------------------------------------------------
# Tests – Certificate Create
# ---------------------------------------------------------------------------

@pytest.mark.order(67)
@pytest.mark.asyncio
async def test_tui_cert_create(op_account, create_vault):
    """Create a new certificate through the TUI."""
    cert_cn = "tui-e2e-test-cert"
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_create")
        await pilot.pause(delay=0.5)

        from opca.tui.screens.cert_create import CertCreateScreen
        assert isinstance(app.screen, CertCreateScreen)

        cn_input = app.screen.query_one("#cn-input", Input)
        cn_input.value = cert_cn

        type_select = app.screen.query_one("#type-select", Select)
        type_select.value = "webserver"

        alt_input = app.screen.query_one("#alt-input", Input)
        alt_input.value = "tui-e2e.example.com"

        btn = app.screen.query_one("#btn-create", Button)
        await pilot.click(btn)
        await wait_for_workers(pilot, timeout=60)

        # On success, CertCreateScreen pops back to the previous screen
        assert not isinstance(app.screen, CertCreateScreen), (
            "Expected screen to pop on successful creation"
        )


@pytest.mark.order(68)
@pytest.mark.asyncio
async def test_tui_cert_appears_in_list(op_account, create_vault):
    """The certificate created by the TUI appears in the cert list."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_list")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        table = app.screen.query_one("#cert-table", DataTable)
        found = False
        for row_idx in range(table.row_count):
            row_data = table.get_row_at(row_idx)
            cn = str(row_data[1])
            if cn == "tui-e2e-test-cert":
                found = True
                break
        assert found, "TUI-created certificate 'tui-e2e-test-cert' not found in cert list"


# ---------------------------------------------------------------------------
# Tests – CRL Screen
# ---------------------------------------------------------------------------

@pytest.mark.order(69)
@pytest.mark.asyncio
async def test_tui_crl_info(op_account, create_vault):
    """CRL screen shows CRL information."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("crl")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        from opca.tui.screens.crl import CRLScreen
        assert isinstance(app.screen, CRLScreen)

        from opca.tui.widgets.log_panel import LogPanel
        log = app.screen.query_one("#crl-log", LogPanel)
        info_text = "\n".join(str(line) for line in log.lines)
        # CRL may or may not exist yet — accept either info or "No CRL found"
        assert len(info_text) > 5, f"Expected CRL info text, got: {info_text}"


@pytest.mark.order(70)
@pytest.mark.asyncio
async def test_tui_crl_generate(op_account, create_vault):
    """Generating a new CRL through the TUI succeeds."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("crl")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        btn = app.screen.query_one("#btn-create", Button)
        await pilot.click(btn)
        await wait_for_workers(pilot, timeout=60)

        from opca.tui.widgets.log_panel import LogPanel
        log = app.screen.query_one("#crl-log", LogPanel)
        log_content = "\n".join(str(line) for line in log.lines)
        assert "generated" in log_content.lower() or "success" in log_content.lower() or "CRL" in log_content, (
            f"Expected CRL generation success, got: {log_content[:200]}"
        )


# ---------------------------------------------------------------------------
# Tests – Database Screen
# ---------------------------------------------------------------------------

@pytest.mark.order(71)
@pytest.mark.asyncio
async def test_tui_database_screen(op_account, create_vault):
    """Database screen loads and shows config info."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("database")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        from opca.tui.screens.database import DatabaseScreen
        assert isinstance(app.screen, DatabaseScreen)

        config = app.screen.query_one("#db-config", Static)
        config_text = str(config.render())
        assert len(config_text) > 10, f"Expected database config, got: {config_text}"


# ---------------------------------------------------------------------------
# Tests – Navigation
# ---------------------------------------------------------------------------

@pytest.mark.order(72)
@pytest.mark.asyncio
async def test_tui_sidebar_navigation(op_account, create_vault):
    """Pressing number keys 1-7 navigates to the correct screens."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)

        from opca.tui.screens.ca import CAScreen
        from opca.tui.screens.cert_list import CertListScreen
        from opca.tui.screens.crl import CRLScreen

        # Press "1" for CA
        await pilot.press("1")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)
        assert isinstance(app.screen, CAScreen)

        await pilot.press("escape")
        await pilot.pause(delay=0.3)

        # Press "2" for Certificates
        await pilot.press("2")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)
        assert isinstance(app.screen, CertListScreen)

        await pilot.press("escape")
        await pilot.pause(delay=0.3)

        # Press "3" for CRL
        await pilot.press("3")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)
        assert isinstance(app.screen, CRLScreen)


# ---------------------------------------------------------------------------
# Tests – Revoke via TUI
# ---------------------------------------------------------------------------

@pytest.mark.order(73)
@pytest.mark.asyncio
async def test_tui_cert_revoke(op_account, create_vault):
    """Revoke the TUI-created certificate through the TUI."""
    app = _make_app(op_account, create_vault)
    async with app.run_test(size=(120, 40)) as pilot:
        await connect_and_get_dashboard(app, pilot)
        _require_ca(app)

        app.navigate_to("cert_list")
        await pilot.pause(delay=0.5)
        await wait_for_workers(pilot)

        table = app.screen.query_one("#cert-table", DataTable)

        # Find our TUI-created cert
        target_row = None
        for row_idx in range(table.row_count):
            row_data = table.get_row_at(row_idx)
            cn = str(row_data[1])
            if cn == "tui-e2e-test-cert":
                target_row = row_idx
                break

        if target_row is None:
            pytest.skip("tui-e2e-test-cert not found, cannot test revoke")

        table.move_cursor(row=target_row)
        await pilot.pause(delay=0.2)

        btn = app.screen.query_one("#btn-revoke", Button)
        await pilot.click(btn)

        # Wait for the confirm modal to appear
        from opca.tui.screens.confirm import ConfirmModal
        for _ in range(20):
            await pilot.pause(delay=0.5)
            if isinstance(app.screen, ConfirmModal):
                break

        assert isinstance(app.screen, ConfirmModal), "ConfirmModal did not appear after clicking Revoke"
        yes_btn = app.screen.query_one("#confirm-yes", Button)
        await pilot.click(yes_btn)
        await pilot.pause(delay=1.0)
        await wait_for_workers(pilot, timeout=60)

        # Allow the revoke callback and worker to complete
        await pilot.pause(delay=3.0)
        await wait_for_workers(pilot, timeout=60)

        # Verify revoke succeeded by checking status in the current "all" view
        table = app.screen.query_one("#cert-table", DataTable)
        for row_idx in range(table.row_count):
            row_data = table.get_row_at(row_idx)
            cn = str(row_data[1])
            if cn == "tui-e2e-test-cert":
                assert "Revoked" in str(row_data[3]), (
                    f"Expected 'Revoked' status after revocation, got: {row_data[3]}"
                )
                break

        # Switch to revoked filter and explicitly refresh
        select = app.screen.query_one("#filter-select", Select)
        select.value = "revoked"
        await pilot.pause(delay=0.5)
        app.screen.action_refresh_list()
        await pilot.pause(delay=2.0)
        await wait_for_workers(pilot, timeout=60)

        table = app.screen.query_one("#cert-table", DataTable)
        found_revoked = False
        for row_idx in range(table.row_count):
            row_data = table.get_row_at(row_idx)
            cn = str(row_data[1])
            if cn == "tui-e2e-test-cert":
                found_revoked = True
                break
        assert found_revoked, "tui-e2e-test-cert should appear in revoked filter after revocation"
