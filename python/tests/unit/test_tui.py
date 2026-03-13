# tests/unit/test_tui.py

"""
Unit tests for the OPCA TUI (Terminal User Interface).

Tests cover:
- TuiContext state management and App bridging
- Worker utilities (ANSI stripping, handler capture)
- Screen composition and widget rendering via Textual's pilot
- Navigation flow between screens
"""

from __future__ import annotations

import sqlite3
from argparse import Namespace
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from opca.tui.context import TuiContext
from opca.tui.workers import strip_ansi, capture_handler


# ---------------------------------------------------------------------------
# TuiContext
# ---------------------------------------------------------------------------

class TestTuiContext:
    """Tests for TuiContext state management."""

    def test_initial_state(self):
        """TuiContext starts disconnected with no CA."""
        ctx = TuiContext()
        assert ctx.connected is False
        assert ctx.has_ca is False
        assert ctx.vault == ""
        assert ctx.account is None

    def test_initial_state_with_values(self):
        """TuiContext can be initialised with vault and account."""
        ctx = TuiContext(account="company.1password.com", vault="MyVault")
        assert ctx.vault == "MyVault"
        assert ctx.account == "company.1password.com"
        assert ctx.connected is False

    def test_connected_property(self):
        """connected is True once op is set."""
        ctx = TuiContext(vault="v")
        ctx.op = MagicMock()
        assert ctx.connected is True

    def test_has_ca_property(self):
        """has_ca is True once ca is set."""
        ctx = TuiContext(vault="v")
        assert ctx.has_ca is False
        ctx.ca = MagicMock()
        assert ctx.has_ca is True

    def test_make_app_creates_namespace(self):
        """make_app builds an App with synthetic Namespace carrying extra kwargs."""
        ctx = TuiContext(account="acct", vault="vault")
        ctx.op = MagicMock()
        ctx.ca = MagicMock()

        app = ctx.make_app(command="cert", subcommand="create", cn="test.example.com")

        assert app.args.account == "acct"
        assert app.args.vault == "vault"
        assert app.args.command == "cert"
        assert app.args.subcommand == "create"
        assert app.args.cn == "test.example.com"
        assert app.op is ctx.op
        assert app.ca is ctx.ca

    def test_make_app_raises_when_disconnected(self):
        """make_app raises RuntimeError when not connected."""
        ctx = TuiContext(vault="v")
        with pytest.raises(RuntimeError, match="Not connected"):
            ctx.make_app(command="cert")

    def test_connect_sets_op_and_loads_ca(self):
        """connect initialises Op and loads CA via prepare_cert_authority."""
        ctx = TuiContext(account="acct", vault="vault")

        mock_op = MagicMock()
        mock_ca = MagicMock()
        # Give the mock CA a ca_database with a real sqlite3 connection
        mock_db = MagicMock()
        mock_db.conn = sqlite3.connect(":memory:")
        mock_db.conn.execute("CREATE TABLE test (id INTEGER)")
        mock_ca.ca_database = mock_db

        with patch("opca.tui.context.Op", return_value=mock_op) as op_cls, \
             patch("opca.tui.context.prepare_cert_authority", return_value=mock_ca) as prep:
            ctx.connect()

        op_cls.assert_called_once_with(account="acct", vault="vault")
        prep.assert_called_once_with(mock_op)
        assert ctx.op is mock_op
        assert ctx.ca is mock_ca

    def test_connect_handles_missing_ca(self):
        """connect sets ca=None when no CA exists in vault."""
        from opca.services.ca_errors import CANotFoundError

        ctx = TuiContext(account="acct", vault="vault")
        mock_op = MagicMock()

        with patch("opca.tui.context.Op", return_value=mock_op), \
             patch("opca.tui.context.prepare_cert_authority", side_effect=CANotFoundError("no CA")):
            ctx.connect()

        assert ctx.op is mock_op
        assert ctx.ca is None

    def test_reload_ca_raises_when_disconnected(self):
        """reload_ca raises RuntimeError when not connected."""
        ctx = TuiContext(vault="v")
        with pytest.raises(RuntimeError, match="Not connected"):
            ctx.reload_ca()

    def test_reload_ca_refreshes_ca(self):
        """reload_ca replaces the CA instance."""
        ctx = TuiContext(vault="v")
        ctx.op = MagicMock()
        ctx.ca = MagicMock()

        new_ca = MagicMock()
        mock_db = MagicMock()
        mock_db.conn = sqlite3.connect(":memory:")
        mock_db.conn.execute("CREATE TABLE test (id INTEGER)")
        new_ca.ca_database = mock_db

        with patch("opca.tui.context.prepare_cert_authority", return_value=new_ca):
            ctx.reload_ca()

        assert ctx.ca is new_ca

    def test_enable_cross_thread_db(self):
        """_enable_cross_thread_db re-creates connection with check_same_thread=False."""
        ctx = TuiContext(vault="v")
        mock_ca = MagicMock()
        mock_db = MagicMock()
        original_conn = sqlite3.connect(":memory:")
        original_conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, val TEXT)")
        original_conn.execute("INSERT INTO test_table VALUES (1, 'hello')")
        original_conn.commit()
        mock_db.conn = original_conn
        mock_ca.ca_database = mock_db
        ctx.ca = mock_ca

        ctx._enable_cross_thread_db()

        # The connection should have been replaced
        new_conn = mock_db.conn
        assert new_conn is not original_conn
        # Data should be preserved
        cursor = new_conn.cursor()
        cursor.execute("SELECT val FROM test_table WHERE id = 1")
        assert cursor.fetchone()[0] == "hello"
        cursor.close()

    def test_enable_cross_thread_db_noop_without_ca(self):
        """_enable_cross_thread_db does nothing when CA is None."""
        ctx = TuiContext(vault="v")
        ctx.ca = None
        ctx._enable_cross_thread_db()  # Should not raise


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------

class TestStripAnsi:
    """Tests for ANSI escape code stripping."""

    def test_strips_color_codes(self):
        """strip_ansi removes ANSI color sequences."""
        text = "\033[32mOK\033[0m"
        assert strip_ansi(text) == "OK"

    def test_strips_bold_codes(self):
        """strip_ansi removes bold/dim/etc sequences."""
        text = "\033[1mBold\033[0m normal"
        assert strip_ansi(text) == "Bold normal"

    def test_preserves_plain_text(self):
        """strip_ansi leaves plain text unchanged."""
        text = "Hello, World!"
        assert strip_ansi(text) == "Hello, World!"

    def test_strips_multiple_codes(self):
        """strip_ansi handles multiple ANSI codes in one string."""
        text = "\033[31mRed\033[0m and \033[32mGreen\033[0m"
        assert strip_ansi(text) == "Red and Green"

    def test_empty_string(self):
        """strip_ansi handles empty strings."""
        assert strip_ansi("") == ""

    def test_strips_complex_codes(self):
        """strip_ansi handles complex multi-param ANSI codes."""
        text = "\033[1;31;42mColorful\033[0m"
        assert strip_ansi(text) == "Colorful"


class TestCaptureHandler:
    """Tests for the handler stdout capture utility."""

    def test_captures_stdout(self):
        """capture_handler captures print output from a handler."""
        def handler():
            print("Hello from handler")
            return 0

        code, output = capture_handler(handler)
        assert code == 0
        assert "Hello from handler" in output

    def test_returns_exit_code(self):
        """capture_handler returns the handler's exit code."""
        def handler():
            return 42

        code, output = capture_handler(handler)
        assert code == 42

    def test_strips_ansi_from_output(self):
        """capture_handler strips ANSI codes from captured output."""
        def handler():
            print("\033[32mGreen text\033[0m")
            return 0

        code, output = capture_handler(handler)
        assert "Green text" in output
        assert "\033[" not in output

    def test_passes_args_to_handler(self):
        """capture_handler forwards positional and keyword args."""
        def handler(name, greeting="hi"):
            print(f"{greeting}, {name}")
            return 0

        code, output = capture_handler(handler, "Alice", greeting="Hello")
        assert code == 0
        assert "Hello, Alice" in output

    def test_captures_multiple_prints(self):
        """capture_handler captures all print calls."""
        def handler():
            print("line 1")
            print("line 2")
            print("line 3")
            return 0

        code, output = capture_handler(handler)
        assert "line 1" in output
        assert "line 2" in output
        assert "line 3" in output


# ---------------------------------------------------------------------------
# Textual App & Screen tests (async, using pilot)
# ---------------------------------------------------------------------------

class TestOpcaTuiApp:
    """Tests for the main TUI application."""

    @pytest.mark.asyncio
    async def test_app_creates_with_context(self):
        """OpcaTuiApp initialises with a TuiContext."""
        from opca.tui.app import OpcaTuiApp

        app = OpcaTuiApp(account="acct", vault="vault")
        assert app.tui_context.account == "acct"
        assert app.tui_context.vault == "vault"
        assert app.tui_context.connected is False

    @pytest.mark.asyncio
    async def test_app_shows_connect_screen(self):
        """App pushes ConnectScreen on mount."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.connect import ConnectScreen

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            assert isinstance(app.screen, ConnectScreen)

    @pytest.mark.asyncio
    async def test_connect_screen_has_inputs(self):
        """ConnectScreen has vault and account input fields."""
        from opca.tui.app import OpcaTuiApp
        from textual.widgets import Input, Button

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            vault_input = app.screen.query_one("#vault-input", Input)
            account_input = app.screen.query_one("#account-input", Input)
            connect_btn = app.screen.query_one("#connect-btn", Button)

            assert vault_input is not None
            assert account_input is not None
            assert connect_btn is not None

    @pytest.mark.asyncio
    async def test_connect_screen_prefills_vault(self):
        """ConnectScreen pre-fills vault from CLI args."""
        from opca.tui.app import OpcaTuiApp
        from textual.widgets import Input

        app = OpcaTuiApp(account="myacct", vault="myvault")
        async with app.run_test(size=(120, 40)) as pilot:
            vault_input = app.screen.query_one("#vault-input", Input)
            account_input = app.screen.query_one("#account-input", Input)
            assert vault_input.value == "myvault"
            assert account_input.value == "myacct"

    @pytest.mark.asyncio
    async def test_connect_screen_requires_vault(self):
        """ConnectScreen shows error when vault is empty."""
        from opca.tui.app import OpcaTuiApp
        from textual.widgets import Input, Static

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            # Clear vault and click connect
            vault_input = app.screen.query_one("#vault-input", Input)
            vault_input.value = ""
            await pilot.click("#connect-btn")
            await pilot.pause()

            status = app.screen.query_one("#connect-status", Static)
            assert "required" in str(status.render()).lower()


class TestDashboardScreen:
    """Tests for the Dashboard screen."""

    @pytest.mark.asyncio
    async def test_dashboard_has_sidebar_and_content(self):
        """Dashboard composes sidebar and content area."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.dashboard import Dashboard
        from textual.widgets import ListView, Static

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            # Manually switch to dashboard (skip connect)
            app.tui_context.op = MagicMock()
            app.switch_screen(Dashboard())
            await pilot.pause()

            sidebar = app.screen.query_one("#sidebar")
            content = app.screen.query_one("#content")
            menu = app.screen.query_one("#menu", ListView)

            assert sidebar is not None
            assert content is not None
            assert menu is not None

    @pytest.mark.asyncio
    async def test_dashboard_has_eight_menu_items(self):
        """Dashboard sidebar has 8 menu items."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.dashboard import Dashboard
        from textual.widgets import ListView, ListItem

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.switch_screen(Dashboard())
            await pilot.pause()

            menu = app.screen.query_one("#menu", ListView)
            items = app.screen.query(ListItem)
            assert len(list(items)) == 8

    @pytest.mark.asyncio
    async def test_dashboard_shows_no_ca_message(self):
        """Dashboard shows 'no CA' message when CA is not loaded."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.dashboard import Dashboard
        from textual.widgets import Footer

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.switch_screen(Dashboard())
            await pilot.pause()

            footer = app.screen.query_one(Footer)
            assert footer is not None


class TestConfirmModal:
    """Tests for the confirmation dialog."""

    @pytest.mark.asyncio
    async def test_confirm_modal_has_buttons(self):
        """ConfirmModal has Confirm and Cancel buttons."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.confirm import ConfirmModal
        from textual.widgets import Button

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = ConfirmModal(title="Test", message="Are you sure?")
            app.push_screen(modal)
            await pilot.pause()

            confirm_btn = app.screen.query_one("#confirm-yes", Button)
            cancel_btn = app.screen.query_one("#confirm-no", Button)
            assert confirm_btn is not None
            assert cancel_btn is not None

    @pytest.mark.asyncio
    async def test_confirm_modal_cancel_returns_false(self):
        """Clicking Cancel dismisses the modal with False."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.confirm import ConfirmModal

        result = None

        def on_dismiss(value):
            nonlocal result
            result = value

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = ConfirmModal(title="Test", message="Are you sure?")
            app.push_screen(modal, callback=on_dismiss)
            await pilot.pause()

            await pilot.click("#confirm-no")
            await pilot.pause()

            assert result is False

    @pytest.mark.asyncio
    async def test_confirm_modal_confirm_returns_true(self):
        """Clicking Confirm dismisses the modal with True."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.confirm import ConfirmModal

        result = None

        def on_dismiss(value):
            nonlocal result
            result = value

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = ConfirmModal(title="Test", message="Are you sure?")
            app.push_screen(modal, callback=on_dismiss)
            await pilot.pause()

            await pilot.click("#confirm-yes")
            await pilot.pause()

            assert result is True


class TestPasswordModal:
    """Tests for the password input modal."""

    @pytest.mark.asyncio
    async def test_password_modal_has_inputs(self):
        """PasswordModal has two password inputs and buttons."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.password import PasswordModal
        from textual.widgets import Input, Button

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = PasswordModal(title="Enter Password")
            app.push_screen(modal)
            await pilot.pause()

            pw_input = app.screen.query_one("#password-input", Input)
            pw_confirm = app.screen.query_one("#password-confirm", Input)
            ok_btn = app.screen.query_one("#password-ok", Button)
            cancel_btn = app.screen.query_one("#password-cancel", Button)

            assert pw_input is not None
            assert pw_confirm is not None
            assert pw_input.password is True
            assert pw_confirm.password is True
            assert ok_btn is not None
            assert cancel_btn is not None

    @pytest.mark.asyncio
    async def test_password_modal_cancel_returns_none(self):
        """Clicking Cancel dismisses with None."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.password import PasswordModal

        result = "not_called"

        def on_dismiss(value):
            nonlocal result
            result = value

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = PasswordModal(title="Test")
            app.push_screen(modal, callback=on_dismiss)
            await pilot.pause()

            await pilot.click("#password-cancel")
            await pilot.pause()

            assert result is None

    @pytest.mark.asyncio
    async def test_password_modal_rejects_empty(self):
        """PasswordModal shows error for empty password."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.password import PasswordModal
        from textual.widgets import Static

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = PasswordModal(title="Test")
            app.push_screen(modal)
            await pilot.pause()

            await pilot.click("#password-ok")
            await pilot.pause()

            error = app.screen.query_one("#password-error", Static)
            assert "empty" in str(error.render()).lower()

    @pytest.mark.asyncio
    async def test_password_modal_rejects_mismatch(self):
        """PasswordModal shows error when passwords don't match."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.password import PasswordModal
        from textual.widgets import Input, Static

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = PasswordModal(title="Test")
            app.push_screen(modal)
            await pilot.pause()

            pw1 = app.screen.query_one("#password-input", Input)
            pw2 = app.screen.query_one("#password-confirm", Input)
            pw1.value = "password123"
            pw2.value = "different456"

            await pilot.click("#password-ok")
            await pilot.pause()

            error = app.screen.query_one("#password-error", Static)
            assert "match" in str(error.render()).lower()

    @pytest.mark.asyncio
    async def test_password_modal_accepts_matching(self):
        """PasswordModal returns password when both fields match."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.password import PasswordModal
        from textual.widgets import Input

        result = "not_called"

        def on_dismiss(value):
            nonlocal result
            result = value

        app = OpcaTuiApp(vault="")
        async with app.run_test(size=(120, 40)) as pilot:
            modal = PasswordModal(title="Test")
            app.push_screen(modal, callback=on_dismiss)
            await pilot.pause()

            pw1 = app.screen.query_one("#password-input", Input)
            pw2 = app.screen.query_one("#password-confirm", Input)
            pw1.value = "mysecret"
            pw2.value = "mysecret"

            await pilot.click("#password-ok")
            await pilot.pause()

            assert result is not None
            assert result.password == "mysecret"
            assert result.store_in_op is False


class TestCertListScreen:
    """Tests for the certificate list screen."""

    @pytest.mark.asyncio
    async def test_cert_list_has_table_and_buttons(self):
        """CertListScreen has a DataTable and action buttons."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.cert_list import CertListScreen
        from textual.widgets import DataTable, Button, Select

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None  # No CA, so table will be empty
            app.push_screen(CertListScreen())
            await pilot.pause()

            table = app.screen.query_one("#cert-table", DataTable)
            filter_select = app.screen.query_one("#filter-select", Select)
            create_btn = app.screen.query_one("#btn-create", Button)

            assert table is not None
            assert filter_select is not None
            assert create_btn is not None

    @pytest.mark.asyncio
    async def test_cert_list_table_has_columns(self):
        """CertListScreen DataTable has the expected columns."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.cert_list import CertListScreen
        from textual.widgets import DataTable

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(CertListScreen())
            await pilot.pause()

            table = app.screen.query_one("#cert-table", DataTable)
            column_labels = [str(col.label) for col in table.columns.values()]
            assert "Serial" in column_labels
            assert "CN" in column_labels
            assert "Status" in column_labels


class TestCertCreateScreen:
    """Tests for the certificate creation form."""

    @pytest.mark.asyncio
    async def test_cert_create_has_form_fields(self):
        """CertCreateScreen has CN input, type select, and buttons."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.cert_create import CertCreateScreen
        from textual.widgets import Input, Select, Button

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.push_screen(CertCreateScreen())
            await pilot.pause()

            cn_input = app.screen.query_one("#cn-input", Input)
            type_select = app.screen.query_one("#type-select", Select)
            create_btn = app.screen.query_one("#btn-create", Button)
            home_btn = app.screen.query_one("#btn-home", Button)

            assert cn_input is not None
            assert type_select is not None
            assert create_btn is not None
            assert home_btn is not None

    @pytest.mark.asyncio
    async def test_cert_create_requires_cn(self):
        """CertCreateScreen shows error when CN is empty."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.cert_create import CertCreateScreen
        from textual.widgets import Static

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.push_screen(CertCreateScreen())
            await pilot.pause()

            await pilot.click("#btn-create")
            await pilot.pause()

            status = app.screen.query_one("#create-status", Static)
            assert "required" in str(status.render()).lower()


class TestCAScreen:
    """Tests for the CA management screen."""

    @pytest.mark.asyncio
    async def test_ca_screen_has_buttons(self):
        """CAScreen has export, upload, and refresh buttons across tabs."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.ca import CAScreen
        from textual.widgets import Button

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(CAScreen())
            await pilot.pause()

            export_btn = app.screen.query_one("#btn-export", Button)
            upload_btn = app.screen.query_one("#btn-upload", Button)
            do_init_btn = app.screen.query_one("#btn-do-init", Button)

            assert export_btn is not None
            assert upload_btn is not None
            assert do_init_btn is not None

    @pytest.mark.asyncio
    async def test_ca_screen_shows_config_tab(self):
        """Switching to Config tab shows the init form inputs."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.ca import CAScreen
        from opca.tui.widgets.nav_bar import NavBar
        from textual.widgets import Input

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(CAScreen())
            await pilot.pause()

            # Config view should be hidden initially (cert tab is default)
            config_view = app.screen.query_one("#view-config")
            assert config_view.display is False

            # Switch to config tab
            app.screen.query_one(NavBar).select("config")
            app.screen._switch_view("config")
            await pilot.pause()

            assert config_view.display is True
            org_input = app.screen.query_one("#org-input", Input)
            cn_input = app.screen.query_one("#cn-input", Input)
            assert org_input is not None
            assert cn_input is not None


class TestCRLScreen:
    """Tests for the CRL management screen."""

    @pytest.mark.asyncio
    async def test_crl_screen_has_controls(self):
        """CRLScreen has generate, export, upload buttons and format select."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.crl import CRLScreen
        from textual.widgets import Button, Select

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(CRLScreen())
            await pilot.pause()

            create_btn = app.screen.query_one("#btn-create", Button)
            export_btn = app.screen.query_one("#btn-export", Button)
            fmt_select = app.screen.query_one("#fmt-select", Select)

            assert create_btn is not None
            assert export_btn is not None
            assert fmt_select is not None


class TestDKIMScreen:
    """Tests for the DKIM key management screen."""

    @pytest.mark.asyncio
    async def test_dkim_screen_has_controls(self):
        """DKIMScreen has NavBar, DataTable, and action buttons."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.dkim import DKIMScreen
        from opca.tui.widgets.nav_bar import NavBar
        from textual.widgets import Button, DataTable

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.push_screen(DKIMScreen())
            await pilot.pause()

            assert app.screen.query_one(NavBar) is not None
            assert app.screen.query_one("#dkim-table", DataTable) is not None
            assert app.screen.query_one("#btn-refresh", Button) is not None
            assert app.screen.query_one("#btn-info", Button) is not None
            assert app.screen.query_one("#btn-deploy", Button) is not None
            assert app.screen.query_one("#btn-verify", Button) is not None

    @pytest.mark.asyncio
    async def test_dkim_screen_shows_create_tab(self):
        """Switching to Create tab shows form inputs and hides keys view."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.dkim import DKIMScreen
        from opca.tui.widgets.nav_bar import NavBar
        from textual.widgets import Button, Checkbox, Input

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.push_screen(DKIMScreen())
            await pilot.pause()

            # Keys view is default, create view is hidden
            keys_view = app.screen.query_one("#view-keys")
            create_view = app.screen.query_one("#view-create")
            assert keys_view.display is True
            assert create_view.display is False

            # Switch to create tab
            app.screen.query_one(NavBar).select("create")
            app.screen._switch_view("create")
            await pilot.pause()

            assert keys_view.display is False
            assert create_view.display is True
            assert app.screen.query_one("#domain-input", Input) is not None
            assert app.screen.query_one("#selector-input", Input) is not None
            assert app.screen.query_one("#deploy-r53-check", Checkbox) is not None
            assert app.screen.query_one("#btn-create", Button) is not None


class TestOpenVPNScreen:
    """Tests for the OpenVPN management screen."""

    @pytest.mark.asyncio
    async def test_openvpn_screen_has_profiles_tab(self):
        """OpenVPNScreen has a Profiles tab with DataTable and controls."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.openvpn import OpenVPNScreen
        from opca.tui.widgets.nav_bar import NavBar
        from textual.widgets import Button, DataTable, Input

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(OpenVPNScreen())
            await pilot.pause()

            assert app.screen.query_one(NavBar) is not None
            assert app.screen.query_one("#profile-table", DataTable) is not None
            assert app.screen.query_one("#dest-vault-input", Input) is not None
            assert app.screen.query_one("#btn-refresh-profiles", Button) is not None
            assert app.screen.query_one("#btn-send-profile", Button) is not None

    @pytest.mark.asyncio
    async def test_openvpn_screen_profiles_view_hidden_by_default(self):
        """Profiles view is hidden when Client tab is active."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.openvpn import OpenVPNScreen

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(OpenVPNScreen())
            await pilot.pause()

            profiles_view = app.screen.query_one("#view-profiles")
            client_view = app.screen.query_one("#view-client")
            assert profiles_view.display is False
            assert client_view.display is True

    @pytest.mark.asyncio
    async def test_openvpn_screen_switch_to_profiles(self):
        """Switching to Profiles tab shows the profiles view."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.openvpn import OpenVPNScreen
        from opca.tui.widgets.nav_bar import NavBar

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(OpenVPNScreen())
            await pilot.pause()

            app.screen._switch_view("profiles")
            await pilot.pause()

            profiles_view = app.screen.query_one("#view-profiles")
            client_view = app.screen.query_one("#view-client")
            server_view = app.screen.query_one("#view-server")
            assert profiles_view.display is True
            assert client_view.display is False
            assert server_view.display is False

    @pytest.mark.asyncio
    async def test_openvpn_profile_table_has_columns(self):
        """Profile DataTable has CN and Created columns."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.openvpn import OpenVPNScreen
        from textual.widgets import DataTable

        app = OpcaTuiApp(vault="test")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.tui_context.ca = None
            app.push_screen(OpenVPNScreen())
            await pilot.pause()

            table = app.screen.query_one("#profile-table", DataTable)
            column_labels = [str(col.label) for col in table.columns.values()]
            assert "CN" in column_labels
            assert "Created" in column_labels


class TestFooter:
    """Tests for the Footer widget on screens."""

    @pytest.mark.asyncio
    async def test_dashboard_has_footer(self):
        """Dashboard shows a Footer with key bindings."""
        from opca.tui.app import OpcaTuiApp
        from opca.tui.screens.dashboard import Dashboard
        from textual.widgets import Footer

        app = OpcaTuiApp(vault="my-vault", account="my-account")
        async with app.run_test(size=(120, 40)) as pilot:
            app.tui_context.op = MagicMock()
            app.switch_screen(Dashboard())
            await pilot.pause()

            footer = app.screen.query_one(Footer)
            assert footer is not None


class TestLogPanel:
    """Tests for the LogPanel widget."""

    @pytest.mark.asyncio
    async def test_log_panel_methods(self):
        """LogPanel has success, error, info, warning log methods."""
        from opca.tui.widgets.log_panel import LogPanel

        # Just verify the methods exist and are callable
        panel = LogPanel()
        assert callable(panel.log_success)
        assert callable(panel.log_error)
        assert callable(panel.log_info)
        assert callable(panel.log_warning)
