# tests/e2e/test_20_certs.py

import os
import pytest
from .helpers import run_opca, assert_ok

pytestmark = pytest.mark.e2e

@pytest.mark.order(20)
def test_cert_create_vpnserver(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "create", "-t", "vpnserver", "-n", "vpnserver-cert"),
              "cert create vpnserver")

@pytest.mark.order(21)
def test_cert_create_vpnclient(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "create", "-t", "vpnclient", "-n", "vpnclient-cert"),
              "cert create vpnclient")

@pytest.mark.order(22)
def test_cert_create_webserver_a(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "create",
                       "-t", "webserver", "-n", "webserver-cert", "--alt", "www.webserver.com"),
              "cert create webserver (www.webserver.com)")

@pytest.mark.order(23)
def test_cert_create_webserver_b(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "create",
                       "-t", "webserver", "-n", "mailserver-cert", "--alt", "mail.webserver.com"),
              "cert create webserver (mail.webserver.com)")

@pytest.mark.order(24)
def test_cert_renew_mailserver(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "renew", "-n", "mailserver-cert"),
              "cert renew mailserver-cert")

@pytest.mark.order(25)
def test_cert_revoke_webserver(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "revoke", "-n", "webserver-cert"),
              "cert revoke webserver-cert")

@pytest.mark.order(26)
def test_cert_revoke_serial_5(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "revoke", "-s", "5"),
              "cert revoke -s 5")

@pytest.mark.order(27)
def test_cert_export_vpnclient(opca_bin, op_account, create_vault, tmp_path_factory):
    """Export the vpnclient-cert (certificate + private key) to files and check perms."""
    v = create_vault
    tmp = tmp_path_factory.mktemp("exported_cert")
    cert_path = tmp / "vpnclient-cert.crt"
    key_path = tmp / "vpnclient-cert.key"

    res = run_opca(
        opca_bin, op_account, v,
        "cert", "export",
        "-n", "vpnclient-cert",
        "--with-key",
        "--cert-out", str(cert_path),
        "--key-out", str(key_path),
    )
    assert_ok(res, "cert export vpnclient (with key)")

    assert cert_path.exists(), "Exported certificate file is missing"
    assert key_path.exists(), "Exported private key file is missing"
    assert os.stat(cert_path).st_size > 0, "Exported certificate file is empty"

    mode = os.stat(key_path).st_mode & 0o777
    assert mode == 0o600, f"Expected key perms 0600, got {oct(mode)}"

@pytest.mark.order(28)
def test_cert_import_vpnclient_into_new_vault(opca_bin, op_account, create_vault, create_vault_2, tmp_path_factory):
    """Export from the primary vault and import into the second vault."""
    v_primary = create_vault
    tmp = tmp_path_factory.mktemp("exported_cert_for_import")
    cert_path = tmp / "vpnclient-cert.crt"
    key_path = tmp / "vpnclient-cert.key"

    # Export again to ensure files exist even if this test runs alone
    res = run_opca(
        opca_bin, op_account, v_primary,
        "cert", "export",
        "-n", "vpnclient-cert",
        "--with-key",
        "--cert-out", str(cert_path),
        "--key-out", str(key_path),
    )
    assert_ok(res, "cert export vpnclient for import")

    # Import into the second vault (PEM import; no -t/--days supported)
    v_new = create_vault_2
    res = run_opca(
        opca_bin, op_account, v_new,
        "cert", "import",
        "-n", "vpnclient-cert",
        "-c", str(cert_path),
        "-k", str(key_path),
    )
    assert_ok(res, "cert import vpnclient into second vault")

    # Sanity: can export from second vault
    res = run_opca(
        opca_bin, op_account, v_new,
        "cert", "export",
        "-n", "vpnclient-cert",
        "--cert-only",
        "--to-stdout",
    )
    assert_ok(res, "cert export from second vault (sanity)")
    assert "-----BEGIN CERTIFICATE-----" in res.stdout

# TODO: Need to test info
