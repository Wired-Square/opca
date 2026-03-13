# tests/e2e/test_10_ca.py

import os
import pytest
from .helpers import run_opca, assert_ok

pytestmark = pytest.mark.e2e

@pytest.mark.order(10)
def test_ca_init(opca_bin, op_account, create_vault):
    v = create_vault
    res = run_opca(opca_bin, op_account, v,
                   "ca", "init",
                   "-e", "no1@home.com",
                   "-o", "Test Organisation",
                   "-n", "Test Certificate Authority",
                   "--ou", "Web Services",
                   "--city", "Canberra",
                   "--state", "ACT",
                   "--country", "AU",
                   "--ca-days", "3650",
                   "--crl-days", "45",
                   "--days", "365",
                   "--ca-url", "https://ca.home.com/ca.crt",
                   "--crl-url", "https://ca.home.com/crl.pem")
    assert_ok(res, "CA init")

@pytest.fixture(scope="session")
def exported_ca(opca_bin, op_account, create_vault, tmp_path_factory):
    v = create_vault
    tmp = tmp_path_factory.mktemp("exported_ca")
    cert_path = tmp / "exported-ca.crt"
    key_path = tmp / "exported-ca.key"

    res = run_opca(
        opca_bin, op_account, v,
        "ca", "export",
        "--with-key",
        "--cert-out", str(cert_path),
        "--key-out", str(key_path),
    )
    assert_ok(res, "ca export (with key)")
    return {"cert": cert_path, "key": key_path, "src_vault": v}

@pytest.mark.order(12)
def test_ca_export_files_exist_and_perms(exported_ca):
    cert_path = exported_ca["cert"]
    key_path = exported_ca["key"]

    assert cert_path.exists(), "Exported certificate file is missing"
    assert key_path.exists(), "Exported private key file is missing"

    # Private key should be 0600
    mode = os.stat(key_path).st_mode & 0o777
    assert mode == 0o600, f"Expected key perms 0600, got {oct(mode)}"

@pytest.mark.order(15)
def test_ca_import_into_new_vault(opca_bin, op_account, create_vault_2, exported_ca):
    v_new = create_vault_2
    cert_path = exported_ca["cert"]
    key_path = exported_ca["key"]

    res = run_opca(
        opca_bin, op_account, v_new,
        "ca", "import",
        "-c", str(cert_path),
        "-k", str(key_path),
        "--days", "365",
        "--crl-days", "30",
    )
    assert_ok(res, "ca import into new vault")

# TODO: Need to test upload
