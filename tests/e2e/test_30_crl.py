# tests/e2e/test_30_crl.py

from pathlib import Path

import re
import subprocess
import sys
import pytest
from .helpers import run_opca, assert_ok

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
pytestmark = pytest.mark.e2e

@pytest.mark.order(30)
def test_crl_create(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "crl", "create"),
              "crl create")

@pytest.mark.order(31)
def test_crl_export_and_verify(opca_bin, op_account, create_vault, tmp_path):
    v = create_vault
    tmp_path = Path(tmp_path)

    ca_pem = tmp_path / "ca.pem"
    crl_pem = tmp_path / "crl.pem"
    crl_der = tmp_path / "crl.der"

    # Ensure CA cert exists (if an earlier test already exported it, this is a no-op)
    if not ca_pem.exists():
        assert_ok(
            run_opca(opca_bin, op_account, v, "ca", "export", "--cert-out", str(ca_pem)),
            "ca export --cert-out ca.pem",
        )
        assert ca_pem.exists(), "Expected ca.pem to exist after export"

    # Export CRL in PEM & DER
    assert_ok(
        run_opca(opca_bin, op_account, v, "crl", "export", "--outfile", str(crl_pem)),
        "crl export --outfile crl.pem",
    )
    assert crl_pem.exists(), "Expected crl.pem to exist after export"

    assert_ok(
        run_opca(opca_bin, op_account, v, "crl", "export", "-f", "der", "--outfile", str(crl_der)),
        "crl export -f der --outfile crl.der",
    )
    assert crl_der.exists(), "Expected crl.der to exist after export"

    # Verify CRL signatures with OpenSSL against the CA cert
    def run(cmd):
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # OpenSSL prints 'verify OK' on stdout when successful; returncode should be 0
        if proc.returncode != 0:
            sys.stderr.write(f"\n[openssl] cmd failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}\n")
        return proc

    # PEM verify
    pem_verify = run(["openssl", "crl", "-in", str(crl_pem), "-noout", "-verify", "-CAfile", str(ca_pem)])
    assert pem_verify.returncode == 0, "PEM CRL signature verification failed"
    assert "verify OK" in pem_verify.stdout or pem_verify.stdout == "", "Unexpected OpenSSL PEM verify output"

    # DER verify
    der_verify = run(["openssl", "crl", "-in", str(crl_der), "-inform", "der", "-noout", "-verify", "-CAfile", str(ca_pem)])
    assert der_verify.returncode == 0, "DER CRL signature verification failed"
    assert "verify OK" in der_verify.stdout or der_verify.stdout == "", "Unexpected OpenSSL DER verify output"

    # (Optional) sanity: issuer & validity timestamps should parse
    pem_info = run(["openssl", "crl", "-in", str(crl_pem), "-noout", "-issuer", "-lastupdate", "-nextupdate"])
    assert pem_info.returncode == 0, "Failed to read CRL issuer/validity (PEM)"

@pytest.mark.order(32)
def test_crl_info(opca_bin, op_account, create_vault):
    v = create_vault
    res = run_opca(opca_bin, op_account, v, "crl", "info")
    assert_ok(res, "crl info")

    out = ANSI_RE.sub("", res.stdout)

    # Banner / section title present
    assert "Certificate Revocation List Info" in out

    # Validity line printed by title()/print_result() path
    # Example line includes: "Checking CRL Validity [ <crl_number> ]"
    assert "Checking" in out and "CRL Validity" in out

    # If a CRL number is present, it should be shown in brackets (can be None for first issuance)
    # Accept either a number or 'None'
    crl_num_match = re.search(r"CRL Validity.*\[\s*(None|\d+)\s*\]", out)
    assert crl_num_match is not None, "Expected CRL number or 'None' in validity line"

    # Core fields your action prints
    assert "Issuer:" in out
    assert re.search(r"Last Update:\s+.+", out)
    assert re.search(r"Next Update:\s+.+", out)

    # Either "No Revoked Certificates" or a list under "Revoked Certificates:"
    assert ("No Revoked Certificates" in out) or ("Revoked Certificates:" in out)

# TODO: test upload
