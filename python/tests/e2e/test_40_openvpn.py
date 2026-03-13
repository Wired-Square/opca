import pytest
from .helpers import run_opca, assert_ok

pytestmark = pytest.mark.e2e

@pytest.mark.order(40)
def test_openvpn_server(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "openvpn", "generate", "--server"),
              "openvpn gen-sample-vpn-server")

@pytest.mark.order(41)
def test_openvpn_dh(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "openvpn", "generate", "--dh"),
              "openvpn gen-dh")

@pytest.mark.order(42)
def test_openvpn_ta_key(opca_bin, op_account, create_vault):
    v = create_vault
    assert_ok(run_opca(opca_bin, op_account, v, "openvpn", "generate", "--ta-key"),
              "openvpn gen-ta-key")

@pytest.mark.order(50)
def test_openvpn_profile_after_reissue(opca_bin, op_account, create_vault):
    v = create_vault
    # revoke & reissue client
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "revoke", "-n", "vpnclient-cert"),
              "cert revoke vpnclient-cert")
    assert_ok(run_opca(opca_bin, op_account, v, "cert", "create", "-t", "vpnclient", "-n", "vpnclient-cert"),
              "cert recreate vpnclient-cert")
    # new profile
    assert_ok(run_opca(opca_bin, op_account, v, "openvpn", "generate", "--profile",
                       "-t", "sample", "-n", "vpnclient-cert"),
              "openvpn gen-vpn-profile (after reissue)")

# TODO: Need to test get, import
