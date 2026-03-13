# tests/ese/helpers.py

import subprocess, sys, time, pytest

def run_opca(opca_bin, op_account, vault_name, *args):
    cmd = [opca_bin, "-a", op_account, "-v", vault_name, *args]
    if opca_bin.endswith(".py"):
        cmd = [sys.executable, *cmd]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def assert_ok(res, step_desc):
    if res.returncode != 0:
        pytest.fail(f"{step_desc} FAILED (code {res.returncode})\n--- output ---\n{res.stdout}\n--------------")
    time.sleep(0.1)
