# tests/e2e/conftest.py

import os
import stat
import sys
import time
import shutil
import random
import string
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

def _rand(n=6):
    pool = string.ascii_lowercase + string.digits
    return "".join(random.choice(pool) for _ in range(n))

@pytest.fixture(scope="session")
def op_path():
    path = shutil.which("op")
    if not path:
        pytest.skip("1Password CLI 'op' not found on PATH; skipping real e2e.")
    return path

@pytest.fixture(scope="session")
def op_account():
    acct = os.environ.get("OP_ACCOUNT")
    if not acct:
        pytest.skip("Set OP_ACCOUNT env var to run real e2e; skipping.")
    return acct

@pytest.fixture(scope="session")
def opca_bin(pytestconfig, tmp_path_factory):
    """
    Run repo code via `python -m opca` (no PATH reliance).
    Allow override via OPCA_BIN.
    """
    override = os.environ.get("OPCA_BIN")
    if override:
        p = Path(override)
        if not p.exists():
            pytest.skip(f"OPCA_BIN={override} does not exist")
        return str(p.resolve())

    root = Path(pytestconfig.rootpath)
    src_dir = root / "src"
    pkg_main = src_dir / "opca" / "__main__.py"
    if not pkg_main.exists():
        pytest.skip(f"Could not find {pkg_main}. Expected package at src/opca.")

    # shim that sets PYTHONPATH and runs -m opca
    shim = tmp_path_factory.mktemp("opca_shim") / "opca"
    shim.write_text(
        f"#!/usr/bin/env bash\n"
        f"set -euo pipefail\n"
        f'export PYTHONPATH="{src_dir}:{os.environ.get("PYTHONPATH", "")}"\n'
        f'"{sys.executable}" -m opca "$@"\n'
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(shim.resolve())

@pytest.fixture(scope="session")
def signin(op_path, op_account):
    # If already signed in, this is a quick no-op.
    res = subprocess.run([op_path, "signin", "--account", op_account],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        pytest.skip(f"Unable to sign in to 1Password: {res.stderr or res.stdout}")
    return True

@pytest.fixture(scope="session")
def vault_name():
    return f"opca-{_rand()}"

@pytest.fixture(scope="session")
def create_vault(op_path, vault_name, signin):
    """Create a vault to store the CA."""
    # Create vault
    res = subprocess.run([op_path, "vault", "create", vault_name, "--icon", "wrench"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        pytest.skip(f"Unable to create vault '{vault_name}': {res.stderr or res.stdout}")

    yield vault_name

    # Cleanup (best effort)
    subprocess.run([op_path, "vault", "delete", vault_name, "--archive"],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

@pytest.fixture(scope="session")
def create_vault_2(op_path, signin):
    """Create a second, independent vault for importing the exported CA."""
    name = f"opca-{_rand()}-import"
    res = subprocess.run(
        [op_path, "vault", "create", name, "--icon", "wrench"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if res.returncode != 0:
        pytest.skip(f"Unable to create second vault '{name}': {res.stderr or res.stdout}")

    yield name

    # Best-effort cleanup
    subprocess.run(
        [op_path, "vault", "delete", name, "--archive"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

