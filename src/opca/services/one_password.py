# opca/services/one_password.py

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Iterable, Optional

from opca.constants import OP_BIN
from opca.services.op_errors import (
    VaultNotFoundError,
    AuthenticationError,
    PermissionDeniedError,
    ItemConflictError,
    ItemNotFoundError,
    CLIError,
)

class Op:
    """ Thin class to act on 1Password CLI """
    def __init__(
            self,
            binary: str = OP_BIN,
            account: Optional[str] = None,
            vault: Optional[str] = None,
        ):
        self.account = account
        self.vault = (vault or "").strip()

        if (os.path.isabs(binary) and os.path.isfile(binary) and os.access(binary, os.X_OK)):
            resolved = binary
        else:
            resolved = shutil.which(binary)

        if not resolved:
            raise CLIError(f"1Password CLI binary not found: {binary!r}. Ensure it's installed and on PATH.")

        self.bin = resolved

        self._ensure_signed_in()
        self._ensure_vault_exists()

    # -------------------------
    # High-level helpers
    # -------------------------

    def _ensure_signed_in(self) -> None:
        """ Ensure we have a valid signin to 1Password """
        result = _run_command([self.bin, "whoami"])

        if result.returncode == 0:
            return

        self._interactive_signin()
        # retry once
        res = _run_command([self.bin, "whoami"])
        if res.returncode == 0:
            return

        raise AuthenticationError(f"Not signed in to 1Password.")

    def _ensure_vault_exists(self) -> None:
        if not self.vault:
            raise VaultNotFoundError("No 1Password vault configured. Use --vault or OPCA_VAULT.")
        result = _run_command([self.bin, "vault", "get", self.vault])
        if result.returncode != 0:
            _raise_mapped_error(result, default=VaultNotFoundError(f"1Password vault {self.vault!r} not found."))

    def _checked(self, args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
        """ Map common CLI failures to OPError subsclesses """
        result = _run_command(args, str_in=input_text)
        if result.returncode == 0:
            return result
        _raise_mapped_error(result)
        # Unreachable
        return result

    def _interactive_signin(self):
        """ Perform an interactive signin to 1Password CLI """

        signin_command = [self.bin, 'signin']

        if self.account:
            signin_command.extend(['--account', self.account])

        result = _run_command(signin_command)

        if result.returncode != 0:
            raise AuthenticationError("1Password sign-in failed. Please run `op signin` and try again.")

    # -------------------------
    # Public API
    # -------------------------
    def delete_item(self, item_title: str, archive: bool = True) -> subprocess.CompletedProcess:
        """ Deletes an item from 1Password """

        cmd = [self.bin, "item", "delete", item_title, "--vault", self.vault]

        if archive:
            cmd.append('--archive')

        return self._checked(cmd)

    def get_current_user_details(self) -> subprocess.CompletedProcess:
        """ Return the current 1Password CLI user details """

        return self._checked([self.bin, "user", "get", "--me"])

    def get_document(self, item_title: str) -> subprocess.CompletedProcess:
        """ Retrieve the contents of a document in 1Password """

        return self._checked([self.bin, 'document', 'get', item_title, f'--vault={self.vault}'])

    def get_item(
            self,
            item_title: str,
            output_format: str = "json"
        ) -> subprocess.CompletedProcess:
        """ Retrieve the contents of an item in 1Password """

        return self._checked(
            [self.bin,
             'item',
             'get',
             item_title,
            f'--vault={self.vault}',
            f'--format={output_format}']
        )

    def get_vault(self) -> subprocess.CompletedProcess:
        """ Return the current 1Password vault details """

        return self._checked([self.bin, 'vault', 'get', self.vault])

    def inject_item(self, template: str, env_vars: Optional[dict]) -> subprocess.CompletedProcess:
        """ Fill out a template from data in 1Password """

        res = _run_command([self.bin, 'inject'], env_vars=env_vars, str_in=template)

        if res.returncode != 0:
            _raise_mapped_error(res)
        
        return res

    def item_exists(self, item_title: str) -> bool:
        """ Checks to see if an item exists in 1Password """

        result = _run_command([self.bin, "item", "get", item_title, f"--vault={self.vault}", "--format=json"])

        return bool(result.returncode == 0)

    def item_list(
            self,
            categories: str,
            output_format: str = "json"
        ) -> subprocess.CompletedProcess:
        """ List all items in the current vault """

        return self._checked(
            [self.bin,
             'item',
             'list',
            f'--vault={self.vault}',
            f'--categories={categories}',
            f'--format={output_format}']
        )

    def read_item(self, url: str) -> subprocess.CompletedProcess:
        """ Retrieve the contents of an item at a given 1Password secrets url """

        return self._checked([self.bin, 'read', url])

    def rename_item(self, src_title: str, dst_title: str) -> subprocess.CompletedProcess:
        """ Rename an item in 1Password """

        cmd = [self.bin, 'item', 'edit', src_title, '--title', dst_title, '--vault', self.vault]

        return self._checked(cmd)

    def mk_url(self, item_title: str, value_key: Optional[str] = None) -> str:
        """ Make a 1Password secret url from an item title and optional value """

        if value_key is None:
            return f"op://{self.vault}/{item_title}"

        return f"op://{self.vault}/{item_title}/{value_key}"

    def store_document(
            self,
            item_title: str,
            filename: str,
            str_in: str,
            action: str = "create",
            vault: Optional[str] = None,
        ) -> subprocess.CompletedProcess:
        """ Store a document in 1Password """

        if action == "auto":
            if self.item_exists(item_title):
                op_action = "edit"
            else:
                op_action = "create"
                item_title = f'--title={item_title}'
        elif action == "create":
            op_action = action
            item_title = f'--title={item_title}'
        elif action == "edit":
            op_action = action
        else:
            raise CLIError(f"Unknown storage command {action!r}")

        op_vault = (vault or self.vault).strip()

        cmd = [self.bin, 'document', op_action, item_title,
                f'--vault={op_vault}', f'--file-name={filename}']

        return self._checked(cmd, input_text=str_in)

    def store_item(
            self,
            item_title: str,
            attributes: Optional[Iterable[str]] = None,
            action: str = "auto",
            category: str = "Secure Note",
            str_in: Optional[str] = None
        ):
        """ Store an item in 1Password """

        if action == "auto":
            if self.item_exists(item_title):
                op_action = "edit"
            else:
                op_action = "create"
                item_title = f'--title={item_title}'
        elif action == "create":
            op_action = action
            item_title = f'--title={item_title}'
        elif action == "edit":
            op_action = action
        else:
            raise CLIError(f"Unknown storage command {action!r}")

        cmd = [self.bin, 'item', op_action, item_title, f'--vault={self.vault}']

        if category is not None and op_action == 'create':
            cmd.append(f'--category={ category }')

        if attributes:
            for attrib in attributes:
                if attrib.startswith("--field"):
                    raise CLIError("OPCA expects op v2 assignment syntax only; do not use '--field'.")
                if "=" not in attrib:
                    raise CLIError(f"Invalid attribute token {attrib!r}. Expected 'label=value'.")
                cmd.append(attrib)

        return self._checked(cmd, input_text=str_in)

    def whoami(self) -> subprocess.CompletedProcess:
        """ Return the current 1Password CLI user """

        return self._checked([self.bin, 'whoami'])


def _run_command(
        command: list[str],
        *,
        text: bool = True,
        shell: bool = False,
        stdin=None,
        str_in: Optional[str] = None,
        env_vars: Optional[dict] = None
    ) -> subprocess.CompletedProcess:
    """ Run a command and capture the output """

    try:
        return subprocess.run(
            command,
            env=env_vars,
            stdin=stdin,
            input=str_in,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            shell=shell,
            check=False
        )
    except FileNotFoundError:
        raise CLIError(f"Command not found: {command[0]!r}. Is it installed?")

def _raise_mapped_error(res: subprocess.CompletedProcess, *, default: Exception | None = None) -> None:
    msg = (res.stderr or res.stdout or "").strip()
    low = msg.lower()

    if "vault" in low and "not found" in low:
        raise VaultNotFoundError(msg or "Vault not found.")
    if "sign in" in low or "unauthenticated" in low or "not authenticated" in low:
        raise AuthenticationError("Not signed in to 1Password. Run `op signin`.")
    if "permission" in low or "denied" in low or "forbidden" in low:
        raise PermissionDeniedError(msg or "Permission denied.")
    if "already exists" in low or "duplicate" in low or "archived" in low:
        raise ItemConflictError(msg or "Item conflict (duplicate/archived).")
    if "not found" in low and "item" in low:
        raise ItemNotFoundError(msg or "Item not found.")

    if default is not None:
        raise default
    raise CLIError(msg or "1Password CLI command failed.")
