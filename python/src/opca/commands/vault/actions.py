# opca/commands/vault/actions.py

from __future__ import annotations

import getpass
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from opca.constants import (
    COLOUR_BRIGHT,
    COLOUR_RESET,
    EXIT_OK,
    EXIT_FATAL,
)
from opca.models import App
from opca.services.backup import (
    encrypt_payload,
    decrypt_payload,
    BackupFormatError,
    BackupDecryptionError,
)
from opca.services.vault import VaultBackup, VaultBackupError, VaultNotEmptyError
from opca.utils.files import read_bytes, write_bytes
from opca.utils.formatting import error, title

log = logging.getLogger(__name__)


def handle_vault_backup(app: App) -> int:
    """Create an encrypted backup of the entire vault."""
    title("Vault Backup", 3)

    password = _get_password(app, confirm=True)
    if not password:
        error("Password is required.")
        return EXIT_FATAL

    output = getattr(app.args, "output", None)
    if not output:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        output = str(Path.home() / f"{app.vault}-{timestamp}.opca")
    elif not Path(output).suffix:
        output += ".opca"

    try:
        vb = VaultBackup(op=app.op)
        title("Enumerating vault items...", 5)
        payload = vb.create_backup()

        metadata = payload["metadata"]
        print(f"  Vault:  {COLOUR_BRIGHT}{metadata['vault_name']}{COLOUR_RESET}")
        print(f"  Items:  {COLOUR_BRIGHT}{metadata['item_count']}{COLOUR_RESET}")

        title("Encrypting...", 5)
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        encrypted = encrypt_payload(plaintext, password)

        title(f"Writing {COLOUR_BRIGHT}{output}{COLOUR_RESET}...", 5)
        write_bytes(output, encrypted, overwrite=True, mode=0o600)

        title(f"Backup complete: {COLOUR_BRIGHT}{output}{COLOUR_RESET}", 3)
        return EXIT_OK

    except (VaultBackupError, BackupFormatError) as exc:
        error(str(exc))
        return EXIT_FATAL
    except Exception:
        log.exception("Vault backup failed")
        return EXIT_FATAL


def handle_vault_restore(app: App) -> int:
    """Restore a vault from an encrypted backup file."""
    title("Vault Restore", 3)

    input_file = app.args.input_file
    password = _get_password(app, confirm=False)
    if not password:
        error("Password is required.")
        return EXIT_FATAL

    try:
        title(f"Reading {COLOUR_BRIGHT}{input_file}{COLOUR_RESET}...", 5)
        data = read_bytes(input_file)
        if not data:
            error(f"Cannot read {input_file}")
            return EXIT_FATAL

        title("Decrypting...", 5)
        plaintext = decrypt_payload(data, password)
        payload = json.loads(plaintext.decode("utf-8"))

        metadata = VaultBackup.get_metadata(payload)
        print(f"  Source vault: {COLOUR_BRIGHT}{metadata.get('vault_name', '?')}{COLOUR_RESET}")
        print(f"  Backup date: {COLOUR_BRIGHT}{metadata.get('backup_date', '?')}{COLOUR_RESET}")
        print(f"  Items:       {COLOUR_BRIGHT}{metadata.get('item_count', '?')}{COLOUR_RESET}")

        title("Restoring items...", 5)
        vb = VaultBackup(op=app.op)
        counts = vb.restore_backup(payload)

        title("Restore complete", 3)
        for item_type, count in sorted(counts.items()):
            print(f"  {item_type}: {COLOUR_BRIGHT}{count}{COLOUR_RESET}")

        return EXIT_OK

    except BackupDecryptionError as exc:
        error(str(exc))
        return EXIT_FATAL
    except BackupFormatError as exc:
        error(str(exc))
        return EXIT_FATAL
    except VaultNotEmptyError as exc:
        error(str(exc))
        return EXIT_FATAL
    except VaultBackupError as exc:
        error(str(exc))
        return EXIT_FATAL
    except Exception:
        log.exception("Vault restore failed")
        return EXIT_FATAL


def handle_vault_info(app: App) -> int:
    """Display metadata from an encrypted backup file."""
    title("Vault Backup Info", 3)

    input_file = app.args.input_file
    password = _get_password(app, confirm=False)
    if not password:
        error("Password is required.")
        return EXIT_FATAL

    try:
        data = read_bytes(input_file)
        if not data:
            error(f"Cannot read {input_file}")
            return EXIT_FATAL

        plaintext = decrypt_payload(data, password)
        payload = json.loads(plaintext.decode("utf-8"))
        metadata = VaultBackup.get_metadata(payload)

        print(f"  OPCA version: {COLOUR_BRIGHT}{metadata.get('opca_version', '?')}{COLOUR_RESET}")
        print(f"  Vault name:   {COLOUR_BRIGHT}{metadata.get('vault_name', '?')}{COLOUR_RESET}")
        print(f"  Backup date:  {COLOUR_BRIGHT}{metadata.get('backup_date', '?')}{COLOUR_RESET}")
        print(f"  Item count:   {COLOUR_BRIGHT}{metadata.get('item_count', '?')}{COLOUR_RESET}")

        # Summarise item types
        items = payload.get("items", [])
        type_counts: dict[str, int] = {}
        for item in items:
            t = item.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        if type_counts:
            print()
            print("  Item breakdown:")
            for t, c in sorted(type_counts.items()):
                print(f"    {t}: {COLOUR_BRIGHT}{c}{COLOUR_RESET}")

        return EXIT_OK

    except (BackupDecryptionError, BackupFormatError) as exc:
        error(str(exc))
        return EXIT_FATAL
    except Exception:
        log.exception("Vault info failed")
        return EXIT_FATAL


def _get_password(app: App, *, confirm: bool) -> str:
    """Return the password from --password or interactive prompt."""
    password = getattr(app.args, "password", None)
    if password:
        return password

    if confirm:
        while True:
            pw1 = getpass.getpass("Enter backup password: ")
            pw2 = getpass.getpass("Confirm backup password: ")
            if pw1 == pw2:
                return pw1
            print("Passwords do not match. Please try again.\n")
    else:
        return getpass.getpass("Enter backup password: ")
