# opca/utils/files.py

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Union
import os
import tempfile

from opca.utils.formatting import error

StrPath = Union[str, Path]

def read_bytes(path: StrPath) -> bytes:
    """Read a file as bytes; exits with a message on failure."""
    file_path = Path(path)

    try:
        return file_path.read_bytes()
    except FileNotFoundError:
        error(f"File '{file_path}' not found.", 1)
    except PermissionError:
        error(f"Permission denied for file '{file_path}'.", 1)
    except IOError as err:
        error(f"I/O error while reading file '{file_path}': {err}", 1)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File '{file_path}' not found.") from e
    except PermissionError as e:
        raise PermissionError(f"Permission denied for file '{file_path}'.") from e
    except OSError as err:
        raise OSError(f"I/O error while reading file '{file_path}': {err}") from err

def write_bytes(
    path: StrPath,
    data: bytes,
    *,
    overwrite: bool = False,
    create_dirs: bool = False,
    atomic: bool = True,
    mode: int = 0o600,
) -> Path:
    """
    Write bytes to a file, with optional atomic replacement.
    Exits with a message on failure (consistent with read_bytes()).

    Args:
        path: Destination file path.
        data: Bytes to write.
        overwrite: If False and path exists, abort.
        create_dirs: Create parent directories if needed.
        atomic: Write to a temp file and os.replace() for durability.
        mode: File permission mode to apply to the written file.

    Returns:
        The resolved Path of the written file.
    """
    file_path = Path(path)
    parent = file_path.parent

    try:
        if file_path.exists() and not overwrite:
            error(f"File '{file_path}' already exists. Aborting.", 1)

        if create_dirs:
            parent.mkdir(parents=True, exist_ok=True)

        if not atomic:
            file_path.write_bytes(data)
            os.chmod(file_path, mode)
            return file_path

        # Atomic write: temp file in same directory -> fsync -> replace -> fsync dir
        with tempfile.NamedTemporaryFile(delete=False, dir=str(parent)) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name

        os.chmod(tmp_name, mode)
        os.replace(tmp_name, file_path)

        # fsync the containing directory so the rename is durable
        dir_fd = os.open(str(parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        return file_path

    except PermissionError:
        error(f"Permission denied for file '{file_path}'.", 1)
    except IsADirectoryError:
        error(f"Path '{file_path}' is a directory.", 1)
    except FileNotFoundError:
        # e.g., parent missing and create_dirs=False
        error(f"Path '{file_path}' not found.", 1)
    except OSError as err:
        error(f"I/O error while writing file '{file_path}': {err}", 1)
    except PermissionError as e:
        raise PermissionError(f"Permission denied for file '{file_path}'.") from e
    except IsADirectoryError as e:
        raise IsADirectoryError(f"Path '{file_path}' is a directory.") from e
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Path '{file_path}' not found.") from e
    except OSError as err:
        raise OSError(f"I/O error while writing file '{file_path}': {err}") from err

def parse_bulk_file(path: str) -> Iterable[Dict[str, object]]:
    """
    Each non-empty/non-comment line is:
      CN [--alt alt1] [--alt alt2] ...
    Returns dicts with keys: cn, alt_dns_names (optional)
    """
    for raw in read_bytes(path).decode("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split("--alt")]

        cfg: Dict[str, object] = {"cn": parts[0]}
        if len(parts) > 1:
            cfg["alt_dns_names"] = [p.strip() for p in parts[1:] if p.strip()]
        yield cfg
