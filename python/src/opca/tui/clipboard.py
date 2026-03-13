# opca/tui/clipboard.py

from __future__ import annotations

import subprocess
import sys


def copy_to_clipboard(data: bytes) -> None:
    """Copy bytes to the system clipboard (macOS or Linux)."""
    cmd = ["pbcopy"] if sys.platform == "darwin" else ["xclip", "-selection", "clipboard"]
    subprocess.run(cmd, input=data, check=True)
