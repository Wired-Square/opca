# opca/__init__.py

"""
OPCA - 1Password Certificate Authority
======================================

This module provides tools for generating and managing keys, CSRs, and certificates,
with optional storage to 1Password, S3, or Rsync backends.
"""

# ---- Package metadata ----
__version__ = "0.99.1"
__title__ = "1Password Certificate Authority"
__short_title__ = "OPCA"
__author__ = "Alex Ferrara <alex@wiredsquare.com>"
__license__ = "MIT"


# ---- Public exports ----
__all__ = [
    "__version__",
    "__title__",
    "__short_title__",
    "__author__",
    "__license__",
]
