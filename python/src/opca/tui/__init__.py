# opca/tui/__init__.py

try:
    import textual  # noqa: F401
except ImportError:
    raise ImportError(
        "The TUI requires the 'textual' package. "
        "Install it with: pip install opca[tui]"
    ) from None
