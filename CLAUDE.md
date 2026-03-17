# CLAUDE.md

## Python Implementation (Deprecated)

The Python implementation (`src/opca/`) is deprecated and in a read-only archive state. Do not modify any Python code.

## Language

Use Australian English for all user-facing text, comments, and variable names (e.g. "colour" not "color", "organisation" not "organization", "serialise" not "serialize", "licence" not "license").

## TUI Styling

The TUI uses [Textual](https://textual.textualize.io/) with global styles in `src/opca/tui/css/app.tcss`.

### Reusable widgets (`src/opca/tui/widgets/`)

| Widget | Purpose | Usage |
|---|---|---|
| `NavBar` | Tabbed button bar with `nav-selected` highlight | `yield NavBar([("Home", "home"), ("Tab", "tab-id")], default="tab-id")` |
| `OpStatus` | Inline spinner + message (same as cert renew) | `op_status.show("Working...")` / `op_status.hide()` |
| `LogPanel` | RichLog output panel with `log_success`, `log_error`, `log_info`, `log_warning` | `yield LogPanel(id="my-log")` |

### Central CSS classes (`app.tcss`)

| Class | Purpose |
|---|---|
| `.button-row` | Horizontal container for action buttons |
| `.form-label` | Single-line label above a form input |
| `.form-row` | Horizontal form layout with `1fr` inputs |

### Screen conventions

- Use `OpStatus` for operation progress (not `set_loading`).
- Use `NavBar` for tabbed navigation within a screen.
- All screens bind `escape` to `app.pop_screen`.
- Background operations use `@work(thread=True, exclusive=True, group="op")`.
- Use `capture_handler()` from `workers.py` to run CLI handlers and capture output.

## Rust Testing

- Unit tests: `cargo test -p opca-core` (no external dependencies)
- Integration tests: `OPCA_INTEGRATION_TEST=1 cargo test -p opca-core --test op_integration` (requires `op` CLI session)
- The `Op` struct uses a `CommandRunner` trait — unit tests inject a `MockRunner` to avoid shelling out
- Integration tests are guarded by the `OPCA_INTEGRATION_TEST` environment variable
- Integration tests require: `op` CLI installed, signed-in session, and a test vault
- Set `OPCA_TEST_VAULT` and optionally `OPCA_TEST_ACCOUNT` for integration tests

## Changelog

Add new entries under `## [Unreleased]` in `CHANGELOG.md`. The release script moves unreleased entries into a versioned section at release time.

## Git

Do not add a Co-Authored-By line to commit messages.
